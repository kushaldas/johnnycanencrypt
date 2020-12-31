use pyo3::create_exception;
use pyo3::exceptions::*;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::types::{PyDateTime, PyDict, PyList};
use pyo3::wrap_pyfunction;

use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::io::Write;
use std::path::Path;
use std::str;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

extern crate anyhow;
extern crate sequoia_openpgp as openpgp;
extern crate talktosc;

use crate::openpgp::armor;
use openpgp::armor::{Kind, Writer};

use crate::openpgp::crypto::{KeyPair, SessionKey};
use crate::openpgp::parse::stream::{
    DecryptionHelper, DecryptorBuilder, DetachedVerifierBuilder, MessageLayer, MessageStructure,
    VerificationHelper,
};

use crate::openpgp::crypto::Decryptor;
use crate::openpgp::packet::key;
use crate::openpgp::parse::{PacketParser, PacketParserResult, Parse};
use crate::openpgp::policy::Policy;
use crate::openpgp::policy::StandardPolicy as P;
use crate::openpgp::serialize::stream::{Encryptor, LiteralWriter, Message, Signer};
use crate::openpgp::serialize::Marshal;
use crate::openpgp::serialize::MarshalInto;
use crate::openpgp::types::KeyFlags;
use crate::openpgp::types::SymmetricAlgorithm;
use crate::openpgp::Packet;
use chrono::prelude::*;
use openpgp::cert::prelude::*;
use openpgp::types::RevocationStatus;
use talktosc::*;

mod scard;

// Our CryptoError exception
create_exception!(johnnycanencrypt, CryptoError, PyException);

// Our SameKeyError exception
create_exception!(johnnycanencrypt, SameKeyError, PyException);

// Error in selecting OpenPGP applet in the card
create_exception!(johnnycanencrypt, CardError, PyException);

pub struct YuBi {
    // KeyID -> Card serial number mapping.
    //keys: HashMap<openpgp::KeyID, String>,
    // PublicKey
    keys: HashMap<openpgp::KeyID, openpgp::packet::Key<key::PublicParts, key::UnspecifiedRole>>,
    pin: Vec<u8>,
}

impl YuBi {
    pub fn new(policy: &dyn Policy, certdata: Vec<u8>, pin: Vec<u8>) -> Self {
        let mut keys = HashMap::new();
        let cert = openpgp::Cert::from_bytes(&certdata).unwrap();
        for ka in cert
            .keys()
            .with_policy(policy, None)
            .for_storage_encryption()
            .for_transport_encryption()
        {
            let key = ka.key();
            keys.insert(key.keyid(), key.clone().into());
        }
        YuBi { keys, pin }
    }
}

#[allow(unused)]
impl DecryptionHelper for YuBi {
    fn decrypt<D>(
        &mut self,
        pkesks: &[openpgp::packet::PKESK],
        _skesks: &[openpgp::packet::SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        mut decrypt: D,
    ) -> openpgp::Result<Option<openpgp::Fingerprint>>
    where
        D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool,
    {
        let p = &P::new();
        // Read the following
        // https://docs.sequoia-pgp.org/src/sequoia_openpgp/packet/pkesk.rs.html#139
        // Try each PKESK until we succeed.
        for pkesk in pkesks {
            if let Some(key) = self.keys.get(pkesk.recipient()) {
                let mut pair = scard::KeyPair::new(self.pin.clone(), key)?;
                let fp = Some(pair.public().fingerprint());
                if pkesk
                    .decrypt(&mut pair, sym_algo)
                    .map(|(algo, session_key)| decrypt(algo, &session_key))
                    .unwrap_or(false)
                {
                    return Ok(fp);
                }
            }
        }

        Ok(None)
    }
}
impl VerificationHelper for YuBi {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
        Ok(vec![]) // Feed the Certs to the verifier here.
    }
    fn check(&mut self, _structure: MessageStructure) -> openpgp::Result<()> {
        Ok(())
    }
}

#[pyfunction]
fn decrypt_bytes_on_card(
    _py: Python,
    data: Vec<u8>,
    pin: Vec<u8>,
    certdata: Vec<u8>,
) -> PyResult<PyObject> {
    //let keys: HashMap<openpgp::KeyID, String> = HashMap::new();
    //for (key, val) in keys_from_py.iter() {
    //let kid: openpgp::KeyID = key.parse().unwrap();
    //keys.insert(kid, val.clone());
    //}
    let p = P::new();

    let mut result = Vec::new();
    let reader = std::io::BufReader::new(&data[..]);

    let dec = DecryptorBuilder::from_reader(reader);
    let dec2 = match dec {
        Ok(dec) => dec,
        Err(msg) => {
            return Err(PySystemError::new_err(format!(
                "Can not create decryptor: {}",
                msg
            )))
        }
    };
    let mut decryptor = match dec2.with_policy(&p, None, YuBi::new(&p, certdata, pin)) {
        Ok(decr) => decr,
        Err(msg) => return Err(PyValueError::new_err(format!("Failed to decrypt: {}", msg))),
    };
    std::io::copy(&mut decryptor, &mut result).unwrap();
    let res = PyBytes::new(_py, &result);
    Ok(res.into())
}

#[pyfunction]
fn reset_yubikey() -> PyResult<bool> {
    let card = talktosc::create_connection();
    let card = match card {
        Ok(card) => card,
        Err(value) => return Err(CardError::new_err(format!("{}", value))),
    };

    let select_openpgp = apdus::create_apdu_select_openpgp();
    let resp = talktosc::send_and_parse(&card, select_openpgp);
    match resp {
        Ok(_) => (),
        Err(value) => return Err(CardError::new_err(format!("{}", value))),
    }

    let badpin = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    // First kill pw1
    for _i in 0..3 {
        let badpw1 = apdus::create_apdu_verify_pw1_for_others(badpin.clone());
        let resp = talktosc::send_and_parse(&card, badpw1);
        match resp {
            Ok(_) => (),
            Err(value) => return Err(CardError::new_err(format!("{}", value))),
        }
    }
    // next kill pw3 (admin pin)
    for _i in 0..3 {
        let badpw3 = apdus::create_apdu_verify_pw3(badpin.clone());
        let resp = talktosc::send_and_parse(&card, badpw3);
        match resp {
            Ok(_) => (),
            Err(value) => return Err(CardError::new_err(format!("{}", value))),
        }
    }

    let kill = vec![0x00, 0xE6, 0x00, 0x00, 0x00];
    let iapdus = vec![kill.clone()];
    let opgp_kill = apdus::APDU {
        cla: 0x00,
        ins: 0xE6,
        p1: 0x00,
        p2: 0x00,
        data: vec![0x00],
        iapdus,
    };
    talktosc::send_and_parse(&card, opgp_kill).unwrap();

    let activate = vec![0x00, 0x44, 0x00, 0x00, 0x00];
    let iapdus = vec![activate.clone()];
    let opgp_activate = apdus::APDU {
        cla: 0x00,
        ins: 0x44,
        p1: 0x00,
        p2: 0x00,
        data: vec![0x00],
        iapdus,
    };
    talktosc::send_and_parse(&card, opgp_activate).unwrap();

    Ok(true)
}

#[pyfunction]
fn get_card_details(py: Python) -> PyResult<PyObject> {
    let card = talktosc::create_connection();
    let card = match card {
        Ok(card) => card,
        Err(value) => return Err(CardError::new_err(format!("{}", value))),
    };

    let select_openpgp = apdus::create_apdu_select_openpgp();
    let resp = talktosc::send_and_parse(&card, select_openpgp);
    match resp {
        Ok(_) => (),
        Err(value) => return Err(CardError::new_err(format!("{}", value))),
    }
    // Now let us get the serial number
    let resp = talktosc::send_and_parse(&card, apdus::create_apdu_get_aid());
    let resp = match resp {
        Ok(resp) => resp,
        Err(value) => return Err(CardError::new_err(format!("{}", value))),
    };

    let pd = PyDict::new(py);
    pd.set_item("serial_number", tlvs::parse_card_serial(resp.get_data()))
        .unwrap();
    // Now the name of the card holder
    let resp = talktosc::send_and_parse(&card, apdus::create_apdu_personal_information());
    let resp = match resp {
        Ok(resp) => resp,
        Err(value) => return Err(CardError::new_err(format!("{}", value))),
    };

    let personal = tlvs::read_list(resp.get_data(), true)[0].clone();
    let name = String::from_utf8(personal.get_name().unwrap()).unwrap();
    pd.set_item("name", name).unwrap();

    // Let us get the URL of the public key
    let url_apdu = apdus::APDU::new(0x00, 0xCA, 0x5F, 0x50, None);
    let resp = talktosc::send_and_parse(&card, url_apdu);
    let resp = match resp {
        Ok(resp) => resp,
        Err(value) => return Err(CardError::new_err(format!("{}", value))),
    };
    let url = String::from_utf8(resp.get_data()).unwrap();
    pd.set_item("url", url).unwrap();

    // Now, we will get the whole of AID
    let mut aiddata: Vec<u8> = Vec::new();

    let mut resp =
        talktosc::send_and_parse(&card, apdus::create_apdu_get_application_data()).unwrap();
    aiddata.extend(resp.get_data());
    // This means we have more data to read.
    while resp.sw1 == 0x61 {
        let apdu = apdus::create_apdu_for_reading(resp.sw2.clone());

        resp = talktosc::send_and_parse(&card, apdu).unwrap();
        aiddata.extend(resp.get_data());
    }
    // Now we have all the data in aiddata
    let tlv = &tlvs::read_list(aiddata, true)[0];
    let sigdata = tlv.get_fingerprints().unwrap();
    let (sig_f, enc_f, auth_f) = tlvs::parse_fingerprints(sigdata);
    pd.set_item("sig_f", sig_f).unwrap();
    pd.set_item("enc_f", enc_f).unwrap();
    pd.set_item("auth_f", auth_f).unwrap();
    // Disconnect
    talktosc::disconnect(card);
    Ok(pd.into())
}

/// Change user pin (PW1)
#[pyfunction]
#[text_signature = "(adminpin, newpin)"]
pub fn change_user_pin(adminpin: Vec<u8>, newpin: Vec<u8>) -> PyResult<bool> {
    // check for minimum length of 6 chars
    if newpin.len() < 6 {
        return Err(PyValueError::new_err(
            "The new pin should be 6 chars length minimum.",
        ));
    }
    let pw3_apdu = talktosc::apdus::create_apdu_verify_pw3(adminpin);
    let newuserpin_apdu = talktosc::apdus::create_apdu_change_pw1(newpin);

    match scard::set_data(pw3_apdu, newuserpin_apdu) {
        Ok(value) => Ok(value),
        Err(value) => Err(CardError::new_err(format!("Error {}", value))),
    }
}

/// Change admin pin (PW3)
#[pyfunction]
#[text_signature = "(adminpin, newadminpin)"]
pub fn change_admin_pin(adminpin: Vec<u8>, newadminpin: Vec<u8>) -> PyResult<bool> {
    // check for minimum length of 6 chars
    if newadminpin.len() < 8 {
        return Err(PyValueError::new_err(
            "The new pin should be 6 chars length minimum.",
        ));
    }
    let newadminpin_apdu = talktosc::apdus::create_apdu_change_pw3(adminpin, newadminpin);

    match scard::chagne_admin_pin(newadminpin_apdu) {
        Ok(value) => Ok(value),
        Err(value) => Err(CardError::new_err(format!("Error {}", value))),
    }
}

/// Sets the name of the card holder.
/// Requires the name as bytes in b"surname<<Firstname" format, and should be less than 39 in size.
/// Also requires the admin pin in bytes.
#[pyfunction]
#[text_signature = "(name, pin)"]
pub fn set_name(name: Vec<u8>, pin: Vec<u8>) -> PyResult<bool> {
    let pw3_apdu = talktosc::apdus::create_apdu_verify_pw3(pin);
    let name_apdu = talktosc::apdus::APDU::new(0x00, 0xDA, 0x00, 0x5B, Some(name));

    match scard::set_data(pw3_apdu, name_apdu) {
        Ok(value) => Ok(value),
        Err(value) => Err(CardError::new_err(format!("Error {}", value))),
    }
}

/// Sets the URL of the public key of the card.
/// Requires the URL as buytes
/// Also requires the admin pin in bytes.
#[pyfunction]
#[text_signature = "(url, pin)"]
pub fn set_url(url: Vec<u8>, pin: Vec<u8>) -> PyResult<bool> {
    let pw3_apdu = talktosc::apdus::create_apdu_verify_pw3(pin);
    let url_apdu = talktosc::apdus::APDU::new(0x00, 0xDA, 0x5F, 0x50, Some(url));

    match scard::set_data(pw3_apdu, url_apdu) {
        Ok(value) => Ok(value),
        Err(value) => Err(CardError::new_err(format!("Error {}", value))),
    }
}

struct Helper {
    keys: HashMap<openpgp::KeyID, KeyPair>,
}

impl Helper {
    /// Creates a Helper for the given Certs with appropriate secrets.
    fn new(p: &dyn Policy, cert: &openpgp::Cert, pass: &str) -> Self {
        // Map (sub)KeyIDs to secrets.
        let mut keys = HashMap::new();

        for ka in cert.keys().with_policy(p, None).secret() {
            // To find the secret keypair
            let keypair = match ka.key().clone().secret().is_encrypted() {
                true => {
                    // When the secret is encrypted with a password
                    ka.key()
                        .clone()
                        .decrypt_secret(&openpgp::crypto::Password::from(pass))
                        .unwrap()
                        .into_keypair()
                        .unwrap()
                }
                false => {
                    // When the secret is not encrypted
                    ka.key().clone().into_keypair().unwrap()
                }
            };
            keys.insert(ka.key().keyid(), keypair.clone());
        }
        Helper { keys }
    }
}

impl DecryptionHelper for Helper {
    fn decrypt<D>(
        &mut self,
        pkesks: &[openpgp::packet::PKESK],
        _skesks: &[openpgp::packet::SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        mut decrypt: D,
    ) -> openpgp::Result<Option<openpgp::Fingerprint>>
    where
        D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool,
    {
        // Try each PKESK until we succeed.
        for pkesk in pkesks {
            let keyid = pkesk.recipient();
            // The following was done to extract the actual encrypted session key.
            // So that we can verify our code by just decrypt that on smartcard
            //let esk = pkesk.esk();
            //match esk {
            //openpgp::crypto::mpi::Ciphertext::RSA { c: myvalue } => {
            //let mut file = File::create("foo2.binary")?;
            //let value = myvalue.value();
            //file.write_all(&value[..]).unwrap();
            //}
            //_ => (),
            //};
            // If the keyid is not present, we should just skip to next pkesk
            let keypair = match self.keys.get_mut(&keyid) {
                Some(keypair) => keypair,
                _ => {
                    continue;
                }
            };
            let fp = keypair.public().fingerprint();
            // now get the algo
            if pkesk
                .decrypt(keypair, sym_algo)
                .map(|(algo, session_key)| decrypt(algo, &session_key))
                .unwrap_or(false)
            {
                return Ok(Some(fp));
            }
        }
        Ok(None)
    }
}

impl VerificationHelper for Helper {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
        Ok(vec![]) // Feed the Certs to the verifier here.
    }
    fn check(&mut self, _structure: MessageStructure) -> openpgp::Result<()> {
        Ok(())
    }
}

struct VHelper {
    cert: openpgp::Cert,
}

impl VHelper {
    /// Creates a VHelper for the given Cert for signature verification.
    fn new(cert: &openpgp::Cert) -> Self {
        let cloned = cert.clone();
        VHelper { cert: cloned }
    }
}

impl VerificationHelper for VHelper {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
        Ok(vec![self.cert.clone()]) // Feed the Certs to the verifier here.
    }
    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        let mut good = false;
        for (i, layer) in structure.into_iter().enumerate() {
            match (i, layer) {
                // First, we are interested in signatures over the
                // data, i.e. level 0 signatures.
                (0, MessageLayer::SignatureGroup { results }) => {
                    // Finally, given a VerificationResult, which only says
                    // whether the signature checks out mathematically, we apply
                    // our policy.
                    match results.into_iter().next() {
                        Some(Ok(_)) => good = true,
                        Some(Err(e)) => return Err(openpgp::Error::from(e).into()),
                        None => return Err(anyhow::anyhow!("No signature")),
                    }
                }
                _ => return Err(anyhow::anyhow!("Unexpected message structure")),
            }
        }

        if good {
            Ok(()) // Good signature.
        } else {
            Err(anyhow::anyhow!("Signature verification failed"))
        }
    }
}

// To create key pairs; from the given Cert
fn get_keys(cert: &openpgp::cert::Cert, password: String) -> Vec<openpgp::crypto::KeyPair> {
    let p = P::new();

    let mut keys = Vec::new();
    for key in cert
        .keys()
        .with_policy(&p, None)
        .alive()
        .revoked(false)
        .for_signing()
        .secret()
        .map(|kd| kd.key())
    {
        let mut key = key.clone();
        let algo = key.pk_algo();

        let _keypair = key
            .secret_mut()
            .decrypt_in_place(algo, &openpgp::crypto::Password::from(password.clone()))
            .expect("decryption failed");
        keys.push(key.into_keypair().unwrap());
    }
    keys
}

#[pyfunction]
pub fn sign_bytes_detached_on_card(
    certdata: Vec<u8>,
    data: Vec<u8>,
    pin: Vec<u8>,
) -> PyResult<String> {
    let mut localdata = io::Cursor::new(data);
    sign_internal_detached_on_card(certdata, &mut localdata, pin)
}

#[pyfunction]
pub fn sign_file_detached_on_card(
    certdata: Vec<u8>,
    filepath: Vec<u8>,
    pin: Vec<u8>,
) -> PyResult<String> {
    let file = Path::new(str::from_utf8(&filepath[..]).unwrap());
    let mut localdata = File::open(file)?;
    sign_internal_detached_on_card(certdata, &mut localdata, pin)
}
// This is the internal function which signs either bytes or an input file on the smartcard
fn sign_internal_detached_on_card(
    certdata: Vec<u8>,
    input: &mut dyn io::Read,
    pin: Vec<u8>,
) -> PyResult<String> {
    let policy = &P::new();
    // This is where we will store all the signing keys
    let mut keys: Vec<scard::KeyPair> = Vec::new();
    let cert = openpgp::Cert::from_bytes(&certdata).unwrap();
    // Note: We are only selecting subkeys for signing via card
    for ka in cert
        .keys()
        .with_policy(policy, None)
        .subkeys()
        .alive()
        .revoked(false)
        .for_signing()
    {
        let key = ka.key();
        let pair = scard::KeyPair::new(pin.clone(), key).unwrap();
        keys.push(pair);
    }
    let mut result = Vec::new();
    let mut sink = armor::Writer::new(&mut result, armor::Kind::Signature)
        .expect("Failed to create armored writer.");

    // Stream an OpenPGP message.
    let message = Message::new(&mut sink);

    // Now, create a signer that emits the detached signature(s).
    let mut signer = Signer::new(message, keys.pop().expect("No key for signing"));
    for s in keys {
        signer = signer.add_signer(s);
    }
    let mut signer = signer.detached().build().expect("Failed to create signer");

    // Copy all the data.
    io::copy(input, &mut signer).expect("Failed to sign data");

    // Finally, teardown the stack to ensure all the data is written.
    signer.finalize().expect("Failed to write data");

    // Finalize the armor writer.
    sink.finalize().expect("Failed to write data");

    Ok(String::from_utf8(result).unwrap())
}

fn sign_bytes_detached_internal(
    cert: &openpgp::cert::Cert,
    input: &mut dyn io::Read,
    password: String,
) -> PyResult<String> {
    // TODO: WHY?
    let mut input = input;

    let mut keys = get_keys(cert, password);

    if keys.len() == 0 {
        return Err(PyAttributeError::new_err("No signing key is present."));
    }

    let mut result = Vec::new();
    let mut sink = armor::Writer::new(&mut result, armor::Kind::Signature)
        .expect("Failed to create armored writer.");

    // Stream an OpenPGP message.
    let message = Message::new(&mut sink);

    // Now, create a signer that emits the detached signature(s).
    let mut signer = Signer::new(message, keys.pop().expect("No key for signing"));
    for s in keys {
        signer = signer.add_signer(s);
    }
    let mut signer = signer.detached().build().expect("Failed to create signer");

    // Copy all the data.
    io::copy(&mut input, &mut signer).expect("Failed to sign data");

    // Finally, teardown the stack to ensure all the data is written.
    signer.finalize().expect("Failed to write data");

    // Finalize the armor writer.
    sink.finalize().expect("Failed to write data");

    Ok(String::from_utf8(result).unwrap())
}

#[pyfunction]
#[text_signature = "(certdata, newcertdata)"]
fn merge_keys(_py: Python, certdata: Vec<u8>, newcertdata: Vec<u8>) -> PyResult<PyObject> {
    let cert = openpgp::Cert::from_bytes(&certdata).unwrap();
    let newcert = openpgp::Cert::from_bytes(&newcertdata).unwrap();
    if cert == newcert {
        return Err(SameKeyError::new_err("Both keys are same. Can not merge."));
    }
    // Now let us merge the new one into old one.
    // Remember, the opposite is a security risk.
    let mergred_cert = cert.merge_public_and_secret(newcert).unwrap();
    let cert_packets = mergred_cert.armored().to_vec().unwrap();
    let res = PyBytes::new(_py, &cert_packets);
    return Ok(res.into());
}

/// This function takes a path to an encrypted message and tries to guess the keyids it was
/// encrypted for. Note: It will read through the whole file and not memory happy code. Use with
/// care.
#[pyfunction]
#[text_signature = "(filepath)"]
fn file_encrypted_for(_py: Python, filepath: String) -> PyResult<PyObject> {
    let mut ppr = PacketParser::from_file(filepath).unwrap();
    let plist = PyList::empty(_py);
    while let PacketParserResult::Some(pp) = ppr {
        // Get the packet out of the parser and start parsing the next
        // packet, recursing.
        let (packet, next_ppr) = pp.recurse().unwrap();
        ppr = next_ppr;

        if let Packet::PKESK(ps) = packet {
            let id = ps.recipient().to_hex();
            plist.append(id).unwrap();
        }
    }
    Ok(plist.into())
}

/// This function takes an encrypted message as bytes and tries to guess the keyids it was
/// encrypted for. Note: It will keep the whole content on memory and not memory happy code. Use
/// with care.
#[pyfunction]
#[text_signature = "(messagedata)"]
fn bytes_encrypted_for(_py: Python, messagedata: Vec<u8>) -> PyResult<PyObject> {
    let mut ppr = PacketParser::from_bytes(&messagedata[..]).unwrap();
    let plist = PyList::empty(_py);
    while let PacketParserResult::Some(pp) = ppr {
        // Get the packet out of the parser and start parsing the next
        // packet, recursing.
        let (packet, next_ppr) = pp.recurse().unwrap();
        ppr = next_ppr;

        if let Packet::PKESK(ps) = packet {
            let id = ps.recipient().to_hex();
            plist.append(id).unwrap();
        }
    }
    Ok(plist.into())
}

#[pyfunction]
#[text_signature = "(certdata)"]
fn get_pub_key(_py: Python, certdata: Vec<u8>) -> PyResult<String> {
    let cert = openpgp::Cert::from_bytes(&certdata).unwrap();
    let armored = cert.armored().to_vec().unwrap();
    Ok(String::from_utf8(armored).unwrap())
}

#[pyfunction]
#[text_signature = "(certdata, pin, password)"]
fn upload_to_smartcard(
    _py: Python,
    certdata: Vec<u8>,
    pin: Vec<u8>,
    password: String,
    whichkeys: u8,
) -> PyResult<bool> {
    let cert = openpgp::Cert::from_bytes(&certdata).unwrap();

    // whichkeys, 1 for encryption, 2 for signing, 4 for authentication
    // 3 - both enc and signing
    // 5 - both enc and authentication.
    // 6 - both signing and authentication
    // 7 - all three subkeys
    //

    // Here the keytype is something I decided
    // 1 -- encryption key
    // 2 -- singing key
    // 3 -- authentication key
    let mut result = false;
    if (whichkeys & 0x01) == 0x01 {
        result = parse_and_move_a_subkey(cert.clone(), 1, pin.clone(), password.clone())?;
    }

    if (whichkeys & 0x02) == 0x02 {
        result = parse_and_move_a_subkey(cert.clone(), 2, pin.clone(), password.clone())?;
    }
    if (whichkeys & 0x04) == 0x04 {
        result = parse_and_move_a_subkey(cert.clone(), 3, pin.clone(), password.clone())?;
    }
    Ok(result)
}

#[allow(unused)]
fn parse_and_move_a_subkey(
    cert: openpgp::Cert,
    keytype: i8,
    pin: Vec<u8>,
    password: String,
) -> PyResult<bool> {
    let policy = P::new();
    // To flag if it is a RSA key, or ECDH or EdDSA
    let mut what_kind_of_key = "";
    // These are for private keys
    // https://docs.sequoia-pgp.org/0.21.0/sequoia_openpgp/crypto/mpi/enum.SecretKeyMaterial.html
    let mut main_d: Option<openpgp::crypto::mpi::ProtectedMPI> = None;
    let mut main_p: Option<openpgp::crypto::mpi::ProtectedMPI> = None;
    let mut main_q: Option<openpgp::crypto::mpi::ProtectedMPI> = None;
    let mut main_u: Option<openpgp::crypto::mpi::ProtectedMPI> = None;
    let mut main_scalar: Option<openpgp::crypto::mpi::ProtectedMPI> = None;
    // Below are for public keys
    // https://docs.sequoia-pgp.org/0.21.0/sequoia_openpgp/crypto/mpi/enum.PublicKey.html
    let mut main_e: Option<openpgp::crypto::mpi::MPI> = None;
    let mut main_eq: Option<openpgp::crypto::mpi::MPI> = None;
    let mut main_curve: Option<openpgp::types::Curve> = None;
    // This is idiotic, but will do for now
    let mut main_e_for_second_use: Option<openpgp::crypto::mpi::MPI> = None;
    let mut main_n: Option<openpgp::crypto::mpi::MPI> = None;
    let mut ts = 0 as u64;

    let mut fp: Option<openpgp::Fingerprint> = None;
    let mut valid_ka = cert
        .keys()
        .subkeys()
        .with_policy(&policy, None)
        .secret()
        .alive()
        .revoked(false);
    valid_ka = match keytype {
        1 => valid_ka.for_storage_encryption(),
        2 => valid_ka.for_signing(),
        3 => valid_ka.for_authentication(),
        _ => return Err(PyValueError::new_err("wrong value for the keytype")),
    };
    for ka in valid_ka {
        // First let us get the value of e from the public key
        let public = ka.parts_as_public();
        match public.mpis().clone() {
            openpgp::crypto::mpi::PublicKey::RSA { ref e, ref n } => {
                main_e = Some(e.clone());
                main_e_for_second_use = Some(e.clone());
                main_n = Some(n.clone());
            }
            openpgp::crypto::mpi::PublicKey::ECDH { curve, q, .. } => {
                main_curve = Some(curve.clone());
                main_eq = Some(q.clone());
            }
            openpgp::crypto::mpi::PublicKey::EdDSA { curve, q } => {
                main_curve = Some(curve.clone());
                main_eq = Some(q.clone());
            }
            _ => (),
        }
        let key = ka
            .key()
            .clone()
            .decrypt_secret(&openpgp::crypto::Password::from(password.clone()))
            .unwrap();
        let ctime = key.creation_time();
        let dt: DateTime<Utc> = DateTime::from(ctime);
        ts = dt.timestamp() as u64;

        fp = Some(key.fingerprint());

        // NOTE: all integers has to converted via to_be_bytes, and then remove any extra 0 in the
        // front.
        //let dd: u32 = 65537;
        //dbg!(dd.to_be_bytes());

        if let Some(secrets) = key.optional_secret() {
            match secrets {
                openpgp::packet::key::SecretKeyMaterial::Unencrypted(ref u) => {
                    u.map(|mpis| match mpis.clone() {
                        openpgp::crypto::mpi::SecretKeyMaterial::RSA { d, p, q, u } => {
                            main_d = Some(d.clone());
                            main_p = Some(p.clone());
                            main_q = Some(q.clone());
                            main_u = Some(u.clone());
                            what_kind_of_key = "rsa";
                        }
                        openpgp::crypto::mpi::SecretKeyMaterial::ECDH { scalar } => {
                            main_scalar = Some(scalar.clone());
                            what_kind_of_key = "ECDH";
                        }
                        openpgp::crypto::mpi::SecretKeyMaterial::EdDSA { scalar } => {
                            main_scalar = Some(scalar.clone());
                            what_kind_of_key = "EdDSA";
                        }
                        _ => (),
                    });
                }
                _ => (),
            }
        }
    }
    let mut result: Vec<u8> = Vec::new();
    // Let us create the TLV for 5F48
    let mut for5f48: Vec<u8> = vec![0x5F, 0x48];
    // This is for the TLV 0x7F48
    let mut for7f48: Vec<u8> = Vec::new();
    // Now this encapsulates to 4D Tag
    let mut for4d: Vec<u8> = vec![0x4D];

    match what_kind_of_key {
        "rsa" => {
            // First the exponent
            let values: Vec<u8> = main_e.unwrap().value().iter().copied().collect();
            for value in values {
                result.push(value);
            }
            // Then the p
            let values: Vec<u8> = main_p.unwrap().value().iter().copied().collect();
            for value in values {
                result.push(value);
            }
            // Then the q
            let values: Vec<u8> = main_q.unwrap().value().iter().copied().collect();
            for value in values {
                result.push(value);
            }
            let len = result.len() as u16;
            // This is for the TLV 0x5F48
            if len > 0xFF {
                for5f48.push(0x82);
            } else {
                for5f48.push(0x81);
            }
            // Now we should add the length of the data in 2 bytes
            let length = len.to_be_bytes();
            for5f48.push(length[0]);
            for5f48.push(length[1]);
            for5f48.extend(result.iter());
            // For the TLV 0x7F48
            //
            for7f48 = vec![
                0x7F, 0x48, 0x0A, 0x91, 0x03, 0x92, 0x82, 0x01, 0x00, 0x93, 0x82, 0x01, 0x00,
            ];
        }
        "EdDSA" | "ECDH" => {
            let data: Vec<u8> = Vec::from(main_scalar.unwrap().value());
            let len = data.len() as u8;
            for5f48.push(len);
            for5f48.extend(data.iter());

            for7f48 = vec![0x7F, 0x48, 0x02, 0x92, len];
        }
        _ => (),
    }

    // check 4.4.3.12 Private Key Template for details
    //
    let mut maindata: Vec<u8> = match keytype {
        1 => vec![0xB8, 0x00],
        2 => vec![0xB6, 0x00],
        3 => vec![0xA4, 0x00],
        _ => return Err(PyValueError::new_err("wrong value for keytype")),
    };

    maindata.extend(for7f48.iter());
    maindata.extend(for5f48.iter());

    match what_kind_of_key {
        "rsa" => {
            let len = maindata.len() as u16;
            if len > 0xFF {
                for4d.push(0x82);
            } else {
                for4d.push(0x81);
            }
            // Now we should add the length of the data in 2 bytes
            let length = len.to_be_bytes();
            for4d.push(length[0]);
            for4d.push(length[1]);
        }
        "ECDH" | "EdDSA" => {
            let len = maindata.len() as u8;
            for4d.push(len);
        }
        _ => (),
    }
    for4d.extend(maindata.iter());

    let apdu = talktosc::apdus::APDU::create_big_apdu(0x00, 0xDB, 0x3F, 0xFF, for4d);

    // Here are the steps we have to do
    // First, verify admin pin (PW3)
    // Set algorithm attributes, see 4.4.3.9 Algorithm Attributes for details
    // Verify admin pin again
    // Put the key via big apdu (put_data)
    // Put the fingerprint (put_data)
    // Put the timestamp (put_data)

    let time_value: Vec<u8> = ts
        .to_be_bytes()
        .iter()
        .skip_while(|&&e| e == 0)
        .copied()
        .collect();
    let mut for_algo_attributes: Vec<u8> = vec![01];

    match what_kind_of_key {
        // Here we will create the algorithm attributes data
        "rsa" => {
            let n_value: Vec<u8> = main_n
                .unwrap()
                .bits()
                .to_be_bytes()
                .iter()
                .skip_while(|&&v| v == 0)
                .copied()
                .collect();
            let e_value: Vec<u8> = main_e_for_second_use
                .unwrap()
                .bits()
                .to_be_bytes()
                .iter()
                .skip_while(|&&v| v == 0)
                .copied()
                .collect();

            for_algo_attributes.extend(n_value);
            if e_value.len() == 1 {
                for_algo_attributes.push(0x00);
            }
            for_algo_attributes.extend(e_value);
            // Because right now we are only dealing with RSA:    00 = standard (e, p, q)
            for_algo_attributes.push(0x00);
        }

        "ECDH" => {
            for_algo_attributes = vec![
                0x12, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01,
            ];
        }
        "EdDSA" => {
            for_algo_attributes = vec![0x16, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01];
        }
        _ => (),
    }
    let algo_apdu = match keytype {
        1 => talktosc::apdus::APDU::create_big_apdu(0x00, 0xDA, 0x00, 0xC2, for_algo_attributes),
        2 => talktosc::apdus::APDU::create_big_apdu(0x00, 0xDA, 0x00, 0xC1, for_algo_attributes),
        3 => talktosc::apdus::APDU::create_big_apdu(0x00, 0xDA, 0x00, 0xC3, for_algo_attributes),
        _ => return Err(PyValueError::new_err("wrong value for keytype")),
    };
    // Details are in PUT DATA DO part in the spec 4.4.2
    let fp_p2 = match keytype {
        1 => 0xC8,
        2 => 0xC7,
        3 => 0xC9,
        _ => return Err(PyValueError::new_err("wrong value for keytype")),
    };
    let fp_apdu = talktosc::apdus::APDU::create_big_apdu(
        0x00,
        0xDA,
        0x00,
        fp_p2,
        fp.unwrap().as_bytes().iter().map(|&x| x).collect(),
    );
    let time_p2 = match keytype {
        1 => 0xCF,
        2 => 0xCE,
        3 => 0xD0,
        _ => return Err(PyValueError::new_err("wrong value for keytype")),
    };

    let time_apdu = talktosc::apdus::APDU::new(0x00, 0xDA, 0x00, time_p2, Some(time_value));
    let pw3_apdu = talktosc::apdus::create_apdu_verify_pw3(pin);

    match scard::move_subkey_to_card(pw3_apdu, algo_apdu, apdu, fp_apdu, time_apdu) {
        Ok(res) => Ok(res),
        Err(value) => Err(CardError::new_err(format!("{}", value))),
    }
    //dbg!(talktosc::tlvs::hexify(algo_apdu.iapdus[0].clone()));
    //dbg!(talktosc::tlvs::hexify(fp_apdu.iapdus[0].clone()));
    //dbg!(talktosc::tlvs::hexify(apdu.iapdus[0].clone()));
    //print!("\n\n\n");
    //Ok(true)
}

#[pyfunction]
#[text_signature = "(certpath)"]
fn parse_cert_file(
    py: Python,
    certpath: String,
) -> PyResult<(PyObject, String, bool, PyObject, PyObject, PyObject)> {
    let cert = openpgp::Cert::from_file(certpath).unwrap();
    internal_parse_cert(py, cert)
}

#[pyfunction]
#[text_signature = "(certpath)"]
fn parse_cert_bytes(
    py: Python,
    certdata: Vec<u8>,
) -> PyResult<(PyObject, String, bool, PyObject, PyObject, PyObject)> {
    let cert = openpgp::Cert::from_bytes(&certdata).unwrap();
    internal_parse_cert(py, cert)
}

fn internal_parse_cert(
    py: Python,
    cert: openpgp::Cert,
) -> PyResult<(PyObject, String, bool, PyObject, PyObject, PyObject)> {
    let p = P::new();
    let creationtime = match cert.primary_key().with_policy(&p, None) {
        Ok(value) => {
            let ctime = value.creation_time();
            let dt: DateTime<Utc> = DateTime::from(ctime);
            Some(PyDateTime::from_timestamp(py, dt.timestamp() as f64, None).unwrap())
        }
        _ => None,
    };

    let expirationtime = match cert.primary_key().with_policy(&p, None) {
        Ok(value) => match value.key_expiration_time() {
            Some(etime) => {
                let dt: DateTime<Utc> = DateTime::from(etime);
                let pd = Some(PyDateTime::from_timestamp(py, dt.timestamp() as f64, None).unwrap());
                pd
            }
            _ => None,
        },
        Err(txt) => {
            let mut err_msg = Vec::new();
            let eiters = txt.chain();
            for error in eiters {
                err_msg.push(error.to_string());
            }
            return Err(CryptoError::new_err(err_msg.join(", ")));
        }
    };
    let plist = PyList::empty(py);
    for ua in cert.userids() {
        let pd = PyDict::new(py);
        //println!("  {}", String::from_utf8_lossy(ua.value()));
        pd.set_item("value", String::from_utf8_lossy(ua.value()))
            .unwrap();
        // If we have a name part in the UID
        match ua.name() {
            Ok(value) => match value {
                Some(name) => {
                    pd.set_item("name", name).unwrap();
                }
                _ => (),
            },
            Err(_) => (),
        }
        // If we have a comment part in the UID
        match ua.comment() {
            Ok(value) => match value {
                Some(comment) => {
                    pd.set_item("comment", comment).unwrap();
                }
                _ => (),
            },
            Err(_) => (),
        }
        // If we have a email part in the UID
        match ua.email() {
            Ok(value) => match value {
                Some(email) => {
                    pd.set_item("email", email).unwrap();
                }
                _ => (),
            },
            Err(_) => (),
        }
        // If we have a URI part in the UID
        match ua.uri() {
            Ok(value) => match value {
                Some(uri) => {
                    pd.set_item("uri", uri).unwrap();
                }
                _ => (),
            },
            Err(_) => (),
        }
        plist.append(pd).unwrap();
    }

    let subkeys = PyList::empty(py);
    for ka in cert.keys().with_policy(&p, None).subkeys() {
        let expirationtime = match ka.key_expiration_time() {
            Some(etime) => {
                let dt: DateTime<Utc> = DateTime::from(etime);
                let pd = Some(PyDateTime::from_timestamp(py, dt.timestamp() as f64, None).unwrap());
                pd
            }
            _ => None,
        };

        let creationtime = {
            let dt: DateTime<Utc> = DateTime::from(ka.creation_time());
            let pd = Some(PyDateTime::from_timestamp(py, dt.timestamp() as f64, None).unwrap());
            pd
        };

        // To find what kind of subkey is this.
        let keytype = if ka.for_storage_encryption() | ka.for_transport_encryption() {
            String::from("encryption")
        } else if ka.for_signing() {
            String::from("signing")
        } else if ka.for_authentication() {
            String::from("authentication")
        } else {
            String::from("unknown")
        };

        // To check if it is revoked or not
        // Just the oppostie from the filter values in
        // https://docs.sequoia-pgp.org/1.0.0/sequoia_openpgp/cert/amalgamation/struct.ValidComponentAmalgamationIter.html#method.revoked
        let revoked = match ka.revocation_status() {
            RevocationStatus::Revoked(_) => true,
            RevocationStatus::CouldBe(_) => false,
            RevocationStatus::NotAsFarAsWeKnow => false,
        };
        subkeys
            .append((
                ka.keyid().to_hex(),
                ka.fingerprint().to_hex(),
                creationtime,
                expirationtime,
                keytype,
                revoked,
            ))
            .unwrap();
    }

    let othervalues = PyDict::new(py);
    othervalues
        .set_item("keyid", cert.primary_key().keyid().to_hex())
        .unwrap();
    othervalues.set_item("subkeys", subkeys).unwrap();

    Ok((
        plist.into(),
        cert.fingerprint().to_hex(),
        cert.is_tsk(),
        expirationtime.to_object(py),
        creationtime.to_object(py),
        othervalues.to_object(py),
    ))
}

/// This function takes a password and an userid as strings, returns a tuple of public and private
/// key and the fingerprint in hex. Remember to save the keys for future use.
#[pyfunction]
#[text_signature = "(password, userid, cipher, creation, expiration)"]
fn create_newkey(
    password: String,
    userids: Vec<String>,
    cipher: String,
    creation: i64,
    expiration: i64,
    subkeys_expiration: bool,
    whichkeys: u8,
) -> PyResult<(String, String, String)> {
    let mut cdt: Option<DateTime<Utc>> = None;
    // Default we create RSA4k keys
    let mut ciphervalue = CipherSuite::RSA4k;
    if cipher == String::from("RSA2k") {
        ciphervalue = CipherSuite::RSA2k;
    } else if cipher == String::from("Cv25519") {
        ciphervalue = CipherSuite::Cv25519;
    }

    let mut crtbuilder = CertBuilder::new()
        .set_cipher_suite(ciphervalue)
        .set_password(Some(openpgp::crypto::Password::from(password)));

    for uid in userids {
        crtbuilder = crtbuilder.add_userid(uid);
    }

    let crtbuilder = match creation {
        0 => crtbuilder,
        _ => {
            cdt = Some(DateTime::<Utc>::from_utc(
                NaiveDateTime::from_timestamp_opt(creation, 0).unwrap(),
                Utc,
            ));
            crtbuilder.set_creation_time(SystemTime::from(cdt.unwrap()))
        }
    };

    let crtbuilder = match expiration {
        0 => {
            let crtbuilder = if (whichkeys & 0x01) == 0x01 {
                crtbuilder.add_subkey(
                    KeyFlags::empty()
                        .set_storage_encryption()
                        .set_transport_encryption(),
                    None,
                    None,
                )
            } else {
                crtbuilder
            };
            let crtbuilder = if (whichkeys & 0x02) == 0x02 {
                crtbuilder.add_signing_subkey()
            } else {
                crtbuilder
            };
            let crtbuilder = if (whichkeys & 0x04) == 0x04 {
                crtbuilder.add_authentication_subkey()
            } else {
                crtbuilder
            };
            crtbuilder
        }

        // Let us calculate the creation time we used
        _ => {
            let validity = match cdt {
                Some(cdt) => Duration::new(expiration as u64 - cdt.timestamp() as u64, 0),

                None => Duration::new(
                    expiration as u64
                        - SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                    0,
                ),
            };
            if subkeys_expiration == false {
                crtbuilder.set_validity_period(validity)
            } else {
                let crtbuilder = if (whichkeys & 0x01) == 0x01 {
                    crtbuilder.add_subkey(
                        KeyFlags::empty()
                            .set_storage_encryption()
                            .set_transport_encryption(),
                        validity,
                        None,
                    )
                } else {
                    crtbuilder
                };
                let crtbuilder = if (whichkeys & 0x02) == 0x02 {
                    crtbuilder.add_subkey(KeyFlags::empty().set_signing(), validity, None)
                } else {
                    crtbuilder
                };

                let crtbuilder = if (whichkeys & 0x04) == 0x04 {
                    crtbuilder.add_subkey(KeyFlags::empty().set_authentication(), validity, None)
                } else {
                    crtbuilder
                };
                crtbuilder
            }
        }
    };

    let (cert, _) = crtbuilder.generate().unwrap();
    let mut buf = Vec::new();
    let mut buffer = Vec::new();

    let mut writer = Writer::new(&mut buf, Kind::SecretKey).unwrap();
    cert.as_tsk().serialize(&mut buffer).unwrap();
    writer.write_all(&buffer).unwrap();
    writer.finalize().unwrap();
    let armored = cert.armored().to_vec().unwrap();
    Ok((
        String::from_utf8(armored).unwrap(),
        String::from_utf8(buf).unwrap(),
        cert.fingerprint().to_hex(),
    ))
}

/// This function takes a list of public key paths, and encrypts the given data from the opened
/// filehandler in bytes to an output file. You can also pass boolen flag armor for armored output.
/// Always remember to open the file in the Python side in "rb" mode, so that the `read()` call can
/// return bytes.
#[pyfunction]
#[text_signature = "(publickeys, fh, output, armor=False)"]
fn encrypt_filehandler_to_file(
    _py: Python,
    publickeys: Vec<Vec<u8>>,
    fh: PyObject,
    output: Vec<u8>,
    armor: Option<bool>,
) -> PyResult<bool> {
    let data = fh.call_method(_py, "read", (), None).unwrap();
    let pbytes: &PyBytes = data.cast_as(_py).expect("Excepted bytes");
    let filedata: Vec<u8> = Vec::from(pbytes.as_bytes());
    return encrypt_bytes_to_file(publickeys, filedata, output, armor);
}

/// This function takes a list of public key paths, and encrypts the given data in bytes to an output
/// file. You can also pass boolen flag armor for armored output.
#[pyfunction]
#[text_signature = "(publickeys, data, output, armor=False)"]
fn encrypt_bytes_to_file(
    publickeys: Vec<Vec<u8>>,
    data: Vec<u8>,
    output: Vec<u8>,
    armor: Option<bool>,
) -> PyResult<bool> {
    let mut certs = Vec::new();
    for certdata in publickeys {
        certs.push(openpgp::Cert::from_bytes(&certdata).unwrap());
    }
    let mode = KeyFlags::empty().set_storage_encryption();

    let p = P::new();
    let recipients = certs.iter().flat_map(|cert| {
        cert.keys()
            .with_policy(&p, None)
            .alive()
            .revoked(false)
            .key_flags(&mode)
    });
    let mut outfile = File::create(str::from_utf8(&output[..]).unwrap()).unwrap();
    // TODO: Find better ways to write this code
    match armor {
        // For armored output file.
        Some(true) => {
            let mut sink = armor::Writer::new(&mut outfile, armor::Kind::Message).unwrap();
            // Stream an OpenPGP message.
            let message = Message::new(&mut sink);

            // We want to encrypt a literal data packet.
            let encryptor = match Encryptor::for_recipients(message, recipients).build() {
                Ok(value) => value,
                Err(_) => {
                    return Err(CryptoError::new_err("Can not encrypt."));
                }
            };

            let mut literal_writer = LiteralWriter::new(encryptor)
                .build()
                .expect("Failed to create literal writer");

            // Copy data to our writer stack to encrypt the data.
            literal_writer.write_all(&data).unwrap();

            // Finally, finalize the OpenPGP message by tearing down the
            // writer stack.
            literal_writer.finalize().unwrap();

            // Finalize the armor writer.
            sink.finalize().expect("Failed to write data");
        }
        _ => {
            let message = Message::new(&mut outfile);

            // We want to encrypt a literal data packet.
            let encryptor = Encryptor::for_recipients(message, recipients)
                .build()
                .expect("Failed to create encryptor");

            let mut literal_writer = LiteralWriter::new(encryptor)
                .build()
                .expect("Failed to create literal writer");

            // Copy data to our writer stack to encrypt the data.
            literal_writer.write_all(&data).unwrap();

            // Finally, finalize the OpenPGP message by tearing down the
            // writer stack.
            literal_writer.finalize().unwrap();
        }
    }

    Ok(true)
}

/// This function takes a list of public key paths, and encrypts the given filepath to an output
/// file. You can also pass boolen flag armor for armored output.
#[pyfunction]
#[text_signature = "(publickeys, filepath, output, armor=False)"]
fn encrypt_file_internal(
    publickeys: Vec<Vec<u8>>,
    filepath: Vec<u8>,
    output: Vec<u8>,
    armor: Option<bool>,
) -> PyResult<bool> {
    let mut certs = Vec::new();
    for certdata in publickeys {
        certs.push(openpgp::Cert::from_bytes(&certdata).unwrap());
    }

    let mode = KeyFlags::empty().set_storage_encryption();

    let p = &P::new();
    let recipients = certs.iter().flat_map(|cert| {
        cert.keys()
            .with_policy(p, None)
            .alive()
            .revoked(false)
            .key_flags(&mode)
    });

    let mut input = File::open(str::from_utf8(&filepath[..]).unwrap()).unwrap();
    let mut outfile = File::create(str::from_utf8(&output[..]).unwrap()).unwrap();
    // TODO: Find better ways to write this code
    match armor {
        // For armored output file.
        Some(true) => {
            let mut sink = armor::Writer::new(&mut outfile, armor::Kind::Message).unwrap();
            // Stream an OpenPGP message.
            let message = Message::new(&mut sink);

            // We want to encrypt a literal data packet.
            let encryptor = Encryptor::for_recipients(message, recipients)
                .build()
                .expect("Failed to create encryptor");

            let mut literal_writer = LiteralWriter::new(encryptor)
                .build()
                .expect("Failed to create literal writer");

            // Copy stdin to our writer stack to encrypt the data.
            io::copy(&mut input, &mut literal_writer).expect("Failed to encrypt");
            //literal_writer.write_all(&data).unwrap();

            // Finally, finalize the OpenPGP message by tearing down the
            // writer stack.
            literal_writer.finalize().unwrap();

            // Finalize the armor writer.
            sink.finalize().expect("Failed to write data");
        }
        _ => {
            let message = Message::new(&mut outfile);

            // We want to encrypt a literal data packet.
            let encryptor = Encryptor::for_recipients(message, recipients)
                .build()
                .expect("Failed to create encryptor");

            let mut literal_writer = LiteralWriter::new(encryptor)
                .build()
                .expect("Failed to create literal writer");

            // Copy stdin to our writer stack to encrypt the data.
            io::copy(&mut input, &mut literal_writer).expect("Failed to encrypt");
            //literal_writer.write_all(&data).unwrap();

            // Finally, finalize the OpenPGP message by tearing down the
            // writer stack.
            literal_writer.finalize().unwrap();
        }
    }

    Ok(true)
}

/// This function takes a list of public key paths, and encrypts the given data in bytes and returns it.
/// You can also pass boolen flag armor for armored output.
#[pyfunction]
#[text_signature = "(publickeys, data, armor=False)"]
fn encrypt_bytes_to_bytes(
    py: Python,
    publickeys: Vec<Vec<u8>>,
    data: Vec<u8>,
    armor: Option<bool>,
) -> PyResult<PyObject> {
    let mut certs = Vec::new();
    for certdata in publickeys {
        certs.push(openpgp::Cert::from_bytes(&certdata).unwrap());
    }

    let mode = KeyFlags::empty().set_storage_encryption();

    let p = P::new();
    let recipients = certs.iter().flat_map(|cert| {
        cert.keys()
            .with_policy(&p, None)
            .alive()
            .revoked(false)
            .key_flags(&mode)
    });
    // TODO: Find better way to do this in rust
    let mut result = Vec::new();
    let mut result2 = Vec::new();
    let mut sink = armor::Writer::new(&mut result2, armor::Kind::Message)?;
    // Stream an OpenPGP message.
    let message = match armor {
        Some(true) => Message::new(&mut sink),
        _ => Message::new(&mut result),
    };
    // We want to encrypt a literal data packet.
    let encryptor = Encryptor::for_recipients(message, recipients)
        .build()
        .expect("Failed to create encryptor");

    let mut literal_writer = LiteralWriter::new(encryptor)
        .build()
        .expect("Failed to create literal writer");

    // Copy stdin to our writer stack to encrypt the data.
    // io::copy(&mut data, &mut literal_writer).expect("Failed to encrypt");
    literal_writer.write_all(&data).unwrap();

    // Finally, finalize the OpenPGP message by tearing down the
    // writer stack.
    literal_writer.finalize().unwrap();

    match armor {
        Some(true) => {
            // Finalize the armor writer.
            sink.finalize().expect("Failed to write data");
            let res = PyBytes::new(py, &result2);
            return Ok(res.into());
        }
        _ => {
            let res = PyBytes::new(py, &result);
            return Ok(res.into());
        }
    }
}

#[pyclass(module="johnnycanencrypt")]
#[derive(Debug)]
struct Johnny {
    cert: openpgp::cert::Cert,
}

#[pymethods]
impl Johnny {
    #[new]
    fn new(certdata: Vec<u8>) -> PyResult<Self> {
        let cert = openpgp::Cert::from_bytes(&certdata).unwrap();
        Ok(Johnny { cert })
    }

    pub fn encrypt_bytes(
        &self,
        py: Python,
        data: Vec<u8>,
        armor: Option<bool>,
    ) -> PyResult<PyObject> {
        let mode = KeyFlags::empty().set_storage_encryption();
        let p = P::new();
        let recipients = self
            .cert
            .keys()
            .with_policy(&p, None)
            .alive()
            .revoked(false)
            .key_flags(&mode);
        // TODO: Find better way to do this in rust
        let mut result = Vec::new();
        let mut result2 = Vec::new();
        let mut sink = armor::Writer::new(&mut result2, armor::Kind::Message)?;
        // Stream an OpenPGP message.
        let message = match armor {
            Some(true) => Message::new(&mut sink),
            _ => Message::new(&mut result),
        };
        // We want to encrypt a literal data packet.
        let encryptor = Encryptor::for_recipients(message, recipients)
            .build()
            .expect("Failed to create encryptor");

        let mut literal_writer = LiteralWriter::new(encryptor)
            .build()
            .expect("Failed to create literal writer");

        // Copy stdin to our writer stack to encrypt the data.
        // io::copy(&mut data, &mut literal_writer).expect("Failed to encrypt");
        literal_writer.write_all(&data).unwrap();

        // Finally, finalize the OpenPGP message by tearing down the
        // writer stack.
        literal_writer.finalize().unwrap();

        match armor {
            Some(true) => {
                // Finalize the armor writer.
                sink.finalize().expect("Failed to write data");
                let res = PyBytes::new(py, &result2);
                return Ok(res.into());
            }
            _ => {
                let res = PyBytes::new(py, &result);
                return Ok(res.into());
            }
        }
    }

    pub fn decrypt_bytes(&self, py: Python, data: Vec<u8>, password: String) -> PyResult<PyObject> {
        let p = P::new();

        let mut result = Vec::new();
        let reader = std::io::BufReader::new(&data[..]);

        let dec = DecryptorBuilder::from_reader(reader);
        let dec2 = match dec {
            Ok(dec) => dec,
            Err(msg) => {
                return Err(PySystemError::new_err(format!(
                    "Can not create decryptor: {}",
                    msg
                )))
            }
        };
        let mut decryptor = match dec2.with_policy(&p, None, Helper::new(&p, &self.cert, &password))
        {
            Ok(decr) => decr,
            Err(msg) => return Err(PyValueError::new_err(format!("Failed to decrypt: {}", msg))),
        };
        std::io::copy(&mut decryptor, &mut result).unwrap();
        let res = PyBytes::new(py, &result);
        Ok(res.into())
    }
    pub fn encrypt_file(
        &self,
        filepath: Vec<u8>,
        output: Vec<u8>,
        armor: Option<bool>,
    ) -> PyResult<bool> {
        let mode = KeyFlags::empty().set_storage_encryption();
        let p = &P::new();
        let recipients = self
            .cert
            .keys()
            .with_policy(p, None)
            .alive()
            .revoked(false)
            .key_flags(&mode);
        let mut input = File::open(str::from_utf8(&filepath[..]).unwrap()).unwrap();
        let mut outfile = File::create(str::from_utf8(&output[..]).unwrap()).unwrap();
        // TODO: Find better ways to write this code
        match armor {
            // For armored output file.
            Some(true) => {
                let mut sink = armor::Writer::new(&mut outfile, armor::Kind::Message).unwrap();
                // Stream an OpenPGP message.
                let message = Message::new(&mut sink);

                // We want to encrypt a literal data packet.
                let encryptor = Encryptor::for_recipients(message, recipients)
                    .build()
                    .expect("Failed to create encryptor");

                let mut literal_writer = LiteralWriter::new(encryptor)
                    .build()
                    .expect("Failed to create literal writer");

                // Copy stdin to our writer stack to encrypt the data.
                io::copy(&mut input, &mut literal_writer).expect("Failed to encrypt");
                //literal_writer.write_all(&data).unwrap();

                // Finally, finalize the OpenPGP message by tearing down the
                // writer stack.
                literal_writer.finalize().unwrap();

                // Finalize the armor writer.
                sink.finalize().expect("Failed to write data");
            }
            _ => {
                let message = Message::new(&mut outfile);

                // We want to encrypt a literal data packet.
                let encryptor = Encryptor::for_recipients(message, recipients)
                    .build()
                    .expect("Failed to create encryptor");

                let mut literal_writer = LiteralWriter::new(encryptor)
                    .build()
                    .expect("Failed to create literal writer");

                // Copy stdin to our writer stack to encrypt the data.
                io::copy(&mut input, &mut literal_writer).expect("Failed to encrypt");
                //literal_writer.write_all(&data).unwrap();

                // Finally, finalize the OpenPGP message by tearing down the
                // writer stack.
                literal_writer.finalize().unwrap();
            }
        }

        Ok(true)
    }

    pub fn decrypt_file(
        &self,
        filepath: Vec<u8>,
        output: Vec<u8>,
        password: String,
    ) -> PyResult<bool> {
        let p = P::new();

        let input = File::open(str::from_utf8(&filepath[..]).unwrap()).unwrap();
        let mut outfile = File::create(str::from_utf8(&output[..]).unwrap()).unwrap();

        let mut decryptor = DecryptorBuilder::from_reader(input)
            .unwrap()
            .with_policy(&p, None, Helper::new(&p, &self.cert, &password))
            .unwrap();
        std::io::copy(&mut decryptor, &mut outfile).unwrap();
        Ok(true)
    }

    pub fn decrypt_filehandler(
        &self,
        _py: Python,
        fh: PyObject,
        output: Vec<u8>,
        password: String,
    ) -> PyResult<bool> {
        let p = P::new();

        let filedata = fh.call_method(_py, "read", (), None).unwrap();
        let pbytes: &PyBytes = filedata.cast_as(_py).expect("Excepted bytes");
        let data: Vec<u8> = Vec::from(pbytes.as_bytes());

        let reader = std::io::BufReader::new(&data[..]);
        let dec = DecryptorBuilder::from_reader(reader);
        let dec2 = match dec {
            Ok(dec) => dec,
            Err(msg) => {
                return Err(PySystemError::new_err(format!(
                    "Can not create decryptor: {}",
                    msg
                )))
            }
        };
        let mut decryptor = match dec2.with_policy(&p, None, Helper::new(&p, &self.cert, &password))
        {
            Ok(decr) => decr,
            Err(msg) => return Err(CryptoError::new_err(format!("Failed to decrypt: {}", msg))),
        };

        let mut outfile = File::create(str::from_utf8(&output[..]).unwrap()).unwrap();

        std::io::copy(&mut decryptor, &mut outfile).unwrap();
        Ok(true)
    }

    pub fn sign_bytes_detached(&self, data: Vec<u8>, password: String) -> PyResult<String> {
        let mut localdata = io::Cursor::new(data);
        sign_bytes_detached_internal(&self.cert, &mut localdata, password)
    }

    pub fn sign_file_detached(&self, filepath: Vec<u8>, password: String) -> PyResult<String> {
        let file = Path::new(str::from_utf8(&filepath[..]).unwrap());
        let mut localdata = File::open(file).unwrap();
        sign_bytes_detached_internal(&self.cert, &mut localdata, password)
    }

    pub fn verify_bytes(&self, data: Vec<u8>, sig: Vec<u8>) -> PyResult<bool> {
        let p = P::new();
        let vh = VHelper::new(&self.cert);
        let mut v = DetachedVerifierBuilder::from_bytes(&sig[..])
            .unwrap()
            .with_policy(&p, None, vh)
            .unwrap();
        match v.verify_bytes(data) {
            Ok(()) => return Ok(true),
            Err(_) => return Ok(false),
        };
    }
    pub fn verify_file(&self, filepath: Vec<u8>, sig: Vec<u8>) -> PyResult<bool> {
        let p = P::new();
        let vh = VHelper::new(&self.cert);
        let mut v = DetachedVerifierBuilder::from_bytes(&sig[..])
            .unwrap()
            .with_policy(&p, None, vh)
            .unwrap();
        let path = Path::new(str::from_utf8(&filepath[..]).unwrap());
        match v.verify_file(path) {
            Ok(()) => return Ok(true),
            Err(_) => return Ok(false),
        };
    }
}

#[pyfunction]
pub fn is_smartcard_connected() -> PyResult<bool> {
    match scard::is_smartcard_connected() {
        Ok(value) => Ok(value),
        Err(_) => Ok(false),
    }
}


/// A Python module implemented in Rust.
#[pymodule]
fn johnnycanencrypt(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_wrapped(wrap_pyfunction!(is_smartcard_connected))?;
    m.add_wrapped(wrap_pyfunction!(reset_yubikey))?;
    m.add_wrapped(wrap_pyfunction!(change_admin_pin))?;
    m.add_wrapped(wrap_pyfunction!(change_user_pin))?;
    m.add_wrapped(wrap_pyfunction!(sign_bytes_detached_on_card))?;
    m.add_wrapped(wrap_pyfunction!(sign_file_detached_on_card))?;
    m.add_wrapped(wrap_pyfunction!(set_name))?;
    m.add_wrapped(wrap_pyfunction!(set_url))?;
    m.add_wrapped(wrap_pyfunction!(get_card_details))?;
    m.add_wrapped(wrap_pyfunction!(decrypt_bytes_on_card))?;
    m.add_wrapped(wrap_pyfunction!(create_newkey))?;
    m.add_wrapped(wrap_pyfunction!(upload_to_smartcard))?;
    m.add_wrapped(wrap_pyfunction!(get_pub_key))?;
    m.add_wrapped(wrap_pyfunction!(bytes_encrypted_for))?;
    m.add_wrapped(wrap_pyfunction!(file_encrypted_for))?;
    m.add_wrapped(wrap_pyfunction!(merge_keys))?;
    m.add_wrapped(wrap_pyfunction!(encrypt_filehandler_to_file))?;
    m.add_wrapped(wrap_pyfunction!(parse_cert_file))?;
    m.add_wrapped(wrap_pyfunction!(parse_cert_bytes))?;
    m.add_wrapped(wrap_pyfunction!(encrypt_bytes_to_file))?;
    m.add_wrapped(wrap_pyfunction!(encrypt_bytes_to_bytes))?;
    m.add_wrapped(wrap_pyfunction!(encrypt_file_internal))?;
    m.add("CryptoError", _py.get_type::<CryptoError>())?;
    m.add("SameKeyError", _py.get_type::<SameKeyError>())?;
    m.add_class::<Johnny>()?;
    Ok(())
}
