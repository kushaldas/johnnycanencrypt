use pyo3::prelude::*;
use pyo3::types::PyBytes;

use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::io::prelude;
use std::io::Write;
use std::str;

extern crate sequoia_openpgp as openpgp;
use crate::openpgp::armor;
use crate::openpgp::crypto::{KeyPair, SessionKey};
use crate::openpgp::parse::stream::{
    DecryptionHelper, DecryptorBuilder, MessageStructure, VerificationHelper,
};
use crate::openpgp::parse::Parse;
use crate::openpgp::policy::NullPolicy as NP;
use crate::openpgp::policy::Policy;
use crate::openpgp::policy::StandardPolicy as P;
use crate::openpgp::serialize::stream::{Encryptor, LiteralWriter, Message, Signer};
use crate::openpgp::types::KeyFlags;
use crate::openpgp::types::SymmetricAlgorithm;

struct Helper {
    keys: HashMap<openpgp::KeyID, KeyPair>,
}

impl Helper {
    /// Creates a Helper for the given Certs with appropriate secrets.
    fn new(p: &dyn Policy, cert: &openpgp::Cert, pass: &str) -> Self {
        // Map (sub)KeyIDs to secrets.
        let mut keys = HashMap::new();

        for ka in cert.keys().with_policy(p, None).secret() {
            keys.insert(
                ka.key().keyid(),
                ka.key()
                    .clone()
                    .decrypt_secret(&openpgp::crypto::Password::from(pass))
                    .unwrap()
                    .into_keypair()
                    .unwrap(),
            );
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
            // If the keyid is not present, we should just skip to next pkesk
            let keypair = self.keys.get_mut(&keyid).unwrap();
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
        Ok(Vec::new()) // Feed the Certs to the verifier here.
    }
    fn check(&mut self, _structure: MessageStructure) -> openpgp::Result<()> {
        //for layer in structure.iter() {
        //match layer {
        //MessageLayer::Compression { algo } => eprintln!("Compressed using {}", algo),
        //MessageLayer::Encryption {
        //sym_algo,
        //aead_algo,
        //} => {
        //if let Some(aead_algo) = aead_algo {
        //eprintln!("Encrypted and protected using {}/{}", sym_algo, aead_algo);
        //} else {
        //eprintln!("Encrypted using {}", sym_algo);
        //}
        //}
        //MessageLayer::SignatureGroup { ref results } => {
        //for result in results {
        //match result {
        //Ok(GoodChecksum { ka, .. }) => {
        //eprintln!("Good signature from {}", ka.cert());
        //}
        //Err(e) => eprintln!("Error: {:?}", e),
        //}
        //}
        //}
        //}
        //}
        Ok(()) // Implement your verification policy here.
    }
}

// To create key pairs; from the given Cert
fn get_keys(cert: &openpgp::cert::Cert, password: String) -> Vec<openpgp::crypto::KeyPair> {
    let p = &P::new();
    let mut keys = Vec::new();
    for key in cert
        .keys()
        .with_policy(p, None)
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

fn sign_bytes_detached_internal(
    cert: &openpgp::cert::Cert,
    input: &mut dyn io::Read,
    password: String,
) -> PyResult<String> {
    // TODO: WHY?
    let mut input = input;

    let mut keys = get_keys(cert, password);

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

#[pyclass]
#[derive(Debug)]
struct Johnny {
    #[pyo3(get, set)]
    filepath: String,
    cert: openpgp::cert::Cert,
}

#[pymethods]
impl Johnny {
    #[new]
    fn new(filepath: String) -> Self {
        let cert = openpgp::Cert::from_file(&filepath).unwrap();
        Johnny { filepath, cert }
    }

    pub fn encrypt_bytes(&self, data: Vec<u8>) -> PyResult<String> {
        let mode = KeyFlags::default().set_storage_encryption(true);
        let p = &P::new();
        let recipients = self
            .cert
            .keys()
            .with_policy(p, None)
            .alive()
            .revoked(false)
            .key_flags(&mode);
        let mut result = Vec::new();
        let mut sink = armor::Writer::new(&mut result, armor::Kind::Message)?;
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
        // io::copy(&mut data, &mut literal_writer).expect("Failed to encrypt");
        literal_writer.write_all(&data).unwrap();

        // Finally, finalize the OpenPGP message by tearing down the
        // writer stack.
        literal_writer.finalize().unwrap();

        // Finalize the armor writer.
        sink.finalize().expect("Failed to write data");
        Ok(str::from_utf8(&result).unwrap().to_string())
    }

    pub fn decrypt_bytes(&self, py: Python, data: Vec<u8>, password: String) -> PyResult<PyObject> {
        let p = &NP::new();

        let mut result = Vec::new();
        let reader = std::io::BufReader::new(&data[..]);
        let mut decryptor = DecryptorBuilder::from_reader(reader)
            .unwrap()
            .with_policy(p, None, Helper::new(p, &self.cert, &password))
            .unwrap();
        std::io::copy(&mut decryptor, &mut result).unwrap();
        let res = PyBytes::new(py, &result);
        Ok(res.into())
    }

    pub fn sign_bytes_detached(&self, data: Vec<u8>, password: String) -> PyResult<String> {
        let mut localdata = io::Cursor::new(data);
        sign_bytes_detached_internal(&self.cert, &mut localdata, password)
    }

    pub fn sign_file_detached(&self, filepath: String, password: String) -> PyResult<String> {
        let mut localdata = File::open(filepath).unwrap();
        sign_bytes_detached_internal(&self.cert, &mut localdata, password)
    }


}

#[pymodule]
/// A Python module implemented in Rust.
fn johnnycanencrypt(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<Johnny>()?;
    Ok(())
}
