use crate::openpgp::packet::key;
use crate::openpgp::types::SymmetricAlgorithm;
use openpgp::crypto;
use openpgp::packet::prelude::*;
use sequoia_openpgp as openpgp;
use talktosc::*;


// Sets the name to the card
#[allow(unused)]
pub fn set_data(pw3_apdu: apdus::APDU, data: apdus::APDU) -> Result<bool, errors::TalktoSCError> {
    let card = talktosc::create_connection();
    let card = match card {
        Ok(card) => card,
        Err(value) => return Err(value),
    };

    let select_openpgp = apdus::create_apdu_select_openpgp();
    let resp = talktosc::send_and_parse(&card, select_openpgp);
    match resp {
        Ok(_) => (),
        Err(value) => return Err(value),
    }
    let resp = talktosc::send_and_parse(&card, pw3_apdu.clone());
    match resp {
        Ok(_) => (),
        Err(value) => return Err(value),
    }

    let resp = talktosc::send_and_parse(&card, data);
    match resp {
        Ok(_) => Ok(true),
        Err(value) => return Err(value),
    }

}

pub fn move_subkey_to_card(
    pw3_apdu: apdus::APDU,
    algo_apdu: apdus::APDU,
    apdu: apdus::APDU,
    fp_apdu: apdus::APDU,
    time_apdu: apdus::APDU,
) -> Result<bool, errors::TalktoSCError> {
    // NOw let us move the key to the card
    let card = talktosc::create_connection();
    let card = match card {
        Ok(card) => card,
        Err(value) => return Err(value),
    };

    let select_openpgp = apdus::create_apdu_select_openpgp();
    let resp = talktosc::send_and_parse(&card, select_openpgp);
    match resp {
        Ok(_) => (),
        Err(value) => return Err(value),
    }

    let resp = talktosc::send_and_parse(&card, pw3_apdu.clone());
    match resp {
        Ok(_) => (),
        Err(value) => return Err(value),
    }

    // NOw the algo first
    let resp = talktosc::send_and_parse(&card, algo_apdu);
    match resp {
        Ok(_) => (),
        Err(value) => return Err(value),
    }

    // Another time pw3 verification
    let resp = talktosc::send_and_parse(&card, pw3_apdu.clone());
    match resp {
        Ok(_) => (),
        Err(value) => return Err(value),
    }
    // Next the actual key
    let resp = talktosc::send_and_parse(&card, apdu);
    match resp {
        Ok(_) => (),
        Err(value) => return Err(value),
    }

    // Next is the fingerprint
    let resp = talktosc::send_and_parse(&card, fp_apdu);
    match resp {
        Ok(_) => (),
        Err(value) => return Err(value),
    }

    // Next is the creation time

    let resp = talktosc::send_and_parse(&card, time_apdu);
    match resp {
        Ok(_) => (),
        Err(value) => return Err(value),
    }
    talktosc::disconnect(card);
    Ok(true)
}

fn decrypt_the_secret_in_card(c: Vec<u8>, pin: Vec<u8>) -> Result<Vec<u8>, errors::TalktoSCError> {
    let card = talktosc::create_connection();
    let card = match card {
        Ok(card) => card,
        Err(value) => return Err(value),
    };

    let select_openpgp = apdus::create_apdu_select_openpgp();
    let resp = talktosc::send_and_parse(&card, select_openpgp);
    match resp {
        Ok(_) => (),
        Err(value) => return Err(value),
    }
    let resp = talktosc::send_and_parse(&card, apdus::create_apdu_verify_pw1_for_others(pin));
    match resp {
        Ok(_) => (),
        Err(value) => return Err(value),
    }

    let dapdu = apdus::create_apdu_for_decryption(c);
    let mut aiddata: Vec<u8> = Vec::new();

    let mut resp = talktosc::send_and_parse(&card, dapdu).unwrap();
    aiddata.extend(resp.get_data());
    // This means we have more data to read.
    while resp.sw1 == 0x61 {
        let apdu = apdus::create_apdu_for_reading(resp.sw2.clone());

        resp = talktosc::send_and_parse(&card, apdu).unwrap();
        aiddata.extend(resp.get_data());
    }

    talktosc::disconnect(card);
    Ok(Vec::from(aiddata))
}

pub struct KeyPair<'a> {
    public: &'a Key<key::PublicParts, key::UnspecifiedRole>,
    pin: Vec<u8>,
}

impl<'a> KeyPair<'a> {
    /// Returns a `KeyPair` for `key` with the secret bits managed by
    /// the smartcard.
    ///
    /// This provides a convenient, synchronous interface for use with
    /// the low-level Sequoia crate.
    pub fn new<R>(pin: Vec<u8>, key: &'a Key<key::PublicParts, R>) -> openpgp::Result<KeyPair<'a>>
    where
        R: key::KeyRole,
    {
        Ok(KeyPair {
            public: key.role_as_unspecified(),
            pin,
        })
    }
}

#[allow(unused)]
impl<'a> crypto::Decryptor for KeyPair<'a> {
    fn public(&self) -> &Key<key::PublicParts, key::UnspecifiedRole> {
        self.public
    }

    fn decrypt(
        &mut self,
        ciphertext: &crypto::mpi::Ciphertext,
        _plaintext_len: Option<usize>,
    ) -> openpgp::Result<crypto::SessionKey> {
        match (ciphertext, self.public.mpis().clone()) {
            (
                openpgp::crypto::mpi::Ciphertext::RSA { c: myvalue },
                openpgp::crypto::mpi::PublicKey::RSA { ref e, ref n },
            ) => {
                let c_ = if myvalue.value().len() < n.value().len() {
                    let mut c_ = vec![0; n.value().len() - myvalue.value().len()];
                    c_.extend_from_slice(myvalue.value());
                    c_
                } else {
                    // If it is bigger, then the packet is likely
                    // corrupted, tough luck then.
                    let mut c_ = vec![0];
                    c_.extend_from_slice(myvalue.value());
                    c_
                };
                // Now we have to decrypt c_ to decrypted value
                let dec = decrypt_the_secret_in_card(c_, self.pin.clone()).unwrap();
                let algo: SymmetricAlgorithm = dec[0].into();
                let length = dec.len();
                // First byte is the algo, and the last two bytes also not part of the key
                //
                // Sequoia needs the full thing, not the real session key like below
                //let sk = openpgp::crypto::SessionKey::from(&dec[1..length - 2]);
                let sk = openpgp::crypto::SessionKey::from(&dec[..]);
                return Ok(sk.clone());
            }

            (public, ciphertext) => Err(openpgp::Error::InvalidOperation(format!(
                "unsupported combination of key pair {:?} \
                     and ciphertext {:?}",
                public, ciphertext
            ))
            .into()),
        }
    }
}
