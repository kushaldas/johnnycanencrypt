// SPDX-FileCopyrightText: © 2020 Kushal Das <mail@kushaldas.in>
// SPDX-License-Identifier: LGPL-3.0-or-later

use crate::openpgp::packet::key;
use crate::openpgp::types::SymmetricAlgorithm;
use crate::KeySlot;
use openpgp::crypto;
use openpgp::packet::prelude::*;
use regex::Regex;
use sequoia_openpgp as openpgp;
use talktosc::*;

#[allow(unused)]
pub fn change_otp(enable: bool) -> Result<bool, errors::TalktoSCError> {
    let card = talktosc::create_connection();
    let card = match card {
        Ok(card) => card,
        Err(value) => return Err(value),
    };
    let select_mgmt = apdus::create_apdu_management_selection();
    let enable_apdu = apdus::create_usb_otp_enable();
    let disable_apdu = apdus::create_usb_otp_disable();
    let resp = talktosc::send_and_parse(&card, select_mgmt);
    let resp = match resp {
        Ok(_) => resp.unwrap(),
        Err(value) => {
            talktosc::disconnect(card);
            return Err(value);
        }
    };

    // Let us try to find the major and minor number for firmware
    let res = String::from_utf8(resp.data).unwrap();
    let re = Regex::new(r"(\d+)\.(\d+)\.(\d+)").unwrap();
    let caps = re.captures(&res);
    let (major, minor) = match caps {
        Some(caps) => {
            let major = caps
                .get(1)
                .map_or(0, |m| i8::from_str_radix(m.as_str(), 10).unwrap());

            let minor = caps
                .get(2)
                .map_or(0, |m| i8::from_str_radix(m.as_str(), 10).unwrap());
            (major, minor)
        }
        None => {
            talktosc::disconnect(card);
            return Err(errors::TalktoSCError::OtpError);
        }
    };

    // For Yubikey 4 we have to send in different data
    let send_apdu = if (major < 5) {
        // We assume these are the YubiKey 4
        let inside = if enable {
            apdus::APDU::new(0x00, 0x16, 0x11, 0x00, Some(vec![0x06, 0x00, 0x00, 0x00]))
        } else {
            apdus::APDU::new(0x00, 0x16, 0x11, 0x00, Some(vec![0x05, 0x00, 0x00, 0x00]))
        };
        inside
    } else {
        // We assume these are the YubiKey 5
        let inside = if enable { enable_apdu } else { disable_apdu };
        inside
    };
    // Send in the real APDU to the card
    let resp = talktosc::send_and_parse(&card, send_apdu);
    let resp = match resp {
        Ok(_) => resp.unwrap(),
        Err(value) => {
            talktosc::disconnect(card);
            return Err(value);
        }
    };

    // Verify if the otp enable/disable worked or not
    if !resp.is_okay() {
        talktosc::disconnect(card);
        return Err(errors::TalktoSCError::OtpError);
    }
    talktosc::disconnect(card);
    Ok(true)
}

// To change the admin pin
#[allow(unused)]
pub fn chagne_admin_pin(pw3change: apdus::APDU) -> Result<bool, errors::TalktoSCError> {
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
    let resp = talktosc::send_and_parse(&card, pw3change);
    let resp = match resp {
        Ok(_) => resp.unwrap(),
        Err(value) => {
            talktosc::disconnect(card);
            return Err(value);
        }
    };

    // Verify if the admin pin worked or not.
    if !resp.is_okay() {
        talktosc::disconnect(card);
        return Err(errors::TalktoSCError::PinError);
    }
    talktosc::disconnect(card);
    Ok(true)
}

// To get the touch policy of a given slot
#[allow(unused)]
pub fn get_touch_policy(slot: KeySlot) -> Result<Vec<u8>, errors::TalktoSCError> {
    let card = talktosc::create_connection();
    let card = match card {
        Ok(card) => card,
        Err(value) => return Err(value),
    };

    let select_openpgp = apdus::create_apdu_select_openpgp();
    let resp = talktosc::send_and_parse(&card, select_openpgp);
    let resp = match resp {
        Ok(_) => resp.unwrap(),
        Err(value) => return Err(value),
    };
    // Just make sure we can talk
    if !resp.is_okay() {
        return Err(errors::TalktoSCError::PinError);
    }
    // Now let us ask about the touch policy
    //
    let slot_value = slot as u8;
    let select_touchpolicy = apdus::APDU::new(0x00, 0xCA, 0x00, slot_value, None);
    let resp = talktosc::send_and_parse(&card, select_touchpolicy);
    let resp = match resp {
        Ok(_) => resp.unwrap(),
        Err(value) => {
            talktosc::disconnect(card);
            return Err(value);
        }
    };

    talktosc::disconnect(card);
    Ok(resp.get_data())
}

// To get the Yubikey card firmware version
#[allow(unused)]
pub fn internal_get_version() -> Result<Vec<u8>, errors::TalktoSCError> {
    let card = talktosc::create_connection();
    let card = match card {
        Ok(card) => card,
        Err(value) => return Err(value),
    };

    let select_openpgp = apdus::create_apdu_select_openpgp();
    let resp = talktosc::send_and_parse(&card, select_openpgp);
    let resp = match resp {
        Ok(_) => resp.unwrap(),
        Err(value) => {
            talktosc::disconnect(card);
            return Err(value);
        }
    };
    // Just make sure we can talk
    if !resp.is_okay() {
        talktosc::disconnect(card);
        return Err(errors::TalktoSCError::PinError);
    }
    // Now let us ask about version
    //
    let select_version = apdus::APDU::new(0x00, 0xF1, 0x00, 0x00, None);
    let resp = talktosc::send_and_parse(&card, select_version);
    let resp = match resp {
        Ok(_) => resp.unwrap(),
        Err(value) => {
            talktosc::disconnect(card);
            return Err(value);
        }
    };

    talktosc::disconnect(card);
    Ok(resp.get_data())
}

#[allow(unused)]
pub fn is_smartcard_connected() -> Result<bool, errors::TalktoSCError> {
    let card = talktosc::create_connection();
    let card = match card {
        Ok(card) => card,
        Err(value) => return Err(value),
    };

    let select_openpgp = apdus::create_apdu_select_openpgp();
    let resp = talktosc::send_and_parse(&card, select_openpgp);
    let resp = match resp {
        Ok(_) => resp.unwrap(),
        Err(value) => {
            talktosc::disconnect(card);
            return Err(value);
        }
    };
    // Verify if the admin pin worked or not.
    if !resp.is_okay() {
        talktosc::disconnect(card);
        return Err(errors::TalktoSCError::PinError);
    }

    talktosc::disconnect(card);
    Ok(true)
}

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
    let resp = talktosc::send_and_parse(&card, pw3_apdu);
    let resp = match resp {
        Ok(_) => resp.unwrap(),
        Err(value) => return Err(value),
    };

    // Verify if the admin pin worked or not.
    if !resp.is_okay() {
        return Err(errors::TalktoSCError::PinError);
    }

    let resp = talktosc::send_and_parse(&card, data);
    let resp = match resp {
        Ok(_) => resp.unwrap(),
        Err(value) => return Err(value),
    };

    if resp.is_okay() {
        return Ok(true);
    }

    // Should not reach here
    Ok(false)
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
    let resp = match resp {
        Ok(_) => resp.unwrap(),
        Err(value) => return Err(value),
    };

    // Verify if the admin pin worked or not.
    if !resp.is_okay() {
        return Err(errors::TalktoSCError::PinError);
    }

    // NOw the algo first
    let resp = talktosc::send_and_parse(&card, algo_apdu);
    match resp {
        Ok(_) => (),
        Err(value) => return Err(value),
    }

    // Another time pw3 verification
    let resp = talktosc::send_and_parse(&card, pw3_apdu);
    let resp = match resp {
        Ok(_) => resp.unwrap(),
        Err(value) => return Err(value),
    };

    // Verify if the admin pin worked or not.
    if !resp.is_okay() {
        return Err(errors::TalktoSCError::PinError);
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
        let apdu = apdus::create_apdu_for_reading(resp.sw2);

        resp = talktosc::send_and_parse(&card, apdu).unwrap();
        aiddata.extend(resp.get_data());
    }

    talktosc::disconnect(card);
    Ok(aiddata)
}

fn sign_hash_in_card(c: Vec<u8>, pin: Vec<u8>) -> Result<Vec<u8>, errors::TalktoSCError> {
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
    let resp = talktosc::send_and_parse(&card, apdus::create_apdu_verify_pw1_for_sign(pin));
    match resp {
        Ok(_) => (),
        Err(value) => return Err(value),
    }

    // Experiment code
    let mut iapdu: Vec<u8> = vec![0x00, 0x2A, 0x9E, 0x9A, c.len() as u8];
    iapdu.extend(c.iter());
    iapdu.push(0x00);
    let iapdus = vec![iapdu];

    let dapdu = apdus::APDU {
        cla: 0x00,
        ins: 0x21,
        p1: 0x9E,
        p2: 0x9A,
        data: c,
        iapdus,
    };

    let mut aiddata: Vec<u8> = Vec::new();

    let mut resp = talktosc::send_and_parse(&card, dapdu).unwrap();
    aiddata.extend(resp.get_data());
    // This means we have more data to read.
    while resp.sw1 == 0x61 {
        let apdu = apdus::create_apdu_for_reading(resp.sw2);

        resp = talktosc::send_and_parse(&card, apdu).unwrap();
        aiddata.extend(resp.get_data());
    }
    talktosc::disconnect(card);
    Ok(aiddata)
}

#[derive(Clone)]
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

#[allow(unused, non_snake_case)]
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
                Ok(sk)
            }
            (
                openpgp::crypto::mpi::Ciphertext::ECDH { ref e, .. },
                openpgp::crypto::mpi::PublicKey::ECDH { ref curve, .. },
            ) => {
                // Now page 68 of the openpgp smartcard spec 3.4.1
                // We have to build the DO properly.
                // The first byte of e is 40, we have to skip it.
                let values = e.value();
                let mut enc: Vec<u8> = Vec::new();
                enc.extend_from_slice(&values[1..33]);
                // Now we hardcode away everything for Cv25519
                //
                let mut c = vec![0xA6, 0x25, 0x7F, 0x49, 0x22, 0x86, 0x20];
                c.extend_from_slice(&enc[..]);
                c.push(0x00);

                // Send this for decryption on the card
                let dec = decrypt_the_secret_in_card(c, self.pin.clone())?;
                let S: openpgp::crypto::mem::Protected = dec.into();
                Ok(openpgp::crypto::ecdh::decrypt_unwrap(
                    self.public,
                    &S,
                    ciphertext,
                )?)
            }

            (ciphertext, public) => Err(openpgp::Error::InvalidOperation(format!(
                "unsupported combination of key pair {:?} \
                     and ciphertext {:?}",
                public, ciphertext
            ))
            .into()),
        }
    }
}
// TODO: This function needs refactoring
impl<'a> crypto::Signer for KeyPair<'a> {
    fn public(&self) -> &Key<key::PublicParts, key::UnspecifiedRole> {
        self.public
    }

    fn sign(
        &mut self,
        hash_algo: openpgp::types::HashAlgorithm,
        digest: &[u8],
    ) -> openpgp::Result<openpgp::crypto::mpi::Signature> {
        use crate::openpgp::crypto::mpi::PublicKey;
        use crate::openpgp::types::PublicKeyAlgorithm::*;

        #[allow(deprecated)]
        match (self.public.pk_algo(), self.public.mpis()) {
            (RSASign, PublicKey::RSA { .. }) | (RSAEncryptSign, PublicKey::RSA { .. }) => {
                match hash_algo {
                    openpgp::types::HashAlgorithm::SHA256 => {
                        let mut data_for_rsa = vec![
                            0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
                            0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
                        ];
                        data_for_rsa.extend(digest);
                        data_for_rsa.push(0x00);
                        let result = sign_hash_in_card(data_for_rsa, self.pin.clone())?;
                        let mpi = openpgp::crypto::mpi::MPI::new(&result[..]);
                        Ok(openpgp::crypto::mpi::Signature::RSA { s: mpi })
                    }
                    openpgp::types::HashAlgorithm::SHA512 => {
                        let mut data_for_rsa = vec![
                            0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
                            0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40,
                        ];
                        data_for_rsa.extend(digest);
                        let result = sign_hash_in_card(data_for_rsa, self.pin.clone())?;
                        let mpi = openpgp::crypto::mpi::MPI::new(&result[..]);
                        Ok(openpgp::crypto::mpi::Signature::RSA { s: mpi })
                    }
                    _ => Err(openpgp::Error::InvalidOperation(format!(
                        "unsupported combination of hash algorithm {:?} and key {:?}",
                        hash_algo, self.public
                    ))
                    .into()),
                }
            }
            (EdDSA, PublicKey::EdDSA { .. }) => {
                let data_for_eddsa: Vec<u8> = digest.to_vec();
                let result = sign_hash_in_card(data_for_eddsa, self.pin.clone())?;
                let r = openpgp::crypto::mpi::MPI::new(&result[..32]);
                let s = openpgp::crypto::mpi::MPI::new(&result[32..]);
                Ok(openpgp::crypto::mpi::Signature::EdDSA { r, s })
            }
            (pk_algo, _) => Err(openpgp::Error::InvalidOperation(format!(
                "unsupported combination of algorithm {:?} and key {:?}",
                pk_algo, self.public
            ))
            .into()),
        }
    }
}
