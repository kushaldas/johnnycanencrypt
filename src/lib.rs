use pyo3::prelude::*;
use std::io::Write;
use std::str;

extern crate sequoia_openpgp as openpgp;
use crate::openpgp::armor;
use crate::openpgp::parse::Parse;
use crate::openpgp::policy::StandardPolicy as P;
use crate::openpgp::serialize::stream::{Encryptor, LiteralWriter, Message};
use crate::openpgp::types::KeyFlags;

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
}

#[pymodule]
/// A Python module implemented in Rust.
fn johnnycanencrypt(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<Johnny>()?;
    Ok(())
}
