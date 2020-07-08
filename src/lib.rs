use pyo3::prelude::*;
use pyo3::types::PyDict;
use pyo3::wrap_pyfunction;

extern crate sequoia_openpgp as openpgp;
use crate::openpgp::parse::Parse;
use crate::openpgp::policy::StandardPolicy as P;

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
        Johnny { filepath, cert}
    }

}


#[pymodule]
/// A Python module implemented in Rust.
fn johnnycanencrypt(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<Johnny>()?;
    Ok(())
}
