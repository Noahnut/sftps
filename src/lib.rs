use pyo3::prelude::*;
use py_ftp::FtpClient;


mod ftp;
mod errors;
mod codes;
mod py_ftp;
use log::info;
/// A Python module implemented in Rust.


#[pyfunction]
fn sftps_logger(level: &str) -> PyResult<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level)).try_init()
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("Failed to init logger: {}", e)))?;
    info!("Logger initialized");
    Ok(())
}


#[pymodule]
fn sftps(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(sftps_logger, m)?)?;
    m.add_class::<FtpClient>()?;
    Ok(())
}
