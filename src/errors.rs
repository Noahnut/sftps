use thiserror::Error;
use pyo3::prelude::*;

#[derive(Debug, Error)]
pub enum FtpError {
    #[error("Failed to connect to FTP server: {0}")]
    ConnectError(std::io::Error),

    #[error("Failed to login to FTP server: {0}")]
    LoginError(String),


    #[error("Failed to parse passive mode response")]
    ParsePasvError(),

    #[error("Failed to establish data connection: {0}")]
    DataConnectionError(String),

    #[error("Failed to get current directory: {0}")]
    PwdError(String),

    #[error("Failed to make directory: {0}")]
    MkdError(String),

    #[error("Failed to list files: {0}")]
    ListFilesError(String),

    #[error("Failed to list details: {0}")]
    ListDetailsError(String),

    #[error("Failed to change directory: {0}")]
    ChangeDirectoryError(String),

    #[error("Failed to remove directory: {0}")]
    RemoveDirectoryError(String),

    #[error("Failed to send command: {0}")]
    SendCommandError(String),

    #[error("Failed to set binary mode: {0}")]
    SetBinaryModeError(String),

    #[error("Failed to upload file: {0}")]
    UploadFileError(String),

    #[error("Failed to remove file: {0}")]
    RemoveFileError(String),

    #[error("Failed to download file: {0}")]
    DownloadFileError(String),

    #[error("Failed to connect to SSL: {0}")]
    SSLConnectionError(String),
}

impl From<FtpError> for PyErr {
    fn from(error: FtpError) -> Self {
        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(error.to_string())
    }
}

