use pyo3::prelude::*;
use crate::ftp::*;



#[pyclass]
pub struct FtpClient {
    ftp_client: _FtpClient,
}

#[pyclass]
pub enum FtpFileMetaDataType {
    Directory,
    File,
    Link,
    SymbolicLink,
    CharacterDevice,
    BlockDevice,
    Unknown,
}

#[pymethods]
impl FtpFileMetaDataType {
    fn __str__(&self) -> String {
        match self {
            FtpFileMetaDataType::Directory => "Directory".to_string(),
            FtpFileMetaDataType::File => "File".to_string(),
            FtpFileMetaDataType::Link => "Link".to_string(),
            FtpFileMetaDataType::SymbolicLink => "SymbolicLink".to_string(),
            FtpFileMetaDataType::CharacterDevice => "CharacterDevice".to_string(),
            FtpFileMetaDataType::BlockDevice => "BlockDevice".to_string(),
            FtpFileMetaDataType::Unknown => "Unknown".to_string(),
        }
    }
}

#[pyclass]
pub struct FtpFileMetaData {
    #[pyo3(get)]
    pub name: String,
    #[pyo3(get)]
    pub owner: String,
    #[pyo3(get)]
    pub group: String,
    #[pyo3(get)]
    pub size: u64,
    #[pyo3(get)]
    pub hard_link_count: u64,
    #[pyo3(get)]
    pub permissions: String,
    #[pyo3(get)]
    pub modified: String,
}

#[pymethods]
impl FtpFileMetaData {
    fn __str__(&self) -> String {
        format!("{} {} {} {} {} {} {}", self.permissions, self.size, self.hard_link_count, self.owner, self.group, self.modified, self.name)
    }

    pub fn get_type(&self) -> FtpFileMetaDataType {
        match self.permissions.chars().nth(0).unwrap() {
            'd' => FtpFileMetaDataType::Directory,
            '-' => FtpFileMetaDataType::File,
            'l' => FtpFileMetaDataType::Link,
            's' => FtpFileMetaDataType::SymbolicLink,
            'c' => FtpFileMetaDataType::CharacterDevice,
            _ => FtpFileMetaDataType::Unknown,
        }
    }
}

impl FtpFileMetaData {
    pub fn parse(line: &str) -> Option<Self> {
        let parts = line.split_whitespace().collect::<Vec<&str>>();

        Some(Self {
            name: parts[8].to_string(),
            hard_link_count: parts[1].parse().unwrap(),
            owner: parts[2].to_string(),
            group: parts[3].to_string(),
            size: parts[4].parse().unwrap(),
            permissions: parts[0].to_string(),
            modified: format!("{} {} {}", parts[5], parts[6], parts[7]),
        })
    }
}

#[pymethods]
impl FtpClient {
    #[new]
    pub fn new() -> Self {
        Self {
            ftp_client: _FtpClient::new()
        }
    }
    
    #[pyo3(signature = (host=None, port=None, username=None, password=None, timeout=None, passive_mode=None))]
    pub fn connect(&mut self, host: Option<String>,
                              port: Option<u16>, 
                              username: Option<String>, 
                              password: Option<String>, 
                              timeout: Option<u64>, 
                            passive_mode: Option<bool>) -> PyResult<()> {
        let options = FtpOptions::new(
            host.unwrap_or("127.0.0.1".to_string()),
            port.unwrap_or(21), passive_mode.unwrap_or(true),
            username.unwrap_or("user".to_string()), 
            password.unwrap_or("pass".to_string()), 
            timeout.unwrap_or(10));

        self.ftp_client.connect(options).map_err(Into::into)
    }

    pub fn login(&mut self, username: &str, password: &str) -> PyResult<()> {
        self.ftp_client.login(username, password).map_err(Into::into)
    }

    pub fn pwd(&mut self) -> PyResult<String> {
        self.ftp_client.pwd().map_err(Into::into)
    }

    pub fn list_files(&mut self) -> PyResult<Vec<String>> {
        self.ftp_client.list_files().map_err(Into::into)
    }

    pub fn list_details(&mut self) -> PyResult<Vec<FtpFileMetaData>> {        
        let list_details_result = self.ftp_client.list_details();

        if let Err(e) = list_details_result {
            return Err(e.into());
        }

        let file_list = list_details_result.unwrap().iter().
                                                    map(|line| FtpFileMetaData::parse(line)).
                                                    filter(|file| file.is_some()).
                                                    map(|file| file.unwrap()).
                                                    collect::<Vec<FtpFileMetaData>>();


        return Ok(file_list);
    }

    pub fn change_directory(&mut self, path: &str) -> PyResult<()> {
        self.ftp_client.change_directory(path).map_err(Into::into)
    }

    #[pyo3(signature = (path, recursive=None, force=None))]
    pub fn remove_directory(&mut self, path: &str, recursive: Option<bool>, force: Option<bool>) -> PyResult<()> {
        self.ftp_client.remove_directory(path, recursive.unwrap_or(false), force.unwrap_or(false)).map_err(Into::into)
    }

    pub fn create_directory(&mut self, path: &str) -> PyResult<()> {
        self.ftp_client.mkdir(path).map_err(Into::into)
    }

    pub fn remove_file(&mut self, path: &str) -> PyResult<()> {
        self.ftp_client.remove_file(path).map_err(Into::into)
    }

    pub fn upload_file(&mut self, local_path: &str, remote_path: &str) -> PyResult<()> {
        self.ftp_client.stor(local_path, remote_path).map_err(Into::into)
    }

    pub fn download_file(&mut self, remote_path: &str, local_path: &str) -> PyResult<()> {
        self.ftp_client.retr(remote_path, local_path).map_err(Into::into)
    }
}