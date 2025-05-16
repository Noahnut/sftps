use pyo3::prelude::*;
use std::net::TcpStream;
use std::io::{BufRead, BufReader, Error, ErrorKind, Read, Write};
use crate::errors::FtpError;
use crate::codes::FtpCode;
use crate::codes::FtpCommand;
use crate::codes::FtpOpts;
use crate::codes::FtpType;
use std::time::Duration;
use log::debug;
use std::fs::File;

enum TransferMode {
    Passive,
    Active,
}



#[derive(Default)]
struct FtpConnection {
    ftp_write_stream: Option<TcpStream>,
    ftp_read_stream: Option<BufReader<TcpStream>>,
    passive_mode_connect_info: (String, u16),
}

struct DataConnection {
    read_stream: BufReader<TcpStream>,
    write_stream: Option<TcpStream>,
}

impl Drop for DataConnection {
    fn drop(&mut self) {
        if let Ok(stream) = self.read_stream.get_ref().try_clone() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    }
}


#[pyclass]
#[derive(Default, Clone)]
pub struct FtpOptions {
    pub host: String,
    pub port: u16,
    pub passive_mode: bool,
    pub username: String,
    pub password: String,
    pub timeout: u64,
}


impl FtpOptions {
    pub fn new(host: String, port: u16, passive_mode: bool, username: String, password: String, timeout: u64) -> Self {
        Self {
            host,
            port,
            passive_mode,
            username,
            password,
            timeout,
        }
    }
}


pub struct _FtpClient {
    options: FtpOptions,
    connection: FtpConnection,
    transfer_mode: TransferMode,
}


impl _FtpClient {
    pub fn new() -> Self {
        Self {
            options: FtpOptions::default(),
            connection: FtpConnection::default(),
            transfer_mode: TransferMode::Passive,
        }
    }
    pub fn connect(&mut self, options: FtpOptions) -> Result<(), FtpError> {
        self.options = options;

        debug!("Connecting to {} on port {}", self.options.host.clone(), self.options.port);

        match TcpStream::connect(format!("{}:{}", self.options.host.clone(), self.options.port)) {
            Ok(stream) => {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(self.options.timeout)));
                self.connection.ftp_write_stream = Some(stream.try_clone().unwrap());
                self.connection.ftp_read_stream = Some(BufReader::new(stream));
                
                let response = self.read_response()?;
                if !response.starts_with(FtpCode::Ready.as_str()) {
                    return Err(FtpError::ConnectError(Error::new(ErrorKind::Other, "Failed to connect to FTP server")));
                }

                debug!("<--- {}", response);

                if self.options.passive_mode == false {
                    self.transfer_mode = TransferMode::Active;
                }

                Ok(())
            }
            Err(e) => Err(FtpError::ConnectError(e)),
        }
    }

    pub fn login(&mut self, username: &str, password: &str) -> Result<(), FtpError> {
        debug!("---> {}", FtpCommand::Opts(FtpOpts::UTF8(true)));

        self.send_command(FtpCommand::Opts(FtpOpts::UTF8(true)))?;

        let response = self.read_response()?;

        debug!("<--- {}", response);

        if !response.starts_with(FtpCode::OptsSuccess.as_str()) {
            return Err(FtpError::ConnectError(Error::new(ErrorKind::Other, "Failed to set UTF8 mode")));
        }

        debug!("---> {}", FtpCommand::User(username.to_string()));

        self.send_command(FtpCommand::User(username.to_string()))?;
        let response = self.read_response()?;

        if !response.starts_with(FtpCode::NeedPassword.as_str()) {
            return Err(FtpError::LoginError(response));
        }

        debug!("<--- {}", response);

        debug!("---> {}", FtpCommand::Pass("*****".to_string()));

        self.send_command(FtpCommand::Pass(password.to_string()))?;
        let response = self.read_response()?;

        debug!("<--- {}", response);

        if !response.starts_with(FtpCode::LoginSuccess.as_str()) {
            return Err(FtpError::LoginError(response));
        }

        Ok(())
    }

    pub fn pwd(&mut self) -> Result<String, FtpError> {
        self.send_command(FtpCommand::Pwd)?;
        let response = self.read_response()?;

        if !response.starts_with(FtpCode::MkdPwdSuccess.as_str()) {
            return Err(FtpError::PwdError(response));
        }

        let pwd_response = response.split("\"").nth(1).unwrap().split("\"")
            .next()
            .unwrap();

        Ok(pwd_response.to_string())
    }

    pub fn mkdir(&mut self, path: &str) -> Result<(), FtpError> {

        self.send_command(FtpCommand::Mkd(path.to_string()))?;

        let response = self.read_response()?;

        if !response.starts_with(FtpCode::MkdPwdSuccess.as_str()) {
            return Err(FtpError::MkdError(response));
        }

        Ok(())
    }

    pub fn list_details(&mut self) -> Result<Vec<String>, FtpError> {

        let mut connection = match self.data_connect_establish() {
            Ok(conn) => conn,
            Err(e) => return Err(e),
        };

        self.send_command(FtpCommand::List)?;
        
        let response = self.read_data_response(&mut connection)?;

        let file_list = response.split("\r\n").
        map(|line| line.to_string()).
        filter(|line| line.len() > 0).
        collect();
        
        debug!("{:?}", file_list);

        Ok(file_list)
    }

    pub fn list_files(&mut self) -> Result<Vec<String>, FtpError> {
        let mut connection = match self.data_connect_establish() {
            Ok(conn) => conn,
            Err(e) => return Err(e),
        };

        self.send_command(FtpCommand::Nlst)?;

        
        let response = self.read_data_response(&mut connection)?;

        debug!("{}", response);

        let file_list = response.split("\r\n").
        map(|line| line.to_string()).
        filter(|line| line.len() > 0).
        collect();
        

        Ok(file_list)
    }

    pub fn retr(&self, _remote_file: &str, _local_file: &str) -> Result<(), FtpError> {
        Ok(())
    }

    pub fn stor(&mut self, _local_file: &str, _remote_file: &str) -> Result<(), FtpError> {
        let connection = match self.data_connect_establish() {
            Ok(conn) => conn,
            Err(e) => return Err(e),
        };

        self.send_command(FtpCommand::Type(FtpType::Binary))?;

        let response = self.read_response()?;

        if !response.starts_with(FtpCode::OptsSuccess.as_str()) {
            return Err(FtpError::SetBinaryModeError(response));
        }

        self.send_command(FtpCommand::Stor(_remote_file.to_string()))?;

        let response = self.read_response()?;

        if !response.starts_with(FtpCode::StartDataConnection.as_str()) {
            return Err(FtpError::UploadFileError(response));
        }

        let mut file = File::open(_local_file).map_err(|e   | FtpError::UploadFileError(e.to_string()))?;
        let mut buffer = [0; 1024];
        while let Ok(bytes_read) = file.read(&mut buffer) {
            if bytes_read == 0 {
                break;
            }
            connection.write_stream.as_ref().unwrap().write_all(&buffer[..bytes_read]).map_err(|e| FtpError::UploadFileError(e.to_string()))?;
        }

        connection.write_stream.as_ref().unwrap().flush().map_err(|e| FtpError::UploadFileError(e.to_string()))?;
        connection.write_stream.as_ref().unwrap().shutdown(std::net::Shutdown::Both).map_err(|e| FtpError::UploadFileError(e.to_string()))?;


        let response = self.read_response()?;

        if !response.starts_with(FtpCode::DataConnectionClose.as_str()) {
            return Err(FtpError::UploadFileError(response));
        }

        Ok(())
    }

    pub fn change_directory(&mut self, _directory: &str) -> Result<(), FtpError> {
        self.send_command(FtpCommand::Cwd(_directory.to_string()))?;
        let  response = self.read_response()?;

        if !response.starts_with(FtpCode::WorkDirCommandSuccess.as_str()) {
            return Err(FtpError::ChangeDirectoryError(response));
        }

        Ok(())
    }

    // TODO have flag to remove not empty directory
    pub fn remove_directory(&mut self, _directory: &str, _recursive: bool, _force: bool) -> Result<(), FtpError> {        
        self.send_command(FtpCommand::Rmd(_directory.to_string()))?;
        let response = self.read_response()?;

        if !response.starts_with(FtpCode::WorkDirCommandSuccess.as_str()) {
            return Err(FtpError::RemoveDirectoryError(response));
        }

        Ok(())
    }

    pub fn remove_file(&mut self, _file: &str) -> Result<(), FtpError> {
        self.send_command(FtpCommand::Dele(_file.to_string()))?;
        let response = self.read_response()?;

        if !response.starts_with(FtpCode::WorkDirCommandSuccess.as_str()) {
            return Err(FtpError::RemoveFileError(response));
        }

        Ok(())
    }

    fn send_command(&mut self, command: FtpCommand) -> Result<(), FtpError> {
        debug!("---> {}", command);

        let mut stream = self.connection.ftp_write_stream.as_ref().
                ok_or_else(|| FtpError::ConnectError(Error::new(ErrorKind::Other, "Failed to write to stream")))?;

        stream.write_all(command.to_string().as_bytes()).map_err(FtpError::ConnectError)?;
        stream.flush().map_err(FtpError::ConnectError)?;
        Ok(())
    }


    fn read_response(&mut self) -> Result<String, FtpError> {
        let mut response = String::new();
        self.connection.ftp_read_stream.as_mut().unwrap().read_line(&mut response).map_err(FtpError::ConnectError)?;
        debug!("<--- {}", response);
        Ok(response)
    }

    fn read_data_response(&mut self, connection: &mut DataConnection) -> Result<String, FtpError> {

        let command_response = self.read_response()?;

        if !command_response.starts_with(FtpCode::StartDataConnection.as_str()) {
            return Err(FtpError::ListDetailsError(command_response));
        }
        
        let mut response = String::new();
        connection.read_stream.read_line(&mut response).map_err(FtpError::ConnectError)?;

        let command_response = self.read_response()?;

        if !command_response.starts_with(FtpCode::DataConnectionClose.as_str()) {
            return Err(FtpError::ListDetailsError(command_response));
        }


        Ok(response)
    }

    fn data_connect_establish(&mut self) -> Result<DataConnection, FtpError> {
        match self.transfer_mode {
            TransferMode::Passive => {
                match self.passive_mode() {
                    Ok(_) => {
                        let stream = TcpStream::connect(
                            format!("{}:{}", self.connection.passive_mode_connect_info.0, 
                                                    self.connection.passive_mode_connect_info.1)).unwrap();
                        Ok(DataConnection {
                            read_stream: BufReader::new(stream.try_clone().unwrap()),
                            write_stream: Some(stream),
                        })
                    },
                    Err(e) => {
                        println!("Failed to establish passive mode will enter active mode: {}", e);
                        self.transfer_mode = TransferMode::Active;
                        return self.data_connect_establish();
                    },
                }
            }
            TransferMode::Active => {
                match self.active_mode() {
                    Ok(data_connection) => Ok(data_connection),
                    Err(e) => {
                        println!("Failed to establish active mode: {}", e);
                        Err(e)
                    }
                }
            }
        }
    }

    
    fn passive_mode(&mut self) -> Result<(), FtpError> {
        self.send_command(FtpCommand::Pasv)?;
        let response = self.read_response()?;
        if !response.starts_with(FtpCode::PassiveMode.as_str()) {
            return Err(FtpError::ConnectError(Error::new(ErrorKind::Other, "Failed to enter passive mode")));
        }

        debug!("{}", response);
        
        let pasv_response = response.split("(").nth(1).unwrap().split(")").next().unwrap();
        
        let mut host_vec = Vec::new();
        let mut port = 0;

        for (index, part) in pasv_response.split(",").enumerate() {
            let num: u8 = part.trim().parse().unwrap();
            match index {
                0_usize..=3_usize => {
                    host_vec.push(num);
                }
                4_usize..=5_usize => {
                    port = port * 256 + num as u16;
                }
                _ => {
                    return Err(FtpError::ParsePasvError());
                }
            }
        }

        self.connection.passive_mode_connect_info.0 = host_vec.iter().map(|num| num.to_string()).collect::<Vec<String>>().join(".");
        self.connection.passive_mode_connect_info.1 = port;

        if self.connection.passive_mode_connect_info.0 != self.options.host.clone() {
            debug!("Address returned by PASV {} seemed to be incorrect and has been fixed", self.connection.passive_mode_connect_info.0);
            self.connection.passive_mode_connect_info.0 = self.options.host.clone();
        }

        Ok(())
    }

    fn active_mode(&mut self) -> Result<DataConnection, FtpError> {
        todo!()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn init() {
        let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).try_init();
    }


    #[test]
    fn test_ftp_connect() {
        init();
        let mut client = _FtpClient::new();

        let options = FtpOptions::new("127.0.0.1".to_string(), 21, true, "user".to_string(), "pass".to_string(), 10);
        
        let result = client.connect(options);
        assert!(result.is_ok(), "Failed to connect to FTP server");

        let new_options = FtpOptions::new("nonexistent.server".to_string(), 21, true, "user".to_string(), "pass".to_string(), 10);
        
        let result = client.connect(new_options);
        assert!(result.is_err(), "Should fail to connect to non-existent server");
    }

    #[test]
    fn test_ftp_login() {
        init();
        let mut client = _FtpClient::new();
        let options = FtpOptions::new("127.0.0.1".to_string(), 21, true, "user".to_string(), "pass".to_string(), 10);
        
        let result = client.connect(options);
        assert!(result.is_ok(), "Failed to connect to FTP server");

        let result = client.login("user", "pass");
        assert!(result.is_ok(), "Failed to login to FTP server");
    }

    #[test]
    fn test_list_details() {
        init();
        let mut client = _FtpClient::new();
        let options = FtpOptions::new("127.0.0.1".to_string(), 21, true, "user".to_string(), "pass".to_string(), 10);
        
        let result = client.connect(options);
        assert!(result.is_ok(), "Failed to connect to FTP server");

        let result = client.login("user", "pass");
        assert!(result.is_ok(), "Failed to login to FTP server");

        let result = client.mkdir("test1");
        assert!(result.is_ok(), "Failed to make directory");

        let response = client.list_details();
        assert!(response.is_ok(), "Failed to list files");
        assert!(response.unwrap()[0].contains("test"), "Directory should be created");

        let result = client.remove_directory("test1", true, true);
        assert!(result.is_ok(), "Failed to remove directory");
    }

    #[test]
    fn test_pasv() {
        init();
        let mut client = _FtpClient::new();
        let options = FtpOptions::new("127.0.0.1".to_string(), 21, true, "user".to_string(), "pass".to_string(), 10);
        
        let result = client.connect(options);
        assert!(result.is_ok(), "Failed to connect to FTP server");

        let result = client.login("user", "pass");
        assert!(result.is_ok(), "Failed to login to FTP server");

        let result = client.passive_mode();
        assert!(result.is_ok(), "Failed to enter passive mode");
    }

    #[test]
    fn test_pwd() {
        init();
        let mut client = _FtpClient::new();
        let options = FtpOptions::new("127.0.0.1".to_string(), 21, true, "user".to_string(), "pass".to_string(), 10);

        let result = client.connect(options);
        assert!(result.is_ok(), "Failed to connect to FTP server");

        let result = client.login("user", "pass");
        assert!(result.is_ok(), "Failed to login to FTP server");

        let response = client.pwd();
        assert!(response.is_ok(), "Failed to get current directory");
        println!("{}", response.unwrap());
    }

    #[test]
    fn test_remove_directory() {
        init();
        let mut client = _FtpClient::new();

        let options = FtpOptions::new("127.0.0.1".to_string(), 21, true, "user".to_string(), "pass".to_string(), 10);
        
        let result = client.connect(options);
        assert!(result.is_ok(), "Failed to connect to FTP server"); 

        let result = client.login("user", "pass");
        assert!(result.is_ok(), "Failed to login to FTP server");

        let result = client.mkdir("test");
        assert!(result.is_ok(), "Failed to make directory");

        let response = client.remove_directory("test", true, true);
        assert!(response.is_ok(), "Failed to remove directory");

        let response = client.list_details();
        assert!(response.is_ok(), "Failed to list files");
        assert!(!response.unwrap()[0].contains("test"), "Directory should be removed");
    }

    #[test]
    fn test_mkdir() {
        init();
        let mut client = _FtpClient::new();

        let options = FtpOptions::new("127.0.0.1".to_string(), 21, true, "user".to_string(), "pass".to_string(), 10);
        
        let result = client.connect(options);
        assert!(result.is_ok(), "Failed to connect to FTP server");

        let result = client.login("user", "pass");
        assert!(result.is_ok(), "Failed to login to FTP server");

        let response = client.mkdir("test");
        assert!(response.is_ok(), "Failed to make directory");

        let response = client.list_details();
        assert!(response.is_ok(), "Failed to list files");
        assert!(response.unwrap()[0].contains("test"), "Directory should be created");

        let response = client.remove_directory("test", true, true);
        assert!(response.is_ok(), "Failed to remove directory");
    }

    #[test]
    fn test_list_files() {
        init();
        let mut client = _FtpClient::new();

        let options = FtpOptions::new("127.0.0.1".to_string(), 21, true, "user".to_string(), "pass".to_string(), 10);
        
        let result = client.connect(options);
        assert!(result.is_ok(), "Failed to connect to FTP server");
        
        let result = client.login("user", "pass");
        assert!(result.is_ok(), "Failed to login to FTP server");

        let response = client.list_files();
        assert!(response.is_ok(), "Failed to list files");
    }

    #[test]
    fn test_change_directory() {
        init();
        let mut client = _FtpClient::new();

        let options = FtpOptions::new("127.0.0.1".to_string(), 21, true, "user".to_string(), "pass".to_string(), 10);
        
        let result = client.connect(options);
        assert!(result.is_ok(), "Failed to connect to FTP server");

        let result = client.login("user", "pass");
        assert!(result.is_ok(), "Failed to login to FTP server");

        let result = client.mkdir("test2");
        assert!(result.is_ok(), "Failed to make directory");


        let response = client.change_directory("test2");
        assert!(response.is_ok(), "Failed to change directory");
        
        let response = client.pwd();
        assert!(response.is_ok(), "Failed to get current directory");
        assert!(response.unwrap().contains("test"), "Current directory should be test");

        let result = client.change_directory("..");
        assert!(result.is_ok(), "Failed to change directory");

        let response = client.pwd();
        assert!(response.is_ok(), "Failed to get current directory");
        assert!(response.unwrap().contains("/"), "Current directory should be .");
        
        let result = client.remove_directory("test", true, true);
        assert!(result.is_ok(), "Failed to remove directory");

        let response = client.pwd();
        assert!(response.is_ok(), "Failed to get current directory");
        assert!(!response.unwrap().contains("test"), "Current directory should not be test");
    }


    #[test]
    fn test_stor() {
        init();
        let mut client = _FtpClient::new();
        
        let options = FtpOptions::new("127.0.0.1".to_string(), 21, true, "user".to_string(), "pass".to_string(), 10);
        
        let result = client.connect(options);
        assert!(result.is_ok(), "Failed to connect to FTP server");

        let result = client.login("user", "pass");
        assert!(result.is_ok(), "Failed to login to FTP server");

        client.mkdir("test3").unwrap();

        let test_content = "Hello, this is a test file for FTP upload!";
        let test_file_path = "test_upload.txt";
        std::fs::write(test_file_path, test_content).expect("Failed to create test file");

        let result = client.stor(test_file_path, "test3/test_upload.txt");
        assert!(result.is_ok(), "Failed to upload file");

        let response = client.change_directory("test3");
        assert!(response.is_ok(), "Failed to change directory");

        let response = client.list_files();
        assert!(response.is_ok(), "Failed to list files");
        let file_list = response.unwrap();
        assert!(file_list.contains(&"test_upload.txt".to_string()), "File should be uploaded");

        let result = client.change_directory("..");
        assert!(result.is_ok(), "Failed to change directory");

        let result = client.remove_file("test3/test_upload.txt");
        assert!(result.is_ok(), "Failed to remove file");

        let response = client.list_files();
        assert!(response.is_ok(), "Failed to list files");
        let file_list = response.unwrap();
        assert!(!file_list.contains(&"test_upload.txt".to_string()), "File should be removed");

    }

    #[test]
    fn test_remove_file() {
        init();
        let mut client = _FtpClient::new();

        let options = FtpOptions::new("127.0.0.1".to_string(), 21, true, "user".to_string(), "pass".to_string(), 10);
        
        let result = client.connect(options);
        assert!(result.is_ok(), "Failed to connect to FTP server");

        let result = client.login("user", "pass");
        assert!(result.is_ok(), "Failed to login to FTP server");

        let result = client.mkdir("test2");
        assert!(result.is_ok(), "Failed to make directory");

        let test_content = "Hello, this is a test file for FTP upload!";
        let test_file_path = "test_upload.txt";
        std::fs::write(test_file_path, test_content).expect("Failed to create test file");

        let result = client.stor(test_file_path, "test2/test_upload.txt");
        assert!(result.is_ok(), "Failed to upload file");

        let response = client.change_directory("test2");
        assert!(response.is_ok(), "Failed to change directory"); 

        let result = client.remove_file("test_upload.txt");
        assert!(result.is_ok(), "Failed to remove file");

        let response = client.list_files();
        assert!(response.is_ok(), "Failed to list files");

        let file_list = response.unwrap();
        assert!(!file_list.contains(&"test_upload.txt".to_string()), "File should be removed");

        let response = client.change_directory("..");
        assert!(response.is_ok(), "Failed to change directory"); 

        let result = client.remove_directory("test2", true, true);
        assert!(result.is_ok(), "Failed to remove directory");
    }
}


