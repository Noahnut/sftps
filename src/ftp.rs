use pyo3::prelude::*;
use std::net::TcpStream;
use std::io::{BufRead, BufReader, Error, ErrorKind, Read, Write};
use crate::errors::FtpError;
use crate::codes::{FtpCode, FtpCommand, FtpOpts, FtpType};
use std::time::Duration;
use log::debug;
use std::fs::File;
use rustls::{StreamOwned, ClientConnection, ClientConfig, RootCertStore};
use rustls::pki_types::{ServerName, CertificateDer};

use webpki_roots::TLS_SERVER_ROOTS;
use std::sync::Arc;
enum TransferMode {
    Passive,
    Active,
}

enum SecurityMode {
    TlsImplicit,
    TlsExplicit,
    None,
}

trait StreamWrapper: Send + Sync {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error>;
    fn read_line(&mut self, buf: &mut String) -> Result<usize, Error>;
    fn write(&mut self, buf: &[u8]) -> Result<usize, Error>;
    fn flush(&mut self) -> std::io::Result<()>;
    fn shutdown(&mut self) -> std::io::Result<()>;
    fn get_stream(&mut self) -> TcpStream;
}


struct TcpStreamWrapper {
    read_stream: Option<BufReader<TcpStream>>,
    write_stream: Option<TcpStream>,
}

impl StreamWrapper for TcpStreamWrapper {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        self.read_stream.as_mut().unwrap().read(buf)
    }

    fn read_line(&mut self, buf: &mut String) -> Result<usize, Error> {
        self.read_stream.as_mut().unwrap().read_line(buf)
    }

    fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
        self.write_stream.as_mut().unwrap().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.write_stream.as_mut().unwrap().flush()
    }

    fn shutdown(&mut self) -> std::io::Result<()> {
        self.write_stream.as_mut().unwrap().shutdown(std::net::Shutdown::Both)
    }

    fn get_stream(&mut self) -> TcpStream {
        self.write_stream.as_mut().unwrap().try_clone().unwrap()
    }
}

struct TlsStreamWrapper {
    tls_stream: Option<StreamOwned<ClientConnection, TcpStream>>,
}

impl StreamWrapper for TlsStreamWrapper {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        self.tls_stream.as_mut().unwrap().read(buf)
    }

    fn read_line(&mut self, buf: &mut String) -> Result<usize, Error> {
        self.tls_stream.as_mut().unwrap().read_line(buf)
    }

    fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
        self.tls_stream.as_mut().unwrap().write(buf)
    }      

    fn flush(&mut self) -> std::io::Result<()> {
        self.tls_stream.as_mut().unwrap().flush()
    }

    fn shutdown(&mut self) -> std::io::Result<()> {
        self.tls_stream.as_mut().unwrap().conn.send_close_notify();
        Ok(())
    }

    fn get_stream(&mut self) -> TcpStream {
        self.tls_stream.as_mut().unwrap().get_ref().try_clone().unwrap()
    }
}

struct TLSConnectionMeta {
    server_name: ServerName<'static>,
    tls_config: Option<ClientConfig>,
}

struct FtpConnection {
    control_stream: Box<dyn StreamWrapper>,
    passive_mode_connect_info: (String, u16),
    tls_meta: Option<TLSConnectionMeta>,
}

struct DataConnection {
    stream: Box<dyn StreamWrapper>,
}

impl Drop for DataConnection {
    fn drop(&mut self) {
        let _ = self.stream.shutdown(); 
        let _ = self.stream.flush();
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
    pub tls_pem: String,
}


impl FtpOptions {
    pub fn new(host: String, 
               port: u16, 
               passive_mode: bool, 
               username: String, 
               password: String, 
               timeout: u64,
               tls_pem: String) -> Self {
        Self {
            host,
            port,
            passive_mode,
            username,
            password,
            timeout,
            tls_pem,
        }
    }
}


pub struct _FtpClient {
    options: FtpOptions,
    connection: Option<FtpConnection>,
    security_mode: SecurityMode,
    transfer_mode: TransferMode,
}


impl _FtpClient {
    pub fn new() -> Self {
        Self {
            options: FtpOptions::default(),
            connection: None,
            transfer_mode: TransferMode::Passive,
            security_mode: SecurityMode::None,
        }
    }

    pub fn connect(&mut self, options: FtpOptions) -> Result<(), FtpError> {
        self.options = options;

        debug!("Connecting to {} on port {}", self.options.host.clone(), self.options.port);

        match TcpStream::connect(format!("{}:{}", self.options.host.clone(), self.options.port)) {
            Ok(stream) => {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(self.options.timeout)));
                self.connection = Some(FtpConnection {
                    control_stream: Box::new(TcpStreamWrapper {
                        read_stream: Some(BufReader::new(stream.try_clone().unwrap())),
                        write_stream: Some(stream),
                    }),
                    passive_mode_connect_info: (self.options.host.clone(), self.options.port),
                    tls_meta: None,
                });
                
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


    pub fn connect_tls_implicit(&mut self) -> Result<(), FtpError> {
        self.security_mode = SecurityMode::TlsImplicit;
        todo!()
    }

    pub fn connect_tls_explicit(&mut self, options: FtpOptions) -> Result<(), FtpError> {

       let r = self.connect(options);

       if r.is_err() {
            return Err(r.unwrap_err());
       }

       self.send_command(FtpCommand::AuthTLS)?;

       let response = self.read_response()?;

       debug!("<--- {}", response);

       if !response.starts_with(FtpCode::ReadyForTLS.as_str()) {
            return Err(FtpError::SSLConnectionError(response));
       }

       let mut root_store = RootCertStore::empty();
       root_store.extend(TLS_SERVER_ROOTS.iter().map(|cert| cert.clone()));

       if self.options.tls_pem.len() > 0 {
        let certs= CertificateDer::from_slice(self.options.tls_pem.as_bytes());
        root_store.add(certs).unwrap();
       }

       let server_name = ServerName::try_from(self.options.host.clone())
            .map_err(|e| FtpError::SSLConnectionError(e.to_string()))?;

        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        self.connection.as_mut().unwrap().tls_meta = Some(TLSConnectionMeta {
            server_name: server_name.clone(),
            tls_config: Some(config.clone()),
        });

        let connection = ClientConnection::new(Arc::new(config), server_name)
            .map_err(|e| FtpError::SSLConnectionError(e.to_string()))?;

        let tls_stream = StreamOwned::new(
            connection, self.connection.as_mut().unwrap().control_stream.as_mut().get_stream());
        
        self.connection.as_mut().unwrap().control_stream = Box::new(TlsStreamWrapper {
            tls_stream: Some(tls_stream),
        });

        self.security_mode = SecurityMode::TlsExplicit;
        
       Ok(())
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

    pub fn retr(&mut self, _remote_file: &str, _local_file: &str) -> Result<(), FtpError> {

        let mut connection = match self.data_connect_establish() {
            Ok(conn) => conn,
            Err(e) => return Err(e),
        };

        self.send_command(FtpCommand::Type(FtpType::Binary))?;

        let response = self.read_response()?;

        if !response.starts_with(FtpCode::OptsSuccess.as_str()) {
            return Err(FtpError::SetBinaryModeError(response));
        }

        self.send_command(FtpCommand::Retr(_remote_file.to_string()))?;

        let response = self.read_response()?;

        if !response.starts_with(FtpCode::StartDataConnection.as_str()) {
            return Err(FtpError::DownloadFileError(response));
        }

        let mut file = File::create(_local_file).map_err(|e| FtpError::DownloadFileError(e.to_string()))?;
        let mut buffer = [0; 1024];
        while let Ok(bytes_read) = connection.stream.as_mut().read(&mut buffer) {
            if bytes_read == 0 {
                break;
            }
            file.write_all(&buffer[..bytes_read]).map_err(|e| FtpError::DownloadFileError(e.to_string()))?;
        }

        file.flush().map_err(|e| FtpError::DownloadFileError(e.to_string()))?;

        let response = self.read_response()?;

        if !response.starts_with(FtpCode::DataConnectionClose.as_str()) {
            return Err(FtpError::DownloadFileError(response));
        }

        Ok(())
    }

    pub fn stor(&mut self, _local_file: &str, _remote_file: &str) -> Result<(), FtpError> {
        let mut connection = match self.data_connect_establish() {
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
            connection.stream.as_mut().write(&buffer[..bytes_read]).map_err(|e| FtpError::UploadFileError(e.to_string()))?;
        }

        connection.stream.as_mut().flush().map_err(|e| FtpError::UploadFileError(e.to_string()))?;
        connection.stream.as_mut().shutdown().map_err(|e| FtpError::UploadFileError(e.to_string()))?;



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

    pub fn is_exist(&mut self, _path: &str) -> Result<bool, FtpError> {
        let file_list = self.list_files()?;

        Ok(file_list.contains(&_path.to_string()))
    }

    fn send_command(&mut self, command: FtpCommand) -> Result<(), FtpError> {
        debug!("---> {}", command);

        let stream = self.connection.as_mut().unwrap().control_stream.as_mut();

        stream.write(command.to_string().as_bytes()).map_err(FtpError::ConnectError)?;
        stream.flush().map_err(FtpError::ConnectError)?;
        Ok(())
    }


    fn read_response(&mut self) -> Result<String, FtpError> {
        let mut response = String::new();
        self.connection.as_mut().unwrap().control_stream.as_mut().read_line(&mut response).map_err(FtpError::ConnectError)?;
        debug!("<--- {}", response);
        Ok(response)
    }

    fn read_data_response(&mut self, connection: &mut DataConnection) -> Result<String, FtpError> {

        let command_response = self.read_response()?;

        if !command_response.starts_with(FtpCode::StartDataConnection.as_str()) {
            return Err(FtpError::ListDetailsError(command_response));
        }
        
        let mut response = String::new();
        connection.stream.as_mut().read_line(&mut response).map_err(FtpError::ConnectError)?;

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

                        let mut ftp_connection = self.connection.as_mut().unwrap();

                        let stream = TcpStream::connect(
                            format!("{}:{}", ftp_connection.passive_mode_connect_info.0.clone(), 
                                                    ftp_connection.passive_mode_connect_info.1)).unwrap();

                        if ftp_connection.tls_meta.is_some() {
                            let client_connection = ClientConnection::new(
                                Arc::new(ftp_connection.tls_meta.as_ref().unwrap().tls_config.as_ref().unwrap().clone()), 
                                ftp_connection.tls_meta.as_ref().unwrap().server_name.clone())
                                .map_err(|e| FtpError::SSLConnectionError(e.to_string()))?;

                            let tls_stream = StreamOwned::new(client_connection, stream);
                            return Ok(DataConnection {
                                stream: Box::new(TlsStreamWrapper {
                                    tls_stream: Some(tls_stream),
                                }),
                            })
                        } else {
                            Ok(DataConnection {
                                stream: Box::new(TcpStreamWrapper {
                                    read_stream: Some(BufReader::new(stream.try_clone().unwrap())),
                                    write_stream: Some(stream),
                                }),
                            })
                        }
                    
                       
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

        self.connection.as_mut().unwrap().passive_mode_connect_info.0 = host_vec.iter().map(|num| num.to_string()).collect::<Vec<String>>().join(".");
        self.connection.as_mut().unwrap().passive_mode_connect_info.1 = port;

        if self.connection.as_mut().unwrap().passive_mode_connect_info.0 != self.options.host.clone() {
            debug!("Address returned by PASV {} seemed to be incorrect and has been fixed", self.connection.as_mut().unwrap().passive_mode_connect_info.0);
            self.connection.as_mut().unwrap().passive_mode_connect_info.0 = self.options.host.clone();
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

        let options = FtpOptions::new("127.0.0.1".to_string(), 21, true, "user".to_string(), "pass".to_string(), 10, "".to_string());
        
        let result = client.connect(options);
        assert!(result.is_ok(), "Failed to connect to FTP server");

        let new_options = FtpOptions::new("nonexistent.server".to_string(), 21, true, "user".to_string(), "pass".to_string(), 10, "".to_string());
        
        let result = client.connect(new_options);
        assert!(result.is_err(), "Should fail to connect to non-existent server");
    }

    #[test]
    fn test_ftp_login() {
        init();
        let mut client = _FtpClient::new();
        let options = FtpOptions::new("127.0.0.1".to_string(), 21, true, "user".to_string(), "pass".to_string(), 10, "".to_string());
        
        let result = client.connect(options);
        assert!(result.is_ok(), "Failed to connect to FTP server");

        let result = client.login("user", "pass");
        assert!(result.is_ok(), "Failed to login to FTP server");
    }

    #[test]
    fn test_list_details() {
        init();
        let mut client = _FtpClient::new();
        let options = FtpOptions::new("127.0.0.1".to_string(), 21, true, "user".to_string(), "pass".to_string(), 10, "".to_string());
        
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
        let options = FtpOptions::new("127.0.0.1".to_string(), 21, true, "user".to_string(), "pass".to_string(), 10, "".to_string());
        
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
        let options = FtpOptions::new("127.0.0.1".to_string(), 21, true, "user".to_string(), "pass".to_string(), 10, "".to_string());

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

        let options = FtpOptions::new("127.0.0.1".to_string(), 21, true, "user".to_string(), "pass".to_string(), 10, "".to_string());
        
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
        let file_list = response.unwrap();
        assert!(!file_list.contains(&"test".to_string()), "Directory should be removed");
    }

    #[test]
    fn test_mkdir() {
        init();
        let mut client = _FtpClient::new();

        let options = FtpOptions::new("127.0.0.1".to_string(), 21, true, "user".to_string(), "pass".to_string(), 10, "".to_string());
        
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

        let options = FtpOptions::new("127.0.0.1".to_string(), 21, true, "user".to_string(), "pass".to_string(), 10, "".to_string());
        
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

        let options = FtpOptions::new("127.0.0.1".to_string(), 21, true, "user".to_string(), "pass".to_string(), 10, "".to_string());
        
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
        
        let result = client.remove_directory("test2", true, true);
        assert!(result.is_ok(), "Failed to remove directory");

        let response = client.pwd();
        assert!(response.is_ok(), "Failed to get current directory");
        assert!(!response.unwrap().contains("test"), "Current directory should not be test");
    }


    #[test]
    fn test_stor() {
        init();
        let mut client = _FtpClient::new();
        
        let options = FtpOptions::new("127.0.0.1".to_string(), 21, true, "user".to_string(), "pass".to_string(), 10, "".to_string());
        
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

        let result = client.remove_directory("test3", true, true);
        assert!(result.is_ok(), "Failed to remove directory");
    }

    #[test]
    fn test_remove_file() {
        init();
        let mut client = _FtpClient::new();

        let options = FtpOptions::new("127.0.0.1".to_string(), 21, true, "user".to_string(), "pass".to_string(), 10, "".to_string());
        
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

    #[test]
    fn test_retr() {
        init();
        let mut client = _FtpClient::new();

        let options = FtpOptions::new("127.0.0.1".to_string(), 21, true, "user".to_string(), "pass".to_string(), 10, "".to_string());
        
        let result = client.connect(options);
        assert!(result.is_ok(), "Failed to connect to FTP server");

        let result = client.login("user", "pass");
        assert!(result.is_ok(), "Failed to login to FTP server");

        let result = client.mkdir("test4");
        assert!(result.is_ok(), "Failed to make directory");

        let test_content = "Hello, this is a test file for FTP upload!";
        let test_file_path = "test_upload.txt";
        std::fs::write(test_file_path, test_content).expect("Failed to create test file");  

        let result = client.stor(test_file_path, "test4/test_upload.txt");
        assert!(result.is_ok(), "Failed to upload file");

        let result = client.retr("test4/test_upload.txt", "test_upload_clone.txt");
        assert!(result.is_ok(), "Failed to download file");

        let file_content = std::fs::read_to_string("test_upload_clone.txt").expect("Failed to read test file");
        assert_eq!(file_content, test_content, "File content should be the same");

        let result = client.remove_file("test4/test_upload.txt");
        assert!(result.is_ok(), "Failed to remove file");

        let result = client.remove_directory("test4", true, true);
        assert!(result.is_ok(), "Failed to remove directory");
        

        std::fs::remove_file("test_upload_clone.txt").expect("Failed to remove test file");
    }
}


