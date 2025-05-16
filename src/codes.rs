
use thiserror::Error;
use std::fmt;

#[derive(Error, Debug)]
pub enum FtpCode {
    #[error("User name okay, need password")]
    NeedPassword,

    #[error("Service ready for new user")]
    Ready,

    #[error("Login successful")]
    LoginSuccess,

    #[error("Passive mode")]
    PassiveMode,

    #[error("Current directory")]
    MkdPwdSuccess,

    #[error("Options success")]
    OptsSuccess,


    #[error("Work directory command success")]
    WorkDirCommandSuccess,


    #[error("Start data connection")]
    StartDataConnection,

    #[error("Data connection close")]
    DataConnectionClose,

    

}


impl FtpCode {
    pub fn as_str(&self) -> &str {
        match self {
            FtpCode::NeedPassword => "331",
            FtpCode::Ready => "220",
            FtpCode::LoginSuccess => "230",
            FtpCode::PassiveMode => "227",
            FtpCode::MkdPwdSuccess => "257",
            FtpCode::OptsSuccess => "200",
            FtpCode::WorkDirCommandSuccess => "250",
            FtpCode::StartDataConnection => "150",
            FtpCode::DataConnectionClose => "226",

        }
    }
}

#[derive(Debug, Clone)]
pub enum FtpOpts {
    UTF8(bool),
}

impl FtpOpts {
    pub fn to_string(&self) -> String {
        match self {
            FtpOpts::UTF8(opts) => format!("UTF8 {}\r\n", if *opts { "ON" } else { "OFF" }),
        }
    }
}

#[derive(Debug, Clone)]
pub enum FtpType {
    Ascii,
    Binary,
}

impl FtpType {
    pub fn to_string(&self) -> String {
        match self {
            FtpType::Ascii => "A".to_string(),
            FtpType::Binary => "I".to_string(),
        }
    }
}


#[derive(Debug, Clone)]
pub enum FtpCommand {
    User(String),
    Pass(String),
    Pwd,
    Pasv,
    List,
    Nlst,
    Mkd(String),
    Cwd(String),
    Opts(FtpOpts),
    Rmd(String),
    Stor(String),
    Type(FtpType),
    Dele(String),
}

impl FtpCommand {
    pub fn to_string(&self) -> String {
        match self {
            FtpCommand::User(username) => format!("USER {}\r\n", username),
            FtpCommand::Pass(password) => format!("PASS {}\r\n", password),
            FtpCommand::Pwd => "PWD\r\n".to_string(),
            FtpCommand::Pasv => "PASV\r\n".to_string(),
            FtpCommand::List => "LIST\r\n".to_string(),
            FtpCommand::Nlst => "NLST\r\n".to_string(),
            FtpCommand::Mkd(path) => format!("MKD {}\r\n", path),
            FtpCommand::Cwd(path) => format!("CWD {}\r\n", path),
            FtpCommand::Opts(opts) => format!("OPTS {}\r\n", opts.to_string()),
            FtpCommand::Rmd(path) => format!("RMD {}\r\n", path),
            FtpCommand::Stor(path) => format!("STOR {}\r\n", path),
            FtpCommand::Type(ftype) => format!("TYPE {}\r\n", ftype.to_string()),
            FtpCommand::Dele(path) => format!("DELE {}\r\n", path),
        }
    }
}

impl fmt::Display for FtpCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FtpCommand::User(username) => write!(f, "USER {}", username),
            FtpCommand::Pass(password) => write!(f, "PASS {}", password),
            FtpCommand::Pwd => write!(f, "PWD"),
            FtpCommand::Pasv => write!(f, "PASV"),
            FtpCommand::List => write!(f, "LIST"),
            FtpCommand::Nlst => write!(f, "NLST"),
            FtpCommand::Mkd(path) => write!(f, "MKD {}", path),
            FtpCommand::Cwd(path) => write!(f, "CWD {}", path),
            FtpCommand::Opts(opts) => write!(f, "OPTS {}", opts.to_string()),
            FtpCommand::Rmd(path) => write!(f, "RMD {}", path),
            FtpCommand::Stor(path) => write!(f, "STOR {}", path),
            FtpCommand::Type(ftype) => write!(f, "TYPE {}", ftype.to_string()),
            FtpCommand::Dele(path) => write!(f, "DELE {}", path),
        }
    }
}



