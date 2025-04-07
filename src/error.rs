use alloc::string::String;
use core::fmt;

#[derive(Debug)]
pub enum Error {
    ExtractionError(String),
    InvalidPrivateKey,
    InvalidAddress,
    InvalidFormat(String),
    InvalidMessage,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::ExtractionError(e) => write!(f, "Unable to extract {}", e),
            Self::InvalidPrivateKey => write!(f, "Invalid private key"),
            Self::InvalidAddress => write!(f, "Invalid address"),
            Self::InvalidFormat(e) => write!(f, "Only valid for {} format", e),
            Self::InvalidMessage => write!(f, "Message hash is not secure"),
        }
    }
}
