use alloc::string::String;
use core::fmt;

#[derive(Debug)]
pub enum Error {
    ExtractionError(String),
    InvalidPrivateKey,
    InvalidAddress,
    InvalidFormat(String),
    InvalidMessage,
    UnsupportedType,
    InvalidPublicKey(String),
    SighashError,
    Base64DecodeError,
    InvalidSignature(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::ExtractionError(e) => write!(f, "Unable to extract {}", e),
            Self::InvalidPrivateKey => write!(f, "Invalid private key"),
            Self::InvalidAddress => write!(f, "Invalid address"),
            Self::InvalidFormat(e) => write!(f, "Only valid for {} format", e),
            Self::InvalidMessage => write!(f, "Message hash is not secure"),
            Self::UnsupportedType => write!(f, "Type is not supported"),
            Self::InvalidPublicKey(e) => write!(f, "Invalid public key {}", e),
            Self::SighashError => write!(f, "Unable to compute signature hash"),
            Self::Base64DecodeError => write!(f, "Base64 decoding failed"),
            Self::InvalidSignature(e) => write!(f, "Invalid Signature - {}", e),
        }
    }
}
