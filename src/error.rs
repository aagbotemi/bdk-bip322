//! Error types for BIP‑322 operations.

/// All possible errors that can occur when signing or verifying a BIP‑322 message.
use alloc::string::String;
use core::fmt;

/// Error types for BIP322 message signing and verification operations.
///
/// This enum encompasses all possible errors that can occur during the BIP322
/// message signing or verification process.
#[derive(Debug)]
pub enum Error {
    /// Error encountered when extracting data, such as from a PSBT
    ExtractionError(String),
    /// The provided private key is invalid
    InvalidPrivateKey,
    /// The provided Bitcoin address is invalid
    InvalidAddress,
    /// The format of the data is invalid for the given context
    InvalidFormat(String),
    /// The message does not meet requirements
    InvalidMessage,
    /// The script or address type is not supported
    UnsupportedType,
    /// The provided public key is invalid
    InvalidPublicKey(String),
    /// Unable to compute the signature hash for signing
    SighashError,
    /// Error encountered when decoding Base64 data
    Base64DecodeError,
    /// The digital signature is invalid
    InvalidSignature(String),
    /// Error encountered when decoding Bitcoin consensus data
    DecodeError(String),
    /// The address is not a Segwit address
    NotSegwitAddress,
    /// The Segwit version is not supported for the given context
    UnsupportedSegwitVersion(String),
    /// The provided sighash type is invalid for this context
    InvalidSighashType,
    /// The transaction witness data is invalid
    InvalidWitness(String),
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
            Self::DecodeError(e) => write!(f, "Consensus decode error - {}", e),
            Self::NotSegwitAddress => write!(f, "Not a Segwit address"),
            Self::UnsupportedSegwitVersion(e) => write!(f, "Only Segwit {} is supported", e),
            Self::InvalidSighashType => write!(f, "Sighash type is invalid"),
            Self::InvalidWitness(e) => write!(f, "Invalid Witness - {}", e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}