//! Error types for BIP‑322 operations.
//!
//! All possible errors that can occur when signing or verifying a BIP‑322 message.
use alloc::{boxed::Box, string::String};
use bdk_wallet::signer::SignerError;
use bitcoin::{
    OutPoint, Txid,
    consensus::encode::Error as ConsensusError,
    io::Error as IoError,
    psbt::{Error as PsbtError, ExtractTxError},
};
use core::fmt;

/// Error types for BIP322 message signing and verification operations.
///
/// This enum encompasses all possible errors that can occur during the BIP322
/// message signing or verification process.
#[derive(Debug)]
pub enum Error {
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
    /// The digital signature is invalid
    InvalidSignature(String),
    /// The address is not a Segwit address
    NotSegwitAddress,
    /// The Segwit version is not supported for the given context
    UnsupportedSegwitVersion(String),
    /// The provided sighash type is invalid for this context
    InvalidSighashType,
    /// The transaction witness data is invalid
    InvalidWitness(String),
    /// Signer Error
    SignerError(SignerError),
    /// Bitcoin IoError
    IoError(IoError),
    /// ExtractTxError
    ExtractTxError(Box<ExtractTxError>),
    /// PsbtError
    PsbtError(PsbtError),
    /// ConsensusError
    ConsensusError(ConsensusError),
    /// Transaction not found in wallet
    TransactionNotFound(Txid),
    /// UTXO not found in wallet
    UtxoNotFound(OutPoint),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::InvalidFormat(e) => write!(f, "Only valid for {} format", e),
            Self::InvalidMessage => write!(f, "Message hash is not secure"),
            Self::UnsupportedType => write!(f, "Type is not supported"),
            Self::InvalidPublicKey(e) => write!(f, "Invalid public key {}", e),
            Self::SighashError => write!(f, "Unable to compute signature hash"),
            Self::InvalidSignature(e) => write!(f, "Invalid Signature - {}", e),
            Self::NotSegwitAddress => write!(f, "Not a Segwit address"),
            Self::UnsupportedSegwitVersion(e) => write!(f, "Only Segwit {} is supported", e),
            Self::InvalidSighashType => write!(f, "Sighash type is invalid"),
            Self::InvalidWitness(e) => write!(f, "Invalid Witness - {}", e),
            Self::SignerError(err) => write!(f, "Signer error: {}", err),
            Self::IoError(err) => write!(f, "Bitcoin IO Error: {}", err),
            Self::ExtractTxError(err) => write!(f, "Extract TX Error: {:?}", err),
            Self::PsbtError(err) => write!(f, "Psbt Error: {:?}", err),
            Self::ConsensusError(err) => write!(f, "Consensus Error: {:?}", err),
            Self::TransactionNotFound(err) => write!(f, "Transaction: {:?} not found", err),
            Self::UtxoNotFound(err) => write!(f, "UTXO: {:?} not found", err),
        }
    }
}

impl From<SignerError> for Error {
    fn from(err: SignerError) -> Self {
        Error::SignerError(err)
    }
}

impl From<IoError> for Error {
    fn from(err: IoError) -> Self {
        Error::IoError(err)
    }
}
impl From<ExtractTxError> for Error {
    fn from(err: ExtractTxError) -> Self {
        Error::ExtractTxError(Box::new(err))
    }
}

impl From<PsbtError> for Error {
    fn from(err: PsbtError) -> Self {
        Error::PsbtError(err)
    }
}
impl From<ConsensusError> for Error {
    fn from(err: ConsensusError) -> Self {
        Error::ConsensusError(err)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
