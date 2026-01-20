//! A no_std Rust library implementing [BIP‑322: Generic Signed Message Format](https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki).
//!
//! This crate provides:
//! - Construction of virtual `to_spend` and `to_sign` transactions
//! - Signing and verification for Legacy, Simple, and Full BIP‑322 formats
//! - Optional “proof of funds” support via additional UTXO inputs
#![no_std]

#[macro_use]
pub extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod error;
pub mod sign;
pub mod utils;
pub mod verify;

pub use error::*;
#[allow(unused_imports)]
pub use sign::*;
pub use utils::*;
pub use verify::*;

use crate::Error;
use alloc::{string::String, vec::Vec};
use bitcoin::{Address, Amount, OutPoint, Psbt};

/// Represents the different formats supported by the BIP322 message signing protocol.
///
/// BIP322 defines multiple formats for signatures to accommodate different use cases
/// and maintain backward compatibility with legacy signing methods.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureFormat {
    /// Legacy Bitcoin Core message signing format (P2PKH only).
    Legacy,
    /// A simplified version of the BIP322 format that includes only essential data.
    Simple,
    /// Full BIP-322 format with complete transaction data.
    Full,
    /// The Full BIP322 format with Proof-of-funds(utxo) capabiility.
    FullProofOfFunds,
}

/// Main trait providing BIP-322 signing and verification functionality.
///
/// This trait is implemented for `bdk_wallet::Wallet` to provide seamless
/// integration with BDK wallets.
///
/// # Examples
///
/// ```no_run
/// use bdk_wallet::{Wallet, KeychainKind};
/// use bdk_bip322::{BIP322, SignatureFormat};
///
/// # fn main() -> Result<(), bdk_bip322::error::Error> {
/// # let mut wallet: Wallet = unimplemented!();
/// let address = wallet.peek_address(KeychainKind::External, 0).address;
///
/// // Sign a message
/// let proof = wallet.sign_bip322(
///     "Hello Bitcoin",
///     SignatureFormat::Simple,
///     &address,
///     None,
/// )?;
///
/// // Verify the signature
/// let result = wallet.verify_bip322(
///     &proof,
///     "Hello Bitcoin",
///     SignatureFormat::Simple,
///     &address,
/// )?;
///
/// assert!(result.valid);
/// # Ok(())
/// # }
/// ```
pub trait BIP322 {
    /// Sign a message for a specific address using BIP-322.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign (as UTF-8 text)
    /// * `signature_type` - The signature format to use
    /// * `address` - The address to sign with (must be owned by wallet)
    /// * `utxos` - Optional list of specific UTXOs for proof-of-funds (only for `FullProofOfFunds`)
    ///
    /// # Returns
    ///
    /// Returns either a complete signature or a PSBT for external signing or [`Error`] when there's an error
    fn sign_bip322(
        &mut self,
        message: &str,
        signature_type: SignatureFormat,
        address: &Address,
        utxos: Option<Vec<OutPoint>>,
    ) -> Result<Bip322Proof, Error>;

    /// Verify a BIP-322 message signature.
    ///
    /// # Arguments
    ///
    /// * `proof` - The signature proof to verify
    /// * `message` - The original message that was signed
    /// * `signature_type` - The signature format used
    /// * `address` - The address that supposedly signed the message
    ///
    /// # Returns
    ///
    /// Returns verification result with validity and optional proven amount or [`Error`] when there's an error
    fn verify_bip322(
        &mut self,
        proof: &Bip322Proof,
        message: &str,
        signature_type: SignatureFormat,
        address: &Address,
    ) -> Result<Bip322VerificationResult, Error>;
}

/// Result of a BIP-322 signature verification.
pub struct Bip322VerificationResult {
    /// Whether the signature is valid for the given message and address
    pub valid: bool,
    /// The total amount proven for FullProofOfFunds signatures.
    ///
    /// This is `Some` only when using `FullProofOfFunds` format and
    /// additional UTXOs were included in the signature. For other formats,
    /// this will always be `None`.
    pub proven_amount: Option<Amount>,
}

/// Result of a BIP-322 signing operation.
///
/// Signing can result in either a complete signature (when the wallet has
/// private keys) or a PSBT ready for external signing (e.g., hardware wallets).
#[derive(Debug)]
pub enum Bip322Proof {
    /// Signature was created successfully.
    ///
    /// Contains the base64-encoded signature string ready for sharing.
    Signed(String),
    /// PSBT ready for external signing.
    Psbt(Psbt),
}
