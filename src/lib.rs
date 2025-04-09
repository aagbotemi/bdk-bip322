//! A no_std Rust library implementing BIP‑322 Generic Signed Message Format.
//!
//! This crate provides:
//! - Construction of virtual `to_spend` and `to_sign` transactions
//! - Signing and verification for Legacy, Simple, and Full BIP‑322 formats
//! - Optional “proof of funds” support via additional UTXO inputs
#![warn(missing_docs)]
#![no_std]

#[macro_use]
pub extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod error;
pub mod signer;
pub mod utils;
pub mod verifier;

pub use error::*;
pub use signer::*;
pub use utils::*;
pub use verifier::*;
