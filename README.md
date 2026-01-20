# `bdk‑bip322`

**Note:** This is an experimental crate exploring a descriptor-based implementation of BIP-322 within the Bitcoin Dev Kit (BDK) ecosystem.

A Rust library implementing the [BIP‑322: Generic Signed Message Format](https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki) for Bitcoin, built on top of the Bitcoin Dev Kit (BDK) ecosystem.

`bdk-bip322` enables cryptographic proof of control over Bitcoin addresses and
funds without moving coins or broadcasting transactions, while securely
committing to arbitrary messages.

## Overview
BIP-322 defines a standardized, script-agnostic mechanism for signing and
verifying messages with Bitcoin addresses. Unlike legacy `signmessage`,
BIP-322 works across modern script types (SegWit, Taproot) and enables advanced use cases such as proof-of-funds.

This library provides a **descriptor-based, wallet-native** implementation of
BIP-322, designed for seamless integration with `bdk_wallet`.

### Common use cases
- Proving ownership of Bitcoin addresses
- Cryptographic proof of reserves or funds
- User authentication in Bitcoin-based applications
- Verifying control of addresses for support or dispute resolution
- Hardware-wallet compatible message signing via PSBTs

## Integration
Designed to integrate with the [Bitcoin Dev Kit](https://bitcoindevkit.org/) ecosystem: 
- **bdk‑wallet** — descriptor-based wallets, key management, and persistence.
- **PSBT-based workflows** — compatible with hardware and air-gapped signers
No private keys or WIFs are passed directly to this library.

## Minimum Supported Rust Version (MSRV)
This crate supports **Rust 1.85.0 or newer** across all feature combinations.

## Supported Signature Formats

- **Legacy**: Original P2PKH `signmessage`/`verifymessage` compatibility  
- **Simple**: SegWit‑only witness stack format  
- **Full**: Complete PSBT/transaction‑based format (any script, including Taproot)  
- **FullProofOfFunds**: Extends Full format with additional UTXO inputs to prove fund ownership.

## Usage
### Signing a Message
```rs
use bdk_wallet::{Wallet, KeychainKind};
use bdk_bip322::{BIP322, SignatureFormat};

// `wallet` is already created and synced
let address = wallet.peek_address(KeychainKind::External, 0).address;

let proof = wallet.sign_bip322(
    "Hello Bitcoin",
    SignatureFormat::Simple,
    &address,
    None,
)?;
```
### Verifying a Signature
```rs
let result = wallet.verify_bip322(
    &proof,
    "Hello Bitcoin",
    SignatureFormat::Simple,
    &address,
)?;

assert!(result.valid);
```

## Contributing
Found a bug, have an issue or a feature request? Feel free to open an issue on GitHub.
