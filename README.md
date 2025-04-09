# bdk‑bip322

A Rust library implementing the [BIP‑322 Generic Signed Message Format](https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki) for Bitcoin, proving fund availabilty without actually moving them or commiting to a message. 

## Overview
BIP-322 provides a standardized way to sign arbitrary messages with Bitcoin addresses, allowing users to cryptographically prove they control the private keys associated with specific Bitcoin addresses without creating transactions. This is particularly useful for:
- Verifying ownership of funds to exchanges or other parties
- Proving reserves by businesses or custodians
- Authenticating identity in Bitcoin-based applications
- Validating control of addresses in disputes or support cases

## Integration
Designed to integrate with the [Bitcoin Dev Kit](https://bitcoindevkit.org/) ecosystem: 
- **bdk‑wallet** for key derivation and database‑backed wallets.

## Minimum Supported Rust Version (MSRV)
This library should compile with any combination of features with Rust 1.75.0 or newer.


## Features

- **Legacy**: Original P2PKH `signmessage`/`verifymessage` compatibility  
- **Simple**: SegWit‑only witness stack format  
- **Full**: Complete PSBT/transaction‑based format (any script, including Taproot)  
- **Proof of Funds**: Include additional UTXO inputs to prove control over funds 


## Real‑World Examples
See the [examples/](/examples) folder for end‑to‑end demos:

1. Legacy: Sign & verify a P2PKH address with SignatureFormat::Legacy
```bash
cargo run --example sign_verify_legacy
```

2. Simple: Sign & verify an address with SignatureFormat::Simple
```bash
cargo run --example sign_verify_simple
```

3. Full: Sign & verify an address with SignatureFormat::Full
```bash
cargo run --example sign_verify_full
```

## API Reference
- **Signer::new(priv_wif, message, address, format, proof_of_funds)**:
Build a signer for any BIP‑322 format.

- **signer.sign() -> Result<String>**:
Produce a Base64‑encoded signature.

- **Verifier::new(address, signature, message, format, priv_wif_opt)**:
Build a verifier (for Legacy, you must supply the WIF).

- **verifier.verify() -> Result<bool>**:
Returns true if the signature is valid.

## Contributing
Found a bug, have an issue or a feature request? Feel free to open an issue on GitHub.
- Fork the repo

- Create a feature branch

- Open a pull request

Please follow the existing code style, run `cargo fmt` and `cargo clippy`, and include tests for new functionality.