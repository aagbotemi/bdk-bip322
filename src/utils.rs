//! The utility methods for BIP-322 for message signing
//! according to the BIP-322 standard.
use alloc::{string::ToString, vec};

use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    absolute::LockTime,
    hashes::{Hash, HashEngine, sha256},
    opcodes::{OP_0, all::OP_RETURN},
    script::Builder,
    secp256k1::{All, Secp256k1},
    transaction::Version,
};

use crate::Error;

/// The tag used for BIP-322 message hashing according to BIP-340 tagged hashes
pub const BIP322_TAG: &str = "BIP0322-signed-message";

/// Creates a tagged hash of a message according to the BIP322 specification.
pub fn tagged_message_hash(message: &[u8]) -> sha256::Hash {
    let mut engine = sha256::Hash::engine();

    let tag_hash = sha256::Hash::hash(BIP322_TAG.as_bytes());
    engine.input(&tag_hash[..]);
    engine.input(&tag_hash[..]);
    engine.input(message);

    sha256::Hash::from_engine(engine)
}

/// Creates the virtual "to_spend" transaction for BIP-322.
pub fn to_spend(script_pubkey: &ScriptBuf, message: &str) -> Transaction {
    let message_hash = tagged_message_hash(message.as_bytes());
    let script_sig = Builder::new()
        .push_opcode(OP_0)
        .push_slice(message_hash.to_byte_array())
        .into_script();

    Transaction {
        version: Version(0),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::default(),
            script_sig,
            sequence: Sequence::ZERO,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: script_pubkey.clone(),
        }],
    }
}

/// Creates the virtual "to_sign" transaction for BIP-322.
pub fn to_sign(to_spend: &Transaction) -> Result<Transaction, Error> {
    let outpoint = OutPoint {
        txid: to_spend.compute_txid(),
        vout: 0x00,
    };
    let script_pub_key = Builder::new().push_opcode(OP_RETURN).into_script();

    let tx = Transaction {
        version: Version(0),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint,
            sequence: Sequence::ZERO,
            script_sig: ScriptBuf::new(),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: script_pub_key,
        }],
    };
    Ok(tx)
}

/// Secp256k1 context type used throughout the crate
pub(crate) type SecpCtx = Secp256k1<All>;

/// Validates witness structure matches the script type.
pub fn validate_witness(witness: &Witness, script_pubkey: &ScriptBuf) -> Result<(), Error> {
    if witness.is_empty() {
        return Err(Error::InvalidFormat("Empty witness".to_string()));
    }

    if script_pubkey.is_p2wpkh() && witness.len() != 2 {
        return Err(Error::InvalidFormat(
            "P2WPKH requires exactly 2 witness elements".to_string(),
        ));
    } else if script_pubkey.is_p2tr() && witness.is_empty() {
        return Err(Error::InvalidFormat(
            "P2TR requires at least 1 witness element".to_string(),
        ));
    } else if script_pubkey.is_p2wsh() && witness.len() < 2 {
        return Err(Error::InvalidFormat(
            "P2WSH requires at least 2 witness elements".to_string(),
        ));
    } else if !(script_pubkey.is_p2wpkh() || script_pubkey.is_p2wsh() || script_pubkey.is_p2tr()) {
        return Err(Error::InvalidFormat(
            "Simple format only supports P2WPKH, P2WSH, or P2TR script types".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use bitcoin::Address;
    use core::str::FromStr;

    const HELLO_WORLD_MESSAGE: &str = "Hello World";
    const SEGWIT_ADDRESS: &str = "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l";

    #[test]
    fn test_message_hashing() {
        let empty_hash = tagged_message_hash(b"");
        let hello_world_hash = tagged_message_hash(b"Hello World");

        assert_eq!(
            empty_hash.to_string(),
            "c90c269c4f8fcbe6880f72a721ddfbf1914268a794cbb21cfafee13770ae19f1"
        );
        assert_eq!(
            hello_world_hash.to_string(),
            "f0eb03b1a75ac6d9847f55c624a99169b5dccba2a31f5b23bea77ba270de0a7a"
        );
    }

    #[test]
    fn test_to_spend_and_to_sign() {
        let script_pubkey = Address::from_str(SEGWIT_ADDRESS)
            .unwrap()
            .assume_checked()
            .script_pubkey();

        // Test case for empty message - to_spend
        let tx_spend_empty_msg = to_spend(&script_pubkey, "");
        assert_eq!(
            tx_spend_empty_msg.compute_txid().to_string(),
            "c5680aa69bb8d860bf82d4e9cd3504b55dde018de765a91bb566283c545a99a7"
        );

        // Test case for "Hello World" - to_spend
        let tx_spend_hello_world_msg = to_spend(&script_pubkey, HELLO_WORLD_MESSAGE);
        assert_eq!(
            tx_spend_hello_world_msg.compute_txid().to_string(),
            "b79d196740ad5217771c1098fc4a4b51e0535c32236c71f1ea4d61a2d603352b"
        );

        // Test case for empty message - to_sign
        let tx_sign_empty_msg = to_sign(&tx_spend_empty_msg).unwrap();
        assert_eq!(
            tx_sign_empty_msg.compute_txid().to_string(),
            "1e9654e951a5ba44c8604c4de6c67fd78a27e81dcadcfe1edf638ba3aaebaed6"
        );

        // Test case for HELLO_WORLD_MESSAGE - to_sign
        let tx_sign_hw_msg = to_sign(&tx_spend_hello_world_msg).unwrap();
        assert_eq!(
            tx_sign_hw_msg.compute_txid().to_string(),
            "88737ae86f2077145f93cc4b153ae9a1cb8d56afa511988c149c5c8c9d93bddf"
        );
    }
}
