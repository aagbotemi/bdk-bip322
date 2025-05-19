//! The utility methods for BIP-322 for message signing
//! according to the BIP-322 standard.

use alloc::{string::ToString, vec};

use bitcoin::{
    absolute::LockTime,
    hashes::{sha256, Hash, HashEngine},
    opcodes::{all::OP_RETURN, OP_0},
    script::Builder,
    secp256k1::{All, Secp256k1},
    transaction::Version,
    Amount, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};

use crate::Error;

/// Represents the different formats supported by the BIP322 message signing protocol.
///
/// BIP322 defines multiple formats for signatures to accommodate different use cases
/// and maintain backward compatibility with legacy signing methods.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SignatureFormat {
    /// The legacy Bitcoin message signature format used before BIP322.
    Legacy,
    /// A simplified version of the BIP322 format that includes only essential data.
    Simple,
    /// The Full BIP322 format that includes all signature data.
    Full,
}

const TAG: &str = "BIP0322-signed-message";

/// Creates a tagged hash of a message according to the BIP322 specification.
pub fn tagged_message_hash(message: &[u8]) -> sha256::Hash {
    let mut engine = sha256::Hash::engine();

    let tag_hash = sha256::Hash::hash(TAG.as_bytes());
    engine.input(&tag_hash[..]);
    engine.input(&tag_hash[..]);
    engine.input(message);

    sha256::Hash::from_engine(engine)
}

/// Constructs the "to_spend" transaction according to the BIP322 specification.
pub fn to_spend(script_pubkey: &ScriptBuf, message: &str) -> Transaction {
    let txid = Txid::from_slice(&[0u8; 32]).expect("Txid slice error");

    let outpoint = OutPoint {
        txid,
        vout: 0xFFFFFFFF,
    };
    let message_hash = tagged_message_hash(message.as_bytes());
    let script_sig = Builder::new()
        .push_opcode(OP_0)
        .push_slice(message_hash.to_byte_array())
        .into_script();

    Transaction {
        version: Version(0),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint,
            script_sig,
            sequence: Sequence::ZERO,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(0),
            script_pubkey: script_pubkey.clone(),
        }],
    }
}

/// Constructs a transaction according to the BIP322 specification.
///
/// This transaction will be signed to prove ownership of the private key
/// corresponding to the script_pubkey.
///
/// Returns a PSBT (Partially Signed Bitcoin Transaction) ready for signing
/// or a [`BIP322Error`] if something goes wrong.
pub fn to_sign(
    script_pubkey: &ScriptBuf,
    txid: Txid,
    lock_time: LockTime,
    sequence: Sequence,
    witness: Option<Witness>,
) -> Result<Psbt, Error> {
    let outpoint = OutPoint { txid, vout: 0x00 };
    let script_pub_key = Builder::new().push_opcode(OP_RETURN).into_script();

    let tx = Transaction {
        version: Version(0),
        lock_time,
        input: vec![TxIn {
            previous_output: outpoint,
            sequence,
            script_sig: ScriptBuf::new(),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(0),
            script_pubkey: script_pub_key,
        }],
    };

    let mut psbt =
        Psbt::from_unsigned_tx(tx).map_err(|_| Error::ExtractionError("psbt".to_string()))?;

    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(0),
        script_pubkey: script_pubkey.clone(),
    });

    psbt.inputs[0].final_script_witness = witness;

    Ok(psbt)
}

pub(crate) type SecpCtx = Secp256k1<All>;

#[cfg(test)]
mod tests {
    use bitcoin::Address;
    use core::str::FromStr;

    use super::*;

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
        let tx_sign_empty_msg = to_sign(
            &tx_spend_empty_msg.output[0].script_pubkey,
            tx_spend_empty_msg.compute_txid(),
            tx_spend_empty_msg.lock_time,
            tx_spend_empty_msg.input[0].sequence,
            Some(tx_spend_empty_msg.input[0].witness.clone()),
        )
        .unwrap();
        assert_eq!(
            tx_sign_empty_msg.unsigned_tx.compute_txid().to_string(),
            "1e9654e951a5ba44c8604c4de6c67fd78a27e81dcadcfe1edf638ba3aaebaed6"
        );

        // Test case for HELLO_WORLD_MESSAGE - to_sign
        let tx_sign_hw_msg = to_sign(
            &tx_spend_hello_world_msg.output[0].script_pubkey,
            tx_spend_hello_world_msg.compute_txid(),
            tx_spend_hello_world_msg.lock_time,
            tx_spend_hello_world_msg.input[0].sequence,
            Some(tx_spend_hello_world_msg.input[0].witness.clone()),
        )
        .unwrap();

        assert_eq!(
            tx_sign_hw_msg.unsigned_tx.compute_txid().to_string(),
            "88737ae86f2077145f93cc4b153ae9a1cb8d56afa511988c149c5c8c9d93bddf"
        );
    }
}
