use alloc::vec;
use bitcoin::{
    absolute::LockTime, hashes::{sha256, Hash, HashEngine}, opcodes::OP_0, script::Builder, transaction::Version, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness
};

#[derive(Debug, PartialEq)]
pub enum SignatureFormat {
    Legacy,
    Simple,
    Full,
}

const TAG: &str = "BIP0322-signed-message";

pub fn tagged_message_hash(message: &[u8]) -> sha256::Hash {
    let mut engine = sha256::Hash::engine();

    let tag_hash = sha256::Hash::hash(TAG.as_bytes());
    engine.input(&tag_hash[..]);
    engine.input(&tag_hash[..]);
    engine.input(message);

    sha256::Hash::from_engine(engine)
}

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
