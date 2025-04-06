use bitcoin::hashes::{Hash, HashEngine, sha256};

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
