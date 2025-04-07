use alloc::{
    str::FromStr,
    string::{String, ToString},
    vec::Vec,
};
use bitcoin::{
    Address, EcdsaSighashType, OutPoint, PrivateKey, ScriptBuf, Sequence, Witness,
    base64::{Engine, prelude::BASE64_STANDARD},
    secp256k1::{Message, ecdsa::Signature},
    sign_message::signed_msg_hash,
};

use crate::{Error, SecpCtx, SignatureFormat};

pub struct Signer {
    private_key_str: String,
    message: String,
    address_str: String,
    signature_type: SignatureFormat,
    proof_of_funds: Option<Vec<(OutPoint, ScriptBuf, Witness, Sequence)>>,
}

impl Signer {
    pub fn new(
        private_key_str: String,
        message: String,
        address_str: String,
        signature_type: SignatureFormat,
        proof_of_funds: Option<Vec<(OutPoint, ScriptBuf, Witness, Sequence)>>,
    ) -> Self {
        Self {
            private_key_str,
            message,
            address_str,
            signature_type,
            proof_of_funds,
        }
    }

    pub fn sign(&self) -> Result<String, Error> {
        let private_key =
            PrivateKey::from_wif(&self.private_key_str).map_err(|_| Error::InvalidPrivateKey)?;

        let script_pubkey = Address::from_str(&self.address_str)
            .map_err(|_| Error::InvalidAddress)?
            .assume_checked()
            .script_pubkey();

        match &self.signature_type {
            SignatureFormat::Legacy => {
                if !script_pubkey.is_p2pkh() {
                    return Err(Error::InvalidFormat("legacy".to_string()));
                }

                let sig_serialized = self.sign_legacy(&private_key)?;
                Ok(BASE64_STANDARD.encode(sig_serialized))
            }
            SignatureFormat::Simple => {
                todo!()
            }
            SignatureFormat::Full => {
                todo!()
            }
        }
    }

    fn sign_legacy(&self, private_key: &PrivateKey) -> Result<Vec<u8>, Error> {
        let secp = SecpCtx::new();

        let message_hash = signed_msg_hash(&self.message);
        let message = &Message::from_digest_slice(message_hash.as_ref())
            .map_err(|_| Error::InvalidMessage)?;

        let mut signature: Signature = secp.sign_ecdsa(message, &private_key.inner);
        signature.normalize_s();
        let mut sig_serialized = signature.serialize_der().to_vec();
        sig_serialized.push(EcdsaSighashType::All as u8);

        Ok(sig_serialized)
    }
}
