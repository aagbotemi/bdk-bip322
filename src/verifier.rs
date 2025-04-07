use alloc::{
    str::FromStr,
    string::{String, ToString},
};

use bitcoin::{
    Address, PrivateKey, PublicKey,
    base64::{Engine, prelude::BASE64_STANDARD},
    secp256k1::{Message, ecdsa::Signature},
    sign_message::signed_msg_hash,
};

use crate::{Error, SecpCtx, SignatureFormat};

pub struct Verifier {
    address_str: String,
    signature: String,
    message: String,
    signature_type: SignatureFormat,
    private_key_str: Option<String>,
}

impl Verifier {
    pub fn new(
        address_str: String,
        signature: String,
        message: String,
        signature_type: SignatureFormat,
        private_key_str: Option<String>,
    ) -> Self {
        Self {
            address_str,
            signature,
            message,
            signature_type,
            private_key_str,
        }
    }

    pub fn verify(&self) -> Result<bool, Error> {
        let signature_bytes = BASE64_STANDARD
            .decode(&self.signature)
            .map_err(|_| Error::Base64DecodeError)?;

        match &self.signature_type {
            SignatureFormat::Legacy => {
                let pk = &self
                    .private_key_str
                    .as_ref()
                    .ok_or(Error::InvalidPrivateKey)?;
                let private_key = PrivateKey::from_wif(pk).map_err(|_| Error::InvalidPrivateKey)?;
                self.verify_legacy(&signature_bytes, private_key)
            }
            SignatureFormat::Simple => {
                todo!()
            }
            SignatureFormat::Full => {
                todo!()
            }
        }
    }

    fn verify_legacy(
        &self,
        signature_bytes: &[u8],
        private_key: PrivateKey,
    ) -> Result<bool, Error> {
        let secp = SecpCtx::new();

        let sig_without_sighash = &signature_bytes[..signature_bytes.len() - 1];

        let pub_key = PublicKey::from_private_key(&secp, &private_key);

        let message_hash = signed_msg_hash(&self.message);
        let msg = &Message::from_digest_slice(message_hash.as_ref())
            .map_err(|_| Error::InvalidMessage)?;

        let sig = Signature::from_der(sig_without_sighash)
            .map_err(|e| Error::InvalidSignature(e.to_string()))?;

        let verify = secp.verify_ecdsa(msg, &sig, &pub_key.inner).is_ok();
        Ok(verify)
    }
}
