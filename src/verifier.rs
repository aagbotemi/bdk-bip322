//! The verification implementation of generated signature for BIP-322 for
//! message signing according to the BIP-322 standard.

use alloc::{
    str::FromStr,
    string::{String, ToString},
};

use bitcoin::{
    base64::{prelude::BASE64_STANDARD, Engine},
    consensus::Decodable,
    io::Cursor,
    opcodes::all::OP_RETURN,
    secp256k1::{ecdsa::Signature, schnorr, Message},
    sighash::{self, SighashCache},
    sign_message::signed_msg_hash,
    Address, Amount, EcdsaSighashType, OutPoint, PrivateKey, Psbt, PublicKey, ScriptBuf,
    TapSighashType, Transaction, TxOut, Witness, WitnessVersion, XOnlyPublicKey,
};

use crate::{to_sign, to_spend, Error, SecpCtx, SignatureFormat};

/// BIP322Verification encapsulates the data and functionality required to verify a message
/// signature according to the BIP322 protocol. It supports verifying signatures produced
/// using different signature formats:
/// - **Legacy:** Standard ECDSA signatures.
/// - **Simple:** Simplified signatures that encapsulate witness data.
/// - **Full:** Fully signed transactions with witness details.
///
/// # Fields
/// - `address_str`: The Bitcoin address as a string against which the signature will be verified.
/// - `signature`: A Base64-encoded signature string.
/// - `message`: The original message that was signed.
/// - `signature_type`: The signature format used during signing, defined by `Bip322SignatureFormat`.
/// - `priv_key`: An optional private key string. Required for verifying legacy signatures.
pub struct Verifier {
    address_str: String,
    signature: String,
    message: String,
    signature_type: SignatureFormat,
    private_key_str: Option<String>,
}

impl Verifier {
    /// Creates a new instance of `BIP322Verification` with the given parameters.
    ///
    /// # Arguments
    /// - `address_str`: The Bitcoin address (as a string) associated with the signature.
    /// - `signature`: The Base64-encoded signature to verify.
    /// - `message`: The original message that was signed.
    /// - `signature_type`: The BIP322 signature format that was used (Legacy, Simple, or Full).
    /// - `priv_key`: An optional private key string used for legacy verification.
    ///
    /// # Returns
    /// An instance of `BIP322Verification`.
    ///
    /// # Example
    /// ```
    /// # use bdk_wallet::bip322::{BIP322Verification, Bip322SignatureFormat};
    ///
    /// let verifier = BIP322Verification::new(
    ///     "1BitcoinAddress...".to_string(),
    ///     "Base64EncodedSignature==".to_string(),
    ///     "Hello, Bitcoin!".to_string(),
    ///     Bip322SignatureFormat::Legacy,
    ///     Some("c...".to_string()),
    /// );
    /// ```
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

    /// Verifies a BIP322 message signature against the provided address and message.
    ///
    /// The verification logic differs depending on the signature format:
    /// - Legacy
    /// - Simple
    /// - Full
    ///
    /// Returns `true` if the signature is valid, or an error if the decoding or verification
    /// process fails.
    pub fn verify(&self) -> Result<bool, Error> {
        let address = Address::from_str(&self.address_str)
            .map_err(|_| Error::InvalidAddress)?
            .assume_checked();
        let script_pubkey = address.script_pubkey();

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
                let mut cursor = Cursor::new(signature_bytes);
                let witness = Witness::consensus_decode_from_finite_reader(&mut cursor)
                    .map_err(|_| Error::DecodeError("witness".to_string()))?;

                let to_spend_witness = to_spend(&script_pubkey, &self.message);
                let to_sign_witness = to_sign(
                    &to_spend_witness.output[0].script_pubkey,
                    to_spend_witness.compute_txid(),
                    to_spend_witness.lock_time,
                    to_spend_witness.input[0].sequence,
                    Some(witness),
                )
                .map_err(|_| Error::ExtractionError("psbt".to_string()))?
                .extract_tx()
                .map_err(|_| Error::ExtractionError("transaction".to_string()))?;

                self.verify_message(address, to_sign_witness)
            }
            SignatureFormat::Full => {
                let mut cursor = Cursor::new(signature_bytes);
                let transaction = Transaction::consensus_decode_from_finite_reader(&mut cursor)
                    .map_err(|_| Error::DecodeError("transaction".to_string()))?;

                self.verify_message(address, transaction)
            }
        }
    }

    /// Verifies a BIP322-signed message by reconstructing the underlying transaction data
    /// and checking the signature against the provided address and message.
    ///
    /// This function performs the following steps:
    /// 1. Constructs a corresponding signing transaction (`to_sign`) using the witness data
    ///    from the given transaction.
    /// 2. It delegates the verification process to the appropriate helper function:
    ///    - P2WPKH
    ///    - P2TR
    ///    - P2SH
    /// 3. If none of the supported script types match, the function returns `Ok(false)`.
    ///
    /// # Returns
    /// A `Result` containing:
    /// - `Ok(true)` if the signature is valid.
    /// - `Ok(false)` if the signature does not match the expected verification criteria.
    /// - An error of type `BIP322Error` if the verification process fails at any step,
    ///   such as during transaction reconstruction or when decoding the witness data.
    fn verify_message(&self, address: Address, transaction: Transaction) -> Result<bool, Error> {
        let script_pubkey = address.script_pubkey();

        let to_spend = to_spend(&script_pubkey, &self.message);
        let to_sign = to_sign(
            &to_spend.output[0].script_pubkey,
            to_spend.compute_txid(),
            to_spend.lock_time,
            to_spend.input[0].sequence,
            Some(transaction.input[0].witness.clone()),
        )?;

        if script_pubkey.is_p2wpkh() {
            let verify = self.verify_p2sh_p2wpkh(address, transaction, to_spend, to_sign, true)?;

            return Ok(verify);
        } else if script_pubkey.is_p2tr() || script_pubkey.is_p2wsh() {
            let verify = self.verify_p2tr(address, to_spend, to_sign, transaction)?;

            return Ok(verify);
        } else if script_pubkey.is_p2sh() {
            let verify = self.verify_p2sh_p2wpkh(address, transaction, to_spend, to_sign, false)?;

            return Ok(verify);
        }

        Ok(false)
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

    fn verify_p2sh_p2wpkh(
        &self,
        address: Address,
        to_sign_witness: Transaction,
        to_spend: Transaction,
        to_sign: Psbt,
        is_segwit: bool,
    ) -> Result<bool, Error> {
        let secp = SecpCtx::new();
        let pub_key = PublicKey::from_slice(&to_sign_witness.input[0].witness[1])
            .map_err(|e| Error::InvalidPublicKey(e.to_string()))?;

        if is_segwit {
            let wp = address.witness_program().ok_or(Error::NotSegwitAddress)?;

            if wp.version() != WitnessVersion::V0 {
                return Err(Error::UnsupportedSegwitVersion("v0".to_string()));
            }
        }

        let to_spend_outpoint = OutPoint {
            txid: to_spend.compute_txid(),
            vout: 0,
        };

        if to_spend_outpoint != to_sign.unsigned_tx.input[0].previous_output {
            return Err(Error::InvalidSignature(
                "to_sign must spend to_spend output".to_string(),
            ));
        }

        if to_sign.unsigned_tx.output[0].script_pubkey
            != ScriptBuf::from_bytes(vec![OP_RETURN.to_u8()])
        {
            return Err(Error::InvalidSignature(
                "to_sign output must be OP_RETURN".to_string(),
            ));
        }

        let witness = to_sign.inputs[0]
            .final_script_witness
            .clone()
            .ok_or(Error::InvalidWitness("missing data".to_string()))?;

        let encoded_signature = &witness.to_vec()[0];
        let witness_pub_key = &witness.to_vec()[1];
        let signature_length = encoded_signature.len();

        if witness.len() != 2 {
            return Err(Error::InvalidWitness("invalid witness length".to_string()));
        }

        if pub_key.to_bytes() != *witness_pub_key {
            return Err(Error::InvalidPublicKey("public key mismatch".to_string()));
        }

        let signature = Signature::from_der(&encoded_signature.as_slice()[..signature_length - 1])
            .map_err(|e| Error::InvalidSignature(e.to_string()))?;
        let sighash_type =
            EcdsaSighashType::from_consensus(encoded_signature[signature_length - 1] as u32);

        if !(sighash_type == EcdsaSighashType::All) {
            return Err(Error::InvalidSighashType);
        }

        let mut sighash_cache = SighashCache::new(to_sign.unsigned_tx);
        let wpubkey_hash = &pub_key
            .wpubkey_hash()
            .map_err(|e| Error::InvalidPublicKey(e.to_string()))?;

        let sighash = sighash_cache
            .p2wpkh_signature_hash(
                0,
                &if is_segwit {
                    to_spend.output[0].script_pubkey.clone()
                } else {
                    ScriptBuf::new_p2wpkh(wpubkey_hash)
                },
                to_spend.output[0].value,
                sighash_type,
            )
            .map_err(|_| Error::SighashError)?;

        let msg =
            &Message::from_digest_slice(sighash.as_ref()).map_err(|_| Error::InvalidMessage)?;

        Ok(secp.verify_ecdsa(msg, &signature, &pub_key.inner).is_ok())
    }

    fn verify_p2tr(
        &self,
        address: Address,
        to_spend: Transaction,
        to_sign: Psbt,
        to_sign_witness: Transaction,
    ) -> Result<bool, Error> {
        let secp = SecpCtx::new();
        let script_pubkey = address.script_pubkey();
        let witness_program = script_pubkey.as_bytes();

        let pubkey_bytes = &witness_program[2..];

        let pub_key = XOnlyPublicKey::from_slice(pubkey_bytes)
            .map_err(|e| Error::InvalidPublicKey(e.to_string()))?;

        let wp = address.witness_program().ok_or(Error::NotSegwitAddress)?;

        if wp.version() != WitnessVersion::V1 {
            return Err(Error::UnsupportedSegwitVersion("v1".to_string()));
        }

        let to_spend_outpoint = OutPoint {
            txid: to_spend.compute_txid(),
            vout: 0,
        };

        if to_spend_outpoint != to_sign.unsigned_tx.input[0].previous_output {
            return Err(Error::InvalidSignature(
                "to_sign must spend to_spend output".to_string(),
            ));
        }

        if to_sign_witness.output[0].script_pubkey != ScriptBuf::from_bytes(vec![OP_RETURN.to_u8()])
        {
            return Err(Error::InvalidSignature(
                "to_sign output must be OP_RETURN".to_string(),
            ));
        }

        let witness = to_sign.inputs[0]
            .final_script_witness
            .clone()
            .ok_or(Error::InvalidWitness("missing data".to_string()))?;

        let encoded_signature = &witness.to_vec()[0];
        if witness.len() != 1 {
            return Err(Error::InvalidWitness("invalid witness length".to_string()));
        }

        let signature = schnorr::Signature::from_slice(&encoded_signature.as_slice()[..64])
            .map_err(|e| Error::InvalidSignature(e.to_string()))?;
        let sighash_type = TapSighashType::from_consensus_u8(encoded_signature[64])
            .map_err(|_| Error::InvalidSighashType)?;

        if sighash_type != TapSighashType::All {
            return Err(Error::InvalidSighashType);
        }

        let mut sighash_cache = SighashCache::new(to_sign.unsigned_tx);

        let sighash = sighash_cache
            .taproot_key_spend_signature_hash(
                0,
                &sighash::Prevouts::All(&[TxOut {
                    value: Amount::from_sat(0),
                    script_pubkey: to_spend.output[0].clone().script_pubkey,
                }]),
                sighash_type,
            )
            .map_err(|_| Error::SighashError)?;

        let msg =
            &Message::from_digest_slice(sighash.as_ref()).map_err(|_| Error::InvalidMessage)?;

        Ok(secp.verify_schnorr(&signature, msg, &pub_key).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Signer;

    // TEST VECTORS FROM
    // https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki#user-content-Test_vectors
    // https://github.com/Peach2Peach/bip322-js/tree/main/test

    const PRIVATE_KEY: &str = "L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k";
    const PRIVATE_KEY_TESTNET: &str = "cTrF79uahxMC7bQGWh2931vepWPWqS8KtF8EkqgWwv3KMGZNJ2yP";

    const SEGWIT_ADDRESS: &str = "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l";
    const SEGWIT_TESTNET_ADDRESS: &str = "tb1q9vza2e8x573nczrlzms0wvx3gsqjx7vaxwd45v";
    const TAPROOT_ADDRESS: &str = "bc1ppv609nr0vr25u07u95waq5lucwfm6tde4nydujnu8npg4q75mr5sxq8lt3";
    const TAPROOT_TESTNET_ADDRESS: &str =
        "tb1ppv609nr0vr25u07u95waq5lucwfm6tde4nydujnu8npg4q75mr5s3g3s37";
    const LEGACY_ADDRESS: &str = "14vV3aCHBeStb5bkenkNHbe2YAFinYdXgc";
    const LEGACY_ADDRESS_TESTNET: &str = "mjSSLdHFzft9NC5NNMik7WrMQ9rRhMhNpT";

    const HELLO_WORLD_MESSAGE: &str = "Hello World";

    const NESTED_SEGWIT_PRIVATE_KEY: &str = "KwTbAxmBXjoZM3bzbXixEr9nxLhyYSM4vp2swet58i19bw9sqk5z";
    const NESTED_SEGWIT_TESTNET_PRIVATE_KEY: &str =
        "cMpadsm2xoVpWV5FywY5cAeraa1PCtSkzrBM45Ladpf9rgDu6cMz";
    const NESTED_SEGWIT_ADDRESS: &str = "3HSVzEhCFuH9Z3wvoWTexy7BMVVp3PjS6f";
    const NESTED_SEGWIT_TESTNET_ADDRESS: &str = "2N8zi3ydDsMnVkqaUUe5Xav6SZqhyqEduap";

    #[test]
    fn sign_and_verify_legacy_signature() {
        let legacy_sign = Signer::new(
            PRIVATE_KEY.to_string(),
            HELLO_WORLD_MESSAGE.to_string(),
            LEGACY_ADDRESS.to_string(),
            SignatureFormat::Legacy,
            None,
        );
        let sign_message = legacy_sign.sign().unwrap();

        let legacy_sign_testnet = Signer::new(
            PRIVATE_KEY_TESTNET.to_string(),
            HELLO_WORLD_MESSAGE.to_string(),
            LEGACY_ADDRESS_TESTNET.to_string(),
            SignatureFormat::Legacy,
            None,
        );
        let sign_message_testnet = legacy_sign_testnet.sign().unwrap();

        let legacy_verify = Verifier::new(
            LEGACY_ADDRESS.to_string(),
            sign_message,
            HELLO_WORLD_MESSAGE.to_string(),
            SignatureFormat::Legacy,
            Some(PRIVATE_KEY.to_string()),
        );

        let verify_message = legacy_verify.verify().unwrap();

        let legacy_verify_testnet = Verifier::new(
            LEGACY_ADDRESS.to_string(),
            sign_message_testnet,
            HELLO_WORLD_MESSAGE.to_string(),
            SignatureFormat::Legacy,
            Some(PRIVATE_KEY_TESTNET.to_string()),
        );

        let verify_message_testnet = legacy_verify_testnet.verify().unwrap();

        assert!(verify_message);
        assert!(verify_message_testnet);
    }

    #[test]
    fn sign_and_verify_legacy_signature_with_wrong_message() {
        let legacy_sign = Signer::new(
            PRIVATE_KEY.to_string(),
            HELLO_WORLD_MESSAGE.to_string(),
            LEGACY_ADDRESS.to_string(),
            SignatureFormat::Legacy,
            None,
        );
        let sign_message = legacy_sign.sign().unwrap();

        let legacy_verify = Verifier::new(
            LEGACY_ADDRESS.to_string(),
            sign_message,
            "".to_string(),
            SignatureFormat::Legacy,
            Some(PRIVATE_KEY.to_string()),
        );

        let verify_message = legacy_verify.verify().unwrap();

        assert!(!verify_message);
    }

    #[test]
    fn test_sign_and_verify_nested_segwit_address() {
        let nested_segwit_simple_sign = Signer::new(
            NESTED_SEGWIT_PRIVATE_KEY.to_string(),
            HELLO_WORLD_MESSAGE.to_string(),
            NESTED_SEGWIT_ADDRESS.to_string(),
            SignatureFormat::Simple,
            None,
        );

        let sign_message = nested_segwit_simple_sign.sign().unwrap();
        assert_eq!(
            sign_message.clone(),
            "AkgwRQIhAMd2wZSY3x0V9Kr/NClochoTXcgDaGl3OObOR17yx3QQAiBVWxqNSS+CKen7bmJTG6YfJjsggQ4Fa2RHKgBKrdQQ+gEhAxa5UDdQCHSQHfKQv14ybcYm1C9y6b12xAuukWzSnS+w"
        );

        let nested_segwit_full_sign_testnet = Signer::new(
            NESTED_SEGWIT_TESTNET_PRIVATE_KEY.to_string(),
            HELLO_WORLD_MESSAGE.to_string(),
            NESTED_SEGWIT_TESTNET_ADDRESS.to_string(),
            SignatureFormat::Full,
            None,
        );

        let sign_message_testnet = nested_segwit_full_sign_testnet.sign().unwrap();
        assert_eq!(
            sign_message_testnet.clone(),
            "AAAAAAABAVuR8vsJiiYj9+vO+8l7Ol3wt3Frz7SVyVSxn0ehOUb+AAAAAAAAAAAAAQAAAAAAAAAAAWoCSDBFAiEAx3bBlJjfHRX0qv80KWhyGhNdyANoaXc45s5HXvLHdBACIFVbGo1JL4Ip6ftuYlMbph8mOyCBDgVrZEcqAEqt1BD6ASEDFrlQN1AIdJAd8pC/XjJtxibUL3LpvXbEC66RbNKdL7AAAAAA"
        );

        let nested_segwit_full_verify = Verifier::new(
            NESTED_SEGWIT_ADDRESS.to_string(),
            sign_message,
            HELLO_WORLD_MESSAGE.to_string(),
            SignatureFormat::Simple,
            None,
        );

        let verify_message = nested_segwit_full_verify.verify().unwrap();

        let nested_segwit_full_verify_testnet = Verifier::new(
            NESTED_SEGWIT_TESTNET_ADDRESS.to_string(),
            sign_message_testnet,
            HELLO_WORLD_MESSAGE.to_string(),
            SignatureFormat::Full,
            None,
        );

        let verify_message_testnet = nested_segwit_full_verify_testnet.verify().unwrap();

        assert!(verify_message);
        assert!(verify_message_testnet);
    }

    #[test]
    fn test_sign_and_verify_segwit_address() {
        let full_sign = Signer::new(
            PRIVATE_KEY.to_string(),
            HELLO_WORLD_MESSAGE.to_string(),
            SEGWIT_ADDRESS.to_string(),
            SignatureFormat::Full,
            None,
        );
        let sign_message = full_sign.sign().unwrap();

        let simple_sign = Signer::new(
            PRIVATE_KEY_TESTNET.to_string(),
            HELLO_WORLD_MESSAGE.to_string(),
            SEGWIT_TESTNET_ADDRESS.to_string(),
            SignatureFormat::Simple,
            None,
        );
        let sign_message_testnet = simple_sign.sign().unwrap();

        let full_verify = Verifier::new(
            SEGWIT_ADDRESS.to_string(),
            sign_message,
            HELLO_WORLD_MESSAGE.to_string(),
            SignatureFormat::Full,
            None,
        );

        let verify_message = full_verify.verify().unwrap();

        let simple_verify = Verifier::new(
            SEGWIT_TESTNET_ADDRESS.to_string(),
            sign_message_testnet,
            HELLO_WORLD_MESSAGE.to_string(),
            SignatureFormat::Simple,
            None,
        );

        let verify_message_testnet = simple_verify.verify().unwrap();

        assert!(verify_message);
        assert!(verify_message_testnet);
    }

    #[test]
    fn test_sign_and_verify_taproot_address() {
        let full_sign = Signer::new(
            PRIVATE_KEY.to_string(),
            HELLO_WORLD_MESSAGE.to_string(),
            TAPROOT_ADDRESS.to_string(),
            SignatureFormat::Full,
            None,
        );
        let sign_message = full_sign.sign().unwrap();

        let simple_sign = Signer::new(
            PRIVATE_KEY.to_string(),
            HELLO_WORLD_MESSAGE.to_string(),
            TAPROOT_TESTNET_ADDRESS.to_string(),
            SignatureFormat::Simple,
            None,
        );

        let sign_message_testnet = simple_sign.sign().unwrap();

        let full_verify = Verifier::new(
            TAPROOT_ADDRESS.to_string(),
            sign_message,
            HELLO_WORLD_MESSAGE.to_string(),
            SignatureFormat::Full,
            None,
        );

        let verify_message = full_verify.verify().unwrap();

        let simple_verify = Verifier::new(
            TAPROOT_TESTNET_ADDRESS.to_string(),
            sign_message_testnet,
            HELLO_WORLD_MESSAGE.to_string(),
            SignatureFormat::Simple,
            None,
        );

        let verify_message_testnet = simple_verify.verify().unwrap();

        assert!(verify_message);
        assert!(verify_message_testnet);
    }

    #[test]
    fn test_simple_segwit_verification() {
        let simple_verify = Verifier::new(
            SEGWIT_ADDRESS.to_string(),
            "AkcwRAIgZRfIY3p7/DoVTty6YZbWS71bc5Vct9p9Fia83eRmw2QCICK/ENGfwLtptFluMGs2KsqoNSk89pO7F29zJLUx9a/sASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=".to_string(),
            HELLO_WORLD_MESSAGE.to_string(),
            SignatureFormat::Simple,
            None,
        );
        assert!(simple_verify.verify().unwrap());

        let simple_verify_2 = Verifier::new(
            SEGWIT_ADDRESS.to_string(),
            "AkgwRQIhAOzyynlqt93lOKJr+wmmxIens//zPzl9tqIOua93wO6MAiBi5n5EyAcPScOjf1lAqIUIQtr3zKNeavYabHyR8eGhowEhAsfxIAMZZEKUPYWI4BruhAQjzFT8FSFSajuFwrDL1Yhy".to_string(),
                HELLO_WORLD_MESSAGE.to_string(),
            SignatureFormat::Simple,
            None,
        );
        assert!(simple_verify_2.verify().unwrap());

        let simple_verify_empty_message = Verifier::new(
            SEGWIT_ADDRESS.to_string(),
            "AkgwRQIhAPkJ1Q4oYS0htvyuSFHLxRQpFAY56b70UvE7Dxazen0ZAiAtZfFz1S6T6I23MWI2lK/pcNTWncuyL8UL+oMdydVgzAEhAsfxIAMZZEKUPYWI4BruhAQjzFT8FSFSajuFwrDL1Yhy".to_string(),
                "".to_string(),
            SignatureFormat::Simple,
            None,
        );
        assert!(simple_verify_empty_message.verify().unwrap());

        let simple_verify_empty_message_2 = Verifier::new(
                SEGWIT_ADDRESS.to_string(),
                "AkcwRAIgM2gBAQqvZX15ZiysmKmQpDrG83avLIT492QBzLnQIxYCIBaTpOaD20qRlEylyxFSeEA2ba9YOixpX8z46TSDtS40ASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=".to_string(),
                    "".to_string(),
                SignatureFormat::Simple,
                None,
            );
        assert!(simple_verify_empty_message_2.verify().unwrap());
    }
}
