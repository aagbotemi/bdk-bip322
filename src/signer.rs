use alloc::{
    str::FromStr,
    string::{String, ToString},
    vec::Vec,
};
use bitcoin::{
    Address, Amount, EcdsaSighashType, OutPoint, PrivateKey, Psbt, PublicKey, ScriptBuf, Sequence,
    TapSighashType, Transaction, TxIn, TxOut, Witness,
    absolute::LockTime,
    base64::{Engine, prelude::BASE64_STANDARD},
    consensus::serialize,
    key::{Keypair, TapTweak},
    psbt::Input,
    secp256k1::{Message, ecdsa::Signature},
    sighash::{self, SighashCache},
    sign_message::signed_msg_hash,
    transaction::Version,
};

use crate::{Error, SecpCtx, SignatureFormat, to_sign, to_spend};

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
        let secp = SecpCtx::new();
        let private_key =
            PrivateKey::from_wif(&self.private_key_str).map_err(|_| Error::InvalidPrivateKey)?;
        let pubkey = private_key.public_key(&secp);

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
                let witness = self.sign_message(&private_key, pubkey, &script_pubkey)?;

                Ok(BASE64_STANDARD.encode(serialize(&witness.input[0].witness.clone())))
            }
            SignatureFormat::Full => {
                let transaction = self.sign_message(&private_key, pubkey, &script_pubkey)?;

                Ok(BASE64_STANDARD.encode(serialize(&transaction)))
            }
        }
    }

    fn sign_message(
        &self,
        private_key: &PrivateKey,
        pubkey: PublicKey,
        script_pubkey: &ScriptBuf,
    ) -> Result<Transaction, Error> {
        let to_spend = to_spend(script_pubkey, &self.message);
        let mut to_sign = to_sign(
            &to_spend.output[0].script_pubkey,
            to_spend.compute_txid(),
            to_spend.lock_time,
            to_spend.input[0].sequence,
            Some(to_spend.input[0].witness.clone()),
        )?;

        if let Some(proofs) = self.proof_of_funds.clone() {
            for (previous_output, script_sig, witness, sequence) in proofs {
                to_sign.inputs.push(Input {
                    non_witness_utxo: Some(Transaction {
                        input: vec![TxIn {
                            previous_output,
                            script_sig,
                            sequence,
                            witness,
                        }],
                        output: vec![],
                        version: Version(2),
                        lock_time: LockTime::ZERO,
                    }),
                    ..Default::default()
                })
            }
        }

        let mut sighash_cache = SighashCache::new(&to_sign.unsigned_tx);

        let witness = if script_pubkey.is_p2wpkh() {
            self.sign_p2sh_p2wpkh(&mut sighash_cache, to_spend, private_key, pubkey, true)?
        } else if script_pubkey.is_p2tr() || script_pubkey.is_p2wsh() {
            self.sign_p2tr(&mut sighash_cache, to_spend, to_sign.clone(), private_key)?
        } else if script_pubkey.is_p2sh() {
            self.sign_p2sh_p2wpkh(&mut sighash_cache, to_spend, private_key, pubkey, false)?
        } else {
            return Err(Error::UnsupportedType);
        };

        to_sign.inputs[0].final_script_witness = Some(witness);

        let transaction = to_sign
            .extract_tx()
            .map_err(|_| Error::ExtractionError("transaction".to_string()))?;

        Ok(transaction)
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

    fn sign_p2sh_p2wpkh(
        &self,
        sighash_cache: &mut SighashCache<&Transaction>,
        to_spend: Transaction,
        private_key: &PrivateKey,
        pubkey: PublicKey,
        is_segwit: bool,
    ) -> Result<Witness, Error> {
        let secp = SecpCtx::new();
        let sighash_type = EcdsaSighashType::All;

        let wpubkey_hash = &pubkey
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

        let signature = secp.sign_ecdsa(msg, &private_key.inner);
        let mut sig_serialized = signature.serialize_der().to_vec();
        sig_serialized.push(sighash_type as u8);

        Ok(Witness::from(vec![
            sig_serialized,
            pubkey.inner.serialize().to_vec(),
        ]))
    }

    fn sign_p2tr(
        &self,
        sighash_cache: &mut SighashCache<&Transaction>,
        to_spend: Transaction,
        mut to_sign: Psbt,
        private_key: &PrivateKey,
    ) -> Result<Witness, Error> {
        let secp = SecpCtx::new();
        let keypair = Keypair::from_secret_key(&secp, &private_key.inner);
        let key_pair = keypair
            .tap_tweak(&secp, to_sign.inputs[0].tap_merkle_root)
            .to_inner();
        let x_only_public_key = keypair.x_only_public_key().0;

        let sighash_type = TapSighashType::All;

        to_sign.inputs[0].tap_internal_key = Some(x_only_public_key);

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

        let signature = secp.sign_schnorr_no_aux_rand(msg, &key_pair);
        let mut sig_serialized = signature.serialize().to_vec();
        sig_serialized.push(sighash_type as u8);

        Ok(Witness::from(vec![sig_serialized]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIVATE_KEY: &str = "L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k";
    const SEGWIT_ADDRESS: &str = "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l";
    const HELLO_WORLD_MESSAGE: &str = "Hello World";

    #[test]
    fn test_sign_with_segwit_address() {
        let simple_sign = Signer::new(
            PRIVATE_KEY.to_string(),
            HELLO_WORLD_MESSAGE.to_string(),
            SEGWIT_ADDRESS.to_string(),
            SignatureFormat::Simple,
            None,
        );
        let sign_message = simple_sign.sign().unwrap();

        let sign_empty_msg = Signer::new(
            PRIVATE_KEY.to_string(),
            "".to_string(),
            SEGWIT_ADDRESS.to_string(),
            SignatureFormat::Simple,
            None,
        );
        let sign_empty_msg_sig = sign_empty_msg.sign().unwrap();

        assert_eq!(
            sign_message,
            "AkgwRQIhAOzyynlqt93lOKJr+wmmxIens//zPzl9tqIOua93wO6MAiBi5n5EyAcPScOjf1lAqIUIQtr3zKNeavYabHyR8eGhowEhAsfxIAMZZEKUPYWI4BruhAQjzFT8FSFSajuFwrDL1Yhy"
        );
        assert_eq!(
            sign_empty_msg_sig,
            "AkgwRQIhAPkJ1Q4oYS0htvyuSFHLxRQpFAY56b70UvE7Dxazen0ZAiAtZfFz1S6T6I23MWI2lK/pcNTWncuyL8UL+oMdydVgzAEhAsfxIAMZZEKUPYWI4BruhAQjzFT8FSFSajuFwrDL1Yhy"
        );
    }
}
