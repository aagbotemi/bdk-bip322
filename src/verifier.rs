use alloc::{
    str::FromStr,
    string::{String, ToString},
};

use bitcoin::{
    Address, Amount, EcdsaSighashType, OutPoint, PrivateKey, Psbt, PublicKey, ScriptBuf,
    TapSighashType, Transaction, TxOut, Witness, WitnessVersion, XOnlyPublicKey,
    base64::{Engine, prelude::BASE64_STANDARD},
    consensus::Decodable,
    io::Cursor,
    opcodes::all::OP_RETURN,
    secp256k1::{Message, ecdsa::Signature, schnorr},
    sighash::{self, SighashCache},
    sign_message::signed_msg_hash,
};

use crate::{Error, SecpCtx, SignatureFormat, to_sign, to_spend};

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
                todo!()
            }
        }
    }

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
