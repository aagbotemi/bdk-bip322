//! BIP-322 signature verification implementation.
//!
//! This module handles verification of all BIP-322 signature formats including
//! legacy, simple, full, and proof-of-funds variants.

use crate::{
    Error, MessageVerificationResult, PUBKEY_LEN, SCRIPT_SIG_LEN, SIG_LEN, SIG_WITHOUT_SIGHASH_LEN,
    SignatureFormat, to_sign, to_spend, validate_witness,
};
use alloc::{string::ToString, vec::Vec};
use bdk_wallet::Wallet;
use bitcoin::{
    Address, Amount, EcdsaSighashType, OutPoint, Psbt, PubkeyHash, PublicKey, ScriptBuf,
    TapSighashType, Transaction, TxOut, Witness, WitnessVersion, XOnlyPublicKey,
    base64::{Engine, engine::general_purpose},
    consensus::Decodable,
    hashes::Hash,
    key::Secp256k1,
    opcodes::all::OP_RETURN,
    secp256k1::{Message, VerifyOnly, ecdsa::Signature, schnorr},
    sighash::{self, SighashCache},
};

/// Verifies a PSBT (unsigned) proof for proof-of-funds.
pub fn verify_psbt_proof(
    psbt: &Psbt,
    script_pubkey: ScriptBuf,
) -> Result<MessageVerificationResult, Error> {
    // Calculate total amount from inputs matching the address
    let total_amount: Amount = psbt
        .inputs
        .iter()
        .enumerate()
        .skip(1)
        .filter_map(|(i, psbt_input)| {
            let tx_input = &psbt.unsigned_tx.input.get(i)?;

            // Get UTXO value from witness_utxo or non_witness_utxo
            psbt_input.witness_utxo.as_ref().or_else(|| {
                psbt_input
                    .non_witness_utxo
                    .as_ref()
                    .and_then(|tx| tx.output.get(tx_input.previous_output.vout as usize))
            })
        })
        .filter(|utxo| utxo.script_pubkey == script_pubkey)
        .map(|utxo| utxo.value)
        .sum();

    Ok(if total_amount > Amount::ZERO {
        MessageVerificationResult {
            valid: true,
            proven_amount: Some(total_amount),
        }
    } else {
        MessageVerificationResult {
            valid: false,
            proven_amount: None,
        }
    })
}

/// Verifies a signed (finalized) BIP-322 proof.
pub fn verify_signed_proof(
    wallet: &mut Wallet,
    message: &str,
    signature_type: SignatureFormat,
    address: &Address,
    script_pubkey: &ScriptBuf,
    tx: &str,
) -> Result<MessageVerificationResult, Error> {
    let to_spend = to_spend(script_pubkey, message);
    let mut to_sign = to_sign(&to_spend);

    // Decode the base64 signature
    let signature_bytes = general_purpose::STANDARD
        .decode(tx)
        .map_err(|_| Error::InvalidFormat("Invalid base64 encoding".to_string()))?;

    let mut cursor = bitcoin::io::Cursor::new(&signature_bytes);

    let secp = Secp256k1::verification_only();

    match signature_type {
        SignatureFormat::Legacy => {
            let verification_result = verify_legacy(&signature_bytes, message, &secp)?;

            Ok(MessageVerificationResult {
                valid: verification_result,
                proven_amount: None,
            })
        }
        SignatureFormat::Simple => {
            let witness = Witness::consensus_decode_from_finite_reader(&mut cursor)?;
            validate_witness(&witness, script_pubkey)?;

            to_sign.input[0].witness = witness;

            let verification_result = verify_message(
                wallet,
                address,
                &to_sign,
                to_spend,
                script_pubkey,
                signature_type,
                &secp,
            )?;

            Ok(MessageVerificationResult {
                valid: verification_result,
                proven_amount: None,
            })
        }
        SignatureFormat::Full => {
            let tx = Transaction::consensus_decode_from_finite_reader(&mut cursor)?;
            let verification_result = verify_message(
                wallet,
                address,
                &tx,
                to_spend,
                script_pubkey,
                signature_type,
                &secp,
            )?;

            Ok(MessageVerificationResult {
                valid: verification_result,
                proven_amount: None,
            })
        }
        SignatureFormat::FullProofOfFunds => {
            let tx = Transaction::consensus_decode_from_finite_reader(&mut cursor)?;
            // Validate transaction has proof-of-funds inputs
            if tx.input.len() < 2 {
                return Err(Error::InvalidFormat(
                    "FullProofOfFunds requires at least 2 inputs".to_string(),
                ));
            }

            let mut total_amount = Amount::ZERO;

            // Verify all additional inputs belong to the same address
            for input in tx.input.iter().skip(1) {
                let utxo = wallet
                    .get_utxo(input.previous_output)
                    .ok_or(Error::UtxoNotFound(input.previous_output))?;

                if utxo.txout.script_pubkey != *script_pubkey {
                    return Err(Error::InvalidFormat(
                        "Additional input doesn't belong to the same address".to_string(),
                    ));
                }

                total_amount += utxo.txout.value;
            }

            let verification_result = verify_message(
                wallet,
                address,
                &tx,
                to_spend,
                script_pubkey,
                signature_type,
                &secp,
            )?;

            Ok(MessageVerificationResult {
                valid: verification_result,
                proven_amount: if total_amount > Amount::ZERO {
                    Some(total_amount)
                } else {
                    None
                },
            })
        }
    }
}

/// Verifies a BIP-322 message signature for the given address using the specified format.
fn verify_message(
    wallet: &mut Wallet,
    address: &Address,
    to_sign: &Transaction,
    to_spend: Transaction,
    script_pubkey: &ScriptBuf,
    signature_type: SignatureFormat,
    secp: &Secp256k1<VerifyOnly>,
) -> Result<bool, Error> {
    // Verify to_sign spends to_spend
    let to_spend_outpoint = OutPoint {
        txid: to_spend.compute_txid(),
        vout: 0,
    };
    if to_spend_outpoint != to_sign.input[0].previous_output {
        return Err(Error::InvalidSignature(
            "to_sign must spend to_spend output".to_string(),
        ));
    }
    // Verify output is OP_RETURN
    if to_sign.output[0].script_pubkey != ScriptBuf::from_bytes(vec![OP_RETURN.to_u8()]) {
        return Err(Error::InvalidSignature(
            "to_sign output must be OP_RETURN".to_string(),
        ));
    }

    let prevouts = TxOut {
        value: Amount::from_sat(0),
        script_pubkey: to_spend.output[0].clone().script_pubkey,
    };

    if script_pubkey.is_p2wpkh() {
        let wp = address.witness_program().ok_or(Error::NotSegwitAddress)?;
        if wp.version() != WitnessVersion::V0 {
            return Err(Error::UnsupportedSegwitVersion("v0".to_string()));
        }
        verify_p2wpkh(to_sign, &prevouts, 0, secp)?
    } else if script_pubkey.is_p2wsh() {
        let wp = address.witness_program().ok_or(Error::NotSegwitAddress)?;
        if wp.version() != WitnessVersion::V0 {
            return Err(Error::UnsupportedSegwitVersion("v0".to_string()));
        }
        verify_p2wsh(to_sign, &prevouts, address, 0, secp)?
    } else if script_pubkey.is_p2tr() {
        let wp = address.witness_program().ok_or(Error::NotSegwitAddress)?;
        if wp.version() != WitnessVersion::V1 {
            return Err(Error::UnsupportedSegwitVersion("v1".to_string()));
        }

        verify_p2tr(to_sign, &prevouts, 0, wallet, &to_spend, secp)?
    } else {
        return Ok(false);
    };

    // For proof-of-funds, verify all additional inputs
    if signature_type == SignatureFormat::FullProofOfFunds {
        return verify_proof_of_funds(wallet, to_sign, script_pubkey, &to_spend, address, secp);
    }

    Ok(true)
}

/// Verifies all proof-of-funds inputs beyond the first.
fn verify_proof_of_funds(
    wallet: &mut Wallet,
    to_sign: &Transaction,
    script_pubkey: &ScriptBuf,
    to_spend: &Transaction,
    address: &Address,
    secp: &Secp256k1<VerifyOnly>,
) -> Result<bool, Error> {
    if to_sign.input.len() < 2 {
        return Err(Error::InvalidFormat(
            "FullProofOfFunds requires at least 2 inputs".to_string(),
        ));
    }

    // Verify each additional input (starting from index 1)
    for (i, tx_input) in to_sign.input.iter().enumerate().skip(1) {
        // Get the UTXO being spent
        let utxo = wallet
            .get_utxo(tx_input.previous_output)
            .ok_or(Error::UtxoNotFound(tx_input.previous_output))?;

        // Verify it belongs to the same address
        if utxo.txout.script_pubkey != *script_pubkey {
            return Ok(false);
        }

        // Verify the signature for this input
        if script_pubkey.is_p2wpkh() {
            verify_p2wpkh(to_sign, &utxo.txout, i, secp)?
        } else if script_pubkey.is_p2tr() {
            verify_p2tr(to_sign, &utxo.txout, i, wallet, to_spend, secp)?
        } else if script_pubkey.is_p2wsh() {
            verify_p2wsh(to_sign, &utxo.txout, address, i, secp)?
        } else {
            return Err(Error::InvalidFormat(
                "Unsupported script type for proof of funds".to_string(),
            ));
        };
    }

    Ok(true)
}

/// Verifies Legacy format Bitcoin Core message signature.
fn verify_legacy(
    signature_bytes: &[u8],
    message: &str,
    secp: &Secp256k1<VerifyOnly>,
) -> Result<bool, Error> {
    // Validate signature length
    if signature_bytes.len() != SCRIPT_SIG_LEN {
        return Err(Error::InvalidFormat(format!(
            "Invalid scriptSig length: {} (expected {})",
            signature_bytes.len(),
            SCRIPT_SIG_LEN
        )));
    }

    // Parse scriptSig: [sig_len][sig_data][sighash][pubkey_len][pubkey_data]
    let sig_len = signature_bytes[0] as usize;
    if sig_len != SIG_LEN {
        return Err(Error::InvalidFormat(format!(
            "Invalid signature length marker: {} (expected {})",
            sig_len, SIG_LEN
        )));
    }

    let sig_with_sighash = &signature_bytes[1..=SIG_LEN];
    let sig_without_sighash = &sig_with_sighash[..SIG_WITHOUT_SIGHASH_LEN];
    let sighash_byte = sig_with_sighash[SIG_WITHOUT_SIGHASH_LEN];

    // Validate pubkey length marker
    let pubkey_len_offset = SIG_LEN + 1;
    let pubkey_len = signature_bytes[pubkey_len_offset] as usize;
    if pubkey_len != PUBKEY_LEN {
        return Err(Error::InvalidFormat(format!(
            "Invalid pubkey length: {} (expected {})",
            pubkey_len, PUBKEY_LEN
        )));
    }

    let pubkey = &signature_bytes[pubkey_len_offset + 1..];

    // Validate sighash type
    let sighash_type = EcdsaSighashType::from_consensus(sighash_byte as u32);
    if sighash_type != EcdsaSighashType::All {
        return Err(Error::InvalidSighashType);
    }

    // Parse public key and derive script_pubkey
    let pub_key =
        PublicKey::from_slice(pubkey).map_err(|e| Error::InvalidPublicKey(e.to_string()))?;

    let pubkey_hash = PubkeyHash::hash(pubkey);
    let script_pubkey = ScriptBuf::new_p2pkh(&pubkey_hash);

    // Create the to_spend transaction using BIP322 method
    let to_spend = to_spend(&script_pubkey, message);
    let to_sign = to_sign(&to_spend);

    // Calculate the legacy sighash that was signed
    let sighash_cache = SighashCache::new(&to_sign);
    let sighash = sighash_cache
        .legacy_signature_hash(0, &script_pubkey, sighash_type.to_u32())
        .map_err(|_| Error::SighashError)?;

    let msg = Message::from_digest_slice(sighash.as_ref()).map_err(|_| Error::InvalidMessage)?;

    // Parse and verify signature
    let signature = Signature::from_der(sig_without_sighash)
        .map_err(|e| Error::InvalidSignature(e.to_string()))?;

    Ok(secp.verify_ecdsa(&msg, &signature, &pub_key.inner).is_ok())
}

/// Verifies P2WPKH (Pay-to-Witness-Public-Key-Hash) signature.
fn verify_p2wpkh(
    to_sign: &Transaction,
    prevout: &TxOut,
    input_index: usize,
    secp: &Secp256k1<VerifyOnly>,
) -> Result<bool, Error> {
    let witness = &to_sign.input[input_index].witness;

    if witness.len() != 2 {
        return Err(Error::InvalidWitness(
            "P2WPKH requires exactly 2 witness elements".to_string(),
        ));
    }

    // Extract witness elements
    let encoded_signature = witness
        .nth(0)
        .ok_or(Error::InvalidWitness("Missing signature".to_string()))?;
    let witness_pub_key = witness
        .nth(1)
        .ok_or(Error::InvalidWitness("Missing public key".to_string()))?;
    let signature_length = encoded_signature.len();

    if encoded_signature.is_empty() {
        return Ok(false);
    }

    // Parse public key
    let pub_key = PublicKey::from_slice(witness_pub_key)
        .map_err(|e| Error::InvalidPublicKey(e.to_string()))?;

    // Parse signature (DER + sighash byte)
    let signature = Signature::from_der(&encoded_signature[..signature_length - 1])
        .map_err(|e| Error::InvalidSignature(e.to_string()))?;
    let sighash_type =
        EcdsaSighashType::from_consensus(encoded_signature[signature_length - 1] as u32);

    if sighash_type != EcdsaSighashType::All {
        return Err(Error::InvalidSighashType);
    }

    // Compute sighash
    let mut sighash_cache = SighashCache::new(to_sign);
    let wpubkey_hash = &pub_key
        .wpubkey_hash()
        .map_err(|e| Error::InvalidPublicKey(e.to_string()))?;
    let script_pubkey = ScriptBuf::new_p2wpkh(wpubkey_hash);

    let sighash = sighash_cache
        .p2wpkh_signature_hash(input_index, &script_pubkey, prevout.value, sighash_type)
        .map_err(|_| Error::SighashError)?;

    let msg = &Message::from_digest_slice(sighash.as_ref()).map_err(|_| Error::InvalidMessage)?;

    Ok(secp.verify_ecdsa(msg, &signature, &pub_key.inner).is_ok())
}

/// Verifies P2WSH (Pay-to-Witness-Script-Hash) signature for single-sig scripts.
fn verify_p2wsh(
    to_sign: &Transaction,
    prevout: &TxOut,
    address: &Address,
    input_index: usize,
    secp: &Secp256k1<VerifyOnly>,
) -> Result<bool, Error> {
    let script_pubkey = address.script_pubkey();
    let witness = &to_sign.input[input_index].witness;

    // Validate witness has minimum required elements
    if witness.len() < 2 {
        return Err(Error::InvalidWitness(
            "P2WSH requires at least 2 witness elements".to_string(),
        ));
    }

    let witness_script_bytes = witness
        .nth(witness.len() - 1)
        .ok_or(Error::InvalidWitness("No witness script found".to_string()))?;
    let witness_script = ScriptBuf::from_bytes(witness_script_bytes.to_vec());

    // Get signature
    let signature_bytes = witness
        .nth(0)
        .ok_or(Error::InvalidWitness("No signature".to_string()))?;

    let signature_length = signature_bytes.len();
    if signature_bytes.is_empty() {
        return Ok(false);
    }

    // Verify witness script hash matches address
    let script_hash = witness_script.wscript_hash();
    let expected_script_pubkey = ScriptBuf::new_p2wsh(&script_hash);

    if script_pubkey != expected_script_pubkey {
        return Err(Error::InvalidSignature(
            "Witness script hash doesn't match address".to_string(),
        ));
    }

    // Parse signature
    let signature = Signature::from_der(&signature_bytes[..signature_length - 1])
        .map_err(|e| Error::InvalidSignature(e.to_string()))?;
    let sighash_type =
        EcdsaSighashType::from_consensus(signature_bytes[signature_length - 1] as u32);

    if sighash_type != EcdsaSighashType::All {
        return Err(Error::InvalidSighashType);
    }

    // Extract public key from witness script
    let pub_key = PublicKey::from_slice(&witness_script.as_bytes()[1..34])
        .map_err(|e| Error::InvalidPublicKey(e.to_string()))?;

    // Compute sighash
    let mut sighash_cache = SighashCache::new(to_sign);
    let sighash = sighash_cache
        .p2wsh_signature_hash(input_index, &witness_script, prevout.value, sighash_type)
        .map_err(|_| Error::SighashError)?;

    let msg = &Message::from_digest_slice(sighash.as_ref()).map_err(|_| Error::InvalidMessage)?;

    Ok(secp.verify_ecdsa(msg, &signature, &pub_key.inner).is_ok())
}

/// Verifies P2TR (Pay-to-Taproot) signature for key path spend.
fn verify_p2tr(
    to_sign: &Transaction,
    prevout: &TxOut,
    input_index: usize,
    wallet: &mut Wallet,
    to_spend: &Transaction,
    secp: &Secp256k1<VerifyOnly>,
) -> Result<bool, Error> {
    let script_bytes = prevout.script_pubkey.as_bytes();

    // Extract x-only public key from script
    let pub_key = XOnlyPublicKey::from_slice(&script_bytes[2..])
        .map_err(|e| Error::InvalidPublicKey(e.to_string()))?;

    // Validate witness structure
    let witness = &to_sign.input[input_index].witness;
    if witness.len() != 1 {
        return Err(Error::InvalidWitness(
            "P2TR key path requires exactly 1 witness element".to_string(),
        ));
    }

    let encoded_signature = witness
        .nth(0)
        .ok_or(Error::InvalidWitness("Missing signature".to_string()))?;
    if encoded_signature.len() != 65 {
        return Ok(false);
    }

    // Parse Schnorr signature
    let signature = schnorr::Signature::from_slice(&encoded_signature[..64])
        .map_err(|e| Error::InvalidSignature(e.to_string()))?;
    let sighash_type = TapSighashType::from_consensus_u8(encoded_signature[64])
        .map_err(|_| Error::InvalidSighashType)?;

    if sighash_type != TapSighashType::All {
        return Err(Error::InvalidSighashType);
    }

    // Build prevouts array for sighash computation
    let mut prevouts_vec = Vec::new();
    let to_spend_outpoint = OutPoint {
        txid: to_spend.compute_txid(),
        vout: 0,
    };
    for (i, txin) in to_sign.input.iter().enumerate() {
        if i == input_index {
            prevouts_vec.push(prevout.clone());
        } else if txin.previous_output == to_spend_outpoint {
            prevouts_vec.push(to_spend.output[0].clone());
        } else {
            let utxo = wallet
                .get_utxo(txin.previous_output)
                .ok_or(Error::UtxoNotFound(txin.previous_output))?;
            prevouts_vec.push(utxo.txout);
        }
    }

    let prevouts = sighash::Prevouts::All(&prevouts_vec);

    // Compute sighash
    let mut sighash_cache = SighashCache::new(to_sign);
    let sighash = sighash_cache
        .taproot_key_spend_signature_hash(input_index, &prevouts, sighash_type)
        .map_err(|_| Error::SighashError)?;

    let msg = &Message::from_digest_slice(sighash.as_ref()).map_err(|_| Error::InvalidMessage)?;

    Ok(secp.verify_schnorr(&signature, msg, &pub_key).is_ok())
}
