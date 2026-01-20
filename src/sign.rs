//! The signature generation implementation for BIP-322 for message signing
//! according to the BIP-322 standard.

use crate::{
    Bip322Proof, Bip322VerificationResult, SignatureFormat, validate_witness, verify_psbt_proof,
    verify_signed_proof,
};
use alloc::{string::ToString, vec::Vec};

use bdk_wallet::SignOptions;
use bdk_wallet::{KeychainKind, Wallet};
use bitcoin::{
    Address, EcdsaSighashType, OutPoint, Psbt, ScriptBuf, Sequence, TapSighashType, Transaction,
    TxIn, TxOut, Witness,
    base64::{Engine, engine::general_purpose},
    consensus::Encodable,
    psbt::PsbtSighashType,
};

use crate::{BIP322, Error, to_sign, to_spend};

impl BIP322 for Wallet {
    fn sign_bip322(
        &mut self,
        message: &str,
        signature_type: SignatureFormat,
        address: &Address,
        utxos: Option<Vec<OutPoint>>,
    ) -> Result<Bip322Proof, Error> {
        let script_pubkey = address.script_pubkey();

        // Create the virtual to_spend and to_sign transactions
        let to_spend = to_spend(&script_pubkey, message);
        let mut to_sign = to_sign(&to_spend)?;

        // Handle proof-of-funds by adding additional inputs
        if signature_type == SignatureFormat::FullWithProofOfFunds {
            add_proof_of_funds_inputs(&mut to_sign, self, &script_pubkey, utxos)?;
        } else if utxos.is_some() {
            return Err(Error::InvalidFormat(
                "UTXOs parameter only supported for FullWithProofOfFunds format".to_string(),
            ));
        }

        let mut psbt = Psbt::from_unsigned_tx(to_sign)?;

        configure_psbt_inputs(&mut psbt, self, &script_pubkey, &to_spend)?;

        let sign_options = SignOptions {
            trust_witness_utxo: true,
            ..Default::default()
        };

        let finalized = self.sign(&mut psbt, sign_options)?;

        if finalized {
            encode_signature(&psbt, signature_type, &script_pubkey)
        } else {
            Ok(Bip322Proof::Psbt(psbt))
        }
    }

    fn verify_bip322(
        &mut self,
        proof: &Bip322Proof,
        message: &str,
        signature_type: SignatureFormat,
        address: &Address,
    ) -> Result<Bip322VerificationResult, Error> {
        let script_pubkey = address.script_pubkey();

        match proof {
            Bip322Proof::Signed(tx) => {
                verify_signed_proof(self, message, signature_type, address, &script_pubkey, tx)
            }
            Bip322Proof::Psbt(psbt) => verify_psbt_proof(psbt, script_pubkey),
        }
    }
}

/// Adds proof-of-funds inputs to the to_sign transaction.
///
/// Collects UTXOs belonging to the signing address and adds them as
/// additional inputs to prove control over funds.
fn add_proof_of_funds_inputs(
    to_sign: &mut Transaction,
    wallet: &Wallet,
    script_pubkey: &ScriptBuf,
    utxos: Option<Vec<OutPoint>>,
) -> Result<(), Error> {
    let address_utxos: Vec<(OutPoint, TxOut)> = if let Some(specific_utxos) = utxos {
        wallet
            .list_unspent()
            .filter(|utxo| {
                specific_utxos.contains(&utxo.outpoint)
                    && utxo.txout.script_pubkey == *script_pubkey
            })
            .map(|utxo| (utxo.outpoint, utxo.txout))
            .collect()
    } else {
        wallet
            .list_unspent()
            .filter(|utxo| utxo.txout.script_pubkey == *script_pubkey)
            .map(|utxo| (utxo.outpoint, utxo.txout))
            .collect()
    };

    if address_utxos.is_empty() {
        return Err(Error::InvalidFormat(
            "No UTXOs available for proof-of-funds".to_string(),
        ));
    }

    // Add each UTXO as an input
    for (outpoint, _) in &address_utxos {
        to_sign.input.push(TxIn {
            previous_output: *outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ZERO,
            witness: Witness::new(),
        });
    }

    Ok(())
}

/// Configures PSBT inputs with necessary witness/non-witness UTXO data.
///
/// Sets up each PSBT input with the correct sighash type and UTXO information
/// based on the address type (SegWit vs legacy).
fn configure_psbt_inputs(
    psbt: &mut Psbt,
    wallet: &Wallet,
    script_pubkey: &ScriptBuf,
    to_spend: &Transaction,
) -> Result<(), Error> {
    for (i, (psbt_input, tx_input)) in psbt
        .inputs
        .iter_mut()
        .zip(psbt.unsigned_tx.input.iter())
        .enumerate()
    {
        // Set appropriate sighash type
        psbt_input.sighash_type = if script_pubkey.is_p2tr() {
            Some(PsbtSighashType::from(TapSighashType::All))
        } else {
            Some(PsbtSighashType::from(EcdsaSighashType::All))
        };

        if i == 0 {
            if script_pubkey.is_p2tr() || script_pubkey.is_p2wpkh() || script_pubkey.is_p2wsh() {
                psbt_input.witness_utxo = Some(to_spend.output[0].clone());

                if script_pubkey.is_p2wsh() {
                    // Add witness script for P2WSH
                    let external_desc = wallet.public_descriptor(KeychainKind::External);

                    if let Ok(derived_desc) = external_desc.at_derivation_index(0) {
                        let script = derived_desc.script_pubkey();
                        psbt_input.witness_script = Some(script);
                    }
                }
            } else {
                // Legacy P2PKH requires full transaction
                psbt_input.non_witness_utxo = Some(to_spend.clone())
            }
        } else {
            let utxo = wallet
                .get_utxo(tx_input.previous_output)
                .ok_or(Error::UtxoNotFound(tx_input.previous_output))?;

            let txout = utxo.txout;

            if txout.script_pubkey.is_p2tr()
                || txout.script_pubkey.is_p2wpkh()
                || txout.script_pubkey.is_p2wsh()
            {
                psbt_input.witness_utxo = Some(txout.clone());

                if txout.script_pubkey.is_p2wsh() {
                    let external_desc = wallet.public_descriptor(KeychainKind::External);
                    if let Ok(derived_desc) = external_desc.at_derivation_index(0) {
                        let script = derived_desc.explicit_script().unwrap();
                        psbt_input.witness_script = Some(script);
                    }
                }
            } else {
                // Legacy input requires full transaction
                let tx = wallet
                    .get_tx(tx_input.previous_output.txid)
                    .ok_or(Error::TransactionNotFound(tx_input.previous_output.txid))?;
                psbt_input.non_witness_utxo = Some(tx.tx_node.tx.as_ref().clone());
            }
        }
    }

    Ok(())
}

/// Encodes the finalized signature according to the signature format.
///
/// Extracts the appropriate data from the signed PSBT and encodes it
/// as a base64 string.
fn encode_signature(
    psbt: &Psbt,
    signature_type: SignatureFormat,
    script_pubkey: &ScriptBuf,
) -> Result<Bip322Proof, Error> {
    let mut buffer = Vec::new();

    match signature_type {
        SignatureFormat::Legacy => {
            if !script_pubkey.is_p2pkh() {
                return Err(Error::InvalidFormat(
                    "Legacy format only supported for P2PKH addresses".to_string(),
                ));
            }
            let script_sig =
                psbt.inputs[0]
                    .final_script_sig
                    .as_ref()
                    .ok_or(Error::InvalidFormat(
                        "No final script_sig found".to_string(),
                    ))?;

            if script_sig.is_empty() {
                return Err(Error::InvalidFormat("Empty script_sig".to_string()));
            }

            let legacy_signature = general_purpose::STANDARD.encode(script_sig.as_bytes());
            Ok(Bip322Proof::Signed(legacy_signature))
        }
        SignatureFormat::Simple => {
            let witness = psbt.inputs[0]
                .final_script_witness
                .as_ref()
                .ok_or(Error::InvalidFormat("No final witness found".to_string()))?;

            validate_witness(witness, script_pubkey)?;

            witness.consensus_encode(&mut buffer)?;
            let simple_signature = general_purpose::STANDARD.encode(&buffer);
            Ok(Bip322Proof::Signed(simple_signature))
        }
        SignatureFormat::Full | SignatureFormat::FullWithProofOfFunds => {
            let tx = psbt.clone().extract_tx()?;

            tx.consensus_encode(&mut buffer)?;
            let full_signature = general_purpose::STANDARD.encode(&buffer);
            Ok(Bip322Proof::Signed(full_signature))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_wallet::{
        KeychainKind,
        test_utils::{get_funded_wallet, get_funded_wallet_single},
    };
    use bitcoin::Amount;

    #[test]
    fn test_legacy_format() {
        const EXTERNAL_DESC: &str = "pkh(tprv8ZgxMBicQKsPfGXKjYNsw4gayjfBsq6FHxvNZ8LSBdz4DSTeBPd7cjvVQXTdMH9NJBVwNrNKLDr58dcrf4YmWLYBs4KogJhSgUELXuo1JwH/44'/1'/0'/0/*)";
        const INTERNAL_DESC: &str = "pkh(tprv8ZgxMBicQKsPfGXKjYNsw4gayjfBsq6FHxvNZ8LSBdz4DSTeBPd7cjvVQXTdMH9NJBVwNrNKLDr58dcrf4YmWLYBs4KogJhSgUELXuo1JwH/44'/1'/0'/1/*)";

        let (mut wallet, _) = get_funded_wallet(EXTERNAL_DESC, INTERNAL_DESC);
        let address = wallet.peek_address(KeychainKind::External, 0).address;

        let signature_type = SignatureFormat::Legacy;

        let sign = wallet
            .sign_bip322("HELLO WORLD", signature_type, &address, None)
            .unwrap();

        let verify = wallet
            .verify_bip322(&sign, "HELLO WORLD", signature_type, &address)
            .unwrap();

        assert!(verify.valid)
    }

    #[test]
    fn test_simple_format_p2pwkh() {
        const EXTERNAL_DESC: &str = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/0/*)";
        const INTERNAL_DESC: &str = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/1/*)";

        let (mut wallet, _) = get_funded_wallet(EXTERNAL_DESC, INTERNAL_DESC);
        let address = wallet.peek_address(KeychainKind::External, 0).address;

        let signature_type = SignatureFormat::Simple;

        let sign = wallet
            .sign_bip322("HELLO WORLD", signature_type, &address, None)
            .unwrap();

        let verify = wallet
            .verify_bip322(&sign, "HELLO WORLD", signature_type, &address)
            .unwrap();

        assert!(verify.valid)
    }

    #[test]
    fn test_simple_format_p2tr() {
        const EXTERNAL_DESC: &str = "tr(tprv8ZgxMBicQKsPd3krDUsBAmtnRsK3rb8u5yi1zhQgMhF1tR8MW7xfE4rnrbbsrbPR52e7rKapu6ztw1jXveJSCGHEriUGZV7mCe88duLp5pj/86'/1'/0'/0/*)";
        const INTERNAL_DESC: &str = "tr(tprv8ZgxMBicQKsPd3krDUsBAmtnRsK3rb8u5yi1zhQgMhF1tR8MW7xfE4rnrbbsrbPR52e7rKapu6ztw1jXveJSCGHEriUGZV7mCe88duLp5pj/86'/1'/0'/1/*)";

        let (mut wallet, _) = get_funded_wallet(EXTERNAL_DESC, INTERNAL_DESC);
        let address = wallet.peek_address(KeychainKind::External, 0).address;

        let signature_type = SignatureFormat::Simple;

        let sign = wallet
            .sign_bip322("HELLO WORLD", signature_type, &address, None)
            .unwrap();

        let verify = wallet
            .verify_bip322(&sign, "HELLO WORLD", signature_type, &address)
            .unwrap();

        assert!(verify.valid)
    }

    #[test]
    fn test_simple_format_p2wsh_single_script() {
        let (mut wallet, _) = get_funded_wallet_single(
            "wsh(and_v(v:pk(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW),older(6)))",
        );
        let address = wallet.peek_address(KeychainKind::External, 0).address;

        let signature_type = SignatureFormat::Simple;

        let sign = wallet
            .sign_bip322("HELLO WORLD", signature_type, &address, None)
            .unwrap();

        let verify = wallet
            .verify_bip322(&sign, "HELLO WORLD", signature_type, &address)
            .unwrap();

        assert!(verify.valid)
    }

    #[test]
    fn test_full_format_p2pwkh() {
        const EXTERNAL_DESC: &str = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/0/*)";
        const INTERNAL_DESC: &str = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/1/*)";

        let (mut wallet, _) = get_funded_wallet(EXTERNAL_DESC, INTERNAL_DESC);
        let address = wallet.peek_address(KeychainKind::External, 0).address;

        let signature_type = SignatureFormat::Full;

        let sign = wallet
            .sign_bip322("HELLO WORLD", signature_type, &address, None)
            .unwrap();

        let verify = wallet
            .verify_bip322(&sign, "HELLO WORLD", signature_type, &address)
            .unwrap();

        assert!(verify.valid)
    }

    #[test]
    fn test_full_format_p2tr() {
        const EXTERNAL_DESC: &str = "tr(tprv8ZgxMBicQKsPd3krDUsBAmtnRsK3rb8u5yi1zhQgMhF1tR8MW7xfE4rnrbbsrbPR52e7rKapu6ztw1jXveJSCGHEriUGZV7mCe88duLp5pj/86'/1'/0'/0/*)";
        const INTERNAL_DESC: &str = "tr(tprv8ZgxMBicQKsPd3krDUsBAmtnRsK3rb8u5yi1zhQgMhF1tR8MW7xfE4rnrbbsrbPR52e7rKapu6ztw1jXveJSCGHEriUGZV7mCe88duLp5pj/86'/1'/0'/1/*)";

        let (mut wallet, _) = get_funded_wallet(EXTERNAL_DESC, INTERNAL_DESC);
        let address = wallet.peek_address(KeychainKind::External, 0).address;

        let signature_type = SignatureFormat::Full;

        let sign = wallet
            .sign_bip322("HELLO WORLD", signature_type, &address, None)
            .unwrap();

        let verify = wallet
            .verify_bip322(&sign, "HELLO WORLD", signature_type, &address)
            .unwrap();

        assert!(verify.valid)
    }

    #[test]
    fn test_full_format_p2wsh_single_script() {
        let (mut wallet, _) = get_funded_wallet_single(
            "wsh(and_v(v:pk(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW),older(6)))",
        );
        let address = wallet.peek_address(KeychainKind::External, 0).address;

        let signature_type = SignatureFormat::Full;

        let sign = wallet
            .sign_bip322("HELLO WORLD", signature_type, &address, None)
            .unwrap();

        let verify = wallet
            .verify_bip322(&sign, "HELLO WORLD", signature_type, &address)
            .unwrap();

        assert!(verify.valid)
    }

    #[test]
    fn test_full_with_proof_of_funds_format_p2pwkh() {
        const EXTERNAL_DESC: &str = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/0/*)";
        const INTERNAL_DESC: &str = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/1/*)";

        let (mut wallet, _) = get_funded_wallet(EXTERNAL_DESC, INTERNAL_DESC);
        let address = wallet.peek_address(KeychainKind::External, 0).address;

        let utxos: Vec<_> = wallet
            .list_unspent()
            .filter(|utxo| utxo.txout.script_pubkey == address.script_pubkey())
            .map(|utxo| utxo.outpoint)
            .collect();

        assert!(!utxos.is_empty(), "No UTXOs found for address");

        let signature_type = SignatureFormat::FullWithProofOfFunds;

        let sign = wallet
            .sign_bip322("HELLO WORLD", signature_type, &address, Some(utxos))
            .unwrap();

        let verify = wallet
            .verify_bip322(&sign, "HELLO WORLD", signature_type, &address)
            .unwrap();

        assert!(verify.valid)
    }

    #[test]
    fn test_full_with_proof_of_funds_format_p2tr() {
        const EXTERNAL_DESC: &str = "tr(tprv8ZgxMBicQKsPd3krDUsBAmtnRsK3rb8u5yi1zhQgMhF1tR8MW7xfE4rnrbbsrbPR52e7rKapu6ztw1jXveJSCGHEriUGZV7mCe88duLp5pj/86'/1'/0'/0/*)";
        const INTERNAL_DESC: &str = "tr(tprv8ZgxMBicQKsPd3krDUsBAmtnRsK3rb8u5yi1zhQgMhF1tR8MW7xfE4rnrbbsrbPR52e7rKapu6ztw1jXveJSCGHEriUGZV7mCe88duLp5pj/86'/1'/0'/1/*)";

        let (mut wallet, _) = get_funded_wallet(EXTERNAL_DESC, INTERNAL_DESC);
        let address = wallet.peek_address(KeychainKind::External, 0).address;

        let utxos: Vec<_> = wallet
            .list_unspent()
            .filter(|utxo| utxo.txout.script_pubkey == address.script_pubkey())
            .map(|utxo| utxo.outpoint)
            .collect();

        assert!(!utxos.is_empty(), "No UTXOs found for address");

        let signature_type = SignatureFormat::FullWithProofOfFunds;

        let sign = wallet
            .sign_bip322("HELLO WORLD", signature_type, &address, Some(utxos))
            .unwrap();

        let verify = wallet
            .verify_bip322(&sign, "HELLO WORLD", signature_type, &address)
            .unwrap();

        assert!(verify.valid)
    }

    #[test]
    fn test_full_with_proof_of_funds_format_p2wsh_single_script() {
        const DESCRIPTOR: &str = "wsh(pk(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW))";

        let (mut wallet, _) = get_funded_wallet_single(DESCRIPTOR);
        let address = wallet.peek_address(KeychainKind::External, 0).address;

        let utxos: Vec<_> = wallet
            .list_unspent()
            .filter(|utxo| utxo.txout.script_pubkey == address.script_pubkey())
            .map(|utxo| utxo.outpoint)
            .collect();

        assert!(!utxos.is_empty(), "No UTXOs found for address");

        let signature_type = SignatureFormat::FullWithProofOfFunds;

        let sign = wallet
            .sign_bip322("HELLO WORLD", signature_type, &address, Some(utxos))
            .unwrap();

        let verify = wallet
            .verify_bip322(&sign, "HELLO WORLD", signature_type, &address)
            .unwrap();

        assert!(verify.valid)
    }

    #[test]
    fn test_full_with_proof_of_funds_psbt() {
        const DESCRIPTOR: &str =
            "wsh(and_v(v:pk(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW),older(6)))";

        let (mut wallet, _) = get_funded_wallet_single(DESCRIPTOR);
        let address = wallet.peek_address(KeychainKind::External, 0).address;

        let utxos: Vec<_> = wallet
            .list_unspent()
            .filter(|utxo| utxo.txout.script_pubkey == address.script_pubkey())
            .map(|utxo| utxo.outpoint)
            .collect();

        assert!(!utxos.is_empty(), "No UTXOs found for address");

        let signature_type = SignatureFormat::FullWithProofOfFunds;

        let sign = wallet
            .sign_bip322("HELLO WORLD", signature_type, &address, Some(utxos))
            .unwrap();

        let verify = wallet
            .verify_bip322(&sign, "HELLO WORLD", signature_type, &address)
            .unwrap();

        assert!(verify.valid);
        assert_eq!(verify.proven_amount.unwrap(), Amount::from_sat(50000));
        assert_ne!(verify.proven_amount.unwrap(), Amount::from_sat(0))
    }
}
