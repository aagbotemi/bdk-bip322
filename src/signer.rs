//! The signature generation implementation for BIP-322 for message signing
//! according to the BIP-322 standard.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use bdk_wallet::{SignOptions, Wallet};
use bitcoin::{
    base64::{engine::general_purpose, Engine},
    consensus::Encodable,
    io::Cursor,
    key::{Keypair, TapTweak},
    psbt::PsbtSighashType,
    secp256k1::{ecdsa::Signature, Message},
    sighash::{self, SighashCache},
    Address, EcdsaSighashType, OutPoint, Psbt, ScriptBuf, Sequence, TapSighashType, TxIn, TxOut,
    Witness,
};
use std::println;

use crate::{to_sign, to_spend, Error, SignatureFormat};

pub trait BIP322 {
    fn sign_bip322(
        &mut self,
        message: &str,
        utxos: Option<Vec<OutPoint>>,
        address: Address,
        sig_type: SignatureFormat,
    ) -> Result<Bip322Proof, Error>;
    fn verify_bip322(
        &mut self,
        proof: &Bip322Proof,
        message: &str,
        sig_type: SignatureFormat,
    ) -> Result<bool, Error>;
}

#[derive(Debug)]
pub enum Bip322Proof {
    Signed(String),
    Psbt(Psbt),
}

impl BIP322 for Wallet {
    fn sign_bip322(
        &mut self,
        message: &str,
        utxos: Option<Vec<OutPoint>>,
        address: Address,
        sig_type: SignatureFormat,
    ) -> Result<Bip322Proof, Error> {
        let script_pubkey = address.script_pubkey();

        let to_spend = to_spend(&script_pubkey, message);
        let mut to_sign = to_sign(&to_spend)?;

        if sig_type == SignatureFormat::FullWithProofOfFunds {
            let address_utxos: Vec<(OutPoint, TxOut)> = if let Some(specific_utxos) = utxos {
                // Use only the specified UTXOs that belong to this address
                self.list_unspent()
                    .into_iter()
                    .filter(|utxo| {
                        specific_utxos.contains(&utxo.outpoint)
                            && utxo.txout.script_pubkey == script_pubkey
                    })
                    .map(|utxo| (utxo.outpoint, utxo.txout))
                    .collect()
            } else {
                // If no specific UTXOs provided, use ALL UTXOs for this address
                self.list_unspent()
                    .into_iter()
                    .filter(|utxo| utxo.txout.script_pubkey == script_pubkey)
                    .map(|utxo| (utxo.outpoint, utxo.txout))
                    .collect()
            };

            if address_utxos.is_empty() {
                return Err(Error::InvalidFormat(
                    "No UTXOs available for proof-of-funds".to_string(),
                ));
            }

            for (outpoint, _) in &address_utxos {
                to_sign.input.push(TxIn {
                    previous_output: *outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ZERO,
                    witness: Witness::new(),
                });
            }
        } else if utxos.is_some() {
            return Err(Error::InvalidFormat(
                "UTXOs only supported for FullWithProofOfFunds".to_string(),
            ));
        }

        let mut psbt = Psbt::from_unsigned_tx(to_sign)?;

        for (i, (psbt_input, tx_input)) in psbt
            .inputs
            .iter_mut()
            .zip(psbt.unsigned_tx.input.iter())
            .enumerate()
        {
            psbt_input.sighash_type = if script_pubkey.is_p2tr() {
                Some(PsbtSighashType::from(TapSighashType::All))
            } else {
                Some(PsbtSighashType::from(EcdsaSighashType::All))
            };

            if i == 0 {
                if script_pubkey.is_p2tr() || script_pubkey.is_p2wpkh() || script_pubkey.is_p2wsh()
                {
                    psbt_input.witness_utxo = Some(to_spend.output[0].clone())
                } else {
                    psbt_input.non_witness_utxo = Some(to_spend.clone())
                }
            } else {
                let utxo = self
                    .get_utxo(tx_input.previous_output)
                    .ok_or(Error::UnsupportedType)?;

                let txout = utxo.txout;

                if txout.script_pubkey.is_p2tr()
                    || txout.script_pubkey.is_p2wpkh()
                    || txout.script_pubkey.is_p2wsh()
                {
                    psbt_input.witness_utxo = Some(txout.clone());
                } else {
                    let tx = self
                        .get_tx(tx_input.previous_output.txid)
                        .ok_or(Error::InvalidMessage)?;
                    psbt_input.non_witness_utxo = Some(tx.tx_node.tx.as_ref().clone());
                }
            }
        }

        let sign_options = SignOptions {
            trust_witness_utxo: true,
            ..Default::default()
        };

        let finalized = self.sign(&mut psbt, sign_options)?;

        if finalized {
            let mut buffer = Vec::new();

            match sig_type {
                SignatureFormat::Simple => {
                    if !script_pubkey.is_p2tr()
                        && !script_pubkey.is_p2wpkh()
                        && !script_pubkey.is_p2wsh()
                    {
                        return Err(Error::InvalidFormat(
                            "Simple format requires segwit address".to_string(),
                        ));
                    }

                    let witness = psbt.inputs[0]
                        .final_script_witness
                        .as_ref()
                        .ok_or(Error::InvalidFormat("No final witness found".to_string()))?;

                    if witness.is_empty() {
                        return Err(Error::InvalidFormat("Empty witness".to_string()));
                    }

                    if script_pubkey.is_p2wpkh() && witness.len() != 2 {
                        return Err(Error::InvalidFormat(
                            "Invalid P2WPKH witness structure".to_string(),
                        ));
                    } else if script_pubkey.is_p2tr() && witness.len() < 1 {
                        return Err(Error::InvalidFormat(
                            "Invalid P2TR witness structure".to_string(),
                        ));
                    }

                    witness.consensus_encode(&mut buffer)?;
                    let simple_signature = general_purpose::STANDARD.encode(&buffer);
                    return Ok(Bip322Proof::Signed(simple_signature));
                }
                SignatureFormat::Full | SignatureFormat::FullWithProofOfFunds => {
                    let tx = psbt.extract_tx()?;
                    tx.consensus_encode(&mut buffer)?;
                    let full_signature = general_purpose::STANDARD.encode(&buffer);
                    return Ok(Bip322Proof::Signed(full_signature));
                }
            }
        } else {
            return Ok(Bip322Proof::Psbt(psbt));
        }
    }

    fn verify_bip322(
        &mut self,
        proof: &Bip322Proof,
        message: &str,
        sig_type: SignatureFormat,
    ) -> Result<bool, Error> {
        match proof {
            Bip322Proof::Signed(tx) => {
                println!("Got a fully signed raw tx: {:?}", tx);
            }
            Bip322Proof::Psbt(psbt) => {
                println!("Got a PSBT that needs hardware signing: {:?}", psbt);
            }
        }

        Ok(true)
    }
}
