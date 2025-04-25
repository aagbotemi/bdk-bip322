use anyhow::Ok;
use bdk_bip322::{SignatureFormat, Signer, Verifier};
use bdk_wallet::{
    keys::DescriptorSecretKey, miniscript::ToPublicKey, rusqlite::Connection, KeychainKind, Wallet,
};
use bitcoin::{key::Secp256k1, Address, Network, PrivateKey};

const DB_PATH: &str = "bdk-example-esplora-async.sqlite";
const NETWORK: Network = Network::Signet;
const EXTERNAL_DESC: &str = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/0/*)";
const INTERNAL_DESC: &str = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/1/*)";

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let mut conn = Connection::open(DB_PATH)?;

    let wallet_opt = Wallet::load()
        .descriptor(KeychainKind::External, Some(EXTERNAL_DESC))
        .descriptor(KeychainKind::Internal, Some(INTERNAL_DESC))
        .extract_keys()
        .check_network(NETWORK)
        .load_wallet(&mut conn)?;
    let mut wallet = match wallet_opt {
        Some(wallet) => wallet,
        None => Wallet::create(EXTERNAL_DESC, INTERNAL_DESC)
            .network(NETWORK)
            .create_wallet(&mut conn)?,
    };

    wallet.persist(&mut conn)?;

    let private_key_option: Option<PrivateKey> = wallet
        .get_signers(KeychainKind::External)
        .signers()
        .iter()
        .filter_map(|signer| signer.descriptor_secret_key())
        .find_map(|descriptor_secret| {
            if let DescriptorSecretKey::XPrv(single_priv) = descriptor_secret {
                Some(PrivateKey::new(single_priv.xkey.private_key, NETWORK))
            } else {
                None
            }
        });

    let secp = Secp256k1::new();

    let compressed_priv = private_key_option.unwrap();
    let pubkey = compressed_priv.public_key(&secp);
    let xonly_pubkey = pubkey.to_x_only_pubkey();

    let address = Address::p2tr(&secp, xonly_pubkey, None, NETWORK).to_string();

    let message = "HELLO WORLD".to_string();
    let private_key_wif = private_key_option.unwrap().to_wif();

    let signer = Signer::new(
        private_key_wif,
        message.clone(),
        address.clone(),
        SignatureFormat::Full,
    );
    let signature = signer.sign().unwrap();

    let verifier = Verifier::new(address, signature, message, SignatureFormat::Full, None);
    let verify = verifier.verify().unwrap();

    assert!(verify);

    Ok(())
}
