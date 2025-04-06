use alloc::{string::String, vec::Vec};
use bitcoin::{OutPoint, ScriptBuf, Sequence, Witness};

use crate::SignatureFormat;

pub struct Signature {
    private_key_str: String,
    message: String,
    address_str: String,
    signature_type: SignatureFormat,
    proof_of_funds: Option<Vec<(OutPoint, ScriptBuf, Witness, Sequence)>>,
}

impl Signature {
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
}
