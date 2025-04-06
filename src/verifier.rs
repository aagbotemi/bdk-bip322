use alloc::string::String;

use crate::SignatureFormat;

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
}
