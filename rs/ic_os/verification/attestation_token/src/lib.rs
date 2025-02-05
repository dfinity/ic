pub mod verification;

use der::{Decode, Encode};
use ic_cbor::CertificateToCbor;
#[cfg(not(target_arch = "wasm32"))]
use ic_certificate_verification::VerifyCertificate;
use ic_certification::certificate::Certificate;
use ic_certification::{AsHashTree, HashTree, LookupResult};
use ic_principal::Principal;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt::{Debug, Display, Formatter};
use std::str::FromStr;
use std::time::SystemTime;

pub const ATTESTATION_TOKENS_LABEL: &[u8] = b"attestation_tokens";

#[derive(Serialize, Deserialize)]
pub struct AttestationTokenPayload {
    pub issued_epoch_sec: u64,
    pub expires_epoch_sec: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AttestationToken {
    pub tls_public_key: Vec<u8>,
    pub hash_tree: HashTree,
    pub certificate: Certificate<Vec<u8>>,
}

#[derive(Debug)]
pub struct DecodingError(pub String);

impl Error for DecodingError {}
impl Display for DecodingError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(self, f)
    }
}
