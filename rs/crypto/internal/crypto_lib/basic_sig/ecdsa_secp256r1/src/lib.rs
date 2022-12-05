#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]

//! ECDSA signatures using the secp256r1 (P-256) group

use openssl::nid::Nid;

mod api;
pub mod types;
pub use api::*;

pub mod test_utils;

// NOTE: prime256v1 is a yet another name for secp256r1 (aka. NIST P-256),
// cf. https://tools.ietf.org/html/rfc5480
const CURVE_NAME: Nid = Nid::X9_62_PRIME256V1;
