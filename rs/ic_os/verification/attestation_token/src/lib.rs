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

#[cfg(not(test))]
const NNS_PUBLIC_KEY: [u8; 133] = [
    48, 129, 130, 48, 29, 6, 13, 43, 6, 1, 4, 1, 130, 220, 124, 5, 3, 1, 2, 1, 6, 12, 43, 6, 1, 4,
    1, 130, 220, 124, 5, 3, 2, 1, 3, 97, 0, 175, 130, 225, 40, 178, 188, 188, 155, 73, 34, 127, 83,
    134, 54, 92, 4, 64, 3, 124, 220, 90, 201, 118, 79, 70, 100, 158, 51, 19, 101, 5, 165, 208, 210,
    226, 104, 27, 209, 144, 197, 176, 19, 202, 102, 214, 167, 94, 146, 3, 123, 14, 3, 123, 207,
    188, 93, 190, 100, 123, 40, 212, 213, 107, 114, 103, 113, 182, 217, 193, 111, 237, 143, 95,
    167, 151, 108, 232, 227, 223, 68, 157, 166, 12, 25, 157, 89, 132, 62, 229, 46, 116, 153, 21,
    230, 211, 55,
];

pub const ATTESTATION_TOKENS_LABEL: &[u8] = b"attestation_tokens";

#[cfg(test)]
const NNS_PUBLIC_KEY: [u8; 32] = [0; 32];

#[derive(Serialize, Deserialize)]
pub struct AttestationTokenPayload {
    pub tls_public_key: Vec<u8>,
    pub issued_epoch_sec: u64,
    pub expires_epoch_sec: u64,
    pub node_id: Principal,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AttestationToken {
    pub node_id: Principal,
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

impl AttestationToken {
    pub fn from_der(attestation_token_der: &[u8]) -> Result<Self, DecodingError> {
        let attestation_token = der::asn1::OctetStringRef::from_der(attestation_token_der)
            .map_err(|err| DecodingError(err.to_string()))?;
        serde_cbor::from_slice(&attestation_token.as_bytes())
            .map_err(|err| DecodingError(err.to_string()))
    }
}

pub struct SerializedAttestationToken(pub Vec<u8>);

impl SerializedAttestationToken {
    pub fn to_der(&self) -> Result<Vec<u8>, der::Error> {
        der::asn1::OctetStringRef::new(&self.0)?.to_der()
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub use read::*;

#[cfg(not(target_arch = "wasm32"))]
mod read {
    use super::*;
    use std::time::Duration;

    impl AttestationToken {
        pub fn verify_and_extract_payload(&self) -> Result<AttestationTokenPayload, String> {
            self.verify_and_extract_payload_impl(
                "bkyz2-fmaaa-aaaaa-qaaaq-cai".parse().unwrap(),
                &NNS_PUBLIC_KEY,
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .expect("Now must be after epoch")
                    .as_nanos(),
                // We're liberal with this and allow ~1 year.
                Duration::from_secs(365 * 24 * 3600).as_nanos(),
            )
        }

        fn verify_and_extract_payload_impl(
            &self,
            verification_canister_id: Principal,
            root_public_key: &[u8],
            current_time_ns: u128,
            allowed_certificate_time_offset: u128,
        ) -> Result<AttestationTokenPayload, String> {
            self.certificate
                .verify(
                    verification_canister_id.as_slice(),
                    root_public_key,
                    &current_time_ns,
                    &allowed_certificate_time_offset,
                )
                .map_err(|err| err.to_string())?;

            let LookupResult::Found(serialized_attestation_token_payload) = self
                .hash_tree
                .lookup_path([b"attestation_tokens", self.node_id.as_slice()])
            else {
                return Err("Attestation token not found in hash tree".to_string());
            };

            dbg!(self.certificate.tree.lookup_path([
                b"canister",
                verification_canister_id.as_slice(),
                b"certified_data",
            ]));
            if self.certificate.tree.lookup_path([
                b"canister",
                verification_canister_id.as_slice(),
                b"certified_data",
            ]) != LookupResult::Found(&self.hash_tree.digest())
            {
                return Err("Certified data hash does not match hash tree root hash".to_string());
            }

            serde_cbor::from_slice(serialized_attestation_token_payload)
                .map_err(|err| format!("Could not deserialize payload {err}"))
        }
    }
}

/*


fn verify_and_extract_payload_impl(
        attestation_token: &AttestationToken,
        verification_canister_id: &[u8],
        root_public_key: &[u8],
        current_time_ns: u128,
        allowed_certificate_time_offset: u128,
    ) -> Result<AttestationTokenPayload, String> {
        attestation_token
            .certificate
            .verify(
                verification_canister_id,
                root_public_key,
                &current_time_ns,
                &allowed_certificate_time_offset,
            )
            .map_err(|err| err.to_string())?;

        let SubtreeLookupResult::Found(attestation_token_subtree) = attestation_token
            .hash_tree
            .lookup_subtree([b"attestation_tokens", attestation_token.node_id.as_slice()]) else {
            return Err("Attestation token not found in hash tree".to_string());
        };

        if attestation_token.certificate.tree.lookup_path([
            b"canister",
            verification_canister_id,
            b"certified_data",
        ]) != LookupResult::Found(&attestation_token.hash_tree.digest())
        {
            return Err("Certified data hash does not match hash tree root hash".to_string());
        }

        let tls_public_key =
            lookup_field_or_err(&attestation_token_subtree, "tls_public_key")?.to_owned();

        let issued_epoch_sec = u64::from_str(
            std::str::from_utf8(lookup_field_or_err(
                &attestation_token_subtree,
                "issued_epoch_sec",
            )?)
            .map_err(|err| "Invalid utf8 in issued_epoch_sec".to_string())?,
        )
        .map_err(|err| "Could not deserialize int")?;

        let expires_epoch_sec = u64::from_str(
            std::str::from_utf8(lookup_field_or_err(
                &attestation_token_subtree,
                "expires_epoch_sec",
            )?)
            .map_err(|err| "Invalid utf8 in expires_epoch_sec".to_string())?,
        )
        .map_err(|err| "Could not deserialize int")?;

        Ok(AttestationTokenPayload {
            tls_public_key,
            issued_epoch_sec,
            expires_epoch_sec,
            node_id: attestation_token.node_id
        })
    }


 */

// #[cfg(test)]
// mod tests {
//     use ic_certification_testing::{CertificateBuilder, CertificateData};
//
//     #[test]
//     fn create_and_read() {
//         CertificateBuilder::new(
//             &canister_id.to_string(),
//             &AssetTree::new().get_certified_data(),
//         )
//     }
// }
