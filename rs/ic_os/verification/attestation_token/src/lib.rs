use ic_cbor::CertificateToCbor;
#[cfg(not(target_arch = "wasm32"))]
use ic_certificate_verification::{CertificateVerificationError, VerifyCertificate};
use ic_certification::certificate::Certificate;
use ic_certification::{fork, labeled, leaf, AsHashTree, Hash, HashTree, LookupResult};
use ic_principal::Principal;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::str::FromStr;
use std::time::{Instant, SystemTime};

const VERIFICATION_CANISTER_ID: [u8; 12] = [0; 12];

#[cfg(not(test))]
const NNS_PUBLIC_KEY: [u8; 32] = [0; 32];

#[cfg(test)]
const NNS_PUBLIC_KEY: [u8; 32] = [0; 32];

// pub struct AttestationTokenPayload {
//     pub tls_public_key: Vec<u8>,
//     pub issued_epoch_sec: u64,
//     pub expires_epoch_sec: u64,
// }

#[derive(Serialize, Deserialize)]
pub struct AttestationTokenPayload {
    pub tls_public_key: Vec<u8>,
    pub issued_epoch_sec: u64,
    pub expires_epoch_sec: u64,
    pub node_id: Principal,
}

// impl AsHashTree for AttestationTokenPayload {
//     fn root_hash(&self) -> Hash {
//         self.as_hash_tree().digest()
//     }
//
//     fn as_hash_tree(&self) -> HashTree {
//         fork(
//             labeled("tls_public_key", leaf(self.tls_public_key.clone())),
//             fork(
//                 // TODO: use native bigendian instead of to string?
//                 labeled("issued_epoch_sec", leaf(self.issued_epoch_sec.to_string())),
//                 labeled(
//                     "expires_epoch_sec",
//                     leaf(self.expires_epoch_sec.to_string()),
//                 ),
//             ),
//         )
//     }
// }

#[derive(Serialize, Deserialize, Debug)]
pub struct AttestationToken {
    pub node_id: Principal,
    pub hash_tree: HashTree,
    pub certificate: Certificate<Vec<u8>>,
}

#[cfg(not(target_arch = "wasm32"))]
pub use read::*;

#[cfg(not(target_arch = "wasm32"))]
mod read {
    use super::*;
    use ic_certification::SubtreeLookupResult;
    use std::time::Duration;

    // #[non_exhaustive]
    // pub enum AttestationTokenError {
    //     InvalidCertificate(CertificateVerificationError),
    //     HashTreeDigestMismatch,
    //     MissingField(&'static str),
    //     InvalidFieldValue(&'static str, Vec<u8>),
    // }

    pub fn verify_and_extract_payload(
        attestation_token: &AttestationToken,
    ) -> Result<AttestationTokenPayload, String> {
        verify_and_extract_payload_impl(
            attestation_token,
            &VERIFICATION_CANISTER_ID,
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

        let LookupResult::Found(serialized_attestation_token_payload) = attestation_token
            .hash_tree
            .lookup_path([b"attestation_tokens", attestation_token.node_id.as_slice()])
        else {
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

        serde_cbor::from_slice(serialized_attestation_token_payload)
            .map_err(|err| format!("Could not deserialize payload {err}"))
    }

    fn lookup_field_or_err<'a>(
        hash_tree: &'a HashTree,
        field_name: &str,
    ) -> Result<&'a [u8], String> {
        match hash_tree.lookup_path([field_name]) {
            LookupResult::Found(value) => Ok(value),
            _ => Err(format!("Missing field in hash tree: {field_name}")),
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
