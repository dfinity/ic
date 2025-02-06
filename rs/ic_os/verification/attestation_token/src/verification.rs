use crate::{AttestationToken, AttestationTokenPayload};
use ic_certificate_verification::VerifyCertificate;
use ic_certification::LookupResult;
use ic_principal::Principal;
use std::fmt::Debug;
use std::ops::Add;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// const NNS_PUBLIC_KEY: [u8; 133] = [
//     48, 129, 130, 48, 29, 6, 13, 43, 6, 1, 4, 1, 130, 220, 124, 5, 3, 1, 2, 1, 6, 12, 43, 6, 1, 4,
//     1, 130, 220, 124, 5, 3, 2, 1, 3, 97, 0, 175, 130, 225, 40, 178, 188, 188, 155, 73, 34, 127, 83,
//     134, 54, 92, 4, 64, 3, 124, 220, 90, 201, 118, 79, 70, 100, 158, 51, 19, 101, 5, 165, 208, 210,
//     226, 104, 27, 209, 144, 197, 176, 19, 202, 102, 214, 167, 94, 146, 3, 123, 14, 3, 123, 207,
//     188, 93, 190, 100, 123, 40, 212, 213, 107, 114, 103, 113, 182, 217, 193, 111, 237, 143, 95,
//     167, 151, 108, 232, 227, 223, 68, 157, 166, 12, 25, 157, 89, 132, 62, 229, 46, 116, 153, 21,
//     230, 211, 55,
const NNS_PUBLIC_KEY: [u8; 0] = []; // TODO: figure this out
const VERIFICATION_CANISTER_ID: Principal = Principal::from_slice(&[]);

enum AttestationTokenError {}

trait TimeSource: Debug + Send + Sync {
    fn get_current_time(&self) -> SystemTime;
}

#[derive(Debug)]
struct SystemTimeSource;

impl TimeSource for SystemTimeSource {
    fn get_current_time(&self) -> SystemTime {
        SystemTime::now()
    }
}

#[derive(Debug)]
pub struct AttestationTokenVerifier {
    time_source: Box<dyn TimeSource>,
    verification_canister_id: Principal,
    root_public_key: Vec<u8>,
    tls_public_key: Vec<u8>,
}

impl AttestationTokenVerifier {
    pub fn set_time_source(mut self, time_source: Box<dyn TimeSource>) -> Self {
        self.time_source = time_source;
        self
    }

    pub fn set_verification_canister_id(mut self, id: Principal) -> Self {
        self.verification_canister_id = id;
        self
    }

    pub fn set_root_public_key(mut self, key: Vec<u8>) -> Self {
        self.root_public_key = key;
        self
    }
}

impl Default for AttestationTokenVerifier {
    fn default() -> Self {
        Self {
            time_source: Box::new(SystemTimeSource),
            verification_canister_id: VERIFICATION_CANISTER_ID,
            root_public_key: NNS_PUBLIC_KEY.to_vec(),
            tls_public_key: Vec::new(),
        }
    }
}

impl AttestationTokenVerifier {
    pub fn verify(&self, attestation_token: &AttestationToken) -> Result<(), String> {
        attestation_token
            .certificate
            .verify(
                self.verification_canister_id.as_slice(),
                &self.root_public_key,
                &self
                    .time_source
                    .get_current_time()
                    .duration_since(UNIX_EPOCH)
                    .expect("Current time must be > 1970-01-01")
                    .as_nanos(),
                // We're liberal with this and allow ~10 years.
                &Duration::from_secs(10 * 365 * 24 * 3600).as_nanos(),
            )
            .map_err(|err| err.to_string())?;

        if attestation_token.tls_public_key != self.tls_public_key {
            return Err("Tls key mismatch".to_string());
        }

        let LookupResult::Found(serialized_attestation_token_payload) =
            attestation_token.hash_tree.lookup_path([
                b"attestation_tokens",
                attestation_token.tls_public_key.as_slice(),
            ])
        else {
            return Err("Attestation token not found in hash tree".to_string());
        };

        if attestation_token.certificate.tree.lookup_path([
            b"canister",
            self.verification_canister_id.as_slice(),
            b"certified_data",
        ]) != LookupResult::Found(&attestation_token.hash_tree.digest())
        {
            return Err("Certified data hash does not match hash tree root hash".to_string());
        }

        let payload: AttestationTokenPayload =
            serde_cbor::from_slice(serialized_attestation_token_payload)
                .map_err(|err| format!("Could not deserialize payload {err}"))?;

        if self.time_source.get_current_time()
            > UNIX_EPOCH.add(Duration::from_secs(payload.expires_epoch_sec))
        {
            return Err("Attestation token expired".to_string());
        }

        Ok(())
    }
}
