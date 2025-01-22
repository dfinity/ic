use crate::certified_state::CertifiedState;
use anyhow::{Context, Result};
use attestation::protocol::{
    GenerateAttestationTokenError, GenerateAttestationTokenRequest,
    GenerateAttestationTokenResponse,
};
use attestation::verify::verify_generate_attestation_token_request;
use attestation_token::{AttestationToken, AttestationTokenPayload};
use candid::CandidType;
use ic_cbor::CertificateToCbor;
use ic_cdk::{query, update};
use ic_certification::{AsHashTree, Certificate};
use serde::Deserialize;
use std::error::Error;
use std::ops::Add;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

mod certified_state;

const ATTESTATION_TOKEN_DEFAULT_EXPIRATION: Duration = Duration::from_secs(90 * 24 * 3600);

thread_local! {
    static CERTIFIED_STATE: CertifiedState = CertifiedState::default();
}

#[update]
fn generate_attestation_token(
    request: GenerateAttestationTokenRequest,
) -> Result<GenerateAttestationTokenResponse, GenerateAttestationTokenError> {
    verify_generate_attestation_token_request(&request, &[])?;

    let node_id = ic_cdk::caller();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Now should be later than epoch");
    CERTIFIED_STATE.with(|state| {
        state
            .insert_attestation_token(&AttestationTokenPayload {
                tls_public_key: request.tls_public_key,
                issued_epoch_sec: now.as_secs(),
                expires_epoch_sec: now.add(ATTESTATION_TOKEN_DEFAULT_EXPIRATION).as_secs(),
                node_id,
            })
            .map_err(|err| GenerateAttestationTokenError::Internal(err.to_string()))?;

        ic_cdk::api::set_certified_data(&state.digest());
        Ok(())
    })?;

    Ok(GenerateAttestationTokenResponse {})
}

#[derive(CandidType)]
enum AttestationTokenError {
    AttestationTokenNotFound,
    Internal(String),
}

impl<E: Error> From<E> for AttestationTokenError {
    fn from(error: E) -> Self {
        AttestationTokenError::Internal(error.to_string())
    }
}

#[derive(CandidType)]
struct AttestationTokenResponse {
    attestation_token: Vec<u8>,
}

#[derive(Deserialize, CandidType)]
struct AttestationTokenRequest {}

#[query]
fn get_attestation_token(
    _request: AttestationTokenRequest,
) -> Result<AttestationTokenResponse, AttestationTokenError> {
    let node_id = ic_cdk::caller();
    CERTIFIED_STATE.with(|state| {
        let Some(attestation_token_witness) = state.attestation_token_witness(&node_id) else {
            return Err(AttestationTokenError::AttestationTokenNotFound);
        };

        let attestation_token = AttestationToken {
            node_id,
            hash_tree: attestation_token_witness,
            certificate: Certificate::from_cbor(
                &ic_cdk::api::data_certificate().expect("Missing data certificate"),
            )?,
        };

        Ok(AttestationTokenResponse {
            attestation_token: serde_cbor::to_vec(&attestation_token)?,
        })
    })
}
