use crate::certified_state::CertifiedState;
use crate::proto::NonceInfo;
use anyhow::{Context, Result};
use attestation::protocol::{
    FetchAttestationTokenRequest, FetchAttestationTokenResponse, GenerateAttestationTokenChallenge,
    GenerateAttestationTokenRequest, GenerateAttestationTokenResponse,
    InitiateGenerateAttestationTokenRequest, InitiateGenerateAttestationTokenResponse,
    VerificationError, VerificationErrorDetail,
};
use attestation::verify::verify_generate_attestation_token_request;
use attestation_token::{AttestationToken, AttestationTokenPayload};
use candid::{export_service, CandidType};
use ic_cbor::CertificateToCbor;
use ic_cdk::api::management_canister::main::raw_rand;
use ic_cdk::{export_candid, query, update};
use ic_certification::{AsHashTree, Certificate};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{DefaultMemoryImpl, Memory, StableBTreeMap};
use serde::Deserialize;
use std::cell::RefCell;
use std::error::Error;
use std::fmt::Display;
use std::ops::Add;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

mod certified_state;
mod proto;

const ATTESTATION_TOKEN_DEFAULT_EXPIRATION: Duration = Duration::from_secs(90 * 24 * 3600);
const MAX_NONCE_AGE: Duration = Duration::from_secs(300);

thread_local! {
    static MEMORY_MANAGER: MemoryManager<DefaultMemoryImpl> = MemoryManager::init(DefaultMemoryImpl::default());
    static CERTIFIED_STATE: CertifiedState = CertifiedState::default();

    static NONCES: RefCell<StableBTreeMap<Vec<u8>, NonceInfo, VirtualMemory<DefaultMemoryImpl>>> =
        RefCell::new(MEMORY_MANAGER.with(|memory| StableBTreeMap::init(memory.get(MemoryId::new(0)))));
}

fn now() -> SystemTime {
    UNIX_EPOCH.add(Duration::from_nanos(ic_cdk::api::time()))
}

#[update]
async fn initiate_generate_attestation_token(
    request: InitiateGenerateAttestationTokenRequest,
) -> Result<InitiateGenerateAttestationTokenResponse, VerificationError> {
    let nonce = raw_rand()
        .await
        .map_err(|err| VerificationError::internal(err.1))?
        .0;
    NONCES.with_borrow_mut(|nonces| {
        nonces.insert(
            request.tls_public_key,
            NonceInfo {
                nonce: nonce.clone(),
                generated_at: Some(now().into()),
            },
        )
    });

    Ok(InitiateGenerateAttestationTokenResponse {
        challenge: GenerateAttestationTokenChallenge { nonce },
    })
}

#[update]
fn generate_attestation_token(
    request: GenerateAttestationTokenRequest,
) -> Result<GenerateAttestationTokenResponse, VerificationError> {
    // Validate nonce & attestation token request
    NONCES.with_borrow(|nonces| {
        let nonce_info = nonces
            .get(&request.tls_public_key)
            .ok_or::<VerificationError>(VerificationErrorDetail::NonceNotFound {}.into())?;
        let nonce_generated_at: SystemTime = nonce_info
            .generated_at
            .unwrap_or_default()
            .try_into()
            .map_err_to_internal_with_context("Could not convert nonce to SystemTime")?;
        if nonce_generated_at < now() - MAX_NONCE_AGE {
            return Err(VerificationErrorDetail::NonceTooOld {}.into());
        }

        verify_generate_attestation_token_request(&request, &nonce_info.nonce)
    })?;

    let node_id = ic_cdk::caller();
    let now_epoch = Duration::from_nanos(ic_cdk::api::time());
    CERTIFIED_STATE.with(|state| {
        state
            .insert_attestation_token(&AttestationTokenPayload {
                tls_public_key: request.tls_public_key,
                issued_epoch_sec: now_epoch.as_secs(),
                expires_epoch_sec: now_epoch
                    .add(ATTESTATION_TOKEN_DEFAULT_EXPIRATION)
                    .as_secs(),
                node_id,
            })
            .map_err_to_internal_with_context(
                "Could not add attestation token to certified state",
            )?;

        ic_cdk::api::set_certified_data(&state.digest());
        Ok::<(), VerificationError>(())
    })?;

    Ok(GenerateAttestationTokenResponse {})
}

#[query]
fn fetch_attestation_token(
    _request: FetchAttestationTokenRequest,
) -> Result<FetchAttestationTokenResponse, VerificationError> {
    let node_id = ic_cdk::caller();

    CERTIFIED_STATE.with(|state| {
        let Some(attestation_token_witness) = state.attestation_token_witness(&node_id) else {
            return Err(VerificationErrorDetail::AttestationTokenNotFound.into());
        };

        let attestation_token = AttestationToken {
            node_id,
            hash_tree: attestation_token_witness,
            certificate: Certificate::from_cbor(
                &ic_cdk::api::data_certificate()
                    .ok_or_else(|| VerificationError::internal("Missing data certificate"))?,
            )
            .map_err_to_internal_with_context("Could not decode data certificate")?,
        };

        Ok(FetchAttestationTokenResponse {
            attestation_token: serde_cbor::to_vec(&attestation_token).map_err_to_internal()?,
        })
    })
}

pub trait ToVerificationError<T> {
    fn map_err_to_internal(self) -> std::result::Result<T, VerificationError>;
    fn map_err_to_internal_with_context(
        self,
        context: &str,
    ) -> std::result::Result<T, VerificationError>;
}

impl<T, E: Display> ToVerificationError<T> for std::result::Result<T, E> {
    fn map_err_to_internal(self) -> std::result::Result<T, VerificationError> {
        self.map_err(|err| VerificationError::internal(err))
    }

    fn map_err_to_internal_with_context(
        self,
        context: &str,
    ) -> std::result::Result<T, VerificationError> {
        self.map_err(|err| VerificationError::internal(format!("{context}\n\nCaused by:\n{err}")))
    }
}

pub mod export {
    use super::*;
    #[test]
    fn test_export() {
        candid::export_service!();
        println!("{}", __export_service());
    }
}
