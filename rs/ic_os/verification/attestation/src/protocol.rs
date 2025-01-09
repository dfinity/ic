use crate::attestation::SevAttestationReport;
use candid::Deserialize;
use std::error::Error;

#[non_exhaustive]
#[derive(candid::CandidType, candid::Deserialize)]
struct GenerateAttestationTokenChallenge {
    nonce: Vec<u8>,
}

#[derive(candid::CandidType)]
pub struct InitiateGenerateAttestationTokenRequest {
    pub chip_id: Vec<u8>,
}

#[derive(candid::CandidType, candid::Deserialize)]
pub struct InitiateGenerateAttestationTokenResponse {
    pub challenge: GenerateAttestationTokenChallenge,
}

#[derive(candid::CandidType, candid::Deserialize)]
pub struct GenerateAttestationTokenRequest {
    pub tls_public_key: Vec<u8>,
    pub nonce: Vec<u8>,
    pub sev_attestation_report: SevAttestationReport,
}

#[derive(candid::CandidType, candid::Deserialize)]
#[non_exhaustive]
pub enum GenerateAttestationTokenError {
    InvalidNonce,
    InvalidAttestationReport(String),
    Internal(String),
}

impl<E: Error> From<E> for GenerateAttestationTokenError {
    fn from(error: E) -> Self {
        GenerateAttestationTokenError::Internal(error.to_string())
    }
}

#[derive(candid::CandidType)]
pub struct GenerateAttestationTokenResponse {}

trait Attestor {
    fn initiate_generate_attestation_token(
        &self,
        request: InitiateGenerateAttestationTokenRequest,
    ) -> InitiateGenerateAttestationTokenResponse;

    fn generate_attestation_token(
        &self,
        request: GenerateAttestationTokenRequest,
    ) -> GenerateAttestationTokenResponse;
}
