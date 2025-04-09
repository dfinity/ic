// use crate::attestation::SevAttestationPackage;
// use candid::CandidType;
// use std::fmt::{Debug, Display};
//
// pub use crate::error::{VerificationError, VerificationErrorDetail};
//
// #[derive(CandidType, candid::Deserialize)]
// pub struct GenerateAttestationTokenChallenge {
//     pub nonce: Vec<u8>,
// }
//
// #[derive(CandidType, candid::Deserialize)]
// pub struct InitiateGenerateAttestationTokenRequest {
//     pub tls_public_key_pem: String,
// }
//
// #[derive(CandidType, candid::Deserialize)]
// pub struct InitiateGenerateAttestationTokenResponse {
//     pub challenge: GenerateAttestationTokenChallenge,
// }
//
// #[derive(CandidType, candid::Deserialize)]
// pub struct GenerateAttestationTokenRequest {
//     pub tls_public_key_der: Vec<u8>,
//     pub nonce: Vec<u8>,
//     pub sev_attestation_report: SevAttestationPackage,
// }
//
// #[derive(CandidType, candid::Deserialize)]
// pub struct GenerateTlsCertificateRequest {
//     pub tls_public_key_pem: String,
//     pub nonce: Vec<u8>,
//     pub sev_attestation_report: SevAttestationPackage,
// }
//
// #[derive(CandidType, candid::Deserialize)]
// pub struct GenerateTlsCertificateResponse {
//     pub tls_certificate_pem: String,
// }
//
// #[derive(CandidType, candid::Deserialize)]
// pub struct GenerateAttestationTokenResponse {}
//
// #[derive(CandidType, candid::Deserialize)]
// pub struct FetchAttestationTokenRequest {
//     pub tls_public_key: Vec<u8>,
// }
//
// #[derive(CandidType, candid::Deserialize)]
// pub struct FetchAttestationTokenResponse {
//     pub attestation_token: Vec<u8>,
// }
