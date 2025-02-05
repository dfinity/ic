use crate::sev_firmware::mock::MockSevFirmware;
use crate::sev_firmware::{RealSevFirmware, SevFirmware};
use crate::verification_agent::{VerificationAgent, VerificationCanisterClient};
use anyhow::{Context, Result};
use attestation::attestation::GenerateAttestationTokenCustomData;
use attestation::protocol::{
    FetchAttestationTokenRequest, GenerateAttestationTokenRequest,
    InitiateGenerateAttestationTokenRequest,
};
use attestation_token::SerializedAttestationToken;
use der::asn1::OctetStringRef;
use der::Encode;
use ic_agent::identity::{AnonymousIdentity, BasicIdentity};
use sev::firmware::guest::Firmware;
use sha2::Digest;
use std::io::Read;

pub mod sev_firmware;
pub mod verification_agent;

#[derive(Debug, Clone)]
pub struct SerializedAttestationToken(pub Vec<u8>);

pub async fn fetch_attestation_token(
    tls_public_key: &[u8],
    identity_pem: impl Read,
) -> Result<SerializedAttestationToken> {
    fetch_attestation_token_impl(
        tls_public_key,
        &mut MockSevFirmware::new(),
        // &mut RealSevFirmware(Firmware::open().context("Could not open SEV firmware")?),
        &mut VerificationCanisterClient::new(
            AnonymousIdentity, // BasicIdentity::from_pem(identity_pem).context("Could not read identity")?,
        ),
    )
    .await
}

pub(crate) async fn fetch_attestation_token_impl(
    tls_public_key: &[u8],
    firmware: &mut dyn SevFirmware,
    verification_agent: &mut dyn VerificationAgent,
) -> Result<SerializedAttestationToken> {
    let initiate_response = verification_agent
        .initiate_generate_attestation_token(&InitiateGenerateAttestationTokenRequest {
            tls_public_key: tls_public_key.to_vec(),
        })
        .await
        .context("Call to initiate_generate_attestation_token failed")?;
    let custom_data_bytes = GenerateAttestationTokenCustomData {
        nonce: OctetStringRef::new(&initiate_response.challenge.nonce)?,
        tls_public_key: OctetStringRef::new(tls_public_key)?,
    }
    .to_bytes()?;
    let report = firmware
        .get_report(&custom_data_bytes)
        .context("Could not get attestation report from SEV firmware")?;

    verification_agent
        .generate_attestation_token(&GenerateAttestationTokenRequest {
            tls_public_key: tls_public_key.to_vec(),
            nonce: initiate_response.challenge.nonce.to_vec(),
            sev_attestation_report: report,
        })
        .await
        .context("Call to generate_attestation_token failed")?;

    let attestation_token = verification_agent
        .fetch_attestation_token(&FetchAttestationTokenRequest {
            tls_public_key: tls_public_key.to_vec(),
        })
        .await
        .context("Call to fetch_attestation_token failed")?;

    Ok(SerializedAttestationToken(
        attestation_token.attestation_token,
    ))
}
