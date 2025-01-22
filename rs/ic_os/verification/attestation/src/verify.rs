use crate::attestation::{GenerateAttestationTokenCustomData, SevAttestationReport};
use crate::protocol::{GenerateAttestationTokenError, GenerateAttestationTokenRequest};
use der::asn1::{OctetString, OctetStringRef};
use sev::firmware::guest::AttestationReport;

pub fn verify_generate_attestation_token_request(
    request: &GenerateAttestationTokenRequest,
    expected_nonce: &[u8],
) -> Result<(), GenerateAttestationTokenError> {
    verify_sev_attestation_report_signature(&request.sev_attestation_report)?;

    if request.nonce != expected_nonce {
        return Err(GenerateAttestationTokenError::InvalidNonce);
    }

    let expected_custom_data = GenerateAttestationTokenCustomData {
        nonce: OctetStringRef::new(&request.nonce)?,
        tls_public_key: OctetStringRef::new(&request.tls_public_key)?,
    }
    .to_bytes()
    .map_err(|err| GenerateAttestationTokenError::Internal(err.to_string()))?;
    let attestation_report =
        as_attestation_report(&request.sev_attestation_report.attestation_report)?;
    let actual_custom_data = attestation_report.report_data;
    if actual_custom_data != expected_custom_data {
        return Err(GenerateAttestationTokenError::InvalidAttestationReport(format!("Expected attestation report custom data: {expected_custom_data:?}, actual: {actual_custom_data:?}")));
    }

    Ok(())
}

fn as_attestation_report(
    report_bytes: &[u8],
) -> Result<&AttestationReport, GenerateAttestationTokenError> {
    if report_bytes.len() != std::mem::size_of::<AttestationReport>() {
        return Err(GenerateAttestationTokenError::InvalidAttestationReport(
            "Attestation report has invalid length".to_string(),
        ));
    }

    unsafe { Ok(&*(report_bytes.as_ptr() as *const AttestationReport)) }
}

fn verify_sev_attestation_report_signature(
    report: &SevAttestationReport, /* root cert */
) -> Result<(), GenerateAttestationTokenError> {
    Ok(())
}
