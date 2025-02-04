use crate::attestation::{GenerateAttestationTokenCustomData, SevAttestationReport};
use crate::error::{VerificationError, VerificationErrorDetail};
use crate::protocol::GenerateAttestationTokenRequest;
use der::asn1::OctetStringRef;
use sev::firmware::guest::AttestationReport;

pub fn verify_generate_attestation_token_request(
    request: &GenerateAttestationTokenRequest,
    expected_nonce: &[u8],
) -> Result<(), VerificationError> {
    verify_sev_attestation_report_signature(&request.sev_attestation_report)?;

    if request.nonce != expected_nonce {
        return Err(VerificationErrorDetail::InvalidNonce {}.into());
    }

    let expected_custom_data = GenerateAttestationTokenCustomData {
        nonce: OctetStringRef::new(&request.nonce).map_err(VerificationError::internal)?,
        tls_public_key: OctetStringRef::new(&request.tls_public_key)
            .map_err(VerificationError::internal)?,
    }
    .to_bytes()
    .map_err(VerificationError::internal)?;
    let attestation_report =
        as_attestation_report(&request.sev_attestation_report.attestation_report)?;
    let actual_custom_data = attestation_report.report_data;
    if actual_custom_data != expected_custom_data {
        return Err(VerificationErrorDetail::InvalidAttestationReport {
            message: format!(
                "Expected attestation report custom data: {expected_custom_data:?}, \
                 actual: {actual_custom_data:?}"
            ),
        }
        .into());
    }

    Ok(())
}

fn as_attestation_report(report_bytes: &[u8]) -> Result<&AttestationReport, VerificationError> {
    if report_bytes.len() != std::mem::size_of::<AttestationReport>() {
        return Err(VerificationErrorDetail::InvalidAttestationReport {
            message: "Attestation report has invalid length".to_string(),
        }
        .into());
    }

    unsafe { Ok(&*(report_bytes.as_ptr() as *const AttestationReport)) }
}

fn verify_sev_attestation_report_signature(
    report: &SevAttestationReport, /* root cert */
) -> Result<(), VerificationError> {
    Ok(())
}
