use crate::custom_data::EncodeSevCustomData;
use crate::error::{VerificationError, VerificationErrorDetail};
use crate::types::{SevAttestationPackage, SevCertificateChain};
use sev::certs::snp::{ca, Certificate, Chain, Verifiable};
use sev::firmware::guest::AttestationReport;

pub fn verify_attestation_report<T: EncodeSevCustomData>(
    attestation_package: &SevAttestationPackage,
    root_certificate_pem: &[u8],
    blessed_guest_launch_measurements: &[impl AsRef<[u8]>],
    expected_custom_data: &T,
) -> Result<(), VerificationError> {
    let Some(ref attestation_report) = attestation_package.attestation_report else {
        return Err(VerificationErrorDetail::InvalidAttestationReport {
            message: "Attestation report is missing".to_string(),
        }
        .into());
    };

    let parsed_attestation_report =
        AttestationReport::from_bytes(attestation_report).map_err(|e| {
            VerificationErrorDetail::InvalidCertificateChain {
                message: format!("Failed to parse attestation report: {e}"),
            }
        })?;

    verify_sev_attestation_report_signature(
        &parsed_attestation_report,
        &attestation_package
            .certificate_chain
            .as_ref()
            .unwrap_or(&SevCertificateChain::default()),
        root_certificate_pem,
    )?;

    verify_measurement(
        &parsed_attestation_report,
        blessed_guest_launch_measurements,
    )?;

    verify_custom_data(&parsed_attestation_report, expected_custom_data)?;

    Ok(())
}

fn verify_custom_data<T: EncodeSevCustomData>(
    attestation_report: &AttestationReport,
    expected_custom_data: &T,
) -> Result<(), VerificationError> {
    let actual_report_data = attestation_report.report_data.as_slice();
    let expected_report_data = expected_custom_data.encode_for_sev().map_err(|e| {
        VerificationError::internal(format!("Could not encode expected custom data: {e}"))
    })?;
    if actual_report_data != expected_report_data {
        return Err(VerificationErrorDetail::InvalidAttestationReport {
            message: format!(
                "Expected attestation report custom data: {expected_report_data:?}, \
                         actual: {actual_report_data:?}"
            ),
        }
        .into());
    }

    Ok(())
}

fn verify_measurement(
    attestation_report: &AttestationReport,
    blessed_guest_launch_measurements: &[impl AsRef<[u8]> + Sized],
) -> Result<(), VerificationError> {
    let launch_measurement = attestation_report.measurement;
    if !blessed_guest_launch_measurements
        .iter()
        .any(|blessed_measurement| blessed_measurement.as_ref() == launch_measurement.as_slice())
    {
        return Err(VerificationErrorDetail::InvalidAttestationReport {
            message: format!(
                "Launch measurement {launch_measurement:?} is not in the list of \
                 blessed guest launch measurements: {}",
                blessed_guest_launch_measurements
                    .iter()
                    .map(|m| format!("{:?}", m.as_ref()))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
        .into());
    }

    Ok(())
}

fn verify_sev_attestation_report_signature(
    attestation_report: &AttestationReport,
    certificate_chain: &SevCertificateChain,
    root_certificate_pem: &[u8],
) -> Result<(), VerificationError> {
    let Some(ref ark_pem) = certificate_chain.ark_pem else {
        return Err(VerificationErrorDetail::InvalidCertificateChain {
            message: "ARK is missing".to_string(),
        }
        .into());
    };
    let Some(ref ask_pem) = certificate_chain.ask_pem else {
        return Err(VerificationErrorDetail::InvalidCertificateChain {
            message: "ASK is missing".to_string(),
        }
        .into());
    };
    let Some(ref vcek_pem) = certificate_chain.vcek_pem else {
        return Err(VerificationErrorDetail::InvalidCertificateChain {
            message: "VCEK is missing".to_string(),
        }
        .into());
    };

    let Ok(ark) = Certificate::from_pem(ark_pem) else {
        return Err(VerificationErrorDetail::InvalidCertificateChain {
            message: "Failed to parse ARK".to_string(),
        }
        .into());
    };
    let Ok(ask) = Certificate::from_pem(ask_pem) else {
        return Err(VerificationErrorDetail::InvalidCertificateChain {
            message: "Failed to parse ASK".to_string(),
        }
        .into());
    };
    let Ok(vcek) = Certificate::from_pem(vcek_pem) else {
        return Err(VerificationErrorDetail::InvalidCertificateChain {
            message: "Failed to parse VCEK".to_string(),
        }
        .into());
    };

    let parsed_root_certificate = Certificate::from_pem(root_certificate_pem).map_err(|_| {
        VerificationError::internal("Failed to parse expected root certificate".to_string())
    })?;

    if ark.public_key_sec1() != parsed_root_certificate.public_key_sec1() {
        return Err(VerificationErrorDetail::InvalidCertificateChain {
            message: "ARK public key does not match expected root certificate".to_string(),
        }
        .into());
    }

    let chain = Chain {
        ca: ca::Chain { ark, ask },
        vek: vcek,
    };

    (&chain, attestation_report).verify().map_err(|e| {
        VerificationErrorDetail::InvalidCertificateChain {
            message: e.to_string(),
        }
    })?;

    Ok(())
}
