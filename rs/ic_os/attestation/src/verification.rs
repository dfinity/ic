use crate::custom_data::EncodeSevCustomData;
use crate::{SevAttestationPackage, SevCertificateChain, VerificationError};
use sev::Generation;
use sev::certs::snp::ca::Chain as SevCaChain;
use sev::certs::snp::{Certificate, Chain, Verifiable, ca};
use sev::firmware::guest::AttestationReport;
use sev::parser::ByteParser;
use std::fmt::Debug;

/// Controls whether the SEV root certificate is verified.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SevRootCertificateVerification {
    /// Default behavior: verify the SEV root certificate.
    Verify,
    /// Skip verification of the SEV root certificate. Should only be used in tests.
    TestOnlySkipVerification,
}

/// Verify an SEV attestation package. The verification includes:
/// - Checking the certificate chain and the attestation report signature.
/// - Checking that the launch measurement is in the list of blessed measurements.
/// - Checking that the custom data in the attestation report matches the expected custom data.
/// - Checking that the chip ID matches the expected chip ID (if provided).
pub fn verify_attestation_package(
    attestation_package: &SevAttestationPackage,
    sev_root_certificate_verification: SevRootCertificateVerification,
    blessed_guest_launch_measurements: &[impl AsRef<[u8]>],
    expected_custom_data: &(impl EncodeSevCustomData + Debug),
    expected_chip_id: Option<&[u8]>,
) -> Result<(), VerificationError> {
    let Some(ref attestation_report) = attestation_package.attestation_report else {
        return Err(VerificationError::invalid_attestation_report(
            "Attestation report is missing",
        ));
    };

    let parsed_attestation_report =
        AttestationReport::from_bytes(attestation_report).map_err(|e| {
            VerificationError::invalid_attestation_report(format!(
                "Failed to parse attestation report: {e}"
            ))
        })?;

    if let Some(expected_chip_id) = expected_chip_id
        && parsed_attestation_report.chip_id.as_slice() != expected_chip_id
    {
        return Err(VerificationError::invalid_chip_id(format!(
            "Expected chip ID: {expected_chip_id:?}, actual: {:?}",
            parsed_attestation_report.chip_id
        )));
    }

    let certificate_chain = attestation_package
        .certificate_chain
        .as_ref()
        .ok_or_else(|| {
            VerificationError::invalid_certificate_chain("Certificate chain is missing")
        })?;
    verify_sev_attestation_report_signature(
        &parsed_attestation_report,
        certificate_chain,
        sev_root_certificate_verification,
    )?;

    verify_measurement(
        &parsed_attestation_report,
        blessed_guest_launch_measurements,
    )?;

    verify_custom_data(
        &parsed_attestation_report,
        attestation_package
            .custom_data_debug_info
            .as_deref()
            .unwrap_or_default(),
        expected_custom_data,
    )?;

    Ok(())
}

fn verify_custom_data(
    attestation_report: &AttestationReport,
    actual_debug_info: &str,
    expected_custom_data: &(impl EncodeSevCustomData + Debug),
) -> Result<(), VerificationError> {
    let actual_report_data = attestation_report.report_data.as_slice();
    let expected_report_data = expected_custom_data.encode_for_sev().map_err(|e| {
        VerificationError::internal(format!("Could not encode expected custom data: {e}"))
    })?;
    if actual_report_data != expected_report_data {
        return Err(VerificationError::invalid_custom_data(format!(
            "Expected attestation report custom data: {expected_report_data:?}, \
             actual: {actual_report_data:?} \
             Debug info: \
             expected: {expected_custom_data:?} \
             actual: {actual_debug_info}",
        )));
    }

    Ok(())
}

fn verify_measurement(
    attestation_report: &AttestationReport,
    blessed_guest_launch_measurements: &[impl AsRef<[u8]>],
) -> Result<(), VerificationError> {
    let launch_measurement = attestation_report.measurement;
    if !blessed_guest_launch_measurements
        .iter()
        .any(|blessed_measurement| blessed_measurement.as_ref() == launch_measurement.as_slice())
    {
        return Err(VerificationError::invalid_measurement(format!(
            "Launch measurement {launch_measurement:?} is not in the list of \
             blessed guest launch measurements: {}",
            blessed_guest_launch_measurements
                .iter()
                .map(|m| format!("{:?}", m.as_ref()))
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }

    Ok(())
}

fn verify_sev_attestation_report_signature(
    attestation_report: &AttestationReport,
    certificate_chain: &SevCertificateChain,
    sev_root_certificate_verification: SevRootCertificateVerification,
) -> Result<(), VerificationError> {
    let Some(ref ark_pem) = certificate_chain.ark_pem else {
        return Err(VerificationError::invalid_certificate_chain(
            "ARK is missing",
        ));
    };
    let Some(ref ask_pem) = certificate_chain.ask_pem else {
        return Err(VerificationError::invalid_certificate_chain(
            "ASK is missing",
        ));
    };
    let Some(ref vcek_pem) = certificate_chain.vcek_pem else {
        return Err(VerificationError::invalid_certificate_chain(
            "VCEK is missing",
        ));
    };

    let Ok(ark) = Certificate::from_pem(ark_pem.as_bytes()) else {
        return Err(VerificationError::invalid_certificate_chain(
            "Failed to parse ARK",
        ));
    };
    let Ok(ask) = Certificate::from_pem(ask_pem.as_bytes()) else {
        return Err(VerificationError::invalid_certificate_chain(
            "Failed to parse ASK",
        ));
    };
    let Ok(vcek) = Certificate::from_pem(vcek_pem.as_bytes()) else {
        return Err(VerificationError::invalid_certificate_chain(
            "Failed to parse VCEK",
        ));
    };

    let verify_amd_root_certificate = match sev_root_certificate_verification {
        SevRootCertificateVerification::Verify => true,
        SevRootCertificateVerification::TestOnlySkipVerification => false,
    };

    let root_certificate = expected_root_certificate(attestation_report)?;

    if verify_amd_root_certificate {
        if ark.public_key_sec1() != root_certificate.public_key_sec1() {
            return Err(VerificationError::invalid_certificate_chain(
                "ARK public key does not match expected root certificate",
            ));
        }
    } else {
        eprintln!(
            "WARNING: Skipping verification of the SEV root certificate. This should only happen \
             in tests."
        );
    }

    let chain = Chain {
        ca: ca::Chain { ark, ask },
        vek: vcek,
    };

    let vcek = chain
        .verify()
        .map_err(VerificationError::invalid_certificate_chain)?;

    (vcek, attestation_report)
        .verify()
        .map_err(VerificationError::invalid_signature)?;

    Ok(())
}

fn expected_root_certificate(
    attestation_report: &AttestationReport,
) -> Result<Certificate, VerificationError> {
    let generation = Generation::identify_cpu(
        attestation_report.cpuid_fam_id.ok_or_else(|| {
            VerificationError::invalid_attestation_report("cpuid_fam_id is missing")
        })?,
        attestation_report.cpuid_mod_id.ok_or_else(|| {
            VerificationError::invalid_attestation_report("CPUID model ID is missing")
        })?,
    )
    .map_err(|err| {
        VerificationError::invalid_attestation_report(format!(
            "Failed to determine CPU generation: {err}"
        ))
    })?;

    Ok(SevCaChain::from(generation).ark)
}
