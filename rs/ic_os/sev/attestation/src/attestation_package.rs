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

/// Extension trait for verifying attestation packages.
pub trait AttestationPackageVerifier: Sized {
    /// Verify that the attestation report chip ID matches one of the expected chip IDs.
    fn verify_chip_id(
        self,
        expected_chip_ids: &[[u8; 64]],
    ) -> Result<ParsedSevAttestationPackage, VerificationError>;

    /// Verify that the attestation report custom data matches the expected custom data.
    fn verify_custom_data(
        self,
        expected_custom_data: &(impl EncodeSevCustomData + Debug),
    ) -> Result<ParsedSevAttestationPackage, VerificationError>;

    /// Verify that the attestation report launch measurement matches one of the blessed guest
    /// launch measurements.
    fn verify_measurement(
        self,
        blessed_guest_launch_measurements: &[impl AsRef<[u8]>],
    ) -> Result<ParsedSevAttestationPackage, VerificationError>;
}

/// A parsed attestation package with the attestation report and certificate chain
/// extracted and validated.
///
/// Example:
/// ```
///     ParsedAttestationPackage::parse(
///         sev_attestation_package,
///         SevRootCertificateVerification::Verify,
///     )
///     .verify_measurement(...)
///     .verify_custom_data(...)
///     .verify_chip_id(...)
///     .expect("Failed to verify attestation package")
///     .attestation_report();
/// ```
#[derive(Debug)]
pub struct ParsedSevAttestationPackage {
    // Invariant: attestation_report is signed by certificate_chain
    attestation_report: AttestationReport,
    certificate_chain: SevCertificateChain,
    custom_data_debug_info: String,
}

impl ParsedSevAttestationPackage {
    pub fn new_verified(
        attestation_report: AttestationReport,
        certificate_chain: SevCertificateChain,
        sev_root_certificate_verification: SevRootCertificateVerification,
        custom_data_debug_info: String,
    ) -> Result<Self, VerificationError> {
        verify_sev_attestation_report_signature(
            &attestation_report,
            &certificate_chain,
            sev_root_certificate_verification,
        )?;
        Ok(Self {
            attestation_report,
            certificate_chain,
            custom_data_debug_info,
        })
    }
    /// Parse an SEV attestation package and verify the signatures.
    ///
    /// This method:
    /// 1. Extracts and parses the attestation report and certificate chain
    /// 2. Verifies the certificate chain (ARK -> ASK -> VCEK)
    /// 3. Verifies the attestation report signature using the VCEK
    /// 4. Verifies that the ARK matches the expected AMD root certificate (if enabled)
    pub fn parse(
        package: SevAttestationPackage,
        sev_root_certificate_verification: SevRootCertificateVerification,
    ) -> Result<Self, VerificationError> {
        let Some(ref attestation_report_bytes) = package.attestation_report else {
            return Err(VerificationError::invalid_attestation_report(
                "Attestation report is missing",
            ));
        };

        let attestation_report =
            AttestationReport::from_bytes(attestation_report_bytes).map_err(|e| {
                VerificationError::invalid_attestation_report(format!(
                    "Failed to parse attestation report: {e}"
                ))
            })?;

        let certificate_chain = package.certificate_chain.ok_or_else(|| {
            VerificationError::invalid_certificate_chain("Certificate chain is missing")
        })?;

        Self::new_verified(
            attestation_report,
            certificate_chain,
            sev_root_certificate_verification,
            package.custom_data_debug_info.unwrap_or_default(),
        )
    }

    pub fn attestation_report(&self) -> &AttestationReport {
        &self.attestation_report
    }
}

impl From<ParsedSevAttestationPackage> for SevAttestationPackage {
    fn from(value: ParsedSevAttestationPackage) -> Self {
        Self {
            attestation_report: Some(
                value
                    .attestation_report
                    .to_bytes()
                    .expect("Failed to encode attestation report")
                    .to_vec(),
            ),
            certificate_chain: Some(value.certificate_chain),
            custom_data_debug_info: Some(value.custom_data_debug_info),
        }
    }
}

impl AttestationPackageVerifier for ParsedSevAttestationPackage {
    fn verify_chip_id(
        self,
        expected_chip_ids: &[[u8; 64]],
    ) -> Result<ParsedSevAttestationPackage, VerificationError> {
        if !expected_chip_ids.contains(&self.attestation_report.chip_id) {
            return Err(VerificationError::invalid_chip_id(format!(
                "Expected one of chip IDs: {}, actual: {}",
                expected_chip_ids
                    .iter()
                    .map(hex::encode)
                    .collect::<Vec<_>>()
                    .join(", "),
                hex::encode(self.attestation_report.chip_id)
            )));
        }

        Ok(self)
    }

    fn verify_custom_data(
        self,
        expected_custom_data: &(impl EncodeSevCustomData + Debug),
    ) -> Result<ParsedSevAttestationPackage, VerificationError> {
        let actual_report_data = &self.attestation_report.report_data;
        let expected_report_data = expected_custom_data.encode_for_sev().map_err(|e| {
            VerificationError::internal(format!("Could not encode expected custom data: {e}"))
        });
        // TODO: remove this once clients no longer send legacy custom data
        #[allow(deprecated)]
        let expected_report_data_legacy =
            expected_custom_data.encode_for_sev_legacy().map_err(|e| {
                VerificationError::internal(format!(
                    "Could not encode expected custom data (legacy): {e}"
                ))
            });
        if !expected_report_data
            .as_ref()
            .is_ok_and(|expected| expected.verify(actual_report_data))
            && !expected_report_data_legacy
                .as_ref()
                .is_ok_and(|expected| actual_report_data == expected)
        {
            return Err(VerificationError::invalid_custom_data(format!(
                "Expected attestation report custom data: {expected_report_data:?}, \
             legacy: {expected_report_data_legacy:?}, \
                 actual: {actual_report_data:?} \
                 Debug info: \
                 expected: {expected_custom_data:?} \
                 actual: {}",
                self.custom_data_debug_info
            )));
        }

        Ok(self)
    }

    fn verify_measurement(
        self,
        blessed_guest_launch_measurements: &[impl AsRef<[u8]>],
    ) -> Result<ParsedSevAttestationPackage, VerificationError> {
        let launch_measurement = self.attestation_report.measurement;
        if !blessed_guest_launch_measurements
            .iter()
            .any(|blessed_measurement| {
                blessed_measurement.as_ref() == launch_measurement.as_slice()
            })
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

        Ok(self)
    }
}

/// Allows chaining verification methods
impl AttestationPackageVerifier for Result<ParsedSevAttestationPackage, VerificationError> {
    fn verify_chip_id(
        self,
        expected_chip_ids: &[[u8; 64]],
    ) -> Result<ParsedSevAttestationPackage, VerificationError> {
        self?.verify_chip_id(expected_chip_ids)
    }

    fn verify_custom_data(
        self,
        expected_custom_data: &(impl EncodeSevCustomData + Debug),
    ) -> Result<ParsedSevAttestationPackage, VerificationError> {
        self?.verify_custom_data(expected_custom_data)
    }

    fn verify_measurement(
        self,
        blessed_guest_launch_measurements: &[impl AsRef<[u8]>],
    ) -> Result<ParsedSevAttestationPackage, VerificationError> {
        self?.verify_measurement(blessed_guest_launch_measurements)
    }
}

pub(crate) fn verify_sev_attestation_report_signature(
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
