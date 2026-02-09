use crate::firmware::SevGuestFirmware;
use anyhow::{Context, Result, anyhow, bail};
use attestation::SevCertificateChain;
use attestation::attestation_package::{
    AttestationPackageVerifier, ParsedSevAttestationPackage, SevRootCertificateVerification,
};
use attestation::custom_data::EncodeSevCustomData;
use config_types::TrustedExecutionEnvironmentConfig;
use sev::firmware::guest::AttestationReport;
use sev::parser::ByteParser;
use std::fmt::Debug;

/// Generate an SEV Attestation Package based on the given SEV firmware, trusted execution
/// environment configuration, and custom data.
/// The implementation verifies that the returned attestation package is signed by the certificate
/// chain from `trusted_execution_environment_config` and contains the passed custom data.
pub fn generate_attestation_package<T: EncodeSevCustomData + Debug>(
    sev_firmware: &mut dyn SevGuestFirmware,
    trusted_execution_environment_config: &TrustedExecutionEnvironmentConfig,
    custom_data: &T,
) -> Result<ParsedSevAttestationPackage> {
    let custom_data_bytes = if T::needs_legacy_encoding() {
        // TODO(NODE-1784): Move to new SEV encoding once clients are updated
        custom_data.encode_for_sev_legacy()?
    } else {
        custom_data.encode_for_sev()?.to_bytes()
    };
    let attestation_report = sev_firmware
        .get_report(None, Some(custom_data_bytes), None)
        .context("Failed to get attestation report from SEV firmware")?;

    let attestation_report = AttestationReport::from_bytes(&attestation_report)
        .context("Failed to parse attestation report")?;
    let certificate_chain = certificate_chain_from_config(trusted_execution_environment_config)
        .context("Failed to get SEV certificate chain")?;
    let custom_data_debug_info = format!("{custom_data:?}");

    // To ensure that the host did not tamper with the attestation report, verify the attestation
    // report acquired from the SEV firmware. However, we may want to deliberately generate invalid
    // attestation packages in tests.
    // We can query the sev firmware object to determine if we should expect an invalid attestation.
    let mut package = if sev_firmware.generates_report_with_wrong_signature() {
        Ok(
            ParsedSevAttestationPackage::new_with_unverified_certificate_chain(
                attestation_report,
                certificate_chain,
                Some(custom_data_debug_info),
            ),
        )
    } else {
        let sev_root_certificate_verification =
            if sev_firmware.generates_report_with_fake_root_cert() {
                SevRootCertificateVerification::TestOnlySkipVerification
            } else {
                SevRootCertificateVerification::Verify
            };

        ParsedSevAttestationPackage::new(
            attestation_report,
            certificate_chain,
            sev_root_certificate_verification,
            Some(custom_data_debug_info),
        )
    };

    if !sev_firmware.generates_report_with_wrong_custom_data() {
        package = package.verify_custom_data(custom_data);
    }

    package.context("Attestation report from firmware is invalid")
}

fn certificate_chain_from_config(
    trusted_execution_environment_config: &TrustedExecutionEnvironmentConfig,
) -> Result<SevCertificateChain> {
    let pem = &trusted_execution_environment_config.sev_cert_chain_pem;

    if pem.is_empty() {
        return Err(anyhow!(
            "SEV certificate chain PEM is empty in configuration"
        ));
    }

    // Parse the PEM certificate chain using the pem crate
    let pem_objects = pem::parse_many(pem).context("Failed to parse PEM certificate chain")?;

    if pem_objects.len() != 3 {
        bail!(
            "Expected exactly 3 PEM objects in SEV certificate chain, found {}",
            pem_objects.len()
        );
    }

    // According to the config, the order is: VCEK / ASK / ARK
    let vcek_pem = pem::encode(&pem_objects[0]);
    let ask_pem = pem::encode(&pem_objects[1]);
    let ark_pem = pem::encode(&pem_objects[2]);

    Ok(SevCertificateChain {
        vcek_pem: Some(vcek_pem),
        ask_pem: Some(ask_pem),
        ark_pem: Some(ark_pem),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use attestation::custom_data::{SevCustomData, SevCustomDataNamespace};
    use rand::SeedableRng;
    use sev_guest_testing::{FakeAttestationReportSigner, MockSevGuestFirmwareBuilder};

    #[test]
    fn test_generate_attestation_package_success() {
        let custom_data = SevCustomData::random(
            SevCustomDataNamespace::Test,
            &mut rand::rngs::SmallRng::seed_from_u64(0),
        );
        let mut firmware = MockSevGuestFirmwareBuilder::new()
            .with_signer(Some(FakeAttestationReportSigner::default()))
            .build();
        let config = TrustedExecutionEnvironmentConfig {
            sev_cert_chain_pem: FakeAttestationReportSigner::default().get_certificate_chain_pem(),
        };

        let result = generate_attestation_package(&mut firmware, &config, &custom_data);

        assert!(result.is_ok());
        assert!(result.unwrap().verify_custom_data(&custom_data).is_ok());
    }

    #[test]
    fn test_generate_attestation_package_with_wrong_custom_data() {
        let custom_data =
            SevCustomData::random(SevCustomDataNamespace::Test, &mut rand::thread_rng());
        let signer = FakeAttestationReportSigner::default();

        let config = TrustedExecutionEnvironmentConfig {
            sev_cert_chain_pem: signer.get_certificate_chain_pem(),
        };

        let mut firmware = MockSevGuestFirmwareBuilder::new()
            .with_custom_data_override(Some([99u8; 64]))
            .with_signer(Some(signer))
            // We make the mock firmware claim that it generates valid custom data, but it doesn't
            // so the attestation package verification will fail.
            .with_generates_report_with_wrong_custom_data(false)
            .build();

        let result = generate_attestation_package(&mut firmware, &config, &custom_data);
        assert!(
            format!("{:?}", result.as_ref().unwrap_err()).contains("InvalidCustomData"),
            "{result:?}",
        );
    }

    #[test]
    fn test_generate_attestation_package_with_wrong_signature() {
        let custom_data =
            SevCustomData::random(SevCustomDataNamespace::Test, &mut rand::thread_rng());

        let config = TrustedExecutionEnvironmentConfig {
            sev_cert_chain_pem: FakeAttestationReportSigner::default().get_certificate_chain_pem(),
        };

        let mut firmware = MockSevGuestFirmwareBuilder::new()
            // We make the mock firmware claim that it generates valid signatures, but it doesn't
            // (we don't pass the signer) so the attestation package verification will fail.
            .with_generates_report_with_wrong_signature(false)
            .build();

        let result = generate_attestation_package(&mut firmware, &config, &custom_data);
        assert!(
            format!("{:?}", result.as_ref().unwrap_err()).contains("InvalidSignature"),
            "{result:?}",
        );
    }
}
