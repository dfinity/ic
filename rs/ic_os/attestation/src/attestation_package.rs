use crate::SevCertificateChain;
use crate::custom_data::EncodeSevCustomData;
use crate::verification::{ParsedAttestationPackage, SevRootCertificateVerification};
use anyhow::{Context, Result, anyhow, bail};
use config_types::TrustedExecutionEnvironmentConfig;
use ic_sev::guest::firmware::SevGuestFirmware;
use sev::firmware::guest::AttestationReport;
use sev::parser::ByteParser;
use std::fmt::Debug;

/// Generate an SEV Attestation Package based on the given SEV firmware,
/// trusted execution environment configuration, and custom data.
pub fn generate_attestation_package(
    sev_firmware: &mut dyn SevGuestFirmware,
    trusted_execution_environment_config: &TrustedExecutionEnvironmentConfig,
    custom_data: &(impl EncodeSevCustomData + Debug),
) -> Result<ParsedAttestationPackage> {
    let attestation_report = sev_firmware
        .get_report(None, Some(custom_data.encode_for_sev()?.to_bytes()), None)
        .context("Failed to get attestation report from SEV firmware")?;

    let sev_root_certificate_verification = if sev_firmware.is_mock() {
        SevRootCertificateVerification::TestOnlySkipVerification
    } else {
        SevRootCertificateVerification::Verify
    };

    ParsedAttestationPackage::new_verified(
        AttestationReport::from_bytes(&attestation_report)
            .context("Failed to parse attestation report")?,
        certificate_chain_from_config(trusted_execution_environment_config)
            .context("Failed to get SEV certificate chain")?,
        sev_root_certificate_verification,
        format!("{custom_data:?}"),
    )
    .map_err(|err| {
        // Fail in debug mode, but only return the error in release mode.
        debug_assert!(
            false,
            "Generated attestation report could not be verified: {err}"
        );
        anyhow!("Generated attestation report could not be verified: {err}")
    })
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
