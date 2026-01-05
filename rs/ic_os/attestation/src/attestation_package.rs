use crate::custom_data::EncodeSevCustomData;
use crate::{SevAttestationPackage, SevCertificateChain};
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
) -> Result<SevAttestationPackage> {
    let attestation_report = sev_firmware
        .get_report(None, Some(custom_data.encode_for_sev()?.to_bytes()), None)
        .context("Failed to get attestation report from SEV firmware")?;
    let parsed_attestation_report = AttestationReport::from_bytes(&attestation_report);
    if let Err(err) = parsed_attestation_report {
        // Fail in debug mode, but only print a warning in release mode.
        debug_assert!(
            false,
            "Own generated attestation report could not be parsed: {err:?}"
        );
        eprintln!("Own generated attestation report could not be parsed: {err:?}",);
    }

    Ok(SevAttestationPackage {
        attestation_report: Some(attestation_report),
        certificate_chain: Some(
            certificate_chain_from_config(trusted_execution_environment_config)
                .context("Failed to get SEV certificate chain")?,
        ),
        custom_data_debug_info: format!("{custom_data:?}").into(),
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
