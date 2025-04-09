use crate::certificates::CertificateProvider;
use crate::custom_data::EncodeSevCustomData;
use crate::types::SevAttestationPackage;
use anyhow::{anyhow, Result};
use sev::firmware::guest::{AttestationReport, Firmware};
use std::io::ErrorKind;

pub struct SevAttestationPackageGenerator {
    sev_firmware: Firmware,
    certificate_provider: CertificateProvider,
}

impl SevAttestationPackageGenerator {
    pub fn new(certificate_provider: CertificateProvider) -> Result<Self> {
        let sev_firmware = Firmware::open().map_err(|e| {
            if e.kind() == ErrorKind::NotFound {
                anyhow!(e).context("SEV firmware not found at /dev/sev-guest. Is SEV available?")
            } else {
                e.into()
            }
        })?;
        Ok(Self {
            sev_firmware,
            certificate_provider,
        })
    }

    pub fn generate_attestation_package(
        &mut self,
        custom_data: &impl EncodeSevCustomData,
    ) -> Result<SevAttestationPackage> {
        let attestation_report =
            self.sev_firmware
                .get_report(None, Some(custom_data.encode_for_sev()?), None)?;
        let parsed_attestation_report = AttestationReport::from_bytes(&attestation_report)?;
        Ok(SevAttestationPackage {
            attestation_report: attestation_report.into(),
            certificate_chain: self
                .certificate_provider
                .get_certificate_chain(&parsed_attestation_report)?
                .into(),
        })
    }
}
