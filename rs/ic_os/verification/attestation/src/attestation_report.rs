use crate::certificates::CertificateProvider;
use crate::custom_data::EncodeSevCustomData;
use crate::types::SevAttestationPackage;
use anyhow::{anyhow, Result};
use sev::firmware::guest::AttestationReport;
#[cfg(target_os = "linux")]
use sev::firmware::guest::Firmware;
use std::io::ErrorKind;
use std::sync::Mutex;

pub struct SevAttestationPackageGenerator {
    // We defer returning the error until we actually need to use the firmware.
    #[cfg(target_os = "linux")]
    sev_firmware: Mutex<Result<Firmware>>,
    available: bool,
    certificate_provider: CertificateProvider,
}

impl SevAttestationPackageGenerator {
    pub fn new(certificate_provider: CertificateProvider) -> Self {
        #[cfg(target_os = "linux")]
        let sev_firmware = Self::open_sev_firmware();
        #[cfg(target_os = "linux")]
        let available = sev_firmware.is_ok();
        #[cfg(not(target_os = "linux"))]
        let available = false;

        Self {
            #[cfg(target_os = "linux")]
            sev_firmware: Mutex::new(sev_firmware),
            certificate_provider,
            available,
        }
    }

    pub fn generate_attestation_package(
        &self,
        custom_data: &impl EncodeSevCustomData,
    ) -> Result<SevAttestationPackage> {
        #[cfg(target_os = "linux")]
        {
            let attestation_report = self.sev_firmware.lock().unwrap().get_report(
                None,
                Some(custom_data.encode_for_sev()?),
                None,
            )?;
            let parsed_attestation_report = AttestationReport::from_bytes(&attestation_report)?;
            return Ok(SevAttestationPackage {
                attestation_report: Some(attestation_report),
                certificate_chain: Some(
                    self.certificate_provider
                        .get_certificate_chain(&parsed_attestation_report)?,
                ),
            });
        }

        #[cfg(not(target_os = "linux"))]
        Err(anyhow!("SEV not supported on this platform"))
    }

    pub fn is_sev_available(&self) -> bool {
        self.available
    }

    #[cfg(target_os = "linux")]
    fn open_sev_firmware() -> Result<Firmware> {
        Firmware::open().map_err(|e| {
            if e.kind() == ErrorKind::NotFound {
                anyhow!(e).context("SEV firmware not found at /dev/sev-guest. Is SEV available?")
            } else {
                e.into()
            }
        })
    }
}
