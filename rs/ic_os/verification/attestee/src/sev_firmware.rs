use anyhow::{Context, Result};
use attestation::attestation::{GenerateAttestationTokenCustomData, SevAttestationReport};
use der::Encode;
use sev::firmware::guest::Firmware;
use sha2::{Digest, Sha512};

pub(crate) trait SevFirmware {
    fn get_report(&mut self, custom_data: [u8; 64]) -> Result<SevAttestationReport>;
}

struct RealSevFirmware(Firmware);

impl SevFirmware for RealSevFirmware {
    fn get_report(&mut self, custom_data: [u8; 64]) -> Result<SevAttestationReport> {
        let (attestation_report, certificates) =
            self.0.get_ext_report(None, Some(custom_data), None)?;
        Ok(SevAttestationReport {
            attestation_report,
            certificates: certificates.context("Missing certificates")?,
        })
    }
}

#[cfg(test)]
mod mock {
    use super::*;

    pub struct MockSevFirmware {}

    impl SevFirmware for MockSevFirmware {
        fn get_report(&mut self, custom_data: [u8; 64]) -> Result<SevAttestationReport> {
            todo!()
        }
    }
}
