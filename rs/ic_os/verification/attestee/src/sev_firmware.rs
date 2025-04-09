use anyhow::{Context, Result};
use attestation::attestation::SevAttestationPackage;
use der::Encode;
use sev::firmware::guest::{AttestationReport, Firmware};
use sev::firmware::host::CertTableEntry;
use sha2::Digest;

pub trait SevFirmware: Send + Sync {
    fn get_report(&mut self, custom_data: &[u8; 64]) -> Result<SevAttestationPackage>;
}

pub struct RealSevFirmware(pub Firmware);

impl SevFirmware for RealSevFirmware {
    fn get_report(&mut self, custom_data: &[u8; 64]) -> Result<SevAttestationPackage> {
        let (attestation_report, certificates) =
            self.0.get_ext_report(None, Some(*custom_data), None)?;
        Ok(SevAttestationPackage {
            attestation_report: attestation_report_to_byte_vec(&attestation_report),
            certificates: convert_cert_table_entries(
                &certificates.context("Missing certificates")?,
            ),
        })
    }
}

fn attestation_report_to_byte_vec(attestation_report: &AttestationReport) -> Vec<u8> {
    let attestation_report_len = std::mem::size_of::<AttestationReport>();
    let mut vec = Vec::with_capacity(attestation_report_len);
    unsafe {
        std::ptr::copy_nonoverlapping(
            attestation_report as *const _ as *const u8,
            vec.as_mut_ptr(),
            attestation_report_len,
        );
        vec.set_len(attestation_report_len);
    }
    vec
}

fn convert_cert_table_entries(
    cert_table_entries: &[CertTableEntry],
) -> Vec<attestation::attestation::CertTableEntry> {
    vec![]
}

// #[cfg(test)]
pub mod mock {
    use super::*;

    pub struct MockSevFirmware {}

    impl MockSevFirmware {
        pub fn new() -> Self {
            Self {}
        }
    }

    impl SevFirmware for MockSevFirmware {
        fn get_report(&mut self, custom_data: &[u8; 64]) -> Result<SevAttestationPackage> {
            let mut report = AttestationReport::default();
            report.report_data.copy_from_slice(custom_data);
            Ok(SevAttestationPackage {
                attestation_report: attestation_report_to_byte_vec(&report),
                certificates: vec![],
            })
        }
    }
}
