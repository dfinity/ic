use crate::types::SevCertificateChain;
use anyhow::{Context, Result};
use sev::certs::snp::Certificate;
use sev::firmware::guest::AttestationReport;
use std::path::{Path, PathBuf};

pub struct CertificateProvider {
    certificate_dir: PathBuf,
}

impl CertificateProvider {
    pub fn new(certificate_dir: PathBuf) -> Self {
        Self { certificate_dir }
    }

    pub fn get_certificate_chain(
        &self,
        attestation_report: &AttestationReport,
    ) -> Result<SevCertificateChain> {
        let vcek = self
            .load_vcek_der(attestation_report)
            .context("Could not load VCEK")?;
        Ok(SevCertificateChain {
            ark_pem: sev::certs::snp::builtin::milan::ARK.to_vec().into(),
            ask_pem: sev::certs::snp::builtin::milan::ASK.to_vec().into(),
            vcek_pem: Some(Certificate::from_der(&vcek)?.to_pem()?),
        })
    }

    fn load_vcek_der(&self, attestation_report: &AttestationReport) -> Result<Vec<u8>> {
        let vcek_path = self
            .certificate_dir
            .join(Self::vcek_filename(attestation_report));
        // TODO: consider caching the VCEK in memory
        let vcek_from_file_system = Self::load_vcek_from_path(&vcek_path);
        if vcek_from_file_system.is_ok() {
            return vcek_from_file_system;
        }

        println!(
            "VCEK could not be loaded from file system: {}",
            vcek_from_file_system.unwrap_err()
        );

        // TODO: log that the VCEK was not found in the file system

        let vcek_from_key_server = self
            .load_vcek_from_amd_key_server(attestation_report)
            .context("Could not fetch VCEK from AMD key server.")?;

        std::fs::write(&vcek_path, &vcek_from_key_server).unwrap_or_else(|err| {
            // TODO: log that the VCEK could not be written to the file system
        });

        Ok(vcek_from_key_server)
    }

    fn vcek_filename(attestation_report: &AttestationReport) -> String {
        let hw_id: String = attestation_report
            .chip_id
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect();
        let reported_tcb = attestation_report.reported_tcb;
        format!(
            "{hw_id}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}.der",
            reported_tcb.bootloader, reported_tcb.tee, reported_tcb.snp, reported_tcb.microcode,
        )
    }

    fn load_vcek_from_path(vcek_path: &Path) -> Result<Vec<u8>> {
        let vcek_der = std::fs::read(&vcek_path)
            .with_context(|| format!("Could not read VCEK from {}", vcek_path.display()))?;
        // Check that the VCEK is valid DER before returning it.
        Certificate::from_der(&vcek_der)?;
        Ok(vcek_der)
    }

    fn load_vcek_from_amd_key_server(
        &self,
        attestation_report: &AttestationReport,
    ) -> Result<Vec<u8>> {
        const KDS_CERT_SITE: &str = "https://kdsintf.amd.com";
        const KDS_VCEK: &str = "/vcek/v1";
        const SEV_PROD_NAME: &str = "Milan";

        let hw_id: String = attestation_report
            .chip_id
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect();
        let reported_tcb = attestation_report.reported_tcb;
        let url = format!(
            "{KDS_CERT_SITE}{KDS_VCEK}/{SEV_PROD_NAME}/{hw_id}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
            reported_tcb.bootloader,
            reported_tcb.tee,
            reported_tcb.snp,
            reported_tcb.microcode,
        );

        let bytes = reqwest::blocking::get(&url)
            .with_context(|| format!("Could not fetch VCEK from {url}"))?
            .bytes()
            .with_context(|| format!("Could not read VCEK from {url}"))?;

        // Check that the VCEK is valid DER before returning it.
        Certificate::from_der(&bytes).context("Cannot parse VCEK from AMD key server as DER")?;
        Ok(bytes.to_vec())
    }
}
