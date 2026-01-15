use crate::guest::firmware::{MockSevGuestFirmware, SevGuestFirmware};
use der::EncodePem;
use der::pem::LineEnding;
use p384::ecdsa::Signature;
use p384::ecdsa::signature::Signer;
use p384::pkcs8::EncodePublicKey;
use rand::SeedableRng;
use rsa::RsaPrivateKey;
use sev::certs::snp::ecdsa::Signature as AttestationReportSignature;
use sev::firmware::guest::AttestationReport;
use sev::parser::Encoder;
use sha2::Sha384;
use std::str::FromStr;
use std::time::Duration;
use x509_cert::Certificate;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfo;
use x509_cert::time::Validity;

/// Builder for creating test attestation reports with customizable fields.
pub struct AttestationReportBuilder {
    attestation_report: AttestationReport,
}

impl AttestationReportBuilder {
    pub fn new() -> Self {
        let mut attestation_report = AttestationReport::default();
        attestation_report.family_id[0] = 0x1A;
        attestation_report.cpuid_fam_id = Some(0x19);
        attestation_report.cpuid_mod_id = Some(0x00);
        attestation_report.version = 3;

        AttestationReportBuilder { attestation_report }
    }

    pub fn with_custom_data(mut self, custom_data: [u8; 64]) -> Self {
        self.attestation_report
            .report_data
            .copy_from_slice(&custom_data);
        self
    }

    pub fn with_measurement(mut self, measurement: [u8; 48]) -> Self {
        self.attestation_report
            .measurement
            .copy_from_slice(&measurement);
        self
    }

    pub fn with_chip_id(mut self, chip_id: [u8; 64]) -> AttestationReportBuilder {
        self.attestation_report.chip_id.copy_from_slice(&chip_id);
        self
    }

    pub fn build_unsigned(self) -> AttestationReport {
        self.attestation_report
    }

    pub fn build_signed(self, signer: &FakeAttestationReportSigner) -> AttestationReport {
        let mut attestation_report = self.attestation_report;
        signer
            .sign_report(&mut attestation_report)
            .expect("Failed to sign attestation report");
        attestation_report
    }
}

impl Default for AttestationReportBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// An AMD SEV-SNP attestation report signer for testing.
/// Creates a fake certificate chain (ARK -> ASK -> VCEK) and uses it to sign attestation reports
/// in a way that passes validation with the SEV verification library.
/// Obviously, this is not secure and should only be used in tests.
#[derive(Clone)]
pub struct FakeAttestationReportSigner {
    ark_cert: Certificate,
    ask_cert: Certificate,
    vcek_cert: Certificate,
    vcek_key: p384::ecdsa::SigningKey,
}

impl FakeAttestationReportSigner {
    const ATTESTATION_REPORT_MEASURABLE_LEN: usize = 0x2a0;

    pub fn new(seed: [u8; 32]) -> Self {
        let mut rng = rand::rngs::StdRng::from_seed(seed);

        // ARK - RSA with RSASSA-PSS (root cert)
        let ark_key = RsaPrivateKey::new(&mut rng, 1024).unwrap();
        let ark_cert =
            create_certificate("ARK", ark_key.to_public_key(), ark_key.clone(), None).unwrap();

        // ASK - RSA with RSASSA-PSS (signed by ARK)
        let ask_key = ark_key.clone(); // Reuse the key to save some time
        let ask_cert =
            create_certificate("ASK", ask_key.to_public_key(), ark_key, Some(&ark_cert)).unwrap();

        // VCEK - P384 ECDSA (signed by ASK)
        let vcek_key = p384::ecdsa::SigningKey::random(&mut rng);
        let vcek_cert =
            create_certificate("VCEK", *vcek_key.verifying_key(), ask_key, Some(&ask_cert))
                .unwrap();

        FakeAttestationReportSigner {
            ark_cert,
            ask_cert,
            vcek_cert,
            vcek_key,
        }
    }

    /// Signs the provided attestation report using the VCEK and stores the signature in the
    /// report's signature field.
    pub fn sign_report(
        &self,
        attestation_report: &mut AttestationReport,
    ) -> Result<(), std::io::Error> {
        let mut raw_report_bytes = vec![];
        // Write the report without signature to a byte vector.
        attestation_report.encode(&mut raw_report_bytes, ())?;

        let measurable_bytes: &[u8] = &raw_report_bytes[..Self::ATTESTATION_REPORT_MEASURABLE_LEN];
        let signature =
            <p384::ecdsa::SigningKey as Signer<Signature>>::sign(&self.vcek_key, measurable_bytes);

        attestation_report.signature = convert_signature(&signature);

        Ok(())
    }

    /// Returns the complete certificate chain (VCEK + ASK + ARK) in PEM format.
    pub fn get_certificate_chain_pem(&self) -> String {
        let mut cert_chain = String::new();
        cert_chain.push_str(&self.get_vcek_pem());
        cert_chain.push_str(&self.get_ask_pem());
        cert_chain.push_str(&self.get_ark_pem());
        cert_chain
    }

    pub fn get_vcek_pem(&self) -> String {
        self.vcek_cert.to_pem(LineEnding::LF).unwrap()
    }

    pub fn get_ask_pem(&self) -> String {
        self.ask_cert.to_pem(LineEnding::LF).unwrap()
    }

    pub fn get_ark_pem(&self) -> String {
        self.ark_cert.to_pem(LineEnding::LF).unwrap()
    }
}

impl Default for FakeAttestationReportSigner {
    fn default() -> Self {
        Self::new([0; 32])
    }
}

fn create_certificate(
    subject: &str,
    public_key: impl EncodePublicKey,
    issuer_key: RsaPrivateKey,
    issuer_cert: Option<&Certificate>,
) -> Result<Certificate, Box<dyn std::error::Error>> {
    let profile = if let Some(issuer_cert) = issuer_cert {
        Profile::SubCA {
            issuer: issuer_cert.tbs_certificate.subject.clone(),
            path_len_constraint: None,
        }
    } else {
        Profile::Root
    };

    let cert = CertificateBuilder::new(
        profile,
        SerialNumber::from(1u32),
        Validity::from_now(Duration::from_secs(86400 * 365))?,
        Name::from_str(&format!("CN={subject}"))?,
        SubjectPublicKeyInfo::from_key(public_key)?,
        &rsa::pss::SigningKey::<Sha384>::new(issuer_key),
    )?
    .build::<rsa::pss::Signature>()?;

    Ok(cert)
}

fn convert_signature(signature: &Signature) -> AttestationReportSignature {
    let mut r_source = signature.r().to_bytes();
    // to_bytes returns big-endian, but AttestationReportSignature is little-endian (see AMD
    // documentation)
    r_source.reverse();
    let mut s_source = signature.s().to_bytes();
    s_source.reverse();
    let mut r = [0; 72];
    r[0..48].copy_from_slice(&r_source);
    let mut s = [0; 72];
    s[0..48].copy_from_slice(&s_source);

    AttestationReportSignature::new(r, s)
}

#[derive(Clone)]
pub struct MockSevGuestFirmwareBuilder {
    custom_data_override: Option<[u8; 64]>,
    /// If not set, the derived key will be derived from the measurement bytes.
    derived_key: Option<[u8; 32]>,
    measurement: [u8; 48],
    chip_id: [u8; 64],
    signer: Option<FakeAttestationReportSigner>,
}

impl Default for MockSevGuestFirmwareBuilder {
    fn default() -> Self {
        Self {
            derived_key: None,
            custom_data_override: None,
            measurement: [0u8; 48],
            chip_id: [0u8; 64],
            signer: None,
        }
    }
}

impl MockSevGuestFirmwareBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_custom_data_override(mut self, custom_data: Option<[u8; 64]>) -> Self {
        self.custom_data_override = custom_data;
        self
    }

    pub fn with_derived_key(mut self, derived_key: Option<[u8; 32]>) -> Self {
        self.derived_key = derived_key;
        self
    }

    pub fn with_measurement(mut self, measurement: [u8; 48]) -> Self {
        self.measurement = measurement;
        self
    }

    pub fn with_chip_id(mut self, chip_id: [u8; 64]) -> Self {
        self.chip_id = chip_id;
        self
    }

    pub fn with_signer(mut self, signer: Option<FakeAttestationReportSigner>) -> Self {
        self.signer = signer;
        self
    }

    pub fn build(&self) -> MockSevGuestFirmware {
        let mut firmware = MockSevGuestFirmware::new();
        let this = self.clone();
        firmware
            .expect_get_report()
            .returning(move |_, custom_data, _| {
                let actual_custom_data =
                    this.custom_data_override.or(custom_data).unwrap_or([0; 64]);

                let builder = AttestationReportBuilder::new()
                    .with_measurement(this.measurement)
                    .with_custom_data(actual_custom_data)
                    .with_chip_id(this.chip_id);

                let attestation_report = if let Some(signer) = &this.signer {
                    builder.build_signed(signer)
                } else {
                    builder.build_unsigned()
                };

                let mut out = vec![];
                attestation_report.encode(&mut out, ()).unwrap();
                Ok(out)
            });

        firmware.expect_get_derived_key().returning(move |_, _| {
            // In reality, the chip would use a more complex process to derive the key from the
            // measurement. In testing, we use a simple approach.
            Ok(this
                .derived_key
                .unwrap_or(this.measurement[4..36].try_into().unwrap()))
        });

        firmware
    }
}

impl SevGuestFirmware for MockSevGuestFirmwareBuilder {
    fn get_report(
        &mut self,
        message_version: Option<u32>,
        data: Option<[u8; 64]>,
        vmpl: Option<u32>,
    ) -> Result<Vec<u8>, sev::error::UserApiError> {
        self.build().get_report(message_version, data, vmpl)
    }

    fn get_derived_key(
        &mut self,
        message_version: Option<u32>,
        derived_key_request: sev::firmware::guest::DerivedKey,
    ) -> Result<[u8; 32], sev::error::UserApiError> {
        self.build()
            .get_derived_key(message_version, derived_key_request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sev::certs::snp::{Chain, Verifiable};

    #[test]
    fn test_fake_cert_chain_and_signature_are_accepted_by_sev_lib() {
        let signer = FakeAttestationReportSigner::default();
        let attestation_report = AttestationReportBuilder::new().build_signed(&signer);

        let cert_chain = Chain::from_pem(
            signer.get_ark_pem().as_bytes(),
            signer.get_ask_pem().as_bytes(),
            signer.get_vcek_pem().as_bytes(),
        )
        .expect("Failed to create certificate chain from PEM");

        (&cert_chain, &attestation_report)
            .verify()
            .expect("Failed to verify attestation report with fake signer");
    }
}
