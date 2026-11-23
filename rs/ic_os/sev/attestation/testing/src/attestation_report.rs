use attestation::LAUNCH_MEASUREMENT_LEN;
use p384::ecdsa::Signature;
use p384::ecdsa::signature::Signer;
use p384::pkcs8::EncodePublicKey;
use rand::SeedableRng;
use rsa::PrivateKey;
use rsa::sha2::Sha384;
use sev::Generation;
use sev::certs::snp::ecdsa::Signature as AttestationReportSignature;
use sev::firmware::guest::{AttestationReport, GuestPolicy};
use sev::firmware::host::TcbVersion;
use sev::parser::Encoder;
use std::str::FromStr;
use std::time::Duration;
use x509_cert::builder::profile::BuilderProfile;
use x509_cert::builder::{Builder, CertificateBuilder};
use x509_cert::der::EncodePem;
use x509_cert::der::pem::LineEnding;
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, KeyUsage, KeyUsages, SubjectKeyIdentifier,
};
use x509_cert::ext::{Extension, ToExtension};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoRef;
use x509_cert::time::Validity;
use x509_cert::{Certificate, SubjectPublicKeyInfo, TbsCertificate};

pub const DEFAULT_GENERATION: Generation = Generation::Milan;

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

    pub fn with_measurement(mut self, measurement: [u8; LAUNCH_MEASUREMENT_LEN]) -> Self {
        self.attestation_report
            .measurement
            .copy_from_slice(&measurement);
        self
    }

    pub fn with_chip_id(mut self, chip_id: [u8; 64]) -> AttestationReportBuilder {
        self.attestation_report.chip_id.copy_from_slice(&chip_id);
        self
    }

    pub fn with_reported_tcb(mut self, reported_tcb: TcbVersion) -> Self {
        self.attestation_report.reported_tcb = reported_tcb;
        self
    }

    pub fn with_launch_tcb(mut self, launch_tcb: TcbVersion) -> Self {
        self.attestation_report.launch_tcb = launch_tcb;
        self
    }

    pub fn with_guest_policy(mut self, guest_policy: GuestPolicy) -> Self {
        self.attestation_report.policy = guest_policy;
        self
    }

    pub fn build_unsigned(&self) -> AttestationReport {
        self.attestation_report
    }

    pub fn build_signed(&self, signer: &FakeAttestationReportSigner) -> AttestationReport {
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
        let ark_key = PrivateKey::new(&mut RandCore10(&mut rng), 1024).unwrap();
        let ark_cert = create_certificate(
            "ARK",
            SubjectPublicKeyInfo::from_key(&ark_key.to_public_key()).unwrap(),
            ark_key.clone(),
            None,
            &mut rng,
        )
        .unwrap();

        // ASK - RSA with RSASSA-PSS (signed by ARK)
        let ask_key = ark_key.clone(); // Reuse the key to save some time
        let ask_cert = create_certificate(
            "ASK",
            SubjectPublicKeyInfo::from_key(&ask_key.to_public_key()).unwrap(),
            ark_key,
            Some(&ark_cert),
            &mut rng,
        )
        .unwrap();

        // VCEK - P384 ECDSA (signed by ASK)
        let vcek_key = p384::ecdsa::SigningKey::random(&mut rng);
        // p384 implements the spki 0.7 traits and x509-cert takes spki 0.8 types, so the public
        // key goes through its DER encoding.
        let vcek_public_key_der = vcek_key.verifying_key().to_public_key_der().unwrap();
        let vcek_cert = create_certificate(
            "VCEK",
            SubjectPublicKeyInfo::try_from(vcek_public_key_der.as_bytes()).unwrap(),
            ask_key,
            Some(&ask_cert),
            &mut rng,
        )
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

fn create_certificate<R: rand::RngCore + rand::CryptoRng>(
    subject: &str,
    subject_public_key_info: SubjectPublicKeyInfo,
    issuer_key: PrivateKey,
    issuer_cert: Option<&Certificate>,
    rng: &mut R,
) -> Result<Certificate, Box<dyn std::error::Error>> {
    let profile = CaProfile {
        subject: Name::from_str(&format!("CN={subject}"))?,
        issuer: issuer_cert.map(|issuer| issuer.tbs_certificate().subject().clone()),
    };

    let cert = CertificateBuilder::new(
        profile,
        SerialNumber::from(1_u32),
        Validity::from_now(Duration::from_secs(86400 * 365))?,
        subject_public_key_info,
    )?
    .build_with_rng::<_, rsa::pss::Signature, _>(
        &rsa::pss::SigningKey::<Sha384>::new(issuer_key),
        &mut RandCore10(rng),
    )?;

    Ok(cert)
}

/// Profile of the fake ARK, ASK and VCEK certificates. x509-cert's `cabf::Root` profile does not
/// fit because it requires C, O and CN in the subject, and these certificates only have a CN.
///
/// Every certificate gets a subject key identifier, an authority key identifier unless it is
/// self-signed (`issuer` is `None`), critical basic constraints marking it as a CA without a path
/// length constraint, and a critical key usage allowing `keyCertSign` and `cRLSign`.
struct CaProfile {
    subject: Name,
    issuer: Option<Name>,
}

impl BuilderProfile for CaProfile {
    fn get_issuer(&self, subject: &Name) -> Name {
        self.issuer.clone().unwrap_or_else(|| subject.clone())
    }

    fn get_subject(&self) -> Name {
        self.subject.clone()
    }

    fn build_extensions(
        &self,
        spk: SubjectPublicKeyInfoRef<'_>,
        issuer_spk: SubjectPublicKeyInfoRef<'_>,
        tbs: &TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        let subject = tbs.subject();
        let ski = SubjectKeyIdentifier::try_from(spk)?;

        let mut extensions: Vec<Extension> = Vec::new();
        extensions.push(ski.to_extension(subject, &extensions)?);
        if self.issuer.is_some() {
            let aki = AuthorityKeyIdentifier::try_from(issuer_spk)?;
            extensions.push(aki.to_extension(subject, &extensions)?);
        }
        let basic_constraints = BasicConstraints {
            ca: true,
            path_len_constraint: None,
        };
        extensions.push(basic_constraints.to_extension(subject, &extensions)?);
        let key_usage = KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign);
        extensions.push(key_usage.to_extension(subject, &extensions)?);

        Ok(extensions)
    }
}

/// Makes a rand 0.8 RNG usable as the rand_core 0.10 RNG that `rsa` and x509-cert's
/// `Builder::build_with_rng` take.
struct RandCore10<'a, R>(&'a mut R);

impl<R: rand::RngCore> rsa::rand_core::TryRng for RandCore10<'_, R> {
    type Error = std::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.0.next_u32())
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.0.next_u64())
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.0.fill_bytes(dst);
        Ok(())
    }
}

impl<R: rand::RngCore + rand::CryptoRng> rsa::rand_core::TryCryptoRng for RandCore10<'_, R> {}

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
