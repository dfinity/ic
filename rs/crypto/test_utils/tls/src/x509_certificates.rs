use x509_cert::der; // re-export of der create
use x509_cert::spki; // re-export of spki create

use ic_crypto_test_utils_reproducible_rng::ReproducibleRng;
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
use rand::{CryptoRng, Rng};
use std::str::FromStr;
use std::time::{Duration, SystemTime};
use x509_cert::{
    builder::{Builder, CertificateBuilder, Profile},
    ext::pkix::BasicConstraints,
    name::Name,
    serial_number::SerialNumber,
    time::Validity,
};

const DEFAULT_SERIAL: [u8; 19] = [42u8; 19];
const DEFAULT_CN: &str = "Spock";
const RFC5280_NO_WELL_DEFINED_CERTIFICATE_EXPIRATION_DATE: &str = "99991231235959Z";
const SECS_PER_DAY: u64 = 60 * 60 * 24;

#[derive(Clone)]
#[allow(clippy::large_enum_variant)]
pub enum KeyPair {
    Ed25519 {
        secret_key: ic_ed25519::PrivateKey,
        public_key: ic_ed25519::PublicKey,
    },
    Secp256r1 {
        secret_key: ic_secp256r1::PrivateKey,
        public_key: ic_secp256r1::PublicKey,
    },
}

impl signature::Signer<Signature> for KeyPair {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, signature::Error> {
        match self {
            KeyPair::Ed25519 { secret_key, .. } => {
                Ok(Signature(secret_key.sign_message(msg).to_vec()))
            }
            KeyPair::Secp256r1 { secret_key, .. } => {
                Ok(Signature(secret_key.sign_message(msg).to_vec()))
            }
        }
    }
}

pub struct Signature(Vec<u8>);

impl spki::SignatureBitStringEncoding for Signature {
    fn to_bitstring(&self) -> der::Result<der::asn1::BitString> {
        der::asn1::BitString::from_bytes(&self.0)
    }
}

impl spki::DynSignatureAlgorithmIdentifier for KeyPair {
    fn signature_algorithm_identifier(&self) -> spki::Result<spki::AlgorithmIdentifierOwned> {
        match self {
            KeyPair::Ed25519 { .. } => Ok(spki::AlgorithmIdentifierOwned {
                oid: pkcs8::ObjectIdentifier::new("1.3.101.112").unwrap(),
                parameters: None,
            }),
            KeyPair::Secp256r1 { .. } => Ok(spki::AlgorithmIdentifierOwned {
                oid: pkcs8::ObjectIdentifier::new("1.2.840.10045.3.1.7").unwrap(),
                parameters: None,
            }),
        }
    }
}

impl signature::Keypair for KeyPair {
    type VerifyingKey = VerifyingKey;

    fn verifying_key(&self) -> Self::VerifyingKey {
        match self {
            KeyPair::Ed25519 { public_key, .. } => VerifyingKey::Ed25519(*public_key),
            KeyPair::Secp256r1 { public_key, .. } => VerifyingKey::Secp256r1(public_key.clone()),
        }
    }
}

#[derive(Clone)]
pub enum VerifyingKey {
    Ed25519(ic_ed25519::PublicKey),
    Secp256r1(ic_secp256r1::PublicKey),
}

impl pkcs8::EncodePublicKey for VerifyingKey {
    fn to_public_key_der(&self) -> spki::Result<pkcs8::Document> {
        match self {
            VerifyingKey::Ed25519(key) => {
                let der = key.serialize_rfc8410_der();
                Ok(pkcs8::Document::try_from(der)
                    .expect("failed to create document from ed25519 DER"))
            }
            VerifyingKey::Secp256r1(key) => Ok(pkcs8::Document::try_from(key.serialize_der())
                .expect("failed to create document from ed25519 DER")),
        }
    }
}

impl KeyPair {
    pub fn gen_ed25519<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        let secret_key = ic_ed25519::PrivateKey::generate_using_rng(rng);
        let public_key = secret_key.public_key();
        Self::Ed25519 {
            secret_key,
            public_key,
        }
    }

    pub fn gen_secp256r1<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        let secret_key = ic_secp256r1::PrivateKey::generate_using_rng(rng);
        let public_key = secret_key.public_key();
        Self::Secp256r1 {
            secret_key,
            public_key,
        }
    }

    pub fn public_key_der(&self) -> Vec<u8> {
        match self {
            KeyPair::Ed25519 {
                secret_key: _,
                public_key,
            } => public_key.serialize_rfc8410_der(),
            KeyPair::Secp256r1 {
                secret_key: _,
                public_key,
            } => public_key.serialize_der(),
        }
    }

    /// Serializes the private key for usage with Rustls.
    ///
    /// In particular, for usage with `ConfigBuilder<ServerConfig, WantsServerCert>::with_single_cert`.
    /// While the documentation says `DER-encoded RSA, ECDSA, or Ed25519 private key`, for Ed25519
    /// both PKCS#8 v1 and v2 work (i.e., both without and with public key), but for ECDSA P256 only
    /// PKCS#8 v2 (i.e., with the public key) works (as well as SEC1). See also the documentation of
    /// `rustls::sign::any_ecdsa_type`.
    pub fn serialize_for_rustls(&self) -> Vec<u8> {
        match self {
            KeyPair::Ed25519 { secret_key, .. } => {
                secret_key.serialize_pkcs8(ic_ed25519::PrivateKeyFormat::Pkcs8v2)
            }
            KeyPair::Secp256r1 { secret_key, .. } => secret_key.serialize_rfc5915_der(),
        }
    }
}

/// Generates an ed25519 key pair.
pub fn ed25519_key_pair<R: Rng + CryptoRng>(rng: &mut R) -> KeyPair {
    KeyPair::gen_ed25519(rng)
}

/// Generates a prime256v1 key pair.
///
/// Note that NIST P-256, prime256v1, secp256r1 are all the same, see https://tools.ietf.org/search/rfc4492#appendix-A
pub fn prime256v1_key_pair<R: Rng + CryptoRng>(rng: &mut R) -> KeyPair {
    KeyPair::gen_secp256r1(rng)
}

/// Generates an X.509 certificate together with its private key.
pub fn generate_ed25519_cert<R: Rng + CryptoRng>(rng: &mut R) -> CertWithPrivateKey {
    CertWithPrivateKey::builder().build_ed25519(rng)
}

/// Converts the `cert` into an `X509PublicKeyCert`.
pub fn x509_public_key_cert(cert: &TlsPublicKeyCert) -> X509PublicKeyCert {
    cert.to_proto()
}

pub struct CertBuilder {
    version_1: bool,
    cn: Option<String>,
    serial_number: Option<[u8; 19]>,
    validity_days: Option<u32>,
    not_after: Option<String>,
    not_before_days_from_now: Option<u32>,
    not_before: Option<String>,
    not_before_unix: Option<i64>,
    ca_signing_data: Option<(KeyPair, String)>,
    set_ca_key_usage_extension: bool,
    duplicate_subject_cn: bool,
    duplicate_issuer_cn: bool,
    self_sign_with_wrong_secret_key: Option<ReproducibleRng>,
}

impl CertBuilder {
    pub fn version_1(mut self) -> Self {
        self.version_1 = true;
        self
    }

    pub fn cn(mut self, cn: String) -> Self {
        self.cn = Some(cn);
        self
    }

    pub fn serial_number(mut self, serial_number: [u8; 19]) -> Self {
        self.serial_number = Some(serial_number);
        self
    }

    pub fn not_before_days_from_now(mut self, not_before_days: u32) -> Self {
        self.not_before = None;
        self.not_before_unix = None;
        self.not_before_days_from_now = Some(not_before_days);
        self
    }

    pub fn not_before(mut self, not_before: &str) -> Self {
        self.not_before_days_from_now = None;
        self.not_before_unix = None;
        self.not_before = Some(not_before.to_string());
        self
    }

    pub fn not_before_unix(mut self, not_before: i64) -> Self {
        self.not_before_days_from_now = None;
        self.not_before = None;
        self.not_before_unix = Some(not_before);
        self
    }

    pub fn validity_days(mut self, not_after_days: u32) -> Self {
        self.validity_days = Some(not_after_days);
        self.not_after = None;
        self
    }

    pub fn not_after(mut self, not_after: &str) -> Self {
        self.not_after = Some(not_after.to_string());
        self.validity_days = None;
        self
    }

    pub fn set_ca_key_usage_extension(mut self) -> Self {
        self.set_ca_key_usage_extension = true;
        self
    }

    pub fn with_ca_signing(mut self, ca_signing_key_pair: KeyPair, issuer_cn: String) -> Self {
        self.ca_signing_data = Some((ca_signing_key_pair, issuer_cn));
        self
    }

    pub fn with_duplicate_subject_cn(mut self) -> Self {
        self.duplicate_subject_cn = true;
        self
    }

    pub fn with_duplicate_issuer_cn(mut self) -> Self {
        self.duplicate_issuer_cn = true;
        self
    }

    pub fn self_sign_with_wrong_secret_key(mut self, rng: ReproducibleRng) -> Self {
        self.self_sign_with_wrong_secret_key = Some(rng);
        self
    }

    pub fn build_ed25519<R: Rng + CryptoRng>(self, rng: &mut R) -> CertWithPrivateKey {
        self.build(ed25519_key_pair(rng))
    }

    pub fn build_prime256v1<R: Rng + CryptoRng>(self, rng: &mut R) -> CertWithPrivateKey {
        self.build(prime256v1_key_pair(rng))
    }

    pub fn build(self, key_pair: KeyPair) -> CertWithPrivateKey {
        if self.self_sign_with_wrong_secret_key.is_some() && self.ca_signing_data.is_some() {
            panic!(
                "unsupported CertBuilder usage: self_sign_with_wrong_secret_key 
                    and ca_signing_data cannot be used in combination. Choose either."
            )
        }
        if self.set_ca_key_usage_extension && self.version_1 {
            panic!("unsupported CertBuilder usage: x509-cert crate doesn't allow to manually set the version; it 
                    sets version to 1 if there are no extensions (and no unique IDs); by default the version is 3; 
                    this means that version_1 and the CA-flag (which is expressed via a BasicConstraints 
                    extension) together are not supported.")
        }
        CertWithPrivateKey {
            x509: self.x509(&key_pair),
            key_pair,
        }
    }

    fn x509(self, key_pair: &KeyPair) -> x509_cert::Certificate {
        let validity = Validity {
            not_before: self.not_before_asn_1_time(),
            not_after: self.not_after_asn_1_time(),
        };
        let cn_or_default = self.cn.unwrap_or_else(|| DEFAULT_CN.to_string());
        let (profile, cert_signer) = if let Some((ca_key_pair, issuer)) = &self.ca_signing_data {
            // CA signed cert
            let cert_signer = ca_key_pair.clone();
            let profile = Profile::Manual {
                issuer: Some(x509_cert_cn(issuer, self.duplicate_issuer_cn)),
            };
            (profile, cert_signer)
        } else {
            // self signed cert
            let cert_signer = if let Some(mut rng) = self.self_sign_with_wrong_secret_key {
                KeyPair::gen_ed25519(&mut rng)
            } else {
                key_pair.clone()
            };
            let profile = Profile::Manual {
                issuer: Some(x509_cert_cn(&cn_or_default, self.duplicate_issuer_cn)),
            };
            (profile, cert_signer)
        };

        let serial_number = SerialNumber::new(&self.serial_number.unwrap_or(DEFAULT_SERIAL))
            .expect("serial failed");
        let subject = x509_cert_cn(&cn_or_default, self.duplicate_subject_cn);
        let subject_public_key_info =
            spki::SubjectPublicKeyInfoOwned::try_from(key_pair.public_key_der().as_slice())
                .expect("spki failed");

        let mut builder = CertificateBuilder::new(
            profile,
            serial_number,
            validity,
            subject,
            subject_public_key_info,
            &cert_signer,
        )
        .expect("Create certificate");

        if !self.version_1 {
            // x509_certs sets version to 3 whenever there are extensions added
            builder
                .add_extension(&BasicConstraints {
                    ca: self.set_ca_key_usage_extension,
                    path_len_constraint: None,
                })
                .expect("failed to add extension");
        }

        builder.build().expect("failed to build certificate")
    }

    fn not_before_asn_1_time(&self) -> x509_cert::time::Time {
        use der::asn1::GeneralizedTime;
        use x509_cert::time::Time;
        match (
            &self.not_before,
            self.not_before_unix,
            self.not_before_days_from_now,
        ) {
            (None, None, None) => {
                Time::try_from(SystemTime::now()).expect("notBefore: Time::try_from failed")
            }
            (Some(nb_string), None, None) => {
                let nb_unix_timestamp = asn1_time_string_to_unix_timestamp(nb_string)
                    .expect("notBefore: invalid ASN1 time");
                let nb_duration_since_unix_epoch = Duration::from_secs(nb_unix_timestamp);
                Time::from(
                    GeneralizedTime::from_unix_duration(nb_duration_since_unix_epoch)
                        .expect("notBefore: GeneralizedTime::from_unix_duration failed"),
                )
            }
            (None, Some(nb_unix_i64), None) => {
                let nb_unix_u64 =
                    u64::try_from(nb_unix_i64).expect("notBefore: u64 conversion failed");
                let nb_unix_duration = Duration::from_secs(nb_unix_u64);
                Time::from(
                    GeneralizedTime::from_unix_duration(nb_unix_duration)
                        .expect("notBefore: GeneralizedTime::from_unix_duration failed"),
                )
            }
            (None, None, Some(nb_days_from_now)) => {
                let nb_secs_from_now = (nb_days_from_now as u64)
                    .checked_mul(SECS_PER_DAY)
                    .expect("notBefore: checked_mul failed");
                let nb_duration_from_now = Duration::from_secs(nb_secs_from_now);
                Time::try_from(SystemTime::now() + nb_duration_from_now)
                    .expect("notBefore: Time::try_from failed")
            }
            _ => panic!("internal error: illegal combination of notBefore fields"),
        }
    }

    fn not_after_asn_1_time(&self) -> x509_cert::time::Time {
        use der::asn1::GeneralizedTime;
        use x509_cert::time::Time;
        if let Some(validity_days) = self.validity_days {
            let validity_secs = (validity_days as u64)
                .checked_mul(SECS_PER_DAY)
                .expect("notAfter: checked_mul failed");
            let validity_duration = Duration::from_secs(validity_secs);
            return Time::try_from(SystemTime::now() + validity_duration)
                .expect("notAfter: Time::try_from failed");
        }
        let na_or_infinity = self
            .not_after
            .clone()
            .unwrap_or_else(|| RFC5280_NO_WELL_DEFINED_CERTIFICATE_EXPIRATION_DATE.to_string());

        let na_unix_timestamp = asn1_time_string_to_unix_timestamp(&na_or_infinity)
            .expect("notAfter: invalid ASN1 time");

        let na_duration_since_unix_epoch = Duration::from_secs(na_unix_timestamp);
        Time::from(
            GeneralizedTime::from_unix_duration(na_duration_since_unix_epoch)
                .expect("notBefore: GeneralizedTime::from_unix_duration failed"),
        )
    }
}

/// An X.509 certificate together with the corresponding private key.
pub struct CertWithPrivateKey {
    x509: x509_cert::Certificate,
    key_pair: KeyPair, // same key pair as within `x509` in different format
}

impl CertWithPrivateKey {
    pub fn builder() -> CertBuilder {
        CertBuilder {
            version_1: false,
            cn: None,
            serial_number: None,
            not_before_days_from_now: None,
            not_before: None,
            not_before_unix: None,
            ca_signing_data: None,
            validity_days: None,
            not_after: None,
            set_ca_key_usage_extension: false,
            duplicate_subject_cn: false,
            duplicate_issuer_cn: false,
            self_sign_with_wrong_secret_key: None,
        }
    }

    /// Returns the key pair.
    pub fn key_pair(&self) -> &KeyPair {
        &self.key_pair
    }

    /// Returns the X.509 certificate.
    pub fn x509(&self) -> TlsPublicKeyCert {
        TlsPublicKeyCert::new_from_der(self.cert_der())
            .expect("unable to convert to TlsPublicKeyCert")
    }

    /// Returns a PEM encoding of the X.509 certificate.
    pub fn cert_pem(&self) -> Vec<u8> {
        use der::EncodePem;
        self.x509
            .to_pem(x509_cert::der::pem::LineEnding::default())
            .expect("unable to PEM encode cert")
            .into_bytes()
    }

    /// Returns a DER encoding of the X.509 certificate.
    pub fn cert_der(&self) -> Vec<u8> {
        use der::Encode;
        self.x509.to_der().expect("unable to DER encode cert")
    }
}

fn x509_cert_cn(cn: &String, duplicate: bool) -> x509_cert::name::Name {
    let cn_effective = if duplicate {
        format!("CN={cn},CN={cn}")
    } else {
        format!("CN={cn}")
    };
    Name::from_str(&cn_effective)
        .unwrap_or_else(|_| panic!("creating CN (cn={cn}, duplicate={duplicate}) failed"))
}

fn asn1_time_string_to_unix_timestamp(time_asn1: &str) -> Result<u64, String> {
    use time::PrimitiveDateTime;
    use time::macros::format_description;

    let asn1_format = format_description!("[year][month][day][hour][minute][second]Z"); // e.g., 99991231235959Z
    let time_primitivedatetime =
        PrimitiveDateTime::parse(time_asn1, asn1_format).map_err(|_e| {
            format!("invalid asn1 time={time_asn1}: failed to parse ASN1 datetime format")
        })?;
    let time_i64 = time_primitivedatetime.assume_utc().unix_timestamp();
    let time_u64 = u64::try_from(time_i64)
        .map_err(|_e| format!("invalid asn1 time={time_asn1}: failed to convert to u64"))?;
    Ok(time_u64)
}
