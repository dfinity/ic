//! Utilities for building X.509 certificates for tests.
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, PKeyRef, Private};
use openssl::x509::extension::BasicConstraints;
use openssl::x509::{X509Name, X509Ref, X509};

const DEFAULT_SERIAL: [u8; 19] = [42u8; 19];
const DEFAULT_X509_VERSION: i32 = 3;
const DEFAULT_CN: &str = "Spock";
const DEFAULT_NOT_BEFORE_DAYS_FROM_NOW: u32 = 0;
const DEFAULT_VALIDITY_DAYS: u32 = 365;

/// Generates an ed25519 key pair.
pub fn ed25519_key_pair() -> PKey<Private> {
    PKey::generate_ed25519().expect("failed to create Ed25519 key pair")
}

/// Generates a prime256v1 key pair.
///
/// Note that NIST P-256, prime256v1, secp256r1 are all the same, see https://tools.ietf.org/search/rfc4492#appendix-A
pub fn prime256v1_key_pair() -> PKey<Private> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("unable to create EC group");
    let ec_key_pair = EcKey::generate(&group).expect("unable to create EC key");
    PKey::from_ec_key(ec_key_pair).expect("unable to create EC key pair")
}

/// Generates an X.509 certificate together with its private key.
pub fn generate_ed25519_cert() -> (PKey<Private>, X509) {
    let key_pair = ed25519_key_pair();
    let server_cert = generate_cert(&key_pair, MessageDigest::null());
    (key_pair, server_cert)
}

/// Generates a TlsPublicKeyCert certificate together with its private key.
pub fn generate_ed25519_tlscert() -> (PKey<Private>, TlsPublicKeyCert) {
    let key_pair = ed25519_key_pair();
    let server_cert_x509 = generate_cert(&key_pair, MessageDigest::null());
    let server_cert = TlsPublicKeyCert::new_from_x509(server_cert_x509)
        .expect("error converting X509 to TlsPublicKeyCert");
    (key_pair, server_cert)
}

/// Converts the `cert` into an `X509PublicKeyCert`.
pub fn x509_public_key_cert(cert: &X509) -> X509PublicKeyCert {
    X509PublicKeyCert {
        certificate_der: cert_to_der(&cert),
    }
}

/// DER encodes the `cert`.
pub fn cert_to_der(cert: &X509Ref) -> Vec<u8> {
    cert.to_der().expect("error converting cert to DER")
}

/// DER encodes the private `key`.
pub fn private_key_to_der(key: &PKeyRef<Private>) -> Vec<u8> {
    key.private_key_to_der()
        .expect("error converting private key to DER")
}

/// Generates an X.509 certificate using the `key_pair`.
pub fn generate_cert(key_pair: &PKey<Private>, digest: MessageDigest) -> X509 {
    CertWithPrivateKey::builder()
        .build(key_pair.clone(), digest)
        .x509()
}

/// A builder that allows to build X.509 certificates using a fluent API.
pub struct CertBuilder {
    version: Option<i32>,
    cn: Option<String>,
    serial_number: Option<[u8; 19]>,
    validity_days: Option<u32>,
    not_after: Option<String>,
    not_before_days_from_now: Option<u32>,
    not_before: Option<String>,
    not_before_unix: Option<i64>,
    ca_signing_data: Option<(PKey<Private>, String)>,
    set_ca_key_usage_extension: bool,
    duplicate_subject_cn: bool,
    duplicate_issuer_cn: bool,
    self_sign_with_wrong_secret_key: bool,
}

impl CertBuilder {
    pub fn version(mut self, version: i32) -> Self {
        self.version = Some(version);
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

    pub fn with_ca_signing(
        mut self,
        ca_signing_key_pair: PKey<Private>,
        issuer_cn: String,
    ) -> Self {
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

    pub fn self_sign_with_wrong_secret_key(mut self) -> Self {
        self.self_sign_with_wrong_secret_key = true;
        self
    }

    pub fn build_ed25519(self) -> CertWithPrivateKey {
        self.build(ed25519_key_pair(), MessageDigest::null())
    }

    pub fn build_prime256v1(self) -> CertWithPrivateKey {
        self.build(prime256v1_key_pair(), MessageDigest::sha256())
    }

    pub fn build(self, key_pair: PKey<Private>, digest: MessageDigest) -> CertWithPrivateKey {
        CertWithPrivateKey {
            x509: self.x509(key_pair.clone(), digest),
            key_pair,
        }
    }

    fn x509(self, key_pair: PKey<Private>, digest: MessageDigest) -> X509 {
        let mut builder = X509::builder().expect("unable to create builder");
        let version = self.version.unwrap_or(DEFAULT_X509_VERSION);
        builder
            .set_version(version - 1) // OpenSSL uses index origin 0 for version
            .expect("unable to set version");
        builder
            .set_serial_number(&serial_number(
                self.serial_number.clone().unwrap_or(DEFAULT_SERIAL),
            ))
            .expect("unable to set serial number");
        let subject_cn = x509_name_with_cn(
            &self.cn.clone().unwrap_or_else(|| DEFAULT_CN.to_string()),
            self.duplicate_subject_cn,
        );
        builder
            .set_subject_name(&subject_cn)
            .expect("unable to set subject cn");
        builder
            .set_pubkey(&key_pair)
            .expect("unable to set public key");
        builder
            .set_not_before(&self.not_before_asn_1_time())
            .expect("unable to set 'not before'");
        builder
            .set_not_after(&self.not_after_asn_1_time())
            .expect("unable to set 'not after'");
        if self.set_ca_key_usage_extension {
            let ca_extension = BasicConstraints::new()
                .ca()
                .build()
                .expect("failed to build basic constraints");
            builder
                .append_extension(ca_extension)
                .expect("unable to set basic constraints extension")
        }
        if let Some((ca_key, issuer)) = &self.ca_signing_data {
            // CA signed cert:
            let issuer_cn = x509_name_with_cn(&issuer, self.duplicate_issuer_cn);
            builder
                .set_issuer_name(&issuer_cn)
                .expect("unable to set issuer cn");
            builder.sign(ca_key, digest).expect("unable to sign");
        } else {
            // self signed cert:
            let issuer_cn = x509_name_with_cn(
                &self.cn.clone().unwrap_or_else(|| DEFAULT_CN.to_string()),
                self.duplicate_issuer_cn,
            );
            builder
                .set_issuer_name(&issuer_cn)
                .expect("unable to set issuer cn");
            if self.self_sign_with_wrong_secret_key {
                let wrong_signing_key_pair = ed25519_key_pair();
                builder
                    .sign(&wrong_signing_key_pair, digest)
                    .expect("unable to sign");
            } else {
                builder.sign(&key_pair, digest).expect("unable to sign");
            }
        }
        builder.build()
    }

    fn not_before_asn_1_time(&self) -> Asn1Time {
        match (
            &self.not_before,
            self.not_before_unix,
            self.not_before_days_from_now,
        ) {
            (None, None, None) => Asn1Time::days_from_now(DEFAULT_NOT_BEFORE_DAYS_FROM_NOW)
                .expect("unable to create 'not before'"),
            (Some(not_before_string), None, None) => {
                Asn1Time::from_str_x509(not_before_string).expect("unable to create 'not before'")
            }
            (None, Some(not_before_unix), None) => {
                Asn1Time::from_unix(not_before_unix).expect("unable to create 'not before'")
            }
            (None, None, Some(not_before_days_from_now)) => {
                Asn1Time::days_from_now(not_before_days_from_now)
                    .expect("unable to create 'not before'")
            }
            _ => panic!("internal error: illegal combination of notBefore fields"),
        }
    }

    fn not_after_asn_1_time(&self) -> Asn1Time {
        if let Some(not_after) = &self.not_after {
            return Asn1Time::from_str_x509(not_after).expect("unable to create 'not after'");
        }
        let validity_days = self.validity_days.unwrap_or(DEFAULT_VALIDITY_DAYS);
        Asn1Time::days_from_now(validity_days).expect("unable to create 'not after'")
    }
}

/// An X.509 certificate together with the corresponding private key.
pub struct CertWithPrivateKey {
    x509: X509,
    key_pair: PKey<Private>,
}

impl CertWithPrivateKey {
    pub fn builder() -> CertBuilder {
        CertBuilder {
            version: None,
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
            self_sign_with_wrong_secret_key: false,
        }
    }

    /// Returns the key pair.
    pub fn key_pair(&self) -> PKey<Private> {
        self.key_pair.clone()
    }

    /// Returns a PEM encoding of the key pair.
    pub fn key_pair_pem(&self) -> Vec<u8> {
        self.key_pair
            .private_key_to_pem_pkcs8()
            .expect("unable to PEM encode private key")
    }

    /// Returns the X.509 certificate.
    pub fn x509(&self) -> X509 {
        self.x509.clone()
    }

    /// Returns a PEM encoding of the X.509 certificate.
    pub fn cert_pem(&self) -> Vec<u8> {
        self.x509.to_pem().expect("unable to PEM encode cert")
    }

    /// Returns a DER encoding of the X.509 certificate.
    pub fn cert_der(&self) -> Vec<u8> {
        self.x509.to_der().expect("unable to DER encode cert")
    }
}

fn x509_name_with_cn(common_name: &str, duplicate: bool) -> X509Name {
    let mut name = X509Name::builder().expect("unable to create name builder");
    name.append_entry_by_nid(Nid::COMMONNAME, common_name)
        .expect("unable to append common name");
    if duplicate {
        name.append_entry_by_nid(Nid::COMMONNAME, common_name)
            .expect("unable to append common name");
    }
    name.build()
}

fn serial_number(serial: [u8; 19]) -> Asn1Integer {
    BigNum::from_slice(&serial)
        .expect("unable to create the serial number big num")
        .to_asn1_integer()
        .expect("unable to create ASN1 integer for serial number")
}
