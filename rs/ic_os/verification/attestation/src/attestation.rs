use der::asn1::OctetStringRef;
use der::Encode;
use sha2::Digest;
use thiserror::Error;

#[derive(der::Sequence)]
pub struct GenerateAttestationTokenCustomData<'a> {
    pub nonce: OctetStringRef<'a>,
    pub tls_public_key: OctetStringRef<'a>,
}

#[derive(Debug, Error)]
#[error("EncodingError")]
pub struct EncodingError;

impl GenerateAttestationTokenCustomData<'_> {
    pub fn to_bytes(&self) -> Result<[u8; 64], EncodingError> {
        let mut encoded = vec![];
        self.encode_to_vec(&mut encoded)
            .map_err(|_| EncodingError)?;
        Ok(sha2::Sha512::digest(encoded).into())
    }
}

pub struct StoreDiskEncryptionKeyCustomData {}

pub struct RetrieveDiskEncryptionKeyCustomData {}

#[derive(candid::CandidType, candid::Deserialize)]
pub struct SevAttestationReport {
    pub attestation_report: Vec<u8>, // sev::firmware::guest::AttestationReport
    pub certificates: Vec<CertTableEntry>,
}

#[derive(candid::CandidType, candid::Deserialize)]
pub struct CertTableEntry {
    /// A specific certificate type.
    pub cert_type: Option<CertType>,

    /// The raw data of the certificate.
    pub data: Vec<u8>,
}

#[derive(candid::CandidType, candid::Deserialize)]
pub enum CertType {
    ARK,

    /// AMD SEV Signing Key (ASK) certificate
    ASK,

    /// Versioned Chip Endorsement Key (VCEK) certificate
    VCEK,

    /// Versioned Loaded Endorsement Key (VLEK) certificate
    VLEK,

    /// Certificate Revocation List (CRLs) certificate(s)
    CRL,

    /// Other (Specify GUID)
    OTHER(/*uuid::Uuid*/),
}
