use der::asn1::{OctetString, OctetStringRef};
use der::Encode;
use sev::firmware::guest::AttestationReport;
use sev::firmware::host::CertTableEntry as SevCertTableEntry;
use sev::firmware::host::CertType as SevCertType;
use sha2::Digest;
use std::collections::HashMap;
use std::error::Error;

#[derive(der::Sequence)]
pub struct FetchAttestationTokenCustomData<'a> {
    pub nonce: OctetStringRef<'a>,
    pub tls_public_key: OctetStringRef<'a>,
}

impl FetchAttestationTokenCustomData<'_> {
    pub fn to_bytes(&self) -> Result<[u8; 64], Box<dyn Error>> {
        let mut encoded = vec![];
        self.encode_to_vec(&mut encoded)?;
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
struct CertTableEntry {
    /// A specific certificate type.
    pub cert_type: CertType,

    /// The raw data of the certificate.
    pub data: Vec<u8>,
}

#[derive(candid::CandidType, candid::Deserialize)]
enum CertType {
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
