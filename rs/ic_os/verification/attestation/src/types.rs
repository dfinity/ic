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
