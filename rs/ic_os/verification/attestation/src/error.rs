use candid::CandidType;
use std::error::Error;
use std::fmt::{Debug, Display, Formatter};

#[derive(Debug, CandidType, candid::Deserialize, Clone)]
pub enum VerificationErrorDetail {
    Internal { message: String },
    InvalidNonce,
    NonceNotFound,
    NonceTooOld,
    AttestationTokenNotFound,
    UnsupportedTlsKey { message: String },
    InvalidAttestationReport { message: String },
    InvalidCertificateChain { message: String },
}

impl Display for VerificationErrorDetail {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(self, f)
    }
}

#[derive(Debug, CandidType, candid::Deserialize, Clone)]
pub struct VerificationError {
    message: String,
    // The detail of the error is always filled on the server side. It's marked as optional
    // to keep it forwards compatible and allow older clients to deserialize newer responses.
    detail: Option<VerificationErrorDetail>,
}

impl VerificationError {
    pub fn internal(err: impl Display) -> Self {
        // VerificationErrorDetail::Internal(err.to_string(), 0).into()
        VerificationErrorDetail::Internal {
            message: err.to_string(),
        }
        .into()
    }
}

impl Display for VerificationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for VerificationError {}

impl From<VerificationErrorDetail> for VerificationError {
    fn from(value: VerificationErrorDetail) -> Self {
        VerificationError {
            message: value.to_string(),
            detail: Some(value),
        }
    }
}
