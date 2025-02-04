use candid::CandidType;
use serde::Deserialize;

pub mod security_metadata;

#[derive(Clone, Debug, CandidType, Deserialize, PartialEq, Eq)]
pub enum Ballot {
    Yes,
    No,
    Undecided,
}

pub enum RecoveryError {
    InvalidPubKey(String),
    InvalidSignatureFormat(String),
    InvalidSignature(String),

    PrincipalPublicKeyMismatch(String),
}

type Result<T> = std::result::Result<T, RecoveryError>;

impl ToString for RecoveryError {
    fn to_string(&self) -> String {
        match self {
            Self::InvalidPubKey(s)
            | Self::InvalidSignatureFormat(s)
            | Self::InvalidSignature(s)
            | Self::PrincipalPublicKeyMismatch(s) => s.to_string(),
        }
    }
}
