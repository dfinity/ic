use candid::CandidType;
use serde::Deserialize;

pub mod recovery;
pub mod security_metadata;

#[derive(Clone, Debug, CandidType, Deserialize, PartialEq, Eq)]
pub enum Ballot {
    Yes,
    No,
    Undecided,
}

#[derive(Debug)]
pub enum RecoveryError {
    InvalidPubKey(String),
    InvalidSignatureFormat(String),
    InvalidSignature(String),
    PrincipalPublicKeyMismatch(String),

    PayloadSerialization(String),
}

type Result<T> = std::result::Result<T, RecoveryError>;

impl ToString for RecoveryError {
    fn to_string(&self) -> String {
        match self {
            Self::InvalidPubKey(s)
            | Self::InvalidSignatureFormat(s)
            | Self::InvalidSignature(s)
            | Self::PrincipalPublicKeyMismatch(s)
            | Self::PayloadSerialization(s) => s.to_string(),
        }
    }
}
