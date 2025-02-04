use candid::CandidType;
use serde::Deserialize;

pub mod recovery;
pub mod security_metadata;
pub mod simple_node_record;

#[derive(Clone, Debug, CandidType, Deserialize, PartialEq, Eq)]
/// Vote types that exist
pub enum Ballot {
    /// Represents a positive vote on a recovery canister proposal
    Yes,
    /// Represents a vote against a recovery canister proposal
    No,
    /// Represents an undecided state of a vote
    ///
    /// This is a default value that gets set until the node operator submits its
    /// vote on the recovery canister
    Undecided,
}

#[derive(Debug)]
pub enum RecoveryError {
    /// Specifies that the provided bytes couldn't be loaded in a public key
    InvalidPubKey(String),
    /// Specifies that the provided signature bytes couldn't be loaded into
    /// signature struct, most likely due to size mismatch
    InvalidSignatureFormat(String),
    /// Provided signature and the resulting signature don't match
    InvalidSignature(String),
    /// Provided principal was not derived from the public key bytes specified
    PrincipalPublicKeyMismatch(String),

    /// Candid error while encoding the recovery canister payload
    PayloadSerialization(String),
}

/// Convenience type to wrap all results in the library
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
