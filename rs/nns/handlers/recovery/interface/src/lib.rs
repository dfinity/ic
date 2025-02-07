use candid::CandidType;
use recovery::RecoveryProposal;
use serde::Deserialize;

pub mod recovery;
pub mod recovery_init;
pub mod security_metadata;
pub mod signing;
pub mod simple_node_operator_record;

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

    /// Errors coming from ic-agent
    AgentError(String),
    /// Candid errors
    CandidError(String),

    /// Identity in use is invalid to fulfil a desired action
    InvalidIdentity(String),

    /// No proposals exist on the canister
    NoProposals(String),

    /// Specifies that the recovery proposal payload cannot be
    /// mapped to a governance proposal. This can happen if the
    /// library versions used for the canister and client don't
    /// match
    InvalidRecoveryProposalPayload(String),

    /// Errors received from the canister
    CanisterError(String),
}

impl From<candid::Error> for RecoveryError {
    fn from(value: candid::Error) -> Self {
        Self::CandidError(value.to_string())
    }
}

/// Convenience type to wrap all results in the library
pub type Result<T> = std::result::Result<T, RecoveryError>;

impl ToString for RecoveryError {
    fn to_string(&self) -> String {
        match self {
            Self::InvalidPubKey(s)
            | Self::InvalidSignatureFormat(s)
            | Self::InvalidSignature(s)
            | Self::PrincipalPublicKeyMismatch(s)
            | Self::PayloadSerialization(s)
            | Self::AgentError(s)
            | Self::CandidError(s)
            | Self::InvalidIdentity(s)
            | Self::NoProposals(s)
            | Self::InvalidRecoveryProposalPayload(s)
            | Self::CanisterError(s) => s.to_string(),
        }
    }
}

pub trait VerifyIntegirty {
    fn verify_integrity(&self) -> Result<()>;
}

impl<'a, I, T> VerifyIntegirty for I
where
    I: Iterator<Item = &'a T> + Clone,
    T: VerifyIntegirty + 'a,
{
    fn verify_integrity(&self) -> Result<()> {
        self.clone()
            .map(|item| item.verify_integrity())
            .find(|res| res.is_err())
            .unwrap_or(Ok(()))
    }
}

/// Convenience method that explicitly checks the authenticity
/// of sent proposal chain. It is equivalent to calling `proposals.iter().verify_integrity()`
pub fn verify_signatures_and_authenticity_of_all_proposals_and_votes(
    proposals: Vec<&RecoveryProposal>,
) -> Result<()> {
    proposals
        .clone()
        .iter()
        .map(|proposal| {
            proposal
                .node_operator_ballots
                .clone()
                .iter()
                .map(|ballot| {
                    ballot
                        .security_metadata
                        .validate_metadata(&ballot.principal)
                })
                .find(|ballot_validation_response| ballot_validation_response.is_err())
                .unwrap_or(Ok(()))
        })
        .find(|proposal_validation_response| proposal_validation_response.is_err())
        .unwrap_or(Ok(()))
}
