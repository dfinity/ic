use crate::*;
use candid::{CandidType, Principal};
use ed25519_dalek::{ed25519::signature::SignerMut, SigningKey};
use serde::Deserialize;

use crate::{security_metadata::SecurityMetadata, Ballot};

#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
/// Types of acceptable payloads by the recovery canister proposals.
pub enum RecoveryPayload {
    /// Halt NNS.
    ///
    /// If adopted, the orchestrator's watching the recovery canister
    /// should deem NNS as halted. This proposal maps to a proposal
    /// similar to [134605](https://dashboard.internetcomputer.org/proposal/134605).
    Halt,
    /// Do the recovery.
    ///
    /// If adopted, the orchestrator's watching recovery canister
    /// should perform a recovery based on the provided information.
    /// This proposal maps to a proposal similar to [134629](https://dashboard.internetcomputer.org/proposal/134629).
    DoRecovery { height: u64, state_hash: String },
    /// Unhalt NNS.
    ///
    /// If adopted, the orchestrator's watching the recovery canister
    /// should deem NNS as unhalted and working normally. This proposal
    /// maps to a proposal similar to [134632](https://dashboard.internetcomputer.org/proposal/134632).
    Unhalt,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
/// Represents a vote from one node operator
pub struct NodeOperatorBallot {
    /// The principal id of the node operator (must be one of the node
    /// operators of the NNS subnet according to the registry at
    /// time of submission).
    pub principal: Principal,
    /// List of nodes that the node operator controls on the NNS.
    /// Each node counts as 1 vote.
    pub nodes_tied_to_ballot: Vec<Principal>,
    /// The node provider's decision on the observed proposal.
    pub ballot: Ballot,
    /// Metadata used for verifying the user's identity, and integrity of the
    /// vote itself.
    pub security_metadata: SecurityMetadata,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct RecoveryProposal {
    /// The principal id of the proposer (must be one of the node
    /// operators of the NNS subnet according to the registry at
    /// time of submission).
    pub proposer: Principal,
    /// The timestamp, in seconds, at which the proposal was submitted.
    pub submission_timestamp_seconds: u64,
    /// The ballots cast by node operators.
    pub node_operator_ballots: Vec<NodeOperatorBallot>,
    /// Payload for the proposal.
    pub payload: RecoveryPayload,
}

#[derive(Debug, CandidType, Deserialize, Clone)]
/// Conveniece struct used for submitting a new proposal
pub struct NewRecoveryProposal {
    pub payload: RecoveryPayload,
}

#[derive(Debug, CandidType, Deserialize, Clone)]
/// Convenience struct used for casting a vote on a proposal
pub struct VoteOnRecoveryProposal {
    pub security_metadata: SecurityMetadata,
    pub ballot: Ballot,
}

impl RecoveryProposal {
    pub fn sign(&self, signing_key: &mut SigningKey) -> Result<[[u8; 32]; 2]> {
        let signature = signing_key.sign(&self.signature_payload()?);
        Ok([*signature.r_bytes(), *signature.s_bytes()])
    }

    pub fn signature_payload(&self) -> Result<Vec<u8>> {
        let self_without_ballots = Self {
            node_operator_ballots: vec![],
            ..self.clone()
        };
        candid::encode_one(self_without_ballots)
            .map_err(|e| RecoveryError::PayloadSerialization(e.to_string()))
    }

    fn is_byzantine_majority(&self, ballot: Ballot) -> bool {
        let total_nodes_nodes = self
            .node_operator_ballots
            .iter()
            .map(|bal| bal.nodes_tied_to_ballot.len())
            .sum::<usize>();
        let max_faults = (total_nodes_nodes - 1) / 3;
        let votes_for_ballot = self
            .node_operator_ballots
            .iter()
            .map(|vote| match vote.ballot == ballot {
                // Each vote has the weight of 1 times
                // the amount of nodes the node operator
                // has in the nns subnet
                true => 1 * vote.nodes_tied_to_ballot.len(),
                false => 0,
            })
            .sum::<usize>();
        votes_for_ballot >= (total_nodes_nodes - max_faults)
    }

    /// For a root proposal to have a byzantine majority of no, it
    /// needs to collect f + 1 "no" votes, where N s the total number
    /// of nodes (same as the number of ballots) and f = (N - 1) / 3.
    pub fn is_byzantine_majority_no(&self) -> bool {
        self.is_byzantine_majority(Ballot::No)
    }

    /// For a root proposal to have a byzantine majority of no, it
    /// needs to collect f + 1 "no" votes, where N s the total number
    /// of nodes (same as the number of ballots) and f = (N - 1) / 3.
    pub fn is_byzantine_majority_yes(&self) -> bool {
        self.is_byzantine_majority(Ballot::Yes)
    }
}

impl VerifyIntegirty for NodeOperatorBallot {
    fn verify(&self) -> Result<()> {
        self.security_metadata.validate_metadata(&self.principal)
    }
}

impl VerifyIntegirty for RecoveryProposal {
    fn verify(&self) -> Result<()> {
        self.node_operator_ballots.iter().verify()
    }
}
