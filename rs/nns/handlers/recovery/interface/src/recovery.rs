use crate::*;
use candid::{CandidType, Principal};
use ed25519_dalek::{ed25519::signature::SignerMut, SigningKey};
use serde::Deserialize;

use crate::{security_metadata::SecurityMetadata, Ballot};

#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub enum RecoveryPayload {
    Halt,
    DoRecovery { height: u64, state_hash: String },
    Unhalt,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct NodeOperatorBallot {
    pub principal: Principal,
    pub nodes_tied_to_ballot: Vec<Principal>,
    pub ballot: Ballot,
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
    /// Payload for the proposal
    pub payload: RecoveryPayload,
}

impl RecoveryProposal {
    pub fn sign(&self, signing_key: &mut SigningKey) -> Result<[u8; 64]> {
        let signature = signing_key.sign(&self.signature_payload()?);
        Ok(signature.to_bytes())
    }

    pub fn signature_payload(&self) -> Result<Vec<u8>> {
        let self_without_ballots = Self {
            node_operator_ballots: vec![],
            ..self.clone()
        };
        candid::encode_one(self_without_ballots)
            .map_err(|e| RecoveryError::PayloadSerialization(e.to_string()))
    }
}

impl RecoveryProposal {
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
