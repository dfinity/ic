use std::str::FromStr;

use crate::*;
use candid::{CandidType, Principal};
use ed25519_dalek::{ed25519::signature::SignerMut, SigningKey};
use ic_base_types::{PrincipalId, SubnetId};
use registry_canister::mutations::{
    do_recover_subnet::RecoverSubnetPayload, do_update_subnet::UpdateSubnetPayload,
};
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
        // If all node operators in the canister
        // were added as initial node operators
        // they would have 0 nodes meaning that
        // their total sum of nodes would be 0
        if total_nodes_nodes == 0 {
            return false;
        }
        let max_faults = (total_nodes_nodes - 1) / 3;
        let votes_for_ballot = self
            .node_operator_ballots
            .iter()
            .map(|vote| match vote.ballot == ballot {
                // Each vote has the weight of 1 times
                // the amount of nodes the node operator
                // has in the nns subnet
                true => vote.nodes_tied_to_ballot.len(),
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
    fn verify_integrity(&self) -> Result<()> {
        self.security_metadata.validate_metadata(&self.principal)
    }
}

impl VerifyIntegirty for RecoveryProposal {
    fn verify_integrity(&self) -> Result<()> {
        self.node_operator_ballots
            .iter()
            .filter(|ballot| !ballot.ballot.eq(&Ballot::Undecided))
            .verify_integrity()
    }
}

fn nns_principal_id() -> PrincipalId {
    PrincipalId::from_str("tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe")
        .expect("Should be a valid NNS id")
}

impl TryFrom<RecoveryProposal> for UpdateSubnetPayload {
    type Error = RecoveryError;

    fn try_from(value: RecoveryProposal) -> std::result::Result<Self, Self::Error> {
        match value.payload {
            RecoveryPayload::Halt => Ok(Self {
                chain_key_config: None,
                chain_key_signing_disable: None,
                chain_key_signing_enable: None,
                dkg_dealings_per_block: None,
                ecdsa_config: None,
                ecdsa_key_signing_disable: None,
                ecdsa_key_signing_enable: None,
                features: None,
                halt_at_cup_height: None,
                initial_notary_delay_millis: None,
                max_artifact_streams_per_peer: None,
                max_block_payload_size: None,
                max_chunk_size: None,
                max_chunk_wait_ms: None,
                max_duplicity: None,
                max_ingress_bytes_per_message: None,
                max_ingress_messages_per_block: None,
                max_number_of_canisters: None,
                pfn_evaluation_period_ms: None,
                receive_check_cache_size: None,
                registry_poll_period_ms: None,
                retransmission_request_ms: None,
                ssh_backup_access: None,
                start_as_nns: None,
                subnet_type: None,
                unit_delay_millis: None,
                dkg_interval_length: None,

                set_gossip_config_to_default: false,
                is_halted: Some(true),
                subnet_id: SubnetId::from(nns_principal_id()),
                // TODO: check if this should be configurable
                ssh_readonly_access: Some(vec!["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPiyAbNALyrFb1PAdPCcV5w6GYqILGyRbyqzLEVspFmJ recovery@dfinity.org".to_string()])
            }),
            RecoveryPayload::Unhalt => Ok(Self {
                chain_key_config: None,
                chain_key_signing_disable: None,
                chain_key_signing_enable: None,
                dkg_dealings_per_block: None,
                ecdsa_config: None,
                ecdsa_key_signing_disable: None,
                ecdsa_key_signing_enable: None,
                features: None,
                halt_at_cup_height: None,
                initial_notary_delay_millis: None,
                max_artifact_streams_per_peer: None,
                max_block_payload_size: None,
                max_chunk_size: None,
                max_chunk_wait_ms: None,
                max_duplicity: None,
                max_ingress_bytes_per_message: None,
                max_ingress_messages_per_block: None,
                max_number_of_canisters: None,
                pfn_evaluation_period_ms: None,
                receive_check_cache_size: None,
                registry_poll_period_ms: None,
                retransmission_request_ms: None,
                ssh_backup_access: None,
                start_as_nns: None,
                subnet_type: None,
                unit_delay_millis: None,
                dkg_interval_length: None,

                set_gossip_config_to_default: false,
                is_halted: Some(false),
                subnet_id: SubnetId::from(nns_principal_id()),
                ssh_readonly_access: Some(vec![])
            }),
            _ => Err(RecoveryError::InvalidRecoveryProposalPayload(
                "Cannot map this proposal payload to UpdateSubnetPayload".to_string(),
            )),
        }
    }
}

impl TryFrom<RecoveryProposal> for RecoverSubnetPayload {
    type Error = RecoveryError;

    fn try_from(value: RecoveryProposal) -> std::result::Result<Self, Self::Error> {
        match value.payload {
            RecoveryPayload::DoRecovery { height, state_hash } => Ok(Self {
                subnet_id: nns_principal_id(),
                height,
                // TODO: Migrate timestamps to nanoseconds in canister
                time_ns: value.submission_timestamp_seconds,
                state_hash: hex::decode(state_hash).map_err(|e| {
                    RecoveryError::PayloadSerialization(format!(
                        "Cannot deserialize state hash into a byte vector: {}",
                        e
                    ))
                })?,
                replacement_nodes: None,
                registry_store_uri: None,
                ecdsa_config: None,
                chain_key_config: None,
            }),
            _ => Err(RecoveryError::InvalidRecoveryProposalPayload(
                "Cannot map this proposal payload to UpdateSubnetPayload".to_string(),
            )),
        }
    }
}
