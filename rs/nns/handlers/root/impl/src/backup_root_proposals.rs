use std::{cell::RefCell, collections::BTreeMap};

use candid::CandidType;
use ic_base_types::NodeId;
use ic_base_types::{PrincipalId, SubnetId};
use ic_nns_common::registry::get_value;
use ic_protobuf::{
    registry::subnet::{self, v1::SubnetRecord},
    types::v1::EquivocationProof,
};
use ic_registry_keys::make_subnet_record_key;
use serde::Deserialize;

use crate::{
    now_seconds,
    root_proposals::{get_node_operator_pid_of_node, RootProposalBallot},
};

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct ChangeSubnetHaltStatus {
    /// The id of the NNS subnet.
    pub subnet_id: SubnetId,
    /// The principal id of the proposer (must be one of the node
    /// operators of the NNS subnet according to the registry at
    /// time of submission).
    pub proposer: PrincipalId,
    /// The ballots cast by node operators.
    pub node_operator_ballots: Vec<(PrincipalId, RootProposalBallot)>,
    /// The timestamp, in seconds, at which the proposal was submitted.
    pub submission_timestamp_seconds: u64,
    /// Should the new status be halted (true) or unhalted (false)
    pub halt: bool,
}

impl ChangeSubnetHaltStatus {
    fn is_byzantine_majority(&self, ballot: RootProposalBallot) -> bool {
        let num_nodes = self.node_operator_ballots.len();
        let max_faults = (num_nodes - 1) / 3;
        let votes_for_ballot: usize = self
            .node_operator_ballots
            .iter()
            .map(|(_, b)| match ballot.eq(b) {
                true => 1,
                false => 0,
            })
            .sum();
        votes_for_ballot >= (num_nodes - max_faults)
    }

    /// For a root proposal to have a byzantine majority of yes, it
    /// needs to collect N - f ""yes"" votes, where N is the total number
    /// of nodes (same as the number of ballots) and f = (N - 1) / 3.
    fn is_byzantine_majority_yes(&self) -> bool {
        self.is_byzantine_majority(RootProposalBallot::Yes)
    }

    /// For a root proposal to have a byzantine majority of no, it
    /// needs to collect f + 1 "no" votes, where N s the total number
    /// of nodes (same as the number of ballots) and f = (N - 1) / 3.
    fn is_byzantine_majority_no(&self) -> bool {
        self.is_byzantine_majority(RootProposalBallot::No)
    }
}

thread_local! {
  static PROPOSALS: RefCell<BTreeMap<PrincipalId, ChangeSubnetHaltStatus>> = const { RefCell::new(BTreeMap::new()) };
}

pub fn get_pending_root_proposals_to_change_subnet_halt_status() -> Vec<ChangeSubnetHaltStatus> {
    // Return the pending proposals
    PROPOSALS.with(|proposals| proposals.borrow().values().cloned().collect())
}

async fn get_subnet_record(subnet_id: SubnetId) -> Result<(SubnetRecord, u64), String> {
    get_value(make_subnet_record_key(subnet_id).as_bytes(), None)
        .await
        .map_err(|e| e.to_string())
}

async fn get_node_operator_ballots_for_subnet(
    subnet_record: SubnetRecord,
    record_version: u64,
    caller: PrincipalId,
) -> Result<Vec<(PrincipalId, RootProposalBallot)>, String> {
    let node_ids: Vec<NodeId> = subnet_record
        .membership
        .iter()
        .map(|node_raw| {
            NodeId::from(PrincipalId::try_from(node_raw).expect("Should be able to decode node id"))
        })
        .collect();

    let mut node_operator_ballots = Vec::new();

    for node_id in node_ids {
        let node_operator_id = get_node_operator_pid_of_node(&node_id, record_version).await?;

        let ballot = match node_operator_id == caller {
            true => RootProposalBallot::Yes,
            false => RootProposalBallot::Undecided,
        };

        node_operator_ballots.push((node_operator_id, ballot))
    }

    Ok(node_operator_ballots)
}

pub async fn submit_root_proposal_to_change_subnet_halt_status(
    caller: PrincipalId,
    subnet_id: SubnetId,
    halt: bool,
) -> Result<(), String> {
    let now = now_seconds();

    let (subnet_record, version) = get_subnet_record(subnet_id.clone()).await?;

    if subnet_record.is_halted == halt {
        return Err(format!(
            "Subnet halt status is already: {}",
            subnet_record.is_halted
        ));
    }

    let node_operator_ballots =
        get_node_operator_ballots_for_subnet(subnet_record.clone(), version, caller).await?;

    // The proposer is not among node operators of the subnet
    if !node_operator_ballots
        .iter()
        .any(|(_, ballot)| ballot.eq(&RootProposalBallot::Yes))
    {
        let message = format!(
            "[Backup root canister] Invalid proposal. Caller: {} must be among the node operators of the nns subnet.",caller
        );
        println!("{}", message);
        return Err(message);
    }

    PROPOSALS.with(|proposals| {
        if let Some(proposal) = proposals.borrow().get(&caller) {
            println!(
                "Current root proposal {:?} from {} is going to be overwritten.",
                proposal, caller,
            );
        }

        proposals.borrow_mut().insert(
            caller,
            ChangeSubnetHaltStatus {
                subnet_id,
                proposer: caller,
                node_operator_ballots,
                submission_timestamp_seconds: now,
                halt,
            },
        )
    });

    Ok(())
}
