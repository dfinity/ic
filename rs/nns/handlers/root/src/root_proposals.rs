use std::cell::RefCell;
use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::str::FromStr;
use std::time::SystemTime;

use candid::{CandidType, Deserialize};
use dfn_core::api::{call, now, CanisterId};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_ic00_types::CanisterInstallMode;
use ic_nervous_system_root::{
    change_canister, CanisterIdRecord, CanisterStatusResult, ChangeCanisterProposal, LOG_PREFIX,
};
use ic_nns_common::registry::get_value;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_protobuf::registry::{
    node::v1::NodeRecord as NodeRecordPb, routing_table::v1::RoutingTable as RoutingTablePb,
    subnet::v1::SubnetRecord as SubnetRecordPb,
};
use ic_registry_keys::{
    make_node_record_key, make_routing_table_record_key, make_subnet_record_key,
};
use ic_registry_routing_table::RoutingTable;

const MAX_TIME_FOR_GOVERNANCE_UPGRADE_ROOT_PROPOSAL: u64 = 60 * 60 * 24 * 7;

/// A ballot in a root proposal.
/// Root proposals are initialized with one ballot per node at creation
/// in the "Undecided" state. These ballots are then changed when the node
/// operators vote.
#[derive(CandidType, Clone, Debug, Deserialize)]
pub enum RootProposalBallot {
    Yes,
    No,
    Undecided,
}

impl FromStr for RootProposalBallot {
    type Err = String;

    fn from_str(string: &str) -> Result<Self, <Self as FromStr>::Err> {
        match string {
            "yes" => Ok(RootProposalBallot::Yes),
            "no" => Ok(RootProposalBallot::No),
            &_ => Err(format!("Unknown root proposal ballot value: {:?}", string)),
        }
    }
}

/// A "root" proposal to upgrade the governance canister.
///
/// This is a special proposal with only one purpose: to upgrade the governance
/// canister in the nns subnetwork.
///
/// It doesn't go through the normal voting process, where we collect votes from
/// neurons, instead it collects votes from node operators that operate the
/// nodes on the nns subnetwork.
///
/// A Root proposal must collect at least N - f votes to pass, so for
/// example if there are 22 nodes, f = (N - 1) \. 3 <=> 7, the proposal must
/// collect N - f = 22 - 7 <=> 15 votes are required for the proposal to pass.
/// (Note the use of integer division to calculate f. For example, f would be 7
/// if N was 22, 23 or 24).
///
/// Note that with the above assumptions the security level of the execution of
/// this proposal is the same as the subnetwork itself.
///
/// Since the membership of the nns subnet can change, we collect the current
/// version of the subnet record in the registry and only allow to vote if it
/// hasn't changed.
///
/// To prevent stale proposals from being executed (say if there are two
/// proposals that target the same current version), the caller must explicitly
/// indicate the hash of the wasm that they intend to upgrade. This way if two
/// proposals to upgrade the same wasm are submitted before any of them is
/// executed, only the the first proposal gets to be executed.
#[derive(CandidType, Debug, Clone, Deserialize)]
pub struct GovernanceUpgradeRootProposal {
    /// The id of the NNS subnet.
    pub nns_subnet_id: SubnetId,
    /// The expected sha256 hash of the governance canister
    /// wasm. This must match the sha of the currently running
    /// governance canister.
    pub current_wasm_sha: Vec<u8>,
    /// The proposal payload to ugprade the governance canister.
    pub payload: ChangeCanisterProposal,
    /// The sha of the binary the proposer wants to upgrade to.
    pub proposed_wasm_sha: Vec<u8>,
    /// The principal id of the proposer (must be one of the node
    /// operators of the NNS subnet according to the registry at
    /// time of submission).
    pub proposer: PrincipalId,
    /// The registry version at which the membership was retrieved
    /// for purposes of tallying votes for this porposal.
    pub subnet_membership_registry_version: u64,
    /// The ballots cast by node operators.
    pub node_operator_ballots: Vec<(PrincipalId, RootProposalBallot)>,
    /// The timestamp, in seconds, at which the proposal was submitted.
    pub submission_timestamp_seconds: u64,
}

impl GovernanceUpgradeRootProposal {
    /// For a root proposal to have a bynzatine majority of yes, it
    /// needs to collect N - f ""yes"" votes, where N is the total number
    /// of nodes (same as the number of ballots) and f = (N - 1) / 3.
    fn is_byzantine_majority_yes(&self) -> bool {
        let num_nodes = self.node_operator_ballots.len();
        let max_faults = (num_nodes - 1) / 3;
        let votes_yes: usize = self
            .node_operator_ballots
            .iter()
            .map(|(_, b)| match b {
                RootProposalBallot::Yes => 1,
                _ => 0,
            })
            .sum();
        votes_yes >= (num_nodes - max_faults)
    }

    /// For a root proposal to have a byzantine majority of no, it
    /// needs to collect f + 1 "no" votes, where N s the total number
    /// of nodes (same as the number of ballots) and f = (N - 1) / 3.
    fn is_byzantine_majority_no(&self) -> bool {
        let num_nodes = self.node_operator_ballots.len();
        let max_faults = (num_nodes - 1) / 3;
        let votes_no: usize = self
            .node_operator_ballots
            .iter()
            .map(|(_, b)| match b {
                RootProposalBallot::No => 1,
                _ => 0,
            })
            .sum();
        votes_no > max_faults
    }
}

thread_local! {
  static PROPOSALS: RefCell<BTreeMap<PrincipalId, GovernanceUpgradeRootProposal>> = RefCell::new(BTreeMap::new());
}

async fn get_current_governance_canister_wasm() -> Vec<u8> {
    let status: CanisterStatusResult = call(
        CanisterId::ic_00(),
        "canister_status",
        dfn_candid::candid,
        (CanisterIdRecord::from(GOVERNANCE_CANISTER_ID),),
    )
    .await
    .unwrap();

    status
        .module_hash
        .expect("Governance canister must return a module hash")
}

/// Submits a "root" governance upgrade proposal.
///
/// The caller must be the principal corresponding to a node operator currently
/// running a node on the nns subnetwork.
///
/// These situations will delete a root proposal:
/// - There can be only one "root" proposal pending from a given principal at a
///   time, if there is already a proposal pending from the same principal the
///   old proposal is deleted and replaced with the new one, voting is reset.
/// - Root proposals are only avaiable for voting for 7 days. After this period
///   the proposal can't be accepted and is deleted, upon receving a vote or a
///   get request or the submission of a new one.
/// - Root proposals are not stored in stable storage, an upgrade of the root
///   canister will delete the currently pending root proposal, if there is one.
pub async fn submit_root_proposal_to_upgrade_governance_canister(
    caller: PrincipalId,
    expected_governance_wasm_sha: Vec<u8>,
    proposal: ChangeCanisterProposal,
) -> Result<(), String> {
    let now = now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Could not get the duration.")
        .as_secs();

    // This is a new proposal and we're ready to prepare it.
    // Do some simple validation first:
    // - That the wasm has some bytes in it.
    // - That it targets the governance canister.
    // - That it is an upgrade (reinstall is not supported).
    if proposal.wasm_module.is_empty()
        || proposal.canister_id != GOVERNANCE_CANISTER_ID
        || proposal.mode != CanisterInstallMode::Upgrade
    {
        let message = format!(
            "{}Invalid proposal. Proposal must be an upgrade proposal \
             to the governance canister with some wasm.",
            LOG_PREFIX
        );
        println!("{}", message);
        return Err(message);
    }

    // Get the sha256 of the currently installed governance canister and
    // make sure it matches the one on the proposal (we'll check it again
    // on execution, but we check it here first to provide a nice error
    // message to the user).
    let current_governance_wasm_sha = get_current_governance_canister_wasm().await;
    if expected_governance_wasm_sha != current_governance_wasm_sha {
        let message = format!(
            "{}Invalid proposal. Expected governance wasm sha must match \
             the currently running governance wasm's sha. Current: {:?}. Expected: {:?}",
            LOG_PREFIX, current_governance_wasm_sha, expected_governance_wasm_sha
        );
        println!("{}", message);
        return Err(message);
    }

    // Get the node operators of the nns subnet from the registry and how
    // many nodes each of them controls. In order to do this we need to:
    // - Get the principal id of the nns subnet
    // - Get the list of nodes
    // - Get the node operators, for each node.
    let mut node_operator_ballots = Vec::new();
    let nns_subnet_id = get_nns_subnet_id()
        .await
        .map_err(|e| format!("Error: {:?}", e))?;
    let (nns_nodes, subnet_membership_registry_version) = get_nns_membership(&nns_subnet_id)
        .await
        .map_err(|e| format!("Error: {:?}", e))?;

    let mut voted_on: i32 = 0;
    let mut total_votes: i32 = 0;
    for node in nns_nodes {
        total_votes += 1;
        let node_operator_pid =
            get_node_operator_pid_of_node(&node, subnet_membership_registry_version)
                .await
                .map_err(|e| format!("Error: {:?}", e))?;
        if node_operator_pid == caller {
            voted_on += 1;
            node_operator_ballots.push((node_operator_pid, RootProposalBallot::Yes));
        } else {
            node_operator_ballots.push((node_operator_pid, RootProposalBallot::Undecided));
        }
    }

    // Check if the caller is among those principals, if it is it will have
    // cast at least one ballot.
    if voted_on == 0 {
        let message = format!(
            "{}Invalid proposal. Caller: {} must be among the node operators of the nns subnet.",
            LOG_PREFIX, caller
        );
        println!("{}", message);
        return Err(message);
    }

    PROPOSALS.with(|proposals| {
        // Check whether there is a previous proposal from the same principal and log
        // that we'll be replacing it.
        if let Some(previous_proposal_from_the_same_principal) = proposals.borrow().get(&caller) {
            println!(
                "{}Current root proposal {:?} from {} is going to be overwritten.",
                LOG_PREFIX, previous_proposal_from_the_same_principal, caller,
            );
        }

        // Store the proposal, the current list of principals that can vote,
        // together with the version number and as many votes for 'yes' as the
        // number of nodes the caller's principal operates, in the nns subnetwork.
        let proposed_wasm_sha = ic_crypto_sha::Sha256::hash(&proposal.wasm_module).to_vec();

        proposals.borrow_mut().insert(
            caller,
            GovernanceUpgradeRootProposal {
                nns_subnet_id,
                current_wasm_sha: current_governance_wasm_sha.clone(),
                proposed_wasm_sha: proposed_wasm_sha.clone(),
                payload: proposal,
                proposer: caller,
                node_operator_ballots,
                subnet_membership_registry_version,
                submission_timestamp_seconds: now,
            },
        );

        println!(
            "{}Root proposal to upgrade the governance canister from: {:?} to {:?}, \
             proposed by: {:?} was submitted. Current tally: {}/{}",
            LOG_PREFIX,
            current_governance_wasm_sha,
            proposed_wasm_sha,
            caller,
            voted_on,
            total_votes
        );
    });
    Ok(())
}

/// Votes on a pending root proposal to change the governance canister
///
/// Votes are only accepted if:
/// - There is one proposal outstanding matching the sha and the proposer.
/// - The latest registry version for the subnet record matches the version when
///   the proposal was submitted. (if it doesn't it clears the proposal and the
///   votes and a new one must be submitted).
/// - The caller's principal is among the principals of the node operators
///   running the nns subnetwork at the time the proposal was submitted.
/// - The caller must pass the sha256 of the wasm that they expect to be on the
///   proposal and this must match the sha256 of the wasm on the current
///   outstanding proposal.
///
/// If the votes are accepted, the caller casts however many ballots as the
/// number of nodes they control on the nns subnetwork.
pub async fn vote_on_root_proposal_to_upgrade_governance_canister(
    caller: PrincipalId,
    proposer: PrincipalId,
    wasm_sha256: Vec<u8>,
    ballot: RootProposalBallot,
) -> Result<(), String> {
    let proposal = get_proposal_clone(&proposer)?;

    let (_, version) = get_nns_membership(&proposal.nns_subnet_id)
        .await
        .map_err(|e| format!("Error executing proposal: {:?}", e))?;

    // Check all the constraints and vote (without any async calls in between).
    PROPOSALS.with(|proposals| {
        let mut proposals = proposals.borrow_mut();
        let proposal = proposals.get_mut(&proposer);
        if proposal.is_none() {
            let message = format!(
                "No root governance upgrade proposal from {} is pending",
                proposer
            );
            println!("{}", message);
            return Err(message);
        }
        let proposal = proposal.unwrap();
        let now = now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Could not get the current time.")
            .as_secs();

        // Check the submission time, if it has elapsed without a majority
        // we can delete it.
        if now
            > (proposal.submission_timestamp_seconds + MAX_TIME_FOR_GOVERNANCE_UPGRADE_ROOT_PROPOSAL)
        {
            proposals.remove(&proposer);
            let message = format!(
                "{}Current root governance upgrade proposal from {} is too old.\
                 Deleting.",
                LOG_PREFIX, proposer,
            );
            println!("{}", message);
            return Err(message);
        }

        // Check that the version of the record on the registry is still the same.
        if version != proposal.subnet_membership_registry_version {
            proposals.remove(&proposer);
            let message = format!(
                "{}Registry version of the subnet record changed since the\
                 proposal from {} was submitted. Deleting.",
                LOG_PREFIX, proposer,
            );
            println!("{}", message);
            return Err(message);
        }

        if wasm_sha256 != proposal.proposed_wasm_sha {
            let message = format!(
                "{}The sha of the wasm in the governance upgrade proposal that the voter intends to vote on: {:?}\
                 is not the same as the sha of the wasm: {:?} proposed by: {}", LOG_PREFIX, wasm_sha256,
                proposal.proposed_wasm_sha, proposer);
            println!("{}", message);
            return Err(message);
        }

        // Add the ballots for this node operator.
        let mut voted_on: i32 = 0;
        for (p, b) in &mut proposal.node_operator_ballots {
            if p == &caller {
                *b = ballot.clone();
                voted_on += 1;
            }
        }

        if voted_on == 0 {
            let message = format!(
                "{}Caller: {} is not eligible to vote on root proposal.",
                LOG_PREFIX, caller,
            );
            println!("{}", message);
            return Err(message);
        }
        Ok(())
    })?;

    // Get the proposal once more. Once the proposal is accepted or rejected it's
    // state is final, so it's ok to clone and execute from the clone.
    let proposal = get_proposal_clone(&proposer)?;

    let mut votes_yes: i32 = 0;
    let mut votes_no: i32 = 0;
    let mut votes_undecided: i32 = 0;
    for (_, b) in &proposal.node_operator_ballots {
        match b {
            RootProposalBallot::Yes => votes_yes += 1,
            RootProposalBallot::No => votes_no += 1,
            RootProposalBallot::Undecided => votes_undecided += 1,
        }
    }

    println!(
        "{}Vote(s) on root proposal to upgrade the governance canister to sha {:?} \
         from: {:?} were accepted. Current tally: {} Yes, {} No, {} Undecided.",
        LOG_PREFIX, wasm_sha256, proposer, votes_yes, votes_no, votes_undecided
    );

    if proposal.is_byzantine_majority_yes() {
        println!(
            "{}Root proposal from {} to upgrade the governance canister to sha: {:?} \
             was accepted. Votes: {} Yes, {} No, {} Undecided. Upgrading.",
            LOG_PREFIX, proposer, wasm_sha256, votes_yes, votes_no, votes_undecided
        );
        let payload = proposal.payload.clone();
        PROPOSALS.with(|proposals| proposals.borrow_mut().remove(&proposer));
        // Check that the wasm of the governance canister is still the same.

        let current_governance_wasm_sha = get_current_governance_canister_wasm().await;
        if current_governance_wasm_sha != proposal.current_wasm_sha {
            let message = format!(
                "{}Invalid proposal. Expected governance wasm sha must match \
             the currently running governance wasm's sha. Current: {:?}. Expected: {:?}",
                LOG_PREFIX, current_governance_wasm_sha, proposal.current_wasm_sha
            );
            println!("{}", message);
            return Err(message);
        }
        change_canister(payload).await;
        Ok(())
    } else if proposal.is_byzantine_majority_no() {
        PROPOSALS.with(|proposals| proposals.borrow_mut().remove(&proposer));
        let message = format!(
            "{}Root proposal from {} to upgrade the governance canister to sha: {:?} \
             was rejected. Votes: {} Yes, {} No, {} Undecided. Deleting.",
            LOG_PREFIX, proposer, wasm_sha256, votes_yes, votes_no, votes_undecided
        );
        println!("{}", message);
        Ok(())
    } else {
        Ok(())
    }
}

fn get_proposal_clone(proposer: &PrincipalId) -> Result<GovernanceUpgradeRootProposal, String> {
    let proposal = PROPOSALS.with(|proposals| proposals.borrow().get(proposer).cloned());
    if proposal.is_none() {
        let message = format!(
            "No root governance upgrade proposal from {} is pending",
            proposer
        );
        println!("{}", message);
        return Err(message);
    }
    Ok(proposal.unwrap())
}

pub fn get_pending_root_proposals_to_upgrade_governance_canister(
) -> Vec<GovernanceUpgradeRootProposal> {
    // Return the pending proposals, but strip the wasm so that the response stays
    // small.
    PROPOSALS.with(|proposals| {
        proposals
            .borrow()
            .values()
            .map(|p| {
                let mut p = p.clone();
                p.payload.wasm_module = vec![];
                p.payload.arg = vec![];
                p
            })
            .collect()
    })
}

/// In order to get the subnet id of the NNS, we get the routing table and
/// figure out which subnet has the governance canister's id.
async fn get_nns_subnet_id() -> Result<SubnetId, String> {
    let routing_table = RoutingTable::try_from(
        get_value::<RoutingTablePb>(&make_routing_table_record_key().as_bytes().to_vec(), None)
            .await
            .map_err(|e| {
                format!(
                    "Error getting routing table of the nns subnet. Error: {:?}",
                    e
                )
            })?
            .0,
    )
    .map_err(|e| format!("Error decoding routing table: {:?}", e))?;
    routing_table
        .route(GOVERNANCE_CANISTER_ID.into())
        .ok_or_else(|| {
            "Error getting the subnet id of the subnet containing the governance canister\
             from the routing table"
                .to_string()
        })
}

/// Returns the membership for the nns subnetwork, and the version at which it
/// was fetched.
async fn get_nns_membership(subnet_id: &SubnetId) -> Result<(Vec<NodeId>, u64), String> {
    let (subnet_registry_entry, version) = get_value::<SubnetRecordPb>(
        &make_subnet_record_key(*subnet_id).as_bytes().to_vec(),
        None,
    )
    .await
    .map_err(|e| format!("Error getting membership of nns subnet. Error: {:?}", e))?;

    Ok((
        subnet_registry_entry
            .membership
            .iter()
            .map(|node_raw| {
                NodeId::from(PrincipalId::try_from(node_raw).expect("Can't decode node id"))
            })
            .collect(),
        version,
    ))
}

/// Returns the principal corresponding to the node operator of the given node.
async fn get_node_operator_pid_of_node(
    node_id: &NodeId,
    version: u64,
) -> Result<PrincipalId, String> {
    let (node_record, _) = get_value::<NodeRecordPb>(
        &make_node_record_key(*node_id).as_bytes().to_vec(),
        Some(version),
    )
    .await
    .map_err(|e| {
        format!(
            "Error getting the node record from the registry. Error: {:?}",
            e
        )
    })?;
    PrincipalId::try_from(node_record.node_operator_id).map_err(|e| {
        format!(
            "Error decoding the node operator id from the node record. Error: {:?}",
            e
        )
    })
}
