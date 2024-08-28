//! Contains methods and structs that support settings up the NNS.

use ic_types::hostos_version::HostosVersion;
use itertools::Itertools;
use registry_canister::mutations::{
    do_update_elected_hostos_versions::ReviseElectedHostosVersionsPayload,
    do_update_nodes_hostos_version::DeployHostosToSomeNodes,
};

use crate::{
    driver::test_env_api::{HasPublicApiUrl, IcNodeSnapshot},
    util::{create_agent, runtime_from_url},
};
use candid::CandidType;
use canister_test::{Canister, Runtime};
use cycles_minting_canister::{
    ChangeSubnetTypeAssignmentArgs, SetAuthorizedSubnetworkListArgs, SubnetListWithType,
    UpdateSubnetTypeArgs,
};
use dfn_candid::candid_one;
use ic_base_types::NodeId;
use ic_canister_client::Sender;
use ic_nervous_system_common_test_keys::{TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_KEYPAIR};
use ic_nns_common::types::{NeuronId, ProposalId};
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, REGISTRY_CANISTER_ID, SNS_WASM_CANISTER_ID};
use ic_nns_governance_api::pb::v1::{
    manage_neuron::{Command, NeuronIdOrSubaccount, RegisterVote},
    ManageNeuron, ManageNeuronResponse, NnsFunction, ProposalInfo, ProposalStatus, Vote,
};
use ic_nns_test_utils::governance::{
    get_proposal_info, submit_external_update_proposal,
    submit_external_update_proposal_allowing_error, wait_for_final_state,
};
use ic_prep_lib::subnet_configuration::{self, duration_to_millis};
use ic_protobuf::registry::subnet::v1::SubnetListRecord;
use ic_registry_client_helpers::deserialize_registry_value;
use ic_registry_keys::make_subnet_list_record_key;
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_registry_subnet_type::SubnetType;
use ic_types::{CanisterId, PrincipalId, ReplicaVersion, SubnetId};
use registry_canister::mutations::{
    do_add_nodes_to_subnet::AddNodesToSubnetPayload,
    do_change_subnet_membership::ChangeSubnetMembershipPayload,
    do_create_subnet::CreateSubnetPayload,
    do_deploy_guestos_to_all_subnet_nodes::DeployGuestosToAllSubnetNodesPayload,
    do_deploy_guestos_to_all_unassigned_nodes::DeployGuestosToAllUnassignedNodesPayload,
    do_remove_nodes_from_subnet::RemoveNodesFromSubnetPayload,
    do_revise_elected_replica_versions::ReviseElectedGuestosVersionsPayload,
};
use slog::{info, Logger};
use std::{convert::TryFrom, time::Duration};
use tokio::time::sleep;
use url::Url;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum UpgradeContent {
    All,
    Orchestrator,
    Replica,
}
/// Detect whether a proposal is executed within `timeout`.
///
/// # Arguments
///
/// * `ctx`         - Fondue context
/// * `governance`  - Governance canister
/// * `proposal_id` - ID of a proposal to be executed
/// * `retry_delay` - Duration between polling attempts
/// * `timeout`     - Duration after which we give up (returning false)
///
/// Eventually returns whether the proposal has been executed.
pub async fn await_proposal_execution(
    log: &Logger,
    governance: &Canister<'_>,
    proposal_id: ProposalId,
    retry_delay: Duration,
    timeout: Duration,
) -> bool {
    let mut i = 0usize;
    let start_time = std::time::Instant::now();
    loop {
        i += 1;
        info!(
            log,
            "Attempt #{} of obtaining final execution status for {:?}", i, proposal_id
        );

        let proposal_info = get_proposal_info(governance, proposal_id)
            .await
            .unwrap_or_else(|| panic!("could not obtain proposal status"));

        match ProposalStatus::try_from(proposal_info.status).unwrap() {
            ProposalStatus::Open => {
                // This proposal is still open
                info!(log, "{:?} is open...", proposal_id,)
            }
            ProposalStatus::Adopted => {
                // This proposal is adopted but not yet executed
                info!(log, "{:?} is adopted...", proposal_id,)
            }
            ProposalStatus::Executed => {
                // This proposal is already executed
                info!(log, "{:?} has been executed.", proposal_id,);
                return true;
            }
            other_status => {
                // This proposal will not be executed
                info!(
                    log,
                    "{:?} could not be adopted: {:?}", proposal_id, other_status
                );
                return false;
            }
        }

        if std::time::Instant::now()
            .duration_since(start_time)
            .gt(&timeout)
        {
            // Give up
            return false;
        } else {
            // Continue polling with delay
            sleep(retry_delay).await;
        }
    }
}

/// Obtain the status of a replica via its `endpoint`.
///
/// Eventually returns the status of the replica.
async fn get_replica_status_from_snapshot(
    endpoint: &IcNodeSnapshot,
) -> Result<ic_agent::agent::status::Status, ic_agent::AgentError> {
    match create_agent(endpoint.get_public_url().as_ref()).await {
        Ok(agent) => agent.status().await,
        Err(e) => Err(e),
    }
}

/// Obtain the software version of a replica via its `endpoint`.
///
/// Eventually returns the replica software version.
pub async fn get_software_version_from_snapshot(
    endpoint: &IcNodeSnapshot,
) -> Option<ReplicaVersion> {
    match get_replica_status_from_snapshot(endpoint).await {
        Ok(status) => status
            .impl_version
            .map(|v| ReplicaVersion::try_from(v).unwrap()),
        Err(_) => None,
    }
}

pub async fn update_xdr_per_icp(
    nns_api: &'_ Runtime,
    timestamp_seconds: u64,
    xdr_permyriad_per_icp: u64,
) -> Result<(), String> {
    let governance_canister = get_governance_canister(nns_api);
    let proposal_payload = ic_nns_common::types::UpdateIcpXdrConversionRatePayload {
        data_source: "".to_string(),
        timestamp_seconds,
        xdr_permyriad_per_icp,
        reason: None,
    };

    let proposal_id = submit_external_proposal_with_test_id(
        &governance_canister,
        NnsFunction::IcpXdrConversionRate,
        proposal_payload,
    )
    .await;

    vote_execute_proposal_assert_executed(&governance_canister, proposal_id).await;
    Ok(())
}

pub async fn set_authorized_subnetwork_list(
    nns_api: &'_ Runtime,
    who: Option<PrincipalId>,
    subnets: Vec<SubnetId>,
) -> Result<(), String> {
    let governance_canister = get_governance_canister(nns_api);
    let proposal_payload = SetAuthorizedSubnetworkListArgs { who, subnets };

    let proposal_id = submit_external_proposal_with_test_id(
        &governance_canister,
        NnsFunction::SetAuthorizedSubnetworks,
        proposal_payload,
    )
    .await;

    vote_execute_proposal_assert_executed(&governance_canister, proposal_id).await;
    Ok(())
}

pub async fn set_authorized_subnetwork_list_with_failure(
    nns_api: &'_ Runtime,
    who: Option<PrincipalId>,
    subnets: Vec<SubnetId>,
    error: String,
) {
    let governance_canister = get_governance_canister(nns_api);
    let proposal_payload = SetAuthorizedSubnetworkListArgs { who, subnets };

    let proposal_id = submit_external_proposal_with_test_id(
        &governance_canister,
        NnsFunction::SetAuthorizedSubnetworks,
        proposal_payload,
    )
    .await;

    vote_execute_proposal_assert_failed(&governance_canister, proposal_id, error).await;
}

pub async fn update_subnet_type(nns_api: &'_ Runtime, subnet_type: String) -> Result<(), String> {
    let governance_canister = get_governance_canister(nns_api);
    let proposal_payload = UpdateSubnetTypeArgs::Add(subnet_type);

    let proposal_id = submit_external_proposal_with_test_id(
        &governance_canister,
        NnsFunction::UpdateSubnetType,
        proposal_payload,
    )
    .await;

    vote_execute_proposal_assert_executed(&governance_canister, proposal_id).await;
    Ok(())
}

pub async fn change_subnet_type_assignment(
    nns_api: &'_ Runtime,
    subnet_type: String,
    subnets: Vec<SubnetId>,
) -> Result<(), String> {
    let governance_canister = get_governance_canister(nns_api);
    let proposal_payload = ChangeSubnetTypeAssignmentArgs::Add(SubnetListWithType {
        subnets,
        subnet_type,
    });

    let proposal_id = submit_external_proposal_with_test_id(
        &governance_canister,
        NnsFunction::ChangeSubnetTypeAssignment,
        proposal_payload,
    )
    .await;

    vote_execute_proposal_assert_executed(&governance_canister, proposal_id).await;
    Ok(())
}

pub async fn change_subnet_type_assignment_with_failure(
    nns_api: &'_ Runtime,
    subnet_type: String,
    subnets: Vec<SubnetId>,
    error: String,
) {
    let governance_canister = get_governance_canister(nns_api);
    let proposal_payload = ChangeSubnetTypeAssignmentArgs::Add(SubnetListWithType {
        subnets,
        subnet_type,
    });

    let proposal_id = submit_external_proposal_with_test_id(
        &governance_canister,
        NnsFunction::ChangeSubnetTypeAssignment,
        proposal_payload,
    )
    .await;

    vote_execute_proposal_assert_failed(&governance_canister, proposal_id, error).await;
}

pub async fn add_nodes_to_subnet(
    url: Url,
    subnet_id: SubnetId,
    node_ids: &[NodeId],
) -> Result<(), String> {
    let nns_api = runtime_from_url(url, REGISTRY_CANISTER_ID.into());
    let governance_canister = get_canister(&nns_api, GOVERNANCE_CANISTER_ID);
    let proposal_payload = AddNodesToSubnetPayload {
        node_ids: node_ids.to_vec(),
        subnet_id: subnet_id.get(),
    };

    let proposal_id = submit_external_update_proposal(
        &governance_canister,
        Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
        NeuronId(TEST_NEURON_1_ID),
        NnsFunction::AddNodeToSubnet,
        proposal_payload,
        String::from("Add nodes for testing"),
        "".to_string(),
    )
    .await;

    vote_and_execute_proposal(&governance_canister, proposal_id).await;
    Ok(())
}

pub async fn remove_nodes_via_endpoint(url: Url, node_ids: &[NodeId]) -> Result<(), String> {
    let nns_api = runtime_from_url(url, REGISTRY_CANISTER_ID.into());
    let governance_canister = get_canister(&nns_api, GOVERNANCE_CANISTER_ID);
    let proposal_payload = RemoveNodesFromSubnetPayload {
        node_ids: node_ids.to_vec(),
    };

    let proposal_id = submit_external_update_proposal(
        &governance_canister,
        Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
        NeuronId(TEST_NEURON_1_ID),
        NnsFunction::RemoveNodesFromSubnet,
        proposal_payload,
        String::from("Remove node for testing"),
        "".to_string(),
    )
    .await;

    vote_and_execute_proposal(&governance_canister, proposal_id).await;
    Ok(())
}

pub async fn change_subnet_membership(
    url: Url,
    subnet_id: SubnetId,
    node_ids_add: &[NodeId],
    node_ids_remove: &[NodeId],
) -> Result<(), String> {
    let nns_api = runtime_from_url(url, REGISTRY_CANISTER_ID.into());
    let governance_canister = get_canister(&nns_api, GOVERNANCE_CANISTER_ID);
    let proposal_payload = ChangeSubnetMembershipPayload {
        subnet_id: subnet_id.get(),
        node_ids_add: node_ids_add.to_vec(),
        node_ids_remove: node_ids_remove.to_vec(),
    };

    let proposal_id = submit_external_update_proposal(
        &governance_canister,
        Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
        NeuronId(TEST_NEURON_1_ID),
        NnsFunction::ChangeSubnetMembership,
        proposal_payload,
        String::from("Change subnet membership for testing"),
        "Motivation: testing".to_string(),
    )
    .await;

    vote_and_execute_proposal(&governance_canister, proposal_id).await;
    Ok(())
}

pub fn get_canister(nns_api: &'_ Runtime, canister_id: CanisterId) -> Canister<'_> {
    Canister::new(nns_api, canister_id)
}

/// Votes for and executes the proposal identified by `proposal_id`. Asserts
/// that the ProposalStatus is Executed.
pub async fn vote_execute_proposal_assert_executed(
    governance_canister: &Canister<'_>,
    proposal_id: ProposalId,
) {
    // Wait for the proposal to be accepted and executed.
    let proposal_info = vote_and_execute_proposal(governance_canister, proposal_id).await;
    assert_eq!(
        proposal_info.status(),
        ProposalStatus::Executed,
        "proposal {proposal_id} did not execute: {proposal_info:?}"
    );
}

/// Votes for and executes the proposal identified by `proposal_id`. Asserts
/// that the ProposalStatus is Failed.
///
/// It is also verified that the rejection message contains (case-insensitive)
/// expected_message_substring. This can be left empty to guarantee a match when
/// not needed.
pub async fn vote_execute_proposal_assert_failed(
    governance_canister: &Canister<'_>,
    proposal_id: ProposalId,
    expected_message_substring: impl ToString,
) {
    let expected_message_substring = expected_message_substring.to_string();
    // Wait for the proposal to be accepted and executed.
    let proposal_info = vote_and_execute_proposal(governance_canister, proposal_id).await;
    assert_eq!(proposal_info.status(), ProposalStatus::Failed);
    let reason = proposal_info.failure_reason.unwrap_or_default();
    assert!(
       reason
            .error_message
            .to_lowercase()
            .contains(expected_message_substring.to_lowercase().as_str()),
        "Rejection error for proposal {}, which is '{}', does not contain the expected substring '{}'",
        proposal_id,
        reason,
        expected_message_substring
    );
}

pub async fn vote_and_execute_proposal(
    governance_canister: &Canister<'_>,
    proposal_id: ProposalId,
) -> ProposalInfo {
    // Cast votes.
    let input = ManageNeuron {
        neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(
            ic_nns_common::pb::v1::NeuronId {
                id: TEST_NEURON_1_ID,
            },
        )),
        id: None,
        command: Some(Command::RegisterVote(RegisterVote {
            vote: Vote::Yes as i32,
            proposal: Some(ic_nns_common::pb::v1::ProposalId { id: proposal_id.0 }),
        })),
    };
    let _result: ManageNeuronResponse = governance_canister
        .update_from_sender(
            "manage_neuron",
            candid_one,
            input,
            &Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
        )
        .await
        .expect("Vote failed");
    wait_for_final_state(governance_canister, proposal_id).await
}

pub fn get_governance_canister(nns_api: &'_ Runtime) -> Canister<'_> {
    get_canister(nns_api, GOVERNANCE_CANISTER_ID)
}

pub fn get_sns_wasm_canister(nns_api: &'_ Runtime) -> Canister<'_> {
    get_canister(nns_api, SNS_WASM_CANISTER_ID)
}

pub async fn submit_external_proposal_with_test_id<T: CandidType>(
    governance_canister: &Canister<'_>,
    nns_function: NnsFunction,
    payload: T,
) -> ProposalId {
    let sender = Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR);
    let neuron_id = NeuronId(TEST_NEURON_1_ID);
    submit_external_update_proposal(
        governance_canister,
        sender,
        neuron_id,
        nns_function,
        payload,
        "<proposal created by submit_external_proposal_with_test_id>".to_string(),
        "".to_string(),
    )
    .await
}

/// Submits a proposal for electing or unelecting a replica software versions.
///
/// # Arguments
///
/// * `governance`          - Governance canister
/// * `sender`              - Sender of the proposal
/// * `neuron_id`           - ID of the proposing neuron. This neuron
///   will automatically vote in favor of the proposal.
/// * `version`             - Replica software version to elect
/// * `sha256`              - Claimed SHA256 of the replica image file
/// * `upgrade_urls`        - URLs leading to the replica image file
/// * `versions_to_unelect` - Replica versions to remove from registry
///
/// Note: The existing replica *may or may not* check that the
/// provided `sha256` corresponds to the image checksum. In case
/// this proposal is adopted, the replica *assumes* that the file
/// under `upgrade_url` has the provided `sha256`. If there has
/// been a mismatch (or if the image has been forged after election),
/// the replica will reject the follow-up proposal for updating the
/// replica version.
///
/// Eventually returns the identifier of the newly submitted proposal.
pub async fn submit_update_elected_replica_versions_proposal(
    governance: &Canister<'_>,
    sender: Sender,
    neuron_id: NeuronId,
    version: Option<ReplicaVersion>,
    sha256: Option<String>,
    upgrade_urls: Vec<String>,
    versions_to_unelect: Vec<String>,
) -> ProposalId {
    submit_external_update_proposal_allowing_error(
        governance,
        sender,
        neuron_id,
        NnsFunction::ReviseElectedGuestosVersions,
        ReviseElectedGuestosVersionsPayload {
            replica_version_to_elect: version.clone().map(String::from),
            release_package_sha256_hex: sha256.clone(),
            release_package_urls: upgrade_urls,
            replica_versions_to_unelect: versions_to_unelect.clone(),
            guest_launch_measurement_sha256_hex: None,
        },
        match (version, sha256, versions_to_unelect.is_empty()) {
            (Some(v), Some(sha), _) => format!(
                "Elect replica version: {} with hash: {}",
                String::from(v),
                sha
            ),
            (None, None, false) => format!(
                "Retiring versions: {}",
                versions_to_unelect.iter().join(", ")
            ),
            _ => panic!("Not valid arguments provided for submitting update elected replica version proposal")
        },
        "".to_string(),
    )
    .await
    .expect("submit_update_elected_replica_versions_proposal failed")
}

/// Submits a proposal for updating a subnet replica software version.
///
/// # Arguments
///
/// * `governance`  - Governance canister
/// * `sender`      - Sender of the proposal
/// * `neuron_id`   - ID of the proposing neuron. This neuron will automatically
///   vote in favor of the proposal.
/// * `version`     - Replica software version
/// * `subnet_id`   - ID of the subnet to be updated
///
/// Note: The existing replica *must* check that the new replica image
/// has the expected SHA256. If there is a mismatch, then this proposal
/// must eventually fail.
///
/// Eventually returns the identifier of the newly submitted proposal.
pub async fn submit_deploy_guestos_to_all_subnet_nodes_proposal(
    governance: &Canister<'_>,
    sender: Sender,
    neuron_id: NeuronId,
    version: ReplicaVersion,
    subnet_id: SubnetId,
) -> ProposalId {
    submit_external_update_proposal_allowing_error(
        governance,
        sender,
        neuron_id,
        NnsFunction::DeployGuestosToAllSubnetNodes,
        DeployGuestosToAllSubnetNodesPayload {
            subnet_id: subnet_id.get(),
            replica_version_id: String::from(version.clone()),
        },
        format!(
            "Update {} subnet's replica version to: {}",
            subnet_id,
            String::from(version)
        ),
        "".to_string(),
    )
    .await
    .expect("submit_deploy_guestos_to_all_subnet_nodes_proposal failed")
}

/// Submits a proposal for creating an application subnet.
///
/// # Arguments
///
/// * `governance`      - Governance canister
/// * `node_ids`        - IDs of (currently, unassigned) nodes that should join
///   the new subnet
/// * `replica_version` - Replica software version to install to the new subnet
///   nodes (see `get_software_version`)
///
/// Eventually returns the identifier of the newly submitted proposal.
pub async fn submit_create_application_subnet_proposal(
    governance: &Canister<'_>,
    node_ids: Vec<NodeId>,
    replica_version: ReplicaVersion,
) -> ProposalId {
    let config =
        subnet_configuration::get_default_config_params(SubnetType::Application, node_ids.len());
    let payload = CreateSubnetPayload {
        node_ids,
        subnet_id_override: None,
        max_ingress_bytes_per_message: config.max_ingress_bytes_per_message,
        max_ingress_messages_per_block: config.max_ingress_messages_per_block,
        max_block_payload_size: config.max_block_payload_size,
        replica_version_id: replica_version.to_string(),
        unit_delay_millis: duration_to_millis(config.unit_delay),
        initial_notary_delay_millis: duration_to_millis(config.initial_notary_delay),
        dkg_interval_length: config.dkg_interval_length.get(),
        dkg_dealings_per_block: config.dkg_dealings_per_block as u64,
        start_as_nns: false,
        subnet_type: SubnetType::Application,
        is_halted: false,
        features: Default::default(),
        max_number_of_canisters: 4,
        ssh_readonly_access: vec![],
        ssh_backup_access: vec![],
        ecdsa_config: None,
        chain_key_config: None,
        // Unused section follows
        ingress_bytes_per_block_soft_cap: Default::default(),
        gossip_max_artifact_streams_per_peer: Default::default(),
        gossip_max_chunk_wait_ms: Default::default(),
        gossip_max_duplicity: Default::default(),
        gossip_max_chunk_size: Default::default(),
        gossip_receive_check_cache_size: Default::default(),
        gossip_pfn_evaluation_period_ms: Default::default(),
        gossip_registry_poll_period_ms: Default::default(),
        gossip_retransmission_request_ms: Default::default(),
    };

    submit_external_proposal_with_test_id(governance, NnsFunction::CreateSubnet, payload).await
}

// Queries the registry for the subnet_list record, awaits, decodes, and returns
// the response.
pub async fn get_subnet_list_from_registry(client: &RegistryCanister) -> Vec<SubnetId> {
    let (original_subnets_enc, _) = client
        .get_value(make_subnet_list_record_key().as_bytes().to_vec(), None)
        .await
        .expect("failed to get value for subnet list");

    deserialize_registry_value::<SubnetListRecord>(Ok(Some(original_subnets_enc)))
        .expect("could not decode subnet list record")
        .unwrap()
        .subnets
        .iter()
        .map(|s| SubnetId::from(PrincipalId::try_from(s.clone().as_slice()).unwrap()))
        .collect::<Vec<SubnetId>>()
}

/// Submits a proposal for updating replica software version of unassigned
/// nodes.
///
/// # Arguments
///
/// * `governance`          - Governance canister
/// * `sender`              - Sender of the proposal
/// * `neuron_id`           - ID of the proposing neuron. This neuron will
///   automatically vote in favor of the proposal.
/// * `version`             - Replica software version
/// * `readonly_public_key` - Public key of ssh credentials for readonly access
///   to the node.
///
/// Eventually returns the identifier of the newly submitted proposal.
pub async fn submit_update_unassigned_node_version_proposal(
    governance: &Canister<'_>,
    sender: Sender,
    neuron_id: NeuronId,
    version: String,
) -> ProposalId {
    submit_external_update_proposal_allowing_error(
        governance,
        sender,
        neuron_id,
        NnsFunction::DeployGuestosToAllUnassignedNodes,
        DeployGuestosToAllUnassignedNodesPayload {
            elected_replica_version: version.clone(),
        },
        format!("Update unassigned nodes version to: {}", version.clone()),
        "".to_string(),
    )
    .await
    .expect("submit_update_unassigned_node_version_proposal failed")
}

/// Submits a proposal for electing or unelecting HostOS versions.
///
/// # Arguments
///
/// * `governance`          - Governance canister
/// * `sender`              - Sender of the proposal
/// * `neuron_id`           - ID of the proposing neuron. This neuron
///   will automatically vote in favor of the proposal.
/// * `version`             - HostOS software version to elect
/// * `sha256`              - Claimed SHA256 of the HostOS image file
/// * `upgrade_urls`        - URLs leading to the HostOS image file
/// * `versions_to_unelect` - HostOS versions to remove from registry
///
/// Eventually returns the identifier of the newly submitted proposal.
pub async fn submit_update_elected_hostos_versions_proposal(
    governance: &Canister<'_>,
    sender: Sender,
    neuron_id: NeuronId,
    version: &HostosVersion,
    sha256: String,
    upgrade_urls: Vec<String>,
    versions_to_unelect: Vec<String>,
) -> ProposalId {
    submit_external_update_proposal_allowing_error(
        governance,
        sender,
        neuron_id,
        NnsFunction::ReviseElectedHostosVersions,
        ReviseElectedHostosVersionsPayload {
            hostos_version_to_elect: Some(String::from(version)),
            release_package_sha256_hex: Some(sha256.clone()),
            release_package_urls: upgrade_urls,
            hostos_versions_to_unelect: versions_to_unelect,
        },
        format!(
            "Elect HostOS version: '{}' with hash: '{}'",
            String::from(version),
            sha256
        ),
        "".to_string(),
    )
    .await
    .expect("submit_update_elected_hostos_versions_proposal failed")
}

/// Submits a proposal for updating nodes to a HostOS version.
///
/// # Arguments
///
/// * `governance`  - Governance canister
/// * `sender`      - Sender of the proposal
/// * `neuron_id`   - ID of the proposing neuron. This neuron will automatically
///   vote in favor of the proposal.
/// * `version`     - HostOS software version
/// * `node_ids`   - List of Node ID to be updated
///
/// Eventually returns the identifier of the newly submitted proposal.
pub async fn submit_update_nodes_hostos_version_proposal(
    governance: &Canister<'_>,
    sender: Sender,
    neuron_id: NeuronId,
    version: HostosVersion,
    node_ids: Vec<NodeId>,
) -> ProposalId {
    submit_external_update_proposal_allowing_error(
        governance,
        sender,
        neuron_id,
        NnsFunction::DeployHostosToSomeNodes,
        DeployHostosToSomeNodes {
            node_ids: node_ids.clone(),
            hostos_version_id: Some(String::from(version.clone())),
        },
        format!(
            "Update nodes '{:#?}' to HostOS version '{}'",
            node_ids,
            String::from(version)
        ),
        "".to_string(),
    )
    .await
    .expect("submit_update_nodes_hostos_version_proposal failed")
}
