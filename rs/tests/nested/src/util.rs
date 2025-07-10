use std::io::Read;

use anyhow::{Context, Result};
use ic_canister_client::Sender;
use ic_nervous_system_common_test_keys::{TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_KEYPAIR};
use ic_nns_common::types::NeuronId;
use ic_protobuf::registry::{
    replica_version::v1::BlessedReplicaVersions,
    unassigned_nodes_config::v1::UnassignedNodesConfigRecord,
};
use ic_registry_keys::{
    make_blessed_replica_versions_key, make_unassigned_nodes_config_record_key,
};
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_system_test_driver::{
    driver::{
        bootstrap::{setup_nested_vms, start_nested_vms},
        farm::Farm,
        ic_gateway_vm::{HasIcGatewayVm, IC_GATEWAY_VM_NAME},
        nested::{NestedNode, NestedVm, NestedVms},
        resource::{allocate_resources, get_resource_request_for_nested_nodes},
        test_env::{HasIcPrepDir, TestEnv, TestEnvAttribute},
        test_env_api::*,
        test_setup::GroupSetup,
    },
    nns::{
        get_governance_canister, submit_update_elected_hostos_versions_proposal,
        submit_update_elected_replica_versions_proposal,
        submit_update_nodes_hostos_version_proposal,
        submit_update_unassigned_node_version_proposal, vote_execute_proposal_assert_executed,
    },
    util::runtime_from_url,
};
use ic_types::{hostos_version::HostosVersion, NodeId, ReplicaVersion};
use prost::Message;
use regex::Regex;
use reqwest::Client;
use std::net::Ipv6Addr;

use slog::info;

/// Use an SSH channel to check the version on the running HostOS.
pub(crate) fn check_hostos_version(node: &NestedVm) -> String {
    let session = node
        .block_on_ssh_session()
        .expect("Could not reach HostOS VM.");
    let mut channel = session.channel_session().unwrap();

    channel.exec("cat /boot/version.txt").unwrap();
    let mut s = String::new();
    channel.read_to_string(&mut s).unwrap();
    channel.close().ok();
    channel.wait_close().ok();

    assert!(
        channel.exit_status().unwrap() == 0,
        "Checking version failed."
    );

    s.trim().to_string()
}

/// Submit a proposal to elect a new GuestOS version
pub(crate) async fn elect_guestos_version(
    nns_node: &IcNodeSnapshot,
    target_version: ReplicaVersion,
    sha256: String,
    upgrade_urls: Vec<String>,
) {
    let nns = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance_canister = get_governance_canister(&nns);
    let test_neuron_id = NeuronId(TEST_NEURON_1_ID);
    let proposal_sender = Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR);

    let proposal_id = submit_update_elected_replica_versions_proposal(
        &governance_canister,
        proposal_sender.clone(),
        test_neuron_id,
        Some(target_version),
        Some(sha256),
        upgrade_urls,
        vec![],
    )
    .await;
    vote_execute_proposal_assert_executed(&governance_canister, proposal_id).await;
}

/// Get the current unassigned nodes configuration from the NNS registry.
pub(crate) async fn get_unassigned_nodes_config(
    nns_node: &IcNodeSnapshot,
) -> UnassignedNodesConfigRecord {
    let registry_canister = RegistryCanister::new(vec![nns_node.get_public_url()]);
    let unassigned_nodes_config_result = registry_canister
        .get_value(
            make_unassigned_nodes_config_record_key()
                .as_bytes()
                .to_vec(),
            None,
        )
        .await
        .unwrap();
    UnassignedNodesConfigRecord::decode(&*unassigned_nodes_config_result.0).unwrap()
}

/// Get the blessed guestOS version from the NNS registry.
pub(crate) async fn get_blessed_guestos_versions(
    nns_node: &IcNodeSnapshot,
) -> BlessedReplicaVersions {
    let registry_canister = RegistryCanister::new(vec![nns_node.get_public_url()]);
    let blessed_vers_result = registry_canister
        .get_value(
            make_blessed_replica_versions_key().as_bytes().to_vec(),
            None,
        )
        .await
        .unwrap();
    BlessedReplicaVersions::decode(&*blessed_vers_result.0).unwrap()
}

/// Get the blessed guestOS version from the NNS registry.
pub(crate) async fn update_unassigned_nodes(
    nns_node: &IcNodeSnapshot,
    target_version: &ReplicaVersion,
) {
    let nns = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance_canister = get_governance_canister(&nns);
    let test_neuron_id = NeuronId(TEST_NEURON_1_ID);
    let proposal_sender = Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR);
    let proposal_id = submit_update_unassigned_node_version_proposal(
        &governance_canister,
        proposal_sender,
        test_neuron_id,
        target_version.to_string(),
    )
    .await;
    vote_execute_proposal_assert_executed(&governance_canister, proposal_id).await;
}

/// Get the current GuestOS version from the metrics endpoint of the guest.
pub async fn check_guestos_version(client: &Client, ipv6_address: &Ipv6Addr) -> Result<String> {
    let url = format!("https://[{ipv6_address}]:9100/metrics");

    let response = client
        .get(&url)
        .send()
        .await
        .context("Failed to send HTTP request")?;

    let body = response
        .text()
        .await
        .context("Failed to read response body")?;

    let re =
        Regex::new(r#"guestos_version\{version="([^"]+)""#).context("Failed to compile regex")?;

    re.captures(&body)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().to_string())
        .context("Version string not found in response")
}

/// Submit a proposal to elect a new HostOS version
pub(crate) async fn elect_hostos_version(
    nns_node: &IcNodeSnapshot,
    target_version: &HostosVersion,
    sha256: &str,
    upgrade_urls: Vec<String>,
) {
    let nns = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance_canister = get_governance_canister(&nns);
    let test_neuron_id = NeuronId(TEST_NEURON_1_ID);
    let proposal_sender = Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR);

    let proposal_id = submit_update_elected_hostos_versions_proposal(
        &governance_canister,
        proposal_sender.clone(),
        test_neuron_id,
        target_version,
        sha256.to_string(),
        upgrade_urls,
        vec![],
    )
    .await;
    vote_execute_proposal_assert_executed(&governance_canister, proposal_id).await;
}

/// Submit a proposal to update the HostOS version on a node
pub(crate) async fn update_nodes_hostos_version(
    nns_node: &IcNodeSnapshot,
    new_hostos_version: &HostosVersion,
    node_ids: Vec<NodeId>,
) {
    let nns = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance_canister = get_governance_canister(&nns);
    let test_neuron_id = NeuronId(TEST_NEURON_1_ID);
    let proposal_sender = Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR);

    let proposal_id = submit_update_nodes_hostos_version_proposal(
        &governance_canister,
        proposal_sender.clone(),
        test_neuron_id,
        new_hostos_version.clone(),
        node_ids,
    )
    .await;
    vote_execute_proposal_assert_executed(&governance_canister, proposal_id).await;
}

pub(crate) fn setup_nested_vm(env: TestEnv, name: &str) {
    let logger = env.logger();
    info!(logger, "Setup nested VMs ...");

    let farm_url = env.get_farm_url().expect("Unable to get Farm url.");
    let farm = Farm::new(farm_url, logger.clone());
    let group_setup = GroupSetup::read_attribute(&env);
    let group_name: String = group_setup.infra_group_name;

    let nodes = vec![NestedNode::new(name.to_owned())];

    let res_request = get_resource_request_for_nested_nodes(&nodes, &env, &group_name)
        .expect("Failed to build resource request for nested test.");
    let res_group = allocate_resources(&farm, &res_request, &env)
        .expect("Failed to allocate resources for nested test.");

    for (name, vm) in res_group.vms.iter() {
        env.write_nested_vm(name, vm)
            .expect("Unable to write nested VM.");
    }

    let ic_gateway = env
        .get_deployed_ic_gateway(IC_GATEWAY_VM_NAME)
        .expect("No HTTP gateway found");
    let ic_gateway_url = ic_gateway.get_public_url();

    let nns_public_key =
        std::fs::read_to_string(env.prep_dir("").unwrap().root_public_key_path()).unwrap();

    setup_nested_vms(
        &nodes,
        &env,
        &farm,
        &group_name,
        &ic_gateway_url,
        &nns_public_key,
    )
    .expect("Unable to setup nested VMs.");
}

pub(crate) fn start_nested_vm(env: TestEnv) {
    let logger = env.logger();
    info!(logger, "Setup nested VMs ...");

    let farm_url = env.get_farm_url().expect("Unable to get Farm url.");
    let farm = Farm::new(farm_url, logger.clone());
    let group_setup = GroupSetup::read_attribute(&env);
    let group_name: String = group_setup.infra_group_name;

    start_nested_vms(&env, &farm, &group_name).expect("Unable to start nested VMs.");
}
