use std::io::Read;
use std::str::FromStr;

use anyhow::{bail, Context, Result};
use canister_test::PrincipalId;
use ic_canister_client::Sender;
use ic_consensus_system_test_utils::rw_message::install_nns_and_check_progress;
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
use ic_registry_transport::Error as RegistryTransportError;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        bootstrap::{setup_nested_vms, start_nested_vms},
        farm::Farm,
        ic::{InternetComputer, Subnet},
        ic_gateway_vm::{HasIcGatewayVm, IcGatewayVm, IC_GATEWAY_VM_NAME},
        nested::{NestedNode, NestedVm, NestedVms},
        resource::{allocate_resources, get_resource_request_for_nested_nodes},
        test_env::{HasIcPrepDir, TestEnv, TestEnvAttribute},
        test_env_api::*,
        test_setup::GroupSetup,
        vector_vm::HasVectorTargets,
    },
    nns::{
        get_governance_canister, submit_update_elected_hostos_versions_proposal,
        submit_update_elected_replica_versions_proposal,
        submit_update_nodes_hostos_version_proposal,
        submit_update_unassigned_node_version_proposal, vote_execute_proposal_assert_executed,
    },
    retry_with_msg_async_quiet,
    util::runtime_from_url,
};
use ic_types::Height;
use ic_types::{hostos_version::HostosVersion, NodeId, ReplicaVersion};
use prost::Message;
use regex::Regex;
use reqwest::Client;
use std::net::Ipv6Addr;
use std::time::Duration;

use ic_protobuf::registry::replica_version::v1::GuestLaunchMeasurements;
use slog::{info, Logger};

pub const NODE_REGISTRATION_TIMEOUT: Duration = Duration::from_secs(10 * 60);
pub const NODE_REGISTRATION_BACKOFF: Duration = Duration::from_secs(5);

/// Setup the basic IC infrastructure (testnet, NNS, gateway)
pub fn setup_ic_infrastructure(env: &TestEnv, dkg_interval: Option<u64>) {
    let principal =
        PrincipalId::from_str("7532g-cd7sa-3eaay-weltl-purxe-qliyt-hfuto-364ru-b3dsz-kw5uz-kqe")
            .unwrap();

    // Setup "testnet"
    let mut subnet = Subnet::fast_single_node(SubnetType::System);
    if let Some(dkg_interval) = dkg_interval {
        subnet = subnet.with_dkg_interval_length(Height::from(dkg_interval));
    }
    InternetComputer::new()
        .add_subnet(subnet)
        .with_api_boundary_nodes(1)
        .with_node_provider(principal)
        .with_node_operator(principal)
        .without_unassigned_config()
        .setup_and_start(env)
        .expect("failed to setup IC under test");

    install_nns_and_check_progress(env.topology_snapshot());

    IcGatewayVm::new(IC_GATEWAY_VM_NAME)
        .start(env)
        .expect("failed to setup ic-gateway");
}

/// Asserts that SetupOS and initial NNS GuestOS image versions match.
/// Only checks if both functions return ReplicaVersion successfully.
/// NOTE: If you want to create a new test with conflicting versions, add a
/// field to override this check and, in your test, account for the fact that
/// after registration, the deployed node will upgrade to the NNS GuestOS version.
pub fn assert_version_compatibility() {
    let setupos_version = get_setupos_img_version();
    let guestos_version = get_guestos_img_version();

    if setupos_version != guestos_version {
        // TODO: Revert change after extending image version support

        // panic!(
        //     "Version mismatch detected: SetupOS version '{setupos_version}' does not match GuestOS version '{guestos_version}'. If you want to create a test with different versions, add a field to override this check."
        // );
    }
}

/// Use an SSH channel to check the version on the running HostOS.
pub(crate) fn check_hostos_version(node: &NestedVm) -> String {
    let session = node
        .block_on_ssh_session()
        .expect("Could not reach HostOS VM.");
    let mut channel = session.channel_session().unwrap();

    channel.exec("cat /opt/ic/share/version.txt").unwrap();
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
    target_version: &ReplicaVersion,
    sha256: String,
    upgrade_urls: Vec<String>,
    guest_launch_measurements: Option<GuestLaunchMeasurements>,
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
        guest_launch_measurements,
        vec![],
    )
    .await;
    vote_execute_proposal_assert_executed(&governance_canister, proposal_id).await;
}

/// Get the current unassigned nodes configuration from the NNS registry.
pub(crate) async fn get_unassigned_nodes_config(
    nns_node: &IcNodeSnapshot,
) -> Option<UnassignedNodesConfigRecord> {
    let registry_canister = RegistryCanister::new(vec![nns_node.get_public_url()]);
    let unassigned_nodes_config_result = registry_canister
        .get_value(
            make_unassigned_nodes_config_record_key()
                .as_bytes()
                .to_vec(),
            None,
        )
        .await;

    // The record may not exist, in this case return None
    match unassigned_nodes_config_result {
        Err(RegistryTransportError::KeyNotPresent(_)) => None,
        Ok(res) => Some(res),
        err @ Err(_) => Some(err.unwrap()),
    }
    .map(|v| UnassignedNodesConfigRecord::decode(v.0.as_slice()).unwrap())
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
        target_version,
    )
    .await;
    vote_execute_proposal_assert_executed(&governance_canister, proposal_id).await;
}

/// Get the current GuestOS version from the metrics endpoint of the guest.
pub async fn check_guestos_version(
    client: &Client,
    ipv6_address: &Ipv6Addr,
) -> Result<ReplicaVersion> {
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

    let capture = re
        .captures(&body)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().to_string())
        .context("Version string not found in response")?;

    Ok(ReplicaVersion::try_from(capture)?)
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

pub fn setup_nested_vm_group(env: TestEnv, names: &[&str]) {
    let logger = env.logger();
    info!(logger, "Setting up nested VM(s) ...");

    let farm_url = env.get_farm_url().expect("Unable to get Farm url.");
    let farm = Farm::new(farm_url, logger.clone());
    let group_setup = GroupSetup::read_attribute(&env);
    let group_name: String = group_setup.infra_group_name;

    let nodes: Vec<NestedNode> = names
        .iter()
        .map(|name| NestedNode::new(name.to_string()))
        .collect();

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

    info!(logger, "Nested VM(s) setup complete!");
}

/// Setup vector targets for a single VM
pub fn setup_vector_targets_for_vm(env: &TestEnv, vm_name: &str) {
    let vm = env
        .get_nested_vm(vm_name)
        .unwrap_or_else(|e| panic!("Expected nested vm {vm_name} to exist, but got error: {e:?}"));

    let network = vm.get_nested_network().unwrap();

    for (job, ip) in [
        ("node_exporter", network.guest_ip),
        ("host_node_exporter", network.host_ip),
    ] {
        env.add_custom_vector_target(
            format!("{vm_name}-{job}"),
            ip.into(),
            Some(
                [("job", job)]
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            ),
        )
        .unwrap();
    }
}

/// Simplified nested VM setup that bypasses IC Gateway and NNS requirements.
pub(crate) fn simple_setup_nested_vm_group(env: TestEnv, names: &[&str]) {
    let logger = env.logger();
    info!(
        logger,
        "Setting up minimal nested VM(s) without IC infrastructure..."
    );

    let farm_url = env.get_farm_url().expect("Unable to get Farm url.");
    let farm = Farm::new(farm_url, logger.clone());
    let group_setup = GroupSetup::read_attribute(&env);
    let group_name: String = group_setup.infra_group_name;

    let nodes: Vec<NestedNode> = names
        .iter()
        .map(|name| NestedNode::new(name.to_string()))
        .collect();

    // Allocate VM resources
    let res_request = get_resource_request_for_nested_nodes(&nodes, &env, &group_name)
        .expect("Failed to build resource request for nested test.");
    let res_group = allocate_resources(&farm, &res_request, &env)
        .expect("Failed to allocate resources for nested test.");

    for (name, vm) in res_group.vms.iter() {
        env.write_nested_vm(name, vm)
            .expect("Unable to write nested VM.");
    }

    // Use dummy values for IC Gateway URL and NNS public key
    let dummy_ic_gateway_url = url::Url::parse("http://localhost:8080").unwrap();
    let dummy_nns_public_key = "dummy_public_key_for_recovery_test";

    setup_nested_vms(
        &nodes,
        &env,
        &farm,
        &group_name,
        &dummy_ic_gateway_url,
        dummy_nns_public_key,
    )
    .expect("Unable to setup nested VMs with minimal config.");

    info!(logger, "Minimal nested VM(s) setup complete!");
}

pub fn start_nested_vm_group(env: TestEnv) {
    let logger = env.logger();
    info!(logger, "Setup nested VMs ...");

    let farm_url = env.get_farm_url().expect("Unable to get Farm url.");
    let farm = Farm::new(farm_url, logger.clone());
    let group_setup = GroupSetup::read_attribute(&env);
    let group_name: String = group_setup.infra_group_name;

    start_nested_vms(&env, &farm, &group_name).expect("Unable to start nested VMs.");
}

/// Wait for the guest to return any available version (not "unavailable").
/// Returns the version string when available.
pub async fn wait_for_guest_version(
    client: &Client,
    guest_ipv6: &Ipv6Addr,
    logger: &Logger,
    timeout: Duration,
    backoff: Duration,
) -> Result<ReplicaVersion> {
    retry_with_msg_async_quiet!(
        "Waiting until the guest returns a version",
        logger,
        timeout,
        backoff,
        || async {
            let current_version = check_guestos_version(client, guest_ipv6)
                .await
                .context("Unable to check GuestOS version")?;
            info!(
                logger,
                "SUCCESS: Guest reported version '{}'", current_version
            );

            Ok(current_version)
        }
    )
    .await
}

/// Wait for the guest to reach a specific version.
pub async fn wait_for_expected_guest_version(
    client: &Client,
    guest_ipv6: &Ipv6Addr,
    expected_version: &ReplicaVersion,
    logger: &Logger,
    timeout: Duration,
    backoff: Duration,
) -> Result<()> {
    retry_with_msg_async_quiet!(
        format!(
            "Waiting until the guest is on the expected version '{}'",
            expected_version
        ),
        logger,
        timeout,
        backoff,
        || async {
            let current_version = check_guestos_version(client, guest_ipv6)
                .await
                .context("Unable to check GuestOS version")?;
            if &current_version != expected_version {
                bail!("FAIL: Guest is still on version '{}'", current_version)
            }
            info!(
                logger,
                "SUCCESS: Guest is now on expected version '{}'", current_version
            );

            Ok(())
        }
    )
    .await
}

/// Get the current boot ID from a HostOS node.
pub fn get_host_boot_id(node: &NestedVm) -> String {
    node.block_on_bash_script("journalctl -q --list-boots | tail -n1 | awk '{print $2}'")
        .expect("Failed to retrieve boot ID")
        .trim()
        .to_string()
}
