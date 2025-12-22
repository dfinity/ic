use std::io::Read;
use std::str::FromStr;

use anyhow::{Context, Result, bail};
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
use ic_registry_subnet_type::SubnetType;
use ic_registry_transport::Error as RegistryTransportError;
use ic_system_test_driver::{
    driver::{
        ic::{InternetComputer, Subnet},
        ic_gateway_vm::{IC_GATEWAY_VM_NAME, IcGatewayVm},
        nested::NestedVm,
        test_env::TestEnv,
        test_env_api::*,
    },
    nns::{
        get_governance_canister, submit_update_elected_hostos_versions_proposal,
        submit_update_elected_replica_versions_proposal,
        submit_update_nodes_hostos_version_proposal,
        submit_update_unassigned_node_version_proposal, vote_execute_proposal_assert_executed,
    },
    retry_with_msg_async_quiet,
    util::{block_on, runtime_from_url},
};
use ic_types::{Height, NodeId, ReplicaVersion, hostos_version::HostosVersion};
use prost::Message;
use regex_lite::Regex;
use reqwest::Client;
use std::net::Ipv6Addr;
use std::time::Duration;

use ic_protobuf::registry::replica_version::v1::GuestLaunchMeasurements;
use slog::{Logger, info, warn};

pub const NODE_REGISTRATION_TIMEOUT: Duration = Duration::from_secs(10 * 60);
pub const NODE_REGISTRATION_BACKOFF: Duration = Duration::from_secs(5);

pub const NODE_UPGRADE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
pub const NODE_UPGRADE_BACKOFF: Duration = Duration::from_secs(5);

/// Setup the basic IC infrastructure (testnet, NNS, gateway)
pub fn setup_ic_infrastructure(env: &TestEnv, dkg_interval: Option<u64>, is_fast: bool) {
    let principal =
        PrincipalId::from_str("7532g-cd7sa-3eaay-weltl-purxe-qliyt-hfuto-364ru-b3dsz-kw5uz-kqe")
            .unwrap();

    // Setup "testnet"
    let mut subnet = if is_fast {
        Subnet::fast(SubnetType::System, 1)
    } else {
        Subnet::new(SubnetType::System).add_nodes(1)
    };
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
        .disable_ipv4()
        .start(env)
        .expect("failed to setup ic-gateway");
}

/// Use an SSH channel to check the version on the running HostOS.
pub fn check_hostos_version(node: &NestedVm) -> String {
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
pub async fn elect_guestos_version(
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
pub async fn get_unassigned_nodes_config(
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
pub async fn get_blessed_guestos_versions(nns_node: &IcNodeSnapshot) -> BlessedReplicaVersions {
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
pub async fn update_unassigned_nodes(nns_node: &IcNodeSnapshot, target_version: &ReplicaVersion) {
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
pub async fn elect_hostos_version(
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
pub async fn update_nodes_hostos_version(
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
    block_on(get_host_boot_id_async(node))
}

/// Get the current boot ID from a HostOS node. Asynchronous version
pub async fn get_host_boot_id_async(node: &NestedVm) -> String {
    node.block_on_bash_script_async("journalctl -q --list-boots | tail -n1 | awk '{print $2}'")
        .await
        .expect("Failed to retrieve boot ID")
        .trim()
        .to_string()
}

/// Execute a bash script on a node via SSH and log the output.
pub fn block_on_bash_script_and_log<N: SshSession>(log: &Logger, node: &N, cmd: &str) {
    match node.block_on_bash_script(cmd) {
        Ok(out) => info!(log, "{cmd}:\n{out}"),
        Err(err) => warn!(log, "Failed to execute '{cmd}': {:?}", err),
    }
}

/// Logs guestos diagnostics, used in the event of test failure
pub fn try_logging_guestos_diagnostics(host: &NestedVm, logger: &Logger) {
    info!(logger, "Logging GuestOS diagnostics...");

    /// 10-second timeout prevents excessive logging when SSH is unavailable.
    const SSH_TIMEOUT: Duration = Duration::from_secs(10);

    let execute_and_log = |node: &dyn SshSession, cmd: &str| match node
        .block_on_ssh_session_with_timeout(SSH_TIMEOUT)
        .and_then(|session| node.block_on_bash_script_from_session(&session, cmd))
    {
        Ok(out) => info!(logger, "{cmd}:\n{out}"),
        Err(err) => warn!(logger, "Failed to execute '{cmd}': {:?}", err),
    };

    info!(logger, "GuestOS console logs...");
    execute_and_log(
        host,
        "sudo tail -n 200 /var/log/libvirt/qemu/guestos-serial.log",
    );

    match host.get_guest_ssh() {
        Ok(guest) => {
            let diagnostics = vec![
                "systemctl --failed --no-pager || true",
                "journalctl -b --no-pager -u systemd-remount-fs.service || true",
                "mount | sort",
                "journalctl -b --no-pager -p warning | tail -n 200",
                "set -o pipefail; dmesg --color=never | grep -iE 'mount|ext4|xfs|btrfs|nvme|sda|i/o error|failed' | tail -n 200 || true",
            ];

            for cmd in diagnostics {
                execute_and_log(&guest, cmd);
            }
        }
        Err(err) => {
            info!(
                logger,
                "Unable to establish GuestOS SSH session for diagnostics: {:?}", err
            );
        }
    }
}
