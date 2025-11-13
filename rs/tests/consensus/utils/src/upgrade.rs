use anyhow::{Result, bail};
use ic_canister_client::Sender;
use ic_nervous_system_common_test_keys::{TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_KEYPAIR};
use ic_nns_common::types::NeuronId;
use ic_protobuf::registry::replica_version::v1::{BlessedReplicaVersions, GuestLaunchMeasurements};
use ic_registry_keys::make_blessed_replica_versions_key;
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_system_test_driver::{
    driver::test_env_api::*,
    nns::{
        get_governance_canister, submit_deploy_guestos_to_all_subnet_nodes_proposal,
        submit_update_elected_replica_versions_proposal, vote_execute_proposal_assert_executed,
    },
    util::runtime_from_url,
};
use ic_types::{ReplicaVersion, SubnetId, messages::ReplicaHealthStatus};
use prost::Message;
use slog::{Logger, info};
use std::{convert::TryFrom, io::Read, path::Path};

pub async fn get_blessed_replica_versions(
    registry_canister: &RegistryCanister,
) -> BlessedReplicaVersions {
    let blessed_vers_result = registry_canister
        .get_value(
            make_blessed_replica_versions_key().as_bytes().to_vec(),
            None,
        )
        .await
        .unwrap();
    BlessedReplicaVersions::decode(&*blessed_vers_result.0).unwrap()
}

/// Reads the replica version from an unassigned node.
pub fn fetch_unassigned_node_version(endpoint: &IcNodeSnapshot) -> Result<ReplicaVersion> {
    let sess = endpoint.block_on_ssh_session()?;
    let version_file = Path::new("/opt/ic/share/version.txt");
    let mut chan = sess.scp_recv(version_file)?.0;
    let mut version = String::new();
    chan.read_to_string(&mut version)?;
    version.retain(|c| !c.is_whitespace());

    Ok(ReplicaVersion::try_from(version)?)
}

pub fn assert_assigned_replica_version(
    node: &IcNodeSnapshot,
    expected_version: &ReplicaVersion,
    logger: Logger,
) {
    assert_assigned_replica_version_with_time(node, expected_version, logger, 600, 10)
}

/// Waits until the node is healthy and running the given replica version.
/// Panics if the timeout is reached while waiting.
pub fn assert_assigned_replica_version_with_time(
    node: &IcNodeSnapshot,
    expected_version: &ReplicaVersion,
    logger: Logger,
    total_secs: u64,
    backoff_secs: u64,
) {
    info!(
        logger,
        "Waiting until the node {} is healthy and running replica version {}",
        node.get_ip_addr(),
        expected_version
    );

    #[derive(PartialEq)]
    enum State {
        Uninitialized,
        OldVersion,
        Reboot,
        OldVersionAgain,
        Finished,
    }
    let mut state = State::Uninitialized;
    let result = ic_system_test_driver::retry_with_msg!(
        format!(
            "Check if node {} is healthy and running replica version {}",
            node.get_ip_addr(),
            expected_version
        ),
        logger.clone(),
        secs(total_secs),
        secs(backoff_secs),
        || match get_assigned_replica_version(node) {
            Ok(ver) if &ver == expected_version => {
                state = State::Finished;
                Ok(())
            }
            Ok(ver) => {
                if state == State::Uninitialized || state == State::OldVersion {
                    state = State::OldVersion
                } else {
                    state = State::OldVersionAgain
                }
                bail!(
                    "Node is running the old replica version: {}. Expected: {}",
                    ver,
                    expected_version
                )
            }
            Err(err) => {
                state = State::Reboot;
                bail!("Error reading replica version: {:?}", err)
            }
        }
    );
    if let Err(error) = result {
        info!(logger, "Error: {}", error);
        match state {
            State::Uninitialized => panic!("No version is fetched at all!"),
            State::OldVersion => panic!("Replica was running the old version only!"),
            State::Reboot => {
                panic!("Replica did reboot, but never came back online!")
            }
            State::OldVersionAgain => panic!("Replica rebooted to a wrong version!"),
            State::Finished => {} // All went well eventually
        }
    }
}

/// Gets the replica version from the node if it is healthy.
pub fn get_assigned_replica_version(node: &IcNodeSnapshot) -> Result<ReplicaVersion, String> {
    let version = match node.status() {
        Ok(status) if Some(ReplicaHealthStatus::Healthy) == status.replica_health_status => status,
        Ok(status) => return Err(format!("Replica is not healthy: {status:?}")),
        Err(err) => return Err(err.to_string()),
    }
    .impl_version
    .ok_or("No version found in status".to_string())?;

    ReplicaVersion::try_from(version).map_err(|_| "Invalid replica version".to_string())
}

pub async fn bless_replica_version(
    nns_node: &IcNodeSnapshot,
    target_version: &ReplicaVersion,
    logger: &Logger,
    sha256: String,
    guest_launch_measurements: Option<GuestLaunchMeasurements>,
    upgrade_url: Vec<String>,
) {
    bless_replica_version_with_urls(
        nns_node,
        target_version,
        upgrade_url,
        sha256,
        guest_launch_measurements,
        logger,
    )
    .await;
}

pub async fn bless_replica_version_with_urls(
    nns_node: &IcNodeSnapshot,
    target_version: &ReplicaVersion,
    release_package_urls: Vec<String>,
    sha256: String,
    guest_launch_measurements: Option<GuestLaunchMeasurements>,
    logger: &Logger,
) {
    let nns = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance_canister = get_governance_canister(&nns);
    let registry_canister = RegistryCanister::new(vec![nns_node.get_public_url()]);
    let test_neuron_id = NeuronId(TEST_NEURON_1_ID);
    let proposal_sender = Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR);
    let blessed_versions = get_blessed_replica_versions(&registry_canister).await;
    info!(logger, "Initial: {:?}", blessed_versions);

    info!(
        logger,
        "Blessing replica version {} with sha256 {}", target_version, sha256
    );

    let proposal_id = submit_update_elected_replica_versions_proposal(
        &governance_canister,
        proposal_sender.clone(),
        test_neuron_id,
        Some(target_version),
        Some(sha256),
        release_package_urls,
        guest_launch_measurements,
        vec![],
    )
    .await;
    vote_execute_proposal_assert_executed(&governance_canister, proposal_id).await;
    let blessed_versions = get_blessed_replica_versions(&registry_canister).await;
    info!(logger, "Updated: {:?}", blessed_versions);
}

pub async fn deploy_guestos_to_all_subnet_nodes(
    nns_node: &IcNodeSnapshot,
    new_replica_version: &ReplicaVersion,
    subnet_id: SubnetId,
) {
    let nns = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance_canister = get_governance_canister(&nns);
    let test_neuron_id = NeuronId(TEST_NEURON_1_ID);
    let proposal_sender = Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR);
    let proposal_id = submit_deploy_guestos_to_all_subnet_nodes_proposal(
        &governance_canister,
        proposal_sender.clone(),
        test_neuron_id,
        new_replica_version.clone(),
        subnet_id,
    )
    .await;
    vote_execute_proposal_assert_executed(&governance_canister, proposal_id).await;
}
