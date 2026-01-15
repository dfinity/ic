/* tag::catalog[]

Title:: Unassigned nodes configuration updates

Goal:: Ensure we can set SSH readonly keys and upgrade the unassigned nodes.

Description::
We deploy an IC with a set of unassigned nodes. Then we make a proposal and add an
SSH key for the read-only access and set the replica version for unassigned nodes.
Then we make sure that unassigned nodes eventually upgrade to that version by
leveraging the SSH access.

Runbook::
. Deploy an IC with unassigned nodes
. Deploy a config for the unassigned nodes with one SSH key and a replica version.
. ssh into one of the unassigned nodes and read the version file.

Success::
. At least one unassigned node has SSH enabled and runs the expected version.

end::catalog[] */

use anyhow::Result;
use anyhow::bail;
use ic_canister_client::Sender;
use ic_consensus_system_test_utils::upgrade::{
    fetch_unassigned_node_version, get_blessed_replica_versions,
};
use ic_consensus_system_test_utils::{
    rw_message::install_nns_and_check_progress,
    ssh_access::{
        AuthMean, generate_key_strings, get_updatesshreadonlyaccesskeyspayload,
        update_ssh_keys_for_all_unassigned_nodes, wait_until_authentication_is_granted,
    },
};
use ic_nervous_system_common_test_keys::{TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_KEYPAIR};
use ic_nns_common::types::NeuronId;
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_system_test_driver::{
    driver::{ic::InternetComputer, test_env::TestEnv, test_env_api::*},
    nns::{
        self, submit_update_elected_replica_versions_proposal,
        submit_update_unassigned_node_version_proposal, vote_execute_proposal_assert_executed,
    },
    util::{block_on, get_nns_node, runtime_from_url},
};
use slog::info;

fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .with_unassigned_nodes(1)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    install_nns_and_check_progress(env.topology_snapshot());
}

fn test(env: TestEnv) {
    let logger = env.logger();

    // choose a node from the nns subnet
    let nns_node = get_nns_node(&env.topology_snapshot());

    // choose an unassigned node
    let unassigned_node = env.topology_snapshot().unassigned_nodes().next().unwrap();

    // obtain readonly access
    let (readonly_private_key, readonly_public_key) = generate_key_strings();
    let payload = get_updatesshreadonlyaccesskeyspayload(vec![readonly_public_key.clone()]);
    block_on(update_ssh_keys_for_all_unassigned_nodes(
        nns_node.get_public_url(),
        payload,
    ));
    let readonly_mean = AuthMean::PrivateKey(readonly_private_key);
    wait_until_authentication_is_granted(
        &logger,
        &unassigned_node.get_ip_addr(),
        "readonly",
        &readonly_mean,
    );
    info!(logger, "SSH authorization succeeded");

    // fetch the current replica version and deduce the new one
    let original_version = fetch_unassigned_node_version(&unassigned_node).unwrap();
    info!(logger, "Original replica version: {}", original_version);

    let upgrade_url = get_guestos_update_img_url().to_string();
    info!(logger, "Upgrade URL: {}", upgrade_url);
    let target_version = get_guestos_update_img_version();
    info!(logger, "Target replica version: {}", target_version);

    let registry_canister = RegistryCanister::new(vec![nns_node.get_public_url()]);

    block_on(async {
        // initial parameters
        let reg_ver = registry_canister.get_latest_version().await.unwrap();
        info!(logger, "Registry version: {}", reg_ver);
        let blessed_versions = get_blessed_replica_versions(&registry_canister).await;
        info!(logger, "Initial: {:?}", blessed_versions);
        let sha256 = get_guestos_update_img_sha256();
        info!(logger, "Update image SHA256: {}", sha256);
        let guest_launch_measurements = get_guestos_launch_measurements();

        // prepare for the 1. proposal
        let nns = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
        let governance_canister = nns::get_governance_canister(&nns);

        let test_neuron_id = NeuronId(TEST_NEURON_1_ID);
        let proposal_sender = Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR);

        let proposal_id = submit_update_elected_replica_versions_proposal(
            &governance_canister,
            proposal_sender.clone(),
            test_neuron_id,
            Some(&target_version),
            Some(sha256),
            vec![upgrade_url],
            Some(guest_launch_measurements),
            vec![],
        )
        .await;
        vote_execute_proposal_assert_executed(&governance_canister, proposal_id).await;

        // was registry updated?
        let reg_ver2 = registry_canister.get_latest_version().await.unwrap();
        info!(logger, "Registry version: {}", reg_ver2);
        assert!(reg_ver < reg_ver2);

        // new blessed versions
        let blessed_versions = get_blessed_replica_versions(&registry_canister).await;
        info!(logger, "Updated: {:?}", blessed_versions);

        // proposal to upgrade the unassigned nodes
        let proposal2_id = submit_update_unassigned_node_version_proposal(
            &governance_canister,
            proposal_sender.clone(),
            test_neuron_id,
            &target_version,
        )
        .await;
        vote_execute_proposal_assert_executed(&governance_canister, proposal2_id).await;

        // was registry updated?
        let reg_ver3 = registry_canister.get_latest_version().await.unwrap();
        info!(logger, "Registry version: {}", reg_ver3);
        assert!(reg_ver2 < reg_ver3);
    });

    // wait for the unassigned node to be updated
    ic_system_test_driver::retry_with_msg!(
        format!(
            "check if unassigned node {} is at version {}",
            unassigned_node.node_id, &target_version
        ),
        env.logger(),
        secs(900),
        secs(10),
        || match fetch_unassigned_node_version(&unassigned_node) {
            Ok(ver) if (ver == target_version) => Ok(()),
            Ok(ver) => bail!("Unassigned node replica version: {}", ver),
            Err(_) => bail!("Waiting for the host to boot..."),
        }
    )
    .expect("Unassigned node was not updated!");
    info!(
        logger,
        "Unassigned node was updated to: {}", &target_version
    );
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}
