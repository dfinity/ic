use std::io::Read;

use ic_canister_client::Sender;
use ic_nervous_system_common_test_keys::{TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_KEYPAIR};
use ic_nns_common::types::NeuronId;
use ic_system_test_driver::{
    driver::{nested::NestedVm, test_env_api::*},
    nns::{
        get_governance_canister, submit_update_elected_hostos_versions_proposal,
        submit_update_nodes_hostos_version_proposal, vote_execute_proposal_assert_executed,
    },
    util::runtime_from_url,
};
use ic_types::{hostos_version::HostosVersion, NodeId};

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
