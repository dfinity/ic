/* tag::catalog[]
Title:: Adding nodes to a subnet running canister threshold signing

Goal:: Test whether removing subnet nodes impacts the threshold signature feature

Runbook::
. Setup:
    . System subnet comprising N nodes, necessary NNS canisters, and with chain key feature featured.
    . X unassigned nodes.
. Enable chain key signing.
. Get public keys for all supported schemes.
. Add all X unassigned nodes to System subnet via proposal.
. Assert that node membership has changed.
. Assert that the key was reshared due to the new membership
. Assert that all nodes are making progress
. Assert that chain key signing continues to work with the same public key as before.

Success::
. System subnet contains N + X nodes.
. Chain key signature succeeds with the same public key as before.

end::catalog[] */

use anyhow::Result;

use canister_test::Canister;
use ic_consensus_system_test_utils::{
    node::await_subnet_earliest_topology_version,
    rw_message::cert_state_makes_progress_with_retries,
};
use ic_consensus_threshold_sig_system_test_utils::{
    DKG_INTERVAL, enable_chain_key_signing, get_public_key_and_test_signature,
    get_public_key_with_logger, make_key_ids_for_all_schemes,
};
use ic_management_canister_types_private::MasterPublicKeyId;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance_api::NnsFunction;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::{
            HasPublicApiUrl, HasRegistryVersion, HasTopologySnapshot, IcNodeContainer,
            NnsInstallationBuilder, SubnetSnapshot, secs,
        },
    },
    nns::{submit_external_proposal_with_test_id, vote_execute_proposal_assert_executed},
    systest,
    util::*,
};
use ic_types::Height;
use registry_canister::mutations::do_add_nodes_to_subnet::AddNodesToSubnetPayload;
use slog::{Logger, info};
use std::collections::BTreeMap;

const NODES_COUNT: usize = 4;
const UNASSIGNED_NODES_COUNT: usize = 3;

const MASTER_KEY_TRANSCRIPTS_CREATED: &str = "consensus_master_key_transcripts_created";

fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .add_nodes(NODES_COUNT),
        )
        .with_unassigned_nodes(UNASSIGNED_NODES_COUNT)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    // Check all subnet nodes are healthy.
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
    // Check all unassigned nodes are ready.
    env.topology_snapshot().unassigned_nodes().for_each(|node| {
        node.await_can_login_as_admin_via_ssh()
            .expect("Timeout while waiting for all unassigned nodes to be ready.");
    });
}

fn test(env: TestEnv) {
    let log = env.logger();
    let topology_snapshot = env.topology_snapshot();
    let (nns_subnet, nns_node, unassigned_node_ids) = {
        let subnet = topology_snapshot.root_subnet();
        let node = subnet.nodes().next().unwrap();
        (
            subnet,
            node,
            topology_snapshot
                .unassigned_nodes()
                .map(|ep| ep.node_id)
                .collect::<Vec<_>>(),
        )
    };
    assert_eq!(unassigned_node_ids.len(), UNASSIGNED_NODES_COUNT);
    info!(log, "Installing nns canisters.");
    NnsInstallationBuilder::new()
        .install(&nns_node, &env)
        .expect("Could not install NNS canisters.");
    info!(log, "Enabling chain key signatures.");
    let nns_runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance = Canister::new(&nns_runtime, GOVERNANCE_CANISTER_ID);
    let key_ids = make_key_ids_for_all_schemes();
    block_on(async {
        enable_chain_key_signing(&governance, nns_subnet.subnet_id, key_ids.clone(), &log).await;
    });
    info!(log, "Initial run to get public key.");
    let agent = nns_node.with_default_agent(|agent| async move { agent });
    let msg_can =
        block_on(async { MessageCanister::new(&agent, nns_node.effective_canister_id()).await });
    let nns = topology_snapshot.root_subnet();
    let mut public_keys = BTreeMap::new();
    for key_id in &key_ids {
        block_on(async {
            let public_key = get_public_key_with_logger(key_id, &msg_can, &log)
                .await
                .unwrap();
            public_keys.insert(key_id.clone(), public_key);
            if key_id.is_idkg_key() {
                info!(log, "Asserting initial metric state of key {}", key_id);
                // Initially, the sum of key creations should be equal to the number of nodes
                assert_metric_sum(&nns, key_id, NODES_COUNT, &log).await;
            }
        });
    }
    info!(
        log,
        "Sending a proposal for the nodes to join NNS subnet via the governance canister."
    );
    let proposal_payload = AddNodesToSubnetPayload {
        subnet_id: nns_subnet.subnet_id.get(),
        node_ids: unassigned_node_ids,
    };
    let proposal_id = block_on(submit_external_proposal_with_test_id(
        &governance,
        NnsFunction::AddNodeToSubnet,
        proposal_payload,
    ));
    info!(
        log,
        "Explicitly voting for the proposal to add nodes to NNS subnet."
    );
    block_on(vote_execute_proposal_assert_executed(
        &governance,
        proposal_id,
    ));

    info!(log, "Waiting for registry update.");
    let topology_snapshot = block_on(topology_snapshot.block_for_newer_registry_version())
        .expect("Should get newer registry version");
    info!(log, "Asserting nodes membership has changed.");
    assert!(topology_snapshot.unassigned_nodes().next().is_none());
    let nns = topology_snapshot.root_subnet();
    assert_eq!(nns.nodes().count(), UNASSIGNED_NODES_COUNT + NODES_COUNT);

    info!(log, "Ensure active subnet membership has progressed.");
    await_subnet_earliest_topology_version(&nns, topology_snapshot.get_registry_version(), &log);

    for key_id in &key_ids {
        if !key_id.is_idkg_key() {
            continue;
        }
        info!(log, "Make sure key {} was rotated.", key_id);
        // All nodes (old and new) should have increased their key rotation metric by one.
        block_on(assert_metric_sum(
            &nns,
            key_id,
            2 * NODES_COUNT + UNASSIGNED_NODES_COUNT,
            &log,
        ));
    }

    info!(log, "Assert all nodes are making progress.");
    for node in nns.nodes() {
        cert_state_makes_progress_with_retries(
            &node.get_public_url(),
            node.effective_canister_id(),
            &log,
            /*timeout=*/ secs(100),
            /*backoff=*/ secs(3),
        );
    }

    info!(log, "Run through signature test.");
    let msg_can = MessageCanister::from_canister_id(&agent, msg_can.canister_id());
    for (key_id, public_key) in public_keys {
        let public_key_ = block_on(get_public_key_and_test_signature(
            &key_id, &msg_can, true, &log,
        ))
        .unwrap();
        assert_eq!(public_key, public_key_);
    }
}

async fn assert_metric_sum(
    subnet: &SubnetSnapshot,
    key_id: &MasterPublicKeyId,
    expected_sum: usize,
    log: &Logger,
) {
    let mut count = 0;
    let metric_with_label = format!("{MASTER_KEY_TRANSCRIPTS_CREATED}{{key_id=\"{key_id}\"}}");
    let metrics = MetricsFetcher::new(subnet.nodes(), vec![metric_with_label.clone()]);
    loop {
        match metrics.fetch::<u64>().await {
            Ok(map) => {
                let values = map[&metric_with_label].clone();
                let sum: u64 = values.into_iter().sum();
                if sum as usize == expected_sum {
                    info!(
                        log,
                        "Found correct value of key rotation metric for {}", key_id
                    );
                    break;
                } else {
                    info!(
                        log,
                        "Sum of metrics for {} is {} != {}", key_id, sum, expected_sum
                    );
                }
            }
            Err(err) => {
                info!(log, "Could not connect to metrics yet {:?}", err);
            }
        }
        count += 1;
        // Abort after 30 tries
        if count > 30 {
            panic!("Failed to find key rotation of {key_id}");
        }
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}
