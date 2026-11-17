/* tag::catalog[]
Title:: Complaints and openings for key transcripts reshared from another subnet

Goal:: Ensure that the nodes of a subnet created with keys reshared from another subnet can load
the reshared key transcripts when some of their dealings are corrupted, by issuing complaints and
getting openings from the other nodes of their subnet.

Runbook::
. Setup:
    . System subnet comprising one node and the necessary NNS canisters.
    . Application subnet comprising N nodes, all of which corrupt the IDKG dealings they create,
      starting at a large height.
    . N unassigned nodes.
. Generate keys on the application subnet and ensure signing works.
. Create a new subnet with the unassigned nodes, resharing the keys from the application subnet.
. Wait until a node of the new subnet loads a transcript with openings.

Success::
. A node of the new subnet loads a transcript with openings.

end::catalog[] */

use anyhow::{Result, bail};
use canister_test::Canister;
use ic_consensus_system_test_utils::rw_message::install_nns_and_check_progress;
use ic_consensus_threshold_sig_system_test_utils::{
    DKG_INTERVAL, create_new_subnet_with_keys, enable_chain_key_signing,
    get_public_key_and_test_signature, make_key_ids_for_all_idkg_schemes,
};
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, READY_WAIT_TIMEOUT, RETRY_BACKOFF,
    get_guestos_img_version,
};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::{
    MessageCanister, MetricsFetcher, assert_malicious_from_topo, block_on, runtime_from_url,
};
use ic_types::Height;
use ic_types::malicious_behavior::MaliciousBehavior;
use slog::info;

const NODES_COUNT: usize = 4;
/// The key transcripts reshared from the application subnet have a source height above this
/// height, while the new subnet starts at height 0 and stays far below it for the whole test.
const SOURCE_SUBNET_INITIAL_HEIGHT: u64 = 1_000_000;
const IDKG_COMPLAINT_METRICS: &str = "idkg_complaint_metrics";
const TRANSCRIPTS_LOADED_WITH_OPENINGS: &str =
    "idkg_complaint_metrics{type=\"transcripts_loaded_with_openings\"}";

fn setup(env: TestEnv) {
    let malicious_behavior = MaliciousBehavior::new(true).set_maliciously_corrupt_idkg_dealings();
    InternetComputer::new()
        .add_subnet(Subnet::fast_single_node(SubnetType::System))
        // All nodes of the subnet holding the keys corrupt the dealings they create, so that every
        // dealing of a key transcript reshared from this subnet is corrupted for one of the
        // receivers on the new subnet.
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .with_initial_height(SOURCE_SUBNET_INITIAL_HEIGHT)
                .add_malicious_nodes(NODES_COUNT, malicious_behavior),
        )
        .with_unassigned_nodes(NODES_COUNT)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    install_nns_and_check_progress(env.topology_snapshot());
}

fn test(env: TestEnv) {
    let log = env.logger();
    let mut topology = env.topology_snapshot();
    let nns_node = topology.root_subnet().nodes().next().unwrap();
    let source_subnet = topology
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .expect("Could not find the application subnet");
    let original_subnet_ids: Vec<_> = topology.subnets().map(|s| s.subnet_id).collect();
    let unassigned_node_ids: Vec<_> = topology.unassigned_nodes().map(|n| n.node_id).collect();
    let key_ids = make_key_ids_for_all_idkg_schemes();

    let nns_runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance = Canister::new(&nns_runtime, GOVERNANCE_CANISTER_ID);

    info!(
        log,
        "Generating the keys on subnet {}", source_subnet.subnet_id
    );
    block_on(enable_chain_key_signing(
        &governance,
        source_subnet.subnet_id,
        key_ids.clone(),
        &log,
    ));
    let nns_agent = nns_node.build_default_agent();
    let msg_can = block_on(MessageCanister::new(
        &nns_agent,
        nns_node.effective_canister_id(),
    ));
    for key_id in &key_ids {
        block_on(get_public_key_and_test_signature(
            key_id, &msg_can, /*zero_cycles=*/ false, &log,
        ))
        .expect("Should successfully create and verify the signature");
    }

    info!(
        log,
        "Creating a new subnet with the keys of subnet {}", source_subnet.subnet_id
    );
    let replica_version = get_guestos_img_version();
    block_on(create_new_subnet_with_keys(
        &governance,
        unassigned_node_ids,
        key_ids
            .iter()
            .map(|key_id| (key_id.clone(), source_subnet.subnet_id.get()))
            .collect(),
        replica_version,
        &log,
    ));

    let new_subnet = loop {
        topology = block_on(topology.block_for_newer_registry_version())
            .expect("Could not obtain an updated registry");
        if let Some(subnet) = topology
            .subnets()
            .find(|s| !original_subnet_ids.contains(&s.subnet_id))
        {
            break subnet;
        }
    };
    new_subnet.nodes().for_each(|node| {
        node.await_status_is_healthy()
            .expect("Timeout while waiting for the nodes of the new subnet to be healthy")
    });

    // The nodes of the new subnet are honest, so their own dealings are never corrupted: a
    // transcript loaded with openings there is necessarily one reshared from the source subnet.
    info!(
        log,
        "Waiting for a node of subnet {} to load a transcript with openings", new_subnet.subnet_id
    );
    let metrics = MetricsFetcher::new(new_subnet.nodes(), vec![IDKG_COMPLAINT_METRICS.into()]);
    ic_system_test_driver::retry_with_msg!(
        format!(
            "check if a node of subnet {} loaded a transcript with openings",
            new_subnet.subnet_id
        ),
        log.clone(),
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || match block_on(metrics.fetch::<u64>()) {
            Ok(val) => {
                info!(log, "Complaint metrics: {:?}", val);
                let loaded_with_openings: u64 = val
                    .get(TRANSCRIPTS_LOADED_WITH_OPENINGS)
                    .map_or(0, |per_node| per_node.iter().sum());
                if loaded_with_openings > 0 {
                    Ok(())
                } else {
                    bail!("No transcript loaded with openings yet")
                }
            }
            Err(err) => bail!("Could not connect to metrics yet {:?}", err),
        }
    )
    .expect("No node of the new subnet loaded a transcript with openings in time");

    assert_malicious_from_topo(&topology, vec!["maliciously_corrupt_idkg_dealings: true"]);
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        // The malicious nodes create corrupted IDKG dealings, so it's expected that the metric
        // will increase.
        .remove_metrics_to_check("idkg_invalidated_artifacts")
        .execute_from_args()?;
    Ok(())
}
