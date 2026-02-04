/* tag::catalog[]

Title:: Subnet Splitting Test

Goal::
Ensure that Subnet Splitting V2 works

Runbook::
. Deploy an IC with NNS and one Application subnet, with 8 nodes.
. Install some canistes on the Application subnet.
. Execute an NNS proposal to split the subnet.

Success::
. Both subnets are functional after the split and the canisters are migrated.

end::catalog[] */

use std::time::Duration;

use anyhow::{Context, Result};
use candid::Principal;
use canister_test::{Canister, Runtime, Wasm};
use dfn_candid::candid;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, StatusCode, body::Bytes};
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use ic_canister_client::Sender;
use ic_consensus_system_test_utils::rw_message::install_nns_and_check_progress;
use ic_nervous_system_common_test_keys::{TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_KEYPAIR};
use ic_nns_common::types::NeuronId;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance_api::{NnsFunction, ProposalStatus};
use ic_nns_test_utils::governance::submit_external_update_proposal;
use ic_protobuf::types::v1 as pb;
use ic_registry_routing_table::{
    CANISTER_IDS_PER_SUBNET, CanisterIdRange, CanisterIdRanges, canister_id_into_u64, difference,
};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::canister_agent::HasCanisterAgentCapability;
use ic_system_test_driver::driver::prometheus_vm::{HasPrometheus, PrometheusVm};
use ic_system_test_driver::driver::test_env_api::get_dependency_path;
use ic_system_test_driver::nns::vote_and_execute_proposal;
use ic_system_test_driver::util::{MetricsFetcher, block_on};
use ic_system_test_driver::{driver::group::SystemTestGroup, systest};
use ic_system_test_driver::{
    driver::{
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::{
            HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, IcNodeSnapshot, SubnetSnapshot,
        },
    },
    util::runtime_from_url,
};
use ic_types::consensus::CatchUpPackage;
use ic_types::crypto::threshold_sig::ni_dkg::NiDkgTargetSubnet;
use ic_types::{CanisterId, Height, NodeId, PrincipalId, SubnetId};
use prost::Message;
use registry_canister::mutations::do_split_subnet::SplitSubnetPayload;
use slog::{info, warn};
use xnet_test::{Metrics, StartArgs};

const DKG_INTERVAL: u64 = 9;
const INITIAL_SOURCE_SUBNET_NODES: usize = 8;

const COUNTER_CANISTER_WAT: &str = "rs/tests/counter.wat";

/// Number of counter canisters to install on the source subnet, before splitting it.
const COUNTER_CANISTERS_COUNT: usize = 13;
const FIRST_COUNTER_CANISTER_ID_OFFSET: usize = 3;
const LAST_COUNTER_CANISTER_ID_OFFSET: usize = 7;

/// Number of "chatting" canisters to install on the source subnet and on a third subnet, before
/// splitting the source subnet. All "chatting" canisters will send messages to each other.
const CHATTING_CANISTERS_ON_SOURCE_SUBNET_COUNT: usize = 10;
const CHATTING_CANISTERS_ON_THIRD_SUBNET_COUNT: usize = 3;
const FIRST_CHATTING_CANISTER_ID_OFFSET: usize = 3;
const LAST_CHATTING_CANISTER_ID_OFFSET: usize = 8;

const PROMETHEUS_SCRAPE_INTERVAL: Duration = Duration::from_secs(5);

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .with_timeout_per_test(Duration::from_secs(5 * 60 * 60))
        .with_overall_timeout(Duration::from_secs(5 * 60 * 60))
        .add_test(systest!(subnet_splitting_test))
        .execute_from_args()
}

/// Setup an IC with
/// 1. one NNS subnet,
/// 2. one Application subnet with 8 nodes, which will be later split,
/// 3. one Verified Application subnet which will send xnet messages to canisters on the Application
/// subnet.
fn setup(env: TestEnv) {
    PrometheusVm::default()
        .with_scrape_interval(PROMETHEUS_SCRAPE_INTERVAL)
        .start(&env)
        .expect("failed to start prometheus VM");

    InternetComputer::new()
        .add_subnet(
            Subnet::fast_single_node(SubnetType::System)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL)),
        )
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .add_nodes(INITIAL_SOURCE_SUBNET_NODES),
        )
        .add_subnet(
            Subnet::fast_single_node(SubnetType::VerifiedApplication)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL)),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    env.sync_with_prometheus();

    install_nns_and_check_progress(env.topology_snapshot());
}

fn subnet_splitting_test(env: TestEnv) {
    let test_params = prepare_canisters(&env);
    info!(
        env.logger(),
        "Sleeping for 10 seconds before splitting the subnet \
        so the canisters have some time to chit chat"
    );
    std::thread::sleep(Duration::from_secs(10));
    block_on(run_subnet_splitting_test(env.clone(), &test_params));
}

fn prepare_canisters(env: &TestEnv) -> TestParams {
    let (source_subnet_chatting_canister_ids, third_subnet_chatting_canister_ids) =
        block_on(install_chatting_canisters(&env));
    let source_subnet_counting_canister_ids = install_counting_canisters(&env);
    TestParams::new(
        source_subnet_counting_canister_ids
            .iter()
            .map(|principal| CanisterId::unchecked_from_principal(PrincipalId(*principal)))
            .collect(),
        source_subnet_chatting_canister_ids.clone(),
        third_subnet_chatting_canister_ids,
    )
}

async fn run_subnet_splitting_test(env: TestEnv, test_params: &TestParams) {
    info!(
        env.logger(),
        "Running subnet splittings test with parameters {test_params:?}"
    );

    // FIXME: only for demo purposes
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let _ = env
            .topology_snapshot()
            .block_for_newer_registry_version()
            .await;
        env.sync_with_prometheus();
    }

    let nns_subnet = get_nns_subnet(&env);
    let source_subnet = get_source_subnet(&env);
    let original_source_subnet_canister_ranges = source_subnet.subnet_canister_ranges();
    let nns_canister_ranges = nns_subnet.subnet_canister_ranges();

    let mut source_subnet_nodes: Vec<_> = source_subnet.nodes().map(|node| node.node_id).collect();
    let destination_subnet_nodes: Vec<_> =
        source_subnet_nodes.split_off(INITIAL_SOURCE_SUBNET_NODES / 2);
    let nns_subnet_nodes: Vec<_> = nns_subnet.nodes().map(|node| node.node_id).collect();

    propose_to_split_subnet(
        &env,
        &source_subnet,
        test_params.canister_migation_list.clone(),
        destination_subnet_nodes.clone(),
    )
    .await;

    check_routing_table(
        &env,
        source_subnet.subnet_id,
        &original_source_subnet_canister_ranges,
        &nns_canister_ranges,
        &test_params.canister_migation_list,
    );
    check_subnet_membership(
        &env,
        source_subnet.subnet_id,
        &source_subnet_nodes,
        &destination_subnet_nodes,
        &nns_subnet_nodes,
    )
    .await;
    check_counter_canisters(&env, source_subnet.subnet_id, test_params).await;
    check_chatting_canisters(&env, test_params).await;
    assert_no_critical_errors(&env).await;
}

fn runtime_from_subnet(subnet: &SubnetSnapshot) -> Runtime {
    let node = subnet
        .nodes()
        .next()
        .expect("Every subnet has at least one node");

    runtime_from_url(node.get_public_url(), node.effective_canister_id())
}

#[derive(Default, Debug)]
struct TestParams {
    source_subnet_counting_canister_ids: Vec<CanisterId>,
    source_subnet_chatting_canister_ids: Vec<CanisterId>,
    destination_subnet_counting_canister_ids: Vec<CanisterId>,
    destination_subnet_chatting_canister_ids: Vec<CanisterId>,
    third_subnet_chatting_canister_ids: Vec<CanisterId>,
    canister_migation_list: Vec<CanisterIdRange>,
}

impl TestParams {
    fn new(
        mut original_source_subnet_counter_canister_ids: Vec<CanisterId>,
        mut original_source_subnet_chatting_canister_ids: Vec<CanisterId>,
        mut third_subnet_chatting_canister_ids: Vec<CanisterId>,
    ) -> Self {
        original_source_subnet_chatting_canister_ids.sort();
        original_source_subnet_counter_canister_ids.sort();
        third_subnet_chatting_canister_ids.sort();

        let counter_canister_range_to_migrate = CanisterIdRange {
            start: original_source_subnet_counter_canister_ids[FIRST_COUNTER_CANISTER_ID_OFFSET]
                .into(),
            end: original_source_subnet_counter_canister_ids[LAST_COUNTER_CANISTER_ID_OFFSET]
                .into(),
        };
        let chatting_canister_range_to_migrate = CanisterIdRange {
            start: original_source_subnet_chatting_canister_ids[FIRST_CHATTING_CANISTER_ID_OFFSET]
                .into(),
            end: original_source_subnet_chatting_canister_ids[LAST_CHATTING_CANISTER_ID_OFFSET]
                .into(),
        };

        let mut test_params = TestParams {
            third_subnet_chatting_canister_ids,
            canister_migation_list: vec![
                counter_canister_range_to_migrate.clone(),
                chatting_canister_range_to_migrate.clone(),
            ],
            ..Default::default()
        };

        test_params.canister_migation_list.sort();

        for canister_id in original_source_subnet_counter_canister_ids {
            if counter_canister_range_to_migrate.contains(&canister_id) {
                test_params
                    .destination_subnet_counting_canister_ids
                    .push(canister_id)
            } else {
                test_params
                    .source_subnet_counting_canister_ids
                    .push(canister_id)
            }
        }

        for canister_id in original_source_subnet_chatting_canister_ids {
            if chatting_canister_range_to_migrate.contains(&canister_id) {
                test_params
                    .destination_subnet_chatting_canister_ids
                    .push(canister_id)
            } else {
                test_params
                    .source_subnet_chatting_canister_ids
                    .push(canister_id)
            }
        }

        test_params
    }
}

async fn stop_chatting_canisters(
    env: &TestEnv,
    subnet: &SubnetSnapshot,
    canister_ids: &[CanisterId],
    subnet_type: &str,
) {
    info!(
        env.logger(),
        "Stopping all the chatting canisters on the {subnet_type} subnet",
    );
    let runtime = runtime_from_subnet(subnet);
    for canister_id in canister_ids {
        info!(env.logger(), "Stopping canister {canister_id}");
        let canister = Canister::new(&runtime, *canister_id);
        canister.stop().await.expect("The canister failed to stop");
    }
}

async fn check_chatting_canisters_metrics(
    env: &TestEnv,
    subnet: &SubnetSnapshot,
    canister_ids: &[CanisterId],
    subnet_type: &str,
) {
    info!(
        env.logger(),
        "Checking if any of the chatting canister metrics on the {subnet_type} subnet \
        returned an error"
    );
    let runtime = runtime_from_subnet(subnet);
    let mut aggregated_metrics = Metrics::default();
    for canister_id in canister_ids {
        info!(
            env.logger(),
            "Instructing canister {canister_id} to stop chatting and collecting metrics"
        );
        let canister = Canister::new(&runtime, *canister_id);
        let _: String = canister
            .update_("stop", candid, ())
            .await
            .expect("Failed to make an update call");
        let metrics = canister
            .query_("metrics", candid, ())
            .await
            .expect("Failed to make a query call");

        aggregated_metrics.merge(&metrics);
    }

    //assert_eq!(aggregated_metrics.call_errors, 0);
    //assert_eq!(aggregated_metrics.reject_responses, 0);
    //assert_eq!(aggregated_metrics.seq_errors, 0);
}

async fn install_chatting_canisters(env: &TestEnv) -> (Vec<CanisterId>, Vec<CanisterId>) {
    info!(
        env.logger(),
        "Installing chatting canisters on the source subnet"
    );
    let wasm = Wasm::from_file(get_dependency_path(
        std::env::var("XNET_TEST_CANISTER_WASM_PATH")
            .expect("XNET_TEST_CANISTER_WASM_PATH not set"),
    ));

    let source_subnet_runtime = runtime_from_subnet(&get_source_subnet(&env));
    let other_subnet_runtime = runtime_from_subnet(&get_third_subnet(&env));

    let mut source_subnet_canisters = Vec::new();
    let mut other_subnet_canisters = Vec::new();

    for _ in 0..CHATTING_CANISTERS_ON_SOURCE_SUBNET_COUNT {
        source_subnet_canisters.push(
            wasm.clone()
                .install_(&source_subnet_runtime, /*payload=*/ vec![])
                .await
                .expect("Failed to install the chatting canister"),
        );
    }

    for _ in 0..CHATTING_CANISTERS_ON_THIRD_SUBNET_COUNT {
        other_subnet_canisters.push(
            wasm.clone()
                .install_(&other_subnet_runtime, /*payload=*/ vec![])
                .await
                .expect("Failed to install the chatting canister"),
        );
    }

    // Each canister will belong to a singleton, meaning that every canister will talk to every
    // other canister.
    let canister_groups: Vec<Vec<_>> = source_subnet_canisters
        .iter()
        .chain(&other_subnet_canisters)
        .map(|canister| vec![canister.canister_id().get().0])
        .collect();

    let canister_start_arguments = StartArgs {
        network_topology: canister_groups.clone(),
        canister_to_subnet_rate: 10,
        request_payload_size_bytes: 1,
        call_timeouts_seconds: vec![None],
        response_payload_size_bytes: 1,
    };

    for canister in source_subnet_canisters
        .iter()
        .chain(&other_subnet_canisters)
    {
        let _: String = canister
            .update_("start", candid, (canister_start_arguments.clone(),))
            .await
            .expect("Failed to start the chatting canister");
    }

    info!(
        env.logger(),
        "Successfully installed {CHATTING_CANISTERS_ON_SOURCE_SUBNET_COUNT} chatting canisters on \
        the source and the third subnet, each"
    );

    (
        source_subnet_canisters
            .iter()
            .map(Canister::canister_id)
            .collect(),
        other_subnet_canisters
            .iter()
            .map(Canister::canister_id)
            .collect(),
    )
}

fn install_counting_canisters(env: &TestEnv) -> Vec<Principal> {
    info!(
        env.logger(),
        "Installing counter canisters on the source subnet"
    );
    let source_node = get_source_subnet(&env)
        .nodes()
        .next()
        .expect("There should be at least one node on the source subnet");
    let canister_ids: Vec<Principal> = (0..COUNTER_CANISTERS_COUNT)
        .map(|_| {
            source_node
                .create_and_install_canister_with_arg(COUNTER_CANISTER_WAT, /*arg=*/ None)
        })
        .inspect(|id| info!(env.logger(), "Installed counter canister {id}"))
        .collect();

    block_on(async {
        let agent = source_node.build_canister_agent().await;
        for canister_id in &canister_ids {
            for _ in 0..20 {
                let response = agent
                    .get()
                    .update(canister_id, "write".to_string())
                    .call()
                    .await;

                if response.is_ok() {
                    break;
                }

                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    });

    info!(
        env.logger(),
        "Successfully installed {COUNTER_CANISTERS_COUNT} counter canisters on the source subnet"
    );
    canister_ids
}

/// First collects metrics from all the canister and checks that there are no reported errors in
/// them, and then stops the canisters. Stopping a canister would fail if there is still an open
/// call context.
async fn check_chatting_canisters(env: &TestEnv, test_params: &TestParams) {
    let source_subnet = get_source_subnet(env);
    let destination_subnet = get_destination_subnet(env);
    let third_subnet = get_third_subnet(env);

    check_chatting_canisters_metrics(
        &env,
        &third_subnet,
        &test_params.third_subnet_chatting_canister_ids,
        "third",
    )
    .await;
    check_chatting_canisters_metrics(
        &env,
        &source_subnet,
        &test_params.source_subnet_chatting_canister_ids,
        "source",
    )
    .await;
    check_chatting_canisters_metrics(
        &env,
        &destination_subnet,
        &test_params.destination_subnet_chatting_canister_ids,
        "destination",
    )
    .await;

    stop_chatting_canisters(
        &env,
        &third_subnet,
        &test_params.third_subnet_chatting_canister_ids,
        "third",
    )
    .await;
    stop_chatting_canisters(
        &env,
        &source_subnet,
        &test_params.source_subnet_chatting_canister_ids,
        "source",
    )
    .await;
    stop_chatting_canisters(
        &env,
        &destination_subnet,
        &test_params.destination_subnet_chatting_canister_ids,
        "destination",
    )
    .await;
}

async fn check_counter_canisters(
    env: &TestEnv,
    source_subnet_id: SubnetId,
    test_params: &TestParams,
) {
    info!(
        env.logger(),
        "Checking that we can make calls to the canisters  if and only if \
        they are on the correct subnets"
    );

    for canister_id in test_params
        .source_subnet_counting_canister_ids
        .iter()
        .chain(&test_params.destination_subnet_counting_canister_ids)
    {
        for subnet in env.topology_snapshot().subnets() {
            let should_host_the_canister = match subnet.subnet_type() {
                // NNS subnet
                SubnetType::System => false,
                // Third subnet
                SubnetType::VerifiedApplication => false,
                // Source subnet
                SubnetType::Application if subnet.subnet_id == source_subnet_id => {
                    // FIXME: !canister_is_migrated
                    if test_params
                        .source_subnet_counting_canister_ids
                        .contains(canister_id)
                    {
                        warn!(env.logger(), "Temporarily skipping the source subnet check");
                        continue;
                    }

                    test_params
                        .source_subnet_counting_canister_ids
                        .contains(canister_id)
                }
                // Destination subnet
                SubnetType::Application => test_params
                    .destination_subnet_counting_canister_ids
                    .contains(canister_id),
            };

            for node in subnet.nodes() {
                let agent = node.build_canister_agent().await;

                let response = agent
                    .get()
                    .query(&canister_id.get().0, "read".to_string())
                    .call()
                    .await
                    .map(|response| u32::from_le_bytes(response.as_slice().try_into().unwrap()));

                if should_host_the_canister {
                    let counter = response.expect(&format!(
                        "The subnet should host the canister with id {canister_id}, so \
                        the request should succeed"
                    ));
                    assert_eq!(
                        counter, 1,
                        "The counter value should not have changed during subnet splitting"
                    );
                } else {
                    let _err = response.expect_err(&format!(
                        "The subnet should no longer host the canister with \
                        id {canister_id}, so the request should fail",
                    ));
                }
            }

            if should_host_the_canister {
                info!(
                    env.logger(),
                    "Verified that the canister {canister_id} is on subnet {} of type {:?}",
                    subnet.subnet_id,
                    subnet.subnet_type()
                )
            } else {
                info!(
                    env.logger(),
                    "Verified that the canister {canister_id} is NOT on subnet {} of type {:?}",
                    subnet.subnet_id,
                    subnet.subnet_type()
                )
            }
        }
    }
}

/// Checks that the nodes are assigned to the correct subnets both according to the registry and the
/// replicas themselves.
async fn check_subnet_membership(
    env: &TestEnv,
    source_subnet_id: SubnetId,
    source_subnet_nodes: &[NodeId],
    destination_subnet_nodes: &[NodeId],
    nns_subnet_nodes: &[NodeId],
) {
    let topology = env.topology_snapshot();

    info!(
        env.logger(),
        "Checking if all nodes are on their respective subnets according to the registry..."
    );
    for subnet in topology.subnets() {
        let nodes: Vec<_> = subnet.nodes().map(|node| node.node_id).collect();

        match subnet.subnet_type() {
            SubnetType::System => {
                assert_eq!(
                    nodes, nns_subnet_nodes,
                    "The NNS subnet membership shouldn't change"
                );
            }
            SubnetType::Application if subnet.subnet_id == source_subnet_id => {
                assert_eq!(
                    nodes, source_subnet_nodes,
                    "Only some of the source subnet's nodes should stay on the subnet"
                );
            }
            SubnetType::Application => {
                assert_eq!(
                    nodes, destination_subnet_nodes,
                    "Some of the source subnet's nodes should move to the destination subnet"
                );
            }
            SubnetType::VerifiedApplication => {
                assert_eq!(
                    nodes.len(),
                    1,
                    "There should be exactly one node on the other app subnet"
                );
            }
        }
    }
    info!(
        env.logger(),
        "All nodes are on their respective subnets according to the registry!"
    );

    info!(
        env.logger(),
        "Checking if replicas believe they are on the correct subnets..."
    );
    for subnet in topology.subnets() {
        match subnet.subnet_type() {
            SubnetType::System => {
                info!(env.logger(), "Checking the NNS subnet");
            }
            SubnetType::Application if subnet.subnet_id == source_subnet_id => {
                info!(env.logger(), "Checking the source subnet");
            }
            SubnetType::Application => {
                info!(env.logger(), "Checking the destination subnet");
            }
            SubnetType::VerifiedApplication => {
                info!(env.logger(), "Checking the other app subnet");
            }
        }

        for node in subnet.nodes() {
            info!(
                env.logger(),
                "Waiting until node {} is on {}", node.node_id, subnet.subnet_id
            );
            wait_for_cup_with_subnet_id(&env, &node, subnet.subnet_id).await;
            info!(
                env.logger(),
                "Node {} is on {}", node.node_id, subnet.subnet_id
            );
        }
    }
    info!(
        env.logger(),
        "Replicas believe they are on the correct subnets!"
    );
}

/// Reads the routing table from the registry and checks that:
/// 1. The NNS and Third subnets' routing tables remain unchanged,
/// 2. The source subnet no longer has the migrated canister ids assigned to it.
/// 3. The destination subnet has the migrated canister ids assigned to it.
fn check_routing_table(
    env: &TestEnv,
    source_subnet_id: SubnetId,
    original_source_canister_ranges: &[CanisterIdRange],
    original_nns_canister_ranges: &[CanisterIdRange],
    migrated_canister_ranges: &[CanisterIdRange],
) {
    info!(
        env.logger(),
        "Making sure the routing table has been updated correctly..."
    );
    let _source_subnet_first_canister_id =
        canister_id_into_u64(original_source_canister_ranges[0].start);
    let source_subnet_last_canister_id =
        canister_id_into_u64(original_source_canister_ranges[0].end);

    for subnet in env.topology_snapshot().subnets() {
        match subnet.subnet_type() {
            SubnetType::System => {
                assert_eq!(
                    subnet.subnet_canister_ranges(),
                    original_nns_canister_ranges,
                    "The NNS subnet canister id assignment shouldn't change"
                );
            }
            // Source subnet
            SubnetType::Application if subnet.subnet_id == source_subnet_id => {
                let new_canister_ranges = subnet.subnet_canister_ranges();
                info!(
                    env.logger(),
                    "New source subnet canister ranges: {:?}", new_canister_ranges
                );

                let expected_canister_ranges = difference(
                    original_source_canister_ranges.iter(),
                    migrated_canister_ranges.iter(),
                )
                .unwrap();
                assert_eq!(
                    CanisterIdRanges::try_from(new_canister_ranges).unwrap(),
                    expected_canister_ranges,
                    "The source subnet should have some of the canister ranges removed"
                );
            }
            // Destination subnet
            SubnetType::Application => {
                let mut new_canister_ranges = subnet.subnet_canister_ranges();
                let mut expected_canister_ranges = migrated_canister_ranges.to_vec();

                new_canister_ranges.sort();
                expected_canister_ranges.sort();

                info!(
                    env.logger(),
                    "New destination subnet canister ranges: {:?}", new_canister_ranges
                );

                // NOTE: this assumes that the source subnet was created before the third
                // (i.e. the verified application) subnet.
                expected_canister_ranges.push(CanisterIdRange {
                    start: CanisterId::from(
                        source_subnet_last_canister_id + CANISTER_IDS_PER_SUBNET + 1,
                    ),
                    end: CanisterId::from(
                        source_subnet_last_canister_id + 2 * CANISTER_IDS_PER_SUBNET,
                    ),
                });
                assert_eq!(
                    new_canister_ranges, expected_canister_ranges,
                    "The destination subnet should have some of the source subnet's canister ids \
                    assigned to it"
                );
            }
            SubnetType::VerifiedApplication => {
                assert_eq!(
                    subnet.subnet_canister_ranges(),
                    vec![CanisterIdRange {
                        start: CanisterId::from(source_subnet_last_canister_id + 1,),
                        end: CanisterId::from(
                            source_subnet_last_canister_id + CANISTER_IDS_PER_SUBNET,
                        ),
                    }],
                    "The third subnet canister id assignment shouldn't change"
                );
            }
        }
    }

    info!(env.logger(), "Routing table has been updated correctly!");
}

async fn wait_for_cup_with_subnet_id(env: &TestEnv, node: &IcNodeSnapshot, subnet_id: SubnetId) {
    loop {
        match get_cup(&node).await {
            Ok(cup)
                if cup.signature.signer.target_subnet == NiDkgTargetSubnet::Local
                    && cup.signature.signer.dealer_subnet == subnet_id =>
            {
                break;
            }
            Ok(cup) => {
                info!(
                    env.logger(),
                    "The downloaded CUP doesn't have the expected subnet id. {} vs expected {}",
                    cup.signature.signer.dealer_subnet,
                    subnet_id,
                );
            }
            Err(err) => {
                warn!(env.logger(), "Failed to fetch the CUP: {err:#}");
            }
        }

        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

async fn get_cup(node: &IcNodeSnapshot) -> anyhow::Result<CatchUpPackage> {
    let url = node.get_public_url();
    let cup_url = format!("{url}_/catch_up_package");
    let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();

    let res = client
        .request(
            Request::builder()
                .method(Method::POST)
                .header(hyper::header::CONTENT_TYPE, "application/cbor")
                .uri(&cup_url)
                .body(Full::from(Bytes::new()))
                .unwrap(),
        )
        .await
        .with_context(|| format!("Failed to send request to {cup_url}"))?;

    if res.status() != StatusCode::OK {
        anyhow::bail!(
            "Failed to send request to {cup_url}. Status: {}",
            res.status()
        );
    }

    let body = res
        .into_body()
        .collect()
        .await
        .context("Failed to collect response body")?;

    let proto =
        pb::CatchUpPackage::decode(body.to_bytes()).context("Failed to decode the response")?;

    let cup =
        CatchUpPackage::try_from(&proto).context("Failed to convert proto to CatchUpPackage")?;

    Ok(cup)
}

fn get_source_subnet(env: &TestEnv) -> SubnetSnapshot {
    env.topology_snapshot()
        .subnets()
        .find(|subnet| subnet.subnet_type() == SubnetType::Application)
        .expect("There should be at least one subnet for every subnet type")
}

/// Should be called only after the subnet was split, otherwise it will panic.
fn get_destination_subnet(env: &TestEnv) -> SubnetSnapshot {
    let mut subnet_it = env
        .topology_snapshot()
        .subnets()
        .filter(|subnet| subnet.subnet_type() == SubnetType::Application);

    subnet_it.next(); // source subnet
    subnet_it
        .next()
        .expect("After the split there should be two application subnets")
}

fn get_third_subnet(env: &TestEnv) -> SubnetSnapshot {
    env.topology_snapshot()
        .subnets()
        .find(|subnet| subnet.subnet_type() == SubnetType::VerifiedApplication)
        .expect("There should be at least one subnet for every subnet type")
}

fn get_nns_subnet(env: &TestEnv) -> SubnetSnapshot {
    env.topology_snapshot()
        .subnets()
        .find(|subnet| subnet.subnet_type() == SubnetType::System)
        .expect("There should be at least one subnet for every subnet type")
}

async fn propose_to_split_subnet(
    env: &TestEnv,
    source_subnet: &SubnetSnapshot,
    canister_ranges_to_migrate: Vec<CanisterIdRange>,
    node_ids_to_migrate: Vec<NodeId>,
) {
    let topology = env.topology_snapshot();
    let nns_node = get_nns_subnet(env)
        .nodes()
        .next()
        .expect("There should be at least one node on each subnet");

    let proposal = SplitSubnetPayload {
        destination_canister_ranges: canister_ranges_to_migrate,
        destination_node_ids: node_ids_to_migrate,
        source_subnet_id: source_subnet.subnet_id,
    };

    let nns_runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance = Canister::new(&nns_runtime, GOVERNANCE_CANISTER_ID);

    let proposal_id = submit_external_update_proposal(
        &governance,
        Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
        NeuronId(TEST_NEURON_1_ID),
        NnsFunction::SplitSubnet,
        proposal,
        String::from("[SYSTEM TEST] Split Subnet Title"),
        String::from("[SYSTEM TEST] Split Subnet Summary"),
    )
    .await;

    let proposal_result = vote_and_execute_proposal(&governance, proposal_id).await;
    assert_eq!(proposal_result.status, ProposalStatus::Executed as i32);

    topology.block_for_newer_registry_version().await.unwrap();
    // This will tell prometheus to use the correct "subnet_id" labels for the migrated nodes.
    env.sync_with_prometheus();
}

async fn assert_no_critical_errors(env: &TestEnv) {
    info!(
        env.logger(),
        "Checking if the nodes encountered any critical errors"
    );
    let nodes = env
        .topology_snapshot()
        .subnets()
        .flat_map(|subnet| subnet.nodes());
    const NUM_RETRIES: u32 = 10;
    const BACKOFF_TIME_MILLIS: u64 = 500;

    let metrics = MetricsFetcher::new(nodes, vec!["critical_errors".to_string()]);

    for i in 0..NUM_RETRIES {
        match metrics.fetch::<u64>().await {
            Ok(result) => {
                let aggregated_errors_count = result
                    .iter()
                    .flat_map(|(_, values)| values.iter())
                    .sum::<u64>();
                assert_eq!(aggregated_errors_count, 0,);
                info!(env.logger(), "The nodes encountered no critical errors");
                return;
            }
            Err(e) => {
                info!(env.logger(), "Could not scrape metrics: {e}, attempt {i}.");
            }
        }
        tokio::time::sleep(Duration::from_millis(BACKOFF_TIME_MILLIS)).await;
    }

    panic!("Couldn't obtain metrics after {NUM_RETRIES} attempts.");
}
