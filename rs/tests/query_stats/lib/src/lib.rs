use candid::Principal;
use futures::future::join_all;
use ic_agent::Agent;
use ic_consensus_system_test_utils::node::await_node_certified_height;
use ic_management_canister_types_private::{
    BoundedVec, CanisterHttpRequestArgs, HttpMethod, Payload, TransformContext, TransformFunc,
};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::{
    ic::{InternetComputer, Subnet},
    test_env::TestEnv,
    test_env_api::{HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, SubnetSnapshot},
};
use ic_types::{Cycles, Height, epoch_from_height};
use ic_universal_canister::{call_args, wasm};
use itertools::Itertools;
use slog::{Logger, info};
use std::time::Duration;

pub mod aggregation;

const QUERY_STATS_TEST_EPOCH_LENGTH: u64 = 120;

const QUERY_STATS_WAIT_PERIOD: u64 = 30;

pub fn query_stats_config(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(1))
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_unit_delay(Duration::from_millis(200))
                .with_initial_notary_delay(Duration::from_millis(200))
                .with_dkg_interval_length(Height::from(99))
                .with_random_height()
                .with_query_stats_epoch_length(QUERY_STATS_TEST_EPOCH_LENGTH)
                .add_nodes(4),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    info!(&env.logger(), "Checking readiness of all nodes...");
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
}

pub(crate) fn wait_until_next_epoch(subnet: &SubnetSnapshot, logger: &Logger) {
    let current_height = subnet
        .nodes()
        .next()
        .unwrap()
        .status()
        .unwrap()
        .certified_height
        .unwrap()
        .get();

    let current_epoch =
        epoch_from_height(current_height.into(), QUERY_STATS_TEST_EPOCH_LENGTH).get();
    let next_epoch = current_epoch + 1;
    let target_height = next_epoch * QUERY_STATS_TEST_EPOCH_LENGTH + QUERY_STATS_WAIT_PERIOD;

    info!(logger, "Waiting until height {}", target_height);
    await_node_certified_height(
        &subnet.nodes().next().unwrap(),
        Height::new(target_height),
        logger.clone(),
    );
}

pub(crate) async fn single_update_call(canister: &Principal, agents: &[Agent]) {
    agents
        .first()
        .unwrap()
        .update(canister, "update")
        .with_arg(wasm().set_global_data(&[1, 2, 3, 4]).reply())
        .call_and_wait()
        .await
        .unwrap();
}

pub(crate) async fn round_robin_query_call(canister: &Principal, agents: &[Agent]) {
    let equals = join_all(agents.iter().map(|agent| {
        agent
            .query(canister, "query")
            .with_arg(wasm().get_global_data().append_and_reply())
            .call()
    }))
    .await
    .iter()
    .tuple_windows()
    .all(|(a, b)| a == b);

    if !equals {
        panic!("Nodes returned different values in round robin query call");
    }
}

pub(crate) async fn single_https_outcall(canister: &Principal, agents: &[Agent]) {
    agents
        .first()
        .unwrap()
        .update(canister, "update")
        .with_arg(
            wasm()
                .set_transform(wasm().message_payload().append_and_reply())
                .reply(),
        )
        .call_and_wait()
        .await
        .unwrap();

    let arg = CanisterHttpRequestArgs {
        url: "https://example.com".to_string(),
        max_response_bytes: None,
        method: HttpMethod::GET,
        headers: BoundedVec::new(vec![]),
        body: None,
        transform: Some(TransformContext {
            function: TransformFunc(candid::Func {
                method: "transform".to_string(),
                principal: *canister,
            }),
            context: vec![],
        }),
        is_replicated: None,
        pricing_version: None,
    };

    agents
        .first()
        .unwrap()
        .update(canister, "update")
        .with_arg(
            wasm()
                .call_with_cycles(
                    Principal::management_canister(),
                    "http_request",
                    call_args().other_side(arg.encode()),
                    Cycles::new(10_000_000_000),
                )
                .reply(),
        )
        .call_and_wait()
        .await
        .unwrap();
}
