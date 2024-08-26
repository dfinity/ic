use canister_test::Project;
use ic_base_types::{CanisterId, SubnetId, NumBytes};
use ic_registry_routing_table::{routing_table_insert_subnet, RoutingTable};
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{StateMachine, StateMachineBuilder};
use ic_test_utilities_types::ids::{SUBNET_0, SUBNET_1};
use ic_types::{Cycles, NumInstructions};
use proptest::prelude::*;
use subnet_memory_test::{
    Config as CanisterConfig, Record,
};
use std::ops::RangeInclusive;
use std::sync::Arc;

const LOCAL_SUBNET_ID: SubnetId = SUBNET_0;
const REMOTE_SUBNET_ID: SubnetId = SUBNET_1;

const KB: u32 = 1024;
const MB: u32 = KB * KB;

/// Generates a local environment with `local_canisters_count` canisters installed;
/// and a remote environment with `remote_canisters_count` canisters installed.
fn new_fixture(
    local_canisters_count: usize,
    remote_canisters_count: usize,
) -> (
    Arc<StateMachine>,
    Vec<CanisterId>,
    Arc<StateMachine>,
    Vec<CanisterId>,
) {
    let mut routing_table = RoutingTable::new();
    routing_table_insert_subnet(&mut routing_table, LOCAL_SUBNET_ID).unwrap();
    routing_table_insert_subnet(&mut routing_table, REMOTE_SUBNET_ID).unwrap();
    let wasm =
        Project::cargo_bin_maybe_from_env("subnet-memory-test-canister", &[]).bytes();

    // Generate local environment and install canisters.
    let local_env = StateMachineBuilder::new()
        .with_subnet_id(LOCAL_SUBNET_ID)
        .with_subnet_type(SubnetType::Application)
        .with_routing_table(routing_table.clone())
        .build();
    let local_canister_ids = (0..local_canisters_count)
        .map(|_| install_canister(&local_env, wasm.clone()))
        .collect();

    // Generate remote environment and install canisters.
    let remote_env = StateMachineBuilder::new()
        .with_subnet_id(REMOTE_SUBNET_ID)
        .with_subnet_type(SubnetType::Application)
        .with_routing_table(routing_table.clone())
        .build();
    let remote_canister_ids = (0..remote_canisters_count)
        .map(|_| install_canister(&remote_env, wasm.clone()))
        .collect();

    (
        local_env.into(),
        local_canister_ids,
        remote_env.into(),
        remote_canister_ids,
    )
}

/// Installs a 'saturating-subnet-memory-test-canister' in `env`.
fn install_canister(env: &StateMachine, wasm: Vec<u8>) -> CanisterId {
    env.install_canister_with_cycles(wasm, Vec::new(), None, Cycles::new(u128::MAX / 2))
        .expect("Installing subnet-memory-test-canister failed")
}
/*
/// Queries the metrics from `canister` on the subnet `env`.
fn query_metrics(env: &StateMachine, canister: CanisterId) -> CanisterMetrics {
    let reply = env.query(canister, "metrics", vec![]).unwrap();
    Decode!(&reply.bytes(), CanisterMetrics).unwrap()
}

/// Calls `start` on `canister` on the subnet `env`.
fn call_start(env: &StateMachine, canister: CanisterId, config: CanisterConfig) -> String {
    let msg = Encode!(&config).unwrap();
    let reply = env.execute_ingress(canister, "start", msg).unwrap();
    Decode!(&reply.bytes(), String).unwrap()
}
*/
prop_compose! {
    fn arb_test_fixture(
        local_env_canister_count_range: RangeInclusive<usize>,
        remote_env_canister_count_range: RangeInclusive<usize>,
    )(
        local_env_canister_count in local_env_canister_count_range,
        remote_env_canister_count in remote_env_canister_count_range,
    ) -> (Arc<StateMachine>, Vec<CanisterId>, Arc<StateMachine>, Vec<CanisterId>) {
        new_fixture(local_env_canister_count, remote_env_canister_count)
    }
}


prop_compose! {
    fn arb_inter_canister_traffic(
        count: RangeInclusive<usize>,
        request_payload_bytes: RangeInclusive<u64>,
        response_payload_bytes: RangeInclusive<u64>,
        response_num_instructions: RangeInclusive<u64>,
    )(
        (request_payload_bytes, response_payload_bytes, response_num_instructions) in count
        .prop_flat_map(move |count| {
            (
                proptest::collection::vec(request_payload_bytes.clone(), count),
                proptest::collection::vec(response_payload_bytes.clone(), count),
                proptest::collection::vec(response_num_instructions.clone(), count),
            )
        })
    ) -> (Vec<NumBytes>, Vec<(NumBytes, NumInstructions)>) {
        (
            request_payload_bytes.into_iter().map(|bytes| bytes.into()).collect(),
            response_payload_bytes
                .into_iter()
                .zip(response_num_instructions.into_iter())
                .map(|(bytes, instructions)| (bytes.into(), instructions.into()))
                .collect(),
        )
    }
}

prop_compose! {
    fn arb_canister_configs(
        canister_ids: Vec<CanisterId>,
        count: RangeInclusive<usize>,
        request_payload_bytes: RangeInclusive<u64>,
        response_payload_bytes: RangeInclusive<u64>,
        response_num_instructions: RangeInclusive<u64>,
    )(
        configs in Just((canister_ids.clone(), canister_ids.clone()))
        .prop_flat_map(move |(senders, receivers)| {
            let mut request_payloads = Vec::<(NumBytes, CanisterId)>::new();
            for sender in senders {
                for receivers in receivers {
                    (request_payloads, response_payloads) in arb_inter_canister_traffic(
                        count.clone(),
                        request_payload_bytes.clone(),
                        response_payload_bytes.clone(),
                        response_num_instructions.clone(),
                    )
                }
            }
        })

            for _ in 0..count {
                
            }
            for receiver in receivers {
                
            }
        })
}



/*
prop_compose! {
    fn arb_canister_config(
        receivers: Vec<CanisterId>,
        params: CanisterConfigParams,
    )(
        requests_per_round in params.requests_per_round_range,
        (receivers, request_payloads) in params.request_count_range
        .prop_flat_map(move |request_count| {
            (
                proptest::collection::vec(proptest::sample::select(receivers.clone()), request_count),
                proptest::collection::vec(params.request_payload_range.clone(), request_count),
            )
        }),
        response_payloads in proptest::collection::vec(params.response_payload_range, params.response_count),
        instructions_count in proptest::collection::vec(params.instructions_count_range, params.response_count),
    ) -> CanisterConfig {
        CanisterConfig {
            requests_per_round: requests_per_round as u32,
            request_configs: request_payloads
                .into_iter()
                .zip(receivers.into_iter())
                .map(|(payload_bytes, receiver)| RequestConfig {
                    payload_bytes,
                    receiver,
                })
                .collect(),
            response_configs: response_payloads
                .into_iter()
                .zip(instructions_count.into_iter())
                .map(|(payload_bytes, instructions_count)| ResponseConfig {
                    payload_bytes,
                    instructions_count,
                })
                .collect(),
        }
    }
}

struct CanisterConfigParams {
    pub requests_per_round_range: RangeInclusive<usize>,
    pub request_count_range: RangeInclusive<usize>,
    pub request_payload_range: RangeInclusive<u32>,
    pub response_count: usize,
    pub response_payload_range: RangeInclusive<u32>,
    pub instructions_count_range: RangeInclusive<u64>,
}

const LOCAL_ENV_CANISTER_COUNT_RANGE: RangeInclusive<usize> = 1..=2;
const REMOTE_ENV_CANISTER_COUNT_RANGE: RangeInclusive<usize> = 1..=2;
const PARAMS: CanisterConfigParams = CanisterConfigParams {
    requests_per_round_range: 1..=10,
    request_count_range: 100..=200,
    request_payload_range: 0..=(2 * MB),
    response_count: 100,
    response_payload_range: 0..=(2 * MB),
    instructions_count_range: 0..=100_000_000,
};

#[test]
fn manual() {
    let (local_env, local_canister_ids, remote_env, remote_canister_ids) = new_fixture(2, 1);
    let config_1 = CanisterConfig {
        requests_per_round: 3,
        request_configs: vec![
            RequestConfig {
                payload_bytes: 100 * 1024,
                receiver: local_canister_ids[0],
            },
            RequestConfig {
                payload_bytes: 200 * 1024,
                receiver: local_canister_ids[1],
            },
            RequestConfig {
                payload_bytes: 150 * 1024,
                receiver: remote_canister_ids[0],
            },
        ],
        response_configs: vec![ResponseConfig {
            payload_bytes: 1 * 1024,
            instructions_count: 100_000_000_000,
        }],
    };
    call_start(&local_env, local_canister_ids[0], config_1);

    //    assert_eq!(0, 1, "{:#?}", local_env.get_latest_state().metadata.clone());
    local_env.tick();
    //    assert_eq!(0, 1, "{:#?}", local_env.get_latest_state().metadata.clone());
    let metrics = query_metrics(&local_env, local_canister_ids[0]);
    assert_eq!(None, Some(metrics));
}
*/
/*
proptest! {
    #![proptest_config(ProptestConfig::with_cases(1))]
    #[test]
    fn inter_canister_traffic_respects_memory_limits(
        (
            local_env,
            local_canister_ids,
            local_canister_configs,
            remote_env,
            remote_canister_ids,
            remote_canister_configs,
        ) in arb_test_fixture(LOCAL_ENV_CANISTER_COUNT_RANGE, REMOTE_ENV_CANISTER_COUNT_RANGE)
        .prop_flat_map(|(local_env, local_canister_ids, remote_env, remote_canister_ids)| {
            let receivers = local_canister_ids
                .iter()
                .chain(remote_canister_ids.iter())
                .cloned()
                .collect::<Vec<_>>();
            let local_canister_ids_len = local_canister_ids.len();
            let remote_canister_ids_len = remote_canister_ids.len();
            (
                Just(local_env),
                Just(local_canister_ids),
                proptest::collection::vec(arb_canister_config(receivers.clone(), PARAMS), local_canister_ids_len),
                Just(remote_env),
                Just(remote_canister_ids),
                proptest::collection::vec(arb_canister_config(receivers, PARAMS), remote_canister_ids_len),
            )
        })
    ) {
        for (canister_id, config) in local_canister_ids.iter().zip(local_canister_configs.into_iter()) {
            call_start(&local_env, *canister_id, config);
        }
        for (canister_id, config) in remote_canister_ids.iter().zip(remote_canister_configs.into_iter()) {
            call_start(&remote_env, *canister_id, config);
        }

        let mut last_local_state = local_env.get_latest_state();
        let mut last_remote_state = remote_env.get_latest_state();
        for _ in 0..30 {

            if let Ok(xnet_payload) = remote_env.generate_xnet_payload(
                local_env.get_subnet_id(),
                None,
                None,
                None,
                None,
            ) {
                local_env.execute_block_with_xnet_payload(xnet_payload);
            }

            if let Ok(xnet_payload) = local_env.generate_xnet_payload(
                remote_env.get_subnet_id(),
                None,
                None,
                None,
                None,
            ) {
                remote_env.execute_block_with_xnet_payload(xnet_payload);
            }

            let local_state = local_env.get_latest_state();
            let remote_state = remote_env.get_latest_state();
            if last_local_state.canister_states == local_state.canister_states && remote_state.canister_states == last_remote_state.canister_states {
                break;
            } else {
                last_local_state = local_state;
                last_remote_state = remote_state;
            }
        }
        assert_eq!(None, Some(last_local_state));
//        assert_eq!(None, Some(query_metrics(&local_env, local_canister_ids[0])));
    }
}
*/
