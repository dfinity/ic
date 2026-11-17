use candid::Encode;
use ic_base_types::{CanisterId, PrincipalId};
use ic_config::{
    execution_environment::Config as HypervisorConfig,
    subnet_config::{SchedulerConfig, SubnetConfig},
};
use ic_management_canister_types_private::{CanisterIdRecord, IC_00, Method};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::canister_state::system_state::ConnectionMetrics;
use ic_state_machine_tests::{StateMachine, StateMachineBuilder, StateMachineConfig, WasmResult};
use ic_test_utilities_metrics::fetch_int_counter_vec;
use ic_types::NumInstructions;
use ic_types::ingress::IngressStatus;
use ic_types_cycles::Cycles;
use ic_universal_canister::{
    UNIVERSAL_CANISTER_NO_HEARTBEAT_WASM, UNIVERSAL_CANISTER_WASM, call_args, wasm,
};
use maplit::btreemap;
use std::collections::BTreeMap;

const INITIAL_CYCLES_BALANCE: Cycles = Cycles::new(100_000_000_000_000);

#[test]
fn scheduler_observes_inducted_messages_to_self() {
    let sm = StateMachine::new();

    let a_id = sm
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.to_vec(),
            vec![],
            None,
            INITIAL_CYCLES_BALANCE,
        )
        .unwrap();

    // Canister A calls self
    let a_calls_self_wasm = wasm().inter_update(a_id, call_args()).build();
    let ingress_id = sm.send_ingress(
        PrincipalId::new_anonymous(),
        a_id,
        "update",
        a_calls_self_wasm,
    );

    assert!(matches!(
        sm.ingress_status(&ingress_id),
        IngressStatus::Known { .. }
    ));

    let inducted_messages =
        fetch_int_counter_vec(sm.metrics_registry(), "scheduler_inducted_messages_total");
    let destination_self = btreemap! {
        "destination".into() => "self".into(),
    };
    // Call and reply
    assert_eq!(2, inducted_messages[&destination_self]);
}

#[test]
fn scheduler_observes_inducted_messages_to_others() {
    let sm = StateMachine::new();

    let a_id = sm
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.to_vec(),
            vec![],
            None,
            INITIAL_CYCLES_BALANCE,
        )
        .unwrap();
    let b_id = sm
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.to_vec(),
            vec![],
            None,
            INITIAL_CYCLES_BALANCE,
        )
        .unwrap();

    // Canister A calls canister B
    let a_calls_b_wasm = wasm().inter_update(b_id, call_args()).build();
    let ingress_id = sm.send_ingress(PrincipalId::new_anonymous(), a_id, "update", a_calls_b_wasm);

    assert!(matches!(
        sm.ingress_status(&ingress_id),
        IngressStatus::Known { .. }
    ));

    let inducted_messages =
        fetch_int_counter_vec(sm.metrics_registry(), "scheduler_inducted_messages_total");
    let destination_others = btreemap! {
        "destination".into() => "others".into(),
    };
    // Call and reply
    assert_eq!(2, inducted_messages[&destination_others]);
}

/// Checks that every request from a canister on the same subnet is recorded in the
/// receiver's connection metrics (keyed by sender) in the round in which it is
/// executed, including requests that survive the round in which they were sent and
/// are only executed in a later round. Requests to the management canister are not
/// recorded.
#[test]
fn connection_metrics_record_every_subnet_local_request_when_executed() {
    const NUM_REQUESTS: usize = 10;
    const INSTRUCTIONS_PER_REQUEST: u64 = 10_000_000;

    // Only leave room for executing a few of the requests per round, so that the
    // others survive into later rounds. The scheduler stops starting new executions
    // once all but one slice worth of the round's instructions are used up.
    let subnet_config = SubnetConfig::new(SubnetType::Application);
    let max_instructions_per_slice = std::cmp::max(
        subnet_config.scheduler_config.max_instructions_per_slice,
        subnet_config
            .scheduler_config
            .max_instructions_per_install_code_slice,
    );
    let subnet_config = SubnetConfig {
        scheduler_config: SchedulerConfig {
            max_instructions_per_round: max_instructions_per_slice
                + NumInstructions::from(3 * INSTRUCTIONS_PER_REQUEST),
            instruction_overhead_per_execution: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            instruction_overhead_per_canister_for_finalization: NumInstructions::from(0),
            ..subnet_config.scheduler_config
        },
        ..subnet_config
    };
    let env = StateMachineBuilder::new()
        .with_config(Some(StateMachineConfig::new(
            subnet_config,
            HypervisorConfig::default(),
        )))
        .with_subnet_type(SubnetType::Application)
        .build();

    let install_canister = || {
        env.install_canister_with_cycles(
            UNIVERSAL_CANISTER_NO_HEARTBEAT_WASM.to_vec(),
            vec![],
            None,
            INITIAL_CYCLES_BALANCE,
        )
        .unwrap()
    };
    let a_id = install_canister();
    let b_id = install_canister();

    // Canister A sends `NUM_REQUESTS` requests to canister B, then deposits cycles to B
    // through the management canister, replying to the ingress message once that's done.
    let b_work = wasm()
        .instruction_counter_is_at_least(INSTRUCTIONS_PER_REQUEST)
        .reply()
        .build();
    let mut a_payload = wasm();
    for _ in 0..NUM_REQUESTS {
        a_payload = a_payload.inter_update(
            b_id,
            call_args()
                .other_side(b_work.clone())
                .on_reply(wasm().noop())
                .on_reject(wasm().noop()),
        );
    }
    let a_payload = a_payload
        .call_with_cycles(
            IC_00,
            Method::DepositCycles,
            call_args()
                .other_side(Encode!(&CanisterIdRecord::from(b_id)).unwrap())
                .on_reply(wasm().reply_data(b"deposited"))
                .on_reject(wasm().reject_message().reject()),
            1_000_u128,
        )
        .build();

    // Returns the connection metrics of the given canister.
    let connection_metrics = |canister_id: CanisterId| {
        env.get_latest_state()
            .canister_state(&canister_id)
            .unwrap()
            .system_state
            .canister_metrics()
            .connection_metrics()
            .get()
            .clone()
    };
    // Returns the number of A's requests that B executed so far. B has no other inputs,
    // and A's requests are all inducted into B's input queue in the round in which
    // they are sent.
    let executed_requests = || {
        let pending_requests = env
            .get_latest_state()
            .canister_state(&b_id)
            .unwrap()
            .system_state
            .queues()
            .input_queues_message_count();
        NUM_REQUESTS - pending_requests
    };
    let expected_connection_metrics = |executed_requests: usize| {
        btreemap! {
            a_id => ConnectionMetrics {
                last_access_timestamp: env.get_time(),
                count: executed_requests as u64,
            },
        }
    };

    // Executes a round, in which A sends its requests and B executes some of them.
    let ingress_id = env.send_ingress(PrincipalId::new_anonymous(), a_id, "update", a_payload);
    let mut executed = executed_requests();
    assert!(
        0 < executed && executed < NUM_REQUESTS,
        "B should execute some, but not all requests in the first round, executed {executed}"
    );
    assert_eq!(
        connection_metrics(b_id),
        expected_connection_metrics(executed)
    );

    // The requests that survived the previous round are recorded in the round in which
    // they are executed.
    while executed < NUM_REQUESTS {
        env.tick();
        let executed_before = executed;
        executed = executed_requests();
        assert!(
            executed > executed_before,
            "B should execute some of the remaining requests in every round"
        );
        assert_eq!(
            connection_metrics(b_id),
            expected_connection_metrics(executed)
        );
    }
    let b_connection_metrics = connection_metrics(b_id);

    // The management canister deposited cycles to B.
    let result = env.await_ingress(ingress_id, 10);
    assert_eq!(result, Ok(WasmResult::Reply(b"deposited".to_vec())));

    // Neither A's request to the management canister, nor the management canister
    // depositing cycles to B were recorded.
    assert_eq!(connection_metrics(b_id), b_connection_metrics);
    assert_eq!(connection_metrics(a_id), BTreeMap::new());
}
