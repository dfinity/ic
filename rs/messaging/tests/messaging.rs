pub mod common;

use assert_matches::assert_matches;
use common::{
    MB, TestSubnet, TestSubnetConfig, TestSubnetSetup, arb_test_subnets, two_test_subnets,
};
use ic_config::message_routing::TARGET_STREAM_SIZE_BYTES;
use ic_error_types::RejectCode;
use ic_management_canister_types_private::CanisterStatusType;
use ic_types::{
    CanisterId, PrincipalId,
    ingress::{IngressState, IngressStatus},
    messages::{
        MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64, MessageId, RequestOrResponse, StreamMessage,
    },
};
use messaging_test::{Call, Response};
use messaging_test_utils::{CallConfig, arb_call};
use proptest::prelude::ProptestConfig;

const MAX_PAYLOAD_SIZE: usize = MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64 as usize;
const SYS_UNKNOWN_U32: u32 = RejectCode::SysUnknown as u32;

/// Tests that a canister with a hanging best-effort call can be stopped after the call has timed out.
#[test]
fn canister_can_be_stopped_with_hanging_call_on_stalled_subnet() {
    let (subnet1, subnet2) =
        two_test_subnets(TestSubnetConfig::default(), TestSubnetConfig::default());

    let canister1 = subnet1.principal_canister();
    let canister2 = subnet2.principal_canister();

    // Make `canister1` a best-effort call to `canister2` on `subnet2`.
    let msg_id = subnet1
        .submit_ingress(
            canister1,
            vec![Call {
                receiver: canister2,
                timeout_secs: Some(10),
                ..Call::default()
            }],
        )
        .unwrap();

    // Two rounds should be enough to route the call.
    subnet1.execute_round();
    subnet1.execute_round();
    // Put `canister1` into `Stopping` state.
    subnet1.env.stop_canister_non_blocking(canister1);
    subnet1.execute_round();
    // Advance time and execute another round; this should time out the downstream call
    // and allow the ingress to conclude.
    subnet1.advance_time_by_secs(100);
    subnet1.execute_round();

    // The downstream call was timed out...
    assert_matches!(
        subnet1.try_get_response(&msg_id),
        Ok(Response::Success {
            downstream_responses,
            ..
        }) if matches!(downstream_responses[..], [Response::AsyncReject {
            reject_code: SYS_UNKNOWN_U32,
            ..
        }])
    );
    // ...and the canister was stopped.
    assert_eq!(
        subnet1.canister_status(&canister1),
        Some(CanisterStatusType::Stopped)
    );
}

/// Tests that requests stuck in output queues are timed out, but backpressure remains
/// if there is a response stuck in the front.
#[test]
fn test_requests_are_timed_out_in_output_queues_but_backpressure_remains() {
    let (subnet1, subnet2) =
        two_test_subnets(TestSubnetConfig::default(), TestSubnetConfig::default());

    let canister1 = subnet1.principal_canister();
    let canister2 = subnet2.principal_canister();

    // Send enough small requests that will produce maximum size responses to fill
    // up the reverse stream and leave at least one in the output queue of `canister`.
    const NUM_CALLS: usize = TARGET_STREAM_SIZE_BYTES / MAX_PAYLOAD_SIZE + 2;
    for _ in 0..NUM_CALLS {
        subnet2
            .submit_ingress(
                canister2,
                vec![Call {
                    receiver: canister1,
                    reply_bytes: MAX_PAYLOAD_SIZE as u32,
                    ..Call::default()
                }],
            )
            .unwrap();
        subnet2.execute_round();
    }

    // Pull the requests and execute them producing large responses; filling up the stream.
    while let None | Some([]) = subnet1
        .output_queue_snapshot(canister1, canister2)
        .as_deref()
    {
        subnet1.execute_round();
    }

    // Send lots of small requests to `canister2` on `canister1` to fill up the output queue;
    // continuously time them out. Note: the output queue capacity for requests is 500.
    for _ in 0..10 {
        subnet1
            .submit_ingress(
                canister1,
                vec![
                    Call {
                        receiver: canister2,
                        ..Call::default()
                    };
                    100
                ],
            )
            .unwrap();
        subnet1.execute_round();
        subnet1.advance_time_by_secs(3600);
    }

    // In each iteration we timed out the requests of the previous round;
    // then pushed 100 new ones. Due to backpressure pushing new ones should
    // fail after some rounds resulting in an output queue of just responses.
    assert!(
        subnet1
            .output_queue_snapshot(canister1, canister2)
            .unwrap()
            .iter()
            .all(|msg| matches!(msg, RequestOrResponse::Response(_)))
    );
}

/// Config used for `test_memory_accounting_and_sequence_errors`.
const MEMORY_ACCOUNTING_CONFIG: TestSubnetConfig = TestSubnetConfig {
    canisters_count: 2,
    max_instructions_per_round: 3_000_000_000,
    guaranteed_response_message_memory_capacity: 30 * MB as u64,
    best_effort_message_memory_capacity: 30 * MB as u64,
};

/// Tests the memory accounting is upheld during random traffic at all times.
/// Also check the outcome of each ingress trigger to make sure there are no
/// sequencing error and sync rejections due to out of memory actually occurred.
///
/// Ingress triggers are only sent to the principal canister on `subnet1`, which
/// will then send downstream calls to all canisters. Through downstream calls,
/// random calls going every which way is established after a few rounds.
#[test_strategy::proptest(ProptestConfig::with_cases(3))]
fn test_memory_accounting_and_sequence_errors(
    #[strategy(arb_test_subnets(MEMORY_ACCOUNTING_CONFIG.clone(), TestSubnetConfig::default()))]
    setup: TestSubnetSetup,

    #[strategy(proptest::collection::vec(arb_call(
        #setup.subnet1.principal_canister(),
        CallConfig {
            receivers: #setup.canisters,
            call_bytes_range: 0..=MAX_PAYLOAD_SIZE,
            reply_bytes_range: 0..=MAX_PAYLOAD_SIZE,
            best_effort_percentage: 50,
            timeout_secs_range: 300..=300,
            downstream_calls_percentage: 20,
            downstream_calls_count_range: 2..=5,
            max_total_calls: 10,
        }
    ), 10))]
    calls: Vec<Call>,
) {
    let (subnet1, subnet2, _) = setup.into_parts();

    // Submit all the calls into the ingress pool.
    let mut msg_ids: Vec<MessageId> = calls
        .into_iter()
        .map(|call| subnet1.submit_call_as_ingress(call).unwrap())
        .collect();

    // Execute rounds on both subnets; check memory accounting in each iteration.
    for _ in 0..100 {
        subnet1.execute_round();
        subnet2.execute_round();

        let state = subnet1.env.get_latest_state();
        let memory_taken = state.guaranteed_response_message_memory_taken().get();
        assert!(
            memory_taken <= MEMORY_ACCOUNTING_CONFIG.guaranteed_response_message_memory_capacity,
            "computed guaranteed response message memory: {} exceeds the capacity: {}",
            memory_taken,
            MEMORY_ACCOUNTING_CONFIG.guaranteed_response_message_memory_capacity
        );
        let memory_taken = state.best_effort_message_memory_taken().get();
        assert!(
            memory_taken <= MEMORY_ACCOUNTING_CONFIG.best_effort_message_memory_capacity,
            "computed best-effort message memory: {} exceeds the capacity: {}",
            memory_taken,
            MEMORY_ACCOUNTING_CONFIG.best_effort_message_memory_capacity,
        );

        // Collect responses; check for traps which indicates a sequence error; keep Ids awaited.
        msg_ids = msg_ids
            .into_iter()
            .filter(|msg_id| match subnet1.try_get_response(msg_id) {
                Ok(response) => {
                    response.for_each_depth_first(|response, _| {
                        if let Response::AsyncReject { reject_message, .. } = response {
                            assert!(!reject_message.contains("trapped"));
                        }
                    });
                    false
                }
                Err(_) => {
                    // Still awaiting, keep the Id.
                    true
                }
            })
            .collect();

        if msg_ids.is_empty() {
            // All calls have concluded; stop executing.
            break;
        }
    }
}

/*
#[test_strategy::proptest(ProptestConfig::with_cases(3))]
fn bla(
    #[strategy(arb_test_subnets(TestSubnetConfig::default(), TestSubnetConfig::default()))]
    setup: TestSubnetSetup,

    #[strategy(proptest::collection::vec(arb_call(CallConfig {
        receivers: #setup.canisters,
        ..CallConfig::default()
    }), 20))]
    calls: Vec<Call>,
) {
    let (subnet1, subnet2, _) = setup.into_parts();

    assert!(false);
}
*/

/*
/// Tests that reject signals for requests are forwarded (as reject responses) to a canister
/// that moved to a different subnet due to a subnet split.
///
/// The canister makes calls to different canister on a different subnet that is stopped,
/// thereby they are all rejected through reject signals; then the canister is moved to different
/// subnet through a subnet split.
///
/// Checks all calls eventually conclude, implying proper forwarding.
#[test]
fn reject_signals_for_requests_are_forwarded_after_subnet_split() {
    let (subnet1, subnet2) = two_test_subnets(
        TestSubnetConfig {
            canisters_count: 2,
            ..TestSubnetConfig::default()
        },
        TestSubnetConfig::default(),
    );

    let canister1 = subnet1.principal_canister();
    let canister2 = subnet2.principal_canister();

    // A call to be sent to `canister1` as ingress which will then
    // make a downstream call to `canister2`.
    let call = Call {
        receiver: canister1,
        downstream_calls: vec![Call {
            receiver: canister2,
            ..Call::default()
        }],
        ..Call::default()
    };

    // Put `canister2` into `Stopped` state.
    subnet2.env.stop_canister_non_blocking(canister2);
    subnet2.execute_round();
    assert_eq!(
        subnet2.canister_status(&canister2),
        Some(CanisterStatusType::Stopped)
    );

    // Submit `call` to `canister1` then make sure the downstream call is routed.
    let msg_id = subnet1.submit_call(call).unwrap();
    subnet1.execute_round();
    assert_matches!(
        subnet1.stream_snapshot(subnet2.id()),
        Some((_, msgs)) if matches!(msgs[..], [StreamMessage::Request(_)])
    );

    // Split `subnet1`, moving `canister1` to the new subnet.
    let subnet3 = subnet1.split(canister1..=canister1).unwrap();
    assert!(!subnet1.has_canister(&canister1));
    assert!(subnet3.has_canister(&canister1));

    // Put `canister1` into `Stopping` state.
    subnet2.env.stop_canister_non_blocking(canister2);

    // Pull from `subnet1`, rejecting the request.
    subnet2.execute_round();
    // Pull from `subnet2`, producing a reject response, routing it to `subnet3`.
    subnet1.execute_round();
    // Pull from `subnet1`, concluding the call.
    subnet3.execute_round();
}
*/

/*
#[test_strategy::proptest(ProptestConfig::with_cases(3))]
fn check_message_memory_limits_are_respected(
    #[strategy(proptest::collection::vec(any::<u64>().no_shrink(), 3))] seeds: Vec<u64>,
    #[strategy(arb_canister_config(MAX_PAYLOAD_BYTES, 5))] config: CanisterConfig,
) {
    if let Err((err_msg, nfo)) = check_message_memory_limits_are_respected_impl(
        30,  // chatter_phase_round_count
        300, // shutdown_phase_max_rounds
        seeds.as_slice(),
        config,
    ) {
        unreachable!("\nerr_msg: {err_msg}\n{:#?}", nfo.records);
    }
}

/// Runs a state machine test with two subnets, a local subnet with 2 canisters installed and a
/// remote subnet with 1 canister installed.
///
/// In the first phase `chatter_phase_round_count` rounds are executed on both subnets, including XNet
/// traffic with 'chatter' enabled, i.e. the installed canisters are making random calls (including
/// downstream calls depending on `config`).
///
/// For the second phase, the 'chatter' is disabled by putting a canister into `Stopping` state
/// every 10 rounds. In addition to shutting down traffic altogether from that canister (including
/// downstream calls) this will also induce a lot asynchronous rejections for requests. If any
/// canister fails to reach `Stopped` state (i.e. no pending calls), something went wrong in
/// message routing, most likely a bug connected to reject signals for requests.
///
/// In the final phase, up to `shutdown_phase_max_rounds` additional rounds are executed after
/// 'chatter' has been turned off to conclude all calls (or else return `Err(_)` if any call fails
/// to do so).
///
/// During all these phases, a check ensures that neither guaranteed response nor best-effort message
/// memory usage exceed the limits imposed on the respective subnets.
fn check_message_memory_limits_are_respected_impl(
    chatter_phase_round_count: usize,
    shutdown_phase_max_rounds: usize,
    seeds: &[u64],
    mut config: CanisterConfig,
) -> Result<(), (String, DebugInfo)> {
    // Limit imposed on both guaranteed response and best-effort message memory on `local_env`.
    const LOCAL_MESSAGE_MEMORY_CAPACITY: u64 = 100 * MB;
    // Limit imposed on both guaranteed response and best-effort message memory on `remote_env`.
    const REMOTE_MESSAGE_MEMORY_CAPACITY: u64 = 50 * MB;

    let subnets = SubnetPair::new(SubnetPairConfig {
        local_canisters_count: 2,
        local_message_memory_capacity: LOCAL_MESSAGE_MEMORY_CAPACITY,
        remote_canisters_count: 1,
        remote_message_memory_capacity: REMOTE_MESSAGE_MEMORY_CAPACITY,
        ..SubnetPairConfig::default()
    });

    config.receivers = subnets.canisters();

    // Send configs to canisters, seed the rng.
    for (index, canister) in subnets.canisters().into_iter().enumerate() {
        subnets.set_config(canister, config.clone());
        subnets.seed_rng(canister, seeds[index]);
    }

    // Build up backlog and keep up chatter for while.
    for _ in 0..chatter_phase_round_count {
        subnets.tick();

        // Check message memory limits are respected.
        subnets.expect_message_memory_taken_at_most(
            "Chatter",
            LOCAL_MESSAGE_MEMORY_CAPACITY,
            REMOTE_MESSAGE_MEMORY_CAPACITY,
        )?;
    }

    // Shut down chatter by putting a canister into `Stopping` state every 10 ticks until they are
    // all `Stopping` or `Stopped`.
    for canister in subnets.canisters().into_iter() {
        subnets.stop_chatter(canister);
        subnets.stop_canister_non_blocking(canister);
        for _ in 0..10 {
            subnets.tick();

            // Check message memory limits are respected.
            subnets.expect_message_memory_taken_at_most(
                "Shutdown",
                LOCAL_MESSAGE_MEMORY_CAPACITY,
                REMOTE_MESSAGE_MEMORY_CAPACITY,
            )?;
        }
    }

    // Tick until all calls have concluded; or else fail the test.
    subnets.tick_to_conclusion(shutdown_phase_max_rounds, || {
        subnets.expect_message_memory_taken_at_most(
            "Wrap up",
            LOCAL_MESSAGE_MEMORY_CAPACITY,
            REMOTE_MESSAGE_MEMORY_CAPACITY,
        )
    })
}
*/

/*
#[test_strategy::proptest(ProptestConfig::with_cases(3))]
fn bla(
    #[strategy(arb_test_subnets(TestSubnetConfig::default(), TestSubnetConfig::default()))]
    setup: TestSubnetSetup,

    #[strategy(proptest::collection::vec(arb_call(CallConfig {
        receivers: #setup.canisters,
        ..CallConfig::default()
    }), 20))]
    calls: Vec<Call>,
) {
    let (subnet1, subnet2, _) = setup.into_parts();

    assert!(false);
}
*/
