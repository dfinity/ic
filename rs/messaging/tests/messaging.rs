pub mod common;

use assert_matches::assert_matches;
use common::{
    MB, TestSubnet, TestSubnetConfig, TestSubnetSetup, arb_test_subnets, check_for_traps,
    two_test_subnets,
};
use ic_config::message_routing::TARGET_STREAM_SIZE_BYTES;
use ic_error_types::RejectCode;
use ic_management_canister_types_private::CanisterStatusType;
use ic_test_utilities_metrics::{HistogramStats, fetch_histogram_vec_stats, metric_vec};
use ic_types::messages::{MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64, MessageId, RequestOrResponse};
use messaging_test::{Call, Reply};
use messaging_test_utils::{CallConfig, arb_call};
use proptest::prelude::*;

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
                receiver: canister2.into(),
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
        subnet1.try_get_reply(&msg_id),
        Ok(Reply::Success {
            downstream_replies,
            ..
        }) if matches!(downstream_replies[..], [Reply::AsyncReject {
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
                    receiver: canister1.into(),
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
                        receiver: canister2.into(),
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

/// Tests that the call tree metrics produce the expected result for a hardcoded specific call,
/// that includes calls to self, XNet calls back and forth (to test that the call depth is tranferred)
/// and calls to the other canister on the same subnet. This should include every scenario.
#[test]
fn test_call_tree_metrics() {
    let two_canisters_config = TestSubnetConfig {
        canisters_count: 2,
        ..TestSubnetConfig::default()
    };
    let (subnet1, subnet2) = two_test_subnets(two_canisters_config.clone(), two_canisters_config);

    let [canister1, canister2] = subnet1.canisters()[..] else {
        unreachable!();
    };
    let [canister3, canister4] = subnet2.canisters()[..] else {
        unreachable!();
    };

    // A call tree that includes self calls, XNet calls back and forth and calls to canisters on the same subnet.
    //
    // call_depth                    call tree
    //
    //     3                   C1        .
    //                        /          .
    //                       /           .
    //     2               C2            .                C4
    //                      \_________________________   /
    //                                   .            \ /
    //     1               C2            .            C3
    //                     |      ___________________/
    //                     |     /       .
    //     0              C2    C1       .
    //                     \    |        .
    //                      \   |        .
    //     -             ingress to C1   .
    // ------------------------------------------------------
    //                     Subnet1       .       Subnet2
    //

    // The subtree starting at C3 on `subnet2`.
    let calls_made_on_subnet2 = vec![
        // The left arm.
        Call {
            receiver: canister2.into(),
            downstream_calls: vec![Call {
                receiver: canister1.into(),
                ..Call::default()
            }],
            ..Call::default()
        },
        // The right arm.
        Call {
            receiver: canister4.into(),
            ..Call::default()
        },
    ];

    // The tree starting as an ingress to C1 on `subnet1`.
    let msg_id = subnet1
        .submit_ingress(
            canister1,
            vec![
                // The left arm.
                Call {
                    receiver: canister2.into(),
                    downstream_calls: vec![Call {
                        receiver: canister2.into(),
                        ..Call::default()
                    }],
                    ..Call::default()
                },
                // The right arm.
                Call {
                    receiver: canister1.into(),
                    downstream_calls: vec![
                        // Calling into `subnet2`.
                        Call {
                            receiver: canister3.into(),
                            downstream_calls: calls_made_on_subnet2,
                            ..Call::default()
                        },
                    ],
                    ..Call::default()
                },
            ],
        )
        .unwrap();

    // Execute until all calls complete.
    while subnet1.try_get_reply(&msg_id).is_err() {
        subnet1.execute_round();
        subnet2.execute_round();
    }

    // Check call tree metrics on `subnet1` correspond to the tree above.
    let stats = fetch_histogram_vec_stats(
        subnet1.env.metrics_registry(),
        "execution_environment_request_call_tree_depth",
    );
    assert_eq!(
        metric_vec(&[(
            &[("class", "guaranteed response")],
            HistogramStats {
                count: 5,   // In total 5 calls are made on `subnet1`,
                sum: 5_f64, // two on depth 0, two on depth 1, one on depth 3, i.e. 0+0+1+1+3
            }
        )]),
        stats
    );

    // Check call tree metrics on `subnet2` correspond to the tree above.
    let stats = fetch_histogram_vec_stats(
        subnet2.env.metrics_registry(),
        "execution_environment_request_call_tree_depth",
    );
    assert_eq!(
        metric_vec(&[(
            &[("class", "guaranteed response")],
            HistogramStats {
                count: 2,   // In total 2 calls are made on `subnet2`,
                sum: 4_f64, // both at call depth 2, i.e. 2+2
            }
        )]),
        stats
    );
}

/// Config used for `test_memory_accounting_and_sequence_errors`.
const MEMORY_ACCOUNTING_CONFIG: TestSubnetConfig = TestSubnetConfig {
    canisters_count: 2,
    max_instructions_per_round: 3_000_000_000,
    guaranteed_response_message_memory_capacity: 20 * MB as u64,
    best_effort_message_memory_capacity: 20 * MB as u64,
};

/// Tests the memory accounting is upheld during random traffic at all times.
/// Also check the outcome of each ingress trigger to make sure there are no
/// sequencing errors.
///
/// Ingress triggers are only sent to the principal canister on `subnet1`, which
/// will then send downstream calls to all canisters. Through downstream calls,
/// random calls going every which way is established after a few rounds.
#[test_strategy::proptest(ProptestConfig::with_cases(3), max_shrink_iters = 0)]
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
            downstream_calls_percentage: 66,
            downstream_calls_count_range: 1..=3,
            call_tree_size: 10,
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
    while !msg_ids.is_empty() {
        subnet1.execute_round();
        subnet2.execute_round();

        let state = subnet1.env.get_latest_state();
        let memory_taken = state.guaranteed_response_message_memory_taken().get();
        prop_assert!(
            memory_taken <= MEMORY_ACCOUNTING_CONFIG.guaranteed_response_message_memory_capacity,
            "computed guaranteed response message memory: {} exceeds the capacity: {}",
            memory_taken,
            MEMORY_ACCOUNTING_CONFIG.guaranteed_response_message_memory_capacity
        );
        let memory_taken = state.best_effort_message_memory_taken().get();
        prop_assert!(
            memory_taken <= MEMORY_ACCOUNTING_CONFIG.best_effort_message_memory_capacity,
            "computed best-effort message memory: {} exceeds the capacity: {}",
            memory_taken,
            MEMORY_ACCOUNTING_CONFIG.best_effort_message_memory_capacity,
        );

        // Filter out completed calls, checking that there were no traps.
        msg_ids = subnet1.check_and_drop_completed(msg_ids, &check_for_traps);
    }
}

/// Tests that all cyclws attached to best-effort calls are eventually refunded.
///
/// For this, we attach huge amounts of cycles to every call (orders of
/// magnitude larger than the cost of making and executing the actual calls) and
/// check that after all calls have completed, the canisters' total balance
/// returns to the initial amount (modulo the costs of the calls themselves).
#[test_strategy::proptest(ProptestConfig::with_cases(3), max_shrink_iters = 0)]
fn test_guaranteed_refunds(
    #[strategy(arb_test_subnets(MEMORY_ACCOUNTING_CONFIG.clone(), TestSubnetConfig {
        canisters_count: 2,  // Local and remote calls.
        max_instructions_per_round: 10_000,  // Build up a backlog of calls.
        ..TestSubnetConfig::default()
    }))]
    setup: TestSubnetSetup,

    #[strategy(proptest::collection::vec(arb_call(
        #setup.subnet1.principal_canister(),
        CallConfig {
            receivers: #setup.canisters,
            call_bytes_range: 0..=0,  // Don't care about payloads.
            reply_bytes_range: 0..=0,
            best_effort_percentage: 90,  // Throw in some guaranteed calls, just in case.
            timeout_secs_range: 1..=50,  // Make sure that at least some calls time out.
            downstream_calls_percentage: 50,
            downstream_calls_count_range: 1..=3,
            call_tree_size: 10,
        }
    ), 10))]
    calls: Vec<Call>,
) {
    fn compute_total_cycles(subnet: &TestSubnet) -> u128 {
        subnet
            .canisters()
            .iter()
            .map(|canister| subnet.env.cycle_balance(*canister))
            .sum()
    }

    let (subnet1, subnet2, _) = setup.into_parts();
    let cycles_before = compute_total_cycles(&subnet1) + compute_total_cycles(&subnet2);

    // Submit all the calls into the ingress pool.
    let mut msg_ids: Vec<MessageId> = calls
        .into_iter()
        .map(|call| subnet1.submit_call_as_ingress(call).unwrap())
        .collect();

    // Execute rounds on both subnets; check memory accounting in each iteration.
    while !msg_ids.is_empty() || subnet1.has_inflight_messages() || subnet2.has_inflight_messages()
    {
        subnet1.execute_round();
        subnet2.execute_round();

        // Filter out completed calls, checking that there were no traps.
        msg_ids = subnet1.check_and_drop_completed(msg_ids, &check_for_traps);
    }

    let cycles_after = compute_total_cycles(&subnet1) + compute_total_cycles(&subnet2);
    prop_assert!(
        cycles_before >= cycles_after,
        "Too many cycles refunded: before = {cycles_before}, after = {cycles_after}"
    );
    // TODO(MR-730): Enable this check once refunds are being routed.
    // prop_assert!(
    //     cycles_before - cycles_after < 1_000_000_000,
    //     "More than 1B cycles lost: before = {cycles_before}, after = {cycles_after}"
    // );
}

/// Tests that all calls are concluded successfully during subnet splitting and whilst upholding
/// ordering guarantees.
///
/// The setup is one subnet with two canisters; this is the subnet that will undergo the split;
/// and another subnet with one canister. All canisters produce random traffic to all the other
/// canisters.
///
/// The changes reflecting the subnet split are made up front, but the registry in either subnet
/// is updated only later at a random index through the split of `subnet1` and at a different
/// random index through a regular registry update to the newest version on `subnet2`.
///
/// These two random indices produce all the cases relevant for subnet splitting:
/// - `subnet1` splits before `subnet2` observes the changes in the registry.
/// - `subnet2` observed the changes on the registry before `subnet1` splits, i.e. before
///    the new `subnet3` even exists (but is referred to in the routing table).
/// -  The two events happen in the same round.
///
/// After both these events have occurred a few more calls are made. If after some more rounds
/// all calls conclude (without any canister trapping which indicates a sequencing error)
/// and the canisters can be stopped, correct routing is implied because hanging calls would
/// prevent stopping at least one canister and no sequencing errors have occurred.
#[test_strategy::proptest(ProptestConfig::with_cases(3), max_shrink_iters = 0)]
fn subnet_splitting_smoke_test(
    #[strategy(arb_test_subnets(
        TestSubnetConfig { canisters_count: 2, ..TestSubnetConfig::default() },
        TestSubnetConfig::default()
    ))]
    setup: TestSubnetSetup,

    #[strategy(
        Just(#setup.canisters)
        .prop_flat_map(|canisters| {
            let config = CallConfig {
                receivers: canisters.clone(),
                call_bytes_range: 0..=0,
                reply_bytes_range: 0..=0,
                call_tree_size: 10,
                ..CallConfig::default()
            };
            (
                proptest::collection::vec(arb_call(canisters[0], config.clone()), 5),
                proptest::collection::vec(arb_call(canisters[1], config.clone()), 5),
                proptest::collection::vec(arb_call(canisters[2], config.clone()), 5),
            )
        })
    )]
    calls: (Vec<Call>, Vec<Call>, Vec<Call>),

    #[strategy(5..=10_usize)] subnet1_split_index: usize,

    #[strategy(5..=10_usize)] subnet2_routing_table_update_index: usize,
) {
    const SEED: [u8; 32] = [123; 32];

    let (subnet1, subnet2, _) = setup.into_parts();
    let (mut calls1, mut calls2, mut calls3) = calls;
    let [canister1, canister2] = subnet1.canisters()[..] else {
        unreachable!("{:?}", subnet1.canisters());
    };
    let canister3 = subnet2.principal_canister();

    // Inject triggers into the ingress pool; keep 2 for after the split / routing table update.
    let inject_calls =
        |calls: &mut Vec<Call>, retain: usize, subnet: &TestSubnet| -> Vec<MessageId> {
            calls
                .split_off(retain)
                .into_iter()
                .map(|call| subnet.submit_call_as_ingress(call).unwrap())
                .collect()
        };
    let mut msg_ids1 = inject_calls(&mut calls1, 2, &subnet1);
    let mut msg_ids2 = inject_calls(&mut calls2, 2, &subnet1);
    let mut msg_ids3 = inject_calls(&mut calls3, 2, &subnet2);

    // Make the registry changes for the split in the data provider; Not yet visible on either subnet.
    subnet1
        .env
        .make_registry_entries_for_subnet_split(SEED, canister2..=canister2);

    // Execute rounds; split / update the routing table at the given index.
    let mut subnet3: Option<TestSubnet> = None;
    for round_index in 0..=15 {
        if round_index == subnet1_split_index {
            subnet3 = Some(subnet1.split(SEED).unwrap());
            assert_matches!(subnet1.canisters()[..], [c] if c == canister1);
            assert_matches!(subnet3.as_ref().unwrap().canisters()[..], [c] if c == canister2);
        }
        if round_index == subnet2_routing_table_update_index {
            subnet2.env.reload_registry();
            subnet2.env.registry_client.update_to_latest_version();
        }

        subnet1.execute_round();
        subnet2.execute_round();
        if let Some(ref subnet3) = subnet3 {
            subnet3.execute_round();
        }
    }

    // Inject the rest of the calls; note that `canister2` is now on `subnet3`.
    let subnet3 = subnet3.unwrap();
    msg_ids1.append(&mut inject_calls(&mut calls1, 0, &subnet1));
    msg_ids2.append(&mut inject_calls(&mut calls2, 0, &subnet3));
    msg_ids3.append(&mut inject_calls(&mut calls3, 0, &subnet2));

    while !msg_ids1.is_empty()
        || !msg_ids2.is_empty()
        || !msg_ids3.is_empty()
        || subnet1.has_inflight_messages()
        || subnet2.has_inflight_messages()
        || subnet3.has_inflight_messages()
    {
        subnet1.execute_round();
        subnet2.execute_round();
        subnet3.execute_round();

        msg_ids1 = subnet1.check_and_drop_completed(msg_ids1, &check_for_traps);
        msg_ids2 = subnet3.check_and_drop_completed(msg_ids2, &check_for_traps);
        msg_ids3 = subnet2.check_and_drop_completed(msg_ids3, &check_for_traps);
    }

    // All calls have concluded without trapping; we should be able to stop them now.
    subnet1.env.stop_canister(canister1).unwrap();
    subnet2.env.stop_canister(canister3).unwrap();
    subnet3.env.stop_canister(canister2).unwrap();
}

/// Tests that all calls are concluded successfully during subnet splitting,
/// whilst upholding ordering guarantees.
///
/// The setup is one subnet with two canisters; this is the subnet that will
/// undergo the split; and another subnet with one canister. All canisters
/// produce random traffic to all the other canisters.
///
/// The registry changes reflecting the subnet split are made up front, but the
/// registry on either subnet is only updated later, in a random round through
/// the split of `subnet1`; and in a different random round through a regular
/// registry update to the newest version on `subnet2`.
///
/// These two random rounds produce all the cases relevant for subnet splitting:
///
///  - `subnet1` splits before `subnet2` observes the changes in the registry.
///  - `subnet2` observes the changes on the registry before `subnet1` splits,
///    i.e. before the new `subnet3` even exists (but is referred to in the
///    routing table).
///  - The two events happen concurrently.
///
/// After both these events have occurred, a few more calls are made. If after
/// some more rounds all calls conclude (without any canister trapping, which
/// would indicate a sequencing error) and the canisters can be stopped, correct
/// routing is implied because hanging calls would prevent stopping at least one
/// canister and no sequencing errors have occurred.
#[test_strategy::proptest(ProptestConfig::with_cases(3), max_shrink_iters = 0)]
fn test_subnet_split(
    #[strategy(arb_test_subnets(
        TestSubnetConfig { canisters_count: 2, ..TestSubnetConfig::default() },
        TestSubnetConfig::default()
    ))]
    setup: TestSubnetSetup,

    #[strategy(
        Just(#setup.canisters)
        .prop_flat_map(|canisters| {
            let config = CallConfig {
                receivers: canisters.clone(),
                // Want all ingress messages to be inducted on the first round. Else, we would
                // have to explicitly wait for them to be inducted before splitting the subnet;
                // or run the risk of orphaning them in the `subnet1` ingress pool.
                call_bytes_range: 0..=0,
                reply_bytes_range: 0..=0,
                call_tree_size: 10,
                ..CallConfig::default()
            };
            (
                proptest::collection::vec(arb_call(canisters[0], config.clone()), 5),
                proptest::collection::vec(arb_call(canisters[1], config.clone()), 5),
                proptest::collection::vec(arb_call(canisters[2], config.clone()), 5),
            )
        })
    )]
    calls: (Vec<Call>, Vec<Call>, Vec<Call>),

    #[strategy(1..=5_usize)] subnet1_split_round: usize,

    #[strategy(1..=5_usize)] subnet2_routing_table_update_round: usize,
) {
    const SEED: [u8; 32] = [123; 32];

    let (subnet1, subnet2, _) = setup.into_parts();
    let (mut calls1, mut calls2, mut calls3) = calls;
    let [canister1, canister2] = subnet1.canisters()[..] else {
        unreachable!("{:?}", subnet1.canisters());
    };
    let canister3 = subnet2.principal_canister();

    // Inject triggers into the ingress pool; keep 2 for after the split / routing table update.
    let inject_calls =
        |calls: &mut Vec<Call>, retain: usize, subnet: &TestSubnet| -> Vec<MessageId> {
            calls
                .split_off(retain)
                .into_iter()
                .map(|call| subnet.submit_call_as_ingress(call).unwrap())
                .collect()
        };
    let mut msg_ids1 = inject_calls(&mut calls1, 2, &subnet1);
    let mut msg_ids2 = inject_calls(&mut calls2, 2, &subnet1);
    let mut msg_ids3 = inject_calls(&mut calls3, 2, &subnet2);

    // Make the registry changes for the split in the data provider; Not yet visible on either subnet.
    subnet1
        .env
        .make_registry_entries_for_subnet_split(SEED, canister2..=canister2);

    // Execute rounds; split / update the routing table at the given index.
    let mut subnet3: Option<TestSubnet> = None;
    for round in 0..=10 {
        if round == subnet1_split_round {
            subnet3 = Some(subnet1.online_split(SEED).unwrap());
            assert_matches!(subnet1.canisters()[..], [c] if c == canister1);
            assert_matches!(subnet3.as_ref().unwrap().canisters()[..], [c] if c == canister2);
        } else {
            subnet1.execute_round();
        }
        if round == subnet2_routing_table_update_round {
            subnet2.env.reload_registry();
            subnet2.env.registry_client.update_to_latest_version();
        }

        subnet2.execute_round();
        if let Some(ref subnet3) = subnet3 {
            subnet3.execute_round();
        }
    }

    // Inject the rest of the calls; note that `canister2` is now on `subnet3`.
    let subnet3 = subnet3.unwrap();
    msg_ids1.append(&mut inject_calls(&mut calls1, 0, &subnet1));
    msg_ids2.append(&mut inject_calls(&mut calls2, 0, &subnet3));
    msg_ids3.append(&mut inject_calls(&mut calls3, 0, &subnet2));

    let mut round = 0;
    while !msg_ids1.is_empty()
        || !msg_ids2.is_empty()
        || !msg_ids3.is_empty()
        || subnet1.has_inflight_messages()
        || subnet2.has_inflight_messages()
        || subnet3.has_inflight_messages()
    {
        subnet1.execute_round();
        subnet2.execute_round();
        subnet3.execute_round();

        msg_ids1 = subnet1.check_and_drop_completed(msg_ids1, &check_for_traps);
        msg_ids2 = subnet3.check_and_drop_completed(msg_ids2, &check_for_traps);
        msg_ids3 = subnet2.check_and_drop_completed(msg_ids3, &check_for_traps);

        round += 1;
        if round >= 1000 {
            panic!("Calls did not conclude after 1000 rounds");
        }
    }

    // All calls have concluded without trapping; we should be able to stop them now.
    subnet1.env.stop_canister(canister1).unwrap();
    subnet2.env.stop_canister(canister3).unwrap();
    subnet3.env.stop_canister(canister2).unwrap();
}
