use assert_matches::assert_matches;
use candid::{Decode, Encode};
use canister_test::Project;
use ic_base_types::CanisterId;
use ic_registry_routing_table::{routing_table_insert_subnet, RoutingTable};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::ReplicatedState;
use ic_state_machine_tests::{StateMachine, StateMachineBuilder, UserError};
use ic_test_utilities::types::ids::subnet_test_id;
use ic_test_utilities_metrics::fetch_int_counter_vec;
use ic_types::{messages::RequestOrResponse, Cycles};
use maplit::btreemap;
use std::sync::Arc;
use xnet_test::Metrics;

/// Generates a pair of state machines with a routing table such that
/// bidirectional traffic can be simulated.
fn make_state_machine_pair() -> (StateMachine, StateMachine) {
    let subnet_id_1 = subnet_test_id(1);
    let subnet_id_2 = subnet_test_id(2);

    let mut routing_table = RoutingTable::new();
    for subnet_id in [subnet_id_1, subnet_id_2] {
        routing_table_insert_subnet(&mut routing_table, subnet_id).unwrap();
    }

    (
        StateMachineBuilder::new()
            .with_subnet_id(subnet_id_1)
            .with_subnet_type(SubnetType::Application)
            .with_routing_table(routing_table.clone())
            .build(),
        StateMachineBuilder::new()
            .with_subnet_id(subnet_id_2)
            .with_subnet_type(SubnetType::Application)
            .with_routing_table(routing_table.clone())
            .build(),
    )
}

// Installs a canister with a large number of cycles.
fn install_canister(env: &StateMachine, wasm: Vec<u8>) -> Result<CanisterId, UserError> {
    env.install_canister_with_cycles(wasm, Vec::new(), None, Cycles::new(u128::MAX / 2))
}

/// Returns an iterator over the raw contents of a specific local canister's
/// output queue to a specific remote canister; or `None` if the queue does not
/// exist.
fn get_output_queue_iter<'a>(
    state: &'a Arc<ReplicatedState>,
    local_canister_id: &CanisterId,
    remote_canister_id: &CanisterId,
) -> Option<impl Iterator<Item = &'a Option<RequestOrResponse>>> {
    state
        .canister_states
        .get(local_canister_id)
        .and_then(|canister_state| {
            canister_state
                .system_state
                .queues()
                .output_queue_iter_for_testing(remote_canister_id)
        })
}

/// Peeks into the output queue of a local canister to a remote canister.
fn peek_output_queue<'a>(
    state: &'a Arc<ReplicatedState>,
    local_canister_id: &CanisterId,
    remote_canister_id: &CanisterId,
) -> Option<&'a Option<RequestOrResponse>> {
    get_output_queue_iter(state, local_canister_id, remote_canister_id)
        .and_then(|mut iter| iter.next())
}

/// Generate the payload for the 'start' method on the XNet canister, where
/// `canister_id_1` and `canister_id_2` are assumed to be on different subnets.
fn start_payload_for_xnet_canister_pair(
    canister_id_1: &CanisterId,
    canister_id_2: &CanisterId,
    canister_to_subnet_rate: u64,
    payload_size_bytes: u64,
) -> Result<Vec<u8>, candid::Error> {
    let network_topology = vec![
        vec![canister_id_1.get().to_vec()],
        vec![canister_id_2.get().to_vec()],
    ];
    Encode!(
        &network_topology,
        &canister_to_subnet_rate,
        &payload_size_bytes
    )
}

/// Calls the 'start' method on a canister in the state machine (assumed to be a XNet canister).
fn call_start_on_xnet_canister(
    env: &StateMachine,
    canister_id: CanisterId,
    payload: Vec<u8>,
) -> Result<(), UserError> {
    let wasm = env.execute_ingress(canister_id, "start", payload)?;
    assert_eq!(
        "started".to_string(),
        Decode!(&wasm.bytes(), String).unwrap()
    );
    Ok(())
}

/// Calls the 'stop' method on a canister in the state machine (assumed to be a XNet canister).
fn call_stop_on_xnet_canister(
    env: &StateMachine,
    canister_id: CanisterId,
) -> Result<(), UserError> {
    let wasm = env.execute_ingress(canister_id, "stop", Vec::new())?;
    assert_eq!(
        "stopped".to_string(),
        Decode!(&wasm.bytes(), String).unwrap()
    );
    Ok(())
}

/// Triggers a timeout by first advancing the time by 1 day (which should far exceed any
/// realistic setting for request lifetimes) and then ticking.
fn execute_round_with_timeout(env: &StateMachine) {
    env.advance_time(std::time::Duration::from_secs(24 * 3600));
    env.tick();
}

/// Ticks until a local canister has produced enough messages that they start piling up in
/// the output queue to a remote canister. Since messages are inducted into a xnet stream
/// as long as its current size is less than its target size, this guarantees that all
/// following messages will be stuck in the output queue (or rejected once the queue is full).
/// Returns the number of ticks until the above is true.
///
/// # Panics
///
/// This function panics if there are no messages in the queue after a resonable
/// amount of time (typically of few seconds, depending on the payload of requests).
fn tick_until_messages_in_output_queue(
    env: &StateMachine,
    local_canister_id: &CanisterId,
    remote_canister_id: &CanisterId,
) -> u64 {
    const MAX_TICKS: u64 = 100;
    for ticks_counter in 1..=MAX_TICKS {
        env.tick();
        if peek_output_queue(
            &env.get_latest_state(),
            local_canister_id,
            remote_canister_id,
        )
        .is_some()
        {
            return ticks_counter;
        }
    }
    panic!("No messages in the output queue after {} ticks", MAX_TICKS)
}

/// Test timing out requests in output queues, by completely filling up the XNet stream with
/// messages from a local canister, such that messages start piling up in its output queue.
/// Then advance the time and execute a round to trigger a timeout; then check the output queue
/// has been emptied out.
#[test]
fn test_timeout_removes_requests_from_output_queues() {
    let (env, remote_env) = make_state_machine_pair();

    // Install XNet canister on the subnets.
    let wasm = Project::cargo_bin_maybe_from_env("xnet-test-canister", &[]).bytes();
    let local_canister_id = install_canister(&env, wasm.clone()).unwrap();
    let remote_canister_id = install_canister(&remote_env, wasm).unwrap();

    // Generate payload used to start canisters.
    let payload = start_payload_for_xnet_canister_pair(
        &local_canister_id,
        &remote_canister_id,
        10,          // canister_to_subnet_rate
        1024 * 1024, // payload_size_bytes
    )
    .unwrap();

    // Send requests until there are messages in the output queue, then stop sending
    // requests and trigger a timeout. The queue should be empty afterwards.
    call_start_on_xnet_canister(&env, local_canister_id, payload).unwrap();
    tick_until_messages_in_output_queue(&env, &local_canister_id, &remote_canister_id);
    call_stop_on_xnet_canister(&env, local_canister_id).unwrap();
    execute_round_with_timeout(&env);

    // Check the output queue is empty.
    assert!(peek_output_queue(
        &env.get_latest_state(),
        &local_canister_id,
        &remote_canister_id,
    )
    .is_none());
}

/// Test a response stuck in an output queue causes backpressure by blocking the evacuation
/// of timed out requests, which can be done using bidirectional communication between two
/// canisters on different subnets.
/// The local canister first fills up its stream, then stops sending requests and finally
/// wipes any remaining requests from its output queue; then a request from the remote canister
/// is inducted into the local canister which will produce a response stuck in its output queue
/// back to the remote canister. If the local canister restarts sending requests and
/// continuously triggering timeouts each round, timed out requests will pile up in the output
/// queue which will eventually lead to failed inductions due to backpressure.
/// In a last step, a request is gc'ed in the XNet stream on the local subnet to the remote
/// subnet, which will cause the blocking response to slip into the XNet stream. With the response
/// popped from the output queue, all the timed out requests are gc'ed, leading to an empty
/// output queue.
#[test]
fn test_response_in_output_queue_causes_backpressure() {
    let (env, remote_env) = make_state_machine_pair();

    // Install XNet canister on the subnets.
    let wasm = Project::cargo_bin_maybe_from_env("xnet-test-canister", &[]).bytes();
    let local_canister_id = install_canister(&env, wasm.clone()).unwrap();
    let remote_canister_id = install_canister(&remote_env, wasm).unwrap();

    // Generate payload used to start canisters.
    let payload = start_payload_for_xnet_canister_pair(
        &local_canister_id,
        &remote_canister_id,
        10,          // canister_to_subnet_rate
        1024 * 1024, // payload_size_bytes
    )
    .unwrap();

    // Make the local canister send requests until there are messages in the output queue
    // (i.e. the stream is full); then call 'stop' and wipe the queue by triggering a timeout.
    call_start_on_xnet_canister(&env, local_canister_id, payload.clone()).unwrap();
    tick_until_messages_in_output_queue(&env, &local_canister_id, &remote_canister_id);
    call_stop_on_xnet_canister(&env, local_canister_id).unwrap();
    execute_round_with_timeout(&env);

    // Call the 'start' method on the remote canister to start sending requests to the local
    // canister. Do one tick and then induct one xnet request into the local canister, which
    // should produce one response in its output queue back to the remote canister.
    call_start_on_xnet_canister(&remote_env, remote_canister_id, payload).unwrap();
    remote_env.tick();
    let xnet_payload = remote_env
        .generate_xnet_payload(
            env.get_subnet_id(),
            None,    // witness_begin
            None,    // msg_begin
            Some(1), // msg_limit
            None,    // byte_limit
        )
        .unwrap();
    env.execute_block_with_xnet_payload(xnet_payload);
    assert_matches!(
        peek_output_queue(
            &env.get_latest_state(),
            &local_canister_id,
            &remote_canister_id,
        ),
        Some(Some(RequestOrResponse::Response(_)))
    );

    // Call the 'start' method on canister 1 to restart sending requests using
    // a high rate and small payload to generate a lot of messages quickly.
    let payload = start_payload_for_xnet_canister_pair(
        &local_canister_id,
        &remote_canister_id,
        100, // canister_to_subnet_rate
        128, // payload_size_bytes
    )
    .unwrap();
    call_start_on_xnet_canister(&env, local_canister_id, payload).unwrap();

    // Keep ticking and triggering timeouts until the XNet canister starts
    // reporting call errors, indicating back pressure.
    const MAX_TICKS: u64 = 100;
    for ticks_counter in 1..=MAX_TICKS {
        execute_round_with_timeout(&env);
        let reply = env.query(local_canister_id, "metrics", Vec::new()).unwrap();
        let metrics = Decode!(&reply.bytes(), Metrics).unwrap();

        if metrics.call_errors > 0 {
            break;
        }
        if ticks_counter == MAX_TICKS {
            panic!("No backpressure detected after {} ticks.", MAX_TICKS);
        }
    }

    // Check the queue is indeed of the shape { response, None, ... }.
    let state = env.get_latest_state();
    let mut iter = get_output_queue_iter(&state, &local_canister_id, &remote_canister_id).unwrap();
    assert_matches!(iter.next(), Some(Some(RequestOrResponse::Response(_))));
    assert!(iter.all(|msg| msg.is_none()));

    // Call the 'stop' method on the local canister, then induct a request from the local subnet
    // into the remote subnet.
    call_stop_on_xnet_canister(&env, local_canister_id).unwrap();
    let xnet_payload = env
        .generate_xnet_payload(
            remote_env.get_subnet_id(),
            None,    // witness_begin
            None,    // msg_begin
            Some(1), // msg_limit
            None,    // byte_limit
        )
        .unwrap();
    remote_env.execute_block_with_xnet_payload(xnet_payload);

    // An 'empty' XNet payload (as in no messages) contains a header including a 'request received'
    // signal. Inducting this payload will trigger the request sent to the remote subnet to be
    // gc'ed in the XNet stream of the local subnet.
    let xnet_payload = remote_env
        .generate_xnet_payload(
            env.get_subnet_id(),
            None,    // witness_begin
            None,    // msg_begin
            Some(0), // msg_limit
            None,    // byte_limit
        )
        .unwrap();
    env.execute_block_with_xnet_payload(xnet_payload);

    // The blocking response should now have slipped into the XNet stream; this will trigger all
    // the timed out requests to be gc'ed, resulting in an empty output queue.
    assert!(peek_output_queue(
        &env.get_latest_state(),
        &local_canister_id,
        &remote_canister_id,
    )
    .is_none());
}

/// Test the presence of reservations in input queues does not inhibit inducting xnet
/// requests to a local canister from a remote subnet.
/// This can be done by having two canisters on different subnets produce requests until
/// backpressure is encountered and then inducting the requests from the remote canister
/// into the local canister. All of the requests should be inducted successfully.
#[test]
fn test_reservations_do_not_inhibit_xnet_induction_of_requests() {
    let (env, remote_env) = make_state_machine_pair();

    // Install XNet canister on the subnets.
    let wasm = Project::cargo_bin_maybe_from_env("xnet-test-canister", &[]).bytes();
    let local_canister_id = install_canister(&env, wasm.clone()).unwrap();
    let remote_canister_id = install_canister(&remote_env, wasm).unwrap();

    // Generate small payload with a high rate to produce a lot messages quickly.
    let payload = start_payload_for_xnet_canister_pair(
        &local_canister_id,
        &remote_canister_id,
        100, // canister_to_subnet_rate
        128, // payload_size_bytes
    )
    .unwrap();

    // Call start on both canisters and tick until call errors are encountered,
    // indicating back pressure.
    call_start_on_xnet_canister(&env, local_canister_id, payload.clone()).unwrap();
    call_start_on_xnet_canister(&remote_env, remote_canister_id, payload).unwrap();
    for (env, canister_id) in [
        (&env, &local_canister_id),
        (&remote_env, &remote_canister_id),
    ] {
        const MAX_TICKS: u64 = 100;
        for ticks_counter in 1..=MAX_TICKS {
            env.tick();
            let reply = env.query(*canister_id, "metrics", Vec::new()).unwrap();
            let metrics = Decode!(&reply.bytes(), Metrics).unwrap();

            if metrics.call_errors > 0 {
                break;
            }
            if ticks_counter == MAX_TICKS {
                panic!("No back pressure encountered after {} ticks", MAX_TICKS);
            }
        }
    }

    // Try inducting all the requests successfully sent by the remote canister into
    // the local canister.
    let reply = remote_env
        .query(remote_canister_id, "metrics", Vec::new())
        .unwrap();
    let metrics = Decode!(&reply.bytes(), Metrics).unwrap();
    let xnet_payload = remote_env
        .generate_xnet_payload(
            env.get_subnet_id(),
            None,                        // witness_begin
            None,                        // msg_begin
            Some(metrics.requests_sent), // msg_limit
            None,                        // byte_limit
        )
        .unwrap();
    env.execute_block_with_xnet_payload(xnet_payload);

    let mr_metrics =
        fetch_int_counter_vec(env.metrics_registry(), "mr_inducted_xnet_message_count");
    let requests_inducted = mr_metrics.get(&btreemap! {
        "status".to_string() => "success".to_string(),
        "type".to_string() => "request".to_string()
    });

    assert_eq!(metrics.requests_sent, *requests_inducted.unwrap() as usize);
}
