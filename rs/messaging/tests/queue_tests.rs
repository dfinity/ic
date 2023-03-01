use assert_matches::assert_matches;
use candid::{Decode, Encode};
use canister_test::Project;
use ic_base_types::{CanisterId, SubnetId};
use ic_interfaces_certified_stream_store::EncodeStreamError;
use ic_registry_routing_table::{routing_table_insert_subnet, RoutingTable};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::ReplicatedState;
use ic_state_machine_tests::{StateMachine, StateMachineBuilder, UserError, WasmResult};
use ic_test_utilities::types::ids::subnet_test_id;
use ic_test_utilities_metrics::fetch_int_counter_vec;
use ic_types::{messages::RequestOrResponse, xnet::StreamIndex, Cycles};
use maplit::btreemap;
use std::sync::Arc;
use xnet_test::Metrics;

const MAX_TICKS: u64 = 100;

/// Wrapper for two state machines, one considered the 'local subnet' and the other the
/// 'remote subnet', such that both subnets have exactly one 'xnet-test-canister' installed.
/// This is useful for tests where bidirectional traffic is simulated between two canisters
/// on different subnets.
struct SingleCanisterSubnetPair {
    pub local_env: StateMachine,
    pub local_canister_id: CanisterId,
    pub remote_env: StateMachine,
    pub remote_canister_id: CanisterId,
}

impl SingleCanisterSubnetPair {
    /// Generates a new pair of subnets using the specified subnet ids.
    pub fn from_subnet_ids(local_subnet_id: SubnetId, remote_subnet_id: SubnetId) -> Self {
        let mut routing_table = RoutingTable::new();
        for subnet_id in [local_subnet_id, remote_subnet_id] {
            routing_table_insert_subnet(&mut routing_table, subnet_id).unwrap();
        }
        let wasm = Project::cargo_bin_maybe_from_env("xnet-test-canister", &[]).bytes();

        let local_env = StateMachineBuilder::new()
            .with_subnet_id(local_subnet_id)
            .with_subnet_type(SubnetType::Application)
            .with_routing_table(routing_table.clone())
            .build();
        let local_canister_id = local_env
            .install_canister_with_cycles(
                wasm.clone(),
                Vec::new(),
                None,
                Cycles::new(u128::MAX / 2),
            )
            .expect("Installing xnet-test-canister failed");

        let remote_env = StateMachineBuilder::new()
            .with_subnet_id(remote_subnet_id)
            .with_subnet_type(SubnetType::Application)
            .with_routing_table(routing_table)
            .build();
        let remote_canister_id = remote_env
            .install_canister_with_cycles(wasm, Vec::new(), None, Cycles::new(u128::MAX / 2))
            .expect("Installing xnet-test-canister failed");

        Self {
            local_env,
            local_canister_id,
            remote_env,
            remote_canister_id,
        }
    }

    /// Generates a new pair of subnets using default subnet ids.
    pub fn new() -> Self {
        Self::from_subnet_ids(subnet_test_id(1), subnet_test_id(2))
    }

    /// Generate the payload for the 'start' method on an XNet canister.
    fn start_payload(
        &self,
        canister_to_subnet_rate: u64,
        payload_size_bytes: u64,
    ) -> Result<Vec<u8>, candid::Error> {
        let network_topology = vec![
            vec![self.local_canister_id.get().to_vec()],
            vec![self.remote_canister_id.get().to_vec()],
        ];
        Encode!(
            &network_topology,
            &canister_to_subnet_rate,
            &payload_size_bytes
        )
    }

    /// Calls the 'start' method on the local canister.
    pub fn start_local_canister(
        &self,
        canister_to_subnet_rate: u64,
        payload_size_bytes: u64,
    ) -> Result<(), UserError> {
        let payload = self
            .start_payload(canister_to_subnet_rate, payload_size_bytes)
            .unwrap();
        call_start_on_xnet_canister(&self.local_env, self.local_canister_id, payload)
    }

    /// Calls the 'start' method on the remote canister.
    pub fn start_remote_canister(
        &self,
        canister_to_subnet_rate: u64,
        payload_size_bytes: u64,
    ) -> Result<(), UserError> {
        let payload = self
            .start_payload(canister_to_subnet_rate, payload_size_bytes)
            .unwrap();
        call_start_on_xnet_canister(&self.remote_env, self.remote_canister_id, payload)
    }

    /// Calls the 'stop' method on the local canister.
    pub fn stop_local_canister(&self) -> Result<(), UserError> {
        call_stop_on_xnet_canister(&self.local_env, self.local_canister_id)
    }

    /// Queries the local canister.
    pub fn query_local_canister(
        &self,
        method: impl ToString,
        method_payload: Vec<u8>,
    ) -> Result<WasmResult, UserError> {
        self.local_env
            .query(self.local_canister_id, method, method_payload)
    }

    /// Queries the remote canister.
    pub fn query_remote_canister(
        &self,
        method: impl ToString,
        method_payload: Vec<u8>,
    ) -> Result<WasmResult, UserError> {
        self.remote_env
            .query(self.remote_canister_id, method, method_payload)
    }

    /// Induct data from the stream on the local subnet to the remote subnet
    /// into the remote subnet.
    fn induct_from_stream_into_remote_subnet(
        &self,
        witness_begin: Option<StreamIndex>,
        msg_begin: Option<StreamIndex>,
        msg_limit: Option<usize>,
        byte_limit: Option<usize>,
    ) -> Result<(), EncodeStreamError> {
        let xnet_payload = self.local_env.generate_xnet_payload(
            self.remote_env.get_subnet_id(),
            witness_begin,
            msg_begin,
            msg_limit,
            byte_limit,
        )?;
        self.remote_env
            .execute_block_with_xnet_payload(xnet_payload);
        Ok(())
    }

    /// Induct data from the stream on the remote subnet to the local subnet
    /// into the local subnet.
    fn induct_from_reverse_stream_into_local_subnet(
        &self,
        witness_begin: Option<StreamIndex>,
        msg_begin: Option<StreamIndex>,
        msg_limit: Option<usize>,
        byte_limit: Option<usize>,
    ) -> Result<(), EncodeStreamError> {
        let xnet_payload = self.remote_env.generate_xnet_payload(
            self.local_env.get_subnet_id(),
            witness_begin,
            msg_begin,
            msg_limit,
            byte_limit,
        )?;
        self.local_env.execute_block_with_xnet_payload(xnet_payload);
        Ok(())
    }

    /// Generates a snapshot of the output queue on the local canister and
    /// returns it as a vector of messages; or 'None' if no output queue exists.
    fn local_output_queue_snapshot(&self) -> Option<Vec<Option<RequestOrResponse>>> {
        get_output_queue_iter(
            &self.local_env.get_latest_state(),
            self.local_canister_id,
            self.remote_canister_id,
        )
        .map(|iter| iter.cloned().collect::<Vec<_>>())
    }
}

/// Returns an iterator over the raw contents of a specific local canister's
/// output queue to a specific remote canister; or `None` if the queue does not
/// exist.
fn get_output_queue_iter(
    state: &Arc<ReplicatedState>,
    local_canister_id: CanisterId,
    remote_canister_id: CanisterId,
) -> Option<impl Iterator<Item = &Option<RequestOrResponse>>> {
    state
        .canister_states
        .get(&local_canister_id)
        .and_then(|canister_state| {
            canister_state
                .system_state
                .queues()
                .output_queue_iter_for_testing(&remote_canister_id)
        })
}

/// Calls the 'start' method on a canister in the state machine (assumed to be an XNet canister).
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

/// Calls the 'stop' method on a canister in the state machine (assumed to be an XNet canister).
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

/// Wrapper for a generic function to be executed at most a maximum number of times.
/// The generic function must provide a condition to decide whether execution should be
/// aborted or not.
/// This is useful as a safety wrapper for code where we tick on a state machine
/// until an exit condition is met. Since this usually depends on a canister that could stall
/// or otherwise take an unreasonably long amount of time to reach the exit condition, this
/// function makes sure a panic is triggered rather than hanging forever.
///
/// # Panics
///
/// This function panics if the exit condition is not reached after `max_iterations` iterations.
fn do_until_or_panic<F>(max_iterations: u64, f: F) -> u64
where
    F: Fn() -> bool,
{
    for counter in 1..=max_iterations {
        if f() {
            return counter;
        }
    }
    panic!("No exit condition after {} iterations.", max_iterations);
}

/// Test timing out requests in output queues, by completely filling up the XNet stream with
/// messages from a local canister, such that messages start piling up in its output queue.
/// Then advance the time and execute a round to trigger a timeout; then check the output queue
/// has been emptied out.
#[test]
fn test_timeout_removes_requests_from_output_queues() {
    let subnets = SingleCanisterSubnetPair::new();

    let canister_to_subnet_rate = 10;
    let payload_size_bytes = 1024 * 1024;

    // Send requests until there are messages in the output queue, then stop sending
    // requests and trigger a timeout. The queue should be empty afterwards.
    subnets
        .start_local_canister(canister_to_subnet_rate, payload_size_bytes)
        .unwrap();
    do_until_or_panic(MAX_TICKS, || {
        subnets.local_env.tick();
        matches!(
            subnets.local_output_queue_snapshot().as_deref(),
            Some([_, ..])
        )
    });
    subnets.stop_local_canister().unwrap();
    execute_round_with_timeout(&subnets.local_env);

    // Check the output queue is empty after the timeout.
    assert_matches!(subnets.local_output_queue_snapshot().as_deref(), Some([]));
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
/// subnet, which will cause the blocking response to slip into the XNet stream. With the
/// response popped from the output queue, all the timed out requests are gc'ed, leading to
/// an empty output queue.
#[test]
fn test_response_in_output_queue_causes_backpressure() {
    let subnets = SingleCanisterSubnetPair::new();

    let canister_to_subnet_rate = 10;
    let payload_size_bytes = 1024 * 1024;

    // Make the local canister send requests until there are messages in the output queue
    // (i.e. the stream is full); then call 'stop' and wipe the queue by triggering a timeout.
    subnets
        .start_local_canister(canister_to_subnet_rate, payload_size_bytes)
        .unwrap();
    do_until_or_panic(MAX_TICKS, || {
        subnets.local_env.tick();
        matches!(
            subnets.local_output_queue_snapshot().as_deref(),
            Some([_, ..])
        )
    });
    subnets.stop_local_canister().unwrap();
    execute_round_with_timeout(&subnets.local_env);

    // Call the 'start' method on the remote canister to start sending requests to the local
    // canister. Do one tick and then induct one xnet request into the local canister, which
    // should produce one response in its output queue back to the remote canister.
    subnets
        .start_remote_canister(canister_to_subnet_rate, payload_size_bytes)
        .unwrap();
    subnets.remote_env.tick();
    subnets
        .induct_from_reverse_stream_into_local_subnet(
            None,    // witness_begin
            None,    // msg_begin
            Some(1), // msg_limit
            None,    // byte_limit
        )
        .unwrap();
    assert_matches!(
        subnets.local_output_queue_snapshot().as_deref(),
        Some([Some(RequestOrResponse::Response(_))])
    );

    // Call the 'start' method on canister 1 to restart sending requests using
    // a high rate and small payload to generate a lot of messages quickly.
    let canister_to_subnet_rate = 100;
    let payload_size_bytes = 128;
    subnets
        .start_local_canister(canister_to_subnet_rate, payload_size_bytes)
        .unwrap();

    // Keep ticking and triggering timeouts until the XNet canister starts
    // reporting call errors, indicating back pressure.
    do_until_or_panic(MAX_TICKS, || {
        execute_round_with_timeout(&subnets.local_env);
        let reply = subnets.query_local_canister("metrics", Vec::new()).unwrap();
        Decode!(&reply.bytes(), Metrics).unwrap().call_errors > 0
    });

    // Check the local output queue is indeed of the shape [ response, None, ... ].
    assert_matches!(
        subnets.local_output_queue_snapshot().as_deref(),
        Some([Some(RequestOrResponse::Response(_)), None, ..])
    );

    // Call the 'stop' method on the local canister, then induct a request from the local subnet
    // into the remote subnet.
    subnets.stop_local_canister().unwrap();
    subnets
        .induct_from_stream_into_remote_subnet(
            None,    // witness_begin
            None,    // msg_begin
            Some(1), // msg_limit
            None,    // byte_limit
        )
        .unwrap();

    // An 'empty' XNet payload (as in no messages) contains a header including an ACK signal.
    // Inducting this payload will trigger the request sent to the remote subnet to be gc'ed
    // in the XNet stream of the local subnet.
    subnets
        .induct_from_reverse_stream_into_local_subnet(
            None,    // witness_begin
            None,    // msg_begin
            Some(0), // msg_limit
            None,    // byte_limit
        )
        .unwrap();

    // The blocking response should now have slipped into the XNet stream; this will trigger all
    // the timed out requests to be gc'ed, resulting in an empty output queue.
    assert_matches!(subnets.local_output_queue_snapshot().as_deref(), Some([]));
}

/// Test the presence of reservations in input queues does not inhibit inducting xnet
/// requests to a local canister from a remote subnet.
/// This can be done by having two canisters on different subnets produce requests until
/// backpressure is encountered and then inducting the requests from the remote canister
/// into the local canister. All of the requests should be inducted successfully.
#[test]
fn test_reservations_do_not_inhibit_xnet_induction_of_requests() {
    let subnets = SingleCanisterSubnetPair::new();

    let canister_to_subnet_rate = 100;
    let payload_size_bytes = 128;

    // Call start on both canisters and tick until call errors are encountered,
    // indicating back pressure.
    subnets
        .start_local_canister(canister_to_subnet_rate, payload_size_bytes)
        .unwrap();
    do_until_or_panic(MAX_TICKS, || {
        subnets.local_env.tick();
        let reply = subnets.query_local_canister("metrics", Vec::new()).unwrap();
        Decode!(&reply.bytes(), Metrics).unwrap().call_errors > 0
    });

    subnets
        .start_remote_canister(canister_to_subnet_rate, payload_size_bytes)
        .unwrap();
    do_until_or_panic(MAX_TICKS, || {
        subnets.remote_env.tick();
        let reply = subnets
            .query_remote_canister("metrics", Vec::new())
            .unwrap();
        Decode!(&reply.bytes(), Metrics).unwrap().call_errors > 0
    });

    // Try inducting all the requests successfully sent by the remote canister into
    // the local canister.
    let reply = subnets
        .query_remote_canister("metrics", Vec::new())
        .unwrap();
    let metrics = Decode!(&reply.bytes(), Metrics).unwrap();
    subnets
        .induct_from_reverse_stream_into_local_subnet(
            None,                        // witness_begin
            None,                        // msg_begin
            Some(metrics.requests_sent), // msg_limit
            None,                        // byte_limit
        )
        .unwrap();

    let mr_metrics = fetch_int_counter_vec(
        subnets.local_env.metrics_registry(),
        "mr_inducted_xnet_message_count",
    );
    let requests_inducted = mr_metrics.get(&btreemap! {
        "status".to_string() => "success".to_string(),
        "type".to_string() => "request".to_string()
    });

    assert_eq!(metrics.requests_sent, *requests_inducted.unwrap() as usize);
}
