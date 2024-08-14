use assert_matches::assert_matches;
use candid::{Decode, Encode};
use canister_test::Project;
use ic_base_types::{CanisterId, SubnetId};
use ic_interfaces_certified_stream_store::EncodeStreamError;
use ic_registry_routing_table::{routing_table_insert_subnet, RoutingTable};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{testing::CanisterQueuesTesting, ReplicatedState};
use ic_state_machine_tests::{StateMachine, StateMachineBuilder, UserError, WasmResult};
use ic_test_utilities_metrics::fetch_int_counter_vec;
use ic_test_utilities_types::ids::{SUBNET_0, SUBNET_1, SUBNET_2};
use ic_types::{
    messages::{CallbackId, Payload, RequestOrResponse},
    xnet::{StreamHeader, StreamIndexedQueue},
    Cycles,
};
use maplit::btreemap;
use std::collections::BTreeSet;
use std::sync::Arc;
use xnet_test::Metrics;

const MAX_TICKS: u64 = 100;

/// Wrapper for two references to state machines, one considered the `local subnet` and the
/// other the `remote subnet`, such that both subnets have a main 'xnet-test-canister' installed,
/// that will be referred to as 'the local canister' with ID `self.local_canister_id` and
/// 'the remote canister' with ID `self.remote_canister_id` respectively.
///
/// The purpose of this struct is to simulate bidirectional XNet traffic between two canisters
/// installed on different subnets each.
struct SubnetPairProxy {
    pub local_env: Arc<StateMachine>,
    pub local_canister_id: CanisterId,
    pub remote_env: Arc<StateMachine>,
    pub remote_canister_id: CanisterId,
}

impl SubnetPairProxy {
    const LOCAL_SUBNET_ID: SubnetId = SUBNET_0;
    const REMOTE_SUBNET_ID: SubnetId = SUBNET_1;
    const DESTINATION_SUBNET_ID: SubnetId = SUBNET_2;

    /// Generates a new proxy of new subnets using default subnet ids.
    fn with_new_subnets() -> Self {
        let routing_table = Self::make_routing_table();
        let wasm = Project::cargo_bin_maybe_from_env("xnet-test-canister", &[]).bytes();

        let local_env = StateMachineBuilder::new()
            .with_subnet_id(Self::LOCAL_SUBNET_ID)
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
            .with_subnet_id(Self::REMOTE_SUBNET_ID)
            .with_subnet_type(SubnetType::Application)
            .with_routing_table(routing_table)
            .build();
        let remote_canister_id = remote_env
            .install_canister_with_cycles(wasm, Vec::new(), None, Cycles::new(u128::MAX / 2))
            .expect("Installing xnet-test-canister failed");

        Self {
            local_env: Arc::from(local_env),
            local_canister_id,
            remote_env: Arc::from(remote_env),
            remote_canister_id,
        }
    }

    /// Generates a routing table with canister ranges for 3 subnets.
    fn make_routing_table() -> RoutingTable {
        let mut routing_table = RoutingTable::new();
        for subnet_id in [
            Self::LOCAL_SUBNET_ID,
            Self::REMOTE_SUBNET_ID,
            Self::DESTINATION_SUBNET_ID,
        ] {
            routing_table_insert_subnet(&mut routing_table, subnet_id).unwrap();
        }
        routing_table
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
    fn call_start_on_local_canister(
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
    fn call_start_on_remote_canister(
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
    fn call_stop_on_local_canister(&self) -> Result<(), UserError> {
        call_stop_on_xnet_canister(&self.local_env, self.local_canister_id)
    }

    /// Calls the 'stop' method on the remote canister.
    fn call_stop_on_remote_canister(&self) -> Result<(), UserError> {
        call_stop_on_xnet_canister(&self.remote_env, self.remote_canister_id)
    }

    /// Stops the local canister.
    fn stop_local_canister(&self) -> Result<WasmResult, UserError> {
        self.local_env.stop_canister(self.local_canister_id)
    }

    /// Stops the remote canister.
    fn stop_remote_canister(&self) -> Result<WasmResult, UserError> {
        self.remote_env.stop_canister(self.remote_canister_id)
    }

    /// Queries the local canister.
    fn query_local_canister(
        &self,
        method: impl ToString,
        method_payload: Vec<u8>,
    ) -> Result<WasmResult, UserError> {
        self.local_env
            .query(self.local_canister_id, method, method_payload)
    }

    /// Queries the remote canister.
    fn query_remote_canister(
        &self,
        method: impl ToString,
        method_payload: Vec<u8>,
    ) -> Result<WasmResult, UserError> {
        self.remote_env
            .query(self.remote_canister_id, method, method_payload)
    }

    /// Generates a snapshot of the output queue on the local canister and
    /// returns it as a vector of messages; or 'None' if no output queue exists.
    fn local_output_queue_snapshot(&self) -> Option<Vec<RequestOrResponse>> {
        get_output_queue_iter(
            &self.local_env.get_latest_state(),
            &self.local_canister_id,
            &self.remote_canister_id,
        )
        .map(|iter| iter.collect::<Vec<_>>())
    }

    /// Generates a snapshot of the output queue on the remote canister and
    /// returns it as a vector of messages; or 'None' if no output queue exists.
    fn remote_output_queue_snapshot(&self) -> Option<Vec<RequestOrResponse>> {
        get_output_queue_iter(
            &self.remote_env.get_latest_state(),
            &self.remote_canister_id,
            &self.local_canister_id,
        )
        .map(|iter| iter.collect::<Vec<_>>())
    }

    /// Build backpressure on `local_env` until a minimum number of requests are found in the
    /// output queue of the local canister (due to a full stream). A XNet canister is assumed
    /// running on the remote subnet and sending messages to the local subnet.
    ///
    /// # Panics
    ///
    /// This function panics if the minimum number of messages is not reached within `MAX_TICKS`
    /// ticks.
    fn build_local_backpressure_until(&self, min_num_messages: usize) {
        do_until_or_panic(MAX_TICKS, |_| {
            let exit_condition = self
                .local_output_queue_snapshot()
                .map(|q| q.len() >= min_num_messages)
                .unwrap_or(false);
            if !exit_condition {
                self.local_env.tick();
            }
            Ok(exit_condition)
        })
        .unwrap();
    }

    /// Adds the remote canister ID to the migration list on both subnets.
    fn mark_remote_canister_as_being_migrated(&self) {
        for env in [&self.local_env, &self.remote_env] {
            env.prepare_canister_migrations(
                self.remote_canister_id..=self.remote_canister_id,
                self.remote_env.get_subnet_id(),
                Self::DESTINATION_SUBNET_ID,
            );
        }
    }

    /// Creates and returns a new instance of `Self` such that `local_env` remains the same,
    /// but `remote_env` is a new subnet with a different subnet id. The remote canister is
    /// subsequently moved to this new subnet and the routing tables are updated accordingly
    /// on all subnets (i.e. `self.local_env`, `self.remote_env` and on the new subnet).
    fn move_remote_canister_to_destination_subnet(&self) -> Result<Self, String> {
        // New destination env using the same routing table as `self`.
        let destination_env = StateMachineBuilder::new()
            .with_subnet_id(Self::DESTINATION_SUBNET_ID)
            .with_subnet_type(SubnetType::Application)
            .with_routing_table(Self::make_routing_table())
            .with_checkpoints_enabled(true)
            .build();

        // Add migration list entry for the destination subnet.
        destination_env.prepare_canister_migrations(
            self.remote_canister_id..=self.remote_canister_id,
            self.remote_env.get_subnet_id(),
            destination_env.get_subnet_id(),
        );

        // Update local, remote and destination routing tables.
        for env in [&self.local_env, &self.remote_env, &destination_env] {
            env.reroute_canister_range(
                self.remote_canister_id..=self.remote_canister_id,
                Self::DESTINATION_SUBNET_ID,
            );
        }

        // Move the remote canister to the destination subnet.
        self.remote_env
            .move_canister_state_to(&destination_env, self.remote_canister_id)?;

        Ok(Self {
            local_env: self.local_env.clone(),
            local_canister_id: self.local_canister_id,
            remote_env: Arc::new(destination_env),
            remote_canister_id: self.remote_canister_id,
        })
    }
}

/// Returns an iterator over the raw contents of a specific local canister's
/// output queue to a specific remote canister; or `None` if the queue does not
/// exist.
fn get_output_queue_iter<'a>(
    state: &'a ReplicatedState,
    local_canister_id: &CanisterId,
    remote_canister_id: &'a CanisterId,
) -> Option<impl Iterator<Item = RequestOrResponse> + 'a> {
    state
        .canister_states
        .get(local_canister_id)
        .and_then(move |canister_state| {
            canister_state
                .system_state
                .queues()
                .output_queue_iter_for_testing(remote_canister_id)
        })
}

/// Returns a snapshot of an XNet stream as stream header and a queue of messages.
fn stream_snapshot(
    from_subnet: &StateMachine,
    to_subnet: &StateMachine,
) -> Option<(StreamHeader, StreamIndexedQueue<RequestOrResponse>)> {
    from_subnet
        .get_latest_state()
        .get_stream(&to_subnet.get_subnet_id())
        .map(|stream| (stream.header(), stream.messages().clone()))
}

/// Inducts data from the head of the stream on `from_env` into `into_env`.
fn induct_from_head_of_stream(
    from_env: &StateMachine,
    into_env: &StateMachine,
    msg_limit: Option<usize>,
) -> Result<(), EncodeStreamError> {
    let xnet_payload = from_env.generate_xnet_payload(
        into_env.get_subnet_id(),
        None, // witness_begin
        None, // msg_begin
        msg_limit,
        None, // byte_limit,
    )?;
    into_env.execute_block_with_xnet_payload(xnet_payload);
    Ok(())
}

/// Inducts just the stream header on `from_env` into `into_env`.
fn induct_stream_header(
    from_env: &StateMachine,
    into_env: &StateMachine,
) -> Result<(), EncodeStreamError> {
    induct_from_head_of_stream(from_env, into_env, Some(0))
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
/// aborted or not. The condition is wrapped in `Result` so that the `?` operator can be used
/// in the closure `f`.
/// This is useful as a safety wrapper for code where we tick on a state machine
/// until an exit condition is met. Since this usually depends on a canister that could stall
/// or otherwise take an unreasonably long amount of time to reach the exit condition, this
/// function makes sure a panic is triggered rather than hanging forever.
/// Returns the number of iterations until the exit condition was met, or an error message
/// indicating that the counter exceeded `max_iterations`.
fn do_until_or_panic<F>(max_iterations: u64, mut f: F) -> Result<u64, String>
where
    F: FnMut(u64) -> Result<bool, String>,
{
    for counter in 1..=max_iterations {
        if f(counter)? {
            return Ok(counter);
        }
    }
    Err(format!(
        "Exit condition not met after {} iterations.",
        max_iterations
    ))
}

/// Test timing out requests in output queues, by completely filling up the XNet stream with
/// messages from a local canister, such that messages start piling up in its output queue.
/// Then advance the time and execute a round to trigger a timeout; then check the output queue
/// has been emptied out.
#[test]
fn test_timeout_removes_requests_from_output_queues() {
    let subnets = SubnetPairProxy::with_new_subnets();

    let canister_to_subnet_rate = 10;
    let payload_size_bytes = 1024 * 1024;

    // Send requests until there are messages in the output queue, then stop sending
    // requests and trigger a timeout. The queue should be empty afterwards.
    subnets
        .call_start_on_local_canister(canister_to_subnet_rate, payload_size_bytes)
        .unwrap();
    subnets.build_local_backpressure_until(1);
    subnets.call_stop_on_local_canister().unwrap();
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
    let subnets = SubnetPairProxy::with_new_subnets();

    let canister_to_subnet_rate = 10;
    let payload_size_bytes = 1024 * 1024;

    // Make the local canister send requests until there are messages in the output queue
    // (i.e. the stream is full); then call 'stop' and wipe the queue by triggering a timeout.
    subnets
        .call_start_on_local_canister(canister_to_subnet_rate, payload_size_bytes)
        .unwrap();
    subnets.build_local_backpressure_until(1);
    subnets.call_stop_on_local_canister().unwrap();
    execute_round_with_timeout(&subnets.local_env);

    // Call the 'start' method on the remote canister to start sending requests to the local
    // canister. Do one tick and then induct one xnet request into the local canister, which
    // should produce one response in its output queue back to the remote canister.
    subnets
        .call_start_on_remote_canister(canister_to_subnet_rate, payload_size_bytes)
        .unwrap();
    subnets.remote_env.tick();
    induct_from_head_of_stream(&subnets.remote_env, &subnets.local_env, Some(1)).unwrap();
    assert_matches!(
        subnets.local_output_queue_snapshot().as_deref(),
        Some([RequestOrResponse::Response(_)])
    );

    // Call the 'start' method on canister 1 to restart sending requests using
    // a high rate and small payload to generate a lot of messages quickly.
    let canister_to_subnet_rate = 100;
    let payload_size_bytes = 128;
    subnets
        .call_start_on_local_canister(canister_to_subnet_rate, payload_size_bytes)
        .unwrap();

    // Keep ticking and triggering timeouts until the XNet canister starts
    // reporting call errors, indicating back pressure.
    do_until_or_panic(MAX_TICKS, |_| {
        execute_round_with_timeout(&subnets.local_env);
        let reply = subnets.query_local_canister("metrics", Vec::new()).unwrap();
        Ok(Decode!(&reply.bytes(), Metrics).unwrap().call_errors > 0)
    })
    .unwrap();

    // Check that the local output queue only contains the response.
    assert_matches!(
        subnets.local_output_queue_snapshot().as_deref(),
        Some([RequestOrResponse::Response(_)])
    );

    // Call the 'stop' method on the local canister, then induct a request from the local subnet
    // into the remote subnet.
    subnets.call_stop_on_local_canister().unwrap();
    induct_from_head_of_stream(&subnets.local_env, &subnets.remote_env, Some(1)).unwrap();

    // Trigger a request to be gc'ed by inducting an ACK signal.
    induct_stream_header(&subnets.remote_env, &subnets.local_env).unwrap();

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
    let subnets = SubnetPairProxy::with_new_subnets();

    let canister_to_subnet_rate = 100;
    let payload_size_bytes = 128;

    // Call start on both canisters and tick until call errors are encountered,
    // indicating back pressure.
    subnets
        .call_start_on_local_canister(canister_to_subnet_rate, payload_size_bytes)
        .unwrap();
    do_until_or_panic(MAX_TICKS, |_| {
        subnets.local_env.tick();
        let reply = subnets.query_local_canister("metrics", Vec::new()).unwrap();
        Ok(Decode!(&reply.bytes(), Metrics).unwrap().call_errors > 0)
    })
    .unwrap();

    subnets
        .call_start_on_remote_canister(canister_to_subnet_rate, payload_size_bytes)
        .unwrap();
    do_until_or_panic(MAX_TICKS, |_| {
        subnets.remote_env.tick();
        let reply = subnets
            .query_remote_canister("metrics", Vec::new())
            .unwrap();
        Ok(Decode!(&reply.bytes(), Metrics).unwrap().call_errors > 0)
    })
    .unwrap();

    // Try inducting all the requests successfully sent by the remote canister into
    // the local canister.
    let reply = subnets
        .query_remote_canister("metrics", Vec::new())
        .unwrap();
    let metrics = Decode!(&reply.bytes(), Metrics).unwrap();
    induct_from_head_of_stream(
        &subnets.remote_env,
        &subnets.local_env,
        Some(metrics.requests_sent),
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

/// Snapshot of a message in a stream or a queue that includes only the message variant and the callback id.
#[derive(Clone, PartialEq)]
enum MessageSnapshot {
    Request(CallbackId),        // Request
    Response(CallbackId),       // Response
    RejectResponse(CallbackId), // RejectResponse
    TimedOutRequest,            // TimedOutRequest
}

/// Provides snappy debug prints.
impl std::fmt::Debug for MessageSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageSnapshot::Request(id) => f.debug_tuple("Q").field(id).finish(),
            MessageSnapshot::Response(id) => f.debug_tuple("P").field(id).finish(),
            MessageSnapshot::RejectResponse(id) => f.debug_tuple("J").field(id).finish(),
            MessageSnapshot::TimedOutRequest => f.debug_tuple("T").finish(),
        }
    }
}

impl From<&RequestOrResponse> for MessageSnapshot {
    fn from(msg: &RequestOrResponse) -> Self {
        use RequestOrResponse::{Request, Response};
        match msg {
            Request(request) => Self::Request(request.sender_reply_callback),
            Response(response) if matches!(response.response_payload, Payload::Data(_)) => {
                Self::Response(response.originator_reply_callback)
            }
            Response(response) => Self::RejectResponse(response.originator_reply_callback),
        }
    }
}

impl From<&Option<RequestOrResponse>> for MessageSnapshot {
    fn from(msg: &Option<RequestOrResponse>) -> Self {
        match msg {
            Some(msg) => msg.into(),
            None => Self::TimedOutRequest,
        }
    }
}

/// Contains the current state of the test `subnet_splitting_test_suite` below.
#[derive(Clone, PartialEq)]
struct SubnetSplittingTestState {
    stream: Option<(StreamHeader, Vec<MessageSnapshot>)>,
    local_queue: Option<Vec<MessageSnapshot>>,
    reverse_stream: Option<(StreamHeader, Vec<MessageSnapshot>)>,
    remote_queue: Option<Vec<MessageSnapshot>>,
    local_callback_id_tracker: BTreeSet<CallbackId>,
    remote_callback_id_tracker: BTreeSet<CallbackId>,
}

impl SubnetSplittingTestState {
    fn new(
        subnets_proxy: &SubnetPairProxy,
        local_callback_id_tracker: BTreeSet<CallbackId>,
        remote_callback_id_tracker: BTreeSet<CallbackId>,
    ) -> Self {
        let stream = stream_snapshot(&subnets_proxy.local_env, &subnets_proxy.remote_env).map(
            |(header, msgs)| {
                (
                    header,
                    msgs.iter().map(|(_, msg)| msg.into()).collect::<_>(),
                )
            },
        );
        let reverse_stream = stream_snapshot(&subnets_proxy.remote_env, &subnets_proxy.local_env)
            .map(|(header, msgs)| {
                (
                    header,
                    msgs.iter().map(|(_, msg)| msg.into()).collect::<_>(),
                )
            });
        let local_queue = subnets_proxy
            .local_output_queue_snapshot()
            .map(|msgs| msgs.iter().map(|msg| msg.into()).collect::<_>());
        let remote_queue = subnets_proxy
            .remote_output_queue_snapshot()
            .map(|msgs| msgs.iter().map(|msg| msg.into()).collect::<_>());

        Self {
            stream,
            local_queue,
            reverse_stream,
            remote_queue,
            local_callback_id_tracker,
            remote_callback_id_tracker,
        }
    }
}

/// Custom pretty printer. This is useful because the options otherwise provided either print
/// everything horizontal, which is hard to read, or everything vertical, which makes it hard to
/// follow the flow of the test because each step takes up far more vertical space than required.
impl std::fmt::Debug for SubnetSplittingTestState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "[")?;
        if let Some((header, messages)) = &self.stream {
            writeln!(f, "   stream:")?;
            writeln!(f, "      {:?}", header)?;
            if !messages.is_empty() {
                writeln!(f, "      {:?}", messages)?;
            }
        }
        if let Some(messages) = &self.local_queue {
            if !messages.is_empty() {
                writeln!(f, "   local queue: {:?}", messages)?;
            }
        }
        if let Some((header, messages)) = &self.reverse_stream {
            writeln!(f, "   reverse stream:")?;
            writeln!(f, "      {:?}", header)?;
            if !messages.is_empty() {
                writeln!(f, "      {:?}", messages)?;
            }
        }
        if let Some(messages) = &self.remote_queue {
            if !messages.is_empty() {
                writeln!(f, "   remote queue: {:?}", messages)?;
            }
        }
        writeln!(
            f,
            "   local_callback_id_tracker: {:?}",
            &self.local_callback_id_tracker
        )?;
        writeln!(
            f,
            "   remote_callback_id_tracker: {:?}",
            &self.remote_callback_id_tracker
        )?;
        write!(f, "]")
    }
}

/// Adds / Removes a message's callback id to/from a tracker according to:
/// - msg is a request: The callback id is added to `add_callback_id_tracker`.
/// - msg is a response: The callback id is removed from `remove_callback_id_tracker`.
fn update_callback_id_trackers(
    msg: &RequestOrResponse,
    add_callback_id_tracker: &mut BTreeSet<CallbackId>,
    remove_callback_id_tracker: &mut BTreeSet<CallbackId>,
) -> Result<(), String> {
    use RequestOrResponse::{Request, Response};
    match msg {
        Request(request) => {
            if !add_callback_id_tracker.insert(request.sender_reply_callback) {
                return Err(format!(
                    "Duplicate callback id {:?} already found in {:?}.",
                    request.sender_reply_callback, add_callback_id_tracker,
                ));
            }
        }
        Response(response) => {
            if !remove_callback_id_tracker.remove(&response.originator_reply_callback) {
                return Err(format!(
                    "Callback id {:?} not found in {:?}.",
                    response.originator_reply_callback, remove_callback_id_tracker,
                ));
            }
        }
    }
    Ok(())
}

/// Inducts `msg_limit` messages and adds/removes their callback ids to/from trackers at the same time.
///
/// Note: Callback IDs are unique per canister and remain so even after canister migration,
///       since a canister migration just copies the whole state as is to another subnet.
///
/// A Callback ID observed in a XNet stream must have originated in a canister installed on the
/// subnet the stream belongs to. OTOH since a response is only generated upon request (with the same
/// Callback ID), its Callback ID must belong to a canister installed on the other subnet.
/// The above is always true except during subnet splitting, where the canister may have been moved
/// intermediately. However, this is irrelevant because during migration, the whole canister state is
/// moved, such that evolution of Callback IDs progresses as it would have on the old subnet.
///
/// Tracking Callback IDs thus works as follows:
/// - If a request is observed in the `stream`, add its Callback ID to a tracker.
/// - If a response is observed in the `reverse_stream`, remove its Callback ID from a tracker
///   (unless the response was rejected).
///
/// Since each message starts as a request on one side and then becomes a response on the other
/// side, this mechanism will ensure each message undergoes its cycle exactly once. I.e. multiple
/// inductions would be registered as duplicate Callback IDs and no induction would result in
/// non-empty trackers after the fact.
fn induct_messages_and_track_callback_ids(
    from_subnet: &StateMachine,
    into_subnet: &StateMachine,
    add_callback_id_tracker: &mut BTreeSet<CallbackId>,
    remove_callback_id_tracker: &mut BTreeSet<CallbackId>,
    msg_limit: Option<usize>,
) -> Result<(), String> {
    match stream_snapshot(from_subnet, into_subnet) {
        Some((_, messages)) if !messages.is_empty() => {
            // Induct messages.
            induct_from_head_of_stream(from_subnet, into_subnet, msg_limit).unwrap();

            // Register/Deregister callback id's. Skip id's whose message triggered a reject signal
            // in the opposite stream.
            let (reverse_header, _) = stream_snapshot(into_subnet, from_subnet).unwrap();
            for (stream_index, msg) in messages
                .iter()
                .take_while(|(stream_index, _)| *stream_index < reverse_header.signals_end())
            {
                if !reverse_header
                    .reject_signals()
                    .iter()
                    .any(|signal| signal.index == stream_index)
                {
                    update_callback_id_trackers(
                        msg,
                        add_callback_id_tracker,
                        remove_callback_id_tracker,
                    )?;
                }
            }
        }
        Some(_) => {
            // Induct the stream header containing signals; triggers garbage collection of
            // messages in the opposite stream.
            induct_stream_header(from_subnet, into_subnet).unwrap()
        }
        None => {}
    }
    Ok(())
}

/// Inducts messages from `local_env` into `remote_env` and vice versa. After each bidirectional
/// induction cycle, the state of the subnets proxy is observed and recorded.
/// Stops when two subsequent state records are identical, i.e. the subnets proxy is 'stale'.
/// Such a situation occurs when no more messages are inducted, nothing is gc'ed or no tracker is
/// updated. This should only occur when there are no more messages in `subnets_proxy`, but we
/// should abort as soon as no more progress is made in any case.
///
/// # Panics
///
/// This function panics if the `subnets_proxy` is not 'stale' within `MAX_TICKS` induction cycles.
fn induct_and_observe_until_stale(
    subnets_proxy: &SubnetPairProxy,
    local_callback_id_tracker: &mut BTreeSet<CallbackId>,
    remote_callback_id_tracker: &mut BTreeSet<CallbackId>,
) -> Result<Vec<SubnetSplittingTestState>, (Vec<SubnetSplittingTestState>, String)> {
    let mut test_states = Vec::new();

    // Observe initial state.
    test_states.push(SubnetSplittingTestState::new(
        subnets_proxy,
        local_callback_id_tracker.clone(),
        remote_callback_id_tracker.clone(),
    ));

    // Do inductions until no more changes in the test state are observed.
    if let Err(errmsg) = do_until_or_panic(MAX_TICKS, |_| {
        // Induct messages `local_env` -> `remote_env`.
        induct_messages_and_track_callback_ids(
            &subnets_proxy.local_env,   // from_subnet
            &subnets_proxy.remote_env,  // into_subnet
            local_callback_id_tracker,  // add_callback_id_set
            remote_callback_id_tracker, // remove_callback_id_set
            None,                       // msg_limit
        )?;
        // Induct messages `remote_env` -> `local_env`.
        induct_messages_and_track_callback_ids(
            &subnets_proxy.remote_env,  // from_subnet
            &subnets_proxy.local_env,   // into_subnet
            remote_callback_id_tracker, // add_callback_id_set
            local_callback_id_tracker,  // remove_callback_id_set
            None,                       // msg_limit
        )?;

        // Observe test state post inductions; Append only if changes were observed.
        let post_inductions = SubnetSplittingTestState::new(
            subnets_proxy,
            local_callback_id_tracker.clone(),
            remote_callback_id_tracker.clone(),
        );
        match &test_states[..] {
            [.., pre_inductions] if *pre_inductions != post_inductions => {
                test_states.push(post_inductions);
                Ok(false)
            }
            _ => Ok(true),
        }
    }) {
        Err((test_states, errmsg))
    } else {
        Ok(test_states)
    }
}

/// Tests bidirectional traffic between two canisters works as intended, even if one canister is
/// migrated at some point. The main property this test must verify, is that each request receives
/// exactly one response.
/// This can be achieved in an all-in-one fashion using two instances of `SubnetPairProxy` (which is a
/// convenience handle for the bidirectional communication between a pair of subnets), such that
/// `local_env` is the same subnet on both proxies, but `remote_env` is a different subnet and only
/// one of the `remote_env` actually hosts the remote canister. If we make sure that all of the streams
/// involved in this setup have both requests and responses in them, then all of the cases related to
/// rejecting requests or rerouting responses should be covered.
///
/// This can be put in place by initially generating requests and responses on `old_subnets_proxy`
/// until both streams and output queues have requests and responses in them. If at this point the
/// remote canister is migrated to another subnet along with routing table updates, the messages in
/// the output queues will slip into streams on both the `new_subnets_proxy.local_env` (due to the
/// routing table update) and the `new_subnets_proxy.remote_env` (due to the canister migration to a
/// new subnet). The messages in the old streams however still remain.
/// The initial setup for this test is depicted in the following two drawings:
///
///
/// `new_subnets_proxy.local_env` | `new_subnets_proxy.remote_env`     The remote canister C' is
///             +---+             |                                    located on `remote_env`.
///   +-------- | C | <------------------ {Q', Q', P, Q'} <----+       This is essentially business
///   |         +---+             |        reverse_stream      |       as usual, except that the
///   |                           |                            |       responses in the reverse
///   |                           |            +----+          |       stream are due to requests
///   +----> {Q, P', Q, Q} ------------------> | C' | ---------+       originally sent to a
///             stream            |            +----+                  different subnet.
///
///
///
/// `old_subnets_proxy.local_env` | `old_subnets_proxy.remote_env`     The remote canister C' has
///                               |                                    migrated and is no longer
///             +---+             |                                    hosted on `remote_env`.
///   +-------- | C | <------------------- {P, Q', Q', Q'} <---+       The messages in the stream
///   |         +---+             |        reverse_stream      |       routed to `remote_env` can
///   |                           |                            |       not be delivered.
///   +----> {Q, Q, P', Q} ------------------------------------+       Requests can be rejected,
///             stream            |            [ .. ]                  but responses receive reject
///                               |        reject_signals              signals and are rerouted.
///
///
/// Note that inductions on `old_subnets_proxy` can only lead to removing messages from the system
/// if a response is consumed successfully or else responses that are routed to streams found on
/// `new_subnets_proxy` due to the change in the routing tables.
/// The sequence of events is therefore as follows:
/// - After the initial situation as depicted above, the XNet canisters stop generating requests.
/// - Bidirectional inductions are done on `old_subnets_proxy` until they stop triggering changes.
/// - Bidirectional inductions are done on `new_subnets_proxy` until they stop triggering changes.
///
/// If everything went in order, at this point:
/// - There are no more messages in the system.
/// - Each request received a response at some point.
///
/// Both of these things can be checked by simply stopping both canisters after the fact, since
/// both canisters can only reach the 'stopped' state if there are any outstanding requests
/// (i.e., ones that didn't receive responses).
///
/// There is however an additional mechanism in place that tracks the current state the test is in
/// as it is otherwise very difficult to understand what is going on. At each step, the message
/// variant (request, response, reject response) is recorded along with its Callback ID.
///
/// Since Callback ID's are unique for each canister, this additionally allows the tracking of ID's
/// during inductions such that when a request is observed in the stream, it's ID is tracked until
/// a response with the same ID is observed in the reverse stream after which the ID is removed.
/// This way it can be made sure that each message's lifecycle is undergone to conclusion because
/// then both trackers must be empty after the fact (implying each request got a response eventually).
/// Note that reject signals must be considered here, i.e. responses may be rerouted and we may
/// only consider their Callback IDs after successful induction.
///
/// Lastly, the sequence of events the test undergoes after each step of bidirectinal inductions is
/// printed out in any case, so that it can be manually verified that the test actually does
/// include all the relevant subnet splitting scenarios.
#[test]
fn state_machine_subnet_splitting_test() {
    use RequestOrResponse::{Request, Response};
    let old_subnets_proxy = SubnetPairProxy::with_new_subnets();
    old_subnets_proxy.mark_remote_canister_as_being_migrated();

    // To ensure all call contexts are closed properly, we keep track of callback ids by
    // canister.
    let mut local_callback_id_tracker = BTreeSet::<CallbackId>::new();
    let mut remote_callback_id_tracker = BTreeSet::<CallbackId>::new();

    // Setup subnets by executing rounds of bidirectional traffic. Each round, 3 large requests
    // are generated and the first message in `stream` (`reverse_stream`) is inducted into `remote_env`
    // (`local_env`). This will produce messages in a ratio of 3:1 of requests vs responses until
    // enough backpressure is built such that messages start piling up in output queues.
    // The setup is complete when when both output queues contain at least one request and at least
    // one response.
    old_subnets_proxy
        .call_start_on_local_canister(3, 1024 * 1024)
        .unwrap();
    old_subnets_proxy.local_env.tick();
    old_subnets_proxy
        .call_start_on_remote_canister(3, 1024 * 1024)
        .unwrap();
    old_subnets_proxy.remote_env.tick();
    do_until_or_panic(MAX_TICKS, |_| {
        induct_messages_and_track_callback_ids(
            &old_subnets_proxy.local_env,    // from_subnet
            &old_subnets_proxy.remote_env,   // into_subnet
            &mut local_callback_id_tracker,  // add_callback_id_set
            &mut remote_callback_id_tracker, // remove_callback_id_set
            Some(1),                         // msg_limit
        )?;
        induct_messages_and_track_callback_ids(
            &old_subnets_proxy.remote_env,   // from_subnet
            &old_subnets_proxy.local_env,    // into_subnet
            &mut remote_callback_id_tracker, // add_callback_id_set
            &mut local_callback_id_tracker,  // remove_callback_id_set
            Some(1),                         // msg_limit
        )?;

        // Exit condition.
        match (
            old_subnets_proxy.local_output_queue_snapshot(),
            old_subnets_proxy.remote_output_queue_snapshot(),
        ) {
            (Some(local_q), Some(remote_q)) => {
                Ok(local_q.iter().any(|msg| matches!(msg, Request(_)))
                    && local_q.iter().any(|msg| matches!(msg, Response(_)))
                    && remote_q.iter().any(|msg| matches!(msg, Request(_)))
                    && remote_q.iter().any(|msg| matches!(msg, Response(_))))
            }
            _ => Ok(false),
        }
    })
    .expect("Setup stage error");
    old_subnets_proxy.call_stop_on_local_canister().unwrap();
    old_subnets_proxy.call_stop_on_remote_canister().unwrap();

    // Migrate canister, which includes updating the routing table on all subnets.
    let new_subnets_proxy = old_subnets_proxy
        .move_remote_canister_to_destination_subnet()
        .unwrap();

    // Tick once on both subnets, to trigger messages slipping into streams.
    new_subnets_proxy.remote_env.tick();
    new_subnets_proxy.local_env.tick();

    // Make sure there really are request(s) and responses(s) in all the streams since otherwise
    // the test might complete without reporting an issue.
    for (from_env, into_env) in [
        (&old_subnets_proxy.local_env, &old_subnets_proxy.remote_env),
        (&old_subnets_proxy.remote_env, &old_subnets_proxy.local_env),
        (&new_subnets_proxy.local_env, &new_subnets_proxy.remote_env),
        (&new_subnets_proxy.remote_env, &new_subnets_proxy.local_env),
    ] {
        if let Some((_, stream)) = stream_snapshot(from_env, into_env) {
            assert!(stream.iter().any(|(_, msg)| matches!(msg, Request(_))));
            assert!(stream.iter().any(|(_, msg)| matches!(msg, Response(_))));
        } else {
            panic!("Empty stream after setup stage.");
        }
    }

    // Do bidirectional inductions until no more changes in the state of `old_subnet_proxy`
    // are observed.
    let old_test_states = induct_and_observe_until_stale(
        &old_subnets_proxy,
        &mut local_callback_id_tracker,
        &mut remote_callback_id_tracker,
    )
    .expect("old_subnet_proxy induction stage");

    // Do bidirectional inductions until no more changes in the state of `new_subnet_proxy`
    // are observed.
    let new_test_states = induct_and_observe_until_stale(
        &new_subnets_proxy,
        &mut local_callback_id_tracker,
        &mut remote_callback_id_tracker,
    )
    .expect("new_subnet_proxy induction stage");

    let print_test_states = || {
        format!(
            "old_subnet_proxy inductions:\n{:#?}\nnew_subnet_proxy inductions:\n{:#?}",
            old_test_states, new_test_states,
        )
    };

    // Print final test state sequence.
    println!("{}", print_test_states());

    // No more changes in bidirectional inductions must imply empty streams.
    for (from_env, into_env) in [
        (&old_subnets_proxy.local_env, &old_subnets_proxy.remote_env),
        (&old_subnets_proxy.remote_env, &old_subnets_proxy.local_env),
        (&new_subnets_proxy.local_env, &new_subnets_proxy.remote_env),
        (&new_subnets_proxy.remote_env, &new_subnets_proxy.local_env),
    ] {
        assert!(stream_snapshot(from_env, into_env)
            .map(|(_, stream)| stream.is_empty())
            .unwrap_or(true));
    }

    // No messages in the system must imply empty callback id trackers because of
    // guaranteed responses to requests (once they reach a stream).
    assert!(
        local_callback_id_tracker.is_empty(),
        "{}",
        print_test_states()
    );
    assert!(
        remote_callback_id_tracker.is_empty(),
        "{}",
        print_test_states()
    );

    // Attempt to stop canisters; This will panic if there are any lingering call contexts.
    new_subnets_proxy.stop_local_canister().unwrap();
    new_subnets_proxy.stop_remote_canister().unwrap();
}
