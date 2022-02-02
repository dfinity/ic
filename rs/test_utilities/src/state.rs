use crate::{
    mock_time,
    types::{
        arbitrary,
        ids::{canister_test_id, message_test_id, subnet_test_id, user_test_id},
        messages::SignedIngressBuilder,
    },
};
use ic_base_types::NumSeconds;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    canister_state::{
        execution_state::{CustomSection, CustomSectionType, WasmBinary, WasmMetadata},
        testing::new_canister_queues_for_test,
        QUEUE_INDEX_NONE,
    },
    metadata_state::Stream,
    page_map::PageMap,
    testing::{CanisterQueuesTesting, ReplicatedStateTesting, SystemStateTesting},
    CallContext, CallOrigin, CanisterState, CanisterStatus, ExecutionState, ExportedFunctions,
    InputQueueType, Memory, NumWasmPages, ReplicatedState, SchedulerState, SystemState,
};
use ic_types::{
    messages::{Ingress, Request, RequestOrResponse},
    xnet::{QueueId, StreamIndex, StreamIndexedQueue},
    CanisterId, CanisterStatusType, ComputeAllocation, Cycles, ExecutionRound, MemoryAllocation,
    NumBytes, PrincipalId, QueueIndex, SubnetId, Time,
};
use ic_wasm_types::BinaryEncodedWasm;
use proptest::prelude::*;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::convert::TryFrom;
use std::sync::Arc;

const WASM_PAGE_SIZE_BYTES: usize = 65536;
const DEFAULT_FREEZE_THRESHOLD: NumSeconds = NumSeconds::new(1 << 30);
const INITIAL_CYCLES: Cycles = Cycles::new(5_000_000_000_000);

pub struct ReplicatedStateBuilder {
    canisters: Vec<CanisterState>,
    subnet_type: SubnetType,
    subnet_id: SubnetId,
    batch_time: Time,
    time_of_last_allocation_charge: Time,
}

impl ReplicatedStateBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_subnet_id(mut self, subnet_id: SubnetId) -> Self {
        self.subnet_id = subnet_id;
        self
    }

    pub fn with_canister(mut self, canister: CanisterState) -> Self {
        self.canisters.push(canister);
        self
    }

    pub fn with_subnet_type(mut self, subnet_type: SubnetType) -> Self {
        self.subnet_type = subnet_type;
        self
    }

    pub fn with_time(mut self, time: Time) -> Self {
        self.batch_time = time;
        self
    }

    pub fn with_time_of_last_allocation(mut self, time: Time) -> Self {
        self.time_of_last_allocation_charge = time;
        self
    }

    pub fn build(self) -> ReplicatedState {
        let mut state =
            ReplicatedState::new_rooted_at(self.subnet_id, self.subnet_type, "Initial".into());

        for canister in self.canisters {
            state.put_canister_state(canister);
        }

        state.metadata.batch_time = self.batch_time;
        state.metadata.time_of_last_allocation_charge = self.time_of_last_allocation_charge;

        state
    }
}

impl Default for ReplicatedStateBuilder {
    fn default() -> Self {
        Self {
            canisters: Vec::new(),
            subnet_type: SubnetType::Application,
            subnet_id: subnet_test_id(1),
            batch_time: mock_time(),
            time_of_last_allocation_charge: mock_time(),
        }
    }
}

pub struct CanisterStateBuilder {
    canister_id: CanisterId,
    controller: PrincipalId,
    cycles: Cycles,
    stable_memory: Option<Vec<u8>>,
    wasm: Option<Vec<u8>>,
    memory_allocation: MemoryAllocation,
    compute_allocation: ComputeAllocation,
    ingress_queue: Vec<Ingress>,
    status: CanisterStatusType,
    freeze_threshold: NumSeconds,
    call_contexts: Vec<CallContext>,
    inputs: Vec<RequestOrResponse>,
}

impl CanisterStateBuilder {
    pub fn new() -> Self {
        // Initialize with sensible defaults.
        Self::default()
    }

    pub fn with_canister_id(mut self, canister_id: CanisterId) -> Self {
        self.canister_id = canister_id;
        self
    }

    pub fn with_controller<P: Into<PrincipalId>>(mut self, controller: P) -> Self {
        self.controller = controller.into();
        self
    }

    pub fn with_stable_memory(mut self, data: Vec<u8>) -> Self {
        self.stable_memory = Some(data);
        self
    }

    pub fn with_cycles<C: Into<Cycles>>(mut self, cycles: C) -> Self {
        self.cycles = cycles.into();
        self
    }

    pub fn with_wasm(mut self, wasm: Vec<u8>) -> Self {
        self.wasm = Some(wasm);
        self
    }

    pub fn with_memory_allocation<B: Into<NumBytes>>(mut self, num_bytes: B) -> Self {
        self.memory_allocation = MemoryAllocation::try_from(num_bytes.into()).unwrap();
        self
    }

    pub fn with_compute_allocation(mut self, allocation: ComputeAllocation) -> Self {
        self.compute_allocation = allocation;
        self
    }

    pub fn with_ingress(mut self, ingress: Ingress) -> Self {
        self.ingress_queue.push(ingress);
        self
    }

    pub fn with_status(mut self, status: CanisterStatusType) -> Self {
        self.status = status;
        self
    }

    pub fn with_freezing_threshold<S: Into<NumSeconds>>(mut self, ft: S) -> Self {
        self.freeze_threshold = ft.into();
        self
    }

    pub fn with_call_context(mut self, call_context: CallContext) -> Self {
        self.call_contexts.push(call_context);
        self
    }

    pub fn with_input(mut self, input: RequestOrResponse) -> Self {
        self.inputs.push(input);
        self
    }

    pub fn with_canister_request(mut self, request: Request) -> Self {
        self.inputs.push(RequestOrResponse::Request(request));
        self
    }

    pub fn build(self) -> CanisterState {
        let mut system_state = match self.status {
            CanisterStatusType::Running => SystemState::new_running(
                self.canister_id,
                self.controller,
                self.cycles,
                self.freeze_threshold,
            ),
            CanisterStatusType::Stopping => SystemState::new_stopping(
                self.canister_id,
                self.controller,
                self.cycles,
                self.freeze_threshold,
            ),
            CanisterStatusType::Stopped => SystemState::new_stopped(
                self.canister_id,
                self.controller,
                self.cycles,
                self.freeze_threshold,
            ),
        };

        system_state.memory_allocation = self.memory_allocation;

        // Add ingress messages to the canister's queues.
        for ingress in self.ingress_queue.into_iter() {
            system_state.queues_mut().push_ingress(ingress)
        }

        // Set call contexts. Because there is no way pass in a `CallContext`
        // object to `CallContextManager`, we have to construct them in this
        // bizarre way.
        for call_context in self.call_contexts.into_iter() {
            let call_context_manager = system_state.call_context_manager_mut().unwrap();
            let call_context_id = call_context_manager.new_call_context(
                call_context.call_origin().clone(),
                call_context.available_cycles(),
            );

            let call_context_in_call_context_manager = call_context_manager
                .call_context_mut(call_context_id)
                .unwrap();
            if call_context.has_responded() {
                call_context_in_call_context_manager.mark_responded();
            }
            if call_context.is_deleted() {
                call_context_in_call_context_manager.mark_deleted();
            }
        }

        // Add inputs to the input queue.
        for input in self.inputs {
            system_state
                .queues_mut()
                .push_input(QUEUE_INDEX_NONE, input, InputQueueType::RemoteSubnet)
                .unwrap();
        }

        let stable_memory = if let Some(data) = self.stable_memory {
            Memory::new(
                PageMap::from(&data[..]),
                NumWasmPages::new((data.len() / WASM_PAGE_SIZE_BYTES) as usize + 1),
            )
        } else {
            Memory::default()
        };

        let execution_state = match self.wasm {
            Some(wasm_binary) => {
                let mut ee = initial_execution_state();
                ee.wasm_binary = WasmBinary::new(BinaryEncodedWasm::new(wasm_binary));
                ee.stable_memory = stable_memory;
                Some(ee)
            }
            None => None,
        };

        CanisterState {
            system_state,
            execution_state,
            scheduler_state: SchedulerState {
                compute_allocation: self.compute_allocation,
                ..SchedulerState::default()
            },
        }
    }
}

impl Default for CanisterStateBuilder {
    fn default() -> Self {
        Self {
            canister_id: canister_test_id(0),
            controller: user_test_id(0).get(),
            cycles: INITIAL_CYCLES,
            stable_memory: None,
            wasm: None,
            memory_allocation: MemoryAllocation::BestEffort,
            compute_allocation: ComputeAllocation::zero(),
            ingress_queue: Vec::default(),
            status: CanisterStatusType::Running,
            freeze_threshold: DEFAULT_FREEZE_THRESHOLD,
            call_contexts: Vec::default(),
            inputs: Vec::default(),
        }
    }
}

pub struct SystemStateBuilder {
    system_state: SystemState,
}

impl Default for SystemStateBuilder {
    fn default() -> Self {
        Self {
            system_state: SystemState::new_running(
                canister_test_id(42),
                user_test_id(24).get(),
                INITIAL_CYCLES,
                DEFAULT_FREEZE_THRESHOLD,
            ),
        }
    }
}

impl SystemStateBuilder {
    pub fn new() -> Self {
        Self {
            system_state: SystemState::new_running(
                canister_test_id(42),
                user_test_id(24).get(),
                INITIAL_CYCLES,
                DEFAULT_FREEZE_THRESHOLD,
            ),
        }
    }

    pub fn initial_cycles(mut self, cycles: Cycles) -> Self {
        self.system_state.cycles_balance = cycles;
        self
    }

    pub fn canister_id(mut self, canister_id: CanisterId) -> Self {
        self.system_state.set_canister_id(canister_id);
        self
    }

    pub fn memory_allocation(mut self, memory_allocation: NumBytes) -> Self {
        self.system_state.memory_allocation =
            MemoryAllocation::try_from(memory_allocation).unwrap();
        self
    }

    pub fn freeze_threshold(mut self, threshold: NumSeconds) -> Self {
        self.system_state.freeze_threshold = threshold;
        self
    }

    pub fn build(self) -> SystemState {
        self.system_state
    }
}

pub struct CallContextBuilder {
    call_origin: CallOrigin,
    responded: bool,
}

impl CallContextBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_call_origin(mut self, call_origin: CallOrigin) -> Self {
        self.call_origin = call_origin;
        self
    }

    pub fn with_responded(mut self, responded: bool) -> Self {
        self.responded = responded;
        self
    }

    pub fn build(self) -> CallContext {
        CallContext::new(self.call_origin, self.responded, false, Cycles::from(0))
    }
}

impl Default for CallContextBuilder {
    fn default() -> Self {
        Self {
            call_origin: CallOrigin::Ingress(user_test_id(0), message_test_id(0)),
            responded: false,
        }
    }
}

pub fn initial_execution_state() -> ExecutionState {
    let mut metadata: BTreeMap<String, CustomSection> = BTreeMap::new();
    metadata.insert(
        String::from("candid"),
        CustomSection {
            visibility: CustomSectionType::Private,
            content: vec![0, 2],
        },
    );
    metadata.insert(
        String::from("dummy"),
        CustomSection {
            visibility: CustomSectionType::Public,
            content: vec![2, 1],
        },
    );
    let wasm_metadata = WasmMetadata::new(metadata);

    ExecutionState {
        canister_root: "NOT_USED".into(),
        session_nonce: None,
        wasm_binary: WasmBinary::new(BinaryEncodedWasm::new(vec![])),
        wasm_memory: Memory::default(),
        stable_memory: Memory::default(),
        exported_globals: vec![],
        exports: ExportedFunctions::new(BTreeSet::new()),
        metadata: wasm_metadata,
        last_executed_round: ExecutionRound::from(0),
    }
}

pub fn canister_from_exec_state(
    execution_state: ExecutionState,
    canister_id: CanisterId,
) -> CanisterState {
    CanisterState {
        system_state: SystemStateBuilder::new()
            .memory_allocation(NumBytes::new(8 * 1024 * 1024 * 1024)) // 8GiB
            .canister_id(canister_id)
            .build(),
        execution_state: Some(execution_state),
        scheduler_state: Default::default(),
    }
}

pub fn get_running_canister_with_balance(
    canister_id: CanisterId,
    initial_balance: Cycles,
) -> CanisterState {
    get_running_canister_with_args(canister_id, user_test_id(1).get(), initial_balance)
}

pub fn get_running_canister(canister_id: CanisterId) -> CanisterState {
    get_running_canister_with_balance(canister_id, INITIAL_CYCLES)
}

pub fn get_running_canister_with_args(
    canister_id: CanisterId,
    controller: PrincipalId,
    initial_cycles: Cycles,
) -> CanisterState {
    CanisterState {
        system_state: SystemState::new_running(
            canister_id,
            controller,
            initial_cycles,
            DEFAULT_FREEZE_THRESHOLD,
        ),
        execution_state: None,
        scheduler_state: Default::default(),
    }
}

pub fn get_stopping_canister(canister_id: CanisterId) -> CanisterState {
    get_stopping_canister_with_controller(canister_id, user_test_id(1).get())
}

pub fn get_stopping_canister_on_nns(canister_id: CanisterId) -> CanisterState {
    get_stopping_canister_with_controller(canister_id, user_test_id(1).get())
}

pub fn get_stopping_canister_with_controller(
    canister_id: CanisterId,
    controller: PrincipalId,
) -> CanisterState {
    CanisterState {
        system_state: SystemState::new_stopping(
            canister_id,
            controller,
            INITIAL_CYCLES,
            DEFAULT_FREEZE_THRESHOLD,
        ),
        execution_state: None,
        scheduler_state: Default::default(),
    }
}

pub fn get_stopped_canister_on_system_subnet(canister_id: CanisterId) -> CanisterState {
    get_stopped_canister_with_controller(canister_id, user_test_id(1).get())
}

pub fn get_stopped_canister(canister_id: CanisterId) -> CanisterState {
    get_stopped_canister_with_controller(canister_id, user_test_id(1).get())
}

pub fn get_stopped_canister_with_controller(
    canister_id: CanisterId,
    controller: PrincipalId,
) -> CanisterState {
    CanisterState {
        system_state: SystemState::new_stopped(
            canister_id,
            controller,
            INITIAL_CYCLES,
            DEFAULT_FREEZE_THRESHOLD,
        ),
        execution_state: None,
        scheduler_state: Default::default(),
    }
}

/// Convert a running canister into a stopped canister. This functionality
/// is added here since it is only allowed in tests.
pub fn running_canister_into_stopped(mut canister: CanisterState) -> CanisterState {
    canister.system_state.status = CanisterStatus::Stopped;
    canister
}

/// Returns a `ReplicatedState` with variable amount of canisters, input
/// messages per canister and methods that are to be called.
pub fn get_initial_state(canister_num: u64, message_num_per_canister: u64) -> ReplicatedState {
    get_initial_state_with_balance(
        canister_num,
        message_num_per_canister,
        INITIAL_CYCLES,
        SubnetType::Application,
    )
}

pub fn get_initial_state_with_balance(
    canister_num: u64,
    message_num_per_canister: u64,
    initial_cycles: Cycles,
    own_subnet_type: SubnetType,
) -> ReplicatedState {
    let mut state =
        ReplicatedState::new_rooted_at(subnet_test_id(1), own_subnet_type, "Initial".into());

    for canister_id in 0..canister_num {
        let mut canister_state_builder = CanisterStateBuilder::new()
            .with_canister_id(canister_test_id(canister_id))
            .with_cycles(initial_cycles)
            .with_wasm(vec![]);

        for i in 0..message_num_per_canister {
            canister_state_builder = canister_state_builder.with_ingress(
                SignedIngressBuilder::new()
                    .canister_id(canister_test_id(canister_id))
                    .nonce(i)
                    .build()
                    .into(),
            );
        }

        state.put_canister_state(canister_state_builder.build());
    }
    state
}

/// Returns the ordered IDs of the canisters contained within `state`.
pub fn canister_ids(state: &ReplicatedState) -> Vec<CanisterId> {
    state
        .canisters_iter()
        .map(|canister_state| canister_state.canister_id())
        .collect()
}

pub fn new_canister_state(
    canister_id: CanisterId,
    controller: PrincipalId,
    initial_cycles: Cycles,
    freeze_threshold: NumSeconds,
) -> CanisterState {
    let scheduler_state = SchedulerState::default();
    let system_state =
        SystemState::new_running(canister_id, controller, initial_cycles, freeze_threshold);
    CanisterState::new(system_state, None, scheduler_state)
}

/// Helper function to insert a canister in the provided `ReplicatedState`.
pub fn insert_dummy_canister(
    state: &mut ReplicatedState,
    canister_id: CanisterId,
    controller: PrincipalId,
) {
    let wasm = BinaryEncodedWasm::new(vec![]);
    let mut canister_state = new_canister_state(
        canister_id,
        controller,
        INITIAL_CYCLES,
        NumSeconds::from(100_000),
    );
    let mut execution_state = initial_execution_state();
    execution_state.wasm_binary = WasmBinary::new(wasm);
    canister_state.execution_state = Some(execution_state);
    state.put_canister_state(canister_state);
}

prop_compose! {
    /// Creates a `ReplicatedState` with a variable amount of canisters and input messages
    /// per canister based on a uniform distribution of the input parameters.
    /// Each canister has a variable `allocation` and
    /// `last_full_execution_round` and a minimal Wasm module.
    ///
    /// Example:
    ///
    /// ```no_run
    /// use ic_test_utilities::state::arb_replicated_state;
    /// use proptest::prelude::*;
    ///
    /// proptest! {
    ///     #[test]
    ///     fn dummy_test(state in arb_replicated_state(10, 10, 5)) {
    ///         println!("{:?}", state);
    ///     }
    /// }
    /// ```
    pub fn arb_replicated_state(
        canister_num_max: u64,
        message_num_per_canister_max: u64,
        last_round_max: u64,
    )
    (
        canister_states in prop::collection::vec(
            arb_canister_state(last_round_max), 1..canister_num_max as usize
        ),
        message_num_per_canister in 1..message_num_per_canister_max,
    ) -> ReplicatedState {
        let tmpdir = tempfile::Builder::new().prefix("test").tempdir().unwrap();

        let mut state = ReplicatedState::new_rooted_at(subnet_test_id(1),  SubnetType::Application, tmpdir.path().into());
        for (_, mut canister_state) in canister_states.into_iter().enumerate() {
            let canister_id = canister_state.canister_id();
            for i in 0..message_num_per_canister {
                canister_state.push_ingress(
                    SignedIngressBuilder::new()
                        .canister_id(canister_id)
                        .nonce(i)
                        .build()
                        .into()
                );
            }
            state.put_canister_state(canister_state);
        }
        state
    }
}

prop_compose! {
    fn arb_canister_state(
        last_round_max: u64,
    )
    (
        (allocation, round) in arb_compute_allocation_and_last_round(last_round_max)
    ) -> CanisterState {
        let mut execution_state = initial_execution_state();
        execution_state.wasm_binary = WasmBinary::new(BinaryEncodedWasm::new(wabt::wat2wasm(r#"(module)"#).unwrap()));
        let scheduler_state = SchedulerState::default();
        let system_state = SystemState::new_running(
            canister_test_id(0),
            user_test_id(24).get(),
            INITIAL_CYCLES,
            DEFAULT_FREEZE_THRESHOLD,
        );
        let mut canister_state = CanisterState::new(
            system_state,
            Some(execution_state),
            scheduler_state
        );
        canister_state.scheduler_state.compute_allocation = allocation;
        canister_state.scheduler_state.last_full_execution_round = round;
        canister_state
    }
}

prop_compose! {
    fn arb_compute_allocation_and_last_round(
        last_round_max: u64
    )
    (
        a in -100..120,
        round in 0..last_round_max,
    ) -> (ComputeAllocation, ExecutionRound) {
        // Clamp `a` to [0, 100], but with high probability for 0 and somewhat
        // higher probability for 100.
        let a = if a < 0 {
            0
        } else if a > 100 {
            100
        } else {
            a
        };

        (
            ComputeAllocation::try_from(a as u64).unwrap(),
            ExecutionRound::from(round),
        )
    }
}

prop_compose! {
    pub fn arb_stream(min_size: usize, max_size: usize)(
        msg_start in 0..10000u64,
        sig_end in 0..10000u64,
        reqs in prop::collection::vec(arbitrary::request(), min_size..=max_size),
    ) -> Stream {
        let mut messages = StreamIndexedQueue::with_begin(StreamIndex::from(msg_start));
        for r in reqs {
            messages.push(r.into())
        }

        let signals_end = StreamIndex::from(sig_end);

        Stream::new(messages, signals_end)
    }
}

prop_compose! {
    /// Generates a strategy consisting of an arbitrary stream and valid slice begin and message
    /// count values for extracting a slice from the stream.
    pub fn arb_stream_slice(min_size: usize, max_size: usize)(
        stream in arb_stream(min_size, max_size),
        from_percent in -20..120i64,
        percent_above_min_size in 0..120i64,
    ) ->  (Stream, StreamIndex, usize) {
        let from_percent = from_percent.max(0).min(100) as usize;
        let percent_above_min_size = percent_above_min_size.max(0).min(100) as usize;
        let msg_count = min_size +
            (stream.messages().len() - min_size) * percent_above_min_size / 100;
        let from = stream.messages_begin() +
            (((stream.messages().len() - msg_count) * from_percent / 100) as u64).into();

        (stream, from, msg_count)
    }
}

prop_compose! {
    /// Strategy that generates an arbitrary number (of receivers) between 1 and the
    /// provided value, if `Some`; or else `usize::MAX` (standing for unlimited
    /// receivers).
    pub fn arb_num_receivers(max_receivers: Option<usize>) (
            random in 0..usize::MAX,
        ) -> usize {
        match max_receivers {
            Some(max_receivers) if max_receivers <= 1 => 1,
            Some(max_receivers) => 1 + random % (max_receivers - 1),
            None => usize::MAX,
        }
    }
}

/// Produces a `ReplicatedState` with the given subnet ID and the given output
/// requests. First group of requests are enqueud into the subnet queues; a
/// canister is created for each following group. Each group's requests are
/// routed round-robin to one of `num_receivers`.
///
/// Returns the generated `ReplicatedState`; the requests grouped by canister,
/// in expected iteration order; and the total number of requests.
fn new_replicated_state_for_test(
    own_subnet_id: SubnetId,
    mut output_requests: Vec<Vec<Request>>,
    num_receivers: usize,
) -> (
    ReplicatedState,
    VecDeque<VecDeque<RequestOrResponse>>,
    usize,
) {
    let mut total_requests = 0;
    let mut requests = VecDeque::new();

    let subnet_queues = if let Some(reqs) = output_requests.pop() {
        let (queues, raw_requests) =
            new_canister_queues_for_test(reqs, CanisterId::from(own_subnet_id), num_receivers);
        total_requests += raw_requests.len();
        requests.push_back(raw_requests);
        Some(queues)
    } else {
        None
    };

    let canister_states: BTreeMap<_, _> = output_requests
        .into_iter()
        .enumerate()
        .map(|(i, reqs)| {
            let canister_id = CanisterId::from_u64(i as u64);
            let mut canister = CanisterStateBuilder::new()
                .with_canister_id(canister_id)
                .build();
            let (queues, raw_requests) =
                new_canister_queues_for_test(reqs, canister_test_id(i as u64), num_receivers);
            canister.system_state.put_queues(queues);
            total_requests += raw_requests.len();
            requests.push_back(raw_requests);
            (canister_id, canister)
        })
        .collect();

    let mut replicated_state = ReplicatedStateBuilder::new().build();
    replicated_state.put_canister_states(canister_states);
    if let Some(subnet_queues) = subnet_queues {
        replicated_state.put_subnet_queues(subnet_queues);
    }

    (replicated_state, requests, total_requests)
}

prop_compose! {
     pub fn arb_replicated_state_with_queues(
        own_subnet_id: SubnetId,
        max_canisters: usize,
        max_requests_per_canister: usize,
        max_receivers: Option<usize>,
    ) (
        time in 1..1000_u64,
        request_queues in prop::collection::vec(prop::collection::vec(arbitrary::request(), 0..=max_requests_per_canister), 0..=max_canisters),
        num_receivers in arb_num_receivers(max_receivers)
    ) -> (ReplicatedState, VecDeque<VecDeque<RequestOrResponse>>, usize) {
        use rand::{Rng, SeedableRng};
        use rand_chacha::ChaChaRng;

        let (mut replicated_state, mut raw_requests, total_requests) = new_replicated_state_for_test(own_subnet_id, request_queues, num_receivers);

        // We pseudorandomly rotate the queues to match the rotation applied by the iterator.
        // Note that subnet queues are always at the front which is why we need to pop them
        // before the rotation and push them to the front afterwards.
        let subnet_queue_requests = raw_requests.pop_front();
        let mut raw_requests : VecDeque<_> = raw_requests.into_iter().filter(|requests| !requests.is_empty()).collect();

        replicated_state.metadata.batch_time = Time::from_nanos_since_unix_epoch(time);
        let mut rng = ChaChaRng::seed_from_u64(time);
        let rotation = rng.gen_range(0, raw_requests.len().max(1));
        raw_requests.rotate_left(rotation);

        if let Some(requests) = subnet_queue_requests {
            raw_requests.push_front(requests);
        }

        (replicated_state, raw_requests, total_requests)
    }
}

/// Asserts that the values returned by `next()` match the ones returned by
/// `peek()` before.
pub fn assert_next_eq(
    peek: (QueueId, QueueIndex, Arc<RequestOrResponse>),
    next: Option<(QueueId, QueueIndex, RequestOrResponse)>,
) {
    let next =
        next.unwrap_or_else(|| panic!("Peek returned a message {:?}, while pop didn't", peek));
    assert_eq!((peek.0, peek.1, peek.2.as_ref()), (next.0, next.1, &next.2));
}
