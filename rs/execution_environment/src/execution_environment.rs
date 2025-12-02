use crate::{
    canister_logs::fetch_canister_logs,
    canister_manager::{
        CanisterManager,
        types::{
            CanisterManagerError, DtsInstallCodeResult, InstallCodeContext,
            PausedInstallCodeExecution, StopCanisterResult, UploadChunkResult,
        },
    },
    canister_settings::CanisterSettings,
    execution::{
        call_or_task::execute_call_or_task, inspect_message, install_code::validate_controller,
        response::execute_response,
    },
    execution_environment_metrics::{
        ExecutionEnvironmentMetrics, SUBMITTED_OUTCOME_LABEL, SUCCESS_STATUS_LABEL,
    },
    hypervisor::Hypervisor,
    ic00_permissions::Ic00MethodPermissions,
    metrics::{CallTreeMetrics, CallTreeMetricsImpl, IngressFilterMetrics},
};
use candid::Encode;
use ic_base_types::PrincipalId;
use ic_config::execution_environment::Config as ExecutionConfig;
use ic_config::flag_status::FlagStatus;
use ic_crypto_utils_canister_threshold_sig::derive_threshold_public_key;
use ic_cycles_account_manager::{
    CyclesAccountManager, IngressInductionCost, ResourceSaturation,
    is_delayed_ingress_induction_cost,
};
use ic_embedders::wasmtime_embedder::system_api::{ExecutionParameters, InstructionLimits};
use ic_error_types::{ErrorCode, RejectCode, UserError};
use ic_interfaces::execution_environment::{
    ExecutionMode, IngressHistoryWriter, RegistryExecutionSettings, SubnetAvailableMemory,
};
use ic_limits::{LOG_CANISTER_OPERATION_CYCLES_THRESHOLD, SMALL_APP_SUBNET_MAX_SIZE};
use ic_logger::{ReplicaLogger, error, info, warn};
use ic_management_canister_types_private::{
    CanisterChangeOrigin, CanisterHttpRequestArgs, CanisterIdRecord, CanisterInfoRequest,
    CanisterInfoResponse, CanisterMetadataRequest, CanisterStatusType, ClearChunkStoreArgs,
    CreateCanisterArgs, DeleteCanisterSnapshotArgs, ECDSAPublicKeyArgs, ECDSAPublicKeyResponse,
    EmptyBlob, FetchCanisterLogsRequest, IC_00, InstallChunkedCodeArgs, InstallCodeArgsV2,
    ListCanisterSnapshotArgs, LoadCanisterSnapshotArgs, MasterPublicKeyId, Method as Ic00Method,
    NodeMetricsHistoryArgs, Payload as Ic00Payload, ProvisionalCreateCanisterWithCyclesArgs,
    ProvisionalTopUpCanisterArgs, ReadCanisterSnapshotDataArgs, ReadCanisterSnapshotMetadataArgs,
    RenameCanisterArgs, ReshareChainKeyArgs, SchnorrAlgorithm, SchnorrPublicKeyArgs,
    SchnorrPublicKeyResponse, SetupInitialDKGArgs, SignWithECDSAArgs, SignWithSchnorrArgs,
    SignWithSchnorrAux, StoredChunksArgs, SubnetInfoArgs, SubnetInfoResponse,
    TakeCanisterSnapshotArgs, UninstallCodeArgs, UpdateSettingsArgs,
    UploadCanisterSnapshotDataArgs, UploadCanisterSnapshotMetadataArgs,
    UploadCanisterSnapshotMetadataResponse, UploadChunkArgs, VetKdDeriveKeyArgs,
    VetKdPublicKeyArgs, VetKdPublicKeyResult,
};
use ic_metrics::MetricsRegistry;
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    CanisterState, ExecutionTask, NetworkTopology, ReplicatedState,
    canister_state::{
        NextExecution,
        system_state::{CyclesUseCase, PausedExecutionId},
    },
    metadata_state::subnet_call_context_manager::{
        EcdsaArguments, InstallCodeCall, InstallCodeCallId, ReshareChainKeyContext,
        SchnorrArguments, SetupInitialDkgContext, SignWithThresholdContext, StopCanisterCall,
        SubnetCallContext, ThresholdArguments, VetKdArguments,
    },
};
use ic_types::{
    CanisterId, Cycles, ExecutionRound, Height, NumBytes, NumInstructions, RegistryVersion,
    ReplicaVersion, SubnetId, Time,
    batch::{CanisterCyclesCostSchedule, ChainKeyData},
    canister_http::{CanisterHttpRequestContext, MAX_CANISTER_HTTP_RESPONSE_BYTES},
    crypto::{
        ExtendedDerivationPath,
        canister_threshold_sig::{MasterPublicKey, PublicKey},
        threshold_sig::ni_dkg::{NiDkgMasterPublicKeyId, NiDkgTargetId},
    },
    ingress::{IngressState, IngressStatus, WasmResult},
    messages::{
        CanisterCall, CanisterCallOrTask, CanisterMessage, CanisterMessageOrTask, CanisterTask,
        MAX_INTER_CANISTER_PAYLOAD_IN_BYTES, Payload, RejectContext, Request, Response,
        SignedIngress, StopCanisterCallId, StopCanisterContext, extract_effective_canister_id,
    },
    methods::SystemMethod,
    nominal_cycles::NominalCycles,
};
use ic_types::{messages::MessageId, methods::WasmMethod};
use ic_utils_thread::deallocator_thread::{DeallocationSender, DeallocatorThread};
use ic_wasm_types::WasmHash;
use phantom_newtype::AmountOf;
use prometheus::IntCounter;
use rand::RngCore;
use std::{
    collections::{BTreeMap, HashMap},
    convert::{Into, TryFrom},
    fmt,
    str::FromStr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use strum::ParseError;

#[cfg(test)]
mod tests;

/// The response of the executed message created by the `ic0.msg_reply()`
/// or `ic0.msg_reject()` System API functions.
/// If the execution failed or did not call these System API functions,
/// then the response is empty.
#[derive(Debug)]
pub enum ExecutionResponse {
    Ingress((MessageId, IngressStatus)),
    Request(Response),
    Empty,
}

/// The data structure returned by
/// `ExecutionEnvironment.execute_canister_input()`.
#[derive(Debug)]
pub enum ExecuteMessageResult {
    Finished {
        /// The new state of the canister after execution.
        canister: CanisterState,

        /// The response of the executed message. The caller needs to either push it
        /// to the output queue of the canister or update the ingress status.
        response: ExecutionResponse,

        /// The number of instructions used by the message execution.
        instructions_used: NumInstructions,

        /// The size of the heap delta the canister produced
        heap_delta: NumBytes,

        /// The call duration, if the call context completed.
        call_duration: Option<Duration>,
    },
    Paused {
        /// The old state of the canister before execution
        /// with some changes necessary for DTS.
        canister: CanisterState,

        /// The paused execution that the caller can either resume or abort.
        paused_execution: Box<dyn PausedExecution>,

        /// If the original message was an ingress message, then this field
        /// contains an ingress status with the state `Processing`.
        ingress_status: Option<(MessageId, IngressStatus)>,
    },
}

/// The result of executing a subnet message.
///
/// Most messages will end up in the `Finished` state once the management
/// canister handles them.
///
/// `Processing` can occur for messages that do not complete immediately, like
/// stop_canister requests or the ones that need to be handled by consensus.
#[derive(Debug)]
enum ExecuteSubnetMessageResult {
    Processing,
    Finished {
        response: Result<(Vec<u8>, Option<CanisterId>), UserError>,
        refund: Cycles,
        instructions: NumInstructions,
    },
}

/// Contains counters needed to keep track of unexpected errors.
#[derive(Clone)]
pub struct RoundCounters<'a> {
    pub execution_refund_error: &'a IntCounter,
    pub state_changes_error: &'a IntCounter,
    pub invalid_system_call_error: &'a IntCounter,
    pub charging_from_balance_error: &'a IntCounter,
    pub unexpected_response_error: &'a IntCounter,
    pub response_cycles_refund_error: &'a IntCounter,
    pub invalid_canister_state_error: &'a IntCounter,
    pub ingress_with_cycles_error: &'a IntCounter,
}

/// Contains round-specific context necessary for resuming a paused execution.
#[derive(Clone)]
pub struct RoundContext<'a> {
    pub network_topology: &'a NetworkTopology,
    pub hypervisor: &'a Hypervisor,
    pub cycles_account_manager: &'a CyclesAccountManager,
    pub counters: RoundCounters<'a>,
    pub log: &'a ReplicaLogger,
    pub time: Time,
    pub cost_schedule: CanisterCyclesCostSchedule,
}

/// Keeps track of instruction remaining in the current execution round.
/// This type is useful for deterministic time slicing because it allows
/// to distinguish a round instructions from a message instructions.
///
/// Another motivation for this type is that `NumInstructions` is backed
/// by an unsigned integer and loses information below zero whereas this
/// type is signed and works well if Wasm execution overshoots the limit
/// making the remaining instructions negative.
pub struct RoundInstructionsTag;
pub type RoundInstructions = AmountOf<RoundInstructionsTag, i64>;

/// Orphan rules prevent defining `From` / `Into` helpers, so we have to define
/// standalone helpers.
pub fn as_round_instructions(n: NumInstructions) -> RoundInstructions {
    RoundInstructions::from(i64::try_from(n.get()).unwrap_or(i64::MAX))
}
pub fn as_num_instructions(a: RoundInstructions) -> NumInstructions {
    NumInstructions::from(u64::try_from(a.get()).unwrap_or(0))
}

/// Contains limits (or budget) for various resources that affect duration of
/// a round such as
/// - executed instructions,
/// - produced heap delta,
/// - allocated bytes,
/// - etc.
///
/// This struct is passed by a mutable reference throughout the entire
/// execution layer:
/// - the scheduler initializes the limits at the start of each round.
/// - high-level execution functions pass the reference through.
/// - low-level execution functions decrease the limits based on the data returned
///   by the Wasm executor.
///
/// A recommended pattern for adding a new limit:
/// - the limit is represented as a signed integer to avoid losing information when
///   a Wasm execution overshoots the limit.
/// - the round stops when the limit reaches zero.
/// - the scheduler (and any other high-level caller) can compute consumption of
///   some function `foo()` as follows:
///   ```text
///   let limit_before = round_limits.$limit;
///   foo(..., &mut round_limits);
///   let consumption = limit_before - round_limits.$limit;
///   ```
///
/// Note that other entry-points of the execution layer such as the query handler,
/// inspect message, benchmarks, tests also have to initialize the round limits.
/// In such cases the "round" should be considered as a trivial round consisting
/// of a single message.
#[derive(Clone, Debug, Default)]
pub struct RoundLimits {
    /// Keeps track of remaining instructions in this execution round.
    pub instructions: RoundInstructions,

    /// Keeps track of the available storage memory. It decreases if
    /// - Wasm execution grows the Wasm/stable memory.
    /// - Wasm execution pushes a new guaranteed response request to the output
    ///   queue.
    pub subnet_available_memory: SubnetAvailableMemory,

    /// The number of outgoing calls that can still be made across the subnet before
    /// canisters are limited to their own callback quota.
    /// This is a soft cap which can be exceeded when executing canisters on threads.
    pub subnet_available_callbacks: i64,

    // TODO would be nice to change that to available, but this requires
    // a lot of changes since available allocation sits in CanisterManager config
    pub compute_allocation_used: u64,

    /// Keeps track of the memory reserved for executing response handlers.
    pub subnet_memory_reservation: NumBytes,
}

impl RoundLimits {
    /// Returns true if the instructions limit has been reached.
    pub fn instructions_reached(&self) -> bool {
        self.instructions <= RoundInstructions::from(0)
    }
}

/// Represent a paused execution that can be resumed or aborted.
pub trait PausedExecution: std::fmt::Debug + Send {
    /// Resumes a paused execution.
    /// It takes:
    /// - the canister state,
    /// - system parameters that can change while the execution is in progress,
    /// - helpers.
    ///
    /// If the execution finishes, then it returns the new canister state and
    /// the result of the execution.
    fn resume(
        self: Box<Self>,
        canister: CanisterState,
        round_context: RoundContext,
        round_limits: &mut RoundLimits,
        subnet_size: usize,
        call_tree_metrics: &dyn CallTreeMetrics,
        deallocation_sender: &DeallocationSender,
    ) -> ExecuteMessageResult;

    /// Aborts the paused execution.
    /// Returns the original message and the cycles prepaid for execution.
    fn abort(self: Box<Self>, log: &ReplicaLogger) -> (CanisterMessageOrTask, Cycles);

    /// Returns a reference to the message or task being executed.
    fn input(&self) -> CanisterMessageOrTask;
}

/// Stores all paused executions keyed by their ids.
#[derive(Default)]
struct PausedExecutionRegistry {
    // A counter that increases monotonically until it wraps around.
    // Wrapping around is not a problem because all paused executions
    // are aborted before the next checkpoint and there cannot be
    // more than 2^64 paused executions between two checkpoints.
    next_id: u64,

    // Paused executions of ordinary canister messages.
    paused_execution: HashMap<PausedExecutionId, Box<dyn PausedExecution>>,

    // Paused executions of `install_code` subnet messages.
    paused_install_code: HashMap<PausedExecutionId, Box<dyn PausedInstallCodeExecution>>,
}

// The replies that can be returned for a `stop_canister` request.
#[derive(Eq, PartialEq, Debug)]
enum StopCanisterReply {
    // The stop request was completed successfully.
    Completed,
    // The stop request timed out.
    Timeout,
}

/// ExecutionEnvironment is the component responsible for executing messages
/// on the IC.
pub struct ExecutionEnvironment {
    log: ReplicaLogger,
    hypervisor: Arc<Hypervisor>,
    canister_manager: Arc<CanisterManager>,
    ingress_history_writer: Arc<dyn IngressHistoryWriter<State = ReplicatedState>>,
    metrics: ExecutionEnvironmentMetrics,
    call_tree_metrics: CallTreeMetricsImpl,
    config: ExecutionConfig,
    cycles_account_manager: Arc<CyclesAccountManager>,
    own_subnet_id: SubnetId,
    own_subnet_type: SubnetType,
    // Global registry of all the paused executions and install code executions
    // on the current subnet.
    paused_execution_registry: Arc<Mutex<PausedExecutionRegistry>>,
    // This scaling factor accounts for the execution threads running in
    // parallel and potentially reserving resources. It should be initialized to
    // the number of scheduler cores.
    scheduler_cores: usize,
    deallocator_thread: DeallocatorThread,
}

/// This is a helper enum that indicates whether the current DTS execution of
/// install_code is the first execution or not.
#[derive(Eq, PartialEq, Debug)]
pub enum DtsInstallCodeStatus {
    StartingFirstExecution,
    ResumingPausedOrAbortedExecution,
}

impl fmt::Display for DtsInstallCodeStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status = match &self {
            DtsInstallCodeStatus::StartingFirstExecution => "StartingFirstExecution",
            DtsInstallCodeStatus::ResumingPausedOrAbortedExecution => {
                "ResumingPausedOrAbortedExecution"
            }
        };
        write!(f, "{status}")
    }
}

impl ExecutionEnvironment {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        log: ReplicaLogger,
        hypervisor: Arc<Hypervisor>,
        canister_manager: Arc<CanisterManager>,
        ingress_history_writer: Arc<dyn IngressHistoryWriter<State = ReplicatedState>>,
        metrics_registry: &MetricsRegistry,
        own_subnet_id: SubnetId,
        own_subnet_type: SubnetType,
        config: ExecutionConfig,
        cycles_account_manager: Arc<CyclesAccountManager>,
        scheduler_cores: usize,
    ) -> Self {
        // Assert the flag implication: DTS => sandboxing.
        assert!(
            config.canister_sandboxing_flag == FlagStatus::Enabled,
            "Deterministic time slicing works only with canister sandboxing."
        );

        let metrics = ExecutionEnvironmentMetrics::new(metrics_registry);
        // Deallocate `SystemStates` and `ExecutionStates` in the background. Sleep for
        // 0.1 ms between deallocations, to spread out the load on the memory allocator
        // (the 0.1 ms was determined by running a benchmark with thousands of messages
        // executed per round and checking CPU profiles to ensure that the vast majority
        // of deallocations happened on the background thread).
        let deallocator_thread =
            DeallocatorThread::new("ExecutionDeallocator", Duration::from_micros(100));
        Self {
            log,
            hypervisor,
            canister_manager,
            ingress_history_writer,
            metrics,
            call_tree_metrics: CallTreeMetricsImpl::new(metrics_registry),
            config,
            cycles_account_manager,
            own_subnet_id,
            own_subnet_type,
            paused_execution_registry: Default::default(),
            scheduler_cores,
            deallocator_thread,
        }
    }

    pub fn state_changes_error(&self) -> &IntCounter {
        &self.metrics.state_changes_error
    }

    pub fn canister_not_found_error(&self) -> &IntCounter {
        &self.metrics.canister_not_found_error
    }

    /// Computes the current amount of memory available for execution.
    ///
    /// Time complexity: `O(|canisters|)`.
    pub fn scaled_subnet_available_memory(&self, state: &ReplicatedState) -> SubnetAvailableMemory {
        let memory_taken = state.memory_taken();
        // We apply the scaling factor `self.scheduler_cores`
        // consistently with the scaling factor of `ResourceSaturation`
        // in the function `self.subnet_memory_saturation`.
        let scaling_factor = self.scheduler_cores as i64;
        SubnetAvailableMemory::new_scaled(
            self.config.subnet_memory_capacity.get() as i64
                - self.config.subnet_memory_reservation.get() as i64
                - memory_taken.execution().get() as i64,
            self.config
                .guaranteed_response_message_memory_capacity
                .get() as i64
                - memory_taken.guaranteed_response_messages().get() as i64,
            self.config
                .subnet_wasm_custom_sections_memory_capacity
                .get() as i64
                - memory_taken.wasm_custom_sections().get() as i64,
            scaling_factor,
        )
    }

    /// Returns the scaled subnet memory reservation.
    pub fn scaled_subnet_memory_reservation(&self) -> NumBytes {
        // This function computes the scaled subnet memory reservation per thread.
        // We apply the scaling factor `self.scheduler_cores`
        // consistently with the scaling factor of `SubnetAvailableMemory`
        // in the function `self.scaled_subnet_available_memory`.
        // and the scaling factor of `ResourceSaturation`
        // in the function `self.subnet_memory_saturation`.
        NumBytes::from(self.config.subnet_memory_reservation.get() / self.scheduler_cores as u64)
    }

    /// Computes the current amount of guaranteed response message memory available
    /// on the subnet.
    ///
    /// This is a more efficient alternative to `memory_taken()` for cases when only
    /// the guaranteed response message memory usage is necessary.
    ///
    /// Time complexity: `O(|canisters|)`.
    pub fn subnet_available_guaranteed_response_message_memory(
        &self,
        state: &ReplicatedState,
    ) -> i64 {
        self.config
            .guaranteed_response_message_memory_capacity
            .get() as i64
            - state.guaranteed_response_message_memory_taken().get() as i64
    }

    /// Computes number of callbacks available up to the subnet's callback soft cap.
    ///
    /// Time complexity: `O(|canisters|)`.
    pub fn subnet_available_callbacks(&self, state: &ReplicatedState) -> i64 {
        self.config
            .subnet_callback_soft_limit
            .saturating_sub(state.callback_count()) as i64
    }

    /// Executes a replicated message sent to a subnet.
    ///
    /// Returns the new replicated state and an optional number of instructions
    /// consumed by the message execution.
    #[allow(clippy::cognitive_complexity)]
    #[allow(clippy::too_many_arguments)]
    pub fn execute_subnet_message(
        &self,
        msg: CanisterMessage,
        mut state: ReplicatedState,
        instruction_limits: InstructionLimits,
        rng: &mut dyn RngCore,
        chain_key_data: &ChainKeyData,
        replica_version: &ReplicaVersion,
        registry_settings: &RegistryExecutionSettings,
        current_round: ExecutionRound,
        round_limits: &mut RoundLimits,
    ) -> (ReplicatedState, Option<NumInstructions>) {
        let since = Instant::now(); // Start logging execution time.
        let cost_schedule = state.get_own_cost_schedule();

        let mut msg = match msg {
            CanisterMessage::Response(response) => {
                let context = state
                    .metadata
                    .subnet_call_context_manager
                    .retrieve_context(response.originator_reply_callback, &self.log);
                return match context {
                    None => (state, Some(NumInstructions::from(0))),
                    Some(context) => {
                        let time_elapsed =
                            state.time().saturating_duration_since(context.get_time());
                        let request = context.get_request();

                        if let SubnetCallContext::CanisterHttpRequest(context) = &context {
                            let old_price = self.cycles_account_manager.http_request_fee(
                                context.variable_parts_size(),
                                context.max_response_bytes,
                                registry_settings.subnet_size,
                                cost_schedule,
                            );

                            let new_price = self.cycles_account_manager.http_request_fee_beta(
                                context.variable_parts_size(),
                                context.max_response_bytes,
                                registry_settings.subnet_size,
                                cost_schedule,
                                NumBytes::from(response.payload_size_bytes()),
                            );

                            self.metrics
                                .observe_http_outcall_price_change(old_price, new_price);
                            self.metrics
                                .observe_http_outcall_request(context, &response);

                            let max_response_size = match context.max_response_bytes {
                                Some(response_size) => response_size.get(),
                                // Defaults to maximum response size.
                                None => MAX_CANISTER_HTTP_RESPONSE_BYTES,
                            };

                            info!(
                                self.log,
                                "Canister Http request with payload_size {}, max_response_size {}, subnet_size {}, reply_callback_id {}, sender {}, process_id {}",
                                response.payload_size_bytes().get(),
                                max_response_size,
                                registry_settings.subnet_size,
                                context.request.sender_reply_callback,
                                context.request.sender,
                                std::process::id(),
                            );
                        }

                        self.metrics.observe_subnet_message(
                            &request.method_name,
                            time_elapsed.as_secs_f64(),
                            &match &response.response_payload {
                                Payload::Data(_) => Ok(()),
                                Payload::Reject(_) => Err(ErrorCode::CanisterRejectedMessage),
                            },
                        );

                        if let (
                            SubnetCallContext::SignWithThreshold(threshold_context),
                            Payload::Data(_),
                        ) = (&context, &response.response_payload)
                        {
                            *state
                                .metadata
                                .subnet_metrics
                                .threshold_signature_agreements
                                .entry(threshold_context.key_id())
                                .or_default() += 1;
                        }

                        state.push_subnet_output_response(
                            Response {
                                originator: request.sender,
                                respondent: CanisterId::from(self.own_subnet_id),
                                originator_reply_callback: request.sender_reply_callback,
                                refund: request.payment,
                                response_payload: response.response_payload.clone(),
                                deadline: request.deadline,
                            }
                            .into(),
                        );

                        (state, Some(NumInstructions::from(0)))
                    }
                };
            }

            CanisterMessage::Ingress(msg) => CanisterCall::Ingress(msg),
            CanisterMessage::Request(msg) => CanisterCall::Request(msg),
        };

        let timestamp_nanos = state.time();
        let method = Ic00Method::from_str(msg.method_name());
        let payload = msg.method_payload();

        if let Ok(permissions) = method.map(Ic00MethodPermissions::new)
            && let Err(err) = permissions.verify(&msg, &state)
        {
            let refund = msg.take_cycles();
            return self.finish_subnet_message_execution(
                state,
                msg,
                ExecuteSubnetMessageResult::Finished {
                    response: Err(err),
                    refund,
                    instructions: NumInstructions::from(0),
                },
                since,
            );
        }

        let result: ExecuteSubnetMessageResult = match method {
            Ok(Ic00Method::InstallCode) => {
                // Tail call is needed for deterministic time slicing here to
                // properly handle the case of a paused execution.
                return self.execute_install_code(
                    msg,
                    None,
                    None,
                    DtsInstallCodeStatus::StartingFirstExecution,
                    state,
                    instruction_limits,
                    round_limits,
                    registry_settings.subnet_size,
                );
            }

            Ok(Ic00Method::InstallChunkedCode) => {
                // Tail call is needed for deterministic time slicing here to
                // properly handle the case of a paused execution.
                return self.execute_install_code(
                    msg,
                    None,
                    None,
                    DtsInstallCodeStatus::StartingFirstExecution,
                    state,
                    instruction_limits,
                    round_limits,
                    registry_settings.subnet_size,
                );
            }

            Ok(Ic00Method::SignWithECDSA) => match &msg {
                CanisterCall::Request(request) => {
                    if payload.is_empty() {
                        use ic_types::messages;
                        state.push_subnet_output_response(
                            Response {
                                originator: request.sender,
                                respondent: CanisterId::from(self.own_subnet_id),
                                originator_reply_callback: request.sender_reply_callback,
                                refund: request.payment,
                                response_payload: messages::Payload::Reject(
                                    messages::RejectContext::new(
                                        ic_error_types::RejectCode::CanisterReject,
                                        "An empty message cannot be signed",
                                    ),
                                ),
                                deadline: request.deadline,
                            }
                            .into(),
                        );
                        return (state, Some(NumInstructions::from(0)));
                    }

                    match SignWithECDSAArgs::decode(payload) {
                        Err(err) => ExecuteSubnetMessageResult::Finished {
                            response: Err(err),
                            refund: msg.take_cycles(),
                            instructions: NumInstructions::from(0),
                        },
                        Ok(args) => {
                            let key_id = MasterPublicKeyId::Ecdsa(args.key_id.clone());
                            match get_master_public_key(
                                &chain_key_data.master_public_keys,
                                self.own_subnet_id,
                                &key_id,
                            ) {
                                Err(err) => ExecuteSubnetMessageResult::Finished {
                                    response: Err(err),
                                    refund: msg.take_cycles(),
                                    instructions: NumInstructions::from(0),
                                },
                                Ok(_) => match self.sign_with_threshold(
                                    (**request).clone(),
                                    ThresholdArguments::Ecdsa(EcdsaArguments {
                                        key_id: args.key_id,
                                        message_hash: args.message_hash,
                                        pre_signature: None,
                                    }),
                                    args.derivation_path.into_inner(),
                                    registry_settings
                                        .chain_key_settings
                                        .get(&key_id)
                                        .map(|setting| setting.max_queue_size)
                                        .unwrap_or_default(),
                                    &mut state,
                                    rng,
                                    registry_settings.subnet_size,
                                ) {
                                    Err(err) => ExecuteSubnetMessageResult::Finished {
                                        response: Err(err),
                                        refund: msg.take_cycles(),
                                        instructions: NumInstructions::from(0),
                                    },
                                    Ok(()) => {
                                        self.metrics.observe_message_with_label(
                                            &request.method_name,
                                            since.elapsed().as_secs_f64(),
                                            SUBMITTED_OUTCOME_LABEL.into(),
                                            SUCCESS_STATUS_LABEL.into(),
                                        );
                                        ExecuteSubnetMessageResult::Processing
                                    }
                                },
                            }
                        }
                    }
                }
                CanisterCall::Ingress(_) => {
                    self.reject_unexpected_ingress(Ic00Method::SignWithECDSA)
                }
            },

            Ok(Ic00Method::CreateCanister) => {
                match &mut msg {
                    CanisterCall::Ingress(_) => {
                        self.reject_unexpected_ingress(Ic00Method::CreateCanister)
                    }
                    CanisterCall::Request(req) => {
                        let cycles = Arc::make_mut(req).take_cycles();
                        match CreateCanisterArgs::decode(req.method_payload()) {
                            Err(err) => ExecuteSubnetMessageResult::Finished {
                                response: Err(err),
                                refund: cycles,
                                instructions: NumInstructions::from(0),
                            },
                            Ok(args) => {
                                // Start logging execution time for `create_canister`.
                                let since = Instant::now();

                                let sender_canister_version = args.get_sender_canister_version();

                                let settings = args.settings.unwrap_or_default();
                                let result = match CanisterSettings::try_from(settings) {
                                    Err(err) => ExecuteSubnetMessageResult::Finished {
                                        response: Err(err.into()),
                                        refund: cycles,
                                        instructions: NumInstructions::from(0),
                                    },
                                    Ok(settings) => self.create_canister(
                                        msg.canister_change_origin(sender_canister_version),
                                        cycles,
                                        settings,
                                        registry_settings,
                                        &mut state,
                                        round_limits,
                                    ),
                                };
                                info!(
                                    self.log,
                                    "Finished executing create_canister message after {:?} with result: {:?}",
                                    since.elapsed().as_secs_f64(),
                                    result
                                );

                                result
                            }
                        }
                    }
                }
            }

            Ok(Ic00Method::UninstallCode) => {
                let res = UninstallCodeArgs::decode(payload).and_then(|args| {
                    self.canister_manager
                        .uninstall_code(
                            msg.canister_change_origin(args.get_sender_canister_version()),
                            args.get_canister_id(),
                            &mut state,
                            round_limits,
                            &self.metrics.canister_not_found_error,
                        )
                        .map(|()| (EmptyBlob.encode(), Some(args.get_canister_id())))
                        .map_err(|err| err.into())
                });
                ExecuteSubnetMessageResult::Finished {
                    response: res,
                    refund: msg.take_cycles(),
                    instructions: NumInstructions::from(0),
                }
            }

            Ok(Ic00Method::UpdateSettings) => {
                let res = match UpdateSettingsArgs::decode(payload) {
                    Err(err) => Err(err),
                    Ok(args) => {
                        // Start logging execution time for `update_settings`.
                        let since = Instant::now();

                        let canister_id = args.get_canister_id();
                        let sender_canister_version = args.get_sender_canister_version();

                        let result = match CanisterSettings::try_from(args.settings) {
                            Err(err) => Err(err.into()),
                            Ok(settings) => self
                                .update_settings(
                                    timestamp_nanos,
                                    msg.canister_change_origin(sender_canister_version),
                                    settings,
                                    canister_id,
                                    &mut state,
                                    round_limits,
                                    registry_settings.subnet_size,
                                )
                                .map(|res| (res, Some(canister_id))),
                        };
                        // The induction cost of `UpdateSettings` is charged
                        // after applying the new settings to allow users to
                        // decrease the freezing threshold if it was set too
                        // high that topping up the canister is not feasible.
                        if let CanisterCall::Ingress(ingress) = &msg {
                            let cost_schedule = state.get_own_cost_schedule();
                            if let Ok(canister) = get_canister_mut(canister_id, &mut state)
                                && is_delayed_ingress_induction_cost(&ingress.method_payload)
                            {
                                let bytes_to_charge =
                                    ingress.method_payload.len() + ingress.method_name.len();
                                let induction_cost = self
                                    .cycles_account_manager
                                    .ingress_induction_cost_from_bytes(
                                        NumBytes::from(bytes_to_charge as u64),
                                        registry_settings.subnet_size,
                                        cost_schedule,
                                    );
                                let memory_usage = canister.memory_usage();
                                let message_memory_usage = canister.message_memory_usage();
                                // This call may fail with `CanisterOutOfCyclesError`,
                                // which is not actionable at this point.
                                let _ignore_error = self.cycles_account_manager.consume_cycles(
                                    &mut canister.system_state,
                                    memory_usage,
                                    message_memory_usage,
                                    canister.scheduler_state.compute_allocation,
                                    induction_cost,
                                    registry_settings.subnet_size,
                                    cost_schedule,
                                    CyclesUseCase::IngressInduction,
                                    false, // we ignore the error anyway => no need to reveal top up balance
                                );
                            }
                        }
                        info!(
                            self.log,
                            "Finished executing update_settings message on canister {:?} after {:?} with result: {:?}",
                            canister_id,
                            since.elapsed().as_secs_f64(),
                            result
                        );
                        result
                    }
                };
                ExecuteSubnetMessageResult::Finished {
                    response: res,
                    refund: msg.take_cycles(),
                    instructions: NumInstructions::from(0),
                }
            }

            Ok(Ic00Method::CanisterStatus) => {
                let res = CanisterIdRecord::decode(payload).and_then(|args| {
                    let ready_for_migration = state.ready_for_migration(&args.get_canister_id());
                    self.get_canister_status(
                        *msg.sender(),
                        args.get_canister_id(),
                        &state,
                        registry_settings.subnet_size,
                        ready_for_migration,
                    )
                    .map(|res| (res, Some(args.get_canister_id())))
                });
                ExecuteSubnetMessageResult::Finished {
                    response: res,
                    refund: msg.take_cycles(),
                    instructions: NumInstructions::from(0),
                }
            }

            Ok(Ic00Method::CanisterInfo) => match &msg {
                CanisterCall::Request(_) => {
                    let res = CanisterInfoRequest::decode(payload).and_then(|record| {
                        self.get_canister_info(
                            record.canister_id(),
                            record.num_requested_changes(),
                            &state,
                        )
                        .map(|res| (res, Some(record.canister_id())))
                    });
                    ExecuteSubnetMessageResult::Finished {
                        response: res,
                        refund: msg.take_cycles(),
                        instructions: NumInstructions::from(0),
                    }
                }
                CanisterCall::Ingress(_) => {
                    self.reject_unexpected_ingress(Ic00Method::CanisterInfo)
                }
            },

            Ok(Ic00Method::CanisterMetadata) => match &msg {
                CanisterCall::Request(_) => {
                    let res = CanisterMetadataRequest::decode(payload).and_then(|record| {
                        self.get_canister_metadata(
                            *msg.sender(),
                            record.canister_id(),
                            &state,
                            record.name(),
                        )
                        .map(|res| (res, Some(record.canister_id())))
                    });
                    ExecuteSubnetMessageResult::Finished {
                        response: res,
                        refund: msg.take_cycles(),
                        instructions: NumInstructions::from(0),
                    }
                }
                CanisterCall::Ingress(_) => {
                    self.reject_unexpected_ingress(Ic00Method::CanisterMetadata)
                }
            },

            Ok(Ic00Method::StartCanister) => {
                let res = CanisterIdRecord::decode(payload).and_then(|args| {
                    self.start_canister(args.get_canister_id(), *msg.sender(), &mut state)
                        .map(|res| (res, Some(args.get_canister_id())))
                });
                ExecuteSubnetMessageResult::Finished {
                    response: res,
                    refund: msg.take_cycles(),
                    instructions: NumInstructions::from(0),
                }
            }

            Ok(Ic00Method::StopCanister) => match CanisterIdRecord::decode(payload) {
                Err(err) => ExecuteSubnetMessageResult::Finished {
                    response: Err(err),
                    refund: msg.take_cycles(),
                    instructions: NumInstructions::from(0),
                },
                Ok(args) => self.stop_canister(args.get_canister_id(), &msg, &mut state),
            },

            Ok(Ic00Method::DeleteCanister) => {
                let res = CanisterIdRecord::decode(payload).and_then(|args| {
                    // Start logging execution time for `delete_canister`.
                    let since = Instant::now();

                    let result = self
                        .canister_manager
                        .delete_canister(*msg.sender(), args.get_canister_id(), &mut state, round_limits)
                        .map(|()| (EmptyBlob.encode(), Some(args.get_canister_id())))
                        .map_err(|err| err.into());

                    info!(
                        self.log,
                        "Finished executing delete_canister message on canister {:?} after {:?} with result: {:?}",
                        args.get_canister_id(),
                        since.elapsed().as_secs_f64(),
                        result
                    );
                    result
                });
                ExecuteSubnetMessageResult::Finished {
                    response: res,
                    refund: msg.take_cycles(),
                    instructions: NumInstructions::from(0),
                }
            }

            Ok(Ic00Method::RawRand) => match &msg {
                CanisterCall::Ingress(_) => self.reject_unexpected_ingress(Ic00Method::RawRand),
                CanisterCall::Request(_) => {
                    let res = match EmptyBlob::decode(payload) {
                        Err(err) => Err(err),
                        Ok(EmptyBlob) => {
                            let mut buffer = vec![0u8; 32];
                            rng.fill_bytes(&mut buffer);
                            Ok(Encode!(&buffer).unwrap())
                        }
                    };
                    ExecuteSubnetMessageResult::Finished {
                        response: res.map(|res| (res, None)),
                        refund: msg.take_cycles(),
                        instructions: NumInstructions::from(0),
                    }
                }
            },

            Ok(Ic00Method::DepositCycles) => match CanisterIdRecord::decode(payload) {
                Err(err) => ExecuteSubnetMessageResult::Finished {
                    response: Err(err),
                    refund: msg.take_cycles(),
                    instructions: NumInstructions::from(0),
                },
                Ok(args) => self.deposit_cycles(args.get_canister_id(), &mut msg, &mut state),
            },

            Ok(Ic00Method::HttpRequest) => match state.metadata.own_subnet_features.http_requests {
                true => match &msg {
                    CanisterCall::Request(request) => {
                        match CanisterHttpRequestArgs::decode(payload) {
                            Err(err) => ExecuteSubnetMessageResult::Finished {
                                response: Err(err),
                                refund: msg.take_cycles(),
                                instructions: NumInstructions::from(0),
                            },
                            Ok(args) => {
                                match CanisterHttpRequestContext::generate_from_args(
                                    state.time(),
                                    request.as_ref(),
                                    args,
                                    &registry_settings.node_ids,
                                    rng,
                                ) {
                                    Err(err) => ExecuteSubnetMessageResult::Finished {
                                        response: Err(err.into()),
                                        refund: msg.take_cycles(),
                                        instructions: NumInstructions::from(0),
                                    },
                                    Ok(canister_http_request_context) => match self
                                        .try_add_http_context_to_replicated_state(
                                            canister_http_request_context,
                                            &mut state,
                                            request.as_ref(),
                                            registry_settings,
                                            since,
                                        ) {
                                        Err(err) => ExecuteSubnetMessageResult::Finished {
                                            response: Err(err),
                                            refund: msg.take_cycles(),
                                            instructions: NumInstructions::from(0),
                                        },
                                        Ok(()) => ExecuteSubnetMessageResult::Processing,
                                    },
                                }
                            }
                        }
                    }

                    CanisterCall::Ingress(_) => {
                        self.reject_unexpected_ingress(Ic00Method::HttpRequest)
                    }
                },
                false => {
                    let err = Err(UserError::new(
                        ErrorCode::CanisterContractViolation,
                        "This API is not enabled on this subnet".to_string(),
                    ));
                    ExecuteSubnetMessageResult::Finished {
                        response: err,
                        refund: msg.take_cycles(),
                        instructions: NumInstructions::from(0),
                    }
                }
            },

            Ok(Ic00Method::SetupInitialDKG) => match &msg {
                CanisterCall::Request(request) => self
                    .setup_initial_dkg(payload, request, &mut state, rng)
                    .map_or_else(
                        |err| ExecuteSubnetMessageResult::Finished {
                            response: Err(err),
                            refund: msg.take_cycles(),
                            instructions: NumInstructions::from(0),
                        },
                        |()| ExecuteSubnetMessageResult::Processing,
                    ),
                CanisterCall::Ingress(_) => {
                    self.reject_unexpected_ingress(Ic00Method::SetupInitialDKG)
                }
            },

            Ok(Ic00Method::ECDSAPublicKey) => {
                let cycles = msg.take_cycles();
                match &msg {
                    CanisterCall::Request(request) => {
                        let res = match ECDSAPublicKeyArgs::decode(request.method_payload()) {
                            Err(err) => Err(err),
                            Ok(args) => match get_master_public_key(
                                &chain_key_data.master_public_keys,
                                self.own_subnet_id,
                                &MasterPublicKeyId::Ecdsa(args.key_id.clone()),
                            ) {
                                Err(err) => Err(err),
                                Ok(pubkey) => {
                                    let canister_id = match args.canister_id {
                                        Some(id) => id.into(),
                                        None => *msg.sender(),
                                    };
                                    self.get_threshold_public_key(
                                        pubkey,
                                        canister_id,
                                        args.derivation_path.into_inner(),
                                    )
                                    .map(|res| {
                                        (
                                            ECDSAPublicKeyResponse {
                                                public_key: res.public_key,
                                                chain_code: res.chain_key,
                                            }
                                            .encode(),
                                            None,
                                        )
                                    })
                                }
                            },
                        };
                        ExecuteSubnetMessageResult::Finished {
                            response: res,
                            refund: cycles,
                            instructions: NumInstructions::from(0),
                        }
                    }
                    CanisterCall::Ingress(_) => {
                        self.reject_unexpected_ingress(Ic00Method::ECDSAPublicKey)
                    }
                }
            }

            Ok(Ic00Method::SchnorrPublicKey) => {
                let cycles = msg.take_cycles();
                match &msg {
                    CanisterCall::Request(request) => {
                        let res = match SchnorrPublicKeyArgs::decode(request.method_payload()) {
                            Err(err) => Err(err),
                            Ok(args) => match get_master_public_key(
                                &chain_key_data.master_public_keys,
                                self.own_subnet_id,
                                &MasterPublicKeyId::Schnorr(args.key_id.clone()),
                            ) {
                                Err(err) => Err(err),
                                Ok(pubkey) => {
                                    let canister_id = match args.canister_id {
                                        Some(id) => id.into(),
                                        None => *msg.sender(),
                                    };
                                    self.get_threshold_public_key(
                                        pubkey,
                                        canister_id,
                                        args.derivation_path.into_inner(),
                                    )
                                    .map(|res| {
                                        (
                                            SchnorrPublicKeyResponse {
                                                public_key: res.public_key,
                                                chain_code: res.chain_key,
                                            }
                                            .encode(),
                                            None,
                                        )
                                    })
                                }
                            },
                        };
                        ExecuteSubnetMessageResult::Finished {
                            response: res,
                            refund: cycles,
                            instructions: NumInstructions::from(0),
                        }
                    }
                    CanisterCall::Ingress(_) => {
                        self.reject_unexpected_ingress(Ic00Method::SchnorrPublicKey)
                    }
                }
            }

            Ok(Ic00Method::SignWithSchnorr) => match &msg {
                CanisterCall::Request(request) => {
                    if payload.is_empty() {
                        use ic_types::messages;
                        state.push_subnet_output_response(
                            Response {
                                originator: request.sender,
                                respondent: CanisterId::from(self.own_subnet_id),
                                originator_reply_callback: request.sender_reply_callback,
                                refund: request.payment,
                                response_payload: messages::Payload::Reject(
                                    messages::RejectContext::new(
                                        ic_error_types::RejectCode::CanisterReject,
                                        "An empty message cannot be signed",
                                    ),
                                ),
                                deadline: request.deadline,
                            }
                            .into(),
                        );
                        return (state, Some(NumInstructions::from(0)));
                    }

                    match SignWithSchnorrArgs::decode(payload) {
                        Err(err) => ExecuteSubnetMessageResult::Finished {
                            response: Err(err),
                            refund: msg.take_cycles(),
                            instructions: NumInstructions::from(0),
                        },
                        Ok(args) => {
                            let key_id = MasterPublicKeyId::Schnorr(args.key_id.clone());
                            match get_master_public_key(
                                &chain_key_data.master_public_keys,
                                self.own_subnet_id,
                                &key_id,
                            ) {
                                Err(err) => ExecuteSubnetMessageResult::Finished {
                                    response: Err(err),
                                    refund: msg.take_cycles(),
                                    instructions: NumInstructions::from(0),
                                },
                                Ok(_) => match self.sign_with_threshold(
                                    (**request).clone(),
                                    ThresholdArguments::Schnorr(SchnorrArguments {
                                        key_id: args.key_id,
                                        message: Arc::new(args.message),
                                        taproot_tree_root: args.aux.map(|v| match v {
                                            SignWithSchnorrAux::Bip341(v) => {
                                                Arc::new(v.merkle_root_hash.into_vec())
                                            }
                                        }),
                                        pre_signature: None,
                                    }),
                                    args.derivation_path.into_inner(),
                                    registry_settings
                                        .chain_key_settings
                                        .get(&key_id)
                                        .map(|setting| setting.max_queue_size)
                                        .unwrap_or_default(),
                                    &mut state,
                                    rng,
                                    registry_settings.subnet_size,
                                ) {
                                    Err(err) => ExecuteSubnetMessageResult::Finished {
                                        response: Err(err),
                                        refund: msg.take_cycles(),
                                        instructions: NumInstructions::from(0),
                                    },
                                    Ok(()) => {
                                        self.metrics.observe_message_with_label(
                                            &request.method_name,
                                            since.elapsed().as_secs_f64(),
                                            SUBMITTED_OUTCOME_LABEL.into(),
                                            SUCCESS_STATUS_LABEL.into(),
                                        );
                                        ExecuteSubnetMessageResult::Processing
                                    }
                                },
                            }
                        }
                    }
                }
                CanisterCall::Ingress(_) => {
                    self.reject_unexpected_ingress(Ic00Method::SignWithSchnorr)
                }
            },

            Ok(Ic00Method::VetKdPublicKey) => {
                let cycles = msg.take_cycles();
                match &msg {
                    CanisterCall::Request(request) => {
                        let res = match VetKdPublicKeyArgs::decode(request.method_payload()) {
                            Err(err) => Err(err),
                            Ok(args) => match get_master_public_key(
                                &chain_key_data.master_public_keys,
                                self.own_subnet_id,
                                &MasterPublicKeyId::VetKd(args.key_id.clone()),
                            ) {
                                Err(err) => Err(err),
                                Ok(pubkey) => {
                                    let canister_id = match args.canister_id {
                                        Some(id) => id.into(),
                                        None => *msg.sender(),
                                    };
                                    self.get_vetkd_public_key(pubkey, canister_id, args.context)
                                        .map(|public_key| {
                                            (VetKdPublicKeyResult { public_key }.encode(), None)
                                        })
                                }
                            },
                        };
                        ExecuteSubnetMessageResult::Finished {
                            response: res,
                            refund: cycles,
                            instructions: NumInstructions::from(0),
                        }
                    }
                    CanisterCall::Ingress(_) => {
                        self.reject_unexpected_ingress(Ic00Method::VetKdPublicKey)
                    }
                }
            }
            Ok(Ic00Method::ReshareChainKey) => {
                let cycles = msg.take_cycles();
                match msg {
                    CanisterCall::Request(ref request) => self
                        .reshare_chain_key(&mut state, rng, chain_key_data, request)
                        .map_or_else(
                            |err| ExecuteSubnetMessageResult::Finished {
                                response: Err(err),
                                refund: cycles,
                                instructions: NumInstructions::from(0),
                            },
                            |()| ExecuteSubnetMessageResult::Processing,
                        ),
                    CanisterCall::Ingress(_) => {
                        self.reject_unexpected_ingress(Ic00Method::ReshareChainKey)
                    }
                }
            }
            Ok(Ic00Method::VetKdDeriveKey) => match &msg {
                CanisterCall::Request(request) => {
                    if payload.is_empty() {
                        use ic_types::messages;
                        state.push_subnet_output_response(
                            Response {
                                originator: request.sender,
                                respondent: CanisterId::from(self.own_subnet_id),
                                originator_reply_callback: request.sender_reply_callback,
                                refund: request.payment,
                                response_payload: messages::Payload::Reject(
                                    messages::RejectContext::new(
                                        ic_error_types::RejectCode::CanisterReject,
                                        "Message payload empty",
                                    ),
                                ),
                                deadline: request.deadline,
                            }
                            .into(),
                        );
                        return (state, Some(NumInstructions::from(0)));
                    }

                    match self.vetkd_derive_key(
                        request,
                        payload,
                        chain_key_data,
                        &mut state,
                        rng,
                        registry_settings,
                        current_round,
                    ) {
                        Err(err) => ExecuteSubnetMessageResult::Finished {
                            response: Err(err),
                            refund: msg.take_cycles(),
                            instructions: NumInstructions::from(0),
                        },
                        Ok(()) => {
                            self.metrics.observe_message_with_label(
                                &request.method_name,
                                since.elapsed().as_secs_f64(),
                                SUBMITTED_OUTCOME_LABEL.into(),
                                SUCCESS_STATUS_LABEL.into(),
                            );
                            ExecuteSubnetMessageResult::Processing
                        }
                    }
                }
                CanisterCall::Ingress(_) => {
                    self.reject_unexpected_ingress(Ic00Method::VetKdDeriveKey)
                }
            },

            Ok(Ic00Method::ProvisionalCreateCanisterWithCycles) => {
                let res =
                    ProvisionalCreateCanisterWithCyclesArgs::decode(payload).and_then(|args| {
                        let cycles_amount = args.to_u128();
                        let sender_canister_version = args.get_sender_canister_version();
                        match CanisterSettings::try_from(args.settings) {
                            Ok(settings) => self
                                .canister_manager
                                .create_canister_with_cycles(
                                    msg.canister_change_origin(sender_canister_version),
                                    cycles_amount,
                                    settings,
                                    args.specified_id,
                                    &mut state,
                                    &registry_settings.provisional_whitelist,
                                    registry_settings.max_number_of_canisters,
                                    round_limits,
                                    self.subnet_memory_saturation(
                                        &round_limits.subnet_available_memory,
                                    ),
                                    registry_settings.subnet_size,
                                    &self.metrics.canister_creation_error,
                                )
                                .map(|canister_id| {
                                    (
                                        CanisterIdRecord::from(canister_id).encode(),
                                        Some(canister_id),
                                    )
                                })
                                .map_err(|err| err.into()),
                            Err(err) => Err(err.into()),
                        }
                    });
                ExecuteSubnetMessageResult::Finished {
                    response: res,
                    refund: msg.take_cycles(),
                    instructions: NumInstructions::from(0),
                }
            }

            Ok(Ic00Method::ProvisionalTopUpCanister) => {
                let res = ProvisionalTopUpCanisterArgs::decode(payload).and_then(|args| {
                    let canister_id = args.get_canister_id();
                    self.add_cycles(
                        *msg.sender(),
                        args.get_canister_id(),
                        args.to_u128(),
                        &mut state,
                        &registry_settings.provisional_whitelist,
                    )
                    .map(|res| (res, Some(canister_id)))
                });
                ExecuteSubnetMessageResult::Finished {
                    response: res,
                    refund: msg.take_cycles(),
                    instructions: NumInstructions::from(0),
                }
            }

            Ok(Ic00Method::BitcoinSendTransactionInternal) => match &msg {
                CanisterCall::Request(request) => {
                    match crate::bitcoin::send_transaction_internal(
                        &self.config.bitcoin.privileged_access,
                        request,
                        &mut state,
                    ) {
                        Ok(()) => ExecuteSubnetMessageResult::Processing,
                        Err(err) => ExecuteSubnetMessageResult::Finished {
                            response: Err(err),
                            refund: msg.take_cycles(),
                            instructions: NumInstructions::from(0),
                        },
                    }
                }
                CanisterCall::Ingress(_) => {
                    self.reject_unexpected_ingress(Ic00Method::BitcoinGetSuccessors)
                }
            },

            Ok(Ic00Method::BitcoinGetSuccessors) => match &msg {
                CanisterCall::Request(request) => {
                    match crate::bitcoin::get_successors(
                        &self.config.bitcoin.privileged_access,
                        request,
                        &mut state,
                    ) {
                        Ok(Some(payload)) => ExecuteSubnetMessageResult::Finished {
                            response: Ok((payload, None)),
                            refund: msg.take_cycles(),
                            instructions: NumInstructions::from(0),
                        },
                        Ok(None) => ExecuteSubnetMessageResult::Processing,
                        Err(err) => ExecuteSubnetMessageResult::Finished {
                            response: Err(err),
                            refund: msg.take_cycles(),
                            instructions: NumInstructions::from(0),
                        },
                    }
                }
                CanisterCall::Ingress(_) => {
                    self.reject_unexpected_ingress(Ic00Method::BitcoinGetSuccessors)
                }
            },

            Ok(Ic00Method::BitcoinGetBalance)
            | Ok(Ic00Method::BitcoinGetUtxos)
            | Ok(Ic00Method::BitcoinGetBlockHeaders)
            | Ok(Ic00Method::BitcoinSendTransaction)
            | Ok(Ic00Method::BitcoinGetCurrentFeePercentiles) => {
                // Code path can only be triggered if there are no bitcoin canisters to route
                // the request to.
                ExecuteSubnetMessageResult::Finished {
                    response: Err(UserError::new(
                        ErrorCode::CanisterRejectedMessage,
                        "No bitcoin canisters available.",
                    )),
                    refund: msg.take_cycles(),
                    instructions: NumInstructions::from(0),
                }
            }

            Ok(Ic00Method::UploadChunk) => {
                let resource_saturation =
                    self.subnet_memory_saturation(&round_limits.subnet_available_memory);
                let res = UploadChunkArgs::decode(payload).and_then(|args| {
                    let canister_id = args.get_canister_id();
                    self.upload_chunk(
                        *msg.sender(),
                        &mut state,
                        args,
                        round_limits,
                        registry_settings.subnet_size,
                        &resource_saturation,
                    )
                    .map(|res| (res, Some(canister_id)))
                });
                ExecuteSubnetMessageResult::Finished {
                    response: res,
                    refund: msg.take_cycles(),
                    instructions: NumInstructions::from(0),
                }
            }

            Ok(Ic00Method::ClearChunkStore) => {
                let resource_saturation =
                    self.subnet_memory_saturation(&round_limits.subnet_available_memory);
                let res = ClearChunkStoreArgs::decode(payload).and_then(|args| {
                    let canister_id = args.get_canister_id();
                    self.clear_chunk_store(
                        *msg.sender(),
                        &mut state,
                        args,
                        round_limits,
                        registry_settings.subnet_size,
                        &resource_saturation,
                    )
                    .map(|res| (res, Some(canister_id)))
                });
                ExecuteSubnetMessageResult::Finished {
                    response: res,
                    refund: msg.take_cycles(),
                    instructions: NumInstructions::from(0),
                }
            }

            Ok(Ic00Method::StoredChunks) => {
                let res = StoredChunksArgs::decode(payload).and_then(|args| {
                    let canister_id = args.get_canister_id();
                    self.stored_chunks(*msg.sender(), &state, args)
                        .map(|res| (res, Some(canister_id)))
                });
                ExecuteSubnetMessageResult::Finished {
                    response: res,
                    refund: msg.take_cycles(),
                    instructions: NumInstructions::from(0),
                }
            }

            Ok(Ic00Method::NodeMetricsHistory) => match &msg {
                CanisterCall::Ingress(_) => {
                    self.reject_unexpected_ingress(Ic00Method::NodeMetricsHistory)
                }
                CanisterCall::Request(_) => {
                    let res = NodeMetricsHistoryArgs::decode(payload)
                        .and_then(|args| self.node_metrics_history(&state, args));
                    ExecuteSubnetMessageResult::Finished {
                        response: res.map(|res| (res, None)),
                        refund: msg.take_cycles(),
                        instructions: NumInstructions::from(0),
                    }
                }
            },

            Ok(Ic00Method::SubnetInfo) => match &msg {
                CanisterCall::Ingress(_) => self.reject_unexpected_ingress(Ic00Method::SubnetInfo),
                CanisterCall::Request(_) => {
                    let res = SubnetInfoArgs::decode(payload).and_then(|args| {
                        self.subnet_info(replica_version, registry_settings.registry_version, args)
                    });
                    ExecuteSubnetMessageResult::Finished {
                        response: res.map(|res| (res, None)),
                        refund: msg.take_cycles(),
                        instructions: NumInstructions::from(0),
                    }
                }
            },

            Ok(Ic00Method::FetchCanisterLogs) => {
                match self.config.replicated_inter_canister_log_fetch {
                    FlagStatus::Disabled => ExecuteSubnetMessageResult::Finished {
                        response: Err(UserError::new(
                            ErrorCode::CanisterRejectedMessage,
                            format!(
                                "{} API is only accessible to end users in non-replicated mode",
                                Ic00Method::FetchCanisterLogs
                            ),
                        )),
                        refund: msg.take_cycles(),
                        instructions: NumInstructions::from(0),
                    },
                    FlagStatus::Enabled => {
                        let sender = *msg.sender();
                        let payload = payload.to_vec();
                        match &mut msg {
                            CanisterCall::Request(request) => {
                                let max_fetch_canister_logs_fee =
                                    self.cycles_account_manager.max_fetch_canister_logs_fee(
                                        registry_settings.subnet_size,
                                        cost_schedule,
                                    );

                                // Check there are sufficient cycles to cover the worst-case execution cost.
                                let response = if request.payment < max_fetch_canister_logs_fee {
                                    Err(UserError::new(
                                        ErrorCode::CanisterRejectedMessage,
                                        format!(
                                            "{} request sent with {} cycles, but {} cycles are required.",
                                            Ic00Method::FetchCanisterLogs,
                                            request.payment,
                                            max_fetch_canister_logs_fee
                                        ),
                                    ))
                                } else {
                                    FetchCanisterLogsRequest::decode(&payload)
                                        .and_then(|args| {
                                            fetch_canister_logs(
                                                sender,
                                                &state,
                                                args,
                                                self.config.fetch_canister_logs_filter,
                                            )
                                        })
                                        .map(|resp| {
                                            let response_bytes = Encode!(&resp).unwrap();
                                            let actual_fee = self
                                                .cycles_account_manager
                                                .fetch_canister_logs_fee(
                                                    NumBytes::new(response_bytes.len() as u64),
                                                    registry_settings.subnet_size,
                                                    cost_schedule,
                                                );
                                            // There are enough cycles, deduct the actual fee from paid cycles and refund the rest.
                                            msg.deduct_cycles(actual_fee);
                                            (response_bytes, None)
                                        })
                                };

                                ExecuteSubnetMessageResult::Finished {
                                    response,
                                    refund: msg.take_cycles(),
                                    instructions: NumInstructions::from(0),
                                }
                            }
                            CanisterCall::Ingress(_) => {
                                self.reject_unexpected_ingress(Ic00Method::FetchCanisterLogs)
                            }
                        }
                    }
                }
            }

            Ok(Ic00Method::TakeCanisterSnapshot) => match TakeCanisterSnapshotArgs::decode(payload)
            {
                Err(err) => ExecuteSubnetMessageResult::Finished {
                    response: Err(err),
                    refund: msg.take_cycles(),
                    instructions: NumInstructions::from(0),
                },
                Ok(args) => {
                    let canister_id = args.get_canister_id();
                    let (result, instructions_used) = self.take_canister_snapshot(
                        *msg.sender(),
                        &mut state,
                        args,
                        registry_settings.subnet_size,
                        round_limits,
                    );
                    ExecuteSubnetMessageResult::Finished {
                        response: result.map(|res| (res, Some(canister_id))),
                        refund: msg.take_cycles(),
                        instructions: instructions_used,
                    }
                }
            },

            Ok(Ic00Method::LoadCanisterSnapshot) => match LoadCanisterSnapshotArgs::decode(payload)
            {
                Err(err) => ExecuteSubnetMessageResult::Finished {
                    response: Err(err),
                    refund: msg.take_cycles(),
                    instructions: NumInstructions::from(0),
                },
                Ok(args) => {
                    let origin = msg.canister_change_origin(args.get_sender_canister_version());
                    let canister_id = args.get_canister_id();
                    let (result, instructions_used) = self.load_canister_snapshot(
                        registry_settings.subnet_size,
                        *msg.sender(),
                        &mut state,
                        args,
                        round_limits,
                        origin,
                    );
                    ExecuteSubnetMessageResult::Finished {
                        response: result.map(|res| (res, Some(canister_id))),
                        refund: msg.take_cycles(),
                        instructions: instructions_used,
                    }
                }
            },

            Ok(Ic00Method::ListCanisterSnapshots) => {
                let res = ListCanisterSnapshotArgs::decode(payload).and_then(|args| {
                    let canister_id = args.get_canister_id();
                    self.list_canister_snapshot(*msg.sender(), &mut state, args)
                        .map(|res| (res, Some(canister_id)))
                });
                ExecuteSubnetMessageResult::Finished {
                    response: res,
                    refund: msg.take_cycles(),
                    instructions: NumInstructions::from(0),
                }
            }

            Ok(Ic00Method::DeleteCanisterSnapshot) => {
                let resource_saturation =
                    self.subnet_memory_saturation(&round_limits.subnet_available_memory);
                let res = DeleteCanisterSnapshotArgs::decode(payload).and_then(|args| {
                    let canister_id = args.get_canister_id();
                    self.delete_canister_snapshot(
                        *msg.sender(),
                        &mut state,
                        args,
                        round_limits,
                        registry_settings.subnet_size,
                        &resource_saturation,
                    )
                    .map(|res| (res, Some(canister_id)))
                });
                ExecuteSubnetMessageResult::Finished {
                    response: res,
                    refund: msg.take_cycles(),
                    instructions: NumInstructions::from(0),
                }
            }

            Ok(Ic00Method::ReadCanisterSnapshotMetadata) => {
                let res = ReadCanisterSnapshotMetadataArgs::decode(payload).and_then(|args| {
                    match self.config.canister_snapshot_download {
                        FlagStatus::Disabled => Err(UserError::new(
                            ErrorCode::UnknownManagementMessage,
                            "Not yet implemented".to_string(),
                        )),
                        FlagStatus::Enabled => {
                            let canister_id = args.get_canister_id();
                            self.read_canister_snapshot_metadata(*msg.sender(), &state, args)
                                .map(|x| (x, Some(canister_id)))
                        }
                    }
                });
                ExecuteSubnetMessageResult::Finished {
                    response: res,
                    refund: msg.take_cycles(),
                    instructions: NumInstructions::from(0),
                }
            }

            Ok(Ic00Method::ReadCanisterSnapshotData) => {
                let res = ReadCanisterSnapshotDataArgs::decode(payload).and_then(|args| match self
                    .config
                    .canister_snapshot_download
                {
                    FlagStatus::Disabled => Err(UserError::new(
                        ErrorCode::UnknownManagementMessage,
                        "Not yet implemented".to_string(),
                    )),
                    FlagStatus::Enabled => {
                        let canister_id = args.get_canister_id();
                        self.read_snapshot_data(
                            *msg.sender(),
                            &mut state,
                            args,
                            registry_settings.subnet_size,
                        )
                        .map(|res| (res, Some(canister_id)))
                    }
                });
                ExecuteSubnetMessageResult::Finished {
                    response: res,
                    refund: msg.take_cycles(),
                    instructions: NumInstructions::from(0),
                }
            }

            Ok(Ic00Method::UploadCanisterSnapshotMetadata) => {
                match UploadCanisterSnapshotMetadataArgs::decode(payload) {
                    Err(err) => ExecuteSubnetMessageResult::Finished {
                        response: Err(err),
                        refund: msg.take_cycles(),
                        instructions: NumInstructions::from(0),
                    },
                    Ok(args) => match self.config.canister_snapshot_upload {
                        FlagStatus::Disabled => ExecuteSubnetMessageResult::Finished {
                            response: Err(UserError::new(
                                ErrorCode::UnknownManagementMessage,
                                "Not yet implemented".to_string(),
                            )),
                            refund: msg.take_cycles(),
                            instructions: NumInstructions::from(0),
                        },
                        FlagStatus::Enabled => {
                            let canister_id = args.get_canister_id();
                            let (result, instructions_used) = self.create_snapshot_from_metadata(
                                *msg.sender(),
                                &mut state,
                                args,
                                registry_settings.subnet_size,
                                round_limits,
                            );
                            ExecuteSubnetMessageResult::Finished {
                                response: result.map(|res| (res, Some(canister_id))),
                                refund: msg.take_cycles(),
                                instructions: instructions_used,
                            }
                        }
                    },
                }
            }

            Ok(Ic00Method::UploadCanisterSnapshotData) => {
                match UploadCanisterSnapshotDataArgs::decode(payload) {
                    Err(err) => ExecuteSubnetMessageResult::Finished {
                        response: Err(err),
                        refund: msg.take_cycles(),
                        instructions: NumInstructions::from(0),
                    },
                    Ok(args) => match self.config.canister_snapshot_upload {
                        FlagStatus::Disabled => ExecuteSubnetMessageResult::Finished {
                            response: Err(UserError::new(
                                ErrorCode::UnknownManagementMessage,
                                "Not yet implemented".to_string(),
                            )),
                            refund: msg.take_cycles(),
                            instructions: NumInstructions::from(0),
                        },
                        FlagStatus::Enabled => {
                            let canister_id = args.get_canister_id();
                            let (result, instructions_used) = self.write_snapshot_data(
                                *msg.sender(),
                                &mut state,
                                args,
                                registry_settings.subnet_size,
                                round_limits,
                            );
                            ExecuteSubnetMessageResult::Finished {
                                response: result.map(|res| (res, Some(canister_id))),
                                refund: msg.take_cycles(),
                                instructions: instructions_used,
                            }
                        }
                    },
                }
            }

            Ok(Ic00Method::RenameCanister) => {
                let res = RenameCanisterArgs::decode(payload).and_then(|args| {
                    let canister_id = args.get_canister_id();
                    let origin = msg.canister_change_origin(args.get_sender_canister_version());
                    self.rename_canister(*msg.sender(), &mut state, round_limits, args, origin)
                        .map(|res| (res, Some(canister_id)))
                });
                ExecuteSubnetMessageResult::Finished {
                    response: res,
                    refund: msg.take_cycles(),
                    instructions: NumInstructions::from(0),
                }
            }

            Err(ParseError::VariantNotFound) => {
                let res = Err(UserError::new(
                    ErrorCode::CanisterMethodNotFound,
                    format!("Management canister has no method '{}'", msg.method_name()),
                ));
                ExecuteSubnetMessageResult::Finished {
                    response: res,
                    refund: msg.take_cycles(),
                    instructions: NumInstructions::from(0),
                }
            }
        };

        // Note that some branches above have early returns:
        //   - `InstallCode`
        //   - `InstallChunkedCode`
        //   - `TakeCanisterSnapshot`
        //   - `LoadCanisterSnapshot`
        //   - `SignWithECDSA`
        // If you modify code below, please also update
        // these cases.
        self.finish_subnet_message_execution(state, msg, result, since)
    }

    fn try_add_http_context_to_replicated_state(
        &self,
        mut canister_http_request_context: CanisterHttpRequestContext,
        state: &mut ReplicatedState,
        request: &Request,
        registry_settings: &RegistryExecutionSettings,
        since: Instant,
    ) -> Result<(), UserError> {
        let http_request_fee = self.cycles_account_manager.http_request_fee(
            canister_http_request_context.variable_parts_size(),
            canister_http_request_context.max_response_bytes,
            registry_settings.subnet_size,
            state.get_own_cost_schedule(),
        );
        // Here we make sure that we do not let upper layers open new
        // http calls while the maximum number of calls is in-flight.
        // Later, in the http adapter we also have a bounded queue of
        // the same size, but this queue alone is not enough as it is
        // used as the interface between DSM and consensus, and the latter
        // consumes requests from this queue upon the request processing
        // start. This means more elements can be added to the queue, while
        // previous requests are still in-flight.
        if state
            .metadata
            .subnet_call_context_manager
            .canister_http_request_contexts
            .len()
            >= self.config.max_canister_http_requests_in_flight
        {
            Err(UserError::new(
                ErrorCode::CanisterRejectedMessage,
                format!(
                    "max number ({}) of http requests in-flight reached.",
                    self.config.max_canister_http_requests_in_flight
                ),
            ))
        } else if request.payment < http_request_fee {
            Err(UserError::new(
                ErrorCode::CanisterRejectedMessage,
                format!(
                    "{} request sent with {} cycles, but {} cycles are required.",
                    Ic00Method::HttpRequest,
                    request.payment,
                    http_request_fee
                ),
            ))
        } else {
            canister_http_request_context.request.payment -= http_request_fee;
            let http_fee = NominalCycles::from(http_request_fee);
            state.metadata.subnet_metrics.consumed_cycles_http_outcalls += http_fee;
            state
                .metadata
                .subnet_metrics
                .observe_consumed_cycles_with_use_case(CyclesUseCase::HTTPOutcalls, http_fee);
            state.metadata.subnet_call_context_manager.push_context(
                SubnetCallContext::CanisterHttpRequest(canister_http_request_context),
            );
            self.metrics.observe_message_with_label(
                &request.method_name,
                since.elapsed().as_secs_f64(),
                SUBMITTED_OUTCOME_LABEL.into(),
                SUCCESS_STATUS_LABEL.into(),
            );
            Ok(())
        }
    }

    /// Observes a subnet message metrics and outputs the given subnet response.
    fn finish_subnet_message_execution(
        &self,
        mut state: ReplicatedState,
        message: CanisterCall,
        result: ExecuteSubnetMessageResult,
        since: Instant,
    ) -> (ReplicatedState, Option<NumInstructions>) {
        let instructions = match &result {
            ExecuteSubnetMessageResult::Processing => None,
            ExecuteSubnetMessageResult::Finished {
                response,
                instructions,
                ..
            } => {
                // Request has been executed. Observe metrics and respond.
                let method_name = String::from(message.method_name());

                let res = match response {
                    Ok((res, canister_id)) => {
                        if let Some(canister_id) = canister_id
                            && let Some(canister_state) = state.canister_state_mut(canister_id)
                        {
                            canister_state.update_on_low_wasm_memory_hook_condition();
                        }
                        Ok(res)
                    }
                    Err(err) => Err(err.code()),
                };

                self.metrics.observe_subnet_message(
                    method_name.as_str(),
                    since.elapsed().as_secs_f64(),
                    &res,
                );
                Some(*instructions)
            }
        };
        let state = self.output_subnet_response(message, state, result);
        (state, instructions)
    }

    /// Executes a replicated message sent to a canister or a canister task.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_canister_input(
        &self,
        canister: CanisterState,
        instruction_limits: InstructionLimits,
        max_instructions_per_message_without_dts: NumInstructions,
        input: CanisterMessageOrTask,
        prepaid_execution_cycles: Option<Cycles>,
        time: Time,
        network_topology: Arc<NetworkTopology>,
        round_limits: &mut RoundLimits,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
    ) -> ExecuteMessageResult {
        match canister.next_execution() {
            NextExecution::None | NextExecution::StartNew => {}
            NextExecution::ContinueLong | NextExecution::ContinueInstallCode => {
                // We should never try to execute a canister message in
                // replicated mode if there is a pending long execution.
                panic!(
                    "Replicated execution with another pending DTS execution: {:?}",
                    canister.next_execution()
                );
            }
        }

        let round_counters = RoundCounters {
            execution_refund_error: &self.metrics.execution_cycles_refund_error,
            state_changes_error: &self.metrics.state_changes_error,
            invalid_system_call_error: &self.metrics.invalid_system_call_error,
            charging_from_balance_error: &self.metrics.charging_from_balance_error,
            unexpected_response_error: &self.metrics.unexpected_response_error,
            response_cycles_refund_error: &self.metrics.response_cycles_refund_error,
            invalid_canister_state_error: &self.metrics.invalid_canister_state_error,
            ingress_with_cycles_error: &self.metrics.ingress_with_cycles_error,
        };

        let round = RoundContext {
            network_topology: &network_topology,
            hypervisor: &self.hypervisor,
            cycles_account_manager: &self.cycles_account_manager,
            counters: round_counters,
            log: &self.log,
            time,
            cost_schedule,
        };

        let req = match input {
            CanisterMessageOrTask::Task(task) => {
                return self.execute_canister_task(
                    canister,
                    task,
                    prepaid_execution_cycles,
                    instruction_limits,
                    round,
                    round_limits,
                    subnet_size,
                );
            }
            CanisterMessageOrTask::Message(CanisterMessage::Response(response)) => {
                return self.execute_canister_response(
                    canister,
                    response,
                    instruction_limits,
                    time,
                    network_topology,
                    round_limits,
                    subnet_size,
                    cost_schedule,
                );
            }
            CanisterMessageOrTask::Message(CanisterMessage::Request(request)) => {
                CanisterCall::Request(request)
            }
            CanisterMessageOrTask::Message(CanisterMessage::Ingress(ingress)) => {
                CanisterCall::Ingress(ingress)
            }
        };

        let method = {
            // Note that Wasm validation guarantees that a name cannot be
            // exported multiple times as different types. So the order of
            // checks here matters only for performance, not correctness.
            let method = WasmMethod::Query(req.method_name().to_string());
            if canister.exports_method(&method) {
                method
            } else {
                let method = WasmMethod::CompositeQuery(req.method_name().to_string());
                if canister.exports_method(&method) {
                    method
                } else {
                    WasmMethod::Update(req.method_name().to_string())
                }
            }
        };

        match &method {
            WasmMethod::Query(_) | WasmMethod::CompositeQuery(_) => {
                let instruction_limits = InstructionLimits::new(
                    max_instructions_per_message_without_dts,
                    instruction_limits.slice(),
                );
                let execution_parameters = self.execution_parameters(
                    &canister,
                    instruction_limits,
                    ExecutionMode::Replicated,
                    // Effectively disable subnet memory resource reservation for queries.
                    ResourceSaturation::default(),
                );
                let result = execute_call_or_task(
                    canister,
                    CanisterCallOrTask::Query(req),
                    method,
                    prepaid_execution_cycles,
                    execution_parameters,
                    time,
                    round,
                    round_limits,
                    subnet_size,
                    &self.call_tree_metrics,
                    self.config.dirty_page_logging,
                    self.deallocator_thread.sender(),
                );
                if let ExecuteMessageResult::Finished {
                    canister: _,
                    response: ExecutionResponse::Request(_),
                    instructions_used: _,
                    heap_delta: _,
                    call_duration: Some(duration),
                } = &result
                {
                    self.metrics.call_durations.observe(duration.as_secs_f64());
                }
                result
            }
            WasmMethod::Update(_) => {
                let execution_parameters = self.execution_parameters(
                    &canister,
                    instruction_limits,
                    ExecutionMode::Replicated,
                    self.subnet_memory_saturation(&round_limits.subnet_available_memory),
                );
                execute_call_or_task(
                    canister,
                    CanisterCallOrTask::Update(req),
                    method,
                    prepaid_execution_cycles,
                    execution_parameters,
                    time,
                    round,
                    round_limits,
                    subnet_size,
                    &self.call_tree_metrics,
                    self.config.dirty_page_logging,
                    self.deallocator_thread.sender(),
                )
            }
            WasmMethod::System(_) => {
                unreachable!("Unreachable based on the previous statement");
            }
        }
    }

    /// Executes a canister task of a given canister.
    fn execute_canister_task(
        &self,
        canister: CanisterState,
        task: CanisterTask,
        prepaid_execution_cycles: Option<Cycles>,
        instruction_limits: InstructionLimits,
        round: RoundContext,
        round_limits: &mut RoundLimits,
        subnet_size: usize,
    ) -> ExecuteMessageResult {
        let execution_parameters = self.execution_parameters(
            &canister,
            instruction_limits,
            ExecutionMode::Replicated,
            self.subnet_memory_saturation(&round_limits.subnet_available_memory),
        );
        execute_call_or_task(
            canister,
            CanisterCallOrTask::Task(task.clone()),
            WasmMethod::System(SystemMethod::from(task)),
            prepaid_execution_cycles,
            execution_parameters,
            round.time,
            round,
            round_limits,
            subnet_size,
            &self.call_tree_metrics,
            self.config.dirty_page_logging,
            self.deallocator_thread.sender(),
        )
    }

    /// Returns the subnet memory capacity.
    pub fn subnet_memory_capacity(&self) -> NumBytes {
        self.config.subnet_memory_capacity
    }

    /// Builds execution parameters for the given canister with the given
    /// instruction limit and available subnet memory counter.
    fn execution_parameters(
        &self,
        canister: &CanisterState,
        instruction_limits: InstructionLimits,
        execution_mode: ExecutionMode,
        subnet_memory_saturation: ResourceSaturation,
    ) -> ExecutionParameters {
        ExecutionParameters {
            instruction_limits,
            wasm_memory_limit: canister.wasm_memory_limit(),
            memory_allocation: canister.memory_allocation(),
            canister_guaranteed_callback_quota: self.config.canister_guaranteed_callback_quota
                as u64,
            compute_allocation: canister.compute_allocation(),
            subnet_type: self.own_subnet_type,
            execution_mode,
            subnet_memory_saturation,
        }
    }

    fn create_canister(
        &self,
        origin: CanisterChangeOrigin,
        cycles: Cycles,
        settings: CanisterSettings,
        registry_settings: &RegistryExecutionSettings,
        state: &mut ReplicatedState,
        round_limits: &mut RoundLimits,
    ) -> ExecuteSubnetMessageResult {
        let sender = origin.origin();
        match state.find_subnet_id(sender) {
            Ok(sender_subnet_id) => {
                let (res, cycles) = self.canister_manager.create_canister(
                    origin,
                    sender_subnet_id,
                    cycles,
                    settings,
                    registry_settings.max_number_of_canisters,
                    state,
                    registry_settings.subnet_size,
                    round_limits,
                    self.subnet_memory_saturation(&round_limits.subnet_available_memory),
                    &self.metrics.canister_creation_error,
                );
                ExecuteSubnetMessageResult::Finished {
                    response: res
                        .map(|new_canister_id| {
                            (
                                CanisterIdRecord::from(new_canister_id).encode(),
                                Some(new_canister_id),
                            )
                        })
                        .map_err(|err| err.into()),
                    refund: cycles,
                    instructions: NumInstructions::from(0),
                }
            }
            Err(err) => ExecuteSubnetMessageResult::Finished {
                response: Err(err),
                refund: cycles,
                instructions: NumInstructions::from(0),
            },
        }
    }

    fn update_settings(
        &self,
        timestamp_nanos: Time,
        origin: CanisterChangeOrigin,
        settings: CanisterSettings,
        canister_id: CanisterId,
        state: &mut ReplicatedState,
        round_limits: &mut RoundLimits,
        subnet_size: usize,
    ) -> Result<Vec<u8>, UserError> {
        let cost_schedule = state.get_own_cost_schedule();
        let canister = get_canister_mut(canister_id, state)?;
        self.canister_manager
            .update_settings(
                timestamp_nanos,
                origin,
                settings,
                canister,
                round_limits,
                self.subnet_memory_saturation(&round_limits.subnet_available_memory),
                subnet_size,
                cost_schedule,
            )
            .map(|()| EmptyBlob.encode())
            .map_err(|err| err.into())
    }

    fn start_canister(
        &self,
        canister_id: CanisterId,
        sender: PrincipalId,
        state: &mut ReplicatedState,
    ) -> Result<Vec<u8>, UserError> {
        let canister = get_canister_mut(canister_id, state)?;

        let result = self.canister_manager.start_canister(sender, canister);

        match result {
            Ok(stop_contexts) => {
                // Reject outstanding stop messages (if any).
                self.reject_stop_requests(canister_id, stop_contexts, state);
                Ok(EmptyBlob.encode())
            }
            Err(err) => Err(err.into()),
        }
    }

    fn deposit_cycles(
        &self,
        canister_id: CanisterId,
        msg: &mut CanisterCall,
        state: &mut ReplicatedState,
    ) -> ExecuteSubnetMessageResult {
        match state.canister_state_mut(&canister_id) {
            None => ExecuteSubnetMessageResult::Finished {
                response: Err(UserError::new(
                    ErrorCode::CanisterNotFound,
                    format!("Canister {} not found.", &canister_id),
                )),
                refund: msg.take_cycles(),
                instructions: NumInstructions::from(0),
            },

            Some(canister_state) => {
                let cycles = msg.take_cycles();
                canister_state
                    .system_state
                    .add_cycles(cycles, CyclesUseCase::NonConsumed);
                if cycles.get() > LOG_CANISTER_OPERATION_CYCLES_THRESHOLD {
                    info!(
                        self.log,
                        "Canister {} deposited {} cycles to canister {}.",
                        msg.sender(),
                        cycles,
                        canister_id.get(),
                    );
                }
                ExecuteSubnetMessageResult::Finished {
                    response: Ok((EmptyBlob.encode(), Some(canister_id))),
                    refund: Cycles::zero(),
                    instructions: NumInstructions::from(0),
                }
            }
        }
    }

    fn get_canister_status(
        &self,
        sender: PrincipalId,
        canister_id: CanisterId,
        state: &ReplicatedState,
        subnet_size: usize,
        ready_for_migration: bool,
    ) -> Result<Vec<u8>, UserError> {
        let cost_schedule = state.get_own_cost_schedule();
        let canister = get_canister(canister_id, state)?;
        self.canister_manager
            .get_canister_status(
                sender,
                canister,
                subnet_size,
                cost_schedule,
                ready_for_migration,
            )
            .map(|status| status.encode())
            .map_err(|err| err.into())
    }

    fn get_canister_info(
        &self,
        canister_id: CanisterId,
        num_requested_changes: Option<u64>,
        state: &ReplicatedState,
    ) -> Result<Vec<u8>, UserError> {
        let canister = get_canister(canister_id, state)?;
        let canister_history = canister.system_state.get_canister_history();
        let total_num_changes = canister_history.get_total_num_changes();
        let changes = canister_history
            .get_changes(num_requested_changes.unwrap_or(0) as usize)
            .map(|e| (*e.clone()).clone())
            .collect();
        let module_hash = canister
            .execution_state
            .as_ref()
            .map(|es| es.wasm_binary.binary.module_hash().to_vec());
        let controllers = canister
            .controllers()
            .iter()
            .copied()
            .collect::<Vec<PrincipalId>>();
        let res = CanisterInfoResponse::new(total_num_changes, changes, module_hash, controllers);
        Ok(res.encode())
    }

    fn get_canister_metadata(
        &self,
        sender: PrincipalId,
        canister_id: CanisterId,
        state: &ReplicatedState,
        name: &str,
    ) -> Result<Vec<u8>, UserError> {
        let canister = get_canister(canister_id, state)?;
        self.canister_manager
            .get_canister_metadata(sender, canister, name)
            .map(|res| res.encode())
            .map_err(|err| err.into())
    }

    fn stop_canister(
        &self,
        canister_id: CanisterId,
        msg: &CanisterCall,
        state: &mut ReplicatedState,
    ) -> ExecuteSubnetMessageResult {
        let call_id = state
            .metadata
            .subnet_call_context_manager
            .push_stop_canister_call(StopCanisterCall {
                call: msg.clone(),
                effective_canister_id: canister_id,
                time: state.time(),
            });
        match self.canister_manager.stop_canister(
            canister_id,
            StopCanisterContext::from((msg.clone(), call_id)),
            state,
        ) {
            StopCanisterResult::RequestAccepted => ExecuteSubnetMessageResult::Processing,
            StopCanisterResult::Failure {
                error,
                cycles_to_return,
            } => ExecuteSubnetMessageResult::Finished {
                response: Err(error.into()),
                refund: cycles_to_return,
                instructions: NumInstructions::from(0),
            },
            StopCanisterResult::AlreadyStopped { cycles_to_return } => {
                ExecuteSubnetMessageResult::Finished {
                    response: Ok((EmptyBlob.encode(), Some(canister_id))),
                    refund: cycles_to_return,
                    instructions: NumInstructions::from(0),
                }
            }
        }
    }

    fn add_cycles(
        &self,
        sender: PrincipalId,
        canister_id: CanisterId,
        cycles: Option<u128>,
        state: &mut ReplicatedState,
        provisional_whitelist: &ProvisionalWhitelist,
    ) -> Result<Vec<u8>, UserError> {
        let canister = get_canister_mut(canister_id, state)?;
        self.canister_manager
            .add_cycles(sender, cycles, canister, provisional_whitelist)
            .map(|()| EmptyBlob.encode())
            .map_err(|err| err.into())
    }

    fn upload_chunk(
        &self,
        sender: PrincipalId,
        state: &mut ReplicatedState,
        args: UploadChunkArgs,
        round_limits: &mut RoundLimits,
        subnet_size: usize,
        resource_saturation: &ResourceSaturation,
    ) -> Result<Vec<u8>, UserError> {
        let cost_schedule = state.get_own_cost_schedule();
        let canister = get_canister_mut(args.get_canister_id(), state)?;
        self.canister_manager
            .upload_chunk(
                sender,
                canister,
                args.chunk,
                round_limits,
                subnet_size,
                cost_schedule,
                resource_saturation,
            )
            .map(
                |UploadChunkResult {
                     reply,
                     heap_delta_increase,
                 }| {
                    state.metadata.heap_delta_estimate += heap_delta_increase;
                    reply.encode()
                },
            )
            .map_err(|err| err.into())
    }

    fn clear_chunk_store(
        &self,
        sender: PrincipalId,
        state: &mut ReplicatedState,
        args: ClearChunkStoreArgs,
        round_limits: &mut RoundLimits,
        subnet_size: usize,
        resource_saturation: &ResourceSaturation,
    ) -> Result<Vec<u8>, UserError> {
        let cost_schedule = state.get_own_cost_schedule();
        let canister = get_canister_mut(args.get_canister_id(), state)?;
        self.canister_manager
            .clear_chunk_store(
                sender,
                canister,
                round_limits,
                subnet_size,
                cost_schedule,
                resource_saturation,
            )
            .map(|()| EmptyBlob.encode())
            .map_err(|err| err.into())
    }

    fn stored_chunks(
        &self,
        sender: PrincipalId,
        state: &ReplicatedState,
        args: StoredChunksArgs,
    ) -> Result<Vec<u8>, UserError> {
        let canister = get_canister(args.get_canister_id(), state)?;
        self.canister_manager
            .stored_chunks(sender, canister)
            .map(|reply| reply.encode())
            .map_err(|err| err.into())
    }

    /// Creates a new canister snapshot and inserts it into `ReplicatedState`.
    fn take_canister_snapshot(
        &self,
        sender: PrincipalId,
        state: &mut ReplicatedState,
        args: TakeCanisterSnapshotArgs,
        subnet_size: usize,
        round_limits: &mut RoundLimits,
    ) -> (Result<Vec<u8>, UserError>, NumInstructions) {
        let canister_id = args.get_canister_id();
        // Take canister out.
        let mut canister = match state.take_canister_state(&canister_id) {
            None => {
                return (
                    Err(UserError::new(
                        ErrorCode::CanisterNotFound,
                        format!("Canister {} not found.", &canister_id),
                    )),
                    NumInstructions::new(0),
                );
            }
            Some(canister) => canister,
        };

        let resource_saturation =
            self.subnet_memory_saturation(&round_limits.subnet_available_memory);
        let replace_snapshot = args.replace_snapshot();
        let result = self.canister_manager.take_canister_snapshot(
            subnet_size,
            sender,
            &mut canister,
            replace_snapshot,
            state,
            round_limits,
            &resource_saturation,
        );
        // Put canister back.
        state.put_canister_state(canister);

        match result {
            Ok((response, instructions_used)) => (Ok(response.encode()), instructions_used),
            Err(err) => (Err(err.into()), NumInstructions::new(0)),
        }
    }

    /// Loads a canister snapshot onto an existing canister.
    fn load_canister_snapshot(
        &self,
        subnet_size: usize,
        sender: PrincipalId,
        state: &mut ReplicatedState,
        args: LoadCanisterSnapshotArgs,
        round_limits: &mut RoundLimits,
        origin: CanisterChangeOrigin,
    ) -> (Result<Vec<u8>, UserError>, NumInstructions) {
        let canister_id = args.get_canister_id();
        // Take canister out.
        let mut old_canister = match state.take_canister_state(&canister_id) {
            None => {
                return (
                    Err(UserError::new(
                        ErrorCode::CanisterNotFound,
                        format!("Canister {} not found.", &canister_id),
                    )),
                    NumInstructions::new(0),
                );
            }
            Some(canister) => canister,
        };

        let snapshot_id = args.snapshot_id();
        let resource_saturation =
            self.subnet_memory_saturation(&round_limits.subnet_available_memory);
        let (result, instructions_used) = self.canister_manager.load_canister_snapshot(
            subnet_size,
            sender,
            &mut old_canister,
            snapshot_id,
            state,
            round_limits,
            origin,
            &resource_saturation,
            &self.metrics.long_execution_already_in_progress,
            &self.metrics.snapshot_exists_without_associated_canister,
        );

        let result = match result {
            Ok(new_canister) => {
                state.put_canister_state(new_canister);
                Ok(EmptyBlob.encode())
            }
            Err(err) => {
                // Could not load the canister snapshot, thus put back old state.
                state.put_canister_state(old_canister);
                Err(err.into())
            }
        };

        (result, instructions_used)
    }

    /// Lists the snapshots belonging to the specified canister.
    fn list_canister_snapshot(
        &self,
        sender: PrincipalId,
        state: &mut ReplicatedState,
        args: ListCanisterSnapshotArgs,
    ) -> Result<Vec<u8>, UserError> {
        let canister = get_canister(args.get_canister_id(), state)?;

        let result = self
            .canister_manager
            .list_canister_snapshot(sender, canister, state)
            .map_err(UserError::from)?;

        Ok(Encode!(&result).unwrap())
    }

    /// Deletes the specified canister snapshot if it exists.
    fn delete_canister_snapshot(
        &self,
        sender: PrincipalId,
        state: &mut ReplicatedState,
        args: DeleteCanisterSnapshotArgs,
        round_limits: &mut RoundLimits,
        subnet_size: usize,
        resource_saturation: &ResourceSaturation,
    ) -> Result<Vec<u8>, UserError> {
        let canister_id = args.get_canister_id();
        // Take canister out.
        let mut canister = match state.take_canister_state(&canister_id) {
            None => {
                return Err(UserError::new(
                    ErrorCode::CanisterNotFound,
                    format!("Canister {} not found.", &canister_id),
                ));
            }
            Some(canister) => canister,
        };

        let result = self
            .canister_manager
            .delete_canister_snapshot(
                sender,
                &mut canister,
                args.get_snapshot_id(),
                state,
                round_limits,
                subnet_size,
                resource_saturation,
            )
            .map(|()| EmptyBlob.encode())
            .map_err(|err| err.into());

        // Put canister back.
        state.put_canister_state(canister);
        result
    }

    fn read_snapshot_data(
        &self,
        sender: PrincipalId,
        state: &mut ReplicatedState,
        args: ReadCanisterSnapshotDataArgs,
        subnet_size: usize,
    ) -> Result<Vec<u8>, UserError> {
        let canister_id = args.get_canister_id();
        // Take canister out.
        let mut canister = match state.take_canister_state(&canister_id) {
            None => {
                return Err(UserError::new(
                    ErrorCode::CanisterNotFound,
                    format!("Canister {} not found.", &canister_id),
                ));
            }
            Some(canister) => canister,
        };

        let result = self
            .canister_manager
            .read_snapshot_data(
                sender,
                &mut canister,
                args.get_snapshot_id(),
                args.kind,
                state,
                subnet_size,
            )
            .map(|res| Encode!(&res).unwrap())
            .map_err(UserError::from);

        // Put canister back.
        state.put_canister_state(canister);
        result
    }

    fn rename_canister(
        &self,
        sender: PrincipalId,
        state: &mut ReplicatedState,
        round_limits: &mut RoundLimits,
        args: RenameCanisterArgs,
        origin: CanisterChangeOrigin,
    ) -> Result<Vec<u8>, UserError> {
        let old_id = args.get_canister_id();
        let new_id = args.rename_to.get_canister_id();
        let to_version = args.rename_to.version;
        let to_total_num_changes = args.rename_to.total_num_changes;
        let requested_by = args.requested_by();

        // Take canister out.
        let mut canister = match state.take_canister_state(&old_id) {
            None => {
                return Err(UserError::new(
                    ErrorCode::CanisterNotFound,
                    format!("Canister {old_id} not found."),
                ));
            }
            Some(canister) => canister,
        };

        let result = self
            .canister_manager
            .rename_canister(
                sender,
                &mut canister,
                origin,
                old_id,
                new_id,
                to_version,
                to_total_num_changes,
                requested_by,
                state,
                round_limits,
            )
            .map(|()| EmptyBlob.encode())
            .map_err(|err| err.into());

        // Put canister back with the new id.
        state.put_canister_state(canister);
        result
    }

    fn read_canister_snapshot_metadata(
        &self,
        sender: PrincipalId,
        state: &ReplicatedState,
        args: ReadCanisterSnapshotMetadataArgs,
    ) -> Result<Vec<u8>, UserError> {
        let canister = get_canister(args.get_canister_id(), state)?;
        let snapshot_id = args.get_snapshot_id();
        self.canister_manager
            .read_snapshot_metadata(sender, snapshot_id, canister, state)
            .map(|res| Encode!(&res).unwrap())
            .map_err(UserError::from)
    }

    fn create_snapshot_from_metadata(
        &self,
        sender: PrincipalId,
        state: &mut ReplicatedState,
        args: UploadCanisterSnapshotMetadataArgs,
        subnet_size: usize,
        round_limits: &mut RoundLimits,
    ) -> (Result<Vec<u8>, UserError>, NumInstructions) {
        let canister_id = args.get_canister_id();
        // Take canister out.
        let mut canister = match state.take_canister_state(&canister_id) {
            None => {
                return (
                    Err(UserError::new(
                        ErrorCode::CanisterNotFound,
                        format!("Canister {} not found.", &canister_id),
                    )),
                    NumInstructions::new(0),
                );
            }
            Some(canister) => canister,
        };

        let resource_saturation =
            self.subnet_memory_saturation(&round_limits.subnet_available_memory);
        let result = self.canister_manager.create_snapshot_from_metadata(
            sender,
            &mut canister,
            args,
            state,
            subnet_size,
            round_limits,
            &resource_saturation,
        );
        // Put canister back.
        state.put_canister_state(canister);
        match result {
            Ok((snapshot_id, instructions_used)) => (
                Ok(Encode!(&UploadCanisterSnapshotMetadataResponse { snapshot_id }).unwrap()),
                instructions_used,
            ),
            Err(e) => (Err(e), NumInstructions::new(0)),
        }
    }

    fn write_snapshot_data(
        &self,
        sender: PrincipalId,
        state: &mut ReplicatedState,
        args: UploadCanisterSnapshotDataArgs,
        subnet_size: usize,
        round_limits: &mut RoundLimits,
    ) -> (Result<Vec<u8>, UserError>, NumInstructions) {
        let canister_id = args.get_canister_id();
        // Take canister out.
        let mut canister = match state.take_canister_state(&canister_id) {
            None => {
                return (
                    Err(UserError::new(
                        ErrorCode::CanisterNotFound,
                        format!("Canister {} not found.", &canister_id),
                    )),
                    NumInstructions::new(0),
                );
            }
            Some(canister) => canister,
        };

        let resource_saturation =
            self.subnet_memory_saturation(&round_limits.subnet_available_memory);
        let result = self.canister_manager.write_snapshot_data(
            sender,
            &mut canister,
            &args,
            state,
            round_limits,
            subnet_size,
            &resource_saturation,
        );
        // Put canister back.
        state.put_canister_state(canister);

        match result {
            Ok(instructions_used) => (Ok(Encode!(&()).unwrap()), instructions_used),
            Err(e) => (Err(UserError::from(e)), NumInstructions::new(0)),
        }
    }

    fn node_metrics_history(
        &self,
        state: &ReplicatedState,
        args: NodeMetricsHistoryArgs,
    ) -> Result<Vec<u8>, UserError> {
        if args.subnet_id != self.own_subnet_id.get() {
            return Err(UserError::new(
                ErrorCode::CanisterRejectedMessage,
                format!(
                    "Provided target subnet ID {} does not match current subnet ID {}.",
                    args.subnet_id, self.own_subnet_id
                ),
            ));
        }

        let result = state
            .metadata
            .blockmaker_metrics_time_series
            .node_metrics_history(Time::from_nanos_since_unix_epoch(
                args.start_at_timestamp_nanos,
            ));
        Ok(Encode!(&result).unwrap())
    }

    fn subnet_info(
        &self,
        replica_version: &ReplicaVersion,
        registry_version: RegistryVersion,
        args: SubnetInfoArgs,
    ) -> Result<Vec<u8>, UserError> {
        if args.subnet_id != self.own_subnet_id.get() {
            return Err(UserError::new(
                ErrorCode::CanisterRejectedMessage,
                format!(
                    "Provided target subnet ID {} does not match current subnet ID {}.",
                    args.subnet_id, self.own_subnet_id
                ),
            ));
        }
        let res = SubnetInfoResponse {
            replica_version: replica_version.to_string(),
            registry_version: registry_version.get(),
        };
        Ok(Encode!(&res).unwrap())
    }

    // Executes an inter-canister response.
    //
    // Returns a tuple with the result, along with a flag indicating whether or
    // not to refund the remaining cycles to the canister.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_canister_response(
        &self,
        canister: CanisterState,
        response: Arc<Response>,
        instruction_limits: InstructionLimits,
        time: Time,
        network_topology: Arc<NetworkTopology>,
        round_limits: &mut RoundLimits,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
    ) -> ExecuteMessageResult {
        let execution_parameters = self.execution_parameters(
            &canister,
            instruction_limits,
            ExecutionMode::Replicated,
            self.subnet_memory_saturation(&round_limits.subnet_available_memory),
        );

        let round_counters = RoundCounters {
            execution_refund_error: &self.metrics.execution_cycles_refund_error,
            state_changes_error: &self.metrics.state_changes_error,
            invalid_system_call_error: &self.metrics.invalid_system_call_error,
            charging_from_balance_error: &self.metrics.charging_from_balance_error,
            unexpected_response_error: &self.metrics.unexpected_response_error,
            response_cycles_refund_error: &self.metrics.response_cycles_refund_error,
            invalid_canister_state_error: &self.metrics.invalid_canister_state_error,
            ingress_with_cycles_error: &self.metrics.ingress_with_cycles_error,
        };

        let round = RoundContext {
            network_topology: &network_topology,
            hypervisor: &self.hypervisor,
            cycles_account_manager: &self.cycles_account_manager,
            counters: round_counters,
            log: &self.log,
            time,
            cost_schedule,
        };
        execute_response(
            canister,
            response,
            time,
            execution_parameters,
            round,
            round_limits,
            subnet_size,
            &self.call_tree_metrics,
            self.config.dirty_page_logging,
            self.deallocator_thread.sender(),
        )
    }

    /// Asks the canister if it is willing to accept the provided ingress
    /// message.
    pub fn should_accept_ingress_message(
        &self,
        state: Arc<ReplicatedState>,
        provisional_whitelist: &ProvisionalWhitelist,
        ingress: &SignedIngress,
        execution_mode: ExecutionMode,
        metrics: &IngressFilterMetrics,
    ) -> Result<(), UserError> {
        let canister = |canister_id: CanisterId| -> Result<&CanisterState, UserError> {
            match state.canister_state(&canister_id) {
                Some(canister) => Ok(canister),
                None => Err(UserError::new(
                    ErrorCode::CanisterNotFound,
                    format!("Canister {canister_id} not found"),
                )),
            }
        };
        let effective_canister_id = extract_effective_canister_id(ingress.content())
            .map_err(|err| err.into_user_error(ingress.content().method_name()))?;

        // A first-pass check on the canister's balance to prevent needless gossiping
        // if the canister's balance is too low. A more rigorous check happens later
        // in the ingress selector.
        {
            let subnet_size = state
                .metadata
                .network_topology
                .get_subnet_size(&state.metadata.own_subnet_id)
                .unwrap_or(SMALL_APP_SUBNET_MAX_SIZE);
            let induction_cost = self.cycles_account_manager.ingress_induction_cost(
                ingress,
                effective_canister_id,
                subnet_size,
                state.get_own_cost_schedule(),
            );

            if let IngressInductionCost::Fee { payer, cost } = induction_cost {
                let paying_canister = canister(payer)?;
                let reveal_top_up = paying_canister
                    .controllers()
                    .contains(&ingress.sender().get());
                if let Err(err) = self.cycles_account_manager.can_withdraw_cycles(
                    &paying_canister.system_state,
                    cost,
                    paying_canister.memory_usage(),
                    paying_canister.message_memory_usage(),
                    paying_canister.scheduler_state.compute_allocation,
                    subnet_size,
                    state.get_own_cost_schedule(),
                    reveal_top_up,
                ) {
                    return Err(UserError::new(
                        ErrorCode::CanisterOutOfCycles,
                        err.to_string(),
                    ));
                }
            }
        }

        if ingress.content().is_addressed_to_subnet() {
            return self.canister_manager.should_accept_ingress_message(
                state,
                provisional_whitelist,
                ingress.content(),
                effective_canister_id,
            );
        }

        let canister_state = canister(ingress.canister_id())?;

        match canister_state.status() {
            CanisterStatusType::Running => {}
            CanisterStatusType::Stopping => {
                return Err(UserError::new(
                    ErrorCode::CanisterStopping,
                    format!("Canister {} is stopping", ingress.canister_id()),
                ));
            }
            CanisterStatusType::Stopped => {
                return Err(UserError::new(
                    ErrorCode::CanisterStopped,
                    format!("Canister {} is stopped", ingress.canister_id()),
                ));
            }
        }

        // Composite queries are not allowed to be called in replicated mode.
        let method = WasmMethod::CompositeQuery(ingress.method_name().to_string());
        if canister_state.exports_method(&method) {
            return Err(UserError::new(
                ErrorCode::CompositeQueryCalledInReplicatedMode,
                "Composite query cannot be called in replicated mode",
            ));
        }

        // An inspect message is expected to finish quickly, so DTS is not
        // supported for it.
        let instruction_limits = InstructionLimits::new(
            self.config.max_instructions_for_message_acceptance_calls,
            self.config.max_instructions_for_message_acceptance_calls,
        );

        // Letting the canister grow arbitrarily when executing the
        // query is fine as we do not persist state modifications.
        let subnet_available_memory = full_subnet_memory_capacity(&self.config);
        let execution_parameters = self.execution_parameters(
            canister_state,
            instruction_limits,
            execution_mode,
            // Effectively disable subnet memory resource reservation for queries.
            ResourceSaturation::default(),
        );

        inspect_message::execute_inspect_message(
            state.time(),
            canister_state.clone(),
            ingress.content(),
            execution_parameters,
            subnet_available_memory,
            &self.hypervisor,
            &state.metadata.network_topology,
            &self.log,
            &self.metrics.state_changes_error,
            metrics,
            state.get_own_cost_schedule(),
        )
        .1
    }

    // Output the response of a subnet message depending on its type.
    //
    // Canister requests are responded to by adding a response to the subnet's
    // output queue. Ingress requests are responded to by writing to ingress
    // history.
    fn output_subnet_response(
        &self,
        msg: CanisterCall,
        mut state: ReplicatedState,
        result: ExecuteSubnetMessageResult,
    ) -> ReplicatedState {
        match msg {
            CanisterCall::Request(req) => match result {
                ExecuteSubnetMessageResult::Processing => state,
                ExecuteSubnetMessageResult::Finished {
                    response, refund, ..
                } => {
                    let payload = match response {
                        Ok((payload, ..)) => Payload::Data(payload),
                        Err(err) => Payload::Reject(err.into()),
                    };

                    let subnet_id_as_canister_id = CanisterId::from(self.own_subnet_id);
                    let response = Response {
                        originator: req.sender,
                        respondent: subnet_id_as_canister_id,
                        originator_reply_callback: req.sender_reply_callback,
                        refund,
                        response_payload: payload,
                        deadline: req.deadline,
                    };

                    state.push_subnet_output_response(response.into());
                    state
                }
            },
            CanisterCall::Ingress(ingress) => match result {
                ExecuteSubnetMessageResult::Processing => {
                    let status = IngressStatus::Known {
                        receiver: ingress.receiver.get(),
                        user_id: ingress.source,
                        time: state.time(),
                        state: IngressState::Processing,
                    };
                    self.ingress_history_writer.set_status(
                        &mut state,
                        ingress.message_id.clone(),
                        status,
                    );
                    state
                }
                ExecuteSubnetMessageResult::Finished {
                    response, refund, ..
                } => {
                    debug_assert!(refund.is_zero());
                    if !refund.is_zero() {
                        self.metrics.ingress_with_cycles_error.inc();
                        warn!(
                            self.log,
                            "[EXC-BUG] No funds can be included with an ingress message: user {}, canister_id {}, message_id {}.",
                            ingress.source,
                            ingress.receiver,
                            ingress.message_id
                        );
                    }
                    let status = match response {
                        Ok((payload, ..)) => IngressStatus::Known {
                            receiver: ingress.receiver.get(),
                            user_id: ingress.source,
                            time: state.time(),
                            state: IngressState::Completed(WasmResult::Reply(payload)),
                        },
                        Err(err) => IngressStatus::Known {
                            receiver: ingress.receiver.get(),
                            user_id: ingress.source,
                            time: state.time(),
                            state: IngressState::Failed(err),
                        },
                    };

                    self.ingress_history_writer.set_status(
                        &mut state,
                        ingress.message_id.clone(),
                        status,
                    );
                    state
                }
            },
        }
    }

    // Rejects pending stop requests with an error indicating the request has been
    // cancelled.
    fn reject_stop_requests(
        &self,
        canister_id: CanisterId,
        stop_contexts: Vec<StopCanisterContext>,
        state: &mut ReplicatedState,
    ) {
        for stop_context in stop_contexts {
            match stop_context {
                StopCanisterContext::Ingress {
                    sender,
                    message_id,
                    call_id,
                } => {
                    let time = state.time();
                    // Rejecting a stop_canister request from a user.
                    self.remove_stop_canister_call(state, canister_id, call_id);
                    self.ingress_history_writer.set_status(
                        state,
                        message_id,
                        IngressStatus::Known {
                            receiver: IC_00.get(),
                            user_id: sender,
                            time,
                            state: IngressState::Failed(UserError::new(
                                ErrorCode::CanisterStoppingCancelled,
                                format!("Canister {canister_id}'s stop request was cancelled."),
                            )),
                        },
                    );
                }
                StopCanisterContext::Canister {
                    sender,
                    reply_callback,
                    call_id,
                    cycles,
                    deadline,
                } => {
                    // Rejecting a stop_canister request from a canister.
                    let subnet_id_as_canister_id = CanisterId::from(self.own_subnet_id);
                    self.remove_stop_canister_call(state, canister_id, call_id);

                    let response = Response {
                        originator: sender,
                        respondent: subnet_id_as_canister_id,
                        originator_reply_callback: reply_callback,
                        refund: cycles,
                        response_payload: Payload::Reject(RejectContext::new(
                            RejectCode::CanisterError,
                            format!("Canister {canister_id}'s stop request cancelled"),
                        )),
                        deadline,
                    };
                    state.push_subnet_output_response(response.into());
                }
            }
        }
    }

    fn setup_initial_dkg(
        &self,
        payload: &[u8],
        request: &Request,
        state: &mut ReplicatedState,
        rng: &mut dyn RngCore,
    ) -> Result<(), UserError> {
        match SetupInitialDKGArgs::decode(payload) {
            Err(err) => Err(err),
            Ok(settings) => match settings.get_set_of_node_ids() {
                Err(err) => Err(err),
                Ok(nodes_in_target_subnet) => {
                    let mut target_id = [0u8; 32];
                    rng.fill_bytes(&mut target_id);

                    info!(
                        self.log,
                        "Assigned the target_id {:?} to the new DKG setup request for nodes {:?}",
                        target_id,
                        &nodes_in_target_subnet
                    );
                    state.metadata.subnet_call_context_manager.push_context(
                        SubnetCallContext::SetupInitialDKG(SetupInitialDkgContext {
                            request: request.clone(),
                            nodes_in_target_subnet,
                            target_id: NiDkgTargetId::new(target_id),
                            registry_version: settings.get_registry_version(),
                            time: state.time(),
                        }),
                    );
                    Ok(())
                }
            },
        }
    }

    fn get_threshold_public_key(
        &self,
        subnet_public_key: &MasterPublicKey,
        caller: PrincipalId,
        derivation_path: Vec<Vec<u8>>,
    ) -> Result<PublicKey, UserError> {
        derive_threshold_public_key(
            subnet_public_key,
            &ExtendedDerivationPath {
                caller,
                derivation_path,
            },
        )
        .map_err(|err| UserError::new(ErrorCode::CanisterRejectedMessage, format!("{err}")))
    }

    fn get_vetkd_public_key(
        &self,
        subnet_public_key: &MasterPublicKey,
        caller: PrincipalId,
        context: Vec<u8>,
    ) -> Result<Vec<u8>, UserError> {
        if subnet_public_key.algorithm_id != ic_types::crypto::AlgorithmId::VetKD {
            return Err(UserError::new(
                ErrorCode::CanisterRejectedMessage,
                "Provided subnet master key is not for VetKD".to_string(),
            ));
        }

        let dpk = ic_vetkeys::MasterPublicKey::deserialize(&subnet_public_key.public_key).map_err(
            |err| {
                UserError::new(
                    ErrorCode::CanisterRejectedMessage,
                    format!("Invalid VetKD subnet key: {err:?}"),
                )
            },
        )?;

        Ok(dpk
            .derive_canister_key(caller.as_slice())
            .derive_sub_key(&context)
            .serialize())
    }

    fn vetkd_derive_key(
        &self,
        request: &Request,
        payload: &[u8],
        chain_key_data: &ChainKeyData,
        state: &mut ReplicatedState,
        rng: &mut dyn RngCore,
        registry_settings: &RegistryExecutionSettings,
        current_round: ExecutionRound,
    ) -> Result<(), UserError> {
        let args = VetKdDeriveKeyArgs::decode(payload)?;
        let key_id = NiDkgMasterPublicKeyId::VetKd(args.key_id.clone());
        let _master_public_key_exists = get_master_public_key(
            &chain_key_data.master_public_keys,
            self.own_subnet_id,
            &key_id.clone().into(),
        )?;
        let Some(ni_dkg_id) = chain_key_data.nidkg_ids.get(&key_id) else {
            warn!(
                self.log,
                "No NiDkgId delivered to answer vetkd request for key {}.", key_id
            );
            return Err(UserError::new(
                ErrorCode::CanisterRejectedMessage,
                format!(
                    "Subnet {} does not hold NiDkgTranscript for key {}.",
                    self.own_subnet_id, key_id
                ),
            ));
        };
        if !ic_vetkeys::is_valid_transport_public_key_encoding(&args.transport_public_key) {
            return Err(UserError::new(
                ErrorCode::CanisterRejectedMessage,
                "The provided transport public key is invalid.",
            ));
        }
        self.sign_with_threshold(
            (*request).clone(),
            ThresholdArguments::VetKd(VetKdArguments {
                key_id: args.key_id,
                input: Arc::new(args.input),
                transport_public_key: args.transport_public_key.to_vec(),
                ni_dkg_id: ni_dkg_id.clone(),
                height: Height::new(current_round.get()),
            }),
            vec![args.context],
            registry_settings
                .chain_key_settings
                .get(&key_id.into())
                .map(|setting| setting.max_queue_size)
                .unwrap_or_default(),
            state,
            rng,
            registry_settings.subnet_size,
        )
    }

    fn calculate_signature_fee(
        &self,
        args: &ThresholdArguments,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
    ) -> Cycles {
        let cam = &self.cycles_account_manager;
        match args {
            ThresholdArguments::Ecdsa(_) => cam.ecdsa_signature_fee(subnet_size, cost_schedule),
            ThresholdArguments::Schnorr(_) => cam.schnorr_signature_fee(subnet_size, cost_schedule),
            ThresholdArguments::VetKd(_) => cam.vetkd_fee(subnet_size, cost_schedule),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn sign_with_threshold(
        &self,
        mut request: Request,
        args: ThresholdArguments,
        derivation_path: Vec<Vec<u8>>,
        max_queue_size: u32,
        state: &mut ReplicatedState,
        rng: &mut dyn RngCore,
        subnet_size: usize,
    ) -> Result<(), UserError> {
        if let ThresholdArguments::Schnorr(schnorr) = &args {
            let alg = schnorr.key_id.algorithm;
            match (alg, &schnorr.taproot_tree_root) {
                (SchnorrAlgorithm::Bip340Secp256k1, Some(aux)) => {
                    if !aux.is_empty() && aux.len() != 32 {
                        return Err(UserError::new(
                            ErrorCode::CanisterRejectedMessage,
                            format!("Invalid aux field for {alg}"),
                        ));
                    }
                }
                (_, None) => {}
                (_, Some(_)) => {
                    return Err(UserError::new(
                        ErrorCode::CanisterRejectedMessage,
                        format!("Schnorr algorithm {alg} does not support aux input"),
                    ));
                }
            }
        }

        let topology = &state.metadata.network_topology;
        // If the request isn't from the NNS, then we need to charge for it.
        let source_subnet = topology.route(request.sender.get());
        if source_subnet != Some(state.metadata.network_topology.nns_subnet_id) {
            let cost_schedule = state.get_own_cost_schedule();
            let signature_fee = self.calculate_signature_fee(&args, subnet_size, cost_schedule);
            if request.payment < signature_fee {
                return Err(UserError::new(
                    ErrorCode::CanisterRejectedMessage,
                    format!(
                        "{} request sent with {} cycles, but {} cycles are required.",
                        request.method_name, request.payment, signature_fee
                    ),
                ));
            } else {
                // Charge for the request.
                request.payment -= signature_fee;
                let nominal_fee = NominalCycles::from(signature_fee);
                let use_case = match args {
                    ThresholdArguments::Ecdsa(_) => {
                        state.metadata.subnet_metrics.consumed_cycles_ecdsa_outcalls += nominal_fee;
                        CyclesUseCase::ECDSAOutcalls
                    }
                    ThresholdArguments::Schnorr(_) => CyclesUseCase::SchnorrOutcalls,
                    ThresholdArguments::VetKd(_) => CyclesUseCase::VetKd,
                };
                state
                    .metadata
                    .subnet_metrics
                    .observe_consumed_cycles_with_use_case(use_case, nominal_fee);
            }
        }

        let threshold_key = args.key_id();

        // Check if the key is enabled.
        if !topology
            .chain_key_enabled_subnets(&threshold_key)
            .contains(&state.metadata.own_subnet_id)
        {
            return Err(UserError::new(
                ErrorCode::CanisterRejectedMessage,
                format!(
                    "{} request failed: unknown or disabled threshold key {}.",
                    request.method_name, threshold_key
                ),
            ));
        }

        // Check if the queue is full.
        if state
            .metadata
            .subnet_call_context_manager
            .sign_with_threshold_contexts_count(&threshold_key)
            >= max_queue_size as usize
        {
            return Err(UserError::new(
                ErrorCode::CanisterRejectedMessage,
                format!(
                    "{} request failed: request queue for key {} is full.",
                    request.method_name, threshold_key
                ),
            ));
        }

        let mut pseudo_random_id = [0u8; 32];
        rng.fill_bytes(&mut pseudo_random_id);

        state.metadata.subnet_call_context_manager.push_context(
            SubnetCallContext::SignWithThreshold(SignWithThresholdContext {
                request,
                args,
                derivation_path: Arc::new(derivation_path),
                pseudo_random_id,
                batch_time: state.metadata.batch_time,
                matched_pre_signature: None,
                nonce: None,
            }),
        );
        Ok(())
    }

    fn reshare_chain_key(
        &self,
        state: &mut ReplicatedState,
        rng: &mut dyn RngCore,
        chain_key_data: &ChainKeyData,
        request: &Request,
    ) -> Result<(), UserError> {
        let args = ReshareChainKeyArgs::decode(request.method_payload())?;
        let _key = get_master_public_key(
            &chain_key_data.master_public_keys,
            self.own_subnet_id,
            &args.key_id,
        )?;

        let mut target_id = [0u8; 32];
        rng.fill_bytes(&mut target_id);

        let nodes = args.get_set_of_nodes()?;
        let registry_version = args.get_registry_version();

        state.metadata.subnet_call_context_manager.push_context(
            SubnetCallContext::ReshareChainKey(ReshareChainKeyContext {
                request: request.clone(),
                key_id: args.key_id,
                nodes,
                registry_version,
                time: state.time(),
                target_id: NiDkgTargetId::new(target_id),
            }),
        );
        Ok(())
    }

    /// A helper function to make error handling more compact using `?`.
    fn decode_input_and_take_canister(
        msg: &CanisterCall,
        state: &mut ReplicatedState,
    ) -> Result<(InstallCodeContext, CanisterState), UserError> {
        let payload = msg.method_payload();
        let method = Ic00Method::from_str(msg.method_name()).map_err(|_| {
            UserError::new(
                ErrorCode::CanisterMethodNotFound,
                format!("Management canister has no method '{}'", msg.method_name()),
            )
        })?;
        let install_context = match method {
            Ic00Method::InstallCode => {
                let args = InstallCodeArgsV2::decode(payload)?;
                InstallCodeContext::try_from((
                    msg.canister_change_origin(args.get_sender_canister_version()),
                    args,
                ))?
            }
            Ic00Method::InstallChunkedCode => {
                let args = InstallChunkedCodeArgs::decode(payload)?;
                let origin = msg.canister_change_origin(args.get_sender_canister_version());

                let store_canister_id = args
                    .store_canister_id()
                    .unwrap_or(args.target_canister_id());

                let store_canister = &state
                        .canister_state(&store_canister_id)
                        .ok_or_else(|| {
                            UserError::new(
                                ErrorCode::CanisterNotFound,
                                format!("InstallChunkedCode Error: Store canister {} was not found on subnet {} of target canister {}", store_canister_id, state.metadata.own_subnet_id, args.target_canister_id()),
                            )
                        })?;
                // If the `store_canister` is different from the caller, we need
                // to verify that the caller is a controller of the store.
                if store_canister.canister_id().get() != origin.origin() {
                    validate_controller(store_canister, &origin.origin())?;
                }
                InstallCodeContext::chunked_install(
                    origin,
                    args,
                    &store_canister.system_state.wasm_chunk_store,
                )?
            }
            other => {
                return Err(UserError::new(
                    ErrorCode::UnknownManagementMessage,
                    format!("Expected an install code message, but found {other}"),
                ));
            }
        };

        let canister = state
            .take_canister_state(&install_context.canister_id)
            .ok_or(CanisterManagerError::CanisterNotFound(
                install_context.canister_id,
            ))?;
        Ok((install_context, canister))
    }

    /// Starts execution of the given `install_code` subnet message.
    /// With deterministic time slicing, the execution may be paused if it
    /// exceeds the given slice limit.
    ///
    /// Precondition:
    /// - The given message is an `install_code` message.
    /// - The canister does not have any paused execution in its task queue.
    /// - A call id will be present for an install code message to ensure that
    ///   potentially long-running messages are exposed to the subnet.
    ///   During a subnet split, the original subnet knows which
    ///   aborted install code message must be rejected if the targeted
    ///   canister has been moved to another subnet.
    ///
    /// Postcondition:
    /// - If the execution is finished, then it outputs the subnet response.
    /// - Otherwise, a new paused `install_code` execution is registered and
    ///   added to the task queue of the canister.
    pub fn execute_install_code(
        &self,
        mut msg: CanisterCall,
        call_id: Option<InstallCodeCallId>,
        prepaid_execution_cycles: Option<Cycles>,
        dts_status: DtsInstallCodeStatus,
        mut state: ReplicatedState,
        instruction_limits: InstructionLimits,
        round_limits: &mut RoundLimits,
        subnet_size: usize,
    ) -> (ReplicatedState, Option<NumInstructions>) {
        // Start logging execution time for `install_code`.
        let since = Instant::now();

        let (install_context, old_canister) =
            match Self::decode_input_and_take_canister(&msg, &mut state) {
                Ok(result) => result,
                Err(err) => {
                    let refund = msg.take_cycles();
                    return self.finish_subnet_message_execution(
                        state,
                        msg,
                        ExecuteSubnetMessageResult::Finished {
                            response: Err(err),
                            refund,
                            instructions: NumInstructions::from(0),
                        },
                        since,
                    );
                }
            };

        let call_id = match call_id {
            None => {
                // Call ID is not provided only if the current
                // DTS execution of install_code is the first execution.
                debug_assert_eq!(
                    dts_status,
                    DtsInstallCodeStatus::StartingFirstExecution,
                    "Dts status mismatch: expected StartingFirstExecution, got {dts_status}"
                );
                // Keep track of all existing long running install code messages.
                // During a subnet split, the requests are rejected if the target canister moved to a new subnet.
                state
                    .metadata
                    .subnet_call_context_manager
                    .push_install_code_call(InstallCodeCall {
                        call: msg.clone(),
                        time: state.time(),
                        effective_canister_id: install_context.canister_id,
                    })
            }
            Some(call_id) => call_id,
        };

        // Check the precondition.
        match old_canister.next_execution() {
            NextExecution::None | NextExecution::StartNew => {}
            NextExecution::ContinueLong | NextExecution::ContinueInstallCode => {
                panic!(
                    "Attempt to start a new `install_code` execution while the previous execution is still in progress."
                );
            }
        }

        let canister_id = old_canister.canister_id();
        let new_wasm_hash = (&install_context.wasm_source).into();
        let compilation_cost_handling = if state
            .metadata
            .expected_compiled_wasms
            .contains(&new_wasm_hash)
        {
            CompilationCostHandling::CountReducedAmount
        } else {
            CompilationCostHandling::CountFullAmount
        };
        info!(
            self.log,
            "Start executing install_code message on canister {:?}", canister_id,
        );

        let execution_parameters = self.execution_parameters(
            &old_canister,
            instruction_limits,
            ExecutionMode::Replicated,
            self.subnet_memory_saturation(&round_limits.subnet_available_memory),
        );
        let round_counters = RoundCounters {
            execution_refund_error: &self.metrics.execution_cycles_refund_error,
            state_changes_error: &self.metrics.state_changes_error,
            invalid_system_call_error: &self.metrics.invalid_system_call_error,
            charging_from_balance_error: &self.metrics.charging_from_balance_error,
            unexpected_response_error: &self.metrics.unexpected_response_error,
            response_cycles_refund_error: &self.metrics.response_cycles_refund_error,
            invalid_canister_state_error: &self.metrics.invalid_canister_state_error,
            ingress_with_cycles_error: &self.metrics.ingress_with_cycles_error,
        };

        let dts_result = self.canister_manager.install_code_dts(
            install_context,
            msg,
            call_id,
            prepaid_execution_cycles,
            old_canister,
            state.time(),
            "NOT_USED".into(),
            &state.metadata.network_topology,
            execution_parameters,
            round_limits,
            compilation_cost_handling,
            round_counters,
            subnet_size,
            state.get_own_cost_schedule(),
            self.config.dirty_page_logging,
        );
        self.process_install_code_result(state, dts_result, dts_status, since)
    }

    /// Processes the result of install code message that was executed using
    /// deterministic time slicing:
    /// - If the execution is finished, then it outputs the subnet response.
    /// - If the execution is paused, then it enqueues it to the task queue of
    ///   the canister.
    ///
    /// In both cases, the functions gets the canister from the result and adds
    /// it to the replicated state.
    fn process_install_code_result(
        &self,
        mut state: ReplicatedState,
        dts_result: DtsInstallCodeResult,
        dts_status: DtsInstallCodeStatus,
        since: Instant,
    ) -> (ReplicatedState, Option<NumInstructions>) {
        let execution_duration = since.elapsed().as_secs_f64();
        match dts_result {
            DtsInstallCodeResult::Finished {
                canister,
                mut message,
                call_id,
                instructions_used,
                result,
            } => {
                let canister_id = canister.canister_id();
                let result = match result {
                    Ok(result) => {
                        state.metadata.heap_delta_estimate += result.heap_delta;
                        if let Some(new_wasm_hash) = result.new_wasm_hash {
                            state
                                .metadata
                                .expected_compiled_wasms
                                .insert(WasmHash::from(new_wasm_hash));
                        }
                        info!(
                            self.log,
                            "Finished executing install_code message on canister {:?} after {:?}, old wasm hash {:?}, new wasm hash {:?}, instructions consumed: {}",
                            canister_id,
                            execution_duration,
                            result.old_wasm_hash,
                            result.new_wasm_hash,
                            instructions_used.display()
                        );

                        Ok((EmptyBlob.encode(), Some(canister_id)))
                    }
                    Err(err) => {
                        info!(
                            self.log,
                            "Finished executing install_code message on canister {:?} after {:?} with error: {:?}, instructions consumed {}",
                            canister_id,
                            execution_duration,
                            err,
                            instructions_used.display()
                        );
                        Err(err.into())
                    }
                };
                state.put_canister_state(canister);
                let refund = message.take_cycles();
                // The message can be removed because a response was produced.
                let install_code_call = state
                    .metadata
                    .subnet_call_context_manager
                    .remove_install_code_call(call_id);
                if install_code_call.is_none() {
                    self.metrics
                        .observe_call_id_without_install_code_call_error_counter(
                            &self.log,
                            call_id,
                            canister_id,
                        );
                }
                self.finish_subnet_message_execution(
                    state,
                    message,
                    ExecuteSubnetMessageResult::Finished {
                        response: result,
                        refund,
                        instructions: instructions_used,
                    },
                    since,
                )
            }
            DtsInstallCodeResult::Paused {
                mut canister,
                paused_execution,
                ingress_status,
            } => {
                let id = self.register_paused_install_code(paused_execution);
                canister
                    .system_state
                    .task_queue
                    .enqueue(ExecutionTask::PausedInstallCode(id));

                match (dts_status, ingress_status) {
                    (DtsInstallCodeStatus::StartingFirstExecution, Some((message_id, status))) => {
                        self.ingress_history_writer
                            .set_status(&mut state, message_id, status);
                    }
                    (DtsInstallCodeStatus::StartingFirstExecution, None) => {
                        // The original message is not an ingress message.
                    }
                    (DtsInstallCodeStatus::ResumingPausedOrAbortedExecution, _) => {
                        // Resuming a previously aborted execution does not
                        // update the ingress status.
                    }
                };

                state.put_canister_state(canister);
                (state, None)
            }
        }
    }

    /// Resumes a previously paused or aborted `install_code`.
    ///
    /// Precondition:
    /// - The first task in the task queue is paused or aborted `install_code`.
    ///
    /// Postcondition:
    /// - If the execution is finished, then it outputs the subnet response.
    /// - Otherwise, a new paused `install_code` execution is registered and
    ///   added to the task queue of the canister.
    pub fn resume_install_code(
        &self,
        mut state: ReplicatedState,
        canister_id: &CanisterId,
        instruction_limits: InstructionLimits,
        round_limits: &mut RoundLimits,
        subnet_size: usize,
    ) -> (ReplicatedState, Option<NumInstructions>) {
        let task = state
            .canister_state_mut(canister_id)
            .unwrap()
            .system_state
            .task_queue
            .pop_front()
            .unwrap();
        match task {
            ExecutionTask::Heartbeat
            | ExecutionTask::GlobalTimer
            | ExecutionTask::OnLowWasmMemory
            | ExecutionTask::PausedExecution { .. }
            | ExecutionTask::AbortedExecution { .. } => {
                panic!("Unexpected task {task:?} in `resume_install_code` (broken precondition).");
            }
            ExecutionTask::PausedInstallCode(id) => {
                let since = Instant::now();
                let paused = self.take_paused_install_code(id).unwrap();
                let canister = state.take_canister_state(canister_id).unwrap();
                let round_counters = RoundCounters {
                    execution_refund_error: &self.metrics.execution_cycles_refund_error,
                    state_changes_error: &self.metrics.state_changes_error,
                    invalid_system_call_error: &self.metrics.invalid_system_call_error,
                    charging_from_balance_error: &self.metrics.charging_from_balance_error,
                    unexpected_response_error: &self.metrics.unexpected_response_error,
                    response_cycles_refund_error: &self.metrics.response_cycles_refund_error,
                    invalid_canister_state_error: &self.metrics.invalid_canister_state_error,
                    ingress_with_cycles_error: &self.metrics.ingress_with_cycles_error,
                };
                let round = RoundContext {
                    network_topology: &state.metadata.network_topology,
                    hypervisor: &self.hypervisor,
                    cycles_account_manager: &self.cycles_account_manager,
                    counters: round_counters,
                    log: &self.log,
                    time: state.metadata.time(),
                    cost_schedule: state.get_own_cost_schedule(),
                };
                let dts_result = paused.resume(canister, round, round_limits);
                let dts_status = DtsInstallCodeStatus::ResumingPausedOrAbortedExecution;
                self.process_install_code_result(state, dts_result, dts_status, since)
            }
            ExecutionTask::AbortedInstallCode {
                message,
                call_id,
                prepaid_execution_cycles,
            } => self.execute_install_code(
                message,
                Some(call_id),
                Some(prepaid_execution_cycles),
                DtsInstallCodeStatus::ResumingPausedOrAbortedExecution,
                state,
                instruction_limits,
                round_limits,
                subnet_size,
            ),
        }
    }

    /// Returns the paused execution by its id.
    fn take_paused_execution(&self, id: PausedExecutionId) -> Option<Box<dyn PausedExecution>> {
        let mut guard = self.paused_execution_registry.lock().unwrap();
        guard.paused_execution.remove(&id)
    }

    /// Returns the paused `install_code` execution by its id.
    fn take_paused_install_code(
        &self,
        id: PausedExecutionId,
    ) -> Option<Box<dyn PausedInstallCodeExecution>> {
        let mut guard = self.paused_execution_registry.lock().unwrap();
        guard.paused_install_code.remove(&id)
    }

    fn abort_paused_execution_and_return_task(
        &self,
        paused_task: &ExecutionTask,
        log: &ReplicaLogger,
    ) -> ExecutionTask {
        match *paused_task {
            ExecutionTask::PausedExecution { id, .. } => {
                let paused = self.take_paused_execution(id).unwrap();
                let (input, prepaid_execution_cycles) = paused.abort(log);

                ExecutionTask::AbortedExecution {
                    input,
                    prepaid_execution_cycles,
                }
            }
            ExecutionTask::PausedInstallCode(id) => {
                let paused = self.take_paused_install_code(id).unwrap();
                let (message, call_id, prepaid_execution_cycles) = paused.abort(log);

                ExecutionTask::AbortedInstallCode {
                    message,
                    call_id,
                    prepaid_execution_cycles,
                }
            }
            ExecutionTask::AbortedExecution { .. }
            | ExecutionTask::AbortedInstallCode { .. }
            | ExecutionTask::Heartbeat
            | ExecutionTask::GlobalTimer
            | ExecutionTask::OnLowWasmMemory => {
                unreachable!(
                    "Function abort_paused_execution_and_return_task is only called after
                    the paused task is returned from TaskQueue, hence no task other than PausedExecution
                    and PausedInstallCode should appear in paused_task except if there is a bug."
                )
            }
        }
    }

    /// Registers the given paused execution and returns its id.
    fn register_paused_execution(&self, paused: Box<dyn PausedExecution>) -> PausedExecutionId {
        let mut guard = self.paused_execution_registry.lock().unwrap();
        let id = PausedExecutionId(guard.next_id);
        guard.next_id += 1;
        guard.paused_execution.insert(id, paused);
        id
    }

    /// Registers the given paused `install_code` execution and returns its id.
    fn register_paused_install_code(
        &self,
        paused: Box<dyn PausedInstallCodeExecution>,
    ) -> PausedExecutionId {
        let mut guard = self.paused_execution_registry.lock().unwrap();
        let id = PausedExecutionId(guard.next_id);
        guard.next_id += 1;
        guard.paused_install_code.insert(id, paused);
        id
    }

    /// Aborts paused execution in the given state.
    pub fn abort_canister(&self, canister: &mut CanisterState, log: &ReplicaLogger) {
        if !canister.system_state.task_queue.is_empty() {
            if let Some(paused_task) = canister.system_state.task_queue.get_paused_task() {
                self.metrics.executions_aborted.inc();
                // TODO: EXC-1730 if `PausedExecutionRegistry` becomes local we can abort
                // paused execution on the canister without requesting ID from TaskQueue.
                let aborted_task = self.abort_paused_execution_and_return_task(paused_task, log);

                canister
                    .system_state
                    .task_queue
                    .replace_paused_with_aborted_task(aborted_task);
            }
            let canister_id = canister.canister_id();
            canister.system_state.apply_ingress_induction_cycles_debit(
                canister_id,
                log,
                &self.metrics.charging_from_balance_error,
            );
        };
    }

    /// Aborts all paused execution in the given state.
    pub fn abort_all_paused_executions(&self, state: &mut ReplicatedState, log: &ReplicaLogger) {
        for canister in state.canisters_iter_mut() {
            self.abort_canister(canister, log);
        }
    }

    /// Aborts all paused executions known to the execution environment. This
    /// function is useful in the case when the replica abandons the old
    /// replicated state that has paused execution when it syncs to a more
    /// recent replicated state.
    pub fn abandon_paused_executions(&self) {
        let mut guard = self.paused_execution_registry.lock().unwrap();
        let paused_execution = std::mem::take(&mut guard.paused_execution);
        for p in paused_execution.into_values() {
            p.abort(&self.log);
        }
        let paused_install_code = std::mem::take(&mut guard.paused_install_code);
        for p in paused_install_code.into_values() {
            p.abort(&self.log);
        }
    }

    /// If the given result corresponds to a finished execution, then it processes
    /// the response and return the ingress status (if any). Otherwise, it registers
    /// the paused execution and adds it to the task queue.
    pub fn process_result(
        &self,
        result: ExecuteMessageResult,
    ) -> (
        CanisterState,
        Option<NumInstructions>,
        NumBytes,
        Option<(MessageId, IngressStatus)>,
    ) {
        match result {
            ExecuteMessageResult::Finished {
                mut canister,
                response,
                instructions_used,
                heap_delta,
                call_duration,
            } => {
                let ingress_status = match response {
                    ExecutionResponse::Ingress(ingress_status) => Some(ingress_status),
                    ExecutionResponse::Request(response) => {
                        debug_assert_eq!(
                            response.respondent,
                            canister.canister_id(),
                            "Respondent mismatch"
                        );
                        canister.push_output_response(response.into());
                        None
                    }
                    ExecutionResponse::Empty => None,
                };
                if let Some(duration) = call_duration {
                    self.metrics.call_durations.observe(duration.as_secs_f64());
                }

                (
                    canister,
                    Some(instructions_used),
                    heap_delta,
                    ingress_status,
                )
            }
            ExecuteMessageResult::Paused {
                mut canister,
                paused_execution,
                ingress_status,
            } => {
                let input = paused_execution.input();
                let id = self.register_paused_execution(paused_execution);
                canister
                    .system_state
                    .task_queue
                    .enqueue(ExecutionTask::PausedExecution { id, input });
                (canister, None, NumBytes::from(0), ingress_status)
            }
        }
    }

    /// Helper function to respond to a stop request based on the provided `StopCanisterReply`.
    fn reply_to_stop_context(
        &self,
        stop_context: &StopCanisterContext,
        state: &mut ReplicatedState,
        canister_id: CanisterId,
        time: Time,
        reply: StopCanisterReply,
    ) {
        let call_id = stop_context.call_id();
        self.remove_stop_canister_call(state, canister_id, *call_id);

        match stop_context {
            StopCanisterContext::Ingress {
                sender, message_id, ..
            } => {
                // Responding to stop_canister request from a user.
                let ingress_state = match reply {
                    StopCanisterReply::Completed => {
                        IngressState::Completed(WasmResult::Reply(EmptyBlob.encode()))
                    }
                    StopCanisterReply::Timeout => IngressState::Failed(UserError::new(
                        ErrorCode::StopCanisterRequestTimeout,
                        "Stop canister request timed out".to_string(),
                    )),
                };
                self.ingress_history_writer.set_status(
                    state,
                    message_id.clone(),
                    IngressStatus::Known {
                        receiver: IC_00.get(),
                        user_id: *sender,
                        time,
                        state: ingress_state,
                    },
                );
            }
            StopCanisterContext::Canister {
                sender,
                reply_callback,
                cycles,
                deadline,
                ..
            } => {
                // Responding to stop_canister request from a canister.
                let subnet_id_as_canister_id = CanisterId::from(self.own_subnet_id);
                let response_payload = match reply {
                    StopCanisterReply::Completed => Payload::Data(EmptyBlob.encode()),
                    StopCanisterReply::Timeout => Payload::Reject(RejectContext::new(
                        RejectCode::SysTransient,
                        "Stop canister request timed out",
                    )),
                };
                let response = ic_types::messages::Response {
                    originator: *sender,
                    respondent: subnet_id_as_canister_id,
                    originator_reply_callback: *reply_callback,
                    refund: *cycles,
                    response_payload,
                    deadline: *deadline,
                };
                state.push_subnet_output_response(response.into());
            }
        }
    }

    /// Helper function to remove stop canister calls
    /// from SubnetCallContextManager based on provided call id.
    fn remove_stop_canister_call(
        &self,
        state: &mut ReplicatedState,
        canister_id: CanisterId,
        call_id: Option<StopCanisterCallId>,
    ) {
        if let Some(call_id) = call_id {
            let stop_canister_call = state
                .metadata
                .subnet_call_context_manager
                .remove_stop_canister_call(call_id);

            match stop_canister_call {
                Some(stop_canister_call) => {
                    let call = stop_canister_call.call;
                    let time_elapsed = state
                        .time()
                        .saturating_duration_since(stop_canister_call.time);
                    if let CanisterCall::Request(request) = call {
                        self.metrics.observe_subnet_message(
                            &request.method_name,
                            time_elapsed.as_secs_f64(),
                            &Ok(()),
                        );
                    }
                }
                None => info!(
                    self.log,
                    "Could not remove stop_canister call for call ID {} and canister {}",
                    call_id,
                    canister_id,
                ),
            }
        }
    }

    /// Checks for stopping canisters and performs the following:
    ///   1. If there are stop contexts that have timed out, respond to them.
    ///   2. If any stopping canisters are ready to stop, transition them to
    ///      be fully stopped and reply to the corresponding stop contexts.
    ///
    /// Responses to the pending stop messages are written to ingress history
    /// or returned to the calling canisters respectively.
    pub fn process_stopping_canisters(&self, mut state: ReplicatedState) -> ReplicatedState {
        let mut canister_states = state.take_canister_states();
        let time = state.time();

        for canister in canister_states.values_mut() {
            let (stopped, stop_contexts) =
                canister.system_state.try_stop_canister(|stop_context| {
                    match stop_context.call_id() {
                        Some(call_id) => {
                            let sc_time = state
                                .metadata
                                .subnet_call_context_manager
                                .get_time_for_stop_canister_call(call_id);
                            match sc_time {
                                Some(t) => time >= t + self.config.stop_canister_timeout_duration,
                                // Should never hit this case unless there's a
                                // bug but handle it for robustness.
                                None => false,
                            }
                        }
                        // Should only happen for old stop requests that existed
                        // before call ids were added.
                        None => false,
                    }
                });
            if stopped {
                canister.system_state.canister_version += 1;
            }
            for stop_context in stop_contexts.iter() {
                self.reply_to_stop_context(
                    stop_context,
                    &mut state,
                    canister.canister_id(),
                    time,
                    if stopped {
                        StopCanisterReply::Completed
                    } else {
                        StopCanisterReply::Timeout
                    },
                );
            }
        }
        state.put_canister_states(canister_states);
        state
    }

    fn reject_unexpected_ingress(&self, method: Ic00Method) -> ExecuteSubnetMessageResult {
        self.metrics.unfiltered_ingress_error.inc();
        error!(
            self.log,
            "[EXC-BUG] Ingress messages to {} should've been filtered earlier.", method
        );
        ExecuteSubnetMessageResult::Finished {
            response: Err(UserError::new(
                ErrorCode::CanisterContractViolation,
                format!("{method} cannot be called by a user."),
            )),
            refund: Cycles::zero(),
            instructions: NumInstructions::from(0),
        }
    }

    // Returns the subnet memory saturation based on the given subnet available memory
    // which is assumed to be scaled with the scaling factor `self.scheduler_cores`.
    // Public for use in tests.
    #[doc(hidden)]
    pub fn subnet_memory_saturation(
        &self,
        subnet_available_memory: &SubnetAvailableMemory,
    ) -> ResourceSaturation {
        // We apply the scaling factor `self.scheduler_cores`
        // consistently with the scaling factor of `SubnetAvailableMemory`
        // in the function `self.scaled_subnet_available_memory`.
        let scaling_factor = self.scheduler_cores as u64;

        // Compute the scaled memory usage as the scaled capacity minus the scaled available memory.
        let scaled_subnet_memory_capacity: u64 =
            self.config.subnet_memory_capacity.get() / scaling_factor;
        let scaled_subnet_available_memory =
            subnet_available_memory.get_execution_memory().max(0) as u64;
        let scaled_subnet_memory_usage: u64 =
            scaled_subnet_memory_capacity.saturating_sub(scaled_subnet_available_memory);

        ResourceSaturation::new(
            scaled_subnet_memory_usage,
            self.config.subnet_memory_threshold.get() / scaling_factor,
            scaled_subnet_memory_capacity,
        )
    }

    /// Returns the default value of `wasm_memory_limit` in canister settings.
    pub fn default_wasm_memory_limit(&self) -> NumBytes {
        self.config.default_wasm_memory_limit
    }

    /// For testing purposes only.
    #[doc(hidden)]
    pub fn hypervisor_for_testing(&self) -> &Hypervisor {
        &self.hypervisor
    }

    #[doc(hidden)]
    pub fn clear_compilation_cache_for_testing(&self) {
        (*self.hypervisor).clear_compilation_cache_for_testing()
    }

    /// Used for tests where the test setup needs to be aware of the subnet
    /// type.
    #[doc(hidden)]
    pub fn own_subnet_type(&self) -> SubnetType {
        self.own_subnet_type
    }

    // Insert a compiled module in the compilation cache speed up tests by
    // skipping the Wasmtime compilation step.
    #[doc(hidden)]
    pub fn compilation_cache_insert_for_testing(
        &self,
        bytes: Vec<u8>,
        compiled_module: ic_embedders::SerializedModule,
    ) {
        self.hypervisor
            .compilation_cache_insert_for_testing(bytes, compiled_module);
    }
}

#[cfg(debug_assertions)]
impl Drop for ExecutionEnvironment {
    fn drop(&mut self) {
        // In tests, wait for all states to be dropped before continuing, to avoid any
        // race conditions. This is not an issue in the replica, as it never drops the
        // `ExecutionEnvironment`.
        self.deallocator_thread.flush_deallocation_channel();
    }
}

/// Indicates whether the full time spent compiling this canister or a reduced
/// amount should count against the round instruction limits. Reduced amounts
/// should be counted when the module was deserialized from a previous
/// compilation instead of fully compiled. Canisters should always be charged
/// for compilation costs even when they aren't counted against the round
/// limits. Only public for testing.
#[doc(hidden)]
#[derive(Copy, Clone, Debug)]
pub enum CompilationCostHandling {
    CountReducedAmount,
    CountFullAmount,
}

/// The expected speed up of deserializing a module compared to compiling it.
const DESERIALIZATION_SPEED_UP_FACTOR: u64 = 100;

impl CompilationCostHandling {
    /// Adjusts the compilation cost based on how it should be handled. Only public for use in tests.
    #[doc(hidden)]
    pub fn adjusted_compilation_cost(&self, compilation_cost: NumInstructions) -> NumInstructions {
        match self {
            CompilationCostHandling::CountReducedAmount => {
                compilation_cost / DESERIALIZATION_SPEED_UP_FACTOR
            }
            CompilationCostHandling::CountFullAmount => compilation_cost,
        }
    }
}

/// Returns the subnet's configured memory capacity (ignoring current usage).
pub(crate) fn full_subnet_memory_capacity(config: &ExecutionConfig) -> SubnetAvailableMemory {
    SubnetAvailableMemory::new_scaled(
        config.subnet_memory_capacity.get() as i64,
        config.guaranteed_response_message_memory_capacity.get() as i64,
        config.subnet_wasm_custom_sections_memory_capacity.get() as i64,
        1,
    )
}

fn get_canister(
    canister_id: CanisterId,
    state: &ReplicatedState,
) -> Result<&CanisterState, UserError> {
    match state.canister_state(&canister_id) {
        Some(canister) => Ok(canister),
        None => Err(UserError::new(
            ErrorCode::CanisterNotFound,
            format!("Canister {} not found.", &canister_id),
        )),
    }
}

fn get_canister_mut(
    canister_id: CanisterId,
    state: &mut ReplicatedState,
) -> Result<&mut CanisterState, UserError> {
    match state.canister_state_mut(&canister_id) {
        Some(canister) => Ok(canister),
        None => Err(UserError::new(
            ErrorCode::CanisterNotFound,
            format!("Canister {} not found.", &canister_id),
        )),
    }
}

/// The result of `execute_canister()`.
pub struct ExecuteCanisterResult {
    pub canister: CanisterState,
    pub instructions_used: Option<NumInstructions>,
    pub heap_delta: NumBytes,
    pub ingress_status: Option<(MessageId, IngressStatus)>,
    // The description of the executed task or message.
    pub description: Option<String>,
}

/// Executes the given input message or task.
/// This is a helper for `execute_canister()`.
fn execute_canister_input(
    input: CanisterMessageOrTask,
    prepaid_execution_cycles: Option<Cycles>,
    exec_env: &ExecutionEnvironment,
    canister: CanisterState,
    instruction_limits: InstructionLimits,
    max_instructions_per_message_without_dts: NumInstructions,
    network_topology: Arc<NetworkTopology>,
    time: Time,
    round_limits: &mut RoundLimits,
    subnet_size: usize,
    cost_schedule: CanisterCyclesCostSchedule,
) -> ExecuteCanisterResult {
    let info = input.to_string();
    let result = exec_env.execute_canister_input(
        canister,
        instruction_limits,
        max_instructions_per_message_without_dts,
        input,
        prepaid_execution_cycles,
        time,
        network_topology,
        round_limits,
        subnet_size,
        cost_schedule,
    );
    let (canister, instructions_used, heap_delta, ingress_status) = exec_env.process_result(result);
    ExecuteCanisterResult {
        canister,
        instructions_used,
        heap_delta,
        ingress_status,
        description: Some(info),
    }
}

/// Executes either a single task from the task queue of the canister or a
/// single input message if there is no task.
pub fn execute_canister(
    exec_env: &ExecutionEnvironment,
    mut canister: CanisterState,
    instruction_limits: InstructionLimits,
    max_instructions_per_message_without_dts: NumInstructions,
    network_topology: Arc<NetworkTopology>,
    time: Time,
    round_limits: &mut RoundLimits,
    subnet_size: usize,
    cost_schedule: CanisterCyclesCostSchedule,
) -> ExecuteCanisterResult {
    match canister.next_execution() {
        NextExecution::None | NextExecution::ContinueInstallCode => {
            return ExecuteCanisterResult {
                canister,
                instructions_used: None,
                heap_delta: NumBytes::from(0),
                ingress_status: None,
                description: None,
            };
        }
        NextExecution::StartNew | NextExecution::ContinueLong => {}
    }

    let (input, prepaid_execution_cycles) = match canister.system_state.task_queue.pop_front() {
        Some(task) => match task {
            ExecutionTask::PausedExecution { id, .. } => {
                let paused = exec_env.take_paused_execution(id).unwrap();
                let round_counters = RoundCounters {
                    execution_refund_error: &exec_env.metrics.execution_cycles_refund_error,
                    state_changes_error: &exec_env.metrics.state_changes_error,
                    invalid_system_call_error: &exec_env.metrics.invalid_system_call_error,
                    charging_from_balance_error: &exec_env.metrics.charging_from_balance_error,
                    unexpected_response_error: &exec_env.metrics.unexpected_response_error,
                    response_cycles_refund_error: &exec_env.metrics.response_cycles_refund_error,
                    invalid_canister_state_error: &exec_env.metrics.invalid_canister_state_error,
                    ingress_with_cycles_error: &exec_env.metrics.ingress_with_cycles_error,
                };
                let round_context = RoundContext {
                    network_topology: &network_topology,
                    hypervisor: &exec_env.hypervisor,
                    cycles_account_manager: &exec_env.cycles_account_manager,
                    counters: round_counters,
                    log: &exec_env.log,
                    time,
                    cost_schedule,
                };
                let result = paused.resume(
                    canister,
                    round_context,
                    round_limits,
                    subnet_size,
                    &exec_env.call_tree_metrics,
                    exec_env.deallocator_thread.sender(),
                );
                let (canister, instructions_used, heap_delta, ingress_status) =
                    exec_env.process_result(result);
                return ExecuteCanisterResult {
                    canister,
                    instructions_used,
                    heap_delta,
                    ingress_status,
                    description: Some("paused execution".to_string()),
                };
            }
            ExecutionTask::Heartbeat => {
                let task = CanisterMessageOrTask::Task(CanisterTask::Heartbeat);
                (task, None)
            }
            ExecutionTask::GlobalTimer => {
                let task = CanisterMessageOrTask::Task(CanisterTask::GlobalTimer);
                (task, None)
            }
            ExecutionTask::OnLowWasmMemory => {
                let task = CanisterMessageOrTask::Task(CanisterTask::OnLowWasmMemory);
                (task, None)
            }
            ExecutionTask::AbortedExecution {
                input,
                prepaid_execution_cycles,
            } => (input, Some(prepaid_execution_cycles)),
            ExecutionTask::PausedInstallCode(..) | ExecutionTask::AbortedInstallCode { .. } => {
                unreachable!("The guard at the beginning filters these cases out")
            }
        },
        None => {
            let message = canister.pop_input().unwrap();
            if let CanisterMessage::Request(req) = &message
                && req.payload_size_bytes() > MAX_INTER_CANISTER_PAYLOAD_IN_BYTES
            {
                exec_env.metrics.oversize_intra_subnet_messages.inc();
            }
            (CanisterMessageOrTask::Message(message), None)
        }
    };
    execute_canister_input(
        input,
        prepaid_execution_cycles,
        exec_env,
        canister,
        instruction_limits,
        max_instructions_per_message_without_dts,
        network_topology,
        time,
        round_limits,
        subnet_size,
        cost_schedule,
    )
}

fn get_master_public_key<'a>(
    chain_key_subnet_public_keys: &'a BTreeMap<MasterPublicKeyId, MasterPublicKey>,
    subnet_id: SubnetId,
    key_id: &MasterPublicKeyId,
) -> Result<&'a MasterPublicKey, UserError> {
    match chain_key_subnet_public_keys.get(key_id) {
        None => Err(UserError::new(
            ErrorCode::CanisterRejectedMessage,
            format!("Subnet {subnet_id} does not hold threshold key {key_id}."),
        )),
        Some(master_key) => Ok(master_key),
    }
}
