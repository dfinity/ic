use crate::{
    canister_manager::{
        CanisterManager, CanisterManagerError, CanisterMgrConfig, DtsInstallCodeResult,
        InstallCodeContext, PausedInstallCodeExecution, StopCanisterResult,
    },
    canister_settings::CanisterSettings,
    execution::{
        inspect_message,
        nonreplicated_query::execute_non_replicated_query,
        replicated_query::execute_replicated_query,
        response::execute_response,
        system_task::{execute_system_task, CanisterSystemTaskError},
        update::execute_update,
    },
    execution_environment_metrics::{
        ExecutionEnvironmentMetrics, SUBMITTED_OUTCOME_LABEL, SUCCESS_STATUS_LABEL,
    },
    hypervisor::Hypervisor,
    util::candid_error_to_user_error,
    NonReplicatedQueryKind,
};
use candid::Encode;
use ic_base_types::PrincipalId;
use ic_config::execution_environment::Config as ExecutionConfig;
use ic_config::flag_status::FlagStatus;
use ic_constants::{LOG_CANISTER_OPERATION_CYCLES_THRESHOLD, SMALL_APP_SUBNET_MAX_SIZE};
use ic_crypto_tecdsa::derive_tecdsa_public_key;
use ic_cycles_account_manager::{CyclesAccountManager, IngressInductionCost};
use ic_error_types::{ErrorCode, RejectCode, UserError};
use ic_ic00_types::{
    CanisterHttpRequestArgs, CanisterIdRecord, CanisterSettingsArgs,
    ComputeInitialEcdsaDealingsArgs, CreateCanisterArgs, ECDSAPublicKeyArgs,
    ECDSAPublicKeyResponse, EcdsaKeyId, EmptyBlob, InstallCodeArgs, Method as Ic00Method,
    Payload as Ic00Payload, ProvisionalCreateCanisterWithCyclesArgs, ProvisionalTopUpCanisterArgs,
    SetControllerArgs, SetupInitialDKGArgs, SignWithECDSAArgs, UpdateSettingsArgs, IC_00,
};
use ic_interfaces::{
    execution_environment::{
        ExecutionMode, IngressHistoryWriter, RegistryExecutionSettings, SubnetAvailableMemory,
    },
    messages::{CanisterInputMessage, RequestOrIngress},
};
use ic_logger::{error, info, warn, ReplicaLogger};
use ic_metrics::{MetricsRegistry, Timer};
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::canister_state::system_state::PausedExecutionId;
use ic_replicated_state::canister_state::NextExecution;
use ic_replicated_state::ExecutionTask;
use ic_replicated_state::{
    metadata_state::subnet_call_context_manager::{
        EcdsaDealingsContext, SetupInitialDkgContext, SignWithEcdsaContext,
    },
    CanisterState, NetworkTopology, ReplicatedState,
};
use ic_system_api::{ExecutionParameters, InstructionLimits};
use ic_types::{
    canister_http::CanisterHttpRequestContext,
    crypto::canister_threshold_sig::{ExtendedDerivationPath, MasterEcdsaPublicKey},
    crypto::threshold_sig::ni_dkg::NiDkgTargetId,
    ingress::{IngressState, IngressStatus, WasmResult},
    messages::{
        extract_effective_canister_id, AnonymousQuery, Payload, RejectContext, Request, Response,
        SignedIngressContent, StopCanisterContext,
    },
    CanisterId, CanisterTimer, Cycles, LongExecutionMode, NumBytes, NumInstructions, SubnetId,
    Time,
};
use ic_types::{messages::MessageId, methods::SystemMethod, methods::WasmMethod};
use ic_wasm_types::WasmHash;
use lazy_static::lazy_static;
use phantom_newtype::AmountOf;
use prometheus::IntCounter;
use rand::RngCore;
use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::{convert::Into, convert::TryFrom, sync::Arc};
use strum::ParseError;

#[cfg(test)]
mod tests;

lazy_static! {
    /// Track how many system task errors have been encountered
    /// so that we can restrict logging to a sample of them.
    static ref SYSTEM_TASK_ERROR_COUNT: AtomicU64 = AtomicU64::new(0);
}

/// How often system task errors should be logged to avoid overloading the logs.
const LOG_ONE_SYSTEM_TASK_OUT_OF: u64 = 100;
/// How many first system task messages to log unconditionally.
const LOG_FIRST_N_SYSTEM_TASKS: u64 = 50;

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
/// `ExecutionEnvironment.execute_canister_message()`.
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

/// Contains round-specific context necessary for resuming a paused execution.
#[derive(Clone)]
pub struct RoundContext<'a> {
    pub network_topology: &'a NetworkTopology,
    pub hypervisor: &'a Hypervisor,
    pub cycles_account_manager: &'a CyclesAccountManager,
    pub execution_refund_error_counter: &'a IntCounter,
    pub log: &'a ReplicaLogger,
    pub time: Time,
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
#[derive(Debug, Default)]
pub struct RoundLimits {
    /// Keeps track of remaining instructions in this execution round.
    pub instructions: RoundInstructions,

    /// Keeps track of the available storage memory. It decreases if
    /// - Wasm execution grows the Wasm/stable memory.
    /// - Wasm execution pushes a new request to the output queue.
    pub subnet_available_memory: SubnetAvailableMemory,

    // TODO would be nice to change that to available, but this requires
    // a lot of changes since available allocation sits in CanisterManager config
    pub compute_allocation_used: u64,
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
    ) -> ExecuteMessageResult;

    /// Aborts the paused execution.
    /// Returns the original message and the cycles prepaid for execution.
    fn abort(self: Box<Self>, log: &ReplicaLogger) -> (CanisterInputMessage, Cycles);
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

/// ExecutionEnvironment is the component responsible for executing messages
/// on the IC.
pub struct ExecutionEnvironment {
    log: ReplicaLogger,
    hypervisor: Arc<Hypervisor>,
    canister_manager: CanisterManager,
    ingress_history_writer: Arc<dyn IngressHistoryWriter<State = ReplicatedState>>,
    metrics: ExecutionEnvironmentMetrics,
    config: ExecutionConfig,
    cycles_account_manager: Arc<CyclesAccountManager>,
    own_subnet_id: SubnetId,
    own_subnet_type: SubnetType,
    paused_execution_registry: Arc<Mutex<PausedExecutionRegistry>>,
}

/// This is a helper enum that indicates whether the current DTS execution of
/// install_code is the first execution or not.
pub enum DtsInstallCodeStatus {
    StartingFirstExecution,
    ResumingPausedOrAbortedExecution,
}

impl ExecutionEnvironment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        log: ReplicaLogger,
        hypervisor: Arc<Hypervisor>,
        ingress_history_writer: Arc<dyn IngressHistoryWriter<State = ReplicatedState>>,
        metrics_registry: &MetricsRegistry,
        own_subnet_id: SubnetId,
        own_subnet_type: SubnetType,
        compute_capacity: usize,
        config: ExecutionConfig,
        cycles_account_manager: Arc<CyclesAccountManager>,
    ) -> Self {
        // Assert the flag implication: DTS => sandboxing.
        assert!(
            config.deterministic_time_slicing == FlagStatus::Disabled
                || config.canister_sandboxing_flag == FlagStatus::Enabled,
            "Deterministic time slicing works only with canister sandboxing."
        );
        let canister_manager_config: CanisterMgrConfig = CanisterMgrConfig::new(
            config.subnet_memory_capacity,
            config.default_provisional_cycles_balance,
            config.default_freeze_threshold,
            own_subnet_id,
            own_subnet_type,
            config.max_controllers,
            compute_capacity,
            config.rate_limiting_of_instructions,
            config.allocatable_compute_capacity_in_percent,
        );
        let canister_manager = CanisterManager::new(
            Arc::clone(&hypervisor),
            log.clone(),
            canister_manager_config,
            Arc::clone(&cycles_account_manager),
            Arc::clone(&ingress_history_writer),
        );
        Self {
            log,
            hypervisor,
            canister_manager,
            ingress_history_writer,
            metrics: ExecutionEnvironmentMetrics::new(metrics_registry),
            config,
            cycles_account_manager,
            own_subnet_id,
            own_subnet_type,
            paused_execution_registry: Default::default(),
        }
    }

    /// Look up the current amount of memory available on the subnet.
    pub fn subnet_available_memory(&self, state: &ReplicatedState) -> SubnetAvailableMemory {
        SubnetAvailableMemory::new(
            self.config.subnet_memory_capacity.get() as i64
                - state.total_memory_taken().get() as i64,
            self.config.subnet_message_memory_capacity.get() as i64
                - state.message_memory_taken().get() as i64,
        )
    }

    /// Executes a replicated message sent to a subnet.
    /// Returns the new replicated state and the number of left instructions.
    #[allow(clippy::cognitive_complexity)]
    #[allow(clippy::too_many_arguments)]
    pub fn execute_subnet_message(
        &self,
        msg: CanisterInputMessage,
        mut state: ReplicatedState,
        instruction_limits: InstructionLimits,
        rng: &mut dyn RngCore,
        ecdsa_subnet_public_keys: &BTreeMap<EcdsaKeyId, MasterEcdsaPublicKey>,
        registry_settings: &RegistryExecutionSettings,
        round_limits: &mut RoundLimits,
    ) -> (ReplicatedState, Option<NumInstructions>) {
        let timer = Timer::start(); // Start logging execution time.

        let mut msg = match msg {
            CanisterInputMessage::Response(response) => {
                let context = state
                    .metadata
                    .subnet_call_context_manager
                    .retrieve_context(response.originator_reply_callback, &self.log);
                return match context {
                    None => (state, Some(NumInstructions::from(0))),
                    Some(context) => {
                        let time_elapsed = state.time() - context.get_time();
                        let request = context.get_request();

                        self.metrics.observe_subnet_message(
                            &request.method_name,
                            time_elapsed.as_secs_f64(),
                            &match &response.response_payload {
                                Payload::Data(_) => Ok(()),
                                Payload::Reject(_) => Err(ErrorCode::CanisterRejectedMessage),
                            },
                        );

                        state.push_subnet_output_response(
                            Response {
                                originator: request.sender,
                                respondent: CanisterId::from(self.own_subnet_id),
                                originator_reply_callback: request.sender_reply_callback,
                                refund: request.payment,
                                response_payload: response.response_payload.clone(),
                            }
                            .into(),
                        );

                        (state, Some(NumInstructions::from(0)))
                    }
                };
            }

            CanisterInputMessage::Ingress(msg) => RequestOrIngress::Ingress(msg),
            CanisterInputMessage::Request(msg) => RequestOrIngress::Request(msg),
        };

        let method = Ic00Method::from_str(msg.method_name());
        let payload = msg.method_payload();
        let result = match method {
            Ok(Ic00Method::InstallCode) => {
                // Tail call is needed for deterministic time slicing here to
                // properly handle the case of a paused execution.
                return self.execute_install_code(
                    msg,
                    None,
                    DtsInstallCodeStatus::StartingFirstExecution,
                    state,
                    instruction_limits,
                    round_limits,
                    registry_settings.subnet_size,
                );
            }

            Ok(Ic00Method::SignWithECDSA) => match &msg {
                RequestOrIngress::Request(request) => {
                    let reject_message = if payload.is_empty() {
                        "An empty message cannot be signed".to_string()
                    } else {
                        String::new()
                    };

                    if !reject_message.is_empty() {
                        use ic_types::messages;
                        state.push_subnet_output_response(
                            Response {
                                originator: request.sender,
                                respondent: CanisterId::from(self.own_subnet_id),
                                originator_reply_callback: request.sender_reply_callback,
                                refund: request.payment,
                                response_payload: messages::Payload::Reject(
                                    messages::RejectContext {
                                        code: ic_error_types::RejectCode::CanisterReject,
                                        message: reject_message,
                                    },
                                ),
                            }
                            .into(),
                        );
                        return (state, Some(NumInstructions::from(0)));
                    }

                    match SignWithECDSAArgs::decode(payload) {
                        Err(err) => Some((Err(candid_error_to_user_error(err)), msg.take_cycles())),
                        Ok(args) => {
                            match get_master_ecdsa_public_key(
                                ecdsa_subnet_public_keys,
                                self.own_subnet_id,
                                &args.key_id,
                            ) {
                                Err(err) => Some((Err(err), msg.take_cycles())),
                                Ok(_) => self
                                    .sign_with_ecdsa(
                                        (**request).clone(),
                                        args.message_hash,
                                        args.derivation_path,
                                        args.key_id,
                                        registry_settings.max_ecdsa_queue_size,
                                        &mut state,
                                        rng,
                                        registry_settings.subnet_size,
                                    )
                                    .map_or_else(
                                        |err| Some((Err(err), msg.take_cycles())),
                                        |()| None,
                                    ),
                            }
                        }
                    }
                }
                RequestOrIngress::Ingress(_) => {
                    self.reject_unexpected_ingress(Ic00Method::SignWithECDSA)
                }
            },

            Ok(Ic00Method::CreateCanister) => {
                match &mut msg {
                    RequestOrIngress::Ingress(_) =>
                        Some((Err(UserError::new(
                            ErrorCode::CanisterMethodNotFound,
                            "create_canister can only be called by other canisters, not via ingress messages.")),
                            Cycles::zero(),
                        )),
                    RequestOrIngress::Request(req) => {
                        let cycles = Arc::make_mut(req).take_cycles();
                        match CreateCanisterArgs::decode(req.method_payload()) {
                            Err(err) => Some((Err(err), cycles)),
                            Ok(args) => {
                                // Start logging execution time for `create_canister`.
                                let timer = Timer::start();

                                let settings = match args.settings {
                                    None => CanisterSettingsArgs::default(),
                                    Some(settings) => settings,
                                };
                                let result = match CanisterSettings::try_from(settings) {
                                    Err(err) => Some((Err(err.into()), cycles)),
                                    Ok(settings) =>
                                        Some(self.create_canister(*msg.sender(), cycles, settings, registry_settings.max_number_of_canisters, &mut state, registry_settings.subnet_size, round_limits))
                                };
                                info!(
                                    self.log,
                                    "Finished executing create_canister message after {:?} with result: {:?}",
                                    timer.elapsed(),
                                    result
                                );

                                result
                            }
                        }
                    }
                }
            }

            Ok(Ic00Method::UninstallCode) => {
                let res = match CanisterIdRecord::decode(payload) {
                    Err(err) => Err(candid_error_to_user_error(err)),
                    Ok(args) => self
                        .canister_manager
                        .uninstall_code(args.get_canister_id(), *msg.sender(), &mut state)
                        .map(|()| EmptyBlob.encode())
                        .map_err(|err| err.into()),
                };
                Some((res, msg.take_cycles()))
            }

            Ok(Ic00Method::UpdateSettings) => {
                let res = match UpdateSettingsArgs::decode(payload) {
                    Err(err) => Err(candid_error_to_user_error(err)),
                    Ok(args) => {
                        // Start logging execution time for `update_settings`.
                        let timer = Timer::start();

                        let canister_id = args.get_canister_id();
                        let result = match CanisterSettings::try_from(args.settings) {
                            Err(err) => Err(err.into()),
                            Ok(settings) => self.update_settings(
                                *msg.sender(),
                                settings,
                                canister_id,
                                &mut state,
                                round_limits,
                            ),
                        };
                        // The induction cost of `UpdateSettings` is charged
                        // after applying the new settings to allow users to
                        // decrease the freezing threshold if it was set too
                        // high that topping up the canister is not feasible.
                        if let RequestOrIngress::Ingress(ingress) = &msg {
                            if let Ok(canister) = get_canister_mut(canister_id, &mut state) {
                                let bytes_to_charge =
                                    ingress.method_payload.len() + ingress.method_name.len();
                                let induction_cost = self
                                    .cycles_account_manager
                                    .ingress_induction_cost_from_bytes(
                                        NumBytes::from(bytes_to_charge as u64),
                                        registry_settings.subnet_size,
                                    );
                                let memory_usage = canister.memory_usage(self.own_subnet_type);
                                // This call may fail with `CanisterOutOfCyclesError`,
                                // which is not actionable at this point.
                                let _ignore_error = self.cycles_account_manager.consume_cycles(
                                    &mut canister.system_state,
                                    memory_usage,
                                    canister.scheduler_state.compute_allocation,
                                    induction_cost,
                                    registry_settings.subnet_size,
                                );
                            }
                        }
                        info!(
                            self.log,
                            "Finished executing update_settings message on canister {:?} after {:?} with result: {:?}",
                            canister_id,
                            timer.elapsed(),
                            result
                        );
                        result
                    }
                };
                Some((res, msg.take_cycles()))
            }

            Ok(Ic00Method::SetController) => {
                let res = match SetControllerArgs::decode(payload) {
                    Err(err) => Err(candid_error_to_user_error(err)),
                    Ok(args) => self
                        .canister_manager
                        .set_controller(
                            *msg.sender(),
                            args.get_canister_id(),
                            args.get_new_controller(),
                            &mut state,
                            round_limits,
                        )
                        .map(|()| EmptyBlob.encode())
                        .map_err(|err| err.into()),
                };
                Some((res, msg.take_cycles()))
            }

            Ok(Ic00Method::CanisterStatus) => {
                let res = match CanisterIdRecord::decode(payload) {
                    Err(err) => Err(candid_error_to_user_error(err)),
                    Ok(args) => self.get_canister_status(
                        *msg.sender(),
                        args.get_canister_id(),
                        &mut state,
                        registry_settings.subnet_size,
                    ),
                };
                Some((res, msg.take_cycles()))
            }

            Ok(Ic00Method::StartCanister) => {
                let res = match CanisterIdRecord::decode(payload) {
                    Err(err) => Err(candid_error_to_user_error(err)),
                    Ok(args) => {
                        self.start_canister(args.get_canister_id(), *msg.sender(), &mut state)
                    }
                };
                Some((res, msg.take_cycles()))
            }

            Ok(Ic00Method::StopCanister) => match CanisterIdRecord::decode(payload) {
                Err(err) => Some((Err(candid_error_to_user_error(err)), msg.take_cycles())),
                Ok(args) => self.stop_canister(args.get_canister_id(), &msg, &mut state),
            },

            Ok(Ic00Method::DeleteCanister) => {
                let res = match CanisterIdRecord::decode(payload) {
                    Err(err) => Err(candid_error_to_user_error(err)),
                    Ok(args) => {
                        // Start logging execution time for `delete_canister`.
                        let timer = Timer::start();

                        let result = self
                            .canister_manager
                            .delete_canister(*msg.sender(), args.get_canister_id(), &mut state)
                            .map(|()| EmptyBlob.encode())
                            .map_err(|err| err.into());

                        info!(
                            self.log,
                            "Finished executing delete_canister message on canister {:?} after {:?} with result: {:?}",
                            args.get_canister_id(),
                            timer.elapsed(),
                            result
                        );
                        result
                    }
                };
                Some((res, msg.take_cycles()))
            }

            Ok(Ic00Method::RawRand) => {
                let res = match EmptyBlob::decode(payload) {
                    Err(err) => Err(candid_error_to_user_error(err)),
                    Ok(EmptyBlob) => {
                        let mut buffer = vec![0u8; 32];
                        rng.fill_bytes(&mut buffer);
                        Ok(Encode!(&buffer).unwrap())
                    }
                };
                Some((res, msg.take_cycles()))
            }

            Ok(Ic00Method::DepositCycles) => match CanisterIdRecord::decode(payload) {
                Err(err) => Some((Err(candid_error_to_user_error(err)), msg.take_cycles())),
                Ok(args) => Some(self.deposit_cycles(args.get_canister_id(), &mut msg, &mut state)),
            },
            Ok(Ic00Method::HttpRequest) => match state.metadata.own_subnet_features.http_requests {
                true => match &msg {
                    RequestOrIngress::Request(request) => {
                        match CanisterHttpRequestArgs::decode(payload) {
                            Err(err) => {
                                Some((Err(candid_error_to_user_error(err)), msg.take_cycles()))
                            }
                            Ok(args) => match CanisterHttpRequestContext::try_from((
                                state.time(),
                                request.as_ref(),
                                args,
                            )) {
                                Err(err) => Some((Err(err.into()), msg.take_cycles())),
                                Ok(mut canister_http_request_context) => {
                                    let http_request_fee =
                                        self.cycles_account_manager.http_request_fee(
                                            canister_http_request_context.variable_parts_size(),
                                            canister_http_request_context.max_response_bytes,
                                            registry_settings.subnet_size,
                                        );
                                    if request.payment < http_request_fee {
                                        let err = Err(UserError::new(
                                            ErrorCode::CanisterRejectedMessage,
                                            format!(
                                                "http_request request sent with {} cycles, but {} cycles are required.",
                                                request.payment, http_request_fee
                                            ),
                                        ));
                                        Some((err, msg.take_cycles()))
                                    } else {
                                        canister_http_request_context.request.payment -=
                                            http_request_fee;
                                        state
                                            .metadata
                                            .subnet_call_context_manager
                                            .push_http_request(canister_http_request_context);
                                        self.metrics.observe_message_with_label(
                                            &request.method_name,
                                            timer.elapsed(),
                                            SUBMITTED_OUTCOME_LABEL.into(),
                                            SUCCESS_STATUS_LABEL.into(),
                                        );
                                        None
                                    }
                                }
                            },
                        }
                    }
                    RequestOrIngress::Ingress(_) => {
                        self.reject_unexpected_ingress(Ic00Method::HttpRequest)
                    }
                },
                false => {
                    let err = Err(UserError::new(
                        ErrorCode::CanisterContractViolation,
                        "This API is not enabled on this subnet".to_string(),
                    ));
                    Some((err, msg.take_cycles()))
                }
            },
            Ok(Ic00Method::SetupInitialDKG) => match &msg {
                RequestOrIngress::Request(request) => match SetupInitialDKGArgs::decode(payload) {
                    Err(err) => Some((Err(candid_error_to_user_error(err)), msg.take_cycles())),
                    Ok(args) => self
                        .setup_initial_dkg(*msg.sender(), &args, request, &mut state, rng)
                        .map_or_else(|err| Some((Err(err), msg.take_cycles())), |()| None),
                },
                RequestOrIngress::Ingress(_) => {
                    self.reject_unexpected_ingress(Ic00Method::SetupInitialDKG)
                }
            },

            Ok(Ic00Method::ECDSAPublicKey) => {
                let cycles = msg.take_cycles();
                match &msg {
                    RequestOrIngress::Request(request) => {
                        let res = match ECDSAPublicKeyArgs::decode(request.method_payload()) {
                            Err(err) => Some(Err(candid_error_to_user_error(err))),
                            Ok(args) => match get_master_ecdsa_public_key(
                                ecdsa_subnet_public_keys,
                                self.own_subnet_id,
                                &args.key_id,
                            ) {
                                Err(err) => Some(Err(err)),
                                Ok(pubkey) => {
                                    let canister_id = match args.canister_id {
                                        Some(id) => id.into(),
                                        None => *msg.sender(),
                                    };
                                    Some(
                                        self.get_ecdsa_public_key(
                                            pubkey,
                                            canister_id,
                                            args.derivation_path,
                                            &args.key_id,
                                        )
                                        .map(|res| res.encode()),
                                    )
                                }
                            },
                        };
                        res.map(|res| (res, cycles))
                    }
                    RequestOrIngress::Ingress(_) => {
                        self.reject_unexpected_ingress(Ic00Method::ECDSAPublicKey)
                    }
                }
            }

            Ok(Ic00Method::ComputeInitialEcdsaDealings) => {
                let cycles = msg.take_cycles();
                match &msg {
                    RequestOrIngress::Request(request) => {
                        let res =
                            match ComputeInitialEcdsaDealingsArgs::decode(request.method_payload())
                            {
                                Err(err) => Some(candid_error_to_user_error(err)),
                                Ok(args) => match get_master_ecdsa_public_key(
                                    ecdsa_subnet_public_keys,
                                    self.own_subnet_id,
                                    &args.key_id,
                                ) {
                                    Err(err) => Some(err),
                                    Ok(_) => self
                                        .compute_initial_ecdsa_dealings(
                                            &mut state,
                                            msg.sender(),
                                            args,
                                            request,
                                        )
                                        .map_or_else(Some, |()| None),
                                },
                            };
                        res.map(|err| (Err(err), cycles))
                    }
                    RequestOrIngress::Ingress(_) => {
                        self.reject_unexpected_ingress(Ic00Method::ComputeInitialEcdsaDealings)
                    }
                }
            }

            Ok(Ic00Method::ProvisionalCreateCanisterWithCycles) => {
                let res = match ProvisionalCreateCanisterWithCyclesArgs::decode(payload) {
                    Err(err) => Err(candid_error_to_user_error(err)),
                    Ok(args) => {
                        let cycles_amount = args.to_u128();
                        match CanisterSettings::try_from(args.settings) {
                            Ok(settings) => self
                                .canister_manager
                                .create_canister_with_cycles(
                                    *msg.sender(),
                                    cycles_amount,
                                    settings,
                                    &mut state,
                                    &registry_settings.provisional_whitelist,
                                    registry_settings.max_number_of_canisters,
                                    round_limits,
                                )
                                .map(|canister_id| CanisterIdRecord::from(canister_id).encode())
                                .map_err(|err| err.into()),
                            Err(err) => Err(err.into()),
                        }
                    }
                };
                Some((res, msg.take_cycles()))
            }

            Ok(Ic00Method::ProvisionalTopUpCanister) => {
                let res = match ProvisionalTopUpCanisterArgs::decode(payload) {
                    Err(err) => Err(candid_error_to_user_error(err)),
                    Ok(args) => self.add_cycles(
                        *msg.sender(),
                        args.get_canister_id(),
                        args.to_u128(),
                        &mut state,
                        &registry_settings.provisional_whitelist,
                    ),
                };
                Some((res, msg.take_cycles()))
            }

            Ok(Ic00Method::BitcoinGetBalance) => {
                let cycles = msg.take_cycles();
                let res = crate::bitcoin::get_balance(msg.method_payload(), &mut state, cycles);
                Some(res)
            }

            Ok(Ic00Method::BitcoinGetUtxos) => {
                let cycles = msg.take_cycles();
                let res = crate::bitcoin::get_utxos(msg.method_payload(), &mut state, cycles);
                Some(res)
            }

            Ok(Ic00Method::BitcoinGetCurrentFeePercentiles) => {
                let cycles = msg.take_cycles();
                let res = crate::bitcoin::get_current_fee_percentiles(
                    msg.method_payload(),
                    &mut state,
                    cycles,
                );
                Some(res)
            }

            Ok(Ic00Method::BitcoinSendTransaction) => {
                let cycles = msg.take_cycles();
                let res =
                    crate::bitcoin::send_transaction(msg.method_payload(), &mut state, cycles);

                Some(res)
            }

            Ok(Ic00Method::BitcoinSendTransactionInternal) => match &msg {
                RequestOrIngress::Request(request) => {
                    match crate::bitcoin::send_transaction_internal(
                        &self.config.bitcoin.privileged_access,
                        request,
                        &mut state,
                    ) {
                        Ok(Some(payload)) => Some(Ok(payload)),
                        Ok(None) => None,
                        Err(err) => Some(Err(err)),
                    }
                }
                RequestOrIngress::Ingress(_) => self
                    .reject_unexpected_ingress(Ic00Method::BitcoinGetSuccessors)
                    .map(|(payload, _)| payload),
            }
            .map(|payload| (payload, msg.take_cycles())),

            Ok(Ic00Method::BitcoinGetSuccessors) => match &msg {
                RequestOrIngress::Request(request) => {
                    match crate::bitcoin::get_successors(
                        &self.config.bitcoin.privileged_access,
                        request,
                        &mut state,
                    ) {
                        Ok(Some(payload)) => Some(Ok(payload)),
                        Ok(None) => None,
                        Err(err) => Some(Err(err)),
                    }
                }
                RequestOrIngress::Ingress(_) => self
                    .reject_unexpected_ingress(Ic00Method::BitcoinGetSuccessors)
                    .map(|(payload, _)| payload),
            }
            .map(|payload| (payload, msg.take_cycles())),

            Err(ParseError::VariantNotFound) => {
                let res = Err(UserError::new(
                    ErrorCode::CanisterMethodNotFound,
                    format!("Management canister has no method '{}'", msg.method_name()),
                ));
                Some((res, msg.take_cycles()))
            }
        };

        // Note that some branches above like `InstallCode` and `SignWithECDSA`
        // have early returns. If you modify code below, please also update
        // these cases.
        let state = match result {
            Some((res, refund)) => {
                self.finish_subnet_message_execution(state, msg, res, refund, timer)
            }
            None => {
                // This scenario happens when calling ic00::stop_canister on a
                // canister that is already stopping. In this scenario, the
                // request is not responded to until the canister has fully
                // stopped. At the moment, requests for these metrics are not
                // observed since it's not feasible with the current
                // architecture to time the request all the way until it is
                // responded to (which currently happens in the scheduler).
                //
                // This scenario also happens in the case of
                // Ic00Method::SetupInitialDKG, Ic00Method::HttpRequest, and
                // Ic00Method::SignWithECDSA. The request is saved and the
                // response from consensus is handled separately.
                state
            }
        };
        (state, Some(NumInstructions::from(0)))
    }

    /// Observes a subnet message metrics and outputs the given subnet response.
    fn finish_subnet_message_execution(
        &self,
        state: ReplicatedState,
        message: RequestOrIngress,
        response: Result<Vec<u8>, UserError>,
        refund: Cycles,
        timer: Timer,
    ) -> ReplicatedState {
        // Request has been executed. Observe metrics and respond.
        let method_name = String::from(message.method_name());
        self.metrics.observe_subnet_message(
            method_name.as_str(),
            timer.elapsed(),
            &response.as_ref().map_err(|err| err.code()),
        );
        self.output_subnet_response(message, state, response, refund)
    }

    /// Executes a replicated message sent to a canister.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_canister_message(
        &self,
        canister: CanisterState,
        instruction_limits: InstructionLimits,
        max_instructions_per_message_without_dts: NumInstructions,
        msg: CanisterInputMessage,
        prepaid_execution_cycles: Option<Cycles>,
        time: Time,
        network_topology: Arc<NetworkTopology>,
        round_limits: &mut RoundLimits,
        subnet_size: usize,
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

        let req = match msg {
            CanisterInputMessage::Response(response) => {
                return self.execute_canister_response(
                    canister,
                    response,
                    instruction_limits,
                    time,
                    network_topology,
                    round_limits,
                    subnet_size,
                )
            }

            CanisterInputMessage::Request(request) => RequestOrIngress::Request(request),
            CanisterInputMessage::Ingress(ingress) => RequestOrIngress::Ingress(ingress),
        };

        let round = RoundContext {
            network_topology: &*network_topology,
            hypervisor: &self.hypervisor,
            cycles_account_manager: &self.cycles_account_manager,
            execution_refund_error_counter: self.metrics.execution_cycles_refund_error_counter(),
            log: &self.log,
            time,
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
                // A query call is expected to finish quickly, so DTS is not supported for it.
                let instruction_limits = InstructionLimits::new(
                    FlagStatus::Disabled,
                    max_instructions_per_message_without_dts,
                    max_instructions_per_message_without_dts,
                );
                let execution_parameters = self.execution_parameters(
                    &canister,
                    instruction_limits,
                    ExecutionMode::Replicated,
                );
                execute_replicated_query(
                    canister,
                    req,
                    method,
                    execution_parameters,
                    time,
                    round,
                    round_limits,
                    subnet_size,
                )
            }
            WasmMethod::Update(_) => {
                let execution_parameters = self.execution_parameters(
                    &canister,
                    instruction_limits,
                    ExecutionMode::Replicated,
                );
                execute_update(
                    canister,
                    req,
                    method,
                    prepaid_execution_cycles,
                    execution_parameters,
                    time,
                    round,
                    round_limits,
                    subnet_size,
                )
            }
            WasmMethod::System(_) => {
                unreachable!("Unreachable based on the previous statement");
            }
        }
    }

    /// Executes a system task of a given canister.
    pub fn execute_canister_system_task(
        &self,
        canister: CanisterState,
        system_task: SystemMethod,
        instruction_limits: InstructionLimits,
        network_topology: Arc<NetworkTopology>,
        time: Time,
        round_limits: &mut RoundLimits,
        subnet_size: usize,
        log: &ReplicaLogger,
    ) -> (
        CanisterState,
        NumInstructions,
        Result<NumBytes, CanisterSystemTaskError>,
    ) {
        let execution_parameters =
            self.execution_parameters(&canister, instruction_limits, ExecutionMode::Replicated);
        let (canister, instructions_used, result) = execute_system_task(
            canister,
            system_task.clone(),
            network_topology,
            execution_parameters,
            self.own_subnet_type,
            time,
            &self.hypervisor,
            &self.cycles_account_manager,
            round_limits,
            self.metrics.execution_cycles_refund_error_counter(),
            subnet_size,
            log,
        )
        .into_parts();
        if let Err(err) = &result {
            // We should monitor all errors in the system subnets and only
            // system errors on other subnets.
            if self.hypervisor.subnet_type() == SubnetType::System || err.is_system_error() {
                // We could improve the rate limiting using some kind of exponential backoff.
                let log_count = SYSTEM_TASK_ERROR_COUNT.fetch_add(1, Ordering::SeqCst);
                if log_count < LOG_FIRST_N_SYSTEM_TASKS
                    || log_count % LOG_ONE_SYSTEM_TASK_OUT_OF == 0
                {
                    warn!(
                        self.log,
                        "Error executing system task {} on canister {} with failure `{}`",
                        system_task,
                        canister.canister_id(),
                        err;
                        messaging.canister_id => canister.canister_id().to_string(),
                    );
                }
            }
        }
        (canister, instructions_used, result)
    }

    /// Returns the maximum amount of memory that can be utilized by a single
    /// canister.
    pub fn max_canister_memory_size(&self) -> NumBytes {
        self.config.max_canister_memory_size
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
    ) -> ExecutionParameters {
        ExecutionParameters {
            instruction_limits,
            canister_memory_limit: canister.memory_limit(self.config.max_canister_memory_size),
            compute_allocation: canister.scheduler_state.compute_allocation,
            subnet_type: self.own_subnet_type,
            execution_mode,
        }
    }

    fn create_canister(
        &self,
        sender: PrincipalId,
        cycles: Cycles,
        settings: CanisterSettings,
        max_number_of_canisters: u64,
        state: &mut ReplicatedState,
        subnet_size: usize,
        round_limits: &mut RoundLimits,
    ) -> (Result<Vec<u8>, UserError>, Cycles) {
        match state.find_subnet_id(sender) {
            Ok(sender_subnet_id) => {
                let (res, cycles) = self.canister_manager.create_canister(
                    sender,
                    sender_subnet_id,
                    cycles,
                    settings,
                    max_number_of_canisters,
                    state,
                    subnet_size,
                    round_limits,
                );
                (
                    res.map(|new_canister_id| CanisterIdRecord::from(new_canister_id).encode())
                        .map_err(|err| err.into()),
                    cycles,
                )
            }
            Err(err) => (Err(err), cycles),
        }
    }

    fn update_settings(
        &self,
        sender: PrincipalId,
        settings: CanisterSettings,
        canister_id: CanisterId,
        state: &mut ReplicatedState,
        round_limits: &mut RoundLimits,
    ) -> Result<Vec<u8>, UserError> {
        let canister = get_canister_mut(canister_id, state)?;
        self.canister_manager
            .update_settings(sender, settings, canister, round_limits)
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
        msg: &mut RequestOrIngress,
        state: &mut ReplicatedState,
    ) -> (Result<Vec<u8>, UserError>, Cycles) {
        match state.canister_state_mut(&canister_id) {
            None => (
                Err(UserError::new(
                    ErrorCode::CanisterNotFound,
                    format!("Canister {} not found.", &canister_id),
                )),
                msg.take_cycles(),
            ),

            Some(canister_state) => {
                let cycles = msg.take_cycles();
                self.cycles_account_manager
                    .add_cycles(canister_state.system_state.balance_mut(), cycles);
                if cycles.get() > LOG_CANISTER_OPERATION_CYCLES_THRESHOLD {
                    info!(
                        self.log,
                        "Canister {} deposited {} cycles to canister {}.",
                        msg.sender(),
                        cycles,
                        canister_id.get(),
                    );
                }
                (Ok(EmptyBlob.encode()), Cycles::zero())
            }
        }
    }

    fn get_canister_status(
        &self,
        sender: PrincipalId,
        canister_id: CanisterId,
        state: &mut ReplicatedState,
        subnet_size: usize,
    ) -> Result<Vec<u8>, UserError> {
        let canister = get_canister_mut(canister_id, state)?;

        self.canister_manager
            .get_canister_status(sender, canister, subnet_size)
            .map(|status| status.encode())
            .map_err(|err| err.into())
    }

    fn stop_canister(
        &self,
        canister_id: CanisterId,
        msg: &RequestOrIngress,
        state: &mut ReplicatedState,
    ) -> Option<(Result<Vec<u8>, UserError>, Cycles)> {
        match self.canister_manager.stop_canister(
            canister_id,
            StopCanisterContext::from(msg.clone()),
            state,
        ) {
            StopCanisterResult::RequestAccepted => None,
            StopCanisterResult::Failure {
                error,
                cycles_to_return,
            } => Some((Err(error.into()), cycles_to_return)),
            StopCanisterResult::AlreadyStopped { cycles_to_return } => {
                Some((Ok(EmptyBlob.encode()), cycles_to_return))
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
    ) -> ExecuteMessageResult {
        let execution_parameters =
            self.execution_parameters(&canister, instruction_limits, ExecutionMode::Replicated);
        let round = RoundContext {
            network_topology: &*network_topology,
            hypervisor: &self.hypervisor,
            cycles_account_manager: &self.cycles_account_manager,
            execution_refund_error_counter: self.metrics.execution_cycles_refund_error_counter(),
            log: &self.log,
            time,
        };
        execute_response(
            canister,
            response,
            time,
            execution_parameters,
            self.metrics.response_cycles_refund_error_counter(),
            round,
            round_limits,
            subnet_size,
        )
    }

    /// Asks the canister if it is willing to accept the provided ingress
    /// message.
    pub fn should_accept_ingress_message(
        &self,
        state: Arc<ReplicatedState>,
        provisional_whitelist: &ProvisionalWhitelist,
        ingress: &SignedIngressContent,
        execution_mode: ExecutionMode,
    ) -> Result<(), UserError> {
        let canister = |canister_id: CanisterId| -> Result<&CanisterState, UserError> {
            match state.canister_state(&canister_id) {
                Some(canister) => Ok(canister),
                None => Err(UserError::new(
                    ErrorCode::CanisterNotFound,
                    format!("Canister {} not found", canister_id),
                )),
            }
        };
        let effective_canister_id =
            extract_effective_canister_id(ingress, state.metadata.own_subnet_id)
                .map_err(|err| err.into_user_error(ingress.method_name()))?;

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
            );

            if let IngressInductionCost::Fee { payer, cost } = induction_cost {
                let paying_canister = canister(payer)?;
                if let Err(err) = self.cycles_account_manager.can_withdraw_cycles(
                    &paying_canister.system_state,
                    cost,
                    paying_canister.memory_usage(self.own_subnet_type),
                    paying_canister.scheduler_state.compute_allocation,
                    subnet_size,
                ) {
                    return Err(UserError::new(
                        ErrorCode::CanisterOutOfCycles,
                        err.to_string(),
                    ));
                }
            }
        }

        if ingress.is_addressed_to_subnet(self.own_subnet_id) {
            return self.canister_manager.should_accept_ingress_message(
                state,
                provisional_whitelist,
                ingress,
                effective_canister_id,
            );
        }

        let canister_state = canister(ingress.canister_id())?;

        // An inspect message is expected to finish quickly, so DTS is not
        // supported for it.
        let instruction_limits = InstructionLimits::new(
            FlagStatus::Disabled,
            self.config.max_instructions_for_message_acceptance_calls,
            self.config.max_instructions_for_message_acceptance_calls,
        );
        let execution_parameters =
            self.execution_parameters(canister_state, instruction_limits, execution_mode);

        // Letting the canister grow arbitrarily when executing the
        // query is fine as we do not persist state modifications.
        let subnet_available_memory = subnet_memory_capacity(&self.config);

        inspect_message::execute_inspect_message(
            state.time(),
            canister_state.clone(),
            ingress,
            self.own_subnet_type,
            execution_parameters,
            subnet_available_memory,
            &self.hypervisor,
            &state.metadata.network_topology,
            &self.log,
        )
        .1
    }

    /// Execute a query call that has no caller provided.
    /// This type of query is triggered by the IC only when
    /// there is a need to execute a query call on the provided canister.
    pub fn execute_anonymous_query(
        &self,
        anonymous_query: AnonymousQuery,
        state: Arc<ReplicatedState>,
        max_instructions_per_query: NumInstructions,
    ) -> Result<WasmResult, UserError> {
        let canister_id = anonymous_query.receiver;
        let canister = state.get_active_canister(&canister_id)?;
        // An anonymous query is expected to finish quickly, so DTS is not
        // supported for it.
        let instruction_limits = InstructionLimits::new(
            FlagStatus::Disabled,
            max_instructions_per_query,
            max_instructions_per_query,
        );
        let execution_parameters =
            self.execution_parameters(&canister, instruction_limits, ExecutionMode::NonReplicated);
        let subnet_available_memory = subnet_memory_capacity(&self.config);
        let mut round_limits = RoundLimits {
            instructions: as_round_instructions(max_instructions_per_query),
            subnet_available_memory,
            // Ignore compute allocation
            compute_allocation_used: 0,
        };
        let result = execute_non_replicated_query(
            NonReplicatedQueryKind::Pure {
                caller: IC_00.get(),
            },
            WasmMethod::Query(anonymous_query.method_name.to_string()),
            &anonymous_query.method_payload,
            canister,
            None,
            state.time(),
            execution_parameters,
            &state.metadata.network_topology,
            &self.hypervisor,
            &mut round_limits,
        )
        .2;

        match result {
            Ok(maybe_wasm_result) => match maybe_wasm_result {
                Some(wasm_result) => Ok(wasm_result),
                None => Err(UserError::new(
                    ErrorCode::CanisterDidNotReply,
                    format!("Canister {} did not reply to the call", canister_id),
                )),
            },
            Err(err) => Err(err),
        }
    }

    // Output the response of a subnet message depending on its type.
    //
    // Canister requests are responded to by adding a response to the subnet's
    // output queue. Ingress requests are responded to by writing to ingress
    // history.
    fn output_subnet_response(
        &self,
        msg: RequestOrIngress,
        mut state: ReplicatedState,
        result: Result<Vec<u8>, UserError>,
        refund: Cycles,
    ) -> ReplicatedState {
        match msg {
            RequestOrIngress::Request(req) => {
                let payload = match result {
                    Ok(payload) => Payload::Data(payload),
                    Err(err) => Payload::Reject(err.into()),
                };

                let subnet_id_as_canister_id = CanisterId::from(self.own_subnet_id);
                let response = Response {
                    originator: req.sender,
                    respondent: subnet_id_as_canister_id,
                    originator_reply_callback: req.sender_reply_callback,
                    refund,
                    response_payload: payload,
                };

                state.push_subnet_output_response(response.into());
                state
            }
            RequestOrIngress::Ingress(ingress) => {
                if !refund.is_zero() {
                    warn!(
                        self.log,
                        "[EXC-BUG] No funds can be included with an ingress message: user {}, canister_id {}, message_id {}.",
                        ingress.source, ingress.receiver, ingress.message_id
                    );
                }
                let status = match result {
                    Ok(payload) => IngressStatus::Known {
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
                StopCanisterContext::Ingress { sender, message_id } => {
                    let time = state.time();
                    // Rejecting a stop_canister request from a user.
                    self.ingress_history_writer.set_status(
                        state,
                        message_id,
                        IngressStatus::Known {
                            receiver: IC_00.get(),
                            user_id: sender,
                            time,
                            state: IngressState::Failed(UserError::new(
                                ErrorCode::CanisterStoppingCancelled,
                                format!("Canister {}'s stop request was cancelled.", canister_id),
                            )),
                        },
                    );
                }
                StopCanisterContext::Canister {
                    sender,
                    reply_callback,
                    cycles,
                } => {
                    // Rejecting a stop_canister request from a canister.
                    let subnet_id_as_canister_id = CanisterId::from(self.own_subnet_id);
                    let response = Response {
                        originator: sender,
                        respondent: subnet_id_as_canister_id,
                        originator_reply_callback: reply_callback,
                        refund: cycles,
                        response_payload: Payload::Reject(RejectContext {
                            code: RejectCode::CanisterReject,
                            message: format!("Canister {}'s stop request cancelled", canister_id),
                        }),
                    };
                    state.push_subnet_output_response(response.into());
                }
            }
        }
    }

    fn setup_initial_dkg(
        &self,
        sender: PrincipalId,
        settings: &SetupInitialDKGArgs,
        request: &Request,
        state: &mut ReplicatedState,
        rng: &mut dyn RngCore,
    ) -> Result<(), UserError> {
        let sender_subnet_id = state.find_subnet_id(sender)?;

        if sender_subnet_id != state.metadata.network_topology.nns_subnet_id {
            return Err(UserError::new(
                ErrorCode::CanisterContractViolation,
                format!(
                    "{} is called by {}. It can only be called by NNS.",
                    Ic00Method::SetupInitialDKG,
                    sender,
                ),
            ));
        }
        match settings.get_set_of_node_ids() {
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
                state
                    .metadata
                    .subnet_call_context_manager
                    .push_setup_initial_dkg_request(SetupInitialDkgContext {
                        request: request.clone(),
                        nodes_in_target_subnet,
                        target_id: NiDkgTargetId::new(target_id),
                        registry_version: settings.get_registry_version(),
                        time: state.time(),
                    });
                Ok(())
            }
        }
    }

    fn get_ecdsa_public_key(
        &self,
        subnet_public_key: &MasterEcdsaPublicKey,
        principal_id: PrincipalId,
        derivation_path: Vec<Vec<u8>>,
        // TODO EXC-1060: get the right public key.
        _key_id: &EcdsaKeyId,
    ) -> Result<ECDSAPublicKeyResponse, UserError> {
        let _ = CanisterId::new(principal_id).map_err(|err| {
            UserError::new(
                ErrorCode::CanisterContractViolation,
                format!("Not a canister id: {}", err),
            )
        })?;
        let path = ExtendedDerivationPath {
            caller: principal_id,
            derivation_path,
        };
        derive_tecdsa_public_key(subnet_public_key, &path)
            .map_err(|err| UserError::new(ErrorCode::CanisterRejectedMessage, format!("{}", err)))
            .map(|res| ECDSAPublicKeyResponse {
                public_key: res.public_key,
                chain_code: res.chain_key,
            })
    }

    #[allow(clippy::too_many_arguments)]
    fn sign_with_ecdsa(
        &self,
        mut request: Request,
        message_hash: [u8; 32],
        derivation_path: Vec<Vec<u8>>,
        key_id: EcdsaKeyId,
        max_queue_size: u32,
        state: &mut ReplicatedState,
        rng: &mut dyn RngCore,
        subnet_size: usize,
    ) -> Result<(), UserError> {
        // We already ensured message_hash is 32 byte statically, so there is
        // no need to check length here.

        // If the request isn't from the NNS, then we need to charge for it.
        // Consensus will return any remaining cycles.
        let source_subnet = state
            .metadata
            .network_topology
            .routing_table
            .route(request.sender.get());
        if source_subnet != Some(state.metadata.network_topology.nns_subnet_id) {
            let signature_fee = self.cycles_account_manager.ecdsa_signature_fee(subnet_size);
            if request.payment < signature_fee {
                return Err(UserError::new(
                    ErrorCode::CanisterRejectedMessage,
                    format!(
                        "sign_with_ecdsa request sent with {} cycles, but {} cycles are required.",
                        request.payment, signature_fee
                    ),
                ));
            } else {
                request.payment -= signature_fee;
            }
        }

        let mut pseudo_random_id = [0u8; 32];
        rng.fill_bytes(&mut pseudo_random_id);

        info!(
            self.log,
            "Assigned the pseudo_random_id {:?} to the new sign_with_ECDSA request from {:?}",
            pseudo_random_id,
            request.sender()
        );
        state
            .metadata
            .subnet_call_context_manager
            .push_sign_with_ecdsa_request(
                SignWithEcdsaContext {
                    request,
                    key_id,
                    message_hash,
                    derivation_path,
                    pseudo_random_id,
                    batch_time: state.metadata.batch_time,
                },
                max_queue_size,
            )?;
        Ok(())
    }

    fn compute_initial_ecdsa_dealings(
        &self,
        state: &mut ReplicatedState,
        sender: &PrincipalId,
        args: ComputeInitialEcdsaDealingsArgs,
        request: &Request,
    ) -> Result<(), UserError> {
        let sender_subnet_id = state.find_subnet_id(*sender)?;

        if sender_subnet_id != state.metadata.network_topology.nns_subnet_id {
            return Err(UserError::new(
                ErrorCode::CanisterContractViolation,
                format!(
                    "{} is called by {}. It can only be called by NNS.",
                    Ic00Method::ComputeInitialEcdsaDealings,
                    sender,
                ),
            ));
        }
        let nodes = args.get_set_of_nodes()?;
        let registry_version = args.get_registry_version();
        state
            .metadata
            .subnet_call_context_manager
            .push_ecdsa_dealings_request(EcdsaDealingsContext {
                request: request.clone(),
                key_id: args.key_id,
                nodes,
                registry_version,
                time: state.time(),
            });
        Ok(())
    }

    /// Starts execution of the given `install_code` subnet message.
    /// With deterministic time slicing, the execution may be paused if it
    /// exceeds the given slice limit.
    ///
    /// Precondition:
    /// - The given message is an `install_code` message.
    /// - The canister does not have any paused execution in its task queue.
    ///
    /// Postcondition:
    /// - If the execution is finished, then it outputs the subnet response.
    /// - Otherwise, a new paused `install_code` execution is registered and
    ///   added to the task queue of the canister.
    pub fn execute_install_code(
        &self,
        mut msg: RequestOrIngress,
        prepaid_execution_cycles: Option<Cycles>,
        dts_status: DtsInstallCodeStatus,
        mut state: ReplicatedState,
        instruction_limits: InstructionLimits,
        round_limits: &mut RoundLimits,
        subnet_size: usize,
    ) -> (ReplicatedState, Option<NumInstructions>) {
        // A helper function to make error handling more compact using `?`.
        fn decode_input_and_take_canister(
            msg: &RequestOrIngress,
            state: &mut ReplicatedState,
        ) -> Result<(InstallCodeContext, CanisterState), UserError> {
            let payload = msg.method_payload();
            let args = InstallCodeArgs::decode(payload).map_err(candid_error_to_user_error)?;
            let install_context = InstallCodeContext::try_from((*msg.sender(), args))?;
            let canister = state
                .take_canister_state(&install_context.canister_id)
                .ok_or(CanisterManagerError::CanisterNotFound(
                    install_context.canister_id,
                ))?;
            Ok((install_context, canister))
        }

        // Start logging execution time for `install_code`.
        let timer = Timer::start();

        let (install_context, old_canister) = match decode_input_and_take_canister(&msg, &mut state)
        {
            Ok(result) => result,
            Err(err) => {
                let refund = msg.take_cycles();
                let state =
                    self.finish_subnet_message_execution(state, msg, Err(err), refund, timer);
                return (state, Some(NumInstructions::from(0)));
            }
        };

        // Check the precondition.
        match old_canister.next_execution() {
            NextExecution::None | NextExecution::StartNew => {}
            NextExecution::ContinueLong | NextExecution::ContinueInstallCode => {
                panic!("Attempt to start a new `install_code` execution while the previous execution is still in progress.");
            }
        }

        let canister_id = old_canister.canister_id();
        let new_wasm_hash = WasmHash::from(&install_context.wasm_module);
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
            "Start executing install_code message on canister {:?}, contains module {:?}",
            canister_id,
            install_context.wasm_module.is_empty().to_string(),
        );

        let execution_parameters =
            self.execution_parameters(&old_canister, instruction_limits, ExecutionMode::Replicated);

        let dts_result = self.canister_manager.install_code_dts(
            install_context,
            msg,
            prepaid_execution_cycles,
            old_canister,
            state.time(),
            "NOT_USED".into(),
            &state.metadata.network_topology,
            execution_parameters,
            round_limits,
            compilation_cost_handling,
            self.metrics.execution_cycles_refund_error_counter(),
            subnet_size,
        );
        self.process_install_code_result(state, dts_result, dts_status, timer)
    }

    /// Processes the result of install code message that was executed using
    /// deterministic time slicing:
    /// - If the execution is finished, then it outputs the subnet response.
    /// - If the execution is paused, then it enqueues it to the task queue of
    ///   the canister.
    /// In both cases, the functions gets the canister from the result and adds
    /// it to the replicated state.
    fn process_install_code_result(
        &self,
        mut state: ReplicatedState,
        dts_result: DtsInstallCodeResult,
        dts_status: DtsInstallCodeStatus,
        timer: Timer,
    ) -> (ReplicatedState, Option<NumInstructions>) {
        let execution_duration = timer.elapsed();
        match dts_result {
            DtsInstallCodeResult::Finished {
                canister,
                mut message,
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
                            "Finished executing install_code message on canister {:?} after {:?}, old wasm hash {:?}, new wasm hash {:?}",
                            canister_id,
                            execution_duration,
                            result.old_wasm_hash,
                            result.new_wasm_hash);

                        Ok(EmptyBlob.encode())
                    }
                    Err(err) => {
                        info!(
                            self.log,
                            "Finished executing install_code message on canister {:?} after {:?} with error: {:?}",
                            canister_id,
                            execution_duration,
                            err);
                        Err(err.into())
                    }
                };
                state.put_canister_state(canister);
                let refund = message.take_cycles();
                let state =
                    self.finish_subnet_message_execution(state, message, result, refund, timer);
                (state, Some(instructions_used))
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
                    .push_front(ExecutionTask::PausedInstallCode(id));

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
            | ExecutionTask::PausedExecution(_)
            | ExecutionTask::AbortedExecution { .. } => {
                panic!(
                    "Unexpected task {:?} in `resume_install_code` (broken precondition).",
                    task
                );
            }
            ExecutionTask::PausedInstallCode(id) => {
                let timer = Timer::start();
                let paused = self.take_paused_install_code(id).unwrap();
                let canister = state.take_canister_state(canister_id).unwrap();
                let round = RoundContext {
                    network_topology: &state.metadata.network_topology,
                    hypervisor: &self.hypervisor,
                    cycles_account_manager: &self.cycles_account_manager,
                    execution_refund_error_counter: self
                        .metrics
                        .execution_cycles_refund_error_counter(),
                    log: &self.log,
                    time: state.metadata.time(),
                };
                let dts_result = paused.resume(canister, round, round_limits);
                let dts_status = DtsInstallCodeStatus::ResumingPausedOrAbortedExecution;
                self.process_install_code_result(state, dts_result, dts_status, timer)
            }
            ExecutionTask::AbortedInstallCode {
                message,
                prepaid_execution_cycles,
            } => self.execute_install_code(
                message,
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
            let task_queue = std::mem::take(&mut canister.system_state.task_queue);
            canister.system_state.task_queue = task_queue
                .into_iter()
                .map(|task| match task {
                    ExecutionTask::AbortedExecution { .. }
                    | ExecutionTask::AbortedInstallCode { .. }
                    | ExecutionTask::Heartbeat
                    | ExecutionTask::GlobalTimer => task,
                    ExecutionTask::PausedExecution(id) => {
                        let paused = self.take_paused_execution(id).unwrap();
                        let (message, prepaid_execution_cycles) = paused.abort(log);
                        self.metrics.executions_aborted.inc();
                        ExecutionTask::AbortedExecution {
                            message,
                            prepaid_execution_cycles,
                        }
                    }
                    ExecutionTask::PausedInstallCode(id) => {
                        let paused = self.take_paused_install_code(id).unwrap();
                        let (message, prepaid_execution_cycles) = paused.abort(log);
                        self.metrics.executions_aborted.inc();
                        ExecutionTask::AbortedInstallCode {
                            message,
                            prepaid_execution_cycles,
                        }
                    }
                })
                .collect();
            canister.apply_priority_credit();
            // Aborting a long-running execution moves the canister to the
            // default execution mode because the canister does not have a
            // pending execution anymore.
            canister.scheduler_state.long_execution_mode = LongExecutionMode::default();
            let canister_id = canister.canister_id();
            canister.system_state.apply_cycles_debit(canister_id, log);
        };
    }

    /// Aborts all paused execution in the given state.
    pub fn abort_all_paused_executions(&self, state: &mut ReplicatedState, log: &ReplicaLogger) {
        for canister in state.canisters_iter_mut() {
            self.abort_canister(canister, log);
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
                let id = self.register_paused_execution(paused_execution);
                canister
                    .system_state
                    .task_queue
                    .push_front(ExecutionTask::PausedExecution(id));
                (canister, None, NumBytes::from(0), ingress_status)
            }
        }
    }

    fn reject_unexpected_ingress(
        &self,
        method: Ic00Method,
    ) -> Option<(Result<Vec<u8>, UserError>, Cycles)> {
        error!(
            self.log,
            "[EXC-BUG] Ingress messages to {} should've been filtered earlier.", method
        );
        Some((
            Err(UserError::new(
                ErrorCode::CanisterContractViolation,
                format!("{} cannot be called by a user.", method),
            )),
            Cycles::zero(),
        ))
    }

    /// For testing purposes only.
    #[doc(hidden)]
    pub fn hypervisor_for_testing(&self) -> &Hypervisor {
        &*self.hypervisor
    }

    #[doc(hidden)]
    pub fn clear_compilation_cache_for_testing(&self) {
        (&*self.hypervisor).clear_compilation_cache_for_testing()
    }
}

/// Indicates whether the full time spent compiling this canister or a reduced
/// amount should count against the round instruction limits. Reduced amounts
/// should be counted when the module was deserialized from a previous
/// compilation instead of fully compiled. Canisters should always be charged
/// for compilation costs even when they aren't counted against the round
/// limits. Only public for testing.
#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
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
pub(crate) fn subnet_memory_capacity(config: &ExecutionConfig) -> SubnetAvailableMemory {
    SubnetAvailableMemory::new(
        config.subnet_memory_capacity.get() as i64,
        config.subnet_message_memory_capacity.get() as i64,
    )
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

/// Executes the given input message.
/// This is a helper for `execute_canister()`.
fn execute_message(
    message: CanisterInputMessage,
    prepaid_execution_cycles: Option<Cycles>,
    exec_env: &ExecutionEnvironment,
    canister: CanisterState,
    instruction_limits: InstructionLimits,
    max_instructions_per_message_without_dts: NumInstructions,
    network_topology: Arc<NetworkTopology>,
    time: Time,
    round_limits: &mut RoundLimits,
    subnet_size: usize,
) -> ExecuteCanisterResult {
    let msg_info = message.to_string();
    let result = exec_env.execute_canister_message(
        canister,
        instruction_limits,
        max_instructions_per_message_without_dts,
        message,
        prepaid_execution_cycles,
        time,
        network_topology,
        round_limits,
        subnet_size,
    );
    let (canister, instructions_used, heap_delta, ingress_status) = exec_env.process_result(result);
    ExecuteCanisterResult {
        canister,
        instructions_used,
        heap_delta,
        ingress_status,
        description: Some(msg_info),
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

    match canister.system_state.task_queue.pop_front() {
        Some(task) => match task {
            ExecutionTask::Heartbeat => {
                // A heartbeat is expected to finish quickly, so DTS is not supported for it.
                let instruction_limits = InstructionLimits::new(
                    FlagStatus::Disabled,
                    max_instructions_per_message_without_dts,
                    max_instructions_per_message_without_dts,
                );
                let (canister, instructions_used, result) = exec_env.execute_canister_system_task(
                    canister,
                    SystemMethod::CanisterHeartbeat,
                    instruction_limits,
                    network_topology,
                    time,
                    round_limits,
                    subnet_size,
                    &exec_env.log,
                );
                let heap_delta = result.unwrap_or_else(|_| NumBytes::from(0));
                ExecuteCanisterResult {
                    canister,
                    instructions_used: Some(instructions_used),
                    heap_delta,
                    ingress_status: None,
                    description: Some("heartbeat".to_string()),
                }
            }
            ExecutionTask::GlobalTimer => {
                // A timer is expected to finish quickly, so DTS is not supported for it.
                let instruction_limits = InstructionLimits::new(
                    FlagStatus::Disabled,
                    max_instructions_per_message_without_dts,
                    max_instructions_per_message_without_dts,
                );
                // The global timer is one-off
                canister.system_state.global_timer = CanisterTimer::Inactive;
                let (canister, instructions_used, result) = exec_env.execute_canister_system_task(
                    canister,
                    SystemMethod::CanisterGlobalTimer,
                    instruction_limits,
                    network_topology,
                    time,
                    round_limits,
                    subnet_size,
                    &exec_env.log,
                );
                let heap_delta = result.unwrap_or_else(|_| NumBytes::from(0));
                ExecuteCanisterResult {
                    canister,
                    instructions_used: Some(instructions_used),
                    heap_delta,
                    ingress_status: None,
                    description: Some("global timer".to_string()),
                }
            }
            ExecutionTask::PausedExecution(id) => {
                let paused = exec_env.take_paused_execution(id).unwrap();
                let round_context = RoundContext {
                    network_topology: &network_topology,
                    hypervisor: &exec_env.hypervisor,
                    cycles_account_manager: &exec_env.cycles_account_manager,
                    execution_refund_error_counter: exec_env
                        .metrics
                        .execution_cycles_refund_error_counter(),
                    log: &exec_env.log,
                    time,
                };
                let result = paused.resume(canister, round_context, round_limits, subnet_size);
                let (canister, instructions_used, heap_delta, ingress_status) =
                    exec_env.process_result(result);
                ExecuteCanisterResult {
                    canister,
                    instructions_used,
                    heap_delta,
                    ingress_status,
                    description: Some("paused execution".to_string()),
                }
            }
            ExecutionTask::AbortedExecution {
                message,
                prepaid_execution_cycles,
            } => execute_message(
                message,
                Some(prepaid_execution_cycles),
                exec_env,
                canister,
                instruction_limits,
                max_instructions_per_message_without_dts,
                network_topology,
                time,
                round_limits,
                subnet_size,
            ),
            ExecutionTask::PausedInstallCode(..) | ExecutionTask::AbortedInstallCode { .. } => {
                unreachable!("The guard at the beginning filters these cases out")
            }
        },
        None => {
            let message = canister.pop_input().unwrap();
            execute_message(
                message,
                None,
                exec_env,
                canister,
                instruction_limits,
                max_instructions_per_message_without_dts,
                network_topology,
                time,
                round_limits,
                subnet_size,
            )
        }
    }
}

fn get_master_ecdsa_public_key<'a>(
    ecdsa_subnet_public_keys: &'a BTreeMap<EcdsaKeyId, MasterEcdsaPublicKey>,
    subnet_id: SubnetId,
    key_id: &EcdsaKeyId,
) -> Result<&'a MasterEcdsaPublicKey, UserError> {
    match ecdsa_subnet_public_keys.get(key_id) {
        None => Err(UserError::new(
            ErrorCode::CanisterRejectedMessage,
            format!("Subnet {} does not hold ECDSA key {}.", subnet_id, key_id),
        )),
        Some(master_key) => Ok(master_key),
    }
}
