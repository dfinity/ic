use crate::execution::response::ExecutionCyclesRefund;
use crate::execution::{
    heartbeat::execute_heartbeat, nonreplicated_query::execute_non_replicated_query,
    response::execute_response,
};
use crate::{
    canister_manager::{
        CanisterManager, CanisterMgrConfig, InstallCodeContext, StopCanisterResult,
    },
    canister_settings::CanisterSettings,
    execution::call::execute_call,
    execution_environment_metrics::ExecutionEnvironmentMetrics,
    hypervisor::Hypervisor,
    util::candid_error_to_user_error,
    NonReplicatedQueryKind,
};
use candid::Encode;
use ic_base_types::PrincipalId;
use ic_config::execution_environment::Config as ExecutionConfig;
use ic_crypto::derive_tecdsa_public_key;
use ic_cycles_account_manager::{
    CyclesAccountManager, IngressInductionCost, IngressInductionCostError,
};
use ic_error_types::{ErrorCode, RejectCode, UserError};
use ic_ic00_types::{
    CanisterHttpRequestArgs, CanisterIdRecord, CanisterSettingsArgs, CanisterStatusType,
    ComputeInitialEcdsaDealingsArgs, CreateCanisterArgs, ECDSAPublicKeyArgs,
    ECDSAPublicKeyResponse, EcdsaKeyId, EmptyBlob, HttpMethod, InstallCodeArgs,
    Method as Ic00Method, Payload as Ic00Payload, ProvisionalCreateCanisterWithCyclesArgs,
    ProvisionalTopUpCanisterArgs, SetControllerArgs, SetupInitialDKGArgs, SignWithECDSAArgs,
    UpdateSettingsArgs, IC_00,
};
use ic_interfaces::execution_environment::{
    AvailableMemory, CanisterOutOfCyclesError, RegistryExecutionSettings,
};
use ic_interfaces::{
    execution_environment::{
        ExecutionMode, ExecutionParameters, HypervisorError, IngressHistoryWriter,
        SubnetAvailableMemory,
    },
    messages::{CanisterInputMessage, RequestOrIngress},
};
use ic_logger::{error, info, warn, ReplicaLogger};
use ic_metrics::{MetricsRegistry, Timer};
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    metadata_state::subnet_call_context_manager::{
        EcdsaDealingsContext, SetupInitialDkgContext, SignWithEcdsaContext,
    },
    CanisterState, NetworkTopology, ReplicatedState,
};
use ic_types::messages::MessageId;
use ic_types::{
    canister_http::{CanisterHttpHeader, CanisterHttpMethod, CanisterHttpRequestContext},
    crypto::canister_threshold_sig::{ExtendedDerivationPath, MasterEcdsaPublicKey},
    crypto::threshold_sig::ni_dkg::NiDkgTargetId,
    ingress::{IngressState, IngressStatus, WasmResult},
    messages::{
        is_subnet_message, AnonymousQuery, Payload, RejectContext, Request, Response,
        SignedIngressContent, StopCanisterContext,
    },
    CanisterId, ComputeAllocation, Cycles, NumBytes, NumInstructions, SubnetId, Time,
};
#[cfg(test)]
use mockall::automock;
use rand::RngCore;
use std::collections::BTreeMap;
use std::str::FromStr;
use std::{convert::Into, convert::TryFrom, sync::Arc};
use strum::ParseError;

/// The response of the executed message created by the `ic0.msg_reply()`
/// or `ic0.msg_reject()` System API functions.
/// If the execution failed or did not call these System API functions,
/// then the response is empty.
#[derive(Debug, PartialEq, Eq)]
pub enum ExecutionResponse {
    Ingress((MessageId, IngressStatus)),
    Request(Response),
    Empty,
}

/// The data structure returned by
/// `ExecutionEnvironment.execute_canister_message()`.
pub struct ExecuteMessageResult {
    /// The `CanisterState` after message execution
    pub canister: CanisterState,
    /// The amount of instructions left after message execution. This must be <=
    /// to the instructions_limit that `execute_canister_message()` was called
    /// with.
    pub num_instructions_left: NumInstructions,
    /// The response of the executed message. The caller needs to either push it
    /// to the output queue of the canister or update the ingress status.
    pub response: ExecutionResponse,
    /// The size of the heap delta the canister produced
    pub heap_delta: NumBytes,
}

/// Represent a paused execution that can be resumed or aborted.
pub trait PausedExecution: std::fmt::Debug {
    /// Resumes a paused execution.
    /// It takes:
    /// - the canister state,
    /// - system parameters that can change while the execution is in progress,
    /// - helpers.
    ///
    /// If the execution finishes, then it returns the new canister state and
    /// the result of the execution.
    /// TODO(RUN-231): Add paused execution to `ExecuteMessageResult` to support
    /// the other case.
    fn resume(
        self: Box<Self>,
        canister: CanisterState,
        subnet_available_memory: SubnetAvailableMemory,
        network_topology: &NetworkTopology,
        hypervisor: &Hypervisor,
        cycles_account_manager: &CyclesAccountManager,
        log: &ReplicaLogger,
    ) -> ExecuteMessageResult;

    /// Aborts the paused execution.
    /// TODO(RUN-75): Add parameters and the return type.
    fn abort(self: Box<Self>);
}

/// ExecutionEnvironment is the component responsible for executing messages
/// on the IC.
#[cfg_attr(test, automock)]
pub trait ExecutionEnvironment: Sync + Send {
    /// Executes a replicated message sent to a subnet.
    //
    // A deterministic cryptographically secure pseudo-random number generator
    // is created per round and per thread and passed to this method to be used
    // while responding to randomness requests (i.e. raw_rand). Using the type
    // "&mut RngCore" imposes a problem with our usage of "mockall" library in
    // the test_utilities. Mockall's doc states: "The only restrictions on
    // mocking generic methods are that all generic parameters must be 'static,
    // and generic lifetime parameters are not allowed." Hence, the type of the
    // parameter is "&mut (dyn RngCore + 'static)".
    //
    // Returns the new replicated state and the number of left instructions.
    #[allow(clippy::too_many_arguments)]
    fn execute_subnet_message(
        &self,
        msg: CanisterInputMessage,
        state: ReplicatedState,
        instructions_limit: NumInstructions,
        rng: &mut (dyn RngCore + 'static),
        ecdsa_subnet_public_keys: &BTreeMap<EcdsaKeyId, MasterEcdsaPublicKey>,
        subnet_available_memory: SubnetAvailableMemory,
        registry_settings: &RegistryExecutionSettings,
    ) -> (ReplicatedState, NumInstructions);

    /// Executes a replicated message sent to a canister.
    #[allow(clippy::too_many_arguments)]
    fn execute_canister_message(
        &self,
        canister_state: CanisterState,
        instructions_limit: NumInstructions,
        msg: CanisterInputMessage,
        time: Time,
        network_topology: Arc<NetworkTopology>,
        subnet_available_memory: SubnetAvailableMemory,
    ) -> ExecuteMessageResult;

    /// Executes a heartbeat of a given canister.
    #[allow(clippy::too_many_arguments)]
    fn execute_canister_heartbeat(
        &self,
        canister_state: CanisterState,
        instructions_limit: NumInstructions,
        network_topology: Arc<NetworkTopology>,
        time: Time,
        subnet_available_memory: SubnetAvailableMemory,
    ) -> (
        CanisterState,
        NumInstructions,
        Result<NumBytes, CanisterHeartbeatError>,
    );

    /// Look up the current amount of memory available on the subnet.
    /// EXC-185 will make this method obsolete.
    fn subnet_available_memory(&self, state: &ReplicatedState) -> AvailableMemory;

    /// Returns the maximum amount of memory that can be utilized by a single
    /// canister.
    fn max_canister_memory_size(&self) -> NumBytes;

    /// Returns the subnet memory capacity.
    fn subnet_memory_capacity(&self) -> NumBytes;

    /// Builds execution parameters for the given canister with the given
    /// instruction limit and available subnet memory counter.
    fn execution_parameters(
        &self,
        canister: &CanisterState,
        instruction_limit: NumInstructions,
        subnet_available_memory: SubnetAvailableMemory,
        execution_mode: ExecutionMode,
    ) -> ExecutionParameters;
}

/// Struct that is responsible for executing update type message messages on
/// canisters and subnet messages.
pub struct ExecutionEnvironmentImpl {
    log: ReplicaLogger,
    hypervisor: Arc<Hypervisor>,
    canister_manager: CanisterManager,
    ingress_history_writer: Arc<dyn IngressHistoryWriter<State = ReplicatedState>>,
    metrics: ExecutionEnvironmentMetrics,
    config: ExecutionConfig,
    cycles_account_manager: Arc<CyclesAccountManager>,
    own_subnet_id: SubnetId,
    own_subnet_type: SubnetType,
}

/// Errors when executing `canister_heartbeat`.
#[derive(Debug, Eq, PartialEq)]
pub enum CanisterHeartbeatError {
    /// The canister isn't running.
    CanisterNotRunning {
        status: CanisterStatusType,
    },

    OutOfCycles(CanisterOutOfCyclesError),

    /// Execution failed while executing the `canister_heartbeat`.
    CanisterExecutionFailed(HypervisorError),
}

impl std::fmt::Display for CanisterHeartbeatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CanisterHeartbeatError::CanisterNotRunning { status } => write!(
                f,
                "Canister in status {} instead of {}",
                status,
                CanisterStatusType::Running
            ),
            CanisterHeartbeatError::OutOfCycles(err) => write!(f, "{}", err),
            CanisterHeartbeatError::CanisterExecutionFailed(err) => write!(f, "{}", err),
        }
    }
}

impl CanisterHeartbeatError {
    /// Does this error come from a problem in the execution environment?
    /// Other errors could be caused by bad canister code.
    pub fn is_system_error(&self) -> bool {
        match self {
            CanisterHeartbeatError::CanisterExecutionFailed(hypervisor_err) => {
                hypervisor_err.is_system_error()
            }
            CanisterHeartbeatError::CanisterNotRunning { status: _ }
            | CanisterHeartbeatError::OutOfCycles(_) => false,
        }
    }
}

impl ExecutionEnvironment for ExecutionEnvironmentImpl {
    fn subnet_available_memory(&self, state: &ReplicatedState) -> AvailableMemory {
        AvailableMemory::new(
            self.config.subnet_memory_capacity.get() as i64
                - state.total_memory_taken().get() as i64,
            self.config.subnet_message_memory_capacity.get() as i64
                - state.message_memory_taken().get() as i64,
        )
    }

    #[allow(clippy::cognitive_complexity)]
    fn execute_subnet_message(
        &self,
        msg: CanisterInputMessage,
        mut state: ReplicatedState,
        instructions_limit: NumInstructions,
        rng: &mut (dyn RngCore + 'static),
        ecdsa_subnet_public_keys: &BTreeMap<EcdsaKeyId, MasterEcdsaPublicKey>,
        subnet_available_memory: SubnetAvailableMemory,
        registry_settings: &RegistryExecutionSettings,
    ) -> (ReplicatedState, NumInstructions) {
        let timer = Timer::start(); // Start logging execution time.

        let mut msg = match msg {
            CanisterInputMessage::Response(response) => {
                let request = state
                    .metadata
                    .subnet_call_context_manager
                    .retrieve_request(response.originator_reply_callback, &self.log);
                return match request {
                    None => (state, instructions_limit),
                    Some(request) => {
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
                        (state, instructions_limit)
                    }
                };
            }

            CanisterInputMessage::Ingress(msg) => RequestOrIngress::Ingress(msg),
            CanisterInputMessage::Request(msg) => RequestOrIngress::Request(msg),
        };

        let method = Ic00Method::from_str(msg.method_name());
        let payload = msg.method_payload();
        let (result, instructions_left) = match method {
            Ok(Ic00Method::CreateCanister) => {
                match &mut msg {
                    RequestOrIngress::Ingress(_) =>
                        (Some((Err(UserError::new(
                            ErrorCode::CanisterMethodNotFound,
                            "create_canister can only be called by other canisters, not via ingress messages.")),
                            Cycles::zero(),
                        )), instructions_limit),
                    RequestOrIngress::Request(req) => {
                        let cycles = Arc::make_mut(req).take_cycles();
                        match CreateCanisterArgs::decode(req.method_payload()) {
                            Err(err) => (Some((Err(err), cycles)), instructions_limit),
                            Ok(args) => {
                                // Start logging execution time for `create_canister`.
                                let timer = Timer::start();

                                let settings = match args.settings {
                                    None => CanisterSettingsArgs::default(),
                                    Some(settings) => settings,
                                };
                                let result = match CanisterSettings::try_from(settings) {
                                    Err(err) => (Some((Err(err.into()), cycles)), instructions_limit),
                                    Ok(settings) =>
                                        (Some(self.create_canister(*msg.sender(), cycles, settings, registry_settings.max_number_of_canisters, &mut state)), instructions_limit)
                                };
                                info!(
                                    self.log,
                                    "Finished executing create_canister message after {:?} with result: {:?}",
                                    timer.elapsed(),
                                    result.0
                                );

                                result
                            }
                        }
                    }
                }
            }

            Ok(Ic00Method::InstallCode) => {
                let (res, instructions_left) = match InstallCodeArgs::decode(payload) {
                    Err(err) => (Err(candid_error_to_user_error(err)), instructions_limit),
                    Ok(args) => match InstallCodeContext::try_from((*msg.sender(), args)) {
                        Err(err) => (Err(err.into()), instructions_limit),
                        Ok(install_context) => {
                            let canister_id = install_context.canister_id;
                            info!(
                                self.log,
                                "Start executing install_code message on canister {:?}, contains module {:?}",
                                canister_id,
                                install_context.wasm_module.is_empty().to_string(),
                            );

                            // Start logging execution time for `install_code`.
                            let timer = Timer::start();

                            let execution_parameters = ExecutionParameters {
                                total_instruction_limit: instructions_limit,
                                slice_instruction_limit: instructions_limit,
                                canister_memory_limit: self.config.max_canister_memory_size,
                                subnet_available_memory,
                                compute_allocation: ComputeAllocation::default(),
                                subnet_type: state.metadata.own_subnet_type,
                                execution_mode: ExecutionMode::Replicated,
                            };

                            let (instructions_left, result) = self.canister_manager.install_code(
                                install_context,
                                &mut state,
                                execution_parameters,
                            );

                            let execution_duration = timer.elapsed();

                            let result = match result {
                                Ok(result) => {
                                    state.metadata.heap_delta_estimate += result.heap_delta;

                                    info!(
                                        self.log,
                                        "Finished executing install_code message on canister {:?} after {:?}, old wasm hash {:?}, new wasm hash {:?}",
                                        canister_id,
                                        execution_duration,
                                        result.old_wasm_hash,
                                        result.new_wasm_hash,
                                    );

                                    (Ok(EmptyBlob::encode()), instructions_left)
                                }
                                Err(err) => {
                                    info!(
                                        self.log,
                                        "Finished executing install_code message on canister {:?} after {:?} with error: {:?}",
                                        canister_id,
                                        execution_duration,
                                        err
                                    );
                                    (Err(err.into()), instructions_left)
                                }
                            };

                            result
                        }
                    },
                };
                (Some((res, msg.take_cycles())), instructions_left)
            }

            Ok(Ic00Method::UninstallCode) => {
                let res = match CanisterIdRecord::decode(payload) {
                    Err(err) => Err(candid_error_to_user_error(err)),
                    Ok(args) => self
                        .canister_manager
                        .uninstall_code(args.get_canister_id(), *msg.sender(), &mut state)
                        .map(|()| EmptyBlob::encode())
                        .map_err(|err| err.into()),
                };
                (Some((res, msg.take_cycles())), instructions_limit)
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
                            ),
                        };
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
                (Some((res, msg.take_cycles())), instructions_limit)
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
                        )
                        .map(|()| EmptyBlob::encode())
                        .map_err(|err| err.into()),
                };
                (Some((res, msg.take_cycles())), instructions_limit)
            }

            Ok(Ic00Method::CanisterStatus) => {
                let res = match CanisterIdRecord::decode(payload) {
                    Err(err) => Err(candid_error_to_user_error(err)),
                    Ok(args) => {
                        self.get_canister_status(*msg.sender(), args.get_canister_id(), &mut state)
                    }
                };
                (Some((res, msg.take_cycles())), instructions_limit)
            }

            Ok(Ic00Method::StartCanister) => {
                let res = match CanisterIdRecord::decode(payload) {
                    Err(err) => Err(candid_error_to_user_error(err)),
                    Ok(args) => {
                        self.start_canister(args.get_canister_id(), *msg.sender(), &mut state)
                    }
                };
                (Some((res, msg.take_cycles())), instructions_limit)
            }

            Ok(Ic00Method::StopCanister) => match CanisterIdRecord::decode(payload) {
                Err(err) => (
                    Some((Err(candid_error_to_user_error(err)), msg.take_cycles())),
                    instructions_limit,
                ),
                Ok(args) => (
                    self.stop_canister(args.get_canister_id(), &msg, &mut state),
                    instructions_limit,
                ),
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
                            .map(|()| EmptyBlob::encode())
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

                (Some((res, msg.take_cycles())), instructions_limit)
            }

            Ok(Ic00Method::RawRand) => {
                let res = match EmptyBlob::decode(payload) {
                    Err(err) => Err(candid_error_to_user_error(err)),
                    Ok(()) => {
                        let mut buffer = vec![0u8; 32];
                        rng.fill_bytes(&mut buffer);
                        Ok(Encode!(&buffer).unwrap())
                    }
                };
                (Some((res, msg.take_cycles())), instructions_limit)
            }

            Ok(Ic00Method::DepositCycles) => match CanisterIdRecord::decode(payload) {
                Err(err) => (
                    Some((Err(candid_error_to_user_error(err)), msg.take_cycles())),
                    instructions_limit,
                ),
                Ok(args) => (
                    Some(self.deposit_cycles(args.get_canister_id(), &mut msg, &mut state)),
                    instructions_limit,
                ),
            },
            Ok(Ic00Method::HttpRequest) => match state.metadata.own_subnet_features.http_requests {
                true => match &msg {
                    RequestOrIngress::Request(request) => {
                        match CanisterHttpRequestArgs::decode(payload) {
                            Err(err) => (
                                Some((Err(candid_error_to_user_error(err)), msg.take_cycles())),
                                instructions_limit,
                            ),
                            Ok(args) => {
                                state
                                    .metadata
                                    .subnet_call_context_manager
                                    .push_http_request(CanisterHttpRequestContext {
                                        request: (**request).clone(),
                                        url: args.url,
                                        headers: args
                                            .headers
                                            .clone()
                                            .into_iter()
                                            .map(|h| CanisterHttpHeader {
                                                name: h.name,
                                                value: h.value,
                                            })
                                            .collect(),
                                        body: args.body,
                                        http_method: match args.http_method {
                                            HttpMethod::GET => CanisterHttpMethod::GET,
                                        },
                                        transform_method_name: args.transform_method_name,
                                        time: state.time(),
                                    });
                                (None, instructions_limit)
                            }
                        }
                    }
                    RequestOrIngress::Ingress(_) => {
                        error!(self.log, "[EXC-BUG] Ingress messages to HttpRequest should've been filtered earlier.");
                        let error_string = format!(
                                "HttpRequest is called by user {}. It can only be called by a canister.",
                                msg.sender()
                            );
                        let user_error =
                            UserError::new(ErrorCode::CanisterContractViolation, error_string);
                        let res = Some((Err(user_error), msg.take_cycles()));
                        (res, instructions_limit)
                    }
                },
                false => {
                    let err = Err(UserError::new(
                        ErrorCode::CanisterContractViolation,
                        "This API is not enabled on this subnet".to_string(),
                    ));
                    (Some((err, msg.take_cycles())), instructions_limit)
                }
            },
            Ok(Ic00Method::SetupInitialDKG) => match &msg {
                RequestOrIngress::Request(request) => match SetupInitialDKGArgs::decode(payload) {
                    Err(err) => (
                        Some((Err(candid_error_to_user_error(err)), msg.take_cycles())),
                        instructions_limit,
                    ),
                    Ok(args) => {
                        let res = self
                            .setup_initial_dkg(*msg.sender(), &args, request, &mut state, rng)
                            .map_or_else(|err| Some((Err(err), msg.take_cycles())), |()| None);
                        (res, instructions_limit)
                    }
                },
                RequestOrIngress::Ingress(_) => {
                    let res = Some((
                        Err(UserError::new(
                            ErrorCode::CanisterContractViolation,
                            format!(
                                "{} is called by {}. It can only be called by NNS.",
                                Ic00Method::SetupInitialDKG,
                                msg.sender()
                            ),
                        )),
                        msg.take_cycles(),
                    ));
                    (res, instructions_limit)
                }
            },

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
                        return (state, instructions_limit);
                    }

                    let res = match SignWithECDSAArgs::decode(payload) {
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
                                    )
                                    .map_or_else(
                                        |err| Some((Err(err), msg.take_cycles())),
                                        |()| None,
                                    ),
                            }
                        }
                    };
                    (res, instructions_limit)
                }
                RequestOrIngress::Ingress(_) => {
                    error!(self.log, "[EXC-BUG] Ingress messages to SignWithECDSA should've been filtered earlier.");
                    let error_string = format!(
                        "SignWithECDSA is called by user {}. It can only be called by a canister.",
                        msg.sender()
                    );
                    let user_error =
                        UserError::new(ErrorCode::CanisterContractViolation, error_string);
                    let res = Some((Err(user_error), msg.take_cycles()));
                    (res, instructions_limit)
                }
            },

            Ok(Ic00Method::ECDSAPublicKey) => {
                let res = match &msg {
                    RequestOrIngress::Request(_request) => {
                            match ECDSAPublicKeyArgs::decode(payload) {
                                Err(err) => Some(Err(candid_error_to_user_error(err))),
                                Ok(args) => match get_master_ecdsa_public_key(ecdsa_subnet_public_keys, self.own_subnet_id, &args.key_id) {
                                    Err(err) => Some(Err(err)),
                                    Ok(pubkey) => {
                                      let canister_id = match args.canister_id {
                                        Some(id) => id.into(),
                                        None => *msg.sender(),
                                      };
                                      Some(self.get_ecdsa_public_key(
                                        pubkey,
                                        canister_id,
                                        args.derivation_path,
                                        &args.key_id,
                                        ).map(|res| res.encode()))
                                    }
                                }
                            }
                    }
                    RequestOrIngress::Ingress(_) => {
                        error!(self.log, "[EXC-BUG] Ingress messages to ECDSAPublicKey should've been filtered earlier.");
                        let error_string = format!(
                            "ECDSAPublicKey is called by user {}. It can only be called by a canister.",
                            msg.sender()
                        );
                        Some(Err(UserError::new(ErrorCode::CanisterContractViolation, error_string)))
                    }
                }.map(|res| (res, msg.take_cycles()));
                (res, instructions_limit)
            }

            Ok(Ic00Method::ComputeInitialEcdsaDealings) => {
                let res = match &msg {
                    RequestOrIngress::Request(request) => {
                            match ComputeInitialEcdsaDealingsArgs::decode(payload) {
                                Err(err) => Some(candid_error_to_user_error(err)),
                                Ok(args) => {
                                    match get_master_ecdsa_public_key(ecdsa_subnet_public_keys,
                                            self.own_subnet_id,
                                            &args.key_id) {
                                        Err(err) => Some(err),
                                        Ok(_) => self.compute_initial_ecdsa_dealings(
                                            &mut state,
                                            msg.sender(),
                                            args,
                                            request)
                                            .map_or_else(Some, |()| None)
                                    }
                                }
                            }
                    }
                    RequestOrIngress::Ingress(_) => {
                        error!(self.log, "[EXC-BUG] Ingress messages to ComputeInitialEcdsaDealings should've been filtered earlier.");
                        let error_string = format!(
                            "ComputeInitialEcdsaDealings is called by user {}. It can only be called by a canister.",
                            msg.sender()
                        );
                        Some(UserError::new(ErrorCode::CanisterContractViolation, error_string))
                    }
                }.map(|err| (Err(err), msg.take_cycles()));
                (res, instructions_limit)
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
                                )
                                .map(|canister_id| CanisterIdRecord::from(canister_id).encode())
                                .map_err(|err| err.into()),
                            Err(err) => Err(err.into()),
                        }
                    }
                };
                (Some((res, Cycles::zero())), instructions_limit)
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
                (Some((res, Cycles::zero())), instructions_limit)
            }

            Ok(Ic00Method::BitcoinGetBalance) => {
                let res = crate::bitcoin::get_balance(payload, &mut state);
                (Some((res, msg.take_cycles())), instructions_limit)
            }

            Ok(Ic00Method::BitcoinGetUtxos) => {
                let res = crate::bitcoin::get_utxos(payload, &mut state);
                (Some((res, msg.take_cycles())), instructions_limit)
            }

            Ok(Ic00Method::BitcoinGetCurrentFees) => {
                let res = crate::bitcoin::get_current_fee_percentiles(&mut state);
                (Some((res, msg.take_cycles())), instructions_limit)
            }

            Ok(Ic00Method::BitcoinSendTransaction) | Err(ParseError::VariantNotFound) => {
                let res = Err(UserError::new(
                    ErrorCode::CanisterMethodNotFound,
                    format!("Management canister has no method '{}'", msg.method_name()),
                ));
                (Some((res, msg.take_cycles())), instructions_limit)
            }
        };

        match result {
            Some((res, refund)) => {
                // Request has been executed. Observe metrics and respond.
                let method_name = String::from(msg.method_name());
                self.metrics
                    .observe_subnet_message(method_name.as_str(), timer, &res);
                let state = self.output_subnet_response(msg, state, res, refund);
                (state, instructions_left)
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
                (state, instructions_left)
            }
        }
    }

    fn execute_canister_message(
        &self,
        canister: CanisterState,
        instructions_limit: NumInstructions,
        msg: CanisterInputMessage,
        time: Time,
        network_topology: Arc<NetworkTopology>,
        subnet_available_memory: SubnetAvailableMemory,
    ) -> ExecuteMessageResult {
        let req = match msg {
            CanisterInputMessage::Response(response) => {
                let (should_refund_remaining_cycles, mut result) = self.execute_canister_response(
                    canister,
                    response,
                    instructions_limit,
                    time,
                    network_topology,
                    subnet_available_memory,
                );

                if should_refund_remaining_cycles == ExecutionCyclesRefund::Yes {
                    // Refund the canister with any cycles left after message execution.
                    self.cycles_account_manager.refund_execution_cycles(
                        &mut result.canister.system_state,
                        result.num_instructions_left,
                        instructions_limit,
                    );
                }
                return result;
            }
            CanisterInputMessage::Request(request) => RequestOrIngress::Request(request),
            CanisterInputMessage::Ingress(ingress) => RequestOrIngress::Ingress(ingress),
        };

        execute_call(
            canister,
            req,
            instructions_limit,
            time,
            network_topology,
            subnet_available_memory,
            &self.config,
            self.own_subnet_type,
            &self.hypervisor,
            &*self.cycles_account_manager,
            &self.log,
        )
    }

    fn execute_canister_heartbeat(
        &self,
        canister: CanisterState,
        instructions_limit: NumInstructions,
        network_topology: Arc<NetworkTopology>,
        time: Time,
        subnet_available_memory: SubnetAvailableMemory,
    ) -> (
        CanisterState,
        NumInstructions,
        Result<NumBytes, CanisterHeartbeatError>,
    ) {
        let execution_parameters = self.execution_parameters(
            &canister,
            instructions_limit,
            subnet_available_memory,
            ExecutionMode::Replicated,
        );
        execute_heartbeat(
            canister,
            network_topology,
            execution_parameters,
            self.own_subnet_type,
            time,
            &self.hypervisor,
            &self.cycles_account_manager,
        )
        .into_parts()
    }

    fn max_canister_memory_size(&self) -> NumBytes {
        self.config.max_canister_memory_size
    }

    fn subnet_memory_capacity(&self) -> NumBytes {
        self.config.subnet_memory_capacity
    }

    fn execution_parameters(
        &self,
        canister: &CanisterState,
        instruction_limit: NumInstructions,
        subnet_available_memory: SubnetAvailableMemory,
        execution_mode: ExecutionMode,
    ) -> ExecutionParameters {
        ExecutionParameters {
            total_instruction_limit: instruction_limit,
            slice_instruction_limit: instruction_limit,
            canister_memory_limit: canister.memory_limit(self.config.max_canister_memory_size),
            subnet_available_memory,
            compute_allocation: canister.scheduler_state.compute_allocation,
            subnet_type: self.own_subnet_type,
            execution_mode,
        }
    }
}

impl ExecutionEnvironmentImpl {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        log: ReplicaLogger,
        hypervisor: Arc<Hypervisor>,
        ingress_history_writer: Arc<dyn IngressHistoryWriter<State = ReplicatedState>>,
        metrics_registry: &MetricsRegistry,
        own_subnet_id: SubnetId,
        own_subnet_type: SubnetType,
        num_cores: usize,
        config: ExecutionConfig,
        cycles_account_manager: Arc<CyclesAccountManager>,
    ) -> Self {
        let canister_manager_config: CanisterMgrConfig = CanisterMgrConfig::new(
            config.subnet_memory_capacity,
            config.default_provisional_cycles_balance,
            config.default_freeze_threshold,
            own_subnet_id,
            own_subnet_type,
            config.max_controllers,
            num_cores,
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
        }
    }

    fn create_canister(
        &self,
        sender: PrincipalId,
        cycles: Cycles,
        settings: CanisterSettings,
        max_number_of_canisters: u64,
        state: &mut ReplicatedState,
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
    ) -> Result<Vec<u8>, UserError> {
        let compute_allocation_used = state.total_compute_allocation();
        let memory_allocation_used = state.total_memory_taken();

        let canister = get_canister_mut(canister_id, state)?;
        self.canister_manager
            .update_settings(
                sender,
                settings,
                canister,
                compute_allocation_used,
                memory_allocation_used,
            )
            .map(|()| EmptyBlob::encode())
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
                Ok(EmptyBlob::encode())
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
                self.cycles_account_manager
                    .add_cycles(canister_state.system_state.balance_mut(), msg.take_cycles());
                (Ok(EmptyBlob::encode()), Cycles::from(0))
            }
        }
    }

    fn get_canister_status(
        &self,
        sender: PrincipalId,
        canister_id: CanisterId,
        state: &mut ReplicatedState,
    ) -> Result<Vec<u8>, UserError> {
        let canister = get_canister_mut(canister_id, state)?;

        self.canister_manager
            .get_canister_status(sender, canister)
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
                Some((Ok(EmptyBlob::encode()), cycles_to_return))
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
            .map(|()| EmptyBlob::encode())
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
        instruction_limit: NumInstructions,
        time: Time,
        network_topology: Arc<NetworkTopology>,
        subnet_available_memory: SubnetAvailableMemory,
    ) -> (ExecutionCyclesRefund, ExecuteMessageResult) {
        let execution_parameters = self.execution_parameters(
            &canister,
            instruction_limit,
            subnet_available_memory,
            ExecutionMode::Replicated,
        );
        execute_response(
            canister,
            response,
            time,
            self.own_subnet_type,
            network_topology,
            execution_parameters,
            &self.log,
            self.metrics.response_cycles_refund_error_counter(),
            &self.hypervisor,
            &self.cycles_account_manager,
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
        // A first-pass check on the canister's balance to prevent needless gossiping
        // if the canister's balance is too low. A more rigorous check happens later
        // in the ingress selector.
        {
            let induction_cost = self
                .cycles_account_manager
                .ingress_induction_cost(ingress)
                .map_err(|e| match e {
                    IngressInductionCostError::UnknownSubnetMethod => UserError::new(
                        ErrorCode::CanisterMethodNotFound,
                        format!(
                            "ic00 interface does not expose method {}",
                            ingress.method_name()
                        ),
                    ),
                    IngressInductionCostError::SubnetMethodNotAllowed => UserError::new(
                        ErrorCode::CanisterRejectedMessage,
                        format!(
                            "ic00 method {} can be called only by a canister",
                            ingress.method_name()
                        ),
                    ),
                    IngressInductionCostError::InvalidSubnetPayload(err) => UserError::new(
                        ErrorCode::InvalidManagementPayload,
                        format!(
                            "Failed to parse payload for ic00 method {}: {}",
                            ingress.method_name(),
                            err
                        ),
                    ),
                })?;

            if let IngressInductionCost::Fee { payer, cost } = induction_cost {
                match state.canister_state(&payer) {
                    Some(canister) => {
                        if let Err(err) = self.cycles_account_manager.can_withdraw_cycles(
                            &canister.system_state,
                            cost,
                            canister.memory_usage(self.own_subnet_type),
                            canister.scheduler_state.compute_allocation,
                        ) {
                            return Err(UserError::new(
                                ErrorCode::CanisterOutOfCycles,
                                err.to_string(),
                            ));
                        }
                    }
                    None => {
                        return Err(UserError::new(
                            ErrorCode::CanisterNotFound,
                            format!("Canister {} not found", payer),
                        ));
                    }
                }
            }
        }

        let canister_id = ingress.canister_id();
        let sender = ingress.sender();
        let method_name = ingress.method_name().to_string();
        let payload = ingress.arg();

        if is_subnet_message(ingress, self.own_subnet_id) {
            self.canister_manager.should_accept_ingress_message(
                state,
                provisional_whitelist,
                sender,
                &method_name,
                payload,
            )
        } else {
            match state.canister_state(&canister_id) {
                Some(canister) => {
                    // Letting the canister grow arbitrarily when executing the
                    // query is fine as we do not persist state modifications.
                    let subnet_available_memory = subnet_memory_capacity(&self.config);
                    let execution_parameters = self.execution_parameters(
                        canister,
                        self.config.max_instructions_for_message_acceptance_calls,
                        subnet_available_memory,
                        execution_mode,
                    );
                    self.hypervisor
                        .execute_inspect_message(
                            canister.clone(),
                            sender.get(),
                            method_name,
                            payload.to_vec(),
                            state.time(),
                            execution_parameters,
                            &state.metadata.network_topology,
                        )
                        .1
                }
                None => Err(UserError::new(
                    ErrorCode::CanisterNotFound,
                    format!("Canister {} not found", canister_id),
                )),
            }
        }
    }

    /// Execute a query call that has no caller provided.
    /// This type of query is triggered by the IC only when
    /// there is a need to execute a query call on the provided canister.
    pub fn execute_anonymous_query(
        &self,
        anonymous_query: AnonymousQuery,
        state: Arc<ReplicatedState>,
        max_instructions_per_message: NumInstructions,
    ) -> Result<WasmResult, UserError> {
        let canister_id = anonymous_query.receiver;
        let canister = state.get_active_canister(&canister_id)?;
        let subnet_available_memory = subnet_memory_capacity(&self.config);
        let execution_parameters = self.execution_parameters(
            &canister,
            max_instructions_per_message,
            subnet_available_memory,
            ExecutionMode::NonReplicated,
        );
        let result = execute_non_replicated_query(
            NonReplicatedQueryKind::Pure {
                caller: IC_00.get(),
            },
            &anonymous_query.method_name,
            &anonymous_query.method_payload,
            canister,
            None,
            state.time(),
            execution_parameters,
            &state.metadata.network_topology,
            &self.hypervisor,
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
        rng: &mut (dyn RngCore + 'static),
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
        message_hash: Vec<u8>,
        derivation_path: Vec<Vec<u8>>,
        key_id: EcdsaKeyId,
        max_queue_size: u32,
        state: &mut ReplicatedState,
        rng: &mut (dyn RngCore + 'static),
    ) -> Result<(), UserError> {
        if message_hash.len() != 32 {
            return Err(UserError::new(
                ErrorCode::CanisterRejectedMessage,
                "message_hash must be 32 bytes",
            ));
        }

        // If the request isn't from the NNS, then we need to charge for it.
        // Consensus will return any remaining cycles.
        let source_subnet = state
            .metadata
            .network_topology
            .routing_table
            .route(request.sender.get());
        if source_subnet != Some(state.metadata.network_topology.nns_subnet_id) {
            let signature_fee = self.cycles_account_manager.ecdsa_signature_fee();
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
            });
        Ok(())
    }

    /// For testing purposes only.
    #[doc(hidden)]
    pub fn hypervisor_for_testing(&self) -> &Hypervisor {
        &*self.hypervisor
    }
}

/// Returns the subnet's configured memory capacity (ignoring current usage).
pub(crate) fn subnet_memory_capacity(config: &ExecutionConfig) -> SubnetAvailableMemory {
    AvailableMemory::new(
        config.subnet_memory_capacity.get() as i64,
        config.subnet_message_memory_capacity.get() as i64,
    )
    .into()
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
