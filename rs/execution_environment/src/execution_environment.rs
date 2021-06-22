use crate::{
    canister_manager::{CanisterManager, CanisterMgrConfig, StopCanisterResult},
    canister_settings::CanisterSettings,
    execution_environment_metrics::ExecutionEnvironmentMetrics,
    hypervisor::Hypervisor,
    QueryExecutionType,
};
use candid::Encode;
use ic_config::execution_environment::Config as ExecutionConfig;
use ic_cycles_account_manager::{CyclesAccountManager, IngressInductionCost};
use ic_ic00_types::{
    CanisterIdRecord, CanisterSettingsArgs, CreateCanisterArgs, EmptyBlob, InstallCodeArgs,
    Method as Ic00Method, Payload as Ic00Payload, ProvisionalCreateCanisterWithCyclesArgs,
    ProvisionalTopUpCanisterArgs, SetControllerArgs, SetupInitialDKGArgs, UpdateSettingsArgs,
    IC_00,
};
use ic_interfaces::{
    execution_environment::{
        CanisterHeartbeatError, EarlyResult, ExecResult, ExecuteMessageResult,
        ExecutionEnvironment, HypervisorError, IngressHistoryWriter, MessageAcceptanceError,
        SubnetAvailableMemory,
    },
    messages::{CanisterInputMessage, RequestOrIngress},
};
use ic_logger::{error, fatal, info, ReplicaLogger};
use ic_metrics::{MetricsRegistry, Timer};
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_registry_routing_table::RoutingTable;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    metadata_state::SubnetCallContext, CallContextAction, CallOrigin, CanisterState,
    ReplicatedState,
};
use ic_types::{
    crypto::threshold_sig::ni_dkg::NiDkgTargetId,
    ingress::{IngressStatus, WasmResult},
    messages::{
        is_subnet_message, CallbackId, Ingress, MessageId, Payload, RejectContext, Request,
        Response, SignedIngressContent, StopCanisterContext,
    },
    user_error::{ErrorCode, RejectCode, UserError},
    CanisterId, CanisterStatusType, Cycles, Funds, InstallCodeContext, NumBytes, NumInstructions,
    SubnetId, Time, UserId, ICP,
};
use rand::RngCore;
use std::str::FromStr;
use std::{collections::BTreeMap, convert::Into, convert::TryFrom, sync::Arc};
use strum::ParseError;

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

impl ExecutionEnvironment for ExecutionEnvironmentImpl {
    type State = ReplicatedState;
    type CanisterState = CanisterState;

    fn subnet_available_memory(&self, state: &ReplicatedState) -> NumBytes {
        let mut total_memory_usage = NumBytes::from(0);
        for canister in state.canister_states.values() {
            total_memory_usage += canister.memory_usage();
        }
        self.config.subnet_memory_capacity - total_memory_usage
    }

    #[allow(clippy::cognitive_complexity)]
    fn execute_subnet_message(
        &self,
        msg: CanisterInputMessage,
        mut state: ReplicatedState,
        instructions_limit: NumInstructions,
        rng: &mut (dyn RngCore + 'static),
        provisional_whitelist: &ProvisionalWhitelist,
        subnet_available_memory: SubnetAvailableMemory,
    ) -> ReplicatedState {
        let timer = Timer::start(); // Start logging execution time.

        let mut msg = match msg {
            CanisterInputMessage::Response(response) => {
                return match state
                    .metadata
                    .subnet_call_context_manager
                    .contexts
                    .remove(&response.originator_reply_callback)
                {
                    None => state,
                    Some(context) => {
                        let SubnetCallContext::SetupInitialDKGContext {
                            request, target_id, ..
                        } = context;
                        info!(
                            self.log,
                            "Received the DKG key material for target {:?}", target_id
                        );
                        state.subnet_queues.push_output_response(Response {
                            originator: request.sender,
                            respondent: CanisterId::from(self.own_subnet_id),
                            originator_reply_callback: request.sender_reply_callback,
                            refund: request.payment,
                            response_payload: response.response_payload,
                        });
                        state
                    }
                }
            }

            CanisterInputMessage::Ingress(msg) => RequestOrIngress::Ingress(msg),
            CanisterInputMessage::Request(msg) => RequestOrIngress::Request(msg),
        };

        let method = Ic00Method::from_str(msg.method_name());
        let payload = msg.method_payload();
        let result: Option<(Result<Vec<u8>, UserError>, Funds)> = match method {
            Ok(Ic00Method::CreateCanister) => {
                match &mut msg { RequestOrIngress::Ingress(_) =>
                    Some((Err(UserError::new(
                        ErrorCode::CanisterMethodNotFound,
                        "create_canister can only be called by other canisters, not via ingress messages.")),
                          Funds::zero(),
                    )),
                    RequestOrIngress::Request(req) => {
                        let funds = req.take_funds();
                        match CreateCanisterArgs::decode(req.method_payload()) {
                            Err(err) => Some((Err(err), funds)),
                            Ok(args) => {
                                let settings = match args.settings {
                                    None => CanisterSettingsArgs::default(),
                                    Some(settings) => settings,
                                };
                                match CanisterSettings::try_from(settings) {
                                    Err(err) => Some((Err(err.into()), funds)),
                                    Ok(settings) => {
                                        let sender_principal = *msg.sender();
                                        let sender_subnet_id_option = state
                                            .metadata
                                            .network_topology
                                            .routing_table
                                            .route(sender_principal);

                                        match sender_subnet_id_option {
                                            Some(sender_subnet_id) => {
                                                let (res, funds) = self.canister_manager.create_canister(
                                                    sender_principal,
                                                    sender_subnet_id,
                                                    funds,
                                                    settings,
                                                    &mut state,
                                                );
                                                Some((res.map(|new_canister_id| CanisterIdRecord::from(new_canister_id).encode()).map_err(|err| err.into()), funds))
                                            }
                                            None => Some((Err(UserError::new(
                                                ErrorCode::SubnetNotFound,
                                                format!("Could not find subnetId given principalId {}", sender_principal),
                                            )), funds)),
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            Ok(Ic00Method::InstallCode) => {
                let res = match InstallCodeArgs::decode(payload) {
                    Err(err) => Err(err.into()),
                    Ok(args) => match InstallCodeContext::try_from((*msg.sender(), args)) {
                        Err(err) => Err(err.into()),
                        Ok(install_context) => match self
                            .canister_manager
                            .install_code(install_context, &mut state, instructions_limit, subnet_available_memory)
                            .1 {
                                Ok(heap_delta) => {
                                    state.metadata.heap_delta_estimate += heap_delta;
                                    Ok(EmptyBlob::encode())
                                }
                                Err(err) => Err(err.into())
                        },
                    },
                };
                Some((res, msg.take_funds()))
            }

            Ok(Ic00Method::UninstallCode) => {
                let res = match CanisterIdRecord::decode(payload) {
                    Err(err) => Err(err.into()),
                    Ok(args) => self
                        .canister_manager
                        .uninstall_code(args.get_canister_id(), *msg.sender(), &mut state)
                        .map(|()| EmptyBlob::encode())
                        .map_err(|err| err.into()),
                };
                Some((res, msg.take_funds()))
            }

            Ok(Ic00Method::UpdateSettings) => {
                let res = match UpdateSettingsArgs::decode(payload) {
                    Err(err) => Err(err.into()),
                    Ok(args) => {
                        let canister_id = args.get_canister_id();
                        match CanisterSettings::try_from(args.settings) {
                            Err(err) => Err(err.into()),
                            Ok(settings) => self
                                .canister_manager
                                .update_settings(
                                    *msg.sender(),
                                    canister_id,
                                    settings,
                                    &mut state,
                                )
                                .map(|()| EmptyBlob::encode())
                                .map_err(|err| err.into()),
                        }
                    }

                };
                Some((res, msg.take_funds()))
            }

            Ok(Ic00Method::SetController) => {
                let res = match SetControllerArgs::decode(payload) {
                    Err(err) => Err(err.into()),
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
                Some((res, msg.take_funds()))
            }

            Ok(Ic00Method::CanisterStatus) => {
                let res = match CanisterIdRecord::decode(payload) {
                    Err(err) => Err(err.into()),
                    Ok(args) => self
                        .canister_manager
                        .get_canister_status(args.get_canister_id(), *msg.sender(), &mut state)
                        .map(|status| status.encode())
                        .map_err(|err| err.into()),
                };
                Some((res, msg.take_funds()))
            }

            Ok(Ic00Method::StartCanister) => {
                let res = match CanisterIdRecord::decode(payload) {
                    Err(err) => Err(err.into()),
                    Ok(args) => {
                        let result = self.canister_manager.start_canister(
                            args.get_canister_id(),
                            *msg.sender(),
                            &mut state,
                        );

                        match result {
                            Ok(stop_contexts) => {
                                // Reject outstanding stop messages (if any).
                                state = self.reject_stop_requests(
                                    args.get_canister_id(),
                                    stop_contexts,
                                    state,
                                );
                                Ok(EmptyBlob::encode())
                            }
                            Err(err) => Err(err.into()),
                        }
                    }
                };
                Some((res, msg.take_funds()))
            }

            Ok(Ic00Method::StopCanister) => match CanisterIdRecord::decode(payload) {
                Err(err) => Some((Err(err.into()), msg.take_funds())),
                Ok(args) => {
                    match self.canister_manager.stop_canister(
                        args.get_canister_id(),
                        StopCanisterContext::from(msg.clone()),
                        &mut state,
                    ) {
                        StopCanisterResult::RequestAccepted => None,
                        StopCanisterResult::Failure {
                            error,
                            funds_to_return,
                        } => Some((Err(error.into()), funds_to_return)),
                        StopCanisterResult::AlreadyStopped { funds_to_return } => {
                            Some((Ok(EmptyBlob::encode()), funds_to_return))
                        }
                    }
                }
            },

            Ok(Ic00Method::DeleteCanister) => {
                let res = match CanisterIdRecord::decode(payload) {
                    Err(err) => Err(err.into()),
                    Ok(args) => self
                        .canister_manager
                        .delete_canister(*msg.sender(), args.get_canister_id(), &mut state)
                        .map(|()| EmptyBlob::encode())
                        .map_err(|err| err.into()),
                };
                Some((res, msg.take_funds()))
            }

            Ok(Ic00Method::RawRand) => {
                let res = match EmptyBlob::decode(payload) {
                    Err(err) => Err(err.into()),
                    Ok(()) => {
                        let mut buffer = vec![0u8; 32];
                        rng.fill_bytes(&mut buffer);
                        Ok(Encode!(&buffer).unwrap())
                    }
                };
                Some((res, msg.take_funds()))
            }

            Ok(Ic00Method::DepositCycles) => match CanisterIdRecord::decode(payload) {
                Err(err) => Some((Err(err.into()), msg.take_funds())),
                Ok(args) => {
                    let mut msg_funds = msg.take_funds();
                    let (cycles_to_return, res) = self.canister_manager.deposit_cycles(
                        args.get_canister_id(),
                        msg_funds.take_cycles(),
                        &mut state,
                    );
                    msg_funds.add_cycles(cycles_to_return);
                    Some((
                        res.map(|()| EmptyBlob::encode()).map_err(|err| err.into()),
                        msg_funds,
                    ))
                }
            },

            Ok(Ic00Method::SetupInitialDKG) => {
                let sender_principal = *msg.sender();
                let sender_subnet_id_option = state
                    .metadata
                    .network_topology
                    .routing_table
                    .route(sender_principal);

                match sender_subnet_id_option {
                    None => Some((
                        Err(UserError::new(
                            ErrorCode::SubnetNotFound,
                            format!(
                                "Could not find subnetId given principalId {}",
                                sender_principal
                            ),
                        )),
                        msg.take_funds(),
                    )),
                    Some(sender_subnet_id) => {
                        if sender_subnet_id != state.metadata.network_topology.nns_subnet_id {
                            Some((
                                Err(UserError::new(
                                    ErrorCode::CanisterContractViolation,
                                    format!(
                                        "{} is called by {}. It can only be called by NNS.",
                                        Ic00Method::SetupInitialDKG.to_string(),
                                        sender_principal,
                                    ),
                                )),
                                msg.take_funds(),
                            ))
                        } else {
                            self.setup_initial_dkg(&msg, payload, &mut state, rng)
                                .map_or_else(|err| Some((Err(err), msg.take_funds())), |()| None)
                        }
                    }
                }
            }

            Ok(Ic00Method::ProvisionalCreateCanisterWithCycles) => {
                let res = match ProvisionalCreateCanisterWithCyclesArgs::decode(payload) {
                    Err(err) => Err(err.into()),
                    Ok(args) => {
                        let cycles_amount = args.to_u64();
                        match CanisterSettings::try_from(args.settings) {
                            Ok(settings) => {
                                self
                                    .canister_manager
                                    .create_canister_with_funds(
                                        *msg.sender(),
                                        cycles_amount,
                                        0,
                                        settings,
                                        &mut state,
                                        provisional_whitelist,
                                    )
                                    .map(|canister_id| CanisterIdRecord::from(canister_id).encode())
                                    .map_err(|err| err.into())
                            },
                            Err(err) =>  Err(err.into()),
                        }
                    }
                };
                Some((res, Funds::zero()))
            }

            Ok(Ic00Method::ProvisionalTopUpCanister) => {
                let res = match ProvisionalTopUpCanisterArgs::decode(payload) {
                    Err(err) => Err(err.into()),
                    Ok(args) => self
                        .canister_manager
                        .add_cycles(
                            *msg.sender(),
                            args.get_canister_id(),
                            args.to_u64(),
                            &mut state,
                            provisional_whitelist,
                        )
                        .map(|()| EmptyBlob::encode())
                        .map_err(|err| err.into()),
                };
                Some((res, Funds::zero()))
            }

            Err(ParseError::VariantNotFound) => {
                let res = Err(UserError::new(
                    ErrorCode::CanisterMethodNotFound,
                    format!("Management canister has no method '{}'", msg.method_name()),
                ));
                Some((res, msg.take_funds()))
            }
        };

        match result {
            Some((res, refund)) => {
                // Request has been executed. Observe metrics and respond.
                let method_name = String::from(msg.method_name());
                let execution_succeeded = res.is_ok();
                let state = self.output_subnet_response(msg, state, res, refund);
                self.metrics.observe_subnet_message(
                    method_name.as_str(),
                    timer,
                    execution_succeeded,
                );
                state
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
                // Ic00Method::SetupInitialDKG.  The request is saved and the
                // response from consensus is handled separately.
                state
            }
        }
    }

    fn execute_canister_message(
        &self,
        mut canister: CanisterState,
        instructions_limit: NumInstructions,
        msg: CanisterInputMessage,
        time: Time,
        routing_table: Arc<RoutingTable>,
        subnet_records: Arc<BTreeMap<SubnetId, SubnetType>>,
        subnet_available_memory: SubnetAvailableMemory,
    ) -> ExecResult<ExecuteMessageResult<CanisterState>> {
        let (should_refund_remaining_cycles, res) = match msg {
            CanisterInputMessage::Request(request) => {
                let memory_usage = canister.memory_usage();
                let compute_allocation = canister.scheduler_state.compute_allocation;
                if let Err(err) = self.cycles_account_manager.withdraw_execution_cycles(
                    &mut canister.system_state,
                    memory_usage,
                    compute_allocation,
                    instructions_limit,
                ) {
                    // Canister is out of cycles. Reject the request.
                    let canister_id = canister.canister_id();
                    return EarlyResult::new(self.reject_request(
                        canister,
                        instructions_limit,
                        request,
                        RejectContext {
                            code: RejectCode::SysTransient,
                            message: format!(
                                "Canister {} is out of cycles: {}",
                                canister_id,
                                err.to_string()
                            ),
                        },
                        NumBytes::from(0),
                    ));
                }
                (
                    true,
                    self.execute_canister_request(
                        canister,
                        request,
                        instructions_limit,
                        time,
                        routing_table,
                        subnet_records,
                        subnet_available_memory,
                    ),
                )
            }

            CanisterInputMessage::Ingress(ingress) => {
                let memory_usage = canister.memory_usage();
                let compute_allocation = canister.scheduler_state.compute_allocation;
                if let Err(err) = self.cycles_account_manager.withdraw_execution_cycles(
                    &mut canister.system_state,
                    memory_usage,
                    compute_allocation,
                    instructions_limit,
                ) {
                    // Canister is out of cycles. Reject the request.
                    let canister_id = canister.canister_id();
                    return EarlyResult::new(ExecuteMessageResult {
                        canister,
                        num_instructions_left: instructions_limit,
                        ingress_status: Some((
                            ingress.message_id,
                            IngressStatus::Failed {
                                receiver: canister_id.get(),
                                user_id: ingress.source,
                                error: UserError::new(
                                    ErrorCode::CanisterOutOfCycles,
                                    format!(
                                        "Canister {} is out of cycles: {}",
                                        canister_id,
                                        err.to_string()
                                    ),
                                ),
                                time,
                            },
                        )),
                        heap_delta: NumBytes::from(0),
                    });
                }
                (
                    true,
                    self.execute_ingress(
                        canister,
                        ingress,
                        instructions_limit,
                        time,
                        routing_table,
                        subnet_records,
                        subnet_available_memory,
                    ),
                )
            }

            CanisterInputMessage::Response(response) => self.execute_canister_response(
                canister,
                response,
                instructions_limit,
                time,
                routing_table,
                subnet_records,
                subnet_available_memory,
            ),
        };

        if should_refund_remaining_cycles {
            // Clone the `cycles_account_manager` to avoid having to require 'static
            // lifetime bound on `self`.
            let cycles_account_manager = Arc::clone(&self.cycles_account_manager);
            res.and_then(move |mut res| {
                // Refund the canister with any cycles left after message execution.
                cycles_account_manager.refund_execution_cycles(
                    &mut res.canister.system_state,
                    res.num_instructions_left,
                );
                res
            })
        } else {
            res
        }
    }

    fn should_accept_ingress_message(
        &self,
        state: Arc<Self::State>,
        provisional_whitelist: &ProvisionalWhitelist,
        ingress: &SignedIngressContent,
    ) -> Result<(), MessageAcceptanceError> {
        // A first-pass check on the canister's balance to prevent needless gossiping
        // if the canister's balance is too low. A more rigorous check happens later
        // in the ingress selector.
        {
            let induction_cost = self
                .cycles_account_manager
                .ingress_induction_cost(ingress)
                .map_err(|_| MessageAcceptanceError::CanisterRejected)?;

            if let IngressInductionCost::Fee { payer, cost } = induction_cost {
                match state.canister_state(&payer) {
                    Some(canister) => {
                        if cost
                            > self
                                .cycles_account_manager
                                .cycles_balance_above_storage_reserve(
                                    &canister.system_state,
                                    canister.memory_usage(),
                                    canister.scheduler_state.compute_allocation,
                                )
                        {
                            return Err(MessageAcceptanceError::CanisterOutOfCycles);
                        }
                    }
                    None => {
                        return Err(MessageAcceptanceError::CanisterNotFound);
                    }
                }
            }
        }

        let canister_id = ingress.canister_id();
        let sender = ingress.sender();
        let method_name = ingress.method_name().to_string();
        let payload = ingress.arg();

        if is_subnet_message(&ingress, self.own_subnet_id) {
            self.canister_manager.should_accept_ingress_message(
                state,
                provisional_whitelist,
                sender,
                &method_name,
                payload,
            )
        } else {
            match state.canister_state(&canister_id) {
                Some(canister) => self
                    .hypervisor
                    .execute_inspect_message(
                        canister.clone(),
                        sender.get(),
                        method_name,
                        payload.to_vec(),
                        self.config.max_instructions_for_message_acceptance_calls,
                        state.time(),
                    )
                    .get_no_pause(),
                None => Err(MessageAcceptanceError::CanisterNotFound),
            }
        }
    }

    fn execute_canister_heartbeat(
        &self,
        mut canister: Self::CanisterState,
        instructions_limit: NumInstructions,
        routing_table: Arc<RoutingTable>,
        subnet_records: Arc<BTreeMap<SubnetId, SubnetType>>,
        time: Time,
        subnet_available_memory: SubnetAvailableMemory,
    ) -> ExecResult<(
        CanisterState,
        NumInstructions,
        Result<NumBytes, CanisterHeartbeatError>,
    )> {
        // Only execute if subnet is NNS and canister is running.
        match self.own_subnet_type {
            SubnetType::Application | SubnetType::VerifiedApplication => {
                return EarlyResult::new((
                    canister,
                    instructions_limit,
                    Err(CanisterHeartbeatError::NotSystemSubnet {
                        subnet_type_given: self.own_subnet_type,
                    }),
                ))
            }
            SubnetType::System => {}
        }

        if canister.status() != CanisterStatusType::Running {
            let status = canister.status();
            return EarlyResult::new((
                canister,
                instructions_limit,
                Err(CanisterHeartbeatError::CanisterNotRunning { status }),
            ));
        }

        let memory_usage = canister.memory_usage();
        let compute_allocation = canister.scheduler_state.compute_allocation;
        if self
            .cycles_account_manager
            .withdraw_execution_cycles(
                &mut canister.system_state,
                memory_usage,
                compute_allocation,
                instructions_limit,
            )
            .is_err()
        {
            return EarlyResult::new((
                canister,
                instructions_limit,
                Err(CanisterHeartbeatError::OutOfCycles),
            ));
        }

        let res = self.hypervisor.execute_canister_heartbeat(
            canister,
            instructions_limit,
            routing_table,
            subnet_records,
            time,
            subnet_available_memory,
        );

        // Clone the `cycles_account_manager` to avoid having to require 'static
        // lifetime bound on `self`.
        let cycles_account_manager = Arc::clone(&self.cycles_account_manager);
        res.and_then(move |(mut canister, num_instructions_left, result)| {
            // Refund the canister with any cycles left after message execution.
            cycles_account_manager
                .refund_execution_cycles(&mut canister.system_state, num_instructions_left);
            let result = match result {
                Ok(heap_delta) => Ok(heap_delta),
                Err(err) => Err(CanisterHeartbeatError::CanisterExecutionFailed(err)),
            };

            (canister, num_instructions_left, result)
        })
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
        cores: usize,
        config: ExecutionConfig,
        cycles_account_manager: Arc<CyclesAccountManager>,
    ) -> Self {
        let canister_manager_config: CanisterMgrConfig = CanisterMgrConfig::new(
            config.subnet_memory_capacity,
            config.max_cycles_per_canister,
            config.default_provisional_cycles_balance,
            config.default_freeze_threshold,
            config.max_globals,
            config.max_functions,
        );
        let canister_manager = CanisterManager::new(
            Arc::clone(&hypervisor),
            cores,
            own_subnet_id,
            own_subnet_type,
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

    // Executes an inter-canister response.
    //
    // Returns a tuple with the result, along with a boolean indicating whether or
    // not to refund the remaining cycles to the canister.
    #[allow(clippy::too_many_arguments)]
    fn execute_canister_response(
        &self,
        mut canister: CanisterState,
        mut resp: Response,
        cycles: NumInstructions,
        time: Time,
        routing_table: Arc<RoutingTable>,
        subnet_records: Arc<BTreeMap<SubnetId, SubnetType>>,
        subnet_available_memory: SubnetAvailableMemory,
    ) -> (bool, ExecResult<ExecuteMessageResult<CanisterState>>) {
        let call_context_manager = match canister.status() {
            CanisterStatusType::Stopped => {
                // A canister by definition can only be stopped when its input
                // queues are empty and it has no outstanding responses. Hence,
                // if we receive a response for a stopped canister then that is
                // a either a bug in the code or potentially a faulty (or
                // malicious) subnet generating spurious messages.
                error!(
                    self.log,
                    "Stopped canister got a response.  originator {} respondent {}.",
                    resp.originator,
                    resp.respondent,
                );
                return (
                    false,
                    EarlyResult::new(ExecuteMessageResult {
                        canister,
                        num_instructions_left: cycles,
                        ingress_status: None,
                        heap_delta: NumBytes::from(0),
                    }),
                );
            }
            CanisterStatusType::Running | CanisterStatusType::Stopping => {
                // We are sure there's a call context manager since the canister isn't stopped.
                canister.system_state.call_context_manager_mut().unwrap()
            }
        };

        let callback = match call_context_manager
            .unregister_callback(resp.originator_reply_callback)
        {
            Some(callback) => callback,
            None => {
                // Received an unknown callback ID. Nothing to do.
                error!(
                    self.log,
                    "Canister got a response with unknown callback ID {}.  originator {} respondent {}.",
                    resp.originator_reply_callback,
                    resp.originator,
                    resp.respondent,
                );
                return (
                    false,
                    EarlyResult::new(ExecuteMessageResult {
                        canister,
                        num_instructions_left: cycles,
                        ingress_status: None,
                        heap_delta: NumBytes::from(0),
                    }),
                );
            }
        };

        let call_context_id = callback.call_context_id;
        let call_context = match call_context_manager.call_context(call_context_id) {
            Some(call_context) => call_context,
            None => {
                // Unknown call context. Nothing to do.
                error!(
                    self.log,
                    "Canister got a response for unknown request.  originator {} respondent {} callback id {}.",
                    resp.originator,
                    resp.respondent,
                    resp.originator_reply_callback,
                );
                return (
                    false,
                    EarlyResult::new(ExecuteMessageResult {
                        canister,
                        num_instructions_left: cycles,
                        ingress_status: None,
                        heap_delta: NumBytes::from(0),
                    }),
                );
            }
        };
        let call_origin = call_context.call_origin().clone();
        let is_call_context_deleted = call_context.is_deleted();
        let num_outstanding_calls = call_context_manager.outstanding_calls(call_context_id);

        // Canister A sends a request to canister B with some cycles.
        // Canister B can accept a subset of the cycles in the request.
        // The unaccepted cycles are returned to A in the response.
        //
        // Therefore, the number of cycles in the response should always
        // be <= to the cycles in the request. If this is not the case,
        // then that indiciates (potential malicious) faults.
        let refunded_cycles = if resp.refund.cycles() > callback.cycles_sent {
            error!(
                self.log,
                "Canister got a response with too many cycles.  originator {} respondent {} max cycles expected {} got {}.",
                resp.originator,
                resp.respondent,
                callback.cycles_sent,
                resp.refund.cycles(),
            );
            callback.cycles_sent
        } else {
            resp.refund.take_cycles()
        };
        self.cycles_account_manager
            .add_cycles(&mut canister.system_state, refunded_cycles);

        // The canister that sends a request must also pay the fee for
        // the transmission of the response. As we do not know how big
        // the response might be, we reserve cycles for the largest
        // possible response when the request is being sent. Now that we
        // have received the response, we can refund the cycles based on
        // the actual size of the response.
        self.cycles_account_manager
            .response_cycles_refund(&mut canister.system_state, &mut resp);

        if is_call_context_deleted {
            // If the call context was deleted (e.g. in uninstall), then do not execute
            // anything. The call context is completely removed if there are no
            // outstanding callbacks.
            if num_outstanding_calls == 0 {
                // NOTE: This unwrap is safe since we acquired the call context earlier.
                canister
                    .system_state
                    .call_context_manager_mut()
                    .unwrap()
                    .unregister_call_context(call_context_id);
            }

            (
                true,
                EarlyResult::new(ExecuteMessageResult {
                    canister,
                    num_instructions_left: cycles,
                    ingress_status: None,
                    heap_delta: NumBytes::from(0),
                }),
            )
        } else {
            let output = self.hypervisor.execute_callback(
                canister,
                &call_origin,
                callback,
                resp.response_payload,
                refunded_cycles,
                cycles,
                time,
                routing_table,
                subnet_records,
                subnet_available_memory,
            );

            let log = self.log.clone();
            (
                true,
                output.and_then(move |(mut canister, cycles, heap_delta, result)| {
                    let action = canister
                        .system_state
                        .call_context_manager_mut()
                        .unwrap()
                        .on_canister_result(call_context_id, result);

                    let ingress_status = match call_origin {
                        CallOrigin::Ingress(user_id, message_id) => {
                            get_ingress_status(&mut canister, user_id, action, message_id, time)
                        }
                        CallOrigin::CanisterUpdate(caller_canister_id, callback_id) => {
                            produce_inter_canister_response(
                                &mut canister,
                                action,
                                caller_canister_id,
                                callback_id,
                            );
                            None
                        }
                        CallOrigin::CanisterQuery(_, _) | CallOrigin::Query(_) => fatal!(log,
                        "The update path should not have created a callback with a query origin",
                    ),
                        CallOrigin::Heartbeat => {
                            // Since heartbeat messages are invoked by the system as opposed
                            // to a principal, they cannot respond since there's no one to
                            // respond to. Do nothing.
                            None
                        }
                    };
                    ExecuteMessageResult {
                        canister,
                        num_instructions_left: cycles,
                        ingress_status,
                        heap_delta,
                    }
                }),
            )
        }
    }

    // Execute an inter-canister request.
    #[allow(clippy::too_many_arguments)]
    fn execute_canister_request(
        &self,
        canister: CanisterState,
        req: Request,
        cycles: NumInstructions,
        time: Time,
        routing_table: Arc<RoutingTable>,
        subnet_records: Arc<BTreeMap<SubnetId, SubnetType>>,
        subnet_available_memory: SubnetAvailableMemory,
    ) -> ExecResult<ExecuteMessageResult<CanisterState>> {
        if CanisterStatusType::Running != canister.status() {
            // Canister isn't running. Reject the request.
            let canister_id = canister.canister_id();
            return EarlyResult::new(self.reject_request(
                canister,
                cycles,
                req,
                RejectContext {
                    code: RejectCode::SysFatal,
                    message: format!("Canister {} is not running", canister_id),
                },
                NumBytes::from(0),
            ));
        }

        if canister.exports_query_method(req.method_name.clone()) {
            self.execute_query_method_for_request(canister, req, cycles, time)
        } else {
            self.execute_update_method_for_request(
                canister,
                req,
                cycles,
                time,
                routing_table,
                subnet_records,
                subnet_available_memory,
            )
        }
    }

    // Helper function to produce a reject `Response` for a given `Request`.
    fn reject_request(
        &self,
        mut canister: CanisterState,
        num_instructions_left: NumInstructions,
        req: Request,
        reject_context: RejectContext,
        heap_delta: NumBytes,
    ) -> ExecuteMessageResult<CanisterState> {
        canister.push_output_response(Response {
            originator: req.sender,
            respondent: canister.canister_id(),
            originator_reply_callback: req.sender_reply_callback,
            refund: req.payment,
            response_payload: Payload::Reject(reject_context),
        });

        ExecuteMessageResult {
            canister,
            num_instructions_left,
            ingress_status: None,
            heap_delta,
        }
    }

    // Execute an update method from an inter-canister request.
    #[allow(clippy::too_many_arguments)]
    fn execute_update_method_for_request(
        &self,
        canister: CanisterState,
        req: Request,
        cycles: NumInstructions,
        time: Time,
        routing_table: Arc<RoutingTable>,
        subnet_records: Arc<BTreeMap<SubnetId, SubnetType>>,
        subnet_available_memory: SubnetAvailableMemory,
    ) -> ExecResult<ExecuteMessageResult<CanisterState>> {
        let sender = req.sender;
        let reply_callback = req.sender_reply_callback;

        let output = self.hypervisor.execute_update(
            canister,
            RequestOrIngress::Request(req),
            cycles,
            time,
            routing_table,
            subnet_records,
            subnet_available_memory,
        );
        output.and_then(move |(mut canister, cycles, action, heap_delta)| {
            produce_inter_canister_response(&mut canister, action, sender, reply_callback);
            ExecuteMessageResult {
                canister,
                num_instructions_left: cycles,
                ingress_status: None,
                heap_delta,
            }
        })
    }

    // Execute a query method from an inter-canister request.
    fn execute_query_method_for_request(
        &self,
        canister: CanisterState,
        req: Request,
        cycles: NumInstructions,
        time: Time,
    ) -> ExecResult<ExecuteMessageResult<CanisterState>> {
        let output = self.hypervisor.execute_query(
            QueryExecutionType::Replicated,
            req.method_name.as_str(),
            req.method_payload.as_slice(),
            *req.sender.get_ref(),
            cycles,
            canister,
            None,
            time,
        );
        let log = self.log.clone();
        output.and_then(move |(mut canister, cycles, result)| {
            let result = result
                .map_err(|err| log_and_transform_to_user_error(&log, err, &canister.canister_id()));
            let response_payload = Payload::from(result);

            canister.push_output_response(Response {
                originator: req.sender,
                respondent: canister.canister_id(),
                originator_reply_callback: req.sender_reply_callback,
                refund: Funds::zero(),
                response_payload,
            });
            ExecuteMessageResult {
                canister,
                num_instructions_left: cycles,
                ingress_status: None,
                heap_delta: NumBytes::from(0),
            }
        })
    }

    // Execute an ingress message.
    #[allow(clippy::too_many_arguments)]
    fn execute_ingress(
        &self,
        canister: CanisterState,
        ingress: Ingress,
        cycles: NumInstructions,
        time: Time,
        routing_table: Arc<RoutingTable>,
        subnet_records: Arc<BTreeMap<SubnetId, SubnetType>>,
        subnet_available_memory: SubnetAvailableMemory,
    ) -> ExecResult<ExecuteMessageResult<CanisterState>> {
        if CanisterStatusType::Running != canister.status() {
            // Canister isn't running. Reject the request.
            let canister_id = canister.canister_id();
            return EarlyResult::new(ExecuteMessageResult {
                canister,
                num_instructions_left: cycles,
                ingress_status: Some((
                    ingress.message_id,
                    IngressStatus::Failed {
                        receiver: canister_id.get(),
                        user_id: ingress.source,
                        error: UserError::new(
                            ErrorCode::CanisterStopped,
                            format!(
                                "Canister {} is not running and cannot accept ingress messages.",
                                canister_id,
                            ),
                        ),
                        time,
                    },
                )),
                heap_delta: NumBytes::from(0),
            });
        }

        // Scheduler must ensure that this function is never called for expired
        // messages.
        assert!(ingress.expiry_time >= time);

        if canister.exports_query_method(ingress.method_name.clone()) {
            self.execute_query_method_for_ingress(canister, ingress, cycles, time)
        } else {
            self.execute_update_method_for_ingress(
                canister,
                ingress,
                cycles,
                time,
                routing_table,
                subnet_records,
                subnet_available_memory,
            )
        }
    }

    // Execute an update method from an ingress message.
    #[allow(clippy::too_many_arguments)]
    fn execute_update_method_for_ingress(
        &self,
        canister: CanisterState,
        ingress: Ingress,
        cycles: NumInstructions,
        time: Time,
        routing_table: Arc<RoutingTable>,
        subnet_records: Arc<BTreeMap<SubnetId, SubnetType>>,
        subnet_available_memory: SubnetAvailableMemory,
    ) -> ExecResult<ExecuteMessageResult<CanisterState>> {
        let message_id = ingress.message_id.clone();
        let source = ingress.source;

        let output = self.hypervisor.execute_update(
            canister,
            RequestOrIngress::Ingress(ingress),
            cycles,
            time,
            routing_table,
            subnet_records,
            subnet_available_memory,
        );

        output.and_then(move |(mut canister, cycles, action, heap_delta)| {
            let ingress_status =
                get_ingress_status(&mut canister, source, action, message_id, time);
            ExecuteMessageResult {
                canister,
                num_instructions_left: cycles,
                ingress_status,
                heap_delta,
            }
        })
    }

    // Execute a query call from an ingress message.
    fn execute_query_method_for_ingress(
        &self,
        canister: CanisterState,
        ingress: Ingress,
        cycles: NumInstructions,
        time: Time,
    ) -> ExecResult<ExecuteMessageResult<CanisterState>> {
        let output = self.hypervisor.execute_query(
            QueryExecutionType::Replicated,
            ingress.method_name.as_str(),
            ingress.method_payload.as_slice(),
            *ingress.source.get_ref(),
            cycles,
            canister,
            None,
            time,
        );
        let log = self.log.clone();
        output.and_then(move |(canister, cycles, result)| {
            let result = result
                .map_err(|err| log_and_transform_to_user_error(&log, err, &canister.canister_id()));
            let ingress_status = match result {
                Ok(wasm_result) => match wasm_result {
                    None => IngressStatus::Failed {
                        receiver: canister.canister_id().get(),
                        user_id: ingress.source,
                        error: UserError::new(
                            ErrorCode::CanisterDidNotReply,
                            format!(
                                "Canister {} did not reply to the call",
                                canister.canister_id(),
                            ),
                        ),
                        time,
                    },
                    Some(wasm_result) => IngressStatus::Completed {
                        receiver: canister.canister_id().get(),
                        user_id: ingress.source,
                        result: wasm_result,
                        time,
                    },
                },
                Err(user_error) => IngressStatus::Failed {
                    receiver: canister.canister_id().get(),
                    user_id: ingress.source,
                    error: user_error,
                    time,
                },
            };
            ExecuteMessageResult {
                canister,
                num_instructions_left: cycles,
                ingress_status: Some((ingress.message_id, ingress_status)),
                heap_delta: NumBytes::from(0),
            }
        })
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
        refund: Funds,
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

                state.subnet_queues.push_output_response(response);
                state
            }
            RequestOrIngress::Ingress(ingress) => {
                // No funds can be included with an ingress message.
                assert_eq!(refund, Funds::zero());
                let status = match result {
                    Ok(payload) => IngressStatus::Completed {
                        receiver: ingress.receiver.get(),
                        user_id: ingress.source,
                        result: WasmResult::Reply(payload),
                        time: state.time(),
                    },
                    Err(err) => IngressStatus::Failed {
                        receiver: ingress.receiver.get(),
                        user_id: ingress.source,
                        error: err,
                        time: state.time(),
                    },
                };

                self.ingress_history_writer
                    .set_status(&mut state, ingress.message_id, status);
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
        mut state: ReplicatedState,
    ) -> ReplicatedState {
        for stop_context in stop_contexts {
            match stop_context {
                StopCanisterContext::Ingress { sender, message_id } => {
                    let time = state.time();
                    // Rejecting a stop_canister request from a user.
                    self.ingress_history_writer.set_status(
                        &mut state,
                        message_id,
                        IngressStatus::Failed {
                            receiver: IC_00.get(),
                            user_id: sender,
                            error: UserError::new(
                                ErrorCode::CanisterStoppingCancelled,
                                format!("Canister {}'s stop request was cancelled.", canister_id),
                            ),
                            time,
                        },
                    );
                }
                StopCanisterContext::Canister {
                    sender,
                    reply_callback,
                    funds,
                } => {
                    // Rejecting a stop_canister request from a canister.
                    let subnet_id_as_canister_id = CanisterId::from(self.own_subnet_id);
                    let response = Response {
                        originator: sender,
                        respondent: subnet_id_as_canister_id,
                        originator_reply_callback: reply_callback,
                        refund: funds,
                        response_payload: Payload::Reject(RejectContext {
                            code: RejectCode::CanisterReject,
                            message: format!("Canister {}'s stop request cancelled", canister_id),
                        }),
                    };
                    state.subnet_queues.push_output_response(response);
                }
            }
        }

        state
    }

    fn setup_initial_dkg(
        &self,
        msg: &RequestOrIngress,
        payload: &[u8],
        state: &mut ReplicatedState,
        rng: &mut (dyn RngCore + 'static),
    ) -> Result<(), UserError> {
        match &msg {
            RequestOrIngress::Request(request) => match SetupInitialDKGArgs::decode(payload) {
                Err(err) => Err(err.into()),
                Ok(args) => match args.get_set_of_node_ids() {
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
                        state.metadata.subnet_call_context_manager.push(
                            SubnetCallContext::SetupInitialDKGContext {
                                request: request.clone(),
                                nodes_in_target_subnet,
                                target_id: NiDkgTargetId::new(target_id),
                                registry_version: args.get_registry_version(),
                            },
                        );
                        Ok(())
                    }
                },
            },
            RequestOrIngress::Ingress(_) => Err(UserError::new(
                ErrorCode::CanisterContractViolation,
                format!(
                    "{} is called by {}. It can only be called by NNS.",
                    Ic00Method::SetupInitialDKG.to_string(),
                    msg.sender(),
                ),
            )),
        }
    }
}

fn produce_inter_canister_response(
    canister: &mut CanisterState,
    action: CallContextAction,
    originator: CanisterId,
    reply_callback_id: CallbackId,
) {
    let response_payload_and_refund = match action {
        CallContextAction::NotYetResponded | CallContextAction::AlreadyResponded => None,
        CallContextAction::NoResponse { refund } => Some((
            Payload::Reject(RejectContext {
                code: RejectCode::CanisterError,
                message: "No response".to_string(),
            }),
            refund,
        )),

        CallContextAction::Reject { payload, refund } => Some((
            Payload::Reject(RejectContext {
                code: RejectCode::CanisterReject,
                message: payload,
            }),
            refund,
        )),

        CallContextAction::Reply { payload, refund } => Some((Payload::Data(payload), refund)),

        CallContextAction::Fail { error, refund } => {
            let user_error = error.into_user_error(&canister.canister_id());
            Some((
                Payload::Reject(RejectContext {
                    code: user_error.reject_code(),
                    message: user_error.to_string(),
                }),
                refund,
            ))
        }
    };
    if let Some((response_payload, refund)) = response_payload_and_refund {
        let refunded_funds = Funds::new(refund, ICP::zero());
        canister.push_output_response(Response {
            originator,
            respondent: canister.canister_id(),
            originator_reply_callback: reply_callback_id,
            refund: refunded_funds,
            response_payload,
        });
    }
}

fn get_ingress_status(
    canister: &mut CanisterState,
    user_id: UserId,
    action: CallContextAction,
    message_id: MessageId,
    time: Time,
) -> Option<(MessageId, IngressStatus)> {
    let ingress_status = match action {
        CallContextAction::NoResponse { refund } => {
            assert_eq!(refund, Cycles::from(0));
            Some(IngressStatus::Failed {
                receiver: canister.canister_id().get(),
                user_id,
                error: UserError::new(
                    ErrorCode::CanisterDidNotReply,
                    format!(
                        "Canister {} did not reply to the call",
                        canister.canister_id()
                    ),
                ),
                time,
            })
        }
        CallContextAction::Reply { payload, refund } => {
            assert_eq!(refund, Cycles::from(0));
            Some(IngressStatus::Completed {
                receiver: canister.canister_id().get(),
                user_id,
                result: WasmResult::Reply(payload),
                time,
            })
        }
        CallContextAction::Reject { payload, refund } => {
            assert_eq!(refund, Cycles::from(0));
            Some(IngressStatus::Completed {
                receiver: canister.canister_id().get(),
                user_id,
                result: WasmResult::Reject(payload),
                time,
            })
        }
        CallContextAction::Fail { error, refund } => {
            assert_eq!(refund, Cycles::from(0));
            Some(IngressStatus::Failed {
                receiver: canister.canister_id().get(),
                user_id,
                error: error.into_user_error(&canister.canister_id()),
                time,
            })
        }
        CallContextAction::NotYetResponded => Some(IngressStatus::Processing {
            receiver: canister.canister_id().get(),
            user_id,
            time,
        }),
        CallContextAction::AlreadyResponded => None,
    };
    ingress_status.map(|status| (message_id, status))
}

fn log_and_transform_to_user_error(
    log: &ReplicaLogger,
    hypervisor_err: HypervisorError,
    canister_id: &CanisterId,
) -> UserError {
    let user_error = hypervisor_err.into_user_error(canister_id);
    info!(
        log,
        "Executing message on {} failed with {:?}", canister_id, user_error
    );
    user_error
}
