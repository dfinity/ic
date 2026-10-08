// This module defines common helper functions.
// TODO(RUN-60): Move helper functions here.

use crate::canister_logs::check_log_visibility_permission;
use crate::execution_environment::ExecutionResponse;
use crate::util::{GOVERNANCE_CANISTER_ID, MIGRATION_CANISTER_ID};
use crate::{
    ExecuteMessageResult, HypervisorMetrics, RoundLimits, as_round_instructions,
    canister_manager::types::CanisterManagerError, metrics::CallTreeMetrics,
};
use candid::Encode;
use ic_base_types::{CanisterId, NumBytes, SubnetId};
use ic_embedders::{
    wasm_executor::{CanisterStateChanges, ExecutionStateChanges, SliceExecutionOutput},
    wasmtime_embedder::system_api::sandbox_safe_system_state::{
        RequestMetadataStats, SystemStateModifications,
    },
};
use ic_error_types::{ErrorCode, RejectCode, UserError};
use ic_interfaces::execution_environment::{
    HypervisorError, HypervisorResult, SubnetAvailableMemory, WasmExecutionOutput,
};
use ic_logger::{ReplicaLogger, error, fatal, info, warn};
use ic_management_canister_types_private::{
    CanisterIdRange, CanisterInfoResponse, CanisterStatusType, EmptyBlob, ListCanistersResponse,
    Method as Ic00Method, Payload as _,
};
use ic_registry_routing_table::canister_id_into_u64;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    CallContext, CallContextAction, CallOrigin, CanisterState, ExecutionState, NetworkTopology,
    ReplicatedState, SystemState, metadata_state::can_have_subnet_admins,
};
use ic_types::ingress::{IngressState, IngressStatus, WasmResult};
use ic_types::messages::{
    CallContextId, CallbackId, CanisterCall, CanisterCallOrTask, MessageId, Payload, RejectContext,
    Response,
};
use ic_types::methods::{Callback, WasmMethod};
use ic_types::time::CoarseTime;
use ic_types::{NumInstructions, PrincipalId, Time, UserId};
use ic_types_cycles::{CanisterCyclesCostSchedule, Cycles};
use lazy_static::lazy_static;
use prometheus::IntCounter;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

lazy_static! {
    /// Track how many system task errors have been encountered
    /// so that we can restrict logging to a sample of them.
    static ref SYSTEM_TASK_ERROR_COUNT: AtomicU64 = AtomicU64::new(0);
}

/// How often system task errors should be logged to avoid overloading the logs.
const LOG_ONE_SYSTEM_TASK_OUT_OF: u64 = 100;
/// How many first system task messages to log unconditionally.
const LOG_FIRST_N_SYSTEM_TASKS: u64 = 50;

pub(crate) fn action_to_response(
    canister: &CanisterState,
    action: CallContextAction,
    call_origin: CallOrigin,
    time: Time,
    log: &ReplicaLogger,
    ingress_with_cycles_error: &IntCounter,
) -> ExecutionResponse {
    match call_origin {
        CallOrigin::Ingress(user_id, message_id, _method_name) => action_to_ingress_response(
            &canister.canister_id(),
            user_id,
            action,
            message_id,
            time,
            log,
            ingress_with_cycles_error,
        ),
        CallOrigin::CanisterUpdate(caller_canister_id, callback_id, deadline, _method_name) => {
            action_to_request_response(canister, action, caller_canister_id, callback_id, deadline)
        }
        CallOrigin::CanisterQuery(..) | CallOrigin::Query(..) => fatal!(
            log,
            "The update path should not have created a callback with a query origin",
        ),
        CallOrigin::SystemTask => {
            // System task is either a Heartbeat or a GlobalTimer.
            // Since system tasks are invoked by the system as opposed
            // to a principal, they cannot respond since there's no one to
            // respond to. Do nothing.
            ExecutionResponse::Empty
        }
    }
}

pub(crate) fn action_to_request_response(
    canister: &CanisterState,
    action: CallContextAction,
    originator: CanisterId,
    reply_callback_id: CallbackId,
    deadline: CoarseTime,
) -> ExecutionResponse {
    let (response_payload, refund) = match action {
        CallContextAction::NotYetResponded | CallContextAction::AlreadyResponded => {
            return ExecutionResponse::Empty;
        }

        CallContextAction::NoResponse { refund } => (
            Payload::Reject(RejectContext::new(RejectCode::CanisterError, "No response")),
            refund,
        ),

        CallContextAction::Reject { payload, refund } => (
            Payload::Reject(RejectContext::new(RejectCode::CanisterReject, payload)),
            refund,
        ),

        CallContextAction::Reply { payload, refund } => (Payload::Data(payload), refund),

        CallContextAction::Fail { error, refund } => {
            let user_error = error.into_user_error(&canister.canister_id());
            (
                Payload::Reject(RejectContext::new(user_error.reject_code(), user_error)),
                refund,
            )
        }
    };

    ExecutionResponse::Request(Response {
        originator,
        respondent: canister.canister_id(),
        originator_reply_callback: reply_callback_id,
        refund,
        response_payload,
        deadline,
    })
}

pub(crate) fn action_to_ingress_response(
    canister_id: &CanisterId,
    user_id: UserId,
    action: CallContextAction,
    message_id: MessageId,
    time: Time,
    log: &ReplicaLogger,
    ingress_with_cycles_error: &IntCounter,
) -> ExecutionResponse {
    let mut refund_amount = Cycles::zero();
    let receiver = canister_id.get();
    let ingress_status = match action {
        CallContextAction::NoResponse { refund } => {
            refund_amount = refund;
            Some(IngressStatus::Known {
                receiver,
                user_id,
                time,
                state: IngressState::Failed(UserError::new(
                    ErrorCode::CanisterDidNotReply,
                    format!("Canister {canister_id} did not reply to the call"),
                )),
            })
        }
        CallContextAction::Reply { payload, refund } => {
            refund_amount = refund;
            Some(IngressStatus::Known {
                receiver,
                user_id,
                time,
                state: IngressState::Completed(WasmResult::Reply(payload)),
            })
        }
        CallContextAction::Reject { payload, refund } => {
            refund_amount = refund;
            Some(IngressStatus::Known {
                receiver,
                user_id,
                time,
                state: IngressState::Completed(WasmResult::Reject(payload)),
            })
        }
        CallContextAction::Fail { error, refund } => {
            refund_amount = refund;
            Some(IngressStatus::Known {
                receiver,
                user_id,
                time,
                state: IngressState::Failed(error.into_user_error(canister_id)),
            })
        }
        CallContextAction::NotYetResponded => Some(IngressStatus::Known {
            receiver,
            user_id,
            time,
            state: IngressState::Processing,
        }),
        CallContextAction::AlreadyResponded => None,
    };
    debug_assert!(refund_amount.is_zero());
    if !refund_amount.is_zero() {
        ingress_with_cycles_error.inc();
        warn!(
            log,
            "[EXC-BUG] No funds can be included with an ingress message: user {}, canister_id {}, message_id {}.",
            user_id,
            canister_id,
            message_id
        );
    }
    match ingress_status {
        Some(status) => ExecutionResponse::Ingress((message_id, status)),
        None => ExecutionResponse::Empty,
    }
}

/// Returns an ingress status with the `Processing` ingress state if the
/// original message was an ingress message.
/// Otherwise, returns `None`.
pub(crate) fn ingress_status_with_processing_state(
    message: &CanisterCall,
    time: Time,
) -> Option<(MessageId, IngressStatus)> {
    match message {
        CanisterCall::Ingress(ingress) => Some((
            ingress.message_id.clone(),
            IngressStatus::Known {
                receiver: ingress.receiver.get(),
                user_id: ingress.source,
                time,
                state: IngressState::Processing,
            },
        )),
        CanisterCall::Request(_) => None,
    }
}

pub(crate) fn wasm_result_to_query_response(
    result: Result<Option<WasmResult>, UserError>,
    canister: &CanisterState,
    time: Time,
    call_origin: CallOrigin,
    log: &ReplicaLogger,
    refund: Cycles,
) -> ExecutionResponse {
    match call_origin {
        CallOrigin::Ingress(user_id, message_id, _method_name) => {
            wasm_result_to_ingress_response(result, canister, user_id, message_id, time)
        }
        CallOrigin::CanisterUpdate(caller_canister_id, callback_id, deadline, _method_name) => {
            let response = Response {
                originator: caller_canister_id,
                respondent: canister.canister_id(),
                originator_reply_callback: callback_id,
                refund,
                response_payload: Payload::from(result),
                deadline,
            };
            ExecutionResponse::Request(response)
        }
        CallOrigin::CanisterQuery(..) | CallOrigin::Query(..) => {
            fatal!(log, "The update path should not have a query origin",)
        }
        CallOrigin::SystemTask => {
            // System task is either a Heartbeat or a GlobalTimer.
            // Since system tasks are invoked by the system as opposed
            // to a principal, they cannot respond since there's no one to
            // respond to. Do nothing.
            ExecutionResponse::Empty
        }
    }
}

pub(crate) fn wasm_result_to_ingress_response(
    result: Result<Option<WasmResult>, UserError>,
    canister: &CanisterState,
    user_id: UserId,
    msg_id: MessageId,
    time: Time,
) -> ExecutionResponse {
    let ingress_status = match result {
        Ok(wasm_result) => match wasm_result {
            None => IngressStatus::Known {
                receiver: canister.canister_id().get(),
                user_id,
                time,
                state: IngressState::Failed(UserError::new(
                    ErrorCode::CanisterDidNotReply,
                    format!(
                        "Canister {} did not reply to the call",
                        canister.canister_id(),
                    ),
                )),
            },
            Some(wasm_result) => IngressStatus::Known {
                receiver: canister.canister_id().get(),
                user_id,
                time,
                state: IngressState::Completed(wasm_result),
            },
        },
        Err(user_error) => IngressStatus::Known {
            receiver: canister.canister_id().get(),
            user_id,
            time,
            state: IngressState::Failed(user_error),
        },
    };

    ExecutionResponse::Ingress((msg_id, ingress_status))
}

pub(crate) fn validate_method(
    method: &WasmMethod,
    canister: &CanisterState,
) -> Result<(), HypervisorError> {
    match canister.execution_state.as_ref() {
        None => return Err(HypervisorError::WasmModuleNotFound),
        Some(es) => {
            if !es.exports_method(method) {
                return Err(HypervisorError::MethodNotFound(method.clone()));
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_message(
    canister: &CanisterState,
    wasm_method: &WasmMethod,
) -> Result<(), UserError> {
    validate_canister(canister)?;

    validate_method(wasm_method, canister)
        .map_err(|err| err.into_user_error(&canister.canister_id()))?;

    Ok(())
}

pub(crate) fn validate_canister(canister: &CanisterState) -> Result<(), UserError> {
    if CanisterStatusType::Running != canister.status() {
        let canister_id = canister.canister_id();
        let err_code = match canister.status() {
            CanisterStatusType::Running => unreachable!(),
            CanisterStatusType::Stopping => ErrorCode::CanisterStopping,
            CanisterStatusType::Stopped => ErrorCode::CanisterStopped,
        };
        let err_msg = format!("Canister {canister_id} is not running");
        return Err(UserError::new(err_code, err_msg));
    }
    Ok(())
}

fn validate_controller(
    canister: &CanisterState,
    controller: &PrincipalId,
) -> Result<(), CanisterManagerError> {
    if !canister.controllers().contains(controller) {
        return Err(CanisterManagerError::CanisterInvalidController {
            canister_id: canister.canister_id(),
            controllers_expected: canister.system_state.controllers.clone(),
            controller_provided: *controller,
        });
    }
    Ok(())
}

fn validate_snapshot_visibility(
    canister: &CanisterState,
    caller: &PrincipalId,
    method_name: &str,
) -> Result<(), CanisterManagerError> {
    if !crate::canister_settings::VisibilitySettings::from(canister.snapshot_visibility())
        .has_access(caller, canister.controllers())
    {
        return Err(CanisterManagerError::CanisterSnapshotAccessDenied {
            caller: *caller,
            method_name: method_name.to_string(),
        });
    }
    Ok(())
}

/// Validates that the `caller` is allowed to read the status of the `canister`
/// according to its canister status visibility settings.
///
/// Subnet admins always retain access; otherwise access is governed by the
/// status visibility setting, which grants access to the controllers plus any
/// additional allowed viewers (or everyone, if the status is public).
fn validate_status_visibility(
    canister: &CanisterState,
    subnet_admins: Option<BTreeSet<PrincipalId>>,
    caller: &PrincipalId,
) -> Result<(), CanisterManagerError> {
    // Subnet admins always retain access to the canister status.
    if let Some(subnet_admins) = &subnet_admins
        && subnet_admins.contains(caller)
    {
        return Ok(());
    }
    // Otherwise, access is governed by the status visibility setting.
    if crate::canister_settings::VisibilitySettings::from(canister.status_visibility())
        .has_access(caller, canister.controllers())
    {
        return Ok(());
    }
    Err(CanisterManagerError::CanisterStatusAccessDenied { caller: *caller })
}

pub(crate) fn validate_subnet_admin(
    subnet_admins: &BTreeSet<PrincipalId>,
    sender: &PrincipalId,
) -> Result<(), CanisterManagerError> {
    if subnet_admins.contains(sender) {
        Ok(())
    } else {
        Err(CanisterManagerError::InvalidSubnetAdmin {
            subnet_admins_expected: subnet_admins.clone(),
            caller: *sender,
        })
    }
}

fn validate_controller_or_subnet_admin(
    canister: &CanisterState,
    subnet_admins: Option<BTreeSet<PrincipalId>>,
    sender: &PrincipalId,
) -> Result<(), CanisterManagerError> {
    if canister.controllers().contains(sender) {
        Ok(())
    } else if let Some(subnet_admins) = subnet_admins {
        if subnet_admins.contains(sender) {
            Ok(())
        } else {
            Err(
                CanisterManagerError::CanisterInvalidControllerOrSubnetAdmin {
                    canister_id: canister.canister_id(),
                    controllers_expected: canister.system_state.controllers.clone(),
                    subnet_admins_expected: subnet_admins,
                    caller: *sender,
                },
            )
        }
    } else {
        // If subnet admins are not set, return the same error as
        // the legacy `validate_controller` would to maintain backward compatibility.
        Err(CanisterManagerError::CanisterInvalidController {
            canister_id: canister.canister_id(),
            controllers_expected: canister.system_state.controllers.clone(),
            controller_provided: *sender,
        })
    }
}

/// Validates that `sender` is allowed to call the management canister method
/// `method` targeting `canister` on a subnet of type `subnet_type` with cost
/// schedule `cost_schedule` and subnet admins `subnet_admins`.
///
/// This is the single place defining which senders can call which management
/// canister methods targeting a canister. It must be called after the method's
/// payload has been decoded and `canister` has been looked up. A method
/// targeting more than one canister must call it once per targeted canister,
/// passing the method whose permission is required on that canister (e.g.,
/// `install_chunked_code` validates its store canister as `stored_chunks`).
///
/// The `subnet_admins` are only taken into account if the subnet can have
/// subnet admins (see `can_have_subnet_admins`).
///
/// Methods that do not target a canister or whose access control does not
/// depend on the targeted canister (e.g., `create_canister`, `list_canisters`,
/// or `canister_metadata`) are rejected: their access control is implemented
/// separately and calling this function for them is a bug.
pub(crate) fn validate_sender(
    sender: &PrincipalId,
    method: Ic00Method,
    canister: &CanisterState,
    subnet_type: SubnetType,
    cost_schedule: CanisterCyclesCostSchedule,
    subnet_admins: &BTreeSet<PrincipalId>,
) -> Result<(), CanisterManagerError> {
    let subnet_admins =
        can_have_subnet_admins(subnet_type, cost_schedule).then(|| subnet_admins.clone());
    let is_sender_the_canister = *sender == canister.canister_id().get();
    match method {
        // A canister can always read its own status and manage its own chunk
        // store, as the canister is considered in the same trust domain.
        Ic00Method::CanisterStatus
        | Ic00Method::UploadChunk
        | Ic00Method::StoredChunks
        | Ic00Method::ClearChunkStore
            if is_sender_the_canister =>
        {
            Ok(())
        }

        Ic00Method::StartCanister
        | Ic00Method::StopCanister
        | Ic00Method::DeleteCanister
        | Ic00Method::CanisterMetrics => {
            validate_controller_or_subnet_admin(canister, subnet_admins, sender)
        }

        // The governance canister can forcefully uninstall the code of any canister.
        Ic00Method::UninstallCode => {
            if *sender == GOVERNANCE_CANISTER_ID.get() {
                Ok(())
            } else {
                validate_controller_or_subnet_admin(canister, subnet_admins, sender)
            }
        }

        Ic00Method::CanisterStatus => validate_status_visibility(canister, subnet_admins, sender),

        // `StoredChunks` (including the exception for the canister itself
        // above) is also used to validate the store canister of
        // `install_chunked_code`: its errors must not refer to `stored_chunks`.
        Ic00Method::UpdateSettings
        | Ic00Method::InstallCode
        | Ic00Method::InstallChunkedCode
        | Ic00Method::UploadChunk
        | Ic00Method::StoredChunks
        | Ic00Method::ClearChunkStore
        | Ic00Method::TakeCanisterSnapshot
        | Ic00Method::LoadCanisterSnapshot
        | Ic00Method::DeleteCanisterSnapshot
        | Ic00Method::UploadCanisterSnapshotMetadata
        | Ic00Method::UploadCanisterSnapshotData => validate_controller(canister, sender),

        // The sender has to be a controller of the canister to be renamed and
        // equal to the migration canister.
        Ic00Method::RenameCanister => {
            validate_controller(canister, sender)?;
            if *sender != MIGRATION_CANISTER_ID.get() {
                return Err(CanisterManagerError::CallerNotAuthorized);
            }
            Ok(())
        }

        Ic00Method::ListCanisterSnapshots
        | Ic00Method::ReadCanisterSnapshotMetadata
        | Ic00Method::ReadCanisterSnapshotData => {
            validate_snapshot_visibility(canister, sender, &method.to_string())
        }

        Ic00Method::FetchCanisterLogs => check_log_visibility_permission(
            sender,
            canister.log_visibility(),
            canister.controllers(),
        ),

        // Anyone can call these methods.
        Ic00Method::CanisterInfo | Ic00Method::DepositCycles => Ok(()),

        Ic00Method::CanisterMetadata
        | Ic00Method::ListCanisters
        | Ic00Method::CreateCanister
        | Ic00Method::HttpRequest
        | Ic00Method::FlexibleHttpRequest
        | Ic00Method::ECDSAPublicKey
        | Ic00Method::RawRand
        | Ic00Method::SetupInitialDKG
        | Ic00Method::SignWithECDSA
        | Ic00Method::ReshareChainKey
        | Ic00Method::SchnorrPublicKey
        | Ic00Method::SignWithSchnorr
        | Ic00Method::VetKdPublicKey
        | Ic00Method::VetKdDeriveKey
        | Ic00Method::BitcoinGetBalance
        | Ic00Method::BitcoinGetUtxos
        | Ic00Method::BitcoinGetBlockHeaders
        | Ic00Method::BitcoinSendTransaction
        | Ic00Method::BitcoinGetCurrentFeePercentiles
        | Ic00Method::BitcoinSendTransactionInternal
        | Ic00Method::BitcoinGetSuccessors
        | Ic00Method::NodeMetricsHistory
        | Ic00Method::SubnetMetrics
        | Ic00Method::SubnetInfo
        | Ic00Method::ProvisionalCreateCanisterWithCycles
        | Ic00Method::ProvisionalTopUpCanister => Err(CanisterManagerError::CallerNotAuthorized),
    }
}

/// Calls `validate_sender` with the subnet type, cost schedule, and subnet
/// admins of the subnet `subnet_id` in `network_topology`.
///
/// If `network_topology` does not contain the subnet `subnet_id`, then safe
/// defaults are used: an application subnet on the normal cost schedule
/// without subnet admins, i.e., a subnet on which subnet admins are not taken
/// into account (consistently with `ReplicatedState::get_own_subnet_admins`).
pub(crate) fn validate_sender_on_subnet(
    sender: &PrincipalId,
    method: Ic00Method,
    canister: &CanisterState,
    network_topology: &NetworkTopology,
    subnet_id: SubnetId,
) -> Result<(), CanisterManagerError> {
    match network_topology.subnets().get(&subnet_id) {
        Some(subnet_topology) => validate_sender(
            sender,
            method,
            canister,
            subnet_topology.subnet_type,
            subnet_topology.cost_schedule,
            &subnet_topology.subnet_admins,
        ),
        None => validate_sender(
            sender,
            method,
            canister,
            SubnetType::Application,
            CanisterCyclesCostSchedule::Normal,
            &BTreeSet::new(),
        ),
    }
}

/// Computes the response to the `canister_info` management canister method.
///
/// The method is not subject to any access control: the canister history is
/// public information that any principal is allowed to retrieve. The size of
/// the response is bounded by `MAX_CANISTER_HISTORY_CHANGES`, so producing it
/// consumes no round instructions.
///
/// This is shared by the replicated path (an inter-canister call to
/// `canister_info`) and the non-replicated path (see
/// `crate::query_handler::subnet_query`) so that both return the same response.
pub(crate) fn canister_info(
    canister: &CanisterState,
    num_requested_changes: Option<u64>,
) -> CanisterInfoResponse {
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
    CanisterInfoResponse::new(total_num_changes, changes, module_hash, controllers)
}

/// Computes the response to the `list_canisters` management canister method.
///
/// The method takes no arguments and is only available on subnets with subnet
/// admins configured, in which case the caller must be a subnet admin. On
/// success, it returns the Candid-encoded `ListCanistersResponse` listing the
/// ranges of canister IDs hosted on this subnet, together with the number of
/// round instructions the caller must deduct for computing it.
pub(crate) fn list_canisters(
    state: &ReplicatedState,
    caller: &PrincipalId,
    payload: &[u8],
) -> Result<(Vec<u8>, NumInstructions), UserError> {
    EmptyBlob::decode(payload)?;
    match state.get_own_subnet_admins() {
        Some(ref admins) => validate_subnet_admin(admins, caller).map_err(UserError::from)?,
        None => {
            return Err(UserError::new(
                ErrorCode::CanisterRejectedMessage,
                "list_canisters is only available on subnets with subnet admins",
            ));
        }
    }
    let mut canisters: Vec<CanisterIdRange> = Vec::new();
    for id in state.canister_states().all_keys() {
        let id_u64 = canister_id_into_u64(*id);
        match canisters.last_mut() {
            Some(last) if canister_id_into_u64(last.end).checked_add(1) == Some(id_u64) => {
                last.end = *id;
            }
            _ => canisters.push(CanisterIdRange {
                start: *id,
                end: *id,
            }),
        }
    }
    let response = ListCanistersResponse { canisters };
    Ok((
        Encode!(&response).unwrap(),
        list_canisters_instructions(state),
    ))
}

/// Computes the number of round instructions consumed by executing the
/// `list_canisters` management method against the given state.
///
/// The cost model was derived from the `list_canisters` benchmark using the
/// conversion `2B instructions = 1 second` (i.e. `2M instructions = 1 ms`):
///   - a base cost of 20M instructions (≈10ms), and
///   - a variable cost of 16K instructions per canister hosted on the subnet
///     (`list_canisters` iterates over all of them to build the ID ranges).
///     The variable cost reflects the worst case where the canister IDs form
///     gaps so that each canister becomes its own ID range.
// Keep in sync with `list_canisters_respects_round_instruction_limit` in
// `execution_test.rs`.
fn list_canisters_instructions(state: &ReplicatedState) -> NumInstructions {
    const BASE_INSTRUCTIONS: u64 = 20_000_000;
    const INSTRUCTIONS_PER_CANISTER: u64 = 16_000;
    let num_canisters = state.num_canisters() as u64;
    NumInstructions::new(BASE_INSTRUCTIONS + INSTRUCTIONS_PER_CANISTER * num_canisters)
}

/// Unregisters the callback corresponding to the given response.
//
// TODO(DSM-95): Consider making this only apply to non-replicated call origins.
pub fn unregister_callback(
    canister: &mut CanisterState,
    response: &Response,
    logger: &ReplicaLogger,
    unexpected_response_error: &IntCounter,
) -> Option<Arc<Callback>> {
    match canister
        .system_state
        .unregister_callback(response.originator_reply_callback)
    {
        Ok(callback) => callback,

        Err(e) => {
            // Received an unknown callback ID. Nothing to do.
            unexpected_response_error.inc();
            error!(
                logger,
                "[EXC-BUG] Canister got unexpected response: {e}.  originator {} respondent {}, deadline {:?}.",
                response.originator,
                response.respondent,
                response.deadline,
            );
            debug_assert!(false);
            None
        }
    }
}

/// Retrieves the call context corresponding to the given callback.
pub fn get_call_context(
    canister: &CanisterState,
    callback: &Callback,
    logger: &ReplicaLogger,
    unexpected_response_error: &IntCounter,
) -> Option<(CallContext, CallContextId)> {
    let call_context_manager = canister.system_state.call_context_manager().or_else(|| {
        // A canister by definition can only be stopped when no open call contexts.
        // Hence, if we receive a response for a stopped canister then that is
        // a either a bug in the code or potentially a faulty (or
        // malicious) subnet generating spurious messages.
        unexpected_response_error.inc();
        error!(
            logger,
            "[EXC-BUG] Stopped canister got a response.  originator {} respondent {} deadline {:?}.",
            canister.canister_id(),
            callback.respondent,
            callback.deadline,
        );
        debug_assert!(false);
        None
    })?;

    let call_context_id = callback.call_context_id;
    match call_context_manager.call_context(call_context_id) {
        Some(call_context) => Some((call_context.clone(), call_context_id)),
        None => {
            // Unknown call context. Nothing to do.
            unexpected_response_error.inc();
            error!(
                logger,
                "[EXC-BUG] Canister got a response for unknown request.  originator {} respondent {} deadline {:?}.",
                canister.canister_id(),
                callback.respondent,
                callback.deadline,
            );
            debug_assert!(false);
            None
        }
    }
}

pub fn update_round_limits(round_limits: &mut RoundLimits, slice: &SliceExecutionOutput) {
    round_limits.instructions -= as_round_instructions(slice.executed_instructions);
}

/// Tries to apply the given canister changes to the given system state and
/// subnet available memory. In case of an error, the partially applied changes
/// are not undone.
fn try_apply_canister_state_changes(
    system_state_modifications: SystemStateModifications,
    output: &WasmExecutionOutput,
    system_state: &mut SystemState,
    subnet_available_memory: &mut SubnetAvailableMemory,
    time: Time,
    network_topology: &NetworkTopology,
    subnet_id: SubnetId,
    is_composite_query: bool,
    metrics: &HypervisorMetrics,
    log: &ReplicaLogger,
) -> HypervisorResult<RequestMetadataStats> {
    subnet_available_memory
        .try_decrement(
            output.allocated_bytes,
            output.allocated_guaranteed_response_message_bytes,
            NumBytes::from(0),
        )
        .map_err(|_| HypervisorError::OutOfMemory)?;

    system_state_modifications.apply_changes(
        time,
        system_state,
        network_topology,
        subnet_id,
        is_composite_query,
        metrics,
        log,
    )
}

/// Applies canister state change after Wasm execution if possible.
/// Otherwise, the function sets the corresponding error in
/// `output.wasm_result`.
/// Potential causes of failure:
/// - Changes in the environment such as subnet available memory while the
///   long-execution with deterministic time slicing was in progress.
/// - A mismatch between checks dones by the Wasm executor and checks done when
///   applying the changes due to a bug.
/// - An escape from the Wasm sandbox that corrupts the execution output.
#[allow(clippy::too_many_arguments)]
pub fn apply_canister_state_changes(
    canister_state_changes: CanisterStateChanges,
    execution_state: &mut ExecutionState,
    system_state: &mut SystemState,
    output: &mut WasmExecutionOutput,
    round_limits: &mut RoundLimits,
    time: Time,
    network_topology: &NetworkTopology,
    subnet_id: SubnetId,
    metrics: &HypervisorMetrics,
    log: &ReplicaLogger,
    state_changes_error: &IntCounter,
    call_tree_metrics: &dyn CallTreeMetrics,
    call_context_creation_time: Time,
    is_composite_query: bool,
    deallocate: &dyn Fn(SystemState),
) {
    let CanisterStateChanges {
        execution_state_changes,
        system_state_modifications,
    } = canister_state_changes;

    let clean_system_state = system_state.clone();
    let clean_subnet_available_memory = round_limits.subnet_available_memory;
    let callbacks_created = system_state_modifications.callbacks_created();
    // Everything that is passed via a mutable reference in this function
    // should be cloned and restored in case of an error.
    match try_apply_canister_state_changes(
        system_state_modifications,
        output,
        system_state,
        &mut round_limits.subnet_available_memory,
        time,
        network_topology,
        subnet_id,
        is_composite_query,
        metrics,
        log,
    ) {
        Ok(request_stats) => {
            if let Some(ExecutionStateChanges {
                globals,
                wasm_memory,
                stable_memory,
            }) = execution_state_changes
            {
                execution_state.wasm_memory = wasm_memory;
                execution_state.stable_memory = stable_memory;
                execution_state.exported_globals = globals;
            }
            round_limits.subnet_available_callbacks -= callbacks_created as i64;
            deallocate(clean_system_state);

            call_tree_metrics.observe(request_stats, call_context_creation_time, time);
        }
        Err(err) => {
            debug_assert_eq!(err, HypervisorError::OutOfMemory);
            match &err {
                HypervisorError::WasmEngineError(err) => {
                    state_changes_error.inc();
                    error!(
                        log,
                        "[EXC-BUG]: Failed to apply state changes due to a bug: {}", err
                    )
                }
                HypervisorError::OutOfMemory => {
                    warn!(log, "Failed to apply state changes due to DTS: {}", err)
                }
                _ => {
                    state_changes_error.inc();
                    error!(
                        log,
                        "[EXC-BUG]: Failed to apply state changes due to an unexpected error: {}",
                        err
                    )
                }
            }
            let old_system_state = std::mem::replace(system_state, clean_system_state);
            deallocate(old_system_state);
            round_limits.subnet_available_memory = clean_subnet_available_memory;
            output.wasm_result = Err(err);
        }
    }

    // Re-evaluate the `OnLowWasmMemory` hook condition after every execution,
    // regardless of whether memory was grown (or even of success), because the
    // scheduler will sometimes "forget" a `Ready` status (if not enough cycles were
    // available to execute the hook).
    system_state.update_on_low_wasm_memory_hook_status(execution_state.wasm_memory_usage());
}

pub(crate) fn finish_call_with_error(
    user_error: UserError,
    canister: CanisterState,
    call_or_task: CanisterCallOrTask,
    instructions_used: NumInstructions,
    time: Time,
    subnet_type: SubnetType,
    log: &ReplicaLogger,
) -> ExecuteMessageResult {
    let response = match call_or_task {
        CanisterCallOrTask::Update(CanisterCall::Request(request))
        | CanisterCallOrTask::Query(CanisterCall::Request(request)) => {
            let response = Response {
                originator: request.sender,
                respondent: canister.canister_id(),
                originator_reply_callback: request.sender_reply_callback,
                refund: request.payment,
                response_payload: Payload::from(Err(user_error)),
                deadline: request.deadline,
            };
            ExecutionResponse::Request(response)
        }
        CanisterCallOrTask::Update(CanisterCall::Ingress(ingress))
        | CanisterCallOrTask::Query(CanisterCall::Ingress(ingress)) => {
            let status = IngressStatus::Known {
                receiver: canister.canister_id().get(),
                user_id: ingress.source,
                time,
                state: IngressState::Failed(user_error),
            };
            ExecutionResponse::Ingress((ingress.message_id.clone(), status))
        }
        CanisterCallOrTask::Task(task) => {
            // We should monitor all errors in the system subnets and only
            // system errors on other subnets.
            if subnet_type == SubnetType::System || user_error.is_system_error() {
                // We could improve the rate limiting using some kind of exponential backoff.
                let log_count = SYSTEM_TASK_ERROR_COUNT.fetch_add(1, Ordering::SeqCst);
                if log_count < LOG_FIRST_N_SYSTEM_TASKS
                    || log_count.is_multiple_of(LOG_ONE_SYSTEM_TASK_OUT_OF)
                {
                    warn!(
                        log,
                        "Error executing canister task {:?} on canister {} with failure `{}`",
                        task,
                        canister.canister_id(),
                        user_error;
                        messaging.canister_id => canister.canister_id().to_string(),
                    );
                }
            }
            ExecutionResponse::Empty
        }
    };
    ExecuteMessageResult::Finished {
        canister,
        response,
        instructions_used,
        heap_delta: NumBytes::from(0),
        call_duration: Some(Duration::from_secs(0)),
    }
}

/// Helper method for logging dirty pages.
pub fn log_dirty_pages(
    log: &ReplicaLogger,
    canister_id: &CanisterId,
    method_name: &str,
    dirty_pages: usize,
    instructions: NumInstructions,
) {
    let output_message = format!(
        "Executed {canister_id}::{method_name}: dirty_4kb_pages = {dirty_pages}, instructions = {instructions}"
    );
    info!(log, "{}", output_message.as_str());
    eprintln!("{output_message}");
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::metrics::CallTreeMetricsNoOp;
    use ic_base_types::NumSeconds;
    use ic_management_canister_types_private::OnLowWasmMemoryHookStatus;
    use ic_metrics::MetricsRegistry;
    use ic_replicated_state::canister_state::WASM_PAGE_SIZE_IN_BYTES;
    use ic_replicated_state::canister_state::canister_snapshots::CanisterSnapshots;
    use ic_replicated_state::{Memory, NumWasmPages, PageMap, SchedulerState};
    use ic_test_utilities_logger::with_test_replica_logger;
    use ic_test_utilities_state::{ExecutionStateBuilder, SystemStateBuilder};
    use ic_test_utilities_types::ids::subnet_test_id;
    use ic_types::messages::NO_DEADLINE;
    use ic_types::time::UNIX_EPOCH;
    use strum::IntoEnumIterator;

    #[test]
    fn test_wasm_result_to_query_response_refunds_correctly() {
        with_test_replica_logger(|log| {
            let scheduler_state = SchedulerState::default();
            let system_state = SystemState::new_running_for_testing(
                CanisterId::from_u64(42),
                CanisterId::from_u64(100).get(),
                Cycles::new(1 << 36),
                NumSeconds::new(100_000),
            );
            let canister_snapshots = CanisterSnapshots::default();

            let response = wasm_result_to_query_response(
                Err(UserError::new(
                    ic_error_types::ErrorCode::CanisterCalledTrap,
                    "",
                )),
                &CanisterState::new(system_state, None, scheduler_state, canister_snapshots),
                Time::from_nanos_since_unix_epoch(100),
                ic_replicated_state::CallOrigin::CanisterUpdate(
                    CanisterId::from_u64(123),
                    CallbackId::new(2),
                    NO_DEADLINE,
                    String::from(""),
                ),
                &log,
                Cycles::new(1000_u128),
            );

            if let ExecutionResponse::Request(response) = response {
                assert_eq!(response.refund, Cycles::new(1000_u128));
            } else {
                panic!("Unexpected response.");
            }
        })
    }

    /// Runs `apply_canister_state_changes` with a `SystemState` parameterized by
    /// `wasm_memory_threshold` / `wasm_memory_limit` / `start_status` and an
    /// `ExecutionStateChanges` whose `wasm_memory` is sized to
    /// `post_execution_wasm_pages`. Returns the resulting hook status to verify
    /// that the hook is re-evaluated against the freshly committed Wasm memory
    /// usage.
    fn run_low_wasm_memory_hook_check(
        wasm_memory_threshold: NumBytes,
        wasm_memory_limit: Option<NumBytes>,
        post_execution_wasm_pages: NumWasmPages,
        start_status: OnLowWasmMemoryHookStatus,
    ) -> OnLowWasmMemoryHookStatus {
        with_test_replica_logger(|log| {
            let mut system_state = SystemStateBuilder::default()
                .wasm_memory_threshold(wasm_memory_threshold)
                .wasm_memory_limit(wasm_memory_limit)
                .empty_task_queue_with_on_low_wasm_memory_hook_status(start_status)
                .build();
            let mut execution_state = ExecutionStateBuilder::new().build();

            let canister_state_changes = CanisterStateChanges {
                execution_state_changes: Some(ExecutionStateChanges {
                    globals: vec![],
                    wasm_memory: Memory::new(PageMap::new_for_testing(), post_execution_wasm_pages),
                    stable_memory: Memory::new_for_testing(),
                }),
                system_state_modifications: Default::default(),
            };

            let mut output = WasmExecutionOutput {
                wasm_result: Ok(None),
                num_instructions_left: NumInstructions::from(0),
                allocated_bytes: NumBytes::from(0),
                allocated_guaranteed_response_message_bytes: NumBytes::from(0),
                new_memory_usage: None,
                new_message_memory_usage: None,
                instance_stats: Default::default(),
                system_api_call_counters: Default::default(),
            };
            let mut round_limits = RoundLimits {
                instructions: as_round_instructions(NumInstructions::from(i64::MAX as u64)),
                subnet_available_memory: SubnetAvailableMemory::new_for_testing(i64::MAX, 0, 0),
                subnet_available_callbacks: i64::MAX,
                compute_allocation_used: 0,
                subnet_memory_reservation: NumBytes::from(0),
            };

            let metrics_registry = MetricsRegistry::new();
            let hypervisor_metrics = HypervisorMetrics::new(&metrics_registry);
            let state_changes_error = IntCounter::new("test_state_changes_error", "test").unwrap();

            apply_canister_state_changes(
                canister_state_changes,
                &mut execution_state,
                &mut system_state,
                &mut output,
                &mut round_limits,
                UNIX_EPOCH,
                &Default::default(),
                subnet_test_id(1),
                &hypervisor_metrics,
                &log,
                &state_changes_error,
                &CallTreeMetricsNoOp,
                UNIX_EPOCH,
                false,
                &|_| {},
            );

            system_state.task_queue.peek_hook_status()
        })
    }

    /// Returns a Wasm page count whose byte size equals `bytes` (rounded up).
    fn wasm_pages_for(bytes: u64) -> NumWasmPages {
        NumWasmPages::from(bytes.div_ceil(WASM_PAGE_SIZE_IN_BYTES as u64) as usize)
    }

    const GIB: u64 = 1 << 30;

    #[test]
    fn apply_canister_state_changes_updates_low_wasm_memory_hook() {
        let wasm_memory_threshold = NumBytes::new(GIB);
        let wasm_memory_limit = Some(NumBytes::new(3 * GIB));
        // `max_allowed_wasm_memory` = `wasm_memory_limit` - `wasm_memory_threshold`
        let max_allowed_wasm_memory = 2 * GIB;
        let unsatisfied = wasm_pages_for(max_allowed_wasm_memory);
        let satisfied = wasm_pages_for(max_allowed_wasm_memory + 1);

        use OnLowWasmMemoryHookStatus::*;
        let cases = [
            (unsatisfied, ConditionNotSatisfied, ConditionNotSatisfied),
            (unsatisfied, Ready, ConditionNotSatisfied),
            (unsatisfied, Executed, ConditionNotSatisfied),
            (satisfied, ConditionNotSatisfied, Ready),
            (satisfied, Ready, Ready),
            (satisfied, Executed, Executed),
        ];
        for (post_execution_wasm_pages, start_status, expected_status) in cases {
            let actual = run_low_wasm_memory_hook_check(
                wasm_memory_threshold,
                wasm_memory_limit,
                post_execution_wasm_pages,
                start_status,
            );
            assert_eq!(
                actual, expected_status,
                "post_pages = {post_execution_wasm_pages:?}, start = {start_status:?}",
            );
        }
    }

    #[test]
    fn apply_canister_state_changes_uses_default_4gib_limit_when_unset() {
        // When the memory limit is not set, the default Wasm memory limit is 4 GiB.
        let wasm_memory_threshold = NumBytes::new(GIB);
        let wasm_memory_limit = None;
        // `max_allowed_wasm_memory` = `wasm_memory_limit` - `wasm_memory_threshold`
        let max_allowed_wasm_memory = 3 * GIB;

        use OnLowWasmMemoryHookStatus::*;
        assert_eq!(
            run_low_wasm_memory_hook_check(
                wasm_memory_threshold,
                wasm_memory_limit,
                wasm_pages_for(max_allowed_wasm_memory),
                ConditionNotSatisfied,
            ),
            ConditionNotSatisfied,
        );
        assert_eq!(
            run_low_wasm_memory_hook_check(
                wasm_memory_threshold,
                wasm_memory_limit,
                wasm_pages_for(max_allowed_wasm_memory + 1),
                ConditionNotSatisfied,
            ),
            Ready,
        );
    }

    /// Checks which senders `validate_sender` accepts for every method it
    /// validates on every subnet type and cost schedule: subnet admins are
    /// only taken into account on rented subnets (application subnets on the
    /// free cost schedule) and on cloud engines on the free cost schedule.
    #[test]
    fn validate_sender_accepts_expected_senders() {
        let canister_id = CanisterId::from_u64(42);
        let controller = PrincipalId::new_user_test_id(1);
        let subnet_admin = PrincipalId::new_user_test_id(2);
        let stranger = PrincipalId::new_user_test_id(3);
        let canister = CanisterState::new(
            SystemState::new_running_for_testing(
                canister_id,
                controller,
                Cycles::new(1 << 36),
                NumSeconds::new(100_000),
            ),
            None,
            SchedulerState::default(),
            CanisterSnapshots::default(),
        );
        let subnet_admins = BTreeSet::from([subnet_admin]);

        // Senders (other than the controller, who is always accepted) that
        // are accepted on subnets with and without subnet admins, respectively.
        let cases: Vec<(Vec<Ic00Method>, Vec<PrincipalId>, Vec<PrincipalId>)> = vec![
            (
                vec![
                    Ic00Method::StartCanister,
                    Ic00Method::StopCanister,
                    Ic00Method::DeleteCanister,
                    Ic00Method::CanisterMetrics,
                ],
                vec![subnet_admin],
                vec![],
            ),
            (
                vec![Ic00Method::UninstallCode],
                vec![subnet_admin, GOVERNANCE_CANISTER_ID.get()],
                vec![GOVERNANCE_CANISTER_ID.get()],
            ),
            (
                vec![Ic00Method::CanisterStatus],
                vec![subnet_admin, canister_id.get()],
                vec![canister_id.get()],
            ),
            (
                vec![
                    Ic00Method::UploadChunk,
                    Ic00Method::StoredChunks,
                    Ic00Method::ClearChunkStore,
                ],
                vec![canister_id.get()],
                vec![canister_id.get()],
            ),
            (
                vec![
                    Ic00Method::UpdateSettings,
                    Ic00Method::InstallCode,
                    Ic00Method::InstallChunkedCode,
                    Ic00Method::TakeCanisterSnapshot,
                    Ic00Method::LoadCanisterSnapshot,
                    Ic00Method::DeleteCanisterSnapshot,
                    Ic00Method::UploadCanisterSnapshotMetadata,
                    Ic00Method::UploadCanisterSnapshotData,
                    Ic00Method::ListCanisterSnapshots,
                    Ic00Method::ReadCanisterSnapshotMetadata,
                    Ic00Method::ReadCanisterSnapshotData,
                    Ic00Method::FetchCanisterLogs,
                ],
                vec![],
                vec![],
            ),
        ];

        for subnet_type in SubnetType::iter() {
            for cost_schedule in [
                CanisterCyclesCostSchedule::Normal,
                CanisterCyclesCostSchedule::Free,
            ] {
                let has_subnet_admins =
                    matches!(
                        subnet_type,
                        SubnetType::Application | SubnetType::CloudEngine
                    ) && matches!(cost_schedule, CanisterCyclesCostSchedule::Free);
                for (methods, accepted_with_subnet_admins, accepted_without_subnet_admins) in &cases
                {
                    let accepted = if has_subnet_admins {
                        accepted_with_subnet_admins
                    } else {
                        accepted_without_subnet_admins
                    };
                    for method in methods {
                        for sender in [
                            controller,
                            subnet_admin,
                            stranger,
                            canister_id.get(),
                            GOVERNANCE_CANISTER_ID.get(),
                        ] {
                            let result = validate_sender(
                                &sender,
                                *method,
                                &canister,
                                subnet_type,
                                cost_schedule,
                                &subnet_admins,
                            );
                            let is_accepted = sender == controller || accepted.contains(&sender);
                            assert_eq!(
                                result.is_ok(),
                                is_accepted,
                                "method: {method}, sender: {sender}, subnet type: {subnet_type:?}, cost schedule: {cost_schedule:?}, result: {result:?}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn validate_sender_rename_canister_requires_controller_and_migration_canister() {
        let canister_id = CanisterId::from_u64(42);
        let other = PrincipalId::new_user_test_id(1);
        for sender in [MIGRATION_CANISTER_ID.get(), other] {
            for is_sender_controller in [true, false] {
                let controller = if is_sender_controller {
                    sender
                } else {
                    PrincipalId::new_user_test_id(2)
                };
                let canister = CanisterState::new(
                    SystemState::new_running_for_testing(
                        canister_id,
                        controller,
                        Cycles::new(1 << 36),
                        NumSeconds::new(100_000),
                    ),
                    None,
                    SchedulerState::default(),
                    CanisterSnapshots::default(),
                );
                let result = validate_sender(
                    &sender,
                    Ic00Method::RenameCanister,
                    &canister,
                    SubnetType::System,
                    CanisterCyclesCostSchedule::Normal,
                    &BTreeSet::new(),
                );
                let is_sender_migration_canister = sender == MIGRATION_CANISTER_ID.get();
                match (is_sender_controller, is_sender_migration_canister) {
                    (true, true) => assert_eq!(result, Ok(())),
                    (true, false) => {
                        assert_eq!(result, Err(CanisterManagerError::CallerNotAuthorized))
                    }
                    (false, _) => assert!(
                        matches!(
                            result,
                            Err(CanisterManagerError::CanisterInvalidController { .. })
                        ),
                        "sender: {sender}, result: {result:?}"
                    ),
                }
            }
        }
    }
}
