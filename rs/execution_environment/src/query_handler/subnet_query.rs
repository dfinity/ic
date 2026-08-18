//! This module implements the execution of the management canister query
//! methods.
//!
//! The same code is used for queries sent by end users directly to the
//! management canister and for calls to the management canister made by
//! composite queries.

use crate::CanisterManager;
use crate::canister_logs::fetch_canister_logs_response;
use crate::execution::common::{canister_info, list_canisters};
use candid::Encode;
use ic_base_types::PrincipalId;
use ic_error_types::{ErrorCode, UserError};
use ic_management_canister_types_private::{
    CanisterIdRecord, CanisterInfoRequest, CanisterMetricsArgs, FetchCanisterLogsRequest, Payload,
    QueryMethod,
};
use ic_replicated_state::{CanisterState, ReplicatedState};
use ic_types::{CanisterId, NumInstructions};
use std::str::FromStr;

/// Parses the given method name as a management canister query method.
pub(super) fn parse_query_method(method_name: &str) -> Result<QueryMethod, UserError> {
    QueryMethod::from_str(method_name).map_err(|_| {
        UserError::new(
            ErrorCode::CanisterMethodNotFound,
            format!("Query method {method_name} not found."),
        )
    })
}

/// Executes the given management canister query method against the given state
/// on behalf of the given caller.
///
/// Returns the encoded reply and the number of instructions consumed while
/// producing it.
pub(super) fn execute_subnet_query(
    canister_manager: &CanisterManager,
    state: &ReplicatedState,
    caller: PrincipalId,
    method: QueryMethod,
    payload: &[u8],
) -> Result<(Vec<u8>, NumInstructions), UserError> {
    match method {
        QueryMethod::FetchCanisterLogs => {
            let args = FetchCanisterLogsRequest::decode(payload)?;
            let canister = get_canister(state, args.get_canister_id())?;
            fetch_canister_logs_response(caller, canister, args).map_err(UserError::from)
        }
        QueryMethod::CanisterStatus => {
            let args = CanisterIdRecord::decode(payload)?;
            let canister_id = args.get_canister_id();
            let ready_for_migration = state.ready_for_migration(&canister_id);
            let canister = get_canister(state, canister_id)?;
            let response = canister_manager.get_canister_status(
                caller,
                canister,
                state.get_own_subnet_cycles_config(),
                ready_for_migration,
                state.get_own_subnet_admins(),
            )?;
            Ok((Encode!(&response).unwrap(), NumInstructions::new(0)))
        }
        QueryMethod::CanisterInfo => {
            let args = CanisterInfoRequest::decode(payload)?;
            let canister = get_canister(state, args.canister_id())?;
            let response = canister_info(canister, args.num_requested_changes());
            Ok((Encode!(&response).unwrap(), NumInstructions::new(0)))
        }
        QueryMethod::ListCanisters => list_canisters(state, &caller, payload),
        QueryMethod::CanisterMetrics => {
            let args = CanisterMetricsArgs::decode(payload)?;
            let canister = get_canister(state, args.get_canister_id())?;
            let response = canister_manager.get_canister_metrics(
                caller,
                canister,
                state.get_own_subnet_admins(),
            )?;
            Ok((Encode!(&response).unwrap(), NumInstructions::new(0)))
        }
    }
}

fn get_canister(
    state: &ReplicatedState,
    canister_id: CanisterId,
) -> Result<&CanisterState, UserError> {
    state.canister_state(&canister_id).ok_or_else(|| {
        UserError::new(
            ErrorCode::CanisterNotFound,
            format!("Canister {canister_id} not found"),
        )
    })
}
