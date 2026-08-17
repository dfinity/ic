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
use ic_config::flag_status::FlagStatus;
use ic_error_types::{ErrorCode, UserError};
use ic_management_canister_types_private::{
    CanisterIdRecord, CanisterInfoRequest, CanisterMetricsArgs, FetchCanisterLogsRequest,
    Method as Ic00Method, Payload, QueryMethod,
};
use ic_replicated_state::{CanisterState, ReplicatedState};
use ic_types::{CanisterId, NumInstructions};
use std::str::FromStr;

/// A management canister method that a composite query may call.
pub(super) enum CompositeQueryMethod {
    /// Also reachable by a query addressed directly to the management
    /// canister.
    User(QueryMethod),
    /// A non-replicated HTTP outcall, reachable only from a composite query:
    /// it is performed on behalf of a calling canister.
    HttpRequest,
}

/// Parses a method name that an end user addressed directly to the management
/// canister.
///
/// Returns a [`QueryMethod`], which has no HTTP-outcall variant: were
/// `http_request` reachable here, anyone could make this node fetch an
/// arbitrary URL on behalf of no canister at all. Do not add one to dedupe with
/// [`parse_composite_query_method`] — the exhaustive match in
/// [`execute_subnet_query`] is a tripwire that forces the decision under
/// review.
pub(super) fn parse_user_query_method(method_name: &str) -> Result<QueryMethod, UserError> {
    QueryMethod::from_str(method_name).map_err(|_| method_not_found(method_name))
}

/// Parses a method name that a composite query called on the management
/// canister.
///
/// While `query_http_requests` is disabled, `http_request` is not recognised at
/// all, so the rejection is indistinguishable from any other unknown method.
pub(super) fn parse_composite_query_method(
    method_name: &str,
    query_http_requests: FlagStatus,
) -> Result<CompositeQueryMethod, UserError> {
    if query_http_requests == FlagStatus::Enabled
        && Ic00Method::from_str(method_name) == Ok(Ic00Method::HttpRequest)
    {
        return Ok(CompositeQueryMethod::HttpRequest);
    }

    parse_user_query_method(method_name).map(CompositeQueryMethod::User)
}

fn method_not_found(method_name: &str) -> UserError {
    UserError::new(
        ErrorCode::CanisterMethodNotFound,
        format!("Query method {method_name} not found."),
    )
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
