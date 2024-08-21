#[cfg(test)]
mod tests;

use crate::StateError;
use ic_interfaces::execution_environment::HypervisorError;
use ic_management_canister_types::IC_00;
use ic_protobuf::proxy::{try_from_option_field, ProxyDecodeError};
use ic_protobuf::state::canister_state_bits::v1 as pb;
use ic_protobuf::types::v1 as pb_types;
use ic_types::ingress::WasmResult;
use ic_types::messages::{
    CallContextId, CallbackId, CanisterCall, CanisterCallOrTask, MessageId, Request,
    RequestMetadata, Response, NO_DEADLINE,
};
use ic_types::methods::Callback;
use ic_types::time::CoarseTime;
use ic_types::{
    user_id_into_protobuf, user_id_try_from_protobuf, CanisterId, Cycles, Funds, NumInstructions,
    PrincipalId, Time, UserId,
};
use serde::{Deserialize, Serialize};
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::convert::{From, TryFrom, TryInto};
use std::sync::Arc;
use std::time::Duration;

/// Contains all context information related to an incoming call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallContext {
    /// Tracks relevant information about who sent the request that created the
    /// `CallContext` needed to form the eventual reply.
    call_origin: CallOrigin,

    /// A `CallContext` may still be alive after the canister has replied on it
    /// already (e.g. it replies without executing all callbacks).
    ///
    /// Tracks the current status.
    responded: bool,

    /// True if the `CallContext` associated with the callback has been deleted
    /// (e.g. during uninstall); false otherwise.
    deleted: bool,

    /// Cycles that were sent in the request that created the `CallContext`.
    available_cycles: Cycles,

    /// Point in time at which the `CallContext` was created.
    time: Time,

    /// Metadata for requests generated within this `CallContext`.
    metadata: RequestMetadata,

    /// The total number of instructions executed in the given call context.
    /// This value is used for the `ic0.performance_counter` type 1.
    instructions_executed: NumInstructions,
}

impl CallContext {
    pub fn new(
        call_origin: CallOrigin,
        responded: bool,
        deleted: bool,
        available_cycles: Cycles,
        time: Time,
        metadata: RequestMetadata,
    ) -> Self {
        Self {
            call_origin,
            responded,
            deleted,
            available_cycles,
            time,
            metadata,
            instructions_executed: NumInstructions::default(),
        }
    }

    /// Returns the available amount of cycles in this call context.
    pub fn available_cycles(&self) -> Cycles {
        self.available_cycles
    }

    /// Updates the available cycles in the `CallContext` based on how much
    /// cycles the canister requested to keep.
    ///
    /// Returns an error if `cycles` is more than what's available in the call
    /// context.
    #[allow(clippy::result_unit_err)]
    pub fn withdraw_cycles(&mut self, cycles: Cycles) -> Result<(), ()> {
        if self.available_cycles < cycles {
            return Err(());
        }
        self.available_cycles -= cycles;
        Ok(())
    }

    pub fn call_origin(&self) -> &CallOrigin {
        &self.call_origin
    }

    pub fn is_deleted(&self) -> bool {
        self.deleted
    }

    /// Mark the call context as deleted.
    pub fn mark_deleted(&mut self) {
        self.deleted = true;
    }

    pub fn has_responded(&self) -> bool {
        self.responded
    }

    /// Marks the call context as responded.
    ///
    /// DO NOT CALL THIS METHOD DIRECTLY AND DO NOT MAKE IT PUBLIC. Use
    /// `CallContextManager::mark_responded()` instead.
    fn mark_responded(&mut self) {
        self.available_cycles = Cycles::new(0);
        self.responded = true;
    }

    /// The point in time at which the call context was created.
    pub fn time(&self) -> Time {
        self.time
    }

    /// Metadata for requests generated within this `CallContext`.
    pub fn metadata(&self) -> &RequestMetadata {
        &self.metadata
    }

    /// Return the total number of instructions executed in the given call context.
    /// This value is used for the `ic0.performance_counter` type 1.
    pub fn instructions_executed(&self) -> NumInstructions {
        self.instructions_executed
    }

    /// Returns the deadline of the originating call if it's a `CanisterUpdate`;
    /// `None` for all other origins.
    pub fn deadline(&self) -> Option<CoarseTime> {
        self.call_origin.deadline()
    }
}

impl From<&CallContext> for pb::CallContext {
    fn from(item: &CallContext) -> Self {
        let funds = Funds::new(item.available_cycles);
        Self {
            call_origin: Some((&item.call_origin).into()),
            responded: item.responded,
            deleted: item.deleted,
            available_funds: Some((&funds).into()),
            time_nanos: item.time.as_nanos_since_unix_epoch(),
            metadata: Some((&item.metadata).into()),
            instructions_executed: item.instructions_executed.get(),
        }
    }
}

impl TryFrom<pb::CallContext> for CallContext {
    type Error = ProxyDecodeError;
    fn try_from(value: pb::CallContext) -> Result<Self, Self::Error> {
        let funds: Funds =
            try_from_option_field(value.available_funds, "CallContext::available_funds")?;

        Ok(Self {
            call_origin: try_from_option_field(value.call_origin, "CallContext::call_origin")?,
            responded: value.responded,
            deleted: value.deleted,
            available_cycles: funds.cycles(),
            time: Time::from_nanos_since_unix_epoch(value.time_nanos),
            metadata: value
                .metadata
                .map(From::from)
                .unwrap_or(RequestMetadata::for_new_call_tree(
                    Time::from_nanos_since_unix_epoch(0),
                )),
            instructions_executed: value.instructions_executed.into(),
        })
    }
}

/// The action the caller of `CallContext.on_canister_result` should take.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallContextAction {
    /// The canister produced a `Reply` for the request which is returned along
    /// with the remaining cycles that the canister did not accept.
    Reply { payload: Vec<u8>, refund: Cycles },
    /// The canister produced a `Reject` for the request which is returned along
    /// with all the cycles that the request initially contained.
    Reject { payload: String, refund: Cycles },
    /// The canister did not produce a `Response` or a `Reject` and will not produce
    /// one. The cycles that the sender supplied is returned.
    NoResponse { refund: Cycles },
    /// Message execution failed; the canister has not produced a `Response` or a
    /// `Reject` yet; and will not produce one.  The produced error and the cycles
    /// that the sender supplied is returned.
    Fail {
        error: HypervisorError,
        refund: Cycles,
    },
    /// The canister did not produce a `Response` or a `Reject` yet but may still
    /// produce one later.
    NotYetResponded,
    /// The canister did not produce a `Response` or a `Reject` during this
    /// execution but it produced one earlier.
    AlreadyResponded,
}

/// Call context and callback stats to initialize and validate `CanisterQueues`
/// guaranteed response memory reservation and queue capacity stats.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub(crate) struct CallContextManagerStats {
    /// The number of canister update call contexts that have not yet been responded
    /// to.
    unresponded_canister_update_call_contexts: usize,

    /// The number of guaranteed response (i.e. `deadline == NO_DEADLINE`) call
    /// contexts that have not yet been responded to.
    unresponded_guaranteed_response_call_contexts: usize,

    /// The number of guaranteed response (i.e. `deadline == NO_DEADLINE`)
    /// callbacks.
    guaranteed_response_callback_count: usize,
}

impl CallContextManagerStats {
    /// Updates the stats following the creation of a new call context.
    fn on_new_call_context(&mut self, call_origin: &CallOrigin) {
        match call_origin {
            CallOrigin::CanisterUpdate(_, _, deadline) => {
                self.unresponded_canister_update_call_contexts += 1;
                if *deadline == NO_DEADLINE {
                    self.unresponded_guaranteed_response_call_contexts += 1;
                }
            }
            CallOrigin::CanisterQuery(_, _)
            | CallOrigin::Ingress(_, _)
            | CallOrigin::Query(_)
            | CallOrigin::SystemTask => {}
        }
    }

    /// Updates the stats following a response for a call context with the given
    /// origin.
    fn on_call_context_response(&mut self, call_origin: &CallOrigin) {
        match call_origin {
            CallOrigin::CanisterUpdate(_, _, deadline) => {
                self.unresponded_canister_update_call_contexts -= 1;
                if *deadline == NO_DEADLINE {
                    self.unresponded_guaranteed_response_call_contexts -= 1;
                }
            }
            CallOrigin::CanisterQuery(_, _)
            | CallOrigin::Ingress(_, _)
            | CallOrigin::Query(_)
            | CallOrigin::SystemTask => {}
        }
    }

    /// Updates the stats following the registration of a new callback.
    fn on_register_callback(&mut self, callback: &Callback) {
        if callback.deadline == NO_DEADLINE {
            self.guaranteed_response_callback_count += 1;
        }
    }

    /// Updates the stats following the invocation of a callback.
    fn on_unregister_callback(&mut self, callback: &Callback) {
        if callback.deadline == NO_DEADLINE {
            self.guaranteed_response_callback_count -= 1;
        }
    }

    /// Calculates the stats for the given call contexts and callbacks.
    ///
    /// Time complexity: `O(N)`.
    pub(crate) fn calculate_stats(
        call_contexts: &BTreeMap<CallContextId, CallContext>,
        callbacks: &BTreeMap<CallbackId, Arc<Callback>>,
    ) -> CallContextManagerStats {
        let unresponded_canister_update_call_contexts = call_contexts
            .values()
            .filter(|call_context| !call_context.responded)
            .filter_map(|call_context| match call_context.call_origin {
                CallOrigin::CanisterUpdate(originator, _, _) => Some(originator),
                _ => None,
            })
            .count();
        let unresponded_guaranteed_response_call_contexts = call_contexts
            .values()
            .filter(|call_context| !call_context.responded)
            .filter(|call_context| {
                matches!(
                    call_context.call_origin,
                    CallOrigin::CanisterUpdate(_, _, deadline) if deadline == NO_DEADLINE
                )
            })
            .count();
        let guaranteed_response_callback_count = callbacks
            .values()
            .filter(|callback| callback.deadline == NO_DEADLINE)
            .count();

        CallContextManagerStats {
            unresponded_canister_update_call_contexts,
            unresponded_guaranteed_response_call_contexts,
            guaranteed_response_callback_count,
        }
    }

    /// Calculates the expected number of response slots (responses plus
    /// reservations) per input queue.
    ///
    /// This is the count of callbacks per respondent; except for the callback
    /// corresponding to a potential paused or aborted canister response execution
    /// (since this response was just delivered).
    ///
    /// Time complexity: `O(N)`.
    #[allow(dead_code)]
    pub(crate) fn calculate_unresponded_callbacks_per_respondent(
        callbacks: &BTreeMap<CallbackId, Arc<Callback>>,
        aborted_or_paused_response: Option<&Response>,
    ) -> BTreeMap<CanisterId, usize> {
        let mut callback_counts = callbacks.values().fold(
            BTreeMap::<CanisterId, usize>::new(),
            |mut counts, callback| {
                *counts.entry(callback.respondent).or_default() += 1;
                counts
            },
        );

        // Discount the callback corresponding to an aborted or paused response
        // execution, because this response was already delivered.
        if let Some(response) = aborted_or_paused_response {
            match callback_counts.entry(response.respondent) {
                Entry::Occupied(mut entry) => {
                    let count = entry.get_mut();
                    if *count > 1 {
                        *count -= 1;
                    } else {
                        entry.remove();
                    }
                }
                Entry::Vacant(_) => {
                    debug_assert!(
                        false,
                        "Aborted or paused DTS response with no matching callback: {:?}",
                        response
                    )
                }
            }
        }

        callback_counts
    }

    /// Calculates the expected number of response slots (responses plus
    /// reservations) per output queue corresponding to unresponded call contexts.
    ///
    /// This is the count of unresponded call contexts per originator; potentially
    /// plus one for a paused or aborted canister request execution, if any.
    ///
    /// Time complexity: `O(N)`.
    #[allow(dead_code)]
    pub(crate) fn calculate_unresponded_call_contexts_per_originator(
        call_contexts: &BTreeMap<CallContextId, CallContext>,
        aborted_or_paused_request: Option<&Request>,
    ) -> BTreeMap<CanisterId, usize> {
        let mut unresponded_canister_update_call_contexts = call_contexts
            .values()
            .filter(|call_context| !call_context.responded)
            .filter_map(|call_context| match call_context.call_origin {
                CallOrigin::CanisterUpdate(originator, _, _) => Some(originator),
                _ => None,
            })
            .fold(
                BTreeMap::<CanisterId, usize>::new(),
                |mut counts, originator| {
                    *counts.entry(originator).or_default() += 1;
                    counts
                },
            );

        // An aborted or paused request execution is equivalent to one extra unresponded
        // call context.
        if let Some(request) = aborted_or_paused_request {
            *unresponded_canister_update_call_contexts
                .entry(request.sender)
                .or_default() += 1;
        }

        unresponded_canister_update_call_contexts
    }
}

/// `CallContextManager` is the entity responsible for managing call contexts of
/// incoming calls of a canister. It must be used for opening new call contexts,
/// registering and unregistering of a callback for subsequent outgoing calls and
/// for closing call contexts.
///
/// In every method, if the provided callback or call context ID was not found
/// inside the call context manager, we panic. Since this logic is executed inside
/// the "trusted" part of the execution (after the consensus), any such error would
/// indicate an unexpected and inconsistent system state.
///
/// Conceptually, this data structure reimplements a reference counter and could
/// be replaced by an `Arc`/`Rc` smart pointer. However, serde does not play well
/// with the serialization of these pointers. In the future we might consider
/// introducing an intermediate layer between the serialization and the actual
/// working data structure, to separate these concerns.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct CallContextManager {
    next_call_context_id: u64,
    next_callback_id: u64,
    /// Maps call context to its responded status.
    call_contexts: BTreeMap<CallContextId, CallContext>,
    callbacks: BTreeMap<CallbackId, Arc<Callback>>,

    /// Guaranteed response and overall callback and call context stats.
    stats: CallContextManagerStats,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallOrigin {
    Ingress(UserId, MessageId),
    CanisterUpdate(CanisterId, CallbackId, CoarseTime),
    Query(UserId),
    CanisterQuery(CanisterId, CallbackId),
    /// System task is either a `Heartbeat` or a `GlobalTimer`.
    SystemTask,
}

impl CallOrigin {
    /// Returns the principal ID associated with this call origin.
    pub fn get_principal(&self) -> PrincipalId {
        match self {
            CallOrigin::Ingress(user_id, _) => user_id.get(),
            CallOrigin::CanisterUpdate(canister_id, _, _) => canister_id.get(),
            CallOrigin::Query(user_id) => user_id.get(),
            CallOrigin::CanisterQuery(canister_id, _) => canister_id.get(),
            CallOrigin::SystemTask => IC_00.get(),
        }
    }

    /// Returns the deadline of the originating call if it's a `CanisterUpdate`;
    /// `None` for all other origins.
    pub fn deadline(&self) -> Option<CoarseTime> {
        match self {
            CallOrigin::CanisterUpdate(_, _, deadline) => Some(*deadline),
            CallOrigin::Ingress(..)
            | CallOrigin::Query(..)
            | CallOrigin::CanisterQuery(..)
            | CallOrigin::SystemTask => None,
        }
    }
}

impl From<&CallOrigin> for pb::call_context::CallOrigin {
    fn from(item: &CallOrigin) -> Self {
        match item {
            CallOrigin::Ingress(user_id, message_id) => Self::Ingress(pb::call_context::Ingress {
                user_id: Some(user_id_into_protobuf(*user_id)),
                message_id: message_id.as_bytes().to_vec(),
            }),
            CallOrigin::CanisterUpdate(canister_id, callback_id, deadline) => {
                Self::CanisterUpdate(pb::call_context::CanisterUpdateOrQuery {
                    canister_id: Some(pb_types::CanisterId::from(*canister_id)),
                    callback_id: callback_id.get(),
                    deadline_seconds: deadline.as_secs_since_unix_epoch(),
                })
            }
            CallOrigin::Query(user_id) => Self::Query(user_id_into_protobuf(*user_id)),
            CallOrigin::CanisterQuery(canister_id, callback_id) => {
                Self::CanisterQuery(pb::call_context::CanisterUpdateOrQuery {
                    canister_id: Some(pb_types::CanisterId::from(*canister_id)),
                    callback_id: callback_id.get(),
                    deadline_seconds: NO_DEADLINE.as_secs_since_unix_epoch(),
                })
            }
            CallOrigin::SystemTask => Self::SystemTask(pb::call_context::SystemTask {}),
        }
    }
}

impl TryFrom<pb::call_context::CallOrigin> for CallOrigin {
    type Error = ProxyDecodeError;
    fn try_from(value: pb::call_context::CallOrigin) -> Result<Self, Self::Error> {
        let call_origin = match value {
            pb::call_context::CallOrigin::Ingress(pb::call_context::Ingress {
                user_id,
                message_id,
            }) => Self::Ingress(
                user_id_try_from_protobuf(try_from_option_field(
                    user_id,
                    "CallOrigin::Ingress::user_id",
                )?)?,
                message_id.as_slice().try_into()?,
            ),
            pb::call_context::CallOrigin::CanisterUpdate(
                pb::call_context::CanisterUpdateOrQuery {
                    canister_id,
                    callback_id,
                    deadline_seconds,
                },
            ) => Self::CanisterUpdate(
                try_from_option_field(canister_id, "CallOrigin::CanisterUpdate::canister_id")?,
                callback_id.into(),
                CoarseTime::from_secs_since_unix_epoch(deadline_seconds),
            ),
            pb::call_context::CallOrigin::Query(user_id) => {
                Self::Query(user_id_try_from_protobuf(user_id)?)
            }
            pb::call_context::CallOrigin::CanisterQuery(
                pb::call_context::CanisterUpdateOrQuery {
                    canister_id,
                    callback_id,
                    deadline_seconds: _,
                },
            ) => Self::CanisterQuery(
                try_from_option_field(canister_id, "CallOrigin::CanisterQuery::canister_id")?,
                callback_id.into(),
            ),
            pb::call_context::CallOrigin::SystemTask { .. } => Self::SystemTask,
        };
        Ok(call_origin)
    }
}

impl CallContextManager {
    /// Must be used to create a new call context at the beginning of every new
    /// ingress or inter-canister message.
    pub fn new_call_context(
        &mut self,
        call_origin: CallOrigin,
        cycles: Cycles,
        time: Time,
        metadata: RequestMetadata,
    ) -> CallContextId {
        self.stats.on_new_call_context(&call_origin);

        self.next_call_context_id += 1;
        let id = CallContextId::from(self.next_call_context_id);
        self.call_contexts.insert(
            id,
            CallContext {
                call_origin,
                responded: false,
                deleted: false,
                available_cycles: cycles,
                time,
                metadata,
                instructions_executed: NumInstructions::default(),
            },
        );
        debug_assert!(self.stats_ok());

        id
    }

    /// Returns the currently open `CallContext`s maintained by this
    /// `CallContextManager`.
    pub fn call_contexts(&self) -> &BTreeMap<CallContextId, CallContext> {
        &self.call_contexts
    }

    pub fn call_contexts_mut(&mut self) -> impl Iterator<Item = &mut CallContext> {
        self.call_contexts.values_mut()
    }

    /// Returns a reference to the call context with `call_context_id`.
    pub fn call_context(&self, call_context_id: CallContextId) -> Option<&CallContext> {
        self.call_contexts.get(&call_context_id)
    }

    /// Returns a mutable reference to the call context with `call_context_id`.
    pub fn call_context_mut(&mut self, call_context_id: CallContextId) -> Option<&mut CallContext> {
        self.call_contexts.get_mut(&call_context_id)
    }

    /// Returns the `Callback`s maintained by this `CallContextManager`.
    pub fn callbacks(&self) -> &BTreeMap<CallbackId, Arc<Callback>> {
        &self.callbacks
    }

    /// Returns a reference to the callback with `callback_id`.
    pub fn callback(&self, callback_id: CallbackId) -> Option<&Callback> {
        self.callbacks.get(&callback_id).map(AsRef::as_ref)
    }

    /// Validates the given response before inducting it into the queue.
    /// Verifies that the stored respondent and originator associated with the
    /// `callback_id`, as well as its deadline match those of the response.
    ///
    /// Returns a `StateError::NonMatchingResponse` if the `callback_id` was not found
    /// or if the response is not valid.
    pub(crate) fn validate_response(&self, response: &Response) -> Result<(), StateError> {
        match self.callback(response.originator_reply_callback) {
            Some(callback) if response.respondent != callback.respondent
                    || response.originator != callback.originator
                    || response.deadline != callback.deadline => {
                Err(StateError::NonMatchingResponse {
                    err_str: format!(
                        "invalid details, expected => [originator => {}, respondent => {}, deadline => {}], but got response with",
                        callback.originator, callback.respondent, Time::from(callback.deadline)
                    ),
                    originator: response.originator,
                    callback_id: response.originator_reply_callback,
                    respondent: response.respondent,
                    deadline: response.deadline,
                })
            }
            Some(_) => Ok(()),
            None => {
                // Received an unknown callback ID.
                Err(StateError::NonMatchingResponse {
                    err_str: "unknown callback ID".to_string(),
                    originator: response.originator,
                    callback_id: response.originator_reply_callback,
                    respondent: response.respondent,
                    deadline: response.deadline,
                })
            }
        }
    }

    /// Accepts a canister result and produces an action that should be taken
    /// by the caller; and the call context, if completed.
    pub fn on_canister_result(
        &mut self,
        call_context_id: CallContextId,
        callback_id: Option<CallbackId>,
        result: Result<Option<WasmResult>, HypervisorError>,
        instructions_used: NumInstructions,
    ) -> (CallContextAction, Option<CallContext>) {
        enum OutstandingCalls {
            Yes,
            No,
        }
        enum Responded {
            Yes,
            No,
        }

        if let Some(callback_id) = callback_id {
            self.unregister_callback(callback_id);
        }

        let outstanding_calls = if self.outstanding_calls(call_context_id) > 0 {
            OutstandingCalls::Yes
        } else {
            OutstandingCalls::No
        };

        let context = self
            .call_contexts
            .get_mut(&call_context_id)
            .unwrap_or_else(|| panic!("no call context with ID={}", call_context_id));
        // Update call context `instructions_executed += instructions_used`
        context.instructions_executed = context
            .instructions_executed
            .get()
            .saturating_add(instructions_used.get())
            .into();
        let responded = if context.responded {
            Responded::Yes
        } else {
            Responded::No
        };

        // This is one big match instead of a few if statements because we want
        // the compiler to tell us if we handled all the possible cases.
        let (action, call_context) = match (result, responded, outstanding_calls) {
            (Ok(None), Responded::No, OutstandingCalls::Yes)
            | (Err(_), Responded::No, OutstandingCalls::Yes) => {
                (CallContextAction::NotYetResponded, None)
            }

            (Ok(None), Responded::Yes, OutstandingCalls::Yes)
            | (Err(_), Responded::Yes, OutstandingCalls::Yes) => {
                (CallContextAction::AlreadyResponded, None)
            }
            (Ok(None), Responded::Yes, OutstandingCalls::No)
            | (Err(_), Responded::Yes, OutstandingCalls::No) => (
                CallContextAction::AlreadyResponded,
                self.call_contexts.remove(&call_context_id),
            ),

            (Ok(None), Responded::No, OutstandingCalls::No) => {
                self.stats.on_call_context_response(&context.call_origin);
                let refund = context.available_cycles;
                (
                    CallContextAction::NoResponse { refund },
                    self.call_contexts.remove(&call_context_id),
                )
            }

            (Ok(Some(WasmResult::Reply(payload))), Responded::No, OutstandingCalls::No) => {
                self.stats.on_call_context_response(&context.call_origin);
                let refund = context.available_cycles;
                (
                    CallContextAction::Reply { payload, refund },
                    self.call_contexts.remove(&call_context_id),
                )
            }
            (Ok(Some(WasmResult::Reply(payload))), Responded::No, OutstandingCalls::Yes) => {
                self.stats.on_call_context_response(&context.call_origin);
                let refund = context.available_cycles;
                context.mark_responded();
                (CallContextAction::Reply { payload, refund }, None)
            }

            (Ok(Some(WasmResult::Reject(payload))), Responded::No, OutstandingCalls::No) => {
                self.stats.on_call_context_response(&context.call_origin);
                let refund = context.available_cycles;
                (
                    CallContextAction::Reject { payload, refund },
                    self.call_contexts.remove(&call_context_id),
                )
            }
            (Ok(Some(WasmResult::Reject(payload))), Responded::No, OutstandingCalls::Yes) => {
                self.stats.on_call_context_response(&context.call_origin);
                let refund = context.available_cycles;
                context.mark_responded();
                (CallContextAction::Reject { payload, refund }, None)
            }

            (Err(error), Responded::No, OutstandingCalls::No) => {
                self.stats.on_call_context_response(&context.call_origin);
                let refund = context.available_cycles;
                (
                    CallContextAction::Fail { error, refund },
                    self.call_contexts.remove(&call_context_id),
                )
            }

            // The following can never happen since we handle at the SystemApi level if a canister
            // tries to reply to an already responded call context.
            (Ok(Some(WasmResult::Reply(_))), Responded::Yes, _) => unreachable!(
                "Canister replied twice on the same request, call_context_id = {}",
                call_context_id
            ),
            (Ok(Some(WasmResult::Reject(_))), Responded::Yes, _) => unreachable!(
                "Canister replied twice on the same request, call_context_id = {}",
                call_context_id
            ),
        };
        debug_assert!(self.stats_ok());

        (action, call_context)
    }

    /// Marks the call context with the given ID as responded.
    ///
    /// Returns an error if the call context was not found. No-op if the call
    /// context was already responded to.
    pub fn mark_responded(&mut self, call_context_id: CallContextId) -> Result<(), String> {
        let call_context = self
            .call_contexts
            .get_mut(&call_context_id)
            .ok_or(format!("Call context not found: {}", call_context_id))?;
        if call_context.responded {
            return Ok(());
        }

        call_context.mark_responded();

        self.stats
            .on_call_context_response(&call_context.call_origin);
        debug_assert!(self.stats_ok());

        Ok(())
    }

    /// Registers a callback for an outgoing call.
    pub fn register_callback(&mut self, callback: Callback) -> CallbackId {
        self.stats.on_register_callback(&callback);

        self.next_callback_id += 1;
        let callback_id = CallbackId::from(self.next_callback_id);
        self.callbacks.insert(callback_id, Arc::new(callback));

        debug_assert!(self.stats_ok());

        callback_id
    }

    /// If we get a response for one of the outstanding calls, we unregister
    /// the callback and return it.
    pub fn unregister_callback(&mut self, callback_id: CallbackId) -> Option<Arc<Callback>> {
        self.callbacks.remove(&callback_id).map(|callback| {
            self.stats.on_unregister_callback(&callback);
            debug_assert!(self.stats_ok());

            callback
        })
    }

    /// Returns the call origin, which is either the message ID of the ingress
    /// message or the canister ID of the canister that sent the initial
    /// request.
    pub fn call_origin(&self, call_context_id: CallContextId) -> Option<CallOrigin> {
        self.call_contexts
            .get(&call_context_id)
            .map(|cc| cc.call_origin.clone())
    }

    /// Returns if a call context was already responded or not.
    pub fn call_responded(&self, call_context_id: CallContextId) -> Option<bool> {
        self.call_contexts
            .get(&call_context_id)
            .map(|cc| cc.responded)
    }

    /// Returns the number of outstanding calls for a given call context.
    pub fn outstanding_calls(&self, call_context_id: CallContextId) -> usize {
        self.callbacks
            .iter()
            .filter(|(_, callback)| callback.call_context_id == call_context_id)
            .count()
    }

    /// Expose the `next_callback_id` field so that the canister sandbox can
    /// predict what the new ids will be.
    pub fn next_callback_id(&self) -> u64 {
        self.next_callback_id
    }

    /// Returns a collection of all call contexts older than the provided age.
    pub fn call_contexts_older_than(
        &self,
        current_time: Time,
        age: Duration,
    ) -> Vec<(&CallOrigin, Time)> {
        // Call contexts are stored in order of increasing CallContextId, and
        // the IDs are generated sequentially, so we are iterating in order of
        // creation time. This means we can stop as soon as we encounter a call
        // context that isn't old enough.
        self.call_contexts
            .iter()
            .take_while(|(_, call_context)| call_context.time() + age <= current_time)
            .filter_map(|(_, call_context)| {
                if !call_context.is_deleted() {
                    return Some((call_context.call_origin(), call_context.time()));
                }
                None
            })
            .collect()
    }

    /// Returns the number of unresponded canister update call contexts, also taking
    /// into account a potential paused or aborted canister request execution
    /// (equivalent to one extra call context).
    ///
    /// Time complexity: `O(1)`.
    pub fn unresponded_canister_update_call_contexts(
        &self,
        aborted_or_paused_request: Option<&Request>,
    ) -> usize {
        self.stats.unresponded_canister_update_call_contexts
            + match aborted_or_paused_request {
                Some(_) => 1,
                None => 0,
            }
    }

    /// Returns the number of unresponded guaranteed response call contexts, also
    /// taking into account a potential paused or aborted canister request execution
    /// (equivalent to one extra call context).
    ///
    /// Time complexity: `O(1)`.
    pub fn unresponded_guaranteed_response_call_contexts(
        &self,
        aborted_or_paused_request: Option<&Request>,
    ) -> usize {
        self.stats.unresponded_guaranteed_response_call_contexts
            + match aborted_or_paused_request {
                Some(request) if request.deadline == NO_DEADLINE => 1,
                _ => 0,
            }
    }

    /// Returns the number of unresponded callbacks, ignoring the callback
    /// corresponding to a potential paused or aborted canister response execution
    /// (since this response was just delivered).
    ///
    /// Time complexity: `O(1)`.
    pub fn unresponded_callback_count(
        &self,
        aborted_or_paused_response: Option<&Response>,
    ) -> usize {
        self.callbacks.len()
            - match aborted_or_paused_response {
                Some(_) => 1,
                None => 0,
            }
    }

    /// Returns the number of unresponded guaranteed response callbacks, ignoring
    /// the callback corresponding to a potential paused or aborted canister
    /// response execution (since this response was just delivered).
    ///
    /// Time complexity: `O(1)`.
    pub fn unresponded_guaranteed_response_callback_count(
        &self,
        aborted_or_paused_response: Option<&Response>,
    ) -> usize {
        self.stats.guaranteed_response_callback_count
            - match aborted_or_paused_response {
                Some(response) if response.deadline == NO_DEADLINE => 1,
                _ => 0,
            }
    }

    /// Helper function to concisely validate stats adjustments in debug builds,
    /// by writing `debug_assert!(self.stats_ok())`.
    ///
    /// Time complexity: `O(N)`.
    fn stats_ok(&self) -> bool {
        debug_assert_eq!(
            CallContextManagerStats::calculate_stats(&self.call_contexts, &self.callbacks),
            self.stats
        );
        true
    }
}

impl From<&CanisterCall> for CallOrigin {
    fn from(msg: &CanisterCall) -> Self {
        match msg {
            CanisterCall::Request(request) => CallOrigin::CanisterUpdate(
                request.sender,
                request.sender_reply_callback,
                request.deadline,
            ),
            CanisterCall::Ingress(ingress) => {
                CallOrigin::Ingress(ingress.source, ingress.message_id.clone())
            }
        }
    }
}

impl From<&CanisterCallOrTask> for CallOrigin {
    fn from(call_or_task: &CanisterCallOrTask) -> Self {
        match call_or_task {
            CanisterCallOrTask::Call(call) => CallOrigin::from(call),
            CanisterCallOrTask::Task(_) => CallOrigin::SystemTask,
        }
    }
}

impl From<&CallContextManager> for pb::CallContextManager {
    fn from(item: &CallContextManager) -> Self {
        Self {
            next_call_context_id: item.next_call_context_id,
            next_callback_id: item.next_callback_id,
            call_contexts: item
                .call_contexts
                .iter()
                .map(|(id, context)| pb::CallContextEntry {
                    call_context_id: id.get(),
                    call_context: Some(context.into()),
                })
                .collect(),
            callbacks: item
                .callbacks
                .iter()
                .map(|(id, callback)| pb::CallbackEntry {
                    callback_id: id.get(),
                    callback: Some(callback.as_ref().into()),
                })
                .collect(),
        }
    }
}

impl TryFrom<pb::CallContextManager> for CallContextManager {
    type Error = ProxyDecodeError;
    fn try_from(value: pb::CallContextManager) -> Result<Self, Self::Error> {
        let mut call_contexts = BTreeMap::<CallContextId, CallContext>::new();
        let mut callbacks = BTreeMap::<CallbackId, Arc<Callback>>::new();
        for pb::CallContextEntry {
            call_context_id,
            call_context,
        } in value.call_contexts.into_iter()
        {
            call_contexts.insert(
                call_context_id.into(),
                try_from_option_field(call_context, "CallContextManager::call_contexts::V")?,
            );
        }
        for pb::CallbackEntry {
            callback_id,
            callback,
        } in value.callbacks.into_iter()
        {
            callbacks.insert(
                callback_id.into(),
                Arc::new(try_from_option_field(
                    callback,
                    "CallContextManager::callbacks::V",
                )?),
            );
        }
        let stats = CallContextManagerStats::calculate_stats(&call_contexts, &callbacks);

        Ok(Self {
            next_call_context_id: value.next_call_context_id,
            next_callback_id: value.next_callback_id,
            call_contexts,
            callbacks,
            stats,
        })
    }
}
