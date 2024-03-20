#[cfg(test)]
mod tests;

use crate::StateError;
use ic_interfaces::execution_environment::HypervisorError;
use ic_management_canister_types::IC_00;
use ic_protobuf::proxy::{try_from_option_field, ProxyDecodeError};
use ic_protobuf::state::canister_state_bits::v1 as pb;
use ic_protobuf::types::v1 as pb_types;
use ic_types::{
    ingress::WasmResult,
    messages::{
        CallContextId, CallbackId, CanisterCall, CanisterCallOrTask, MessageId, RequestMetadata,
        Response, NO_DEADLINE,
    },
    methods::Callback,
    time::CoarseTime,
    user_id_into_protobuf, user_id_try_from_protobuf, CanisterId, Cycles, Funds, NumInstructions,
    PrincipalId, Time, UserId,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::convert::{From, TryFrom, TryInto};
use std::time::Duration;

/// Contains all context information related to an incoming call.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

    /// Mark the call context as responded.
    pub fn mark_responded(&mut self) {
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
    /// `NO_DEADLINE` for all other origins.
    pub fn deadline(&self) -> CoarseTime {
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

/// `CallContextManager` is the entity responsible for managing call contexts of
/// incoming calls of a canister. It must be used for opening new call contexts,
/// registering and unregistering of a callback for subsequent outgoing calls and
/// for closing call contexts.
///
/// In every method, if the provided callback or call context id was not found
/// inside the call context manager, we panic. Since this logic is executed inside
/// the "trusted" part of the execution (after the consensus), any such error would
/// indicate an unexpected and inconsistent system state.
///
/// Conceptually, this data structure reimplements a reference counter and could
/// be replaced by an `Arc`/`Rc` smart pointer. However, serde does not play well
/// with the serialization of these pointers. In the future we might consider
/// introducing an intermediate layer between the serialization and the actual
/// working data structure, to separate these concerns.
#[derive(Clone, Default, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallContextManager {
    next_call_context_id: u64,
    next_callback_id: u64,
    /// Maps call context to its responded status.
    call_contexts: BTreeMap<CallContextId, CallContext>,
    callbacks: BTreeMap<CallbackId, Callback>,
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
    /// Returns the principal id associated with this call origin.
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
    /// `NO_DEADLINE` for all other origins.
    pub fn deadline(&self) -> CoarseTime {
        match self {
            CallOrigin::CanisterUpdate(_, _, deadline) => *deadline,
            CallOrigin::Ingress(..)
            | CallOrigin::Query(..)
            | CallOrigin::CanisterQuery(..)
            | CallOrigin::SystemTask => NO_DEADLINE,
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
        id
    }

    /// Returns the currently open `CallContext`s maintained by this
    /// `CallContextManager`.
    pub fn call_contexts(&self) -> &BTreeMap<CallContextId, CallContext> {
        &self.call_contexts
    }

    pub fn call_contexts_mut(&mut self) -> &mut BTreeMap<CallContextId, CallContext> {
        &mut self.call_contexts
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
    pub fn callbacks(&self) -> &BTreeMap<CallbackId, Callback> {
        &self.callbacks
    }

    /// Returns a reference to the callback with `callback_id`.
    pub fn callback(&self, callback_id: CallbackId) -> Option<&Callback> {
        self.callbacks.get(&callback_id)
    }

    /// Validates the given response before inducting it into the queue.
    /// Verifies that the stored respondent and originator associated with the
    /// `callback_id` match with details provided by the response.
    ///
    /// Returns a `StateError::NonMatchingResponse` if the `callback_id` was not found
    /// or if the response is not valid.
    pub(crate) fn validate_response(&self, response: &Response) -> Result<(), StateError> {
        match self.callback(response.originator_reply_callback) {
            Some(callback) if response.respondent != callback.respondent
                    || response.originator != callback.originator => {
                Err(StateError::NonMatchingResponse {
                    err_str: format!(
                        "invalid details, expected => [originator => {}, respondent => {}], but got response with",
                        callback.originator, callback.respondent,
                    ),
                    originator: response.originator,
                    callback_id: response.originator_reply_callback,
                    respondent: response.respondent,
                })
            }
            Some(_) => Ok(()),
            None => {
                // Received an unknown callback ID.
                Err(StateError::NonMatchingResponse {
                    err_str: "unknown callback id".to_string(),
                    originator: response.originator,
                    callback_id: response.originator_reply_callback,
                    respondent: response.respondent,
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
            .unwrap_or_else(|| panic!("no call context for id={} found", call_context_id));
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
        match (result, responded, outstanding_calls) {
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
                let refund = context.available_cycles;
                (
                    CallContextAction::NoResponse { refund },
                    self.call_contexts.remove(&call_context_id),
                )
            }

            (Ok(Some(WasmResult::Reply(payload))), Responded::No, OutstandingCalls::No) => {
                let refund = context.available_cycles;
                (
                    CallContextAction::Reply { payload, refund },
                    self.call_contexts.remove(&call_context_id),
                )
            }
            (Ok(Some(WasmResult::Reply(payload))), Responded::No, OutstandingCalls::Yes) => {
                let refund = context.available_cycles;
                context.mark_responded();
                (CallContextAction::Reply { payload, refund }, None)
            }

            (Ok(Some(WasmResult::Reject(payload))), Responded::No, OutstandingCalls::No) => {
                let refund = context.available_cycles;
                (
                    CallContextAction::Reject { payload, refund },
                    self.call_contexts.remove(&call_context_id),
                )
            }
            (Ok(Some(WasmResult::Reject(payload))), Responded::No, OutstandingCalls::Yes) => {
                let refund = context.available_cycles;
                context.mark_responded();
                (CallContextAction::Reject { payload, refund }, None)
            }

            (Err(error), Responded::No, OutstandingCalls::No) => {
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
        }
    }

    /// Registers a callback for an outgoing call.
    pub fn register_callback(&mut self, callback: Callback) -> CallbackId {
        self.next_callback_id += 1;
        let callback_id = CallbackId::from(self.next_callback_id);
        self.callbacks.insert(callback_id, callback);
        callback_id
    }

    /// If we get a response for one of the outstanding calls, we unregister
    /// the callback and return it.
    pub fn unregister_callback(&mut self, callback_id: CallbackId) -> Option<Callback> {
        self.callbacks.remove(&callback_id)
    }

    /// Returns the call origin, which is either the message id of the ingress
    /// message or the canister id of the canister that sent the initial
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
                    callback: Some(callback.into()),
                })
                .collect(),
        }
    }
}

impl TryFrom<pb::CallContextManager> for CallContextManager {
    type Error = ProxyDecodeError;
    fn try_from(value: pb::CallContextManager) -> Result<Self, Self::Error> {
        let mut call_contexts = BTreeMap::<CallContextId, CallContext>::new();
        let mut callbacks = BTreeMap::<CallbackId, Callback>::new();
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
                try_from_option_field(callback, "CallContextManager::callbacks::V")?,
            );
        }

        Ok(Self {
            next_call_context_id: value.next_call_context_id,
            next_callback_id: value.next_callback_id,
            call_contexts,
            callbacks,
        })
    }
}
