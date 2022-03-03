#[cfg(test)]
mod tests;

use crate::StateError;
use ic_interfaces::{execution_environment::HypervisorError, messages::RequestOrIngress};
use ic_protobuf::proxy::{try_from_option_field, ProxyDecodeError};
use ic_protobuf::state::canister_state_bits::v1 as pb;
use ic_protobuf::types::v1 as pb_types;
use ic_types::messages::Response;
use ic_types::Time;
use ic_types::{
    ingress::WasmResult,
    messages::{CallContextId, CallbackId, MessageId},
    methods::Callback,
    user_id_into_protobuf, user_id_try_from_protobuf, CanisterId, Cycles, Funds, UserId,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::convert::{From, TryFrom, TryInto};
use std::time::Duration;

/// Call context contains all context information related to an incoming call.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallContext {
    /// Tracks relevant information about who sent the request that created the
    /// CallContext needed to form the eventual reply.
    call_origin: CallOrigin,

    /// A CallContext may still be alive after the canister has replied on it
    /// already (e.g. it replies without executing all callbacks).  Tracks the
    /// current status.
    responded: bool,

    /// True if the call context associated with the callback has been deleted
    /// (e.g. during uninstall), false otherwise.
    deleted: bool,

    /// Cycles that were sent in the request that created the CallContext.
    available_cycles: Cycles,

    /// Time that the call context was created. This field is only optional to
    /// accomodate contexts that were created before this field was created.
    time: Option<Time>,
}

impl CallContext {
    pub fn new(
        call_origin: CallOrigin,
        responded: bool,
        deleted: bool,
        available_cycles: Cycles,
        time: Time,
    ) -> Self {
        Self {
            call_origin,
            responded,
            deleted,
            available_cycles,
            time: Some(time),
        }
    }

    /// Returns the available amount of cycles in this call context.
    pub fn available_cycles(&self) -> Cycles {
        self.available_cycles
    }

    /// Updates the available cycles in the call context based on how much
    /// cycles the canister requested to keep.
    ///
    /// Returns a `CallContextError::InsufficientCyclesInCall` if `cycles` is
    /// more than what's available in the call context.
    pub fn withdraw_cycles(&mut self, cycles: Cycles) -> Result<(), CallContextError> {
        if self.available_cycles < cycles {
            return Err(CallContextError::InsufficientCyclesInCall {
                available: self.available_cycles,
                requested: cycles,
            });
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
        self.responded = true;
    }

    /// The time at which the call context was created.
    pub fn time(&self) -> Option<Time> {
        self.time
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
            time_nanos: item.time.map(|t| t.as_nanos_since_unix_epoch()),
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
            time: value.time_nanos.map(Time::from_nanos_since_unix_epoch),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallContextError {
    InsufficientCyclesInCall {
        available: Cycles,
        requested: Cycles,
    },
}

impl From<CallContextError> for HypervisorError {
    fn from(val: CallContextError) -> Self {
        match val {
            CallContextError::InsufficientCyclesInCall {
                available,
                requested,
            } => HypervisorError::InsufficientCyclesInCall {
                available,
                requested,
            },
        }
    }
}

/// The action the caller of `CallContext.on_canister_result` should take.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallContextAction {
    /// The canister produced a reply for the request which is returned along
    /// with the remaining cycles that the canister did not accept.
    Reply { payload: Vec<u8>, refund: Cycles },
    /// The canister produced a reject for the request which is returned along
    /// with all the cycles that the request initially contained.
    Reject { payload: String, refund: Cycles },
    /// The canister did not produce a response or a reject and will not produce
    /// one.  The cycles that the sender supplied is returned.
    NoResponse { refund: Cycles },
    /// Message execution failed; the canister has not produced a response or a
    /// reject yet; and will not produce one.  The produced error and the cycles
    /// that the sender supplied is returned.
    Fail {
        error: HypervisorError,
        refund: Cycles,
    },
    /// The canister did not produce a response or a reject yet but may still
    /// produce one later.
    NotYetResponded,
    /// The canister did not produce a response or a reject during this
    /// execution but it produced one earlier.
    AlreadyResponded,
}

/// Call context manager is an entity responsible for management of contexts of
/// incoming calls of a canister. The call context manager must be used for
/// opening new call contexts, registering and unregistering of callback for
/// subsequent outgoing calls and for closing call contexts.
///
/// In every method, if the provided callback or call context id was
/// not found inside the call context manager, we panic. Since this logic is
/// executed inside the "trusted" part of the execution (after the consensus),
/// any such error would indicate an unexpected and inconsistent system state.
///
/// Conceptually, this data structure reimplements a reference counter and could
/// be replaced by an Arc/Rc smart pointer. However, serde does not play well
/// with the serialization of these pointers. In the future we might consider
/// introducing an intermediate layer between the serialization and the actual
/// working data structure, to separate these concerns.
#[derive(Clone, Default, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallContextManager {
    next_call_context_id: u64,
    next_callback_id: u64,
    // maps call context to its responded status
    call_contexts: BTreeMap<CallContextId, CallContext>,
    callbacks: BTreeMap<CallbackId, Callback>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallOrigin {
    Ingress(UserId, MessageId),
    CanisterUpdate(CanisterId, CallbackId),
    Query(UserId),
    CanisterQuery(CanisterId, CallbackId),
    Heartbeat,
}

impl From<&CallOrigin> for pb::call_context::CallOrigin {
    fn from(item: &CallOrigin) -> Self {
        match item {
            CallOrigin::Ingress(user_id, message_id) => Self::Ingress(pb::call_context::Ingress {
                user_id: Some(user_id_into_protobuf(*user_id)),
                message_id: message_id.as_bytes().to_vec(),
            }),
            CallOrigin::CanisterUpdate(canister_id, callback_id) => {
                Self::CanisterUpdate(pb::call_context::CanisterUpdateOrQuery {
                    canister_id: Some(pb_types::CanisterId::from(*canister_id)),
                    callback_id: callback_id.get(),
                })
            }
            CallOrigin::Query(user_id) => Self::Query(user_id_into_protobuf(*user_id)),
            CallOrigin::CanisterQuery(canister_id, callback_id) => {
                Self::CanisterQuery(pb::call_context::CanisterUpdateOrQuery {
                    canister_id: Some(pb_types::CanisterId::from(*canister_id)),
                    callback_id: callback_id.get(),
                })
            }
            CallOrigin::Heartbeat => Self::Heartbeat(pb::call_context::Heartbeat {}),
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
                },
            ) => Self::CanisterUpdate(
                try_from_option_field(canister_id, "CallOrigin::CanisterUpdate::canister_id")?,
                callback_id.into(),
            ),
            pb::call_context::CallOrigin::Query(user_id) => {
                Self::Query(user_id_try_from_protobuf(user_id)?)
            }
            pb::call_context::CallOrigin::CanisterQuery(
                pb::call_context::CanisterUpdateOrQuery {
                    canister_id,
                    callback_id,
                },
            ) => Self::CanisterQuery(
                try_from_option_field(canister_id, "CallOrigin::CanisterQuery::canister_id")?,
                callback_id.into(),
            ),
            pb::call_context::CallOrigin::Heartbeat { .. } => Self::Heartbeat,
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
                time: Some(time),
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
    pub fn callback(&self, callback_id: &CallbackId) -> Option<&Callback> {
        self.callbacks.get(callback_id)
    }

    /// Validates the given response before inducting it into the queue.
    /// Verifies that the stored respondent and originator associated with the
    /// `callback_id` match with details provided by the response.
    ///
    /// Returns a `StateError::NonMatchingResponse` if could not find the `callback_id` or
    /// if the response is not valid.
    pub(crate) fn validate_response(&self, response: &Response) -> Result<(), StateError> {
        match self.callback(&response.originator_reply_callback) {
            Some(callback) => {
                // (EXC-877) Once this is deployed in production,
                // it's safe to make `respondent` and `originator` non-optional.
                // Currently optional to ensure backwards compatibility.
                match (callback.respondent, callback.originator) {
                    (Some(respondent), Some(originator))
                        if response.respondent != respondent
                            || response.originator != originator =>
                    {
                        return Err(StateError::NonMatchingResponse {
                                err_str: format!(
                                    "invalid details, expected => [originator => {}, respondent => {}], but got response with",
                                    originator, respondent,
                                ),
                                originator: response.originator,
                                callback_id: response.originator_reply_callback,
                                respondent: response.respondent,
                            });
                    }
                    _ => Ok(()),
                }
            }
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
    /// by the caller.
    pub fn on_canister_result(
        &mut self,
        call_context_id: CallContextId,
        result: Result<Option<WasmResult>, HypervisorError>,
    ) -> CallContextAction {
        enum OutstandingCalls {
            Yes,
            No,
        }
        enum Responded {
            Yes,
            No,
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
        let responded = if context.responded {
            Responded::Yes
        } else {
            Responded::No
        };

        // This is one big match instead of a few if statements because we want
        // the compiler to tell us if we handled all the possible cases.
        match (result, responded, outstanding_calls) {
            (Ok(None), Responded::No, OutstandingCalls::Yes)
            | (Err(_), Responded::No, OutstandingCalls::Yes) => CallContextAction::NotYetResponded,

            (Ok(None), Responded::Yes, OutstandingCalls::Yes)
            | (Err(_), Responded::Yes, OutstandingCalls::Yes) => {
                CallContextAction::AlreadyResponded
            }
            (Ok(None), Responded::Yes, OutstandingCalls::No)
            | (Err(_), Responded::Yes, OutstandingCalls::No) => {
                self.call_contexts.remove(&call_context_id);
                CallContextAction::AlreadyResponded
            }

            (Ok(None), Responded::No, OutstandingCalls::No) => {
                let refund = context.available_cycles;
                self.call_contexts.remove(&call_context_id);
                CallContextAction::NoResponse { refund }
            }

            (Ok(Some(WasmResult::Reply(payload))), Responded::No, OutstandingCalls::No) => {
                let refund = context.available_cycles;
                self.call_contexts.remove(&call_context_id);
                CallContextAction::Reply { payload, refund }
            }
            (Ok(Some(WasmResult::Reply(payload))), Responded::No, OutstandingCalls::Yes) => {
                context.responded = true;
                CallContextAction::Reply {
                    payload,
                    refund: context.available_cycles,
                }
            }

            (Ok(Some(WasmResult::Reject(payload))), Responded::No, OutstandingCalls::No) => {
                let refund = context.available_cycles;
                self.call_contexts.remove(&call_context_id);
                CallContextAction::Reject { payload, refund }
            }
            (Ok(Some(WasmResult::Reject(payload))), Responded::No, OutstandingCalls::Yes) => {
                context.responded = true;
                CallContextAction::Reject {
                    payload,
                    refund: context.available_cycles,
                }
            }

            (Err(error), Responded::No, OutstandingCalls::No) => {
                let refund = context.available_cycles;
                self.call_contexts.remove(&call_context_id);
                CallContextAction::Fail { error, refund }
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

    /// Returns a copy of the callback for the given callback_id
    pub fn peek_callback(&self, callback_id: CallbackId) -> Option<&Callback> {
        self.callbacks.get(&callback_id)
    }

    /// If we get a response for one of the outstanding calls, we unregister
    /// the callback and return it.
    pub fn unregister_callback(&mut self, callback_id: CallbackId) -> Option<Callback> {
        self.callbacks.remove(&callback_id)
    }

    pub fn unregister_call_context(
        &mut self,
        call_context_id: CallContextId,
    ) -> Option<CallContext> {
        self.call_contexts.remove(&call_context_id)
    }

    /// Returns the call origin, which is either the message id of the ingress
    /// message or the canister id of the canister that sent the initial
    /// request.
    pub fn call_origin(&self, call_context_id: CallContextId) -> Option<CallOrigin> {
        self.call_contexts
            .get(&call_context_id)
            .map(|cc| cc.call_origin.clone())
    }

    /// Tells if a call context was already responded or not.
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

    pub fn call_contexts_older_than(
        &self,
        current_time: Time,
        duration: Duration,
    ) -> Vec<(CallOrigin, Time)> {
        // Call contexts are stored in order of increasing CallContextId, and
        // the IDs are generated sequentially, so we are iterating in order of
        // creation time. This means we can stop as soon as we encounter a call
        // context that isn't old enough.
        self.call_contexts
            .iter()
            .take_while(|(_, call_context)| match call_context.time() {
                Some(context_time) => context_time + duration <= current_time,
                None => true,
            })
            .filter_map(|(_, call_context)| {
                if let Some(time) = call_context.time() {
                    if !call_context.is_deleted() {
                        return Some((call_context.call_origin().clone(), time));
                    }
                }
                None
            })
            .collect()
    }
}

impl From<&RequestOrIngress> for CallOrigin {
    fn from(msg: &RequestOrIngress) -> Self {
        match msg {
            RequestOrIngress::Request(request) => {
                CallOrigin::CanisterUpdate(request.sender, request.sender_reply_callback)
            }
            RequestOrIngress::Ingress(ingress) => {
                CallOrigin::Ingress(ingress.source, ingress.message_id.clone())
            }
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
