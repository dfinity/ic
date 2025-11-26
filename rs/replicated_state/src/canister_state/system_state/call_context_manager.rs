pub mod proto;
#[cfg(test)]
mod tests;

use crate::page_map::int_map::{AsInt, MutableIntMap};
use ic_interfaces::execution_environment::HypervisorError;
use ic_management_canister_types_private::IC_00;
use ic_types::ingress::WasmResult;
use ic_types::messages::{
    CallContextId, CallbackId, CanisterCall, CanisterCallOrTask, MessageId, NO_DEADLINE, Request,
    RequestMetadata, Response,
};
use ic_types::methods::Callback;
use ic_types::time::CoarseTime;
use ic_types::{
    CanisterId, Cycles, Funds, NumInstructions, PrincipalId, Time, UserId, user_id_into_protobuf,
    user_id_try_from_protobuf,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::convert::{From, TryFrom, TryInto};
use std::sync::Arc;
use std::time::Duration;

#[cfg(test)]
use std::collections::BTreeMap;

/// Contains all context information related to an incoming call.
#[derive(Clone, Eq, PartialEq, Debug)]
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
    fn withdraw_cycles(&mut self, cycles: Cycles) -> Result<(), ()> {
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
    fn mark_deleted(&mut self) {
        self.deleted = true;
    }

    pub fn has_responded(&self) -> bool {
        self.responded
    }

    /// Marks the call context as responded.
    ///
    /// DO NOT CALL THIS METHOD DIRECTLY AND DO NOT MAKE IT PUBLIC. Use
    /// `CallContextManager::on_canister_result()` instead.
    fn mark_responded(&mut self) {
        self.available_cycles = Cycles::new(0);
        self.responded = true;
    }

    /// Takes the available cycles out of the call context and returns them.
    fn take_available_cycles(&mut self) -> Cycles {
        self.available_cycles.take()
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

/// The action the caller of `CallContext.on_canister_result` should take.
#[derive(Clone, Eq, PartialEq, Debug)]
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
#[derive(Clone, Eq, PartialEq, Debug, Default)]
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
            CallOrigin::CanisterUpdate(_, _, deadline, _) => {
                self.unresponded_canister_update_call_contexts += 1;
                if *deadline == NO_DEADLINE {
                    self.unresponded_guaranteed_response_call_contexts += 1;
                }
            }
            CallOrigin::CanisterQuery(..)
            | CallOrigin::Ingress(..)
            | CallOrigin::Query(..)
            | CallOrigin::SystemTask => {}
        }
    }

    /// Updates the stats following a response for a call context with the given
    /// origin.
    fn on_call_context_response(&mut self, call_origin: &CallOrigin) {
        match call_origin {
            CallOrigin::CanisterUpdate(_, _, deadline, _) => {
                self.unresponded_canister_update_call_contexts -= 1;
                if *deadline == NO_DEADLINE {
                    self.unresponded_guaranteed_response_call_contexts -= 1;
                }
            }
            CallOrigin::CanisterQuery(..)
            | CallOrigin::Ingress(..)
            | CallOrigin::Query(..)
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
    /// Time complexity: `O(n)`.
    pub(crate) fn calculate_stats(
        call_contexts: &MutableIntMap<CallContextId, CallContext>,
        callbacks: &MutableIntMap<CallbackId, Arc<Callback>>,
    ) -> CallContextManagerStats {
        let unresponded_canister_update_call_contexts = call_contexts
            .values()
            .filter(|call_context| !call_context.responded)
            .filter(|call_context| {
                matches!(call_context.call_origin, CallOrigin::CanisterUpdate(..))
            })
            .count();
        let unresponded_guaranteed_response_call_contexts = call_contexts
            .values()
            .filter(|call_context| !call_context.responded)
            .filter(|call_context| {
                matches!(
                    call_context.call_origin,
                    CallOrigin::CanisterUpdate(_, _, deadline, _) if deadline == NO_DEADLINE
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
    /// Time complexity: `O(n)`.
    #[cfg(test)]
    pub(crate) fn calculate_unresponded_callbacks_per_respondent(
        callbacks: &MutableIntMap<CallbackId, Arc<Callback>>,
        aborted_or_paused_response: Option<&Response>,
    ) -> BTreeMap<CanisterId, usize> {
        use std::collections::btree_map::Entry;

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
                        "Aborted or paused DTS response with no matching callback: {response:?}"
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
    /// Time complexity: `O(n)`.
    #[cfg(test)]
    pub(crate) fn calculate_unresponded_call_contexts_per_originator(
        call_contexts: &MutableIntMap<CallContextId, CallContext>,
        aborted_or_paused_request: Option<&Request>,
    ) -> BTreeMap<CanisterId, usize> {
        let mut unresponded_canister_update_call_contexts = call_contexts
            .values()
            .filter(|call_context| !call_context.responded)
            .filter_map(|call_context| match call_context.call_origin {
                CallOrigin::CanisterUpdate(originator, ..) => Some(originator),
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
#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct CallContextManager {
    next_call_context_id: u64,
    next_callback_id: u64,

    /// Call contexts (including deleted ones) that still have open callbacks.
    call_contexts: MutableIntMap<CallContextId, CallContext>,

    /// Counts of open callbacks per call context.
    outstanding_callbacks: MutableIntMap<CallContextId, usize>,

    /// Callbacks still awaiting response, plus the callback of the currently
    /// paused or aborted DTS response execution, if any.
    callbacks: MutableIntMap<CallbackId, Arc<Callback>>,

    /// Callback deadline priority queue. Holds all not-yet-expired best-effort
    /// callbacks, ordered by deadline. `CallbackIds` break ties, ensuring
    /// deterministic ordering.
    ///
    /// When a `CallbackId` is returned by `expired_callbacks()`, it is removed from
    /// the queue. This ensures that each callback is expired at most once.
    unexpired_callbacks: MutableIntMap<(CoarseTime, CallbackId), ()>,

    /// Guaranteed response and overall callback and call context stats.
    stats: CallContextManagerStats,
}

type MethodName = String;

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub enum CallOrigin {
    Ingress(UserId, MessageId, MethodName),
    CanisterUpdate(CanisterId, CallbackId, CoarseTime, MethodName),
    Query(UserId, MethodName),
    CanisterQuery(CanisterId, CallbackId, MethodName),
    /// System task is either a `Heartbeat` or a `GlobalTimer`.
    SystemTask,
}

impl CallOrigin {
    /// Returns the principal ID associated with this call origin.
    pub fn get_principal(&self) -> PrincipalId {
        match self {
            CallOrigin::Ingress(user_id, ..) => user_id.get(),
            CallOrigin::CanisterUpdate(canister_id, ..) => canister_id.get(),
            CallOrigin::Query(user_id, ..) => user_id.get(),
            CallOrigin::CanisterQuery(canister_id, ..) => canister_id.get(),
            CallOrigin::SystemTask => IC_00.get(),
        }
    }

    /// Returns the deadline of the originating call if it's a `CanisterUpdate`;
    /// `None` for all other origins.
    pub fn deadline(&self) -> Option<CoarseTime> {
        match self {
            CallOrigin::CanisterUpdate(_, _, deadline, _) => Some(*deadline),
            CallOrigin::Ingress(..)
            | CallOrigin::Query(..)
            | CallOrigin::CanisterQuery(..)
            | CallOrigin::SystemTask => None,
        }
    }
}

impl CallContextManager {
    /// Must be used to create a new call context at the beginning of every new
    /// ingress or inter-canister message.
    pub(super) fn new_call_context(
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

    /// Returns the currently open `CallContexts` maintained by this
    /// `CallContextManager`.
    pub fn call_contexts(&self) -> &MutableIntMap<CallContextId, CallContext> {
        &self.call_contexts
    }

    /// Returns a reference to the call context with `call_context_id`.
    pub fn call_context(&self, call_context_id: CallContextId) -> Option<&CallContext> {
        self.call_contexts.get(&call_context_id)
    }

    /// Withdraws cycles from the call context with the given ID.
    ///
    /// Returns a reference to the `CallContext` if successful. Returns an error
    /// message if the call context does not exist or if the call context does not
    /// have enough cycles.
    pub(super) fn withdraw_cycles(
        &mut self,
        call_context_id: CallContextId,
        cycles: Cycles,
    ) -> Result<&CallContext, &str> {
        let mut call_context = self
            .call_contexts
            .remove(&call_context_id)
            .ok_or("Canister accepted cycles from invalid call context")?;
        let res = call_context.withdraw_cycles(cycles);
        self.call_contexts.insert(call_context_id, call_context);

        match res {
            Ok(()) => Ok(self.call_contexts.get(&call_context_id).unwrap()),
            Err(()) => Err("Canister accepted more cycles than available from call context"),
        }
    }

    /// Returns the `Callback`s maintained by this `CallContextManager`.
    pub fn callbacks(&self) -> &MutableIntMap<CallbackId, Arc<Callback>> {
        &self.callbacks
    }

    /// Returns a reference to the callback with `callback_id`.
    pub fn callback(&self, callback_id: CallbackId) -> Option<&Callback> {
        self.callbacks.get(&callback_id).map(AsRef::as_ref)
    }

    /// Accepts a canister result and produces an action that should be taken
    /// by the caller; and the call context, if completed.
    pub(super) fn on_canister_result(
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

        let mut context = self
            .call_contexts
            .remove(&call_context_id)
            .unwrap_or_else(|| panic!("no call context with ID={call_context_id}"));
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
                self.call_contexts.insert(call_context_id, context);
                (CallContextAction::NotYetResponded, None)
            }

            (Ok(None), Responded::Yes, OutstandingCalls::Yes)
            | (Err(_), Responded::Yes, OutstandingCalls::Yes) => {
                self.call_contexts.insert(call_context_id, context);
                (CallContextAction::AlreadyResponded, None)
            }
            (Ok(None), Responded::Yes, OutstandingCalls::No)
            | (Err(_), Responded::Yes, OutstandingCalls::No) => {
                (CallContextAction::AlreadyResponded, Some(context))
            }

            (Ok(None), Responded::No, OutstandingCalls::No) => {
                self.stats.on_call_context_response(&context.call_origin);
                let refund = context.take_available_cycles();
                (CallContextAction::NoResponse { refund }, Some(context))
            }

            (Ok(Some(WasmResult::Reply(payload))), Responded::No, OutstandingCalls::No) => {
                self.stats.on_call_context_response(&context.call_origin);
                let refund = context.take_available_cycles();
                (CallContextAction::Reply { payload, refund }, Some(context))
            }
            (Ok(Some(WasmResult::Reply(payload))), Responded::No, OutstandingCalls::Yes) => {
                self.stats.on_call_context_response(&context.call_origin);
                let refund = context.take_available_cycles();
                context.mark_responded();
                self.call_contexts.insert(call_context_id, context);
                (CallContextAction::Reply { payload, refund }, None)
            }

            (Ok(Some(WasmResult::Reject(payload))), Responded::No, OutstandingCalls::No) => {
                self.stats.on_call_context_response(&context.call_origin);
                let refund = context.take_available_cycles();
                (CallContextAction::Reject { payload, refund }, Some(context))
            }
            (Ok(Some(WasmResult::Reject(payload))), Responded::No, OutstandingCalls::Yes) => {
                self.stats.on_call_context_response(&context.call_origin);
                let refund = context.take_available_cycles();
                context.mark_responded();
                self.call_contexts.insert(call_context_id, context);
                (CallContextAction::Reject { payload, refund }, None)
            }

            (Err(error), Responded::No, OutstandingCalls::No) => {
                self.stats.on_call_context_response(&context.call_origin);
                let refund = context.take_available_cycles();
                (CallContextAction::Fail { error, refund }, Some(context))
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
    //
    // TODO: Remove, this is only used in tests.
    #[cfg(test)]
    fn mark_responded(&mut self, call_context_id: CallContextId) -> Result<(), String> {
        let mut call_context = self
            .call_contexts
            .remove(&call_context_id)
            .ok_or(format!("Call context not found: {call_context_id}"))?;
        if !call_context.responded {
            call_context.mark_responded();

            self.stats
                .on_call_context_response(&call_context.call_origin);
        }
        self.call_contexts.insert(call_context_id, call_context);
        debug_assert!(self.stats_ok());

        Ok(())
    }

    /// Registers a callback for an outgoing call.
    pub(super) fn register_callback(&mut self, callback: Callback) -> CallbackId {
        self.next_callback_id += 1;
        let callback_id = CallbackId::from(self.next_callback_id);

        self.stats.on_register_callback(&callback);
        if callback.deadline != NO_DEADLINE {
            self.unexpired_callbacks
                .insert((callback.deadline, callback_id), ());
        }

        self.outstanding_callbacks.insert(
            callback.call_context_id,
            self.outstanding_callbacks
                .get(&callback.call_context_id)
                .unwrap_or(&0)
                + 1,
        );
        self.callbacks.insert(callback_id, Arc::new(callback));
        debug_assert_eq!(
            calculate_outstanding_callbacks(&self.callbacks),
            self.outstanding_callbacks
        );
        debug_assert!(self.stats_ok());

        callback_id
    }

    /// If we get a response for one of the outstanding calls, we unregister
    /// the callback and return it.
    pub(super) fn unregister_callback(&mut self, callback_id: CallbackId) -> Option<Arc<Callback>> {
        self.callbacks.remove(&callback_id).inspect(|callback| {
            let outstanding_callbacks = *self
                .outstanding_callbacks
                .get(&callback.call_context_id)
                .unwrap_or(&0);
            if outstanding_callbacks <= 1 {
                self.outstanding_callbacks.remove(&callback.call_context_id);
            } else {
                self.outstanding_callbacks
                    .insert(callback.call_context_id, outstanding_callbacks - 1);
            }

            self.stats.on_unregister_callback(callback);
            if callback.deadline != NO_DEADLINE {
                self.unexpired_callbacks
                    .remove(&(callback.deadline, callback_id));
            }

            debug_assert_eq!(
                calculate_outstanding_callbacks(&self.callbacks),
                self.outstanding_callbacks
            );
            debug_assert!(self.stats_ok());
        })
    }

    /// Checks whether there exist any not previously expired best-effort callbacks
    /// whose deadlines are `< now`.
    pub(super) fn has_expired_callbacks(&self, now: CoarseTime) -> bool {
        self.unexpired_callbacks
            .min_key()
            .map(|(deadline, _)| *deadline < now)
            .unwrap_or(false)
    }

    /// Expires (i.e. removes from the set of unexpired callbacks, with no change to
    /// the callback itself) and returns the IDs of all not previously expired
    /// best-effort callbacks whose deadlines are `< now`.
    ///
    /// Note: A given callback ID will be returned at most once by this function.
    pub(super) fn expire_callbacks(
        &mut self,
        now: CoarseTime,
    ) -> impl Iterator<Item = CallbackId> + use<> {
        const MIN_CALLBACK_ID: CallbackId = CallbackId::new(0);

        // Unfortunate two-step splitting off of the expired callbacks.
        let unexpired_callbacks = self.unexpired_callbacks.split_off(&(now, MIN_CALLBACK_ID));
        let expired_callbacks =
            std::mem::replace(&mut self.unexpired_callbacks, unexpired_callbacks);

        expired_callbacks
            .into_iter()
            .map(|((_, callback_id), ())| callback_id)
    }

    /// Returns the call origin, which is either the message ID of the ingress
    /// message or the canister ID of the canister that sent the initial
    /// request.
    pub fn call_origin(&self, call_context_id: CallContextId) -> Option<CallOrigin> {
        self.call_contexts
            .get(&call_context_id)
            .map(|cc| cc.call_origin.clone())
    }

    /// Returns the number of outstanding calls for a given call context.
    pub fn outstanding_calls(&self, call_context_id: CallContextId) -> usize {
        *self
            .outstanding_callbacks
            .get(&call_context_id)
            .unwrap_or(&0)
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
    /// Time complexity: `O(n * log(n))`.
    fn stats_ok(&self) -> bool {
        debug_assert_eq!(
            CallContextManagerStats::calculate_stats(&self.call_contexts, &self.callbacks),
            self.stats
        );
        // The best we can do here is to check that the set of unexpired_callbacks is a
        // subset of all best-effort callbacks.
        let all_callback_deadlines = calculate_callback_deadlines(&self.callbacks);
        debug_assert!(
            self.unexpired_callbacks
                .iter()
                .all(|(key, ())| all_callback_deadlines.contains(key)),
            "unexpired_callbacks: {:?}, all_callback_deadlines: {:?}",
            self.unexpired_callbacks,
            all_callback_deadlines
        );
        true
    }

    /// Marks all call contexts as deleted and produces reject responses for the
    /// not yet responded ones. This is called as part of uninstalling a canister.
    ///
    /// Callbacks will be unregistered when responses are received.
    pub(super) fn delete_all_call_contexts<R>(
        &mut self,
        reject: impl Fn(&CallContext) -> Option<R>,
    ) -> Vec<R> {
        let mut reject_responses = Vec::new();

        let call_contexts = std::mem::take(&mut self.call_contexts);
        self.call_contexts = call_contexts
            .into_iter()
            .map(|(id, mut call_context)| {
                if !call_context.has_responded() {
                    // Generate a reject response.
                    if let Some(response) = reject(&call_context) {
                        reject_responses.push(response)
                    }

                    call_context.mark_responded();
                    self.stats
                        .on_call_context_response(&call_context.call_origin);
                }

                // Mark the call context as deleted.
                call_context.mark_deleted();
                (id, call_context)
            })
            .collect();
        debug_assert!(self.stats_ok());

        reject_responses
    }
}

impl From<&CanisterCall> for CallOrigin {
    fn from(msg: &CanisterCall) -> Self {
        match msg {
            CanisterCall::Request(request) => CallOrigin::CanisterUpdate(
                request.sender,
                request.sender_reply_callback,
                request.deadline,
                request.method_name.clone(),
            ),
            CanisterCall::Ingress(ingress) => CallOrigin::Ingress(
                ingress.source,
                ingress.message_id.clone(),
                ingress.method_name.clone(),
            ),
        }
    }
}

impl From<&CanisterCallOrTask> for CallOrigin {
    fn from(call_or_task: &CanisterCallOrTask) -> Self {
        match call_or_task {
            CanisterCallOrTask::Update(call) | CanisterCallOrTask::Query(call) => {
                CallOrigin::from(call)
            }
            CanisterCallOrTask::Task(_) => CallOrigin::SystemTask,
        }
    }
}

/// Calculates the deadlines of all best-effort callbacks.
///
/// Time complexity: `O(n)`.
fn calculate_callback_deadlines(
    callbacks: &MutableIntMap<CallbackId, Arc<Callback>>,
) -> BTreeSet<(CoarseTime, CallbackId)> {
    callbacks
        .iter()
        .map(|(id, callback)| (callback.deadline, *id))
        .filter(|(deadline, _)| *deadline != NO_DEADLINE)
        .collect()
}

/// Calculates the counts of callbacks per call context.
///
/// Time complexity: `O(n)`.
fn calculate_outstanding_callbacks(
    callbacks: &MutableIntMap<CallbackId, Arc<Callback>>,
) -> MutableIntMap<CallContextId, usize> {
    callbacks
        .iter()
        .map(|(_, callback)| callback.call_context_id)
        .fold(
            MutableIntMap::<CallContextId, usize>::new(),
            |mut counts, call_context_id| {
                counts.insert(
                    call_context_id,
                    counts.get(&call_context_id).unwrap_or(&0) + 1,
                );
                counts
            },
        )
}

impl AsInt for (CoarseTime, CallbackId) {
    type Repr = u128;

    #[inline]
    fn as_int(&self) -> u128 {
        ((self.0.as_secs_since_unix_epoch() as u128) << 64) | self.1.get() as u128
    }
}

pub mod testing {
    use super::{CallContext, CallContextManager};
    use ic_types::messages::CallContextId;

    /// Exposes `CallContextManager` internals for use in other modules' or crates'
    /// tests.
    pub trait CallContextManagerTesting {
        /// Testing only: Registers the given call context (which may already be
        /// responded or deleted).
        fn with_call_context(&mut self, call_context: CallContext) -> CallContextId;
    }

    impl CallContextManagerTesting for CallContextManager {
        fn with_call_context(&mut self, call_context: CallContext) -> CallContextId {
            if !call_context.responded {
                self.stats.on_new_call_context(&call_context.call_origin);
            }

            self.next_call_context_id += 1;
            let id = CallContextId::from(self.next_call_context_id);
            self.call_contexts.insert(id, call_context);

            debug_assert!(self.stats_ok());

            id
        }
    }
}
