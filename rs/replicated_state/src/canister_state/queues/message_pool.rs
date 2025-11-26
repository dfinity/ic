use super::CanisterInput;
use crate::page_map::int_map::{AsInt, MutableIntMap};
use crate::{
    CLASS_BEST_EFFORT, CLASS_GUARANTEED_RESPONSE, CONTEXT_INBOUND, CONTEXT_OUTBOUND, KIND_REQUEST,
    KIND_RESPONSE,
};
use ic_types::messages::{
    CallbackId, MAX_RESPONSE_COUNT_BYTES, NO_DEADLINE, Request, RequestOrResponse, Response,
};
use ic_types::time::CoarseTime;
use ic_types::{CountBytes, Cycles, Time};
use ic_validate_eq::ValidateEq;
use ic_validate_eq_derive::ValidateEq;
use std::collections::BTreeSet;
use std::marker::PhantomData;
use std::ops::{AddAssign, SubAssign};
use std::sync::Arc;
use std::time::Duration;

pub mod proto;
#[cfg(test)]
pub(super) mod tests;

/// The lifetime of a guaranteed response call request in an output queue, from
/// which its deadline is computed (as `now + REQUEST_LIFETIME`).
pub const REQUEST_LIFETIME: Duration = Duration::from_secs(300);

/// Bit encoding the message kind (request or response).
#[repr(u64)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub(super) enum Kind {
    Request = 0,
    Response = Self::BIT,
}

impl Kind {
    /// Message kind bit (request or response).
    const BIT: u64 = 1;

    /// Returns a string representation to be used as metric label value.
    pub(super) fn to_label_value(self) -> &'static str {
        match self {
            Self::Request => KIND_REQUEST,
            Self::Response => KIND_RESPONSE,
        }
    }
}

impl From<&RequestOrResponse> for Kind {
    fn from(msg: &RequestOrResponse) -> Self {
        match msg {
            RequestOrResponse::Request(_) => Kind::Request,
            RequestOrResponse::Response(_) => Kind::Response,
        }
    }
}

/// Bit encoding the message context (inbound or outbound).
#[repr(u64)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub(super) enum Context {
    Inbound = 0,
    Outbound = Self::BIT,
}

impl Context {
    /// Message context bit (inbound or outbound).
    const BIT: u64 = 1 << 1;

    /// Returns a string representation to be used as metric label value.
    pub(super) fn to_label_value(self) -> &'static str {
        match self {
            Self::Inbound => CONTEXT_INBOUND,
            Self::Outbound => CONTEXT_OUTBOUND,
        }
    }
}

/// Bit encoding the message class (guaranteed response vs best-effort).
#[repr(u64)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub(super) enum Class {
    GuaranteedResponse = 0,
    BestEffort = Self::BIT,
}

impl Class {
    /// Message class bit (guaranteed response vs best-effort).
    const BIT: u64 = 1 << 2;

    /// Returns a string representation to be used as metric label value.
    pub(super) fn to_label_value(self) -> &'static str {
        match self {
            Self::GuaranteedResponse => CLASS_GUARANTEED_RESPONSE,
            Self::BestEffort => CLASS_BEST_EFFORT,
        }
    }
}

impl From<&RequestOrResponse> for Class {
    fn from(msg: &RequestOrResponse) -> Self {
        if msg.deadline() == NO_DEADLINE {
            Class::GuaranteedResponse
        } else {
            Class::BestEffort
        }
    }
}

/// A generated identifier for a message held in a `MessagePool` that also
/// encodes the message kind (request or response), context (incoming or
/// outgoing) and class (guaranteed response or best-effort).
///
/// This is the key used internally by `MessagePool` to identify messages.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
struct Id(u64);

impl Id {
    /// Number of `Id` bits used as flags.
    const BITMASK_LEN: u32 = 3;

    /// The minimum `Id` value, for use in e.g. `BTreeSet::split_off()` calls.
    const MIN: Self = Self(0);

    fn kind(&self) -> Kind {
        if self.0 & Kind::BIT == Kind::Request as u64 {
            Kind::Request
        } else {
            Kind::Response
        }
    }

    fn context(&self) -> Context {
        if self.0 & Context::BIT == Context::Inbound as u64 {
            Context::Inbound
        } else {
            Context::Outbound
        }
    }

    fn class(&self) -> Class {
        if self.0 & Class::BIT == Class::GuaranteedResponse as u64 {
            Class::GuaranteedResponse
        } else {
            Class::BestEffort
        }
    }

    /// Tests whether this `Id` represents an inbound best-effort response.
    fn is_inbound_best_effort_response(&self) -> bool {
        self.0 & (Context::BIT | Class::BIT | Kind::BIT)
            == (Context::Inbound as u64 | Class::BestEffort as u64 | Kind::Response as u64)
    }

    /// Tests whether this `Id` represents an outbound guaranteed-response request.
    fn is_outbound_guaranteed_request(&self) -> bool {
        self.0 & (Context::BIT | Class::BIT | Kind::BIT)
            == (Context::Outbound as u64 | Class::GuaranteedResponse as u64 | Kind::Request as u64)
    }
}

impl AsInt for Id {
    type Repr = u64;

    #[inline]
    fn as_int(&self) -> u64 {
        self.0
    }
}

impl AsInt for (CoarseTime, Id) {
    type Repr = u128;

    #[inline]
    fn as_int(&self) -> u128 {
        ((self.0.as_secs_since_unix_epoch() as u128) << 64) | self.1.0 as u128
    }
}

impl AsInt for (usize, Id) {
    type Repr = u128;

    #[inline]
    fn as_int(&self) -> u128 {
        ((self.0 as u128) << 64) | self.1.0 as u128
    }
}

/// A typed reference -- inbound (`CanisterInput`) or outbound
/// (`RequestOrResponse`) -- to a message in the `MessagePool`.
#[derive(Debug)]
pub(super) struct Reference<T>(u64, PhantomData<T>);

impl<T> Reference<T>
where
    T: ToContext,
{
    /// Constructs a new `Reference<T>` of the given `class` and `kind`.
    fn new(class: Class, kind: Kind, generator: u64) -> Self {
        Self(
            T::context() as u64 | class as u64 | kind as u64 | (generator << Id::BITMASK_LEN),
            PhantomData,
        )
    }
}

impl<T> Reference<T> {
    pub(super) fn kind(&self) -> Kind {
        Id::from(self).kind()
    }

    #[cfg(test)]
    fn context(&self) -> Context {
        Id::from(self).context()
    }

    #[allow(dead_code)]
    fn class(&self) -> Class {
        Id::from(self).class()
    }

    /// Tests whether this is a reference to an inbound best-effort response.
    pub(super) fn is_inbound_best_effort_response(&self) -> bool {
        Id::from(self).is_inbound_best_effort_response()
    }
}

impl<T> Clone for Reference<T> {
    fn clone(&self) -> Self {
        *self
    }
}

// This and other traits must be explicitly implemented because
// `#[derive(Copy)]` generates something like `impl<T> Copy for Reference<T>
// where T: Copy`. And because neither `CanisterInput` nor `RequestOrResponse`
// are `Copy`, the attribute does nothing.
impl<T> Copy for Reference<T> {}

impl<T> PartialEq for Reference<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<T> Eq for Reference<T> {}

impl<T> PartialOrd for Reference<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<T> Ord for Reference<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl<T> From<&Reference<T>> for Id {
    fn from(reference: &Reference<T>) -> Id {
        Id(reference.0)
    }
}

impl<T> From<Reference<T>> for Id {
    fn from(reference: Reference<T>) -> Id {
        Id(reference.0)
    }
}

impl<T> AsInt for Reference<T> {
    type Repr = u64;

    #[inline]
    fn as_int(&self) -> u64 {
        self.0
    }
}

/// A reference to an inbound message (returned as a `CanisterInput`).
pub(super) type InboundReference = Reference<CanisterInput>;

/// A reference to an outbound message (returned as a `RequestOrResponse`).
pub(super) type OutboundReference = Reference<RequestOrResponse>;

/// A means for queue item types to declare whether they're inbound or outbound.
pub(super) trait ToContext {
    /// The context (inbound or outbound) of this queue item type.
    fn context() -> Context;
}

impl ToContext for CanisterInput {
    fn context() -> Context {
        Context::Inbound
    }
}

impl ToContext for RequestOrResponse {
    fn context() -> Context {
        Context::Outbound
    }
}

/// An enum that can hold either an inbound or an outbound reference.
#[derive(Eq, PartialEq, Ord, PartialOrd, Debug)]
pub(super) enum SomeReference {
    Inbound(InboundReference),
    Outbound(OutboundReference),
}

impl SomeReference {
    fn id(&self) -> Id {
        match self {
            Self::Inbound(reference) => reference.into(),
            Self::Outbound(reference) => reference.into(),
        }
    }

    pub(super) fn kind(&self) -> Kind {
        self.id().kind()
    }

    pub(super) fn context(&self) -> Context {
        self.id().context()
    }

    pub(super) fn class(&self) -> Class {
        self.id().class()
    }
}

impl From<Id> for SomeReference {
    fn from(id: Id) -> SomeReference {
        match id.context() {
            Context::Inbound => SomeReference::Inbound(Reference(id.0, PhantomData)),
            Context::Outbound => SomeReference::Outbound(Reference(id.0, PhantomData)),
        }
    }
}

/// Helper for encoding / decoding `pb_queues::canister_queues::CallbackReference`.
#[derive(Clone, Eq, PartialEq, Debug)]
pub(super) struct CallbackReference(pub(super) InboundReference, pub(super) CallbackId);

/// A pool of canister messages, guaranteed response and best effort, with
/// built-in support for time-based expiration and load shedding.
///
/// Messages in the pool are identified by a key (`Id`) generated by the pool.
/// The key also encodes the message kind (request or response); and context
/// (inbound or outbound). The public API however, uses exclusively typed
/// references (`Reference<CantisterInput>` for inbound references  and
/// `Reference<RequestOrResponse>` for outbound references).
///
/// Messages are added to the deadline queue based on their class (best-effort
/// vs guaranteed response) and context: i.e. all best-effort messages except
/// responses in input queues; plus guaranteed response call requests in output
/// queues. All best-effort messages (and only best-effort messages) are added
/// to the load shedding queue.
///
/// All pool operations except `expire_messages()` and
/// `calculate_message_stats()` (only called during deserialization) execute in
/// at most `O(log(N))` time.
#[derive(Clone, Eq, PartialEq, Debug, Default, ValidateEq)]
pub(super) struct MessagePool {
    /// Pool contents.
    #[validate_eq(CompareWithValidateEq)]
    messages: MutableIntMap<Id, RequestOrResponse>,

    /// Records the (implicit) deadlines of all the outbound guaranteed response
    /// requests (only).
    ///
    /// Invariants:
    ///  * Contains all outbound guaranteed requests:
    ///    `outbound_guaranteed_request_deadlines.keys().collect() == messages.keys().filter(|id| (id.context(), id.class(), id.kind()) == (Context::Outbound, Class::GuaranteedResponse, Kind::Request)).collect()`
    ///  * The deadline matches the one recorded in `deadline_queue`:
    ///    `outbound_guaranteed_request_deadlines.iter().all(|(id, deadline)| deadline_queue.contains(&(deadline, id)))`
    outbound_guaranteed_request_deadlines: MutableIntMap<Id, CoarseTime>,

    /// Running message stats for the pool.
    message_stats: MessageStats,

    /// Deadline priority queue. Holds all best-effort messages except responses in
    /// input queues (which we don't want to expire); plus guaranteed response call
    /// requests in output queues (which expire after `REQUEST_LIFETIME`); ordered
    /// by deadline.
    ///
    /// Message IDs break ties, ensuring deterministic ordering.
    deadline_queue: MutableIntMap<(CoarseTime, Id), ()>,

    /// Load shedding priority queue. Holds all best-effort messages, ordered by
    /// size.
    ///
    /// Message IDs break ties, ensuring deterministic ordering.
    size_queue: MutableIntMap<(usize, Id), ()>,

    /// A monotonically increasing counter used to generate unique message IDs.
    message_id_generator: u64,
}

impl MessagePool {
    /// Inserts an inbound message (one that is to be enqueued in an input queue)
    /// into the pool. Returns the ID assigned to the message.
    ///
    /// The message is added to the deadline queue iff it is a best-effort request
    /// (best effort responses that already made it into an input queue should not
    /// expire). It is added to the load shedding queue if it is a best-effort
    /// message.
    pub(super) fn insert_inbound(&mut self, msg: RequestOrResponse) -> InboundReference {
        let actual_deadline = match &msg {
            RequestOrResponse::Request(request) => request.deadline,

            // Never expire responses already enqueued in an input queue.
            RequestOrResponse::Response(_) => NO_DEADLINE,
        };

        self.insert_impl(msg, actual_deadline, Context::Inbound)
    }

    /// Reserves an `InboundReference` for a timeout reject response for a
    /// best-effort callback.
    ///
    /// This is equivalent to inserting and then immediately removing the response.
    pub(super) fn make_inbound_timeout_response_reference(&mut self) -> InboundReference {
        self.next_reference(Class::BestEffort, Kind::Response)
    }

    /// Inserts an outbound request (one that is to be enqueued in an output queue)
    /// into the pool. Returns the reference assigned to the request.
    ///
    /// The request is always added to the deadline queue: if it is a best-effort
    /// request, with its explicit deadline; if it is a guaranteed response call
    /// request, with a deadline of `now + REQUEST_LIFETIME`. It is added to the
    /// load shedding queue iff it is a best-effort request.
    pub(super) fn insert_outbound_request(
        &mut self,
        request: Arc<Request>,
        now: Time,
    ) -> OutboundReference {
        let actual_deadline = if request.deadline == NO_DEADLINE {
            // Guaranteed response call requests in canister output queues expire after
            // `REQUEST_LIFETIME`.
            CoarseTime::floor(now + REQUEST_LIFETIME)
        } else {
            // Best-effort requests expire as per their specified deadline.
            request.deadline
        };

        self.insert_impl(
            RequestOrResponse::Request(request),
            actual_deadline,
            Context::Outbound,
        )
    }

    /// Inserts an outbound response (one that is to be enqueued in an output queue)
    /// into the pool. Returns the reference assigned to the response.
    ///
    /// The response is added to both the deadline queue and the load shedding queue
    /// iff it is a best-effort response.
    pub(super) fn insert_outbound_response(
        &mut self,
        response: Arc<Response>,
    ) -> OutboundReference {
        let actual_deadline = response.deadline;
        self.insert_impl(
            RequestOrResponse::Response(response),
            actual_deadline,
            Context::Outbound,
        )
    }

    /// Inserts the given message into the pool. Returns the reference assigned to
    /// the message.
    ///
    /// The message is recorded into the deadline queue with the provided
    /// `actual_deadline` iff it is non-zero (as opposed to the message's nominal
    /// deadline; this is so we can expire outgoing guaranteed response requests;
    /// and not expire incoming best-effort responses). It is recorded in the load
    /// shedding priority queue iff it is a best-effort message.
    fn insert_impl<T>(
        &mut self,
        msg: RequestOrResponse,
        actual_deadline: CoarseTime,
        context: Context,
    ) -> Reference<T>
    where
        T: ToContext,
    {
        let kind = Kind::from(&msg);
        let class = Class::from(&msg);
        let reference = self.next_reference(class, kind);
        let id = reference.into();

        let size_bytes = msg.count_bytes();

        // Update message stats.
        self.message_stats += MessageStats::stats_delta(&msg, context);

        // Insert.
        assert!(self.messages.insert(id, msg).is_none());
        debug_assert_eq!(
            Self::calculate_message_stats(&self.messages),
            self.message_stats
        );

        // Record in deadline queue iff `actual_deadline` is non-zero. This applies to
        // all best-effort messages except responses in input queues; plus guaranteed
        // response requests in output queues
        if actual_deadline != NO_DEADLINE {
            self.deadline_queue.insert((actual_deadline, id), ());

            // Record in the outbound guaranteed response deadline map, iff it's an outbound
            // guaranteed response request.
            if class == Class::GuaranteedResponse {
                debug_assert_eq!((Context::Outbound, Kind::Request), (context, kind));
                self.outbound_guaranteed_request_deadlines
                    .insert(id, actual_deadline);
            }
        }

        // Record in load shedding queue iff it's a best-effort message.
        if class == Class::BestEffort {
            self.size_queue.insert((size_bytes, id), ());
        }

        reference
    }

    /// Reserves and returns a new message reference.
    fn next_reference<T>(&mut self, class: Class, kind: Kind) -> Reference<T>
    where
        T: ToContext,
    {
        let reference = Reference::new(class, kind, self.message_id_generator);
        self.message_id_generator += 1;
        reference
    }

    /// Retrieves the message with the given `Reference`.
    pub(super) fn get<T>(&self, reference: Reference<T>) -> Option<&RequestOrResponse> {
        self.messages.get(&reference.into())
    }

    /// Removes the message with the given `Reference` from the pool.
    ///
    /// Updates the stats; and the priority queues, where applicable.
    pub(super) fn take<T>(&mut self, reference: Reference<T>) -> Option<RequestOrResponse> {
        let id = reference.into();
        let msg = self.take_impl(id)?;

        self.remove_from_deadline_queue(id, &msg);
        self.remove_from_size_queue(id, &msg);

        debug_assert_eq!(Ok(()), self.check_invariants());
        Some(msg)
    }

    /// Removes the message with the given `Reference` from the pool.
    ///
    /// Updates the stats, but not the priority queues.
    fn take_impl(&mut self, id: Id) -> Option<RequestOrResponse> {
        let msg = self.messages.remove(&id)?;
        // Sanity check.
        debug_assert_eq!(
            (id.class(), id.kind()),
            (Class::from(&msg), Kind::from(&msg))
        );

        self.message_stats -= MessageStats::stats_delta(&msg, id.context());
        debug_assert_eq!(
            Self::calculate_message_stats(&self.messages),
            self.message_stats
        );

        Some(msg)
    }

    /// Removes the given message from the deadline queue and from
    /// `self.outbound_guaranteed_request_deadlines`, if applicable.
    fn remove_from_deadline_queue(&mut self, id: Id, msg: &RequestOrResponse) {
        use Class::*;
        use Context::*;
        use Kind::*;

        match (id.context(), id.class(), id.kind()) {
            // Outbound guaranteed response requests have (separately recorded) deadlines.
            (Outbound, GuaranteedResponse, Request) => {
                let deadline = self
                    .outbound_guaranteed_request_deadlines
                    .remove(&id)
                    .unwrap();
                let removed = self.deadline_queue.remove(&(deadline, id)).is_some();
                debug_assert!(removed);
            }

            // All other guaranteed response messages do not expire.
            (_, GuaranteedResponse, _) => {}

            // Inbound best-effort responses do not expire.
            (Inbound, BestEffort, Response) => {}

            // All other best-effort messages do expire.
            (_, BestEffort, _) => {
                let removed = self.deadline_queue.remove(&(msg.deadline(), id)).is_some();
                debug_assert!(removed);
            }
        }
    }

    /// Removes the given message from the load shedding queue.
    fn remove_from_size_queue(&mut self, id: Id, msg: &RequestOrResponse) {
        if id.class() == Class::BestEffort {
            let removed = self.size_queue.remove(&(msg.count_bytes(), id)).is_some();
            debug_assert!(removed);
        }
    }

    /// Queries whether any message's deadline has expired.
    ///
    /// Time complexity: `O(log(self.len()))`.
    pub(super) fn has_expired_deadlines(&self, now: Time) -> bool {
        if let Some((deadline, _)) = self.deadline_queue.min_key() {
            let now = CoarseTime::floor(now);
            if *deadline < now {
                return true;
            }
        }
        false
    }

    /// Removes and returns all messages with expired deadlines (i.e. `deadline <
    /// now`). Updates the stats; and the priority queues, where applicable.
    ///
    /// Time complexity per expired message: `O(log(self.len()))`.
    pub(super) fn expire_messages(&mut self, now: Time) -> Vec<(SomeReference, RequestOrResponse)> {
        if self.deadline_queue.is_empty() {
            // No messages with deadlines, bail out.
            return Vec::new();
        }

        let now = CoarseTime::floor(now);
        if self.deadline_queue.min_key().unwrap().0 >= now {
            // No expired messages, bail out.
            return Vec::new();
        }

        // Split the deadline queue at `now`.
        let mut temp = self.deadline_queue.split_off(&(now, Id::MIN));
        std::mem::swap(&mut temp, &mut self.deadline_queue);

        // Take and return all expired messages.
        let expired = temp
            .into_iter()
            .map(|((_, id), _)| {
                let msg = self.take_impl(id).unwrap();
                if id.is_outbound_guaranteed_request() {
                    self.outbound_guaranteed_request_deadlines.remove(&id);
                }
                self.remove_from_size_queue(id, &msg);
                (id.into(), msg)
            })
            .collect();

        debug_assert_eq!(Ok(()), self.check_invariants());
        expired
    }

    /// Removes and returns the largest best-effort message in the pool, if any.
    /// Updates the stats; and the priority queues, where applicable.
    ///
    /// Time complexity: `O(log(self.len()))`.
    pub(super) fn shed_largest_message(&mut self) -> Option<(SomeReference, RequestOrResponse)> {
        if let Some(&(size_bytes, id)) = self.size_queue.max_key() {
            self.size_queue.remove(&(size_bytes, id)).unwrap();
            debug_assert_eq!(Class::BestEffort, id.class());

            let msg = self.take_impl(id).unwrap();
            self.remove_from_deadline_queue(id, &msg);

            debug_assert_eq!(Ok(()), self.check_invariants());
            return Some((id.into(), msg));
        }

        // Nothing to shed.
        None
    }

    /// Returns the number of messages in the pool.
    pub(super) fn len(&self) -> usize {
        self.messages.len()
    }

    /// Returns a reference to the pool's message stats.
    pub(super) fn message_stats(&self) -> &MessageStats {
        &self.message_stats
    }

    /// Computes message stats from scratch. Used when deserializing and in
    /// `debug_assert!()` checks.
    ///
    /// Time complexity: `O(n)`.
    fn calculate_message_stats(messages: &MutableIntMap<Id, RequestOrResponse>) -> MessageStats {
        let mut stats = MessageStats::default();
        for (id, msg) in messages.iter() {
            stats += MessageStats::stats_delta(msg, id.context());
        }
        stats
    }

    /// Invariant check for use at loading time and in `debug_asserts`.
    ///
    /// Time complexity: `O(n * log(n))`.
    fn check_invariants(&self) -> Result<(), String> {
        // `Id` kind and class must match those of the message.
        self.messages.iter().try_for_each(|(id, msg)| {
            if id.kind() != Kind::from(msg) {
                return Err(format!(
                    "Message kind mismatch: message {:?}, Id {:?}",
                    Kind::from(msg),
                    id.kind()
                ));
            }
            if id.class() != Class::from(msg) {
                return Err(format!(
                    "Message class mismatch: message {:?}, Id {:?}",
                    Class::from(msg),
                    id.class()
                ));
            }
            Ok(())
        })?;

        // Validate the priority queues.
        let (expected_deadline_queue, expected_size_queue) = Self::calculate_priority_queues(
            &self.messages,
            &self.outbound_guaranteed_request_deadlines,
        );
        if self.deadline_queue != expected_deadline_queue {
            return Err(format!(
                "Unexpected deadline queue: expected {:?}, actual {:?}",
                expected_deadline_queue, self.deadline_queue
            ));
        }
        if self.size_queue != expected_size_queue {
            return Err(format!(
                "Unexpected load shedding queue: expected {:?}, actual {:?}",
                expected_size_queue, self.size_queue
            ));
        }

        // Validate that `outbound_guaranteed_request_deadlines` holds all outbound
        // guaranteed response requests (and nothing else).
        let mut expected_outbound_guaranteed_request_ids = BTreeSet::new();
        self.messages.keys().for_each(|id| {
            if id.is_outbound_guaranteed_request() {
                expected_outbound_guaranteed_request_ids.insert(id);
            }
        });
        if self
            .outbound_guaranteed_request_deadlines
            .keys()
            .collect::<BTreeSet<_>>()
            != expected_outbound_guaranteed_request_ids
        {
            return Err(format!(
                "Unexpected outbound guaranteed request deadlines: expected keys {:?}, actual {:?}",
                expected_outbound_guaranteed_request_ids,
                self.outbound_guaranteed_request_deadlines
            ));
        }

        if !self.messages.is_empty() {
            // Validate `message_id_generator` against the largest seen `Id`.
            let mut max_message_id = 0;
            self.messages.keys().for_each(|id| {
                max_message_id = max_message_id.max(id.0);
            });
            if max_message_id >> Id::BITMASK_LEN >= self.message_id_generator {
                return Err(format!(
                    "`Id` out of bounds: max `Id`: {}, message_id_generator: {}",
                    max_message_id, self.message_id_generator
                ));
            }
        }

        Ok(())
    }

    /// Calculates the deadline and load shedding priority queues for the given
    /// messages and outbound guaranteed response request (implicit) deadlines.
    ///
    /// Time complexity: `O(n * log(n))`.
    #[allow(clippy::type_complexity)]
    fn calculate_priority_queues(
        messages: &MutableIntMap<Id, RequestOrResponse>,
        outbound_guaranteed_request_deadlines: &MutableIntMap<Id, CoarseTime>,
    ) -> (
        MutableIntMap<(CoarseTime, Id), ()>,
        MutableIntMap<(usize, Id), ()>,
    ) {
        let mut expected_deadline_queue = MutableIntMap::new();
        let mut expected_size_queue = MutableIntMap::new();
        messages.iter().for_each(|(id, msg)| {
            use Class::*;
            use Context::*;
            use Kind::*;
            match (id.context(), id.class(), id.kind()) {
                // Outbound guaranteed response requests have (separately recorded) deadlines.
                (Outbound, GuaranteedResponse, Request) => {
                    let deadline = outbound_guaranteed_request_deadlines.get(id).unwrap();
                    expected_deadline_queue.insert((*deadline, *id), ());
                }

                // All other guaranteed response messages neither expire nor can be shed.
                (_, GuaranteedResponse, _) => {}

                // Inbound best-effort responses don't have expiration deadlines, but can be
                // shed.
                (Inbound, BestEffort, Response) => {
                    expected_size_queue.insert((msg.count_bytes(), *id), ());
                }

                // All other best-effort messages are enqueued in both priority queues.
                (_, BestEffort, _) => {
                    expected_deadline_queue.insert((msg.deadline(), *id), ());
                    expected_size_queue.insert((msg.count_bytes(), *id), ());
                }
            }
        });
        (expected_deadline_queue, expected_size_queue)
    }
}

/// Running stats for all messages in a `MessagePool`.
///
/// Slot reservations and memory reservations for guaranteed responses, being
/// queue metrics, are tracked separately by `CanisterQueues`.
///
/// All operations (computing stats deltas and retrieving the stats) are
/// constant time.
#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub(super) struct MessageStats {
    /// Total byte size of all messages in the pool.
    pub(super) size_bytes: usize,

    /// Total byte size of all best-effort messages in the pool. Zero iff the pool
    /// contains zero best-effort messages.
    pub(super) best_effort_message_bytes: usize,

    /// Total byte size of all guaranteed responses in the pool.
    pub(super) guaranteed_responses_size_bytes: usize,

    /// Sum total of bytes above `MAX_RESPONSE_COUNT_BYTES` per oversized guaranteed
    /// response call request. Execution allows local-subnet requests larger than
    /// `MAX_RESPONSE_COUNT_BYTES`.
    pub(super) oversized_guaranteed_requests_extra_bytes: usize,

    /// Total byte size of all messages in input queue.
    pub(super) inbound_size_bytes: usize,

    /// Count of messages in input queues.
    pub(super) inbound_message_count: usize,

    /// Count of responses in input queues.
    pub(super) inbound_response_count: usize,

    /// Count of guaranteed response requests in input queues.
    ///
    /// At the end of each round, this plus the number of not yet responded
    /// guaranteed response call contexts must be equal to the number of guaranteed
    /// response memory reservations for inbound calls.
    pub(super) inbound_guaranteed_request_count: usize,

    /// Count of guaranteed responses in input queues.
    ///
    /// At the end of each round, the number of guaranteed response callbacks minus
    /// this must be equal to the number of guaranteed response memory reservations
    /// for outbound calls.
    pub(super) inbound_guaranteed_response_count: usize,

    /// Count of messages in output queues.
    pub(super) outbound_message_count: usize,

    /// Amount of cycles attached to all messages in the pool.
    pub(super) cycles: Cycles,
}

impl MessageStats {
    /// Returns the memory usage of the guaranteed response messages in the pool,
    /// excluding memory reservations for guaranteed responses.
    ///
    /// Complexity: `O(1)`.
    pub fn guaranteed_response_memory_usage(&self) -> usize {
        self.guaranteed_responses_size_bytes + self.oversized_guaranteed_requests_extra_bytes
    }

    /// Calculates the change in stats caused by pushing (+) or popping (-) the
    /// given message in the given context.
    fn stats_delta(msg: &RequestOrResponse, context: Context) -> MessageStats {
        match msg {
            RequestOrResponse::Request(req) => Self::request_stats_delta(req, context),
            RequestOrResponse::Response(rep) => Self::response_stats_delta(rep, context),
        }
    }

    /// Calculates the change in stats caused by pushing (+) or popping (-) the
    /// given request in the given context.
    fn request_stats_delta(req: &Request, context: Context) -> MessageStats {
        use Class::*;
        use Context::*;

        let size_bytes = req.count_bytes();
        let class = if req.deadline == NO_DEADLINE {
            GuaranteedResponse
        } else {
            BestEffort
        };

        // This is a request, response stats are all unaffected.
        let guaranteed_responses_size_bytes = 0;
        let inbound_response_count = 0;
        let inbound_guaranteed_response_count = 0;

        match (context, class) {
            (Inbound, GuaranteedResponse) => MessageStats {
                size_bytes,
                best_effort_message_bytes: 0,
                guaranteed_responses_size_bytes,
                oversized_guaranteed_requests_extra_bytes: size_bytes
                    .saturating_sub(MAX_RESPONSE_COUNT_BYTES),
                inbound_size_bytes: size_bytes,
                inbound_message_count: 1,
                inbound_response_count,
                inbound_guaranteed_request_count: 1,
                inbound_guaranteed_response_count,
                outbound_message_count: 0,
                cycles: req.payment,
            },
            (Inbound, BestEffort) => MessageStats {
                size_bytes,
                best_effort_message_bytes: size_bytes,
                guaranteed_responses_size_bytes,
                oversized_guaranteed_requests_extra_bytes: 0,
                inbound_size_bytes: size_bytes,
                inbound_message_count: 1,
                inbound_response_count,
                inbound_guaranteed_request_count: 0,
                inbound_guaranteed_response_count,
                outbound_message_count: 0,
                cycles: req.payment,
            },
            (Outbound, GuaranteedResponse) => MessageStats {
                size_bytes,
                best_effort_message_bytes: 0,
                guaranteed_responses_size_bytes,
                oversized_guaranteed_requests_extra_bytes: size_bytes
                    .saturating_sub(MAX_RESPONSE_COUNT_BYTES),
                inbound_size_bytes: 0,
                inbound_message_count: 0,
                inbound_response_count,
                inbound_guaranteed_request_count: 0,
                inbound_guaranteed_response_count,
                outbound_message_count: 1,
                cycles: req.payment,
            },
            (Outbound, BestEffort) => MessageStats {
                size_bytes,
                best_effort_message_bytes: size_bytes,
                guaranteed_responses_size_bytes,
                oversized_guaranteed_requests_extra_bytes: 0,
                inbound_size_bytes: 0,
                inbound_message_count: 0,
                inbound_response_count,
                inbound_guaranteed_request_count: 0,
                inbound_guaranteed_response_count,
                outbound_message_count: 1,
                cycles: req.payment,
            },
        }
    }

    /// Calculates the change in stats caused by pushing (+) or popping (-) the
    /// given response in the given context.
    fn response_stats_delta(rep: &Response, context: Context) -> MessageStats {
        use Class::*;
        use Context::*;

        let size_bytes = rep.count_bytes();
        let class = if rep.deadline == NO_DEADLINE {
            GuaranteedResponse
        } else {
            BestEffort
        };

        // This is a response, request stats are all unaffected.
        let oversized_guaranteed_requests_extra_bytes = 0;
        let inbound_guaranteed_request_count = 0;

        match (context, class) {
            (Inbound, GuaranteedResponse) => MessageStats {
                size_bytes,
                best_effort_message_bytes: 0,
                guaranteed_responses_size_bytes: size_bytes,
                oversized_guaranteed_requests_extra_bytes,
                inbound_size_bytes: size_bytes,
                inbound_message_count: 1,
                inbound_response_count: 1,
                inbound_guaranteed_request_count,
                inbound_guaranteed_response_count: 1,
                outbound_message_count: 0,
                cycles: rep.refund,
            },
            (Inbound, BestEffort) => MessageStats {
                size_bytes,
                best_effort_message_bytes: size_bytes,
                guaranteed_responses_size_bytes: 0,
                oversized_guaranteed_requests_extra_bytes,
                inbound_size_bytes: size_bytes,
                inbound_message_count: 1,
                inbound_response_count: 1,
                inbound_guaranteed_request_count,
                inbound_guaranteed_response_count: 0,
                outbound_message_count: 0,
                cycles: rep.refund,
            },
            (Outbound, GuaranteedResponse) => MessageStats {
                size_bytes,
                best_effort_message_bytes: 0,
                guaranteed_responses_size_bytes: size_bytes,
                oversized_guaranteed_requests_extra_bytes,
                inbound_size_bytes: 0,
                inbound_message_count: 0,
                inbound_response_count: 0,
                inbound_guaranteed_request_count,
                inbound_guaranteed_response_count: 0,
                outbound_message_count: 1,
                cycles: rep.refund,
            },
            (Outbound, BestEffort) => MessageStats {
                size_bytes,
                best_effort_message_bytes: size_bytes,
                guaranteed_responses_size_bytes: 0,
                oversized_guaranteed_requests_extra_bytes,
                inbound_size_bytes: 0,
                inbound_message_count: 0,
                inbound_response_count: 0,
                inbound_guaranteed_request_count,
                inbound_guaranteed_response_count: 0,
                outbound_message_count: 1,
                cycles: rep.refund,
            },
        }
    }
}

impl AddAssign<MessageStats> for MessageStats {
    fn add_assign(&mut self, rhs: MessageStats) {
        let MessageStats {
            size_bytes,
            best_effort_message_bytes,
            guaranteed_responses_size_bytes,
            oversized_guaranteed_requests_extra_bytes,
            inbound_size_bytes,
            inbound_message_count,
            inbound_response_count,
            inbound_guaranteed_request_count,
            inbound_guaranteed_response_count,
            outbound_message_count,
            cycles,
        } = rhs;
        self.size_bytes += size_bytes;
        self.best_effort_message_bytes += best_effort_message_bytes;
        self.guaranteed_responses_size_bytes += guaranteed_responses_size_bytes;
        self.oversized_guaranteed_requests_extra_bytes += oversized_guaranteed_requests_extra_bytes;
        self.inbound_size_bytes += inbound_size_bytes;
        self.inbound_message_count += inbound_message_count;
        self.inbound_response_count += inbound_response_count;
        self.inbound_guaranteed_request_count += inbound_guaranteed_request_count;
        self.inbound_guaranteed_response_count += inbound_guaranteed_response_count;
        self.outbound_message_count += outbound_message_count;
        self.cycles += cycles;
    }
}

impl SubAssign<MessageStats> for MessageStats {
    fn sub_assign(&mut self, rhs: MessageStats) {
        let MessageStats {
            size_bytes,
            best_effort_message_bytes,
            guaranteed_responses_size_bytes,
            oversized_guaranteed_requests_extra_bytes,
            inbound_size_bytes,
            inbound_message_count,
            inbound_response_count,
            inbound_guaranteed_request_count,
            inbound_guaranteed_response_count,
            outbound_message_count,
            cycles,
        } = rhs;
        self.size_bytes -= size_bytes;
        self.best_effort_message_bytes -= best_effort_message_bytes;
        self.guaranteed_responses_size_bytes -= guaranteed_responses_size_bytes;
        self.oversized_guaranteed_requests_extra_bytes -= oversized_guaranteed_requests_extra_bytes;
        self.inbound_size_bytes -= inbound_size_bytes;
        self.inbound_message_count -= inbound_message_count;
        self.inbound_response_count -= inbound_response_count;
        self.inbound_guaranteed_request_count -= inbound_guaranteed_request_count;
        self.inbound_guaranteed_response_count -= inbound_guaranteed_response_count;
        self.outbound_message_count -= outbound_message_count;
        self.cycles -= cycles;
    }
}
