//! Types used by the Xnet component.
use crate::ProxyDecodeError;
use crate::{consensus::certification::Certification, messages::RequestOrResponse};
#[cfg(test)]
use ic_exhaustive_derive::ExhaustiveSet;
use ic_protobuf::state::queues::v1 as pb_queues;
use phantom_newtype::AmountOf;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use strum_macros::EnumIter;

pub mod proto;

pub struct StreamIndexTag;
/// Index into a subnet-to-subnet message stream; used in the context of a
/// `Stream` to define message order.
pub type StreamIndex = AmountOf<StreamIndexTag, u64>;

/// A gap-free `StreamIndex`-ed queue for the messages and signals of a stream.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct StreamIndexedQueue<T> {
    begin: StreamIndex,
    queue: VecDeque<T>,
}

impl<T: Clone> StreamIndexedQueue<T> {
    /// Extracts a slice of the given queue beginning at `slice_begin` and
    /// containing at most `max` items.
    pub fn slice(&self, slice_begin: StreamIndex, max: Option<usize>) -> StreamIndexedQueue<T> {
        assert!(
            slice_begin >= self.begin(),
            "Requested `slice_begin` ({}) before `self.begin()` ({})",
            slice_begin,
            self.begin()
        );
        assert!(
            slice_begin <= self.end(),
            "Requested `slice_begin` ({}) after `self.end()` ({})",
            slice_begin,
            self.end()
        );

        let skip = (slice_begin - self.begin()).get() as usize;
        let max = max.unwrap_or_else(|| self.len());
        StreamIndexedQueue {
            begin: slice_begin,
            queue: self
                .queue
                .iter()
                .skip(skip)
                .take(max)
                .cloned()
                .collect::<VecDeque<_>>(),
        }
    }
}

impl<T> StreamIndexedQueue<T> {
    /// Constructs a `StreamIndexedQueue` beginning at the given index.
    pub fn with_begin(begin: StreamIndex) -> Self {
        StreamIndexedQueue {
            begin,
            queue: VecDeque::new(),
        }
    }

    /// Returns the index of the first item in the queue.
    pub fn begin(&self) -> StreamIndex {
        self.begin
    }

    /// Returns the index that will be assigned to the next item to be enqueued.
    pub fn end(&self) -> StreamIndex {
        self.begin + StreamIndex::from(self.queue.len() as u64)
    }

    /// Enqueues an item into the queue, assigning it the next available index.
    pub fn push(&mut self, item: T) {
        self.queue.push_back(item);
    }

    /// Pops the next item with its index, if one is available.
    pub fn pop(&mut self) -> Option<(StreamIndex, T)>
    where
        T: Clone,
    {
        self.queue.pop_front().map(|msg| {
            let index = self.begin;
            self.begin.inc_assign();
            (index, msg)
        })
    }

    /// Retrieves the item with the given index.
    pub fn get(&self, index: StreamIndex) -> Option<&T> {
        if index >= self.begin {
            self.queue.get((index - self.begin).get() as usize)
        } else {
            None
        }
    }

    /// Discards all items before the given index.
    ///
    /// Panics if the index is not in the `[begin(), end())` range.
    pub fn discard_before(&mut self, new_begin: StreamIndex) {
        assert!(
            new_begin >= self.begin,
            "Begin index ({}) has already advanced past requested begin index ({})",
            self.begin,
            new_begin
        );
        assert!(
            new_begin <= self.end(),
            "Cannot advance begin index ({}) beyond end index ({})",
            new_begin,
            self.end()
        );

        while self.begin < new_begin {
            self.queue.pop_front().unwrap();
            self.begin.inc_assign();
        }
    }

    /// Returns the size of the queue.
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Returns `true` if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Returns an iterator over the items in the queue, with their indices.
    pub fn iter(&self) -> impl std::iter::Iterator<Item = (StreamIndex, &T)> {
        (self.begin.get()..)
            .zip(self.queue.iter())
            .map(|(index, item)| (StreamIndex::from(index), item))
    }
}

impl<T> Default for StreamIndexedQueue<T> {
    fn default() -> Self {
        StreamIndexedQueue {
            begin: StreamIndex::from(0),
            queue: VecDeque::new(),
        }
    }
}

/// StreamHeader contains a digest of information about the communication
/// session between subnets: indices of messages that can be pulled and signals
/// for received incoming messages.
///
/// The idea behind this digest is that a subnet can obtain just the header and
/// decide how many messages it wants to pull.
///
/// Conceptually we use a gap-free queue containing one signal for each
/// inducted message; but because most signals are `Accept`we represent that
/// queue as a combination of `signals_end` (pointing just beyond the last
/// signal) and a collection of `reject_signals`.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct StreamHeader {
    begin: StreamIndex,
    end: StreamIndex,

    /// Index of the next expected message.
    signals_end: StreamIndex,

    /// Stream indices of rejected messages by reject reason, in ascending order.
    reject_signals: VecDeque<RejectSignal>,

    /// Flags informing the other subnet e.g. what kinds of messages will be accepted.
    flags: StreamFlags,
}

/// Reasons for why inter canister messages may fail to be inducted into the state.
///
/// All reason are applicable to `Request`, whereas only `CanisterMigrating` is
/// applicable to `Response`.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, EnumIter)]
pub enum RejectReason {
    /// Message enqueuing failed due to migrating canister. In contrast to
    /// `CanisterNotFound` this is mapped to `RejectCode::SysTransient`, i.e.
    /// the canister will be available again shortly.
    ///
    /// This is the only reject reason that (also) applies to to responses.
    CanisterMigrating = 1,

    /// Message enqueuing failed due to no matching canister ID. In contrast to
    /// `CanisterMigrating` this is mapped to `RejectCode::DestinationInvalid`, i.e.
    /// the canister was not found in any capacity on the IC.
    CanisterNotFound = 2,

    /// Canister is stopped, not accepting any messages.
    CanisterStopped = 3,

    /// Canister is stopping, only accepting responses.
    CanisterStopping = 4,

    /// Message enqueuing failed due to full in/out queue.
    QueueFull = 5,

    /// Message enqueuing would have caused the canister or subnet to run over
    /// their memory limit.
    OutOfMemory = 6,

    /// Message enqueuing failed due to an unknown error. This is used to map
    /// `StateError` variants that shouldn't be possible to occur for requests.
    /// It is not expected that this reason will ever be used.
    Unknown = 7,
}

impl From<RejectReason> for pb_queues::RejectReason {
    fn from(item: RejectReason) -> Self {
        match item {
            RejectReason::CanisterMigrating => Self::CanisterMigrating,
            RejectReason::CanisterNotFound => Self::CanisterNotFound,
            RejectReason::CanisterStopped => Self::CanisterStopped,
            RejectReason::CanisterStopping => Self::CanisterStopping,
            RejectReason::QueueFull => Self::QueueFull,
            RejectReason::OutOfMemory => Self::OutOfMemory,
            RejectReason::Unknown => Self::Unknown,
        }
    }
}

impl TryFrom<pb_queues::RejectReason> for RejectReason {
    type Error = ProxyDecodeError;

    fn try_from(item: pb_queues::RejectReason) -> Result<Self, Self::Error> {
        match item {
            pb_queues::RejectReason::Unspecified => Err(ProxyDecodeError::Other(
                "bad reject reason {} received".into(),
            )),
            pb_queues::RejectReason::CanisterMigrating => Ok(Self::CanisterMigrating),
            pb_queues::RejectReason::CanisterNotFound => Ok(Self::CanisterNotFound),
            pb_queues::RejectReason::CanisterStopped => Ok(Self::CanisterStopped),
            pb_queues::RejectReason::CanisterStopping => Ok(Self::CanisterStopping),
            pb_queues::RejectReason::QueueFull => Ok(Self::QueueFull),
            pb_queues::RejectReason::OutOfMemory => Ok(Self::OutOfMemory),
            pb_queues::RejectReason::Unknown => Ok(Self::Unknown),
        }
    }
}

/// Reject signal for messages who failed to induct.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct RejectSignal {
    pub reason: RejectReason,
    pub index: StreamIndex,
}

impl RejectSignal {
    pub fn new(reason: RejectReason, index: StreamIndex) -> Self {
        Self { reason, index }
    }
}

/// Flags for `Stream`.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Default)]
pub struct StreamFlags {
    /// Indicates that the subnet expects responses only in the reverse stream.
    pub deprecated_responses_only: bool,
}

impl StreamHeader {
    pub fn new(
        begin: StreamIndex,
        end: StreamIndex,
        signals_end: StreamIndex,
        reject_signals: VecDeque<RejectSignal>,
        flags: StreamFlags,
    ) -> Self {
        Self {
            begin,
            end,
            signals_end,
            reject_signals,
            flags,
        }
    }

    pub fn begin(&self) -> StreamIndex {
        self.begin
    }

    pub fn end(&self) -> StreamIndex {
        self.end
    }

    pub fn signals_end(&self) -> StreamIndex {
        self.signals_end
    }

    pub fn reject_signals(&self) -> &VecDeque<RejectSignal> {
        &self.reject_signals
    }

    pub fn flags(&self) -> &StreamFlags {
        &self.flags
    }
}

/// A continuous slice of messages pulled from a remote subnet.  The slice also
/// includes the header with the communication session metadata.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct StreamSlice {
    header: StreamHeader,
    // Messages coming from a remote subnet, together with their indices.
    //
    // In case of messages, the indices are only known if there is at least one
    // message in the queue.  So an empty set of messages is represented as
    // None, not as a an empty queue with a fixed begin index.
    //
    // Invariant: `messages = None ∨ messages = Some(q) ∧ !q.is_empty()`
    messages: Option<StreamIndexedQueue<RequestOrResponse>>,
}

impl StreamSlice {
    pub fn new(header: StreamHeader, messages: StreamIndexedQueue<RequestOrResponse>) -> Self {
        let messages = if messages.is_empty() {
            None
        } else {
            Some(messages)
        };
        Self { header, messages }
    }

    pub fn from_parts(
        header: StreamHeader,
        messages: Option<StreamIndexedQueue<RequestOrResponse>>,
    ) -> Self {
        match messages {
            None => Self { header, messages },
            Some(q) => Self::new(header, q),
        }
    }

    pub fn header(&self) -> &StreamHeader {
        &self.header
    }

    pub fn messages(&self) -> Option<&StreamIndexedQueue<RequestOrResponse>> {
        self.messages.as_ref()
    }

    pub fn pop_message(&mut self) -> Option<(StreamIndex, RequestOrResponse)> {
        match self.messages {
            Some(ref mut q) => {
                let result = q.pop();
                if q.is_empty() {
                    self.messages = None
                }
                result
            }
            None => None,
        }
    }
}

/// A slice of the stream of messages produced by the other subnet together with
/// a cryptographic proof that the majority of the subnet agrees on it.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct CertifiedStreamSlice {
    /// Serialized part of the state tree containing the stream data.
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,

    /// The witness that can be used to recompute the root hash from the
    /// payload.
    #[serde(with = "serde_bytes")]
    pub merkle_proof: Vec<u8>,

    /// The certification of the root hash.
    pub certification: Certification,
}

pub mod testing {
    use super::{StreamFlags, StreamHeader, StreamIndex, StreamIndexedQueue};
    use crate::messages::RequestOrResponse;

    /// Provides test-only methods for `StreamHeader`.
    pub trait StreamHeaderTesting {
        fn set_begin(&mut self, begin: StreamIndex);
        fn set_end(&mut self, end: StreamIndex);
        fn set_flags(&mut self, flags: StreamFlags);
    }

    impl StreamHeaderTesting for super::StreamHeader {
        fn set_begin(&mut self, begin: StreamIndex) {
            self.begin = begin;
        }

        fn set_end(&mut self, end: StreamIndex) {
            self.end = end;
        }

        fn set_flags(&mut self, flags: StreamFlags) {
            self.flags = flags;
        }
    }

    /// Provides test-only methods for `StreamSlice`.
    pub trait StreamSliceTesting {
        /// Pushes a message onto the slice.
        fn push_message(&mut self, message: RequestOrResponse);

        fn header_mut(&mut self) -> &mut StreamHeader;
    }

    impl StreamSliceTesting for super::StreamSlice {
        fn push_message(&mut self, message: RequestOrResponse) {
            match self.messages {
                Some(ref mut q) => {
                    q.push(message);
                }
                None => {
                    let mut q = StreamIndexedQueue::with_begin(self.header.begin);
                    q.push(message);
                    self.messages = Some(q);
                }
            }
            let messages_end = self.messages.as_ref().unwrap().end();
            if self.header.end < messages_end {
                self.header.end = messages_end;
            }
        }

        fn header_mut(&mut self) -> &mut StreamHeader {
            &mut self.header
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const EIGHT: StreamIndex = StreamIndex::new(8);
    const NINE: StreamIndex = StreamIndex::new(9);
    const TEN: StreamIndex = StreamIndex::new(10);

    #[test]
    fn stream_indexed_queue_default() {
        const ZERO: StreamIndex = StreamIndex::new(0);
        const ONE: StreamIndex = StreamIndex::new(1);
        const TWO: StreamIndex = StreamIndex::new(2);

        let mut q = StreamIndexedQueue::<u64>::default();

        // Test initial state.
        assert!(q.is_empty());
        assert_eq!(0, q.len());
        assert_eq!(ZERO, q.begin());
        assert_eq!(ZERO, q.end());
        assert_eq!(None, q.get(ZERO));

        // Push a couple of items.
        q.push(13);
        q.push(14);

        // Test intermediate state.
        assert!(!q.is_empty());
        assert_eq!(2, q.len());
        assert_eq!(ZERO, q.begin());
        assert_eq!(TWO, q.end());
        assert_eq!(Some(&13), q.get(ZERO));
        assert_eq!(Some(&14), q.get(ONE));
        assert_eq!(None, q.get(TWO));

        // Pop the items.
        assert_eq!(Some((ZERO, 13)), q.pop());
        assert_eq!(Some((ONE, 14)), q.pop());
        assert_eq!(None, q.pop());

        // Test final state.
        assert!(q.is_empty());
        assert_eq!(0, q.len());
        assert_eq!(TWO, q.begin());
        assert_eq!(TWO, q.end());
        assert_eq!(None, q.get(ZERO));
    }

    #[test]
    fn stream_indexed_queue_with_begin() {
        let mut q = StreamIndexedQueue::<u64>::with_begin(EIGHT);

        // Test initial state.
        assert!(q.is_empty());
        assert_eq!(0, q.len());
        assert_eq!(EIGHT, q.begin());
        assert_eq!(EIGHT, q.end());
        assert_eq!(None, q.get(EIGHT));

        // Push a couple of items.
        q.push(13);
        q.push(14);

        // Test intermediate state.
        assert!(!q.is_empty());
        assert_eq!(2, q.len());
        assert_eq!(EIGHT, q.begin());
        assert_eq!(TEN, q.end());
        assert_eq!(Some(&13), q.get(EIGHT));
        assert_eq!(Some(&14), q.get(NINE));
        assert_eq!(None, q.get(TEN));

        // Pop the items.
        assert_eq!(Some((EIGHT, 13)), q.pop());
        assert_eq!(Some((NINE, 14)), q.pop());
        assert_eq!(None, q.pop());

        // Test final state.
        assert!(q.is_empty());
        assert_eq!(0, q.len());
        assert_eq!(TEN, q.begin());
        assert_eq!(TEN, q.end());
        assert_eq!(None, q.get(EIGHT));
    }

    #[test]
    fn stream_indexed_queue_discard_before() {
        let mut q = StreamIndexedQueue::<u64>::with_begin(EIGHT);

        // Push a couple of items.
        q.push(13);
        q.push(14);

        // Remove before `begin()` is a no-op.
        q.discard_before(EIGHT);
        assert_eq!(EIGHT, q.begin());
        assert_eq!(2, q.len());

        // Remove before an index within the stream.
        q.discard_before(NINE);
        assert_eq!(NINE, q.begin());
        assert_eq!(1, q.len());

        // Remove before `end()` clears the stream.
        q.discard_before(TEN);
        assert_eq!(TEN, q.begin());
        assert_eq!(0, q.len());
    }

    #[test]
    #[should_panic(
        expected = "Begin index (9) has already advanced past requested begin index (8)"
    )]
    fn stream_indexed_queue_discard_before_before_begin() {
        // StreamIndexedQueue with an item.
        let mut q = StreamIndexedQueue::<u64>::with_begin(NINE);
        q.push(13);

        // Before q.begin().
        q.discard_before(EIGHT);
    }

    #[test]
    #[should_panic(expected = "Cannot advance begin index (10) beyond end index (9)")]
    fn stream_indexed_queue_discard_before_after_end() {
        // StreamIndexedQueue with an item.
        let mut q = StreamIndexedQueue::<u64>::with_begin(EIGHT);
        q.push(13);

        // After q.end().
        q.discard_before(TEN);
    }

    #[test]
    fn stream_indexed_queue_iter() {
        let mut q = StreamIndexedQueue::<u64>::with_begin(EIGHT);

        // Push a couple of items.
        q.push(13);
        q.push(14);

        // Non-mutable iterator yields references to all items.
        let mut iter = q.iter();
        assert_eq!(Some((EIGHT, &13)), iter.next());
        assert_eq!(Some((NINE, &14)), iter.next());
        assert_eq!(None, iter.next());

        // Stream is unmodified.
        assert_eq!(EIGHT, q.begin());
        assert_eq!(2, q.len());
    }

    #[test]
    fn stream_indexed_queue_slice() {
        let mut q = StreamIndexedQueue::<u64>::with_begin(EIGHT);

        // Push a couple of items.
        q.push(13);
        q.push(14);

        // max > q.len()
        assert_eq!(
            StreamIndexedQueue {
                begin: EIGHT,
                queue: vec![13, 14].into()
            },
            q.slice(EIGHT, Some(10))
        );
        // max == None
        assert_eq!(
            StreamIndexedQueue {
                begin: NINE,
                queue: vec![14].into()
            },
            q.slice(NINE, None)
        );
        // slice_begin + max < q.len()
        assert_eq!(
            StreamIndexedQueue {
                begin: EIGHT,
                queue: vec![13].into()
            },
            q.slice(EIGHT, Some(1))
        );
        // slice_begin == q.end()
        assert_eq!(
            StreamIndexedQueue {
                begin: TEN,
                queue: vec![].into()
            },
            q.slice(TEN, None)
        );
    }

    #[test]
    #[should_panic(expected = "Requested `slice_begin` (8) before `self.begin()` (9)")]
    fn stream_indexed_queue_slice_slice_begin_before_queue_begin() {
        // StreamIndexedQueue with an item.
        let mut q = StreamIndexedQueue::<u64>::with_begin(NINE);
        q.push(13);

        q.slice(EIGHT, None);
    }

    #[test]
    #[should_panic(expected = "Requested `slice_begin` (10) after `self.end()` (9)")]
    fn stream_indexed_queue_slice_slice_begin_after_queue_end() {
        // StreamIndexedQueue with an item.
        let mut q = StreamIndexedQueue::<u64>::with_begin(EIGHT);
        q.push(13);

        q.slice(TEN, None);
    }
}
