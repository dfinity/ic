//! A pool of incoming `CertifiedStreamSlices` used by `XNetPayloadBuilderImpl`
//! to build `XNetPayloads` without the need for I/O on the critical path.

use crate::xnet_payload_builder::{
    witness_count_bytes, ExpectedIndices, NO_MESSAGES_WITNESS_BYTES,
};
use header::Header;
use ic_canonical_state::LabelLike;
use ic_crypto_tree_hash::{
    first_sub_witness, flat_map::FlatMap, prune_witness, sub_witness, Label, LabeledTree,
    TreeHashError, Witness,
};
use ic_metrics::{
    buckets::{decimal_buckets, decimal_buckets_with_zero},
    MetricsRegistry,
};
use ic_protobuf::messaging::xnet::v1;
use ic_protobuf::proxy::{ProtoProxy, ProxyDecodeError};
use ic_types::{
    consensus::certification::Certification,
    xnet::{CertifiedStreamSlice, StreamIndex},
    CountBytes, SubnetId,
};
use messages::Messages;
use prometheus::{Histogram, IntCounterVec, IntGauge};
use std::collections::BTreeMap;
use std::convert::{From, TryFrom, TryInto};

const LABEL_STREAMS: &[u8] = b"streams";
const LABEL_HEADER: &[u8] = b"header";
const LABEL_MESSAGES: &[u8] = b"messages";

// Helper types, to save some typing.
type PayloadTree = LabeledTree<Vec<u8>>;
type PayloadTreeMap = FlatMap<Label, PayloadTree>;

/// `Result` type returned by `CertifiedSlicePool` operations.
pub type CertifiedSliceResult<T> = Result<T, CertifiedSliceError>;

/// Metrics for [`CertifiedSlicePool`].
#[derive(Debug)]
struct CertifiedSlicePoolMetrics {
    pool_size_bytes: IntGauge,
    take_count: IntCounterVec,
    take_messages: Histogram,
    take_gced_messages: Histogram,
    take_size_bytes: Histogram,
}

pub const METRIC_POOL_SIZE_BYTES: &str = "xnet_pool_size_bytes";
pub const METRIC_TAKE_COUNT: &str = "xnet_pool_take_count";
pub const METRIC_TAKE_MESSAGES: &str = "xnet_pool_take_messages";
pub const METRIC_TAKE_SIZE_BYTES: &str = "xnet_pool_take_size_bytes";
pub const METRIC_TAKE_GCED_MESSAGES: &str = "xnet_pool_take_gced_messages";

pub const LABEL_STATUS: &str = "status";

pub const STATUS_SUCCESS: &str = "success";
pub const STATUS_NONE: &str = "none";

impl CertifiedSlicePoolMetrics {
    fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            pool_size_bytes: metrics_registry.int_gauge(
                METRIC_POOL_SIZE_BYTES,
                "Total size of the XNet slice pool, in bytes.",
            ),
            take_count: metrics_registry.int_counter_vec(
                METRIC_TAKE_COUNT,
                "Count of XNet slice pool takes, by status.",
                &[LABEL_STATUS]
            ),
            take_messages: metrics_registry.histogram(
                METRIC_TAKE_MESSAGES,
                "The number of messages returned by successful XNet slice pool takes.",
                // 0 - 50K
                decimal_buckets_with_zero(0, 4)
            ),
            take_gced_messages: metrics_registry.histogram(
                METRIC_TAKE_GCED_MESSAGES,
                "The number of garbage collected messages while taking a slice from the XNet slice pool (due to being out of date).",
                // 0 - 50K
                decimal_buckets_with_zero(0, 4)
            ),
            take_size_bytes: metrics_registry.histogram(
                METRIC_TAKE_SIZE_BYTES,
                "The byte sizes of slices returned by successful XNet slice pool takes.",
                // 100 B - 5 MB
                decimal_buckets(2, 6)
            ),
        }
    }

    /// Observes the status of a pool take.
    fn observe_take(&self, status: &str) {
        self.take_count.with_label_values(&[status]).inc();
    }

    /// Observes the number of messages returned by a successful pool take.
    fn observe_take_message_count(&self, message_count: usize) {
        self.take_messages.observe(message_count as f64);
    }

    /// Observes the number of garbage collected messages while taking a slice
    /// from the pool.
    fn observe_take_messages_gced(&self, message_count: usize) {
        self.take_gced_messages.observe(message_count as f64);
    }

    /// Observes the byte size of a slice returned by a successful pool take.
    fn observe_take_size_bytes(&self, size_bytes: usize) {
        self.take_size_bytes.observe(size_bytes as f64);
    }
}

use InvalidAppend::*;
use InvalidSlice::*;

mod header {
    use super::{CertifiedSliceError, InvalidSlice};
    use ic_canonical_state::encoding;
    use ic_types::xnet::{StreamHeader, StreamIndex};
    use std::convert::TryFrom;

    /// Wrapper around serialized header plus transient metadata.
    #[derive(Clone, Debug, PartialEq)]
    pub(super) struct Header {
        /// Serialized stream header.
        bytes: Vec<u8>,

        /// Transient: deserialized header.
        decoded: StreamHeader,
    }

    impl Header {
        pub(super) fn begin(&self) -> StreamIndex {
            self.decoded.begin
        }

        pub(super) fn end(&self) -> StreamIndex {
            self.decoded.end
        }

        pub(super) fn signals_end(&self) -> StreamIndex {
            self.decoded.signals_end
        }
    }

    impl TryFrom<Vec<u8>> for Header {
        type Error = CertifiedSliceError;

        fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
            let decoded = encoding::decode_stream_header(&bytes)?;
            if decoded.begin > decoded.end {
                return Err(CertifiedSliceError::InvalidPayload(
                    InvalidSlice::InvalidBounds,
                ));
            }
            Ok(Header { bytes, decoded })
        }
    }

    impl From<Header> for Vec<u8> {
        fn from(header: Header) -> Self {
            header.bytes
        }
    }
}

mod messages {
    use super::*;

    /// Wrapper around slice messages plus transient metadata.
    #[derive(Debug, PartialEq)]
    pub(super) struct Messages {
        /// Slice messages.
        ///
        /// Must be non-empty. All children are leaves, keyed by stream index.
        messages: PayloadTreeMap,

        /// Transient: precomputed deterministic estimate of the overall byte
        /// size of `messages`, used for efficiently implementing
        /// `CountBytes`.
        count_bytes: usize,

        /// Transient: slice begin index.
        begin: StreamIndex,
    }

    impl Messages {
        pub(super) fn new(messages: PayloadTreeMap) -> CertifiedSliceResult<Self> {
            if messages.is_empty() {
                return Err(CertifiedSliceError::InvalidPayload(EmptyMessages));
            }

            let count_bytes = byte_size(&messages)?;
            let begin = to_stream_index(&messages.keys()[0])
                .map_err(CertifiedSliceError::InvalidPayload)?;

            Ok(Messages {
                messages,
                count_bytes,
                begin,
            })
        }

        /// Returns the number of contained messages.
        pub(super) fn len(&self) -> usize {
            self.messages.len()
        }

        /// Returns the messages' begin index.
        pub(super) fn begin(&self) -> StreamIndex {
            self.begin
        }

        /// Returns the messages' end index.
        pub(super) fn end(&self) -> StreamIndex {
            self.begin + (self.messages.len() as u64).into()
        }

        /// Appends the given messages to `self`.
        ///
        /// Returns `Err(InvalidPayload)` if `suffix.messages` is malformed.
        /// Returns `Err(InvalidAppend)` and leaves `self` unmodified if
        /// `suffix` does not extend `self` gap-free.
        pub(super) fn append(&mut self, suffix: Messages) -> CertifiedSliceResult<()> {
            // Do all validation / fallible operations first, so `self` remains unmodified
            // on error.
            if suffix.begin.get() != self.begin.get() + self.len() as u64 {
                return Err(CertifiedSliceError::InvalidAppend(IndexMismatch));
            }
            let suffix_byte_size = byte_size(&suffix.messages)?;

            // `self.begin` stays unchanged.
            self.messages = FlatMap::from_key_values(
                std::mem::take(&mut self.messages)
                    .into_iter()
                    .chain(suffix.messages.into_iter())
                    .collect(),
            );
            self.count_bytes += suffix_byte_size;
            debug_assert_eq!(byte_size(&self.messages).unwrap(), self.count_bytes);
            Ok(())
        }

        /// Takes a slice prefix up to the given label (exclusive).
        ///
        /// Returns the prefix (if non-empty) and the remaining payload (if
        /// any). At least one of the two is `Some(_)`.
        ///
        /// Returns `Err(InvalidPayload)` if `self.messages` is malformed.
        pub(super) fn take_prefix(
            mut self,
            to: &Label,
        ) -> CertifiedSliceResult<(Option<PayloadTreeMap>, Option<Self>)> {
            let postfix = self.messages.split_off(to);
            let prefix = self.messages;

            // Update the estimated size and put back the postfix if not empty.
            self.count_bytes = byte_size(&postfix)?;

            if prefix.is_empty() {
                self.messages = postfix;
                Ok((None, Some(self)))
            } else if postfix.is_empty() {
                Ok((Some(prefix), None))
            } else {
                // Both prefix and postfix are non-empty.
                Ok((Some(prefix), Some(Self::new(postfix)?)))
            }
        }

        /// Produces a witness from the provided one with `self.messages` pruned
        /// (but the header untouched).
        ///
        /// Returns `Err(InvalidPayload)` if `self.messages` is malformed;
        /// `Err(WitnessPruningFailed)` if `witness` is malformed or does not
        /// entirely cover `self.messages`.
        pub fn pruned_witness(
            &mut self,
            witness: &Witness,
            subnet_id: Label,
        ) -> CertifiedSliceResult<Witness> {
            // Temporarily swap out `self.messages` so we don't have to copy it.
            let mut messages = PayloadTreeMap::new();
            std::mem::swap(&mut messages, &mut self.messages);

            let partial_tree = Payload::pack(subnet_id, None, Some(messages));
            let pruned_witness = prune_witness(witness, &partial_tree)?;

            // Put back `self.messages`.
            self.messages = Payload::unpack(partial_tree).map(|(_, _, m)| m)?.unwrap();

            Ok(pruned_witness)
        }

        /// Returns an iterator over the contained messages.
        pub(super) fn iter(&self) -> impl DoubleEndedIterator<Item = (&Label, &PayloadTree)> {
            self.messages.iter()
        }
    }

    impl From<Messages> for PayloadTreeMap {
        fn from(messages: Messages) -> Self {
            messages.messages
        }
    }

    impl CountBytes for Messages {
        fn count_bytes(&self) -> usize {
            self.count_bytes
        }
    }

    /// Returns a byte size estimate of a set of messages, including their
    /// labels.
    ///
    /// Returns `Err(InvalidPayload)` if `messages` is malformed.
    fn byte_size(messages: &PayloadTreeMap) -> CertifiedSliceResult<usize> {
        let mut byte_size = 0;
        for message in messages.values() {
            byte_size += message_byte_size(message)?;
        }
        Ok(byte_size)
    }

    /// Returns a byte size estimate of a message plus its label.
    ///
    /// Returns `Err(InvalidPayload)` if `message` is not a leaf.
    pub(super) fn message_byte_size(message: &PayloadTree) -> CertifiedSliceResult<usize> {
        // 8 bytes overhead for `LabelTree` encoding, 8 bytes for label (u64).
        Ok(8 + Payload::value_of_ref(message)?.len() + 8)
    }
}

/// Unpacked `CertifiedStreamSlice::payload`, plus transient metadata.
#[derive(Debug, PartialEq)]
struct Payload {
    /// The intended destination subnet of this stream slice.
    subnet_id: Label,

    /// Stream header.
    header: Header,

    /// Slice messages.
    messages: Option<Messages>,
}

/// Mean empty payload byte size: `LabelTree` with `"streams"` and `"header"`
/// labels; subnet ID; and serialized header (3 variable length encoded
/// integers).
const EMPTY_PAYLOAD_BYTES: usize = 62;

/// Mean non-empty payload byte size excluding messages: `LabelTree` with
/// `"streams"` and `"header"` labels; subnet ID; serialized header (3 variable
/// length encoded integers); plus "messages" node.
const NON_EMPTY_PAYLOAD_FIXED_BYTES: usize = 84;

impl Payload {
    /// Takes a slice prefix whose estimated size meets the given limits.
    /// `byte_limit` applies to the total estimated size of both the payload and
    /// the resulting witness.
    ///
    /// Returns the prefix (if one can be created) and the remaining payload (if
    /// any). At least one of the two is `Some(_)`.
    ///
    /// Returns `Err(InvalidPayload)` if `self.messages` is malformed.
    #[allow(clippy::assertions_on_constants)]
    pub fn take_prefix(
        mut self,
        message_limit: Option<usize>,
        byte_limit: Option<usize>,
    ) -> CertifiedSliceResult<(Option<Self>, Option<Self>)> {
        let message_limit = message_limit.unwrap_or(std::usize::MAX);
        let byte_limit = byte_limit.unwrap_or(std::usize::MAX);

        debug_assert!(EMPTY_PAYLOAD_BYTES <= NON_EMPTY_PAYLOAD_FIXED_BYTES);
        if byte_limit < EMPTY_PAYLOAD_BYTES + NO_MESSAGES_WITNESS_BYTES {
            // `byte_limit` smaller than minimum payload size, bail out.
            return Ok((None, Some(self)));
        }

        let stream_begin = self.header.begin();
        let stream_end = self.header.end();
        let witness_bytes = witness_count_bytes(
            stream_begin,
            stream_end,
            self.messages.as_ref().map(|m| m.begin()),
            self.messages.as_ref().map(|m| m.end()),
        );
        if self.len() <= message_limit && self.count_bytes() + witness_bytes <= byte_limit {
            // Payload under both limits, return it.
            return Ok((Some(self), None));
        }

        // If we got here, we have at least one message.
        let messages = self
            .messages
            .as_ref()
            .expect("Non-zero byte size for empty `messages`.");

        // Find the rightmost cutoff point that respects the provided limits.
        let mut byte_size = NON_EMPTY_PAYLOAD_FIXED_BYTES;
        let mut cutoff = None;
        let slice_begin = messages.begin();
        for (i, (label, message)) in messages.iter().enumerate() {
            // Incremental message byte size.
            let message_byte_size = messages::message_byte_size(message)?;
            // Total witness byte size.
            let witness_byte_size = witness_count_bytes(
                stream_begin,
                stream_end,
                Some(slice_begin),
                Some(slice_begin + (1 + i as u64).into()),
            );
            if byte_size + message_byte_size + witness_byte_size > byte_limit || i >= message_limit
            {
                cutoff = Some(label.clone());
                break;
            }
            byte_size += message_byte_size;
        }
        let cutoff = cutoff.unwrap_or_else(|| {
            // `count_bytes()` returned a value above `byte_limit`, but
            // `byte_size` (computed the same way) is below `byte_limit`.
            panic!(
                "Invalid `messages_count_bytes`: was {}, expecting {}",
                messages.count_bytes(),
                byte_size
            )
        });

        // Take the messages prefix, expect non-empty leftover postfix.
        let prefix = self.take_messages_prefix(&cutoff)?;
        assert!(
            self.messages.is_some(),
            "`take_messages_prefix()` produced an empty postfix for existing key {}",
            cutoff
        );

        // Return (possibly empty) prefix, retain non-empty postfix.
        let prefix = self.new_partial(prefix)?;
        if prefix.len() == 0 {
            debug_assert_eq!(prefix.count_bytes(), EMPTY_PAYLOAD_BYTES);
        } else {
            debug_assert_eq!(prefix.count_bytes(), byte_size);
        }

        Ok((Some(prefix), Some(self)))
    }

    /// Garbage collects the payload by dropping all messages before `cutoff`.
    /// Returns the pruned messages as a `LabeledTree`, to be used for witness
    /// pruning.
    ///
    /// Returns `Err(InvalidPayload)` if `self.messages` is malformed.
    pub fn garbage_collect(
        &mut self,
        cutoff: StreamIndex,
    ) -> CertifiedSliceResult<Option<PayloadTree>> {
        Ok(self
            .take_messages_prefix(&cutoff.to_label())?
            .map(|pruned_messages| {
                Payload::pack(self.subnet_id.clone(), None, Some(pruned_messages))
            }))
    }

    /// Appends a payload's messages to `self`, updating the header and metadata
    /// as necessary.
    ///
    /// Returns `Err(InvalidPayload)` if `self.messages` is malformed. Returns
    /// `Err(InvalidAppend)` and leaves `self` unmodified if `other` has
    /// a different `subnet_id`; its messages do not extend `self`'s gap-free;
    /// or its `signals_end` regresses.
    pub fn append(&mut self, other: Payload) -> CertifiedSliceResult<()> {
        if other.subnet_id != self.subnet_id {
            return Err(CertifiedSliceError::InvalidAppend(DifferentSubnet));
        }
        if other.header.signals_end() < self.header.signals_end() {
            // Not an actual error, just a race condition. We could choose to go ahead with
            // the merge and trade a larger slice for the possibility that the slice may be
            // invalid if the higher `signals_end` was already included into a block.
            return Err(CertifiedSliceError::InvalidAppend(SignalsEndRegresses));
        }

        match (self.messages.as_ref(), other.messages) {
            (Some(messages), Some(suffix)) => {
                // Do all validation / fallible operations first, so `self` remains unmodified
                // on error.
                if other.header.begin() > messages.begin() || other.header.end() < suffix.end() {
                    return Err(CertifiedSliceError::InvalidAppend(IndexMismatch));
                }
                self.messages
                    .as_mut()
                    .map(|m| m.append(suffix))
                    .transpose()?;
                self.header = other.header;
            }

            (messages, None) => {
                if let Some(messages) = messages {
                    if other.header.begin() > messages.begin()
                        || other.header.end() < messages.end()
                    {
                        return Err(CertifiedSliceError::InvalidAppend(IndexMismatch));
                    }
                }
                // `other` has no messages: take its `header`, keep the rest.
                self.header = other.header;
            }

            (None, messages) => {
                // `self` has no messages: wholesale replace with `other`.
                self.header = other.header;
                self.messages = messages;
            }
        };
        Ok(())
    }

    /// Produces a witness from the provided one with `self.messages` pruned
    /// (but the header untouched).
    ///
    /// Returns `Err(InvalidPayload)` if `self.messages` is malformed;
    /// `Err(WitnessPruningFailed)` if `witness` is malformed or does not
    /// entirely cover `self.messages`.
    pub fn pruned_witness(&mut self, witness: &Witness) -> CertifiedSliceResult<Witness> {
        match self.messages.as_mut() {
            Some(messages) => messages.pruned_witness(witness, self.subnet_id.clone()),

            None => Ok(witness.clone()),
        }
    }

    /// Returns the number of messages in this payload.
    pub fn len(&self) -> usize {
        self.messages.as_ref().map(|msgs| msgs.len()).unwrap_or(0)
    }

    /// Takes the prefix of `messages` up to the given index. Returns a
    /// non-empty message map; or `None` if `to` is before the first message in
    /// the slice; never an empty map.
    ///
    /// Returns `Err(InvalidPayload)` if `self.messages` is malformed.
    fn take_messages_prefix(&mut self, to: &Label) -> CertifiedSliceResult<Option<PayloadTreeMap>> {
        match self.messages.take() {
            Some(messages) => {
                let (prefix, messages) = messages.take_prefix(to)?;
                self.messages = messages;
                Ok(prefix)
            }
            None => Ok(None),
        }
    }

    /// Unpacks a `LabeledTree`-representation of a slice into subnet ID label,
    /// serialized header and messages.
    ///
    /// Returns `Err(InvalidPayload)` if the payload is obviously invalid (e.g.
    /// no `/streams`; or empty `messages` subtree) but does not do full
    /// validation.
    ///
    /// Reverse of `pack()`.
    fn unpack(
        payload: PayloadTree,
    ) -> CertifiedSliceResult<(Label, Option<Vec<u8>>, Option<PayloadTreeMap>)> {
        let streams_tree = Self::children_of(payload)?
            .remove(&Label::from(LABEL_STREAMS))
            .ok_or(CertifiedSliceError::InvalidPayload(MissingStreams))?;
        let mut streams = Self::children_of(streams_tree)?.into_iter();

        let (subnet_id, stream_tree) = streams
            .next()
            .ok_or(CertifiedSliceError::InvalidPayload(MissingStream))?;
        if streams.next().is_some() {
            return Err(CertifiedSliceError::InvalidPayload(MoreThanOneStream));
        }
        let mut stream = Self::children_of(stream_tree)?;

        let header = stream
            .remove(&Label::from(LABEL_HEADER))
            .map(Self::value_of)
            .transpose()?;
        let messages = stream
            .remove(&Label::from(LABEL_MESSAGES))
            .map(Self::children_of)
            .transpose()?;
        if let Some(messages) = messages.as_ref() {
            if messages.is_empty() {
                return Err(CertifiedSliceError::InvalidPayload(EmptyMessages));
            }
        }

        Ok((subnet_id, header, messages))
    }

    /// Packs a `subnet_id` label, optional serialized `header` (`None` iff
    /// pruning the witness) and messages into a `LabeledTree` representation of
    /// a slice.
    ///
    /// Reverse of `unpack()`.
    fn pack(
        subnet_id: Label,
        header: Option<Vec<u8>>,
        messages: Option<PayloadTreeMap>,
    ) -> PayloadTree {
        assert!(
            header.is_some() || messages.is_some(),
            "At least one of header or messages must be provided"
        );

        let mut stream = Vec::with_capacity(2);
        if let Some(header) = header {
            stream.push((Label::from(LABEL_HEADER), LabeledTree::Leaf(header)));
        }
        if let Some(messages) = messages {
            if !messages.is_empty() {
                stream.push((Label::from(LABEL_MESSAGES), LabeledTree::SubTree(messages)));
            }
        }
        let stream = FlatMap::from_key_values(stream);
        let streams = FlatMap::from_key_values(vec![(subnet_id, LabeledTree::SubTree(stream))]);
        let payload = FlatMap::from_key_values(vec![(
            Label::from(LABEL_STREAMS),
            LabeledTree::SubTree(streams),
        )]);

        LabeledTree::SubTree(payload)
    }

    /// Creates a `Payload` that contains a subset of this `Payload`'s messages.
    fn new_partial(&self, messages: Option<PayloadTreeMap>) -> CertifiedSliceResult<Self> {
        Ok(Self {
            subnet_id: self.subnet_id.clone(),
            header: self.header.clone(),
            messages: messages.map(Messages::new).transpose()?,
        })
    }

    /// Returns the `StreamIndex` of the first message, if any;
    /// `Err(InvalidPayload)` if `self.messages` is malformed.
    fn messages_begin(&self) -> Option<StreamIndex> {
        self.messages.as_ref().map(|m| m.begin())
    }

    /// Returns the `FlatMap` contained in a `SubTree`; `Err(InvalidPayload)` if
    /// `tree` is a `Leaf`.
    fn children_of(tree: PayloadTree) -> CertifiedSliceResult<PayloadTreeMap> {
        match tree {
            LabeledTree::SubTree(children) => Ok(children),
            LabeledTree::Leaf(_) => Err(CertifiedSliceError::InvalidPayload(NotASubTree)),
        }
    }

    /// Returns the value contained in a `Leaf`; `Err(InvalidPayload)` if `leaf`
    /// is a `SubTree`.
    fn value_of(leaf: PayloadTree) -> CertifiedSliceResult<Vec<u8>> {
        match leaf {
            LabeledTree::SubTree(_) => Err(CertifiedSliceError::InvalidPayload(NotALeaf)),
            LabeledTree::Leaf(value) => Ok(value),
        }
    }

    /// Returns a reference to the value contained in a `Leaf`;
    /// `Err(InvalidPayload)` if `leaf` is a `SubTree`.
    fn value_of_ref(leaf: &PayloadTree) -> CertifiedSliceResult<&[u8]> {
        match leaf {
            LabeledTree::SubTree(_) => Err(CertifiedSliceError::InvalidPayload(NotALeaf)),
            LabeledTree::Leaf(value) => Ok(value),
        }
    }
}

impl CountBytes for Payload {
    fn count_bytes(&self) -> usize {
        match self.messages.as_ref() {
            Some(messages) => NON_EMPTY_PAYLOAD_FIXED_BYTES + messages.count_bytes(),
            None => EMPTY_PAYLOAD_BYTES,
        }
    }
}

impl TryFrom<&[u8]> for Payload {
    type Error = CertifiedSliceError;

    fn try_from(payload_bytes: &[u8]) -> Result<Self, Self::Error> {
        let tree: PayloadTree = v1::LabeledTree::proxy_decode(payload_bytes)?;
        let (subnet_id, header, messages) = Self::unpack(tree)?;

        let header = header.ok_or(CertifiedSliceError::InvalidPayload(MissingHeader))?;
        let header = Header::try_from(header)?;

        let messages = messages.map(Messages::new).transpose()?;
        if let Some(messages) = messages.as_ref() {
            if header.begin() > messages.begin() || messages.end() > header.end() {
                return Err(CertifiedSliceError::InvalidPayload(InvalidBounds));
            }
        }

        Ok(Self {
            subnet_id,
            header,
            messages,
        })
    }
}

impl From<Payload> for Vec<u8> {
    fn from(payload: Payload) -> Self {
        v1::LabeledTree::proxy_encode(Payload::pack(
            payload.subnet_id,
            Some(payload.header.into()),
            payload.messages.map(|m| m.into()),
        ))
        .expect("failed to serialize a labeled tree")
    }
}

/// An unpacked `CertifiedStreamSlice`: a slice of the stream of messages
/// produced by a subnet together with a cryptographic proof that the majority
/// of that subnet agrees on it.
#[derive(Debug, PartialEq)]
pub struct UnpackedStreamSlice {
    /// Stream slice contents.
    payload: Payload,

    /// Witness that can be used to recompute the root hash from the payload.
    merkle_proof: Witness,

    /// The certification of the root hash.
    certification: Certification,
}

impl UnpackedStreamSlice {
    /// Takes a prefix of the slice that meets the given limits. Returns the
    /// prefix (if one can be created) and the remaining slice (if any).
    ///
    /// Returns `Err(InvalidPayload)` or `Err(WitnessPruningFailed)` if
    /// `self.payload` is malformed.
    pub fn take_prefix(
        mut self,
        msg_limit: Option<usize>,
        mut byte_limit: Option<usize>,
    ) -> CertifiedSliceResult<(Option<Self>, Option<Self>)> {
        // Adjust the byte limit by subtracting the certification size.
        if let Some(byte_limit_) = byte_limit {
            let certification_count_bytes = self.certification.count_bytes();
            if certification_count_bytes > byte_limit_ {
                return Ok((None, Some(self)));
            }
            byte_limit = Some(byte_limit_ - certification_count_bytes);
        }

        match self.payload.take_prefix(msg_limit, byte_limit)? {
            (None, None) => unreachable!("slice with no messages or signals"),

            // Nothing taken, put back the payload.
            (None, Some(payload)) => {
                self.payload = payload;
                Ok((None, Some(self)))
            }

            // All messages taken.
            (Some(payload), None) => {
                self.payload = payload;
                Ok((Some(self), None))
            }

            // Messages actually split or empty (header-only) prefix.
            (Some(mut prefix_payload), Some(mut postfix_payload)) => {
                let certification = self.certification.clone();
                let prefix_witness = postfix_payload.pruned_witness(&self.merkle_proof)?;

                self.payload = postfix_payload;
                if prefix_payload.messages.is_some() {
                    // Messages actually split, prune postfix witness.
                    self.merkle_proof = prefix_payload.pruned_witness(&self.merkle_proof)?;
                }

                let prefix = UnpackedStreamSlice {
                    payload: prefix_payload,
                    merkle_proof: prefix_witness,
                    certification,
                };

                Ok((Some(prefix), Some(self)))
            }
        }
    }

    /// Garbage collects the slice: drops all messages before
    /// `cutoff.message_index` and updates the witness. If all messages were
    /// dropped and `cutoff.signal_index` is beyond `signals_end`, the slice is
    /// dropped altogether.
    ///
    /// Returns `Err(InvalidPayload)` or `Err(WitnessPruningFailed)` if
    /// `self.payload` is malformed.
    pub fn garbage_collect(
        mut self,
        cutoff: &ExpectedIndices,
    ) -> CertifiedSliceResult<Option<Self>> {
        let pruned_tree = self.payload.garbage_collect(cutoff.message_index)?;
        if cutoff.signal_index >= self.payload.header.signals_end()
            && self.payload.messages.is_none()
        {
            // All signals and messages were garbage collected.
            return Ok(None);
        }

        if let Some(pruned_tree) = pruned_tree {
            self.merkle_proof = prune_witness(&self.merkle_proof, &pruned_tree)?;
        }
        Ok(Some(self))
    }

    /// Appends a partial slice with a matching witness to `self`.
    ///
    /// A partial slice is a slice with messages covering only a (possibly
    /// zero-length) suffix of the range covered by its witness.
    ///
    /// Returns `Err(InvalidPayload)` if `self.payload` is malformed. Returns
    /// `Err(InvalidWitness)` if `self.merkle_proof` is malformed. Returns
    /// `Err(InvalidAppend)` if `partial`'s witness doesn't precisely cover the
    /// concatenation of `self`s and `partial`s messages; if `partial` has a
    /// different `subnet_id`; its messages do not extend `self`'s gap-free; or
    /// its `signals_end` regresses.
    pub fn append(&mut self, partial: UnpackedStreamSlice) -> CertifiedSliceResult<()> {
        let messages_begin = self.payload.messages_begin();
        if messages_begin.is_some() {
            if messages_begin != partial.witness_messages_begin()? {
                return Err(CertifiedSliceError::InvalidAppend(IndexMismatch));
            }
        } else if !partial.is_complete()? {
            return Err(CertifiedSliceError::InvalidAppend(IndexMismatch));
        }

        self.payload.append(partial.payload)?;
        self.merkle_proof = partial.merkle_proof;
        self.certification = partial.certification;

        Ok(())
    }

    /// Tests whether this is a complete (`true`) or partial (`false`) slice.
    ///
    /// Returns `Err(InvalidWitness)` if `self.merkle_proof` is malformed.
    fn is_complete(&self) -> CertifiedSliceResult<bool> {
        Ok(self.payload.messages_begin() == self.witness_messages_begin()?)
    }

    /// Returns the index of the first `Known` message in `self.merkle_proof`.
    ///
    /// Returns `Err(InvalidWitness)` if `self.merkle_proof` is malformed.
    fn witness_messages_begin(&self) -> CertifiedSliceResult<Option<StreamIndex>> {
        let streams = sub_witness(&self.merkle_proof, &Label::from(LABEL_STREAMS))
            .ok_or(CertifiedSliceError::InvalidWitness(MissingStreams))?;
        let (_subnet_id, stream) =
            first_sub_witness(streams).ok_or(CertifiedSliceError::InvalidWitness(MissingStream))?;
        sub_witness(stream, &Label::from(LABEL_MESSAGES))
            .map(first_sub_witness)
            .flatten()
            .map(|first_message| {
                to_stream_index(first_message.0).map_err(CertifiedSliceError::InvalidWitness)
            })
            .transpose()
    }

    /// Packs a `Payload`, `Witness` and `Certification` into a
    /// `CertifiedStreamSlice`.
    fn pack(self) -> CertifiedStreamSlice {
        CertifiedStreamSlice {
            payload: self.payload.into(),
            merkle_proof: v1::Witness::proxy_encode(self.merkle_proof)
                .expect("failed to serialize a witness"),
            certification: self.certification,
        }
    }
}

impl CountBytes for UnpackedStreamSlice {
    fn count_bytes(&self) -> usize {
        let stream_begin = self.payload.header.begin();
        let stream_end = self.payload.header.end();
        let slice_begin = self.payload.messages_begin();
        let slice_end =
            slice_begin.map(|begin| begin + StreamIndex::new(self.payload.len() as u64));
        self.payload.count_bytes()
            + crate::xnet_payload_builder::witness_count_bytes(
                stream_begin,
                stream_end,
                slice_begin,
                slice_end,
            )
            + self.certification.count_bytes()
    }
}

impl TryFrom<CertifiedStreamSlice> for UnpackedStreamSlice {
    type Error = CertifiedSliceError;

    fn try_from(packed: CertifiedStreamSlice) -> Result<Self, Self::Error> {
        Ok(Self {
            payload: Payload::try_from(packed.payload.as_slice())?,
            merkle_proof: v1::Witness::proxy_decode(&packed.merkle_proof)?,
            certification: packed.certification,
        })
    }
}

impl From<UnpackedStreamSlice> for CertifiedStreamSlice {
    fn from(unpacked: UnpackedStreamSlice) -> Self {
        unpacked.pack()
    }
}

/// Error type returned when a pool operation failed due to an invalid slice.
#[derive(Debug)]
pub enum CertifiedSliceError {
    /// Payload is malformed, slice was dropped from pool (or will be, on the
    /// first mutation).
    InvalidPayload(InvalidSlice),

    /// Witness is malformed, slice was dropped from pool (or will be, on the
    /// first mutation).
    InvalidWitness(InvalidSlice),

    /// Witness-payload mismatch, slice was dropped from pool.
    WitnessPruningFailed(TreeHashError),

    /// Slice could not be deserialized.
    DecodeFailed(ProxyDecodeError),

    /// Provided slice could not be appended to pooled slice. Provided slice was
    /// discarded.
    InvalidAppend(InvalidAppend),

    /// Attempted to take already garbage-collected messages, slice was dropped
    /// from pool.
    TakeBeforeSliceBegin,
}

/// `CertifiedSliceError::InvalidPayload` and
/// `CertifiedSliceError::InvalidWitness` detail.
#[derive(Debug, PartialEq, Eq)]
pub enum InvalidSlice {
    EmptyMessages,
    MissingStreams,
    MissingStream,
    MoreThanOneStream,
    MissingHeader,
    NotAStreamIndex,
    NotASubTree,
    NotALeaf,
    InvalidBounds,
}

/// Root cause of `append()` failure.
#[derive(Debug, PartialEq, Eq)]
pub enum InvalidAppend {
    DifferentSubnet,
    SignalsEndRegresses,
    IndexMismatch,
}

impl CertifiedSliceError {
    /// Maps the error to a string slice suitable for use as metric label.
    pub fn to_label_value(&self) -> &'static str {
        match self {
            Self::InvalidPayload(_) => "InvalidPayload",
            Self::InvalidWitness(_) => "InvalidWitness",
            Self::WitnessPruningFailed(_) => "WitnessPruningFailed",
            Self::DecodeFailed(_) => "DecodeFailed",
            Self::InvalidAppend(_) => "InvalidAppend",
            Self::TakeBeforeSliceBegin => "TakeBeforeSliceBegin",
        }
    }
}

impl std::fmt::Display for CertifiedSliceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for CertifiedSliceError {}

impl From<TreeHashError> for CertifiedSliceError {
    fn from(err: TreeHashError) -> Self {
        Self::WitnessPruningFailed(err)
    }
}

impl From<ProxyDecodeError> for CertifiedSliceError {
    fn from(err: ProxyDecodeError) -> Self {
        Self::DecodeFailed(err)
    }
}

/// Converts a `LabeledTree` or `Witness` label into a `StreamIndex`.
fn to_stream_index(label: &Label) -> Result<StreamIndex, InvalidSlice> {
    StreamIndex::from_label(label.as_bytes()).ok_or(NotAStreamIndex)
}

/// A pool of `CertifiedStreamSlices` that provides support for taking out
/// valid certified sub-slices of arbitrary size starting from arbitrary stream
/// indices; and maintains cached stream positions, so an asynchronous process
/// may populate the pool in the background with appropriate slices.
///
/// It does not verify the validity of the slices it stores or returns, but
/// operations will return `CertifiedSliceError` if the slices are obviously
/// invalid (e.g. if payload structure is invalid or witness pruning fails).
#[derive(Debug)]
pub struct CertifiedSlicePool {
    /// The actual slice pool contents.
    slices: BTreeMap<SubnetId, UnpackedStreamSlice>,

    /// Cached stream positions (message and signal indices), to be used for
    /// asynchronously populating the pool. They may not match the begin indices
    /// of the pooled slice.
    ///
    /// Replaced with the positions provided to `garbage_collect()`; and
    /// advanced to the end of the slice returned by a `take_slice()` call.
    stream_positions: BTreeMap<SubnetId, ExpectedIndices>,

    metrics: CertifiedSlicePoolMetrics,
}

impl CertifiedSlicePool {
    /// Creates a new pool instance using the given `MetricsRegistry` for
    /// instrumentation.
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            slices: Default::default(),
            stream_positions: Default::default(),
            metrics: CertifiedSlicePoolMetrics::new(metrics_registry),
        }
    }

    /// Takes a sub-slice of the stream from `subnet_id` starting at `begin`,
    /// respecting the given message count and byte limits; or, if the provided
    /// `byte_limit` is too small for a header-only slice, returns `Ok(None)`).
    ///
    /// If all messages are taken, the slice is removed from the pool.
    ///
    /// Returns `Err(InvalidPayload)` or `Err(WitnessPruningFailed)` and drops
    /// the pooled slice if malformed. Returns `Err(TakeBeforeSliceBegin)` and
    /// drops the pooled slice if `begin`'s `message_index` is before the
    /// first pooled message.
    pub fn take_slice(
        &mut self,
        subnet_id: SubnetId,
        begin: Option<&ExpectedIndices>,
        msg_limit: Option<usize>,
        byte_limit: Option<usize>,
    ) -> CertifiedSliceResult<Option<(CertifiedStreamSlice, usize)>> {
        match self.take_slice_impl(subnet_id, begin, msg_limit, byte_limit) {
            Ok(Some(slice)) => {
                let slice_count_bytes = slice.count_bytes();
                self.metrics.observe_take(STATUS_SUCCESS);
                self.metrics.observe_take_message_count(slice.payload.len());
                self.metrics.observe_take_size_bytes(slice_count_bytes);
                Ok(Some((slice.pack(), slice_count_bytes)))
            }
            Ok(None) => {
                self.metrics.observe_take(STATUS_NONE);
                Ok(None)
            }
            Err(e) => {
                // Invalid slice, has been dropped.
                self.metrics.observe_take(e.to_label_value());
                Err(e)
            }
        }
    }

    /// Helper function to allow easy instrumentation of `take_slice` results.
    ///
    /// On success, returns a prefix respecting the given limits.
    ///
    /// Returns `Err(InvalidPayload)` or `Err(WitnessPruningFailed)` if
    /// `self.payload` is malformed. Returns `Err(TakeBeforeSliceBegin)` if
    /// `begin`'s `message_index` is before the pooled slice's messages begin
    /// index.
    fn take_slice_impl(
        &mut self,
        subnet_id: SubnetId,
        begin: Option<&ExpectedIndices>,
        msg_limit: Option<usize>,
        byte_limit: Option<usize>,
    ) -> CertifiedSliceResult<Option<UnpackedStreamSlice>> {
        // Update the stream position in case we bail out early with no slice returned.
        begin.map(|begin| self.stream_positions.insert(subnet_id, begin.clone()));

        let (subnet_id, mut slice) = match self.slices.remove_entry(&subnet_id) {
            Some(entry) => entry,
            None => return Ok(None),
        };

        // GC first if explicit begin indices were provided.
        let original_message_count = slice.payload.len();
        if let Some(begin) = begin {
            slice = match slice.garbage_collect(begin)? {
                Some(slice) => slice,
                None => {
                    self.metrics
                        .observe_take_messages_gced(original_message_count);
                    return Ok(None);
                }
            };

            if let Some(actual_begin) = slice.payload.messages_begin() {
                if actual_begin != begin.message_index {
                    // Slice's `messages.begin` is past the requested stream index, bail out.
                    return Err(CertifiedSliceError::TakeBeforeSliceBegin);
                }
            }
        }

        let mut prefix_message_count = slice.payload.len();
        self.metrics
            .observe_take_messages_gced(original_message_count - prefix_message_count);
        let signals_end = slice.payload.header.signals_end();

        let (prefix, slice) = slice.take_prefix(msg_limit, byte_limit)?;

        // Put back the rest of the slice, if any.
        if let Some(slice) = slice {
            prefix_message_count -= slice.payload.len();
            self.slices.insert(subnet_id, slice);
        }

        if let Some(prefix) = prefix {
            // A prefix is being returned, update stream position accordingly.
            if let Some(stream_indices) = self.stream_positions.get_mut(&subnet_id) {
                stream_indices.message_index += StreamIndex::from(prefix_message_count as u64);
                stream_indices.signal_index = stream_indices.signal_index.max(signals_end);
            }
            Ok(Some(prefix))
        } else {
            Ok(None)
        }
    }

    /// Garbage collects all messages and signals before the given stream
    /// positions. Slices from subnets not present in the provided map are all
    /// dropped.
    ///
    /// `new_stream_positions` is retained as `self.stream_positions`.
    pub fn garbage_collect(&mut self, new_stream_positions: BTreeMap<SubnetId, ExpectedIndices>) {
        self.slices = new_stream_positions
            .iter()
            .filter_map(|(subnet_id, stream_position)| {
                self.garbage_collect_impl(subnet_id, stream_position)
            })
            .collect();
        self.stream_positions = new_stream_positions;
    }

    /// Garbage collects all messages and signals before the given stream
    /// position for the given slice.
    ///
    /// Updates the subnet's `self.stream_positions` with the new position.
    pub fn garbage_collect_slice(&mut self, subnet_id: SubnetId, stream_position: ExpectedIndices) {
        if let Some((subnet_id, slice)) = self.garbage_collect_impl(&subnet_id, &stream_position) {
            self.slices.insert(subnet_id, slice);
        }

        self.stream_positions.insert(subnet_id, stream_position);
    }

    fn garbage_collect_impl(
        &mut self,
        subnet_id: &SubnetId,
        stream_position: &ExpectedIndices,
    ) -> Option<(SubnetId, UnpackedStreamSlice)> {
        match self.slices.remove_entry(subnet_id) {
            None => None,

            Some((subnet_id, slice)) => {
                match slice.garbage_collect(&stream_position) {
                    // Some (or no) messages GC-ed. Retain the slice.
                    Ok(Some(slice)) => Some((subnet_id, slice)),

                    // All messages and signals GC-ed.
                    Ok(None) => None,

                    // Invalid slice, drop it.
                    Err(_) => {
                        // TODO(MR-6): Log and increment an error counter.
                        None
                    }
                }
            }
        }
    }

    /// Returns an iterator over the `SubnetIds` passed to the last
    /// `garbage_collect()` call, i.e. the set of known peer subnets.
    pub fn peers(&self) -> impl Iterator<Item = &SubnetId> {
        self.stream_positions.keys()
    }

    /// Returns the cached stream position; as well as the `messages_begin`,
    /// message count and byte size of the pooled slice originating from the
    /// given subnet, if any.
    pub fn slice_stats(
        &self,
        subnet_id: SubnetId,
    ) -> (Option<ExpectedIndices>, Option<StreamIndex>, usize, usize) {
        let (messages_begin, message_count, byte_size) =
            if let Some(slice) = self.slices.get(&subnet_id) {
                (
                    slice.payload.messages_begin(),
                    slice.payload.len(),
                    slice.count_bytes(),
                )
            } else {
                Default::default()
            };
        (
            self.stream_positions.get(&subnet_id).cloned(),
            messages_begin,
            message_count,
            byte_size,
        )
    }

    /// Returns the total estimated size of the slices in the pool.
    pub fn byte_size(&self) -> usize {
        self.slices.values().map(|slice| slice.count_bytes()).sum()
    }

    /// Places the provided slice into the pool, after trimming off any prefix
    /// before the corresponding `self.stream_positions` entry.
    ///
    /// On success always replaces the pooled slice regardless of its contents,
    /// as slices may originate from malicious replicas and we would rather
    /// temporarily replace a good slice with a bad one than be stuck with a bad
    /// one (e.g. because it has an exceedingly high `signals_end`).
    ///
    /// Returns `Err(InvalidPayload)` or `Err(WitnessPruningFailed)` if
    /// `slice` is malformed.
    pub fn put(
        &mut self,
        subnet_id: SubnetId,
        slice: CertifiedStreamSlice,
    ) -> CertifiedSliceResult<()> {
        self.put_impl(subnet_id, slice.try_into()?)
    }

    /// Appends a partial slice to the corresponding pool entry, trimming
    /// off any prefix before the matching`self.stream_positions` entry.
    /// Appending virtually consists of prepending the pooled messages to the
    /// provided partial slice.
    ///
    /// The provided partial slice's messages (if any) must extend gap-free the
    /// ones already in the pool and its `signals_end` must not regress. Its
    /// witness must cover the stream header and the concatenated messages.
    ///
    /// Returns `Err(DecodeFailed)` if `partial` could not be deserialized.
    /// Returns `Err(InvalidPayload)`,  `Err(InvalidWitness)` or
    /// `Err(WitnessPruningFailed)` if `self` or `partial` are malformed.
    /// Returns `Err(InvalidAppend)` if the two slices do not match.
    pub fn append(
        &mut self,
        subnet_id: SubnetId,
        partial: CertifiedStreamSlice,
    ) -> CertifiedSliceResult<()> {
        let partial: UnpackedStreamSlice = partial.try_into()?;

        let (res, slice) = match self.slices.remove(&subnet_id) {
            // We have a pooled slice, try appending to it.
            Some(mut pooled) => (pooled.append(partial), pooled),

            // No existing slice, retain the partial slice (and ensure it's actually complete).
            None => {
                if !partial.is_complete()? {
                    return Err(CertifiedSliceError::InvalidAppend(IndexMismatch));
                }
                (Ok(()), partial)
            }
        };

        self.put_impl(subnet_id, slice)?;
        res
    }

    /// Garbage collects the provided slice and pools the rest, if any.
    ///
    /// Returns `Err(InvalidPayload)` or `Err(WitnessPruningFailed)` if
    /// `unpacked` is malformed.
    fn put_impl(
        &mut self,
        subnet_id: SubnetId,
        mut unpacked: UnpackedStreamSlice,
    ) -> CertifiedSliceResult<()> {
        // Trim off everything before the cached stream position.
        if let Some(cutoff) = self.stream_positions.get(&subnet_id) {
            unpacked = match unpacked.garbage_collect(cutoff)? {
                Some(unpacked) => unpacked,
                // Bail out if nothing left.
                None => return Ok(()),
            };
        }

        self.slices.insert(subnet_id, unpacked);
        Ok(())
    }

    /// Observes the total size of all pooled slices.
    pub fn observe_pool_size_bytes(&self) {
        self.metrics.pool_size_bytes.set(self.byte_size() as i64);
    }
}

/// Internal functionality, exposed for use by integration tests.
pub mod testing {
    use super::*;

    /// Calls `slice.payload.count_bytes()`.
    pub fn payload_count_bytes(slice: &UnpackedStreamSlice) -> usize {
        slice.payload.count_bytes()
    }

    /// Returns the result of calling
    /// `xnet_payload_builder::witness_count_bytes()` on the given unpacked
    /// slice, i.e. the estimated witness size in bytes.
    pub fn witness_count_bytes(slice: &UnpackedStreamSlice) -> usize {
        let stream_begin = slice.payload.header.begin();
        let stream_end = slice.payload.header.end();
        let slice_begin = slice.payload.messages_begin();
        let slice_end =
            slice_begin.map(|begin| begin + StreamIndex::new(slice.payload.len() as u64));
        crate::xnet_payload_builder::witness_count_bytes(
            stream_begin,
            stream_end,
            slice_begin,
            slice_end,
        )
    }

    pub fn slice_len(slice: &UnpackedStreamSlice) -> usize {
        slice.payload.len()
    }
}
