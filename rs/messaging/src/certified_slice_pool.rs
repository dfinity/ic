//! A pool of incoming `CertifiedStreamSlices` used by `XNetPayloadBuilderImpl`
//! to build `XNetPayloads` without the need for I/O on the critical path.

use crate::xnet_payload_builder::ExpectedIndices;
use ic_canonical_state::{encoding, LabelLike};
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

/// Unpacked `CertifiedStreamSlice::payload` plus cached metadata.
#[derive(Debug, PartialEq)]
struct Payload {
    /// The intended destination subnet of this stream slice.
    subnet_id: Label,

    /// Serialized stream header.
    header: Vec<u8>,

    /// Slice messages, may be missing from the `CertifiedStreamSlice`. Never
    /// empty when present.
    messages: Option<PayloadTreeMap>,

    /// Metadata: signals end index, extracted from stream header.
    signals_end: StreamIndex,

    /// Metadata: upper-bound byte size estimate of encoded payload, used in
    /// limiting sub-slice sizes.
    byte_size: usize,
}

impl Payload {
    /// Takes a prefix of the slice that is guaranteed to meet the given limits
    /// (particularly, the serialized byte size is guaranteed to be at most
    /// `byte_limit`).
    ///
    /// Returns the prefix (if one can be created) and the remaining payload (if
    /// any). At least one of the two is `Some(_)`.
    ///
    /// Returns `Err(InvalidPayload)` if `self.messages` is malformed.
    pub fn take_prefix(
        mut self,
        message_limit: Option<usize>,
        byte_limit: Option<usize>,
    ) -> CertifiedSliceResult<(Option<Self>, Option<Self>)> {
        let message_limit = message_limit.unwrap_or(std::usize::MAX);
        let byte_limit = byte_limit.unwrap_or(std::usize::MAX);

        // Find the cutoff point that respects the provided limits.
        let (cutoff, byte_size) = if let Some(messages) = self.messages.as_ref() {
            // Iterate right to left through messages until limits are met.
            let mut message_count = messages.len();
            let mut byte_size = self.byte_size;
            let mut messages = messages.iter();
            let mut cutoff = None;
            while byte_size > byte_limit || message_count > message_limit {
                let (label, leaf) = match messages.next_back() {
                    Some(res) => res,
                    None => break,
                };
                cutoff = Some(label);
                message_count -= 1;
                byte_size -= Self::min_message_byte_size(leaf)?;
            }
            (cutoff.map(Clone::clone), byte_size)
        } else {
            // Empty slice: return if under `byte_limit`, else keep it.
            if self.byte_size <= byte_limit {
                return Ok((Some(self), None));
            } else {
                return Ok((None, Some(self)));
            }
        };

        if byte_size > byte_limit {
            // Header-only prefix would be over `byte_limit`: bail out early.
            return Ok((None, Some(self)));
        }

        let cutoff = match cutoff {
            Some(cutoff) => cutoff,

            // No trimming necessary, return the whole slice.
            None => return Ok((Some(self), None)),
        };

        let prefix = self.take_messages_prefix(&cutoff)?;
        match prefix {
            // Empty prefix, under `byte_limit`: return it.
            None => Ok((Some(self.new_partial(None, byte_size)), Some(self))),

            // Prefix is non-empty and below limits, return it; keep the leftover iff
            // non-empty.
            Some(_) => {
                if self.messages.is_none() {
                    Ok((Some(self.new_partial(prefix, byte_size)), None))
                } else {
                    Ok((Some(self.new_partial(prefix, byte_size)), Some(self)))
                }
            }
        }
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
            .take_messages_prefix(&Label::from(cutoff.to_label()))?
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
        if other.signals_end < self.signals_end {
            // Not an actual error, just a race condition. We could choose to go ahead with
            // the merge and trade a larger slice for the possibility that the slice may be
            // invalid if the higher `signals_end` was already included into a block.
            return Err(CertifiedSliceError::InvalidAppend(SignalsEndRegresses));
        }

        match (self.messages.as_ref(), other.messages) {
            (Some(prefix), Some(suffix)) => {
                // Do all validation / fallible operations first, so `self` remains unmodified
                // on error.
                if Self::messages_begin_impl(&suffix)?.get()
                    != Self::messages_begin_impl(prefix)?.get() + self.len() as u64
                {
                    return Err(CertifiedSliceError::InvalidAppend(IndexMismatch));
                }
                let suffix_byte_size = Self::min_byte_size(&suffix)?;

                self.header = other.header;
                self.messages = Some(FlatMap::from_key_values(
                    self.messages
                        .take()
                        .unwrap()
                        .into_iter()
                        .chain(suffix.into_iter())
                        .collect(),
                ));
                // `self.messages_begin` stays unchanged.
                self.signals_end = other.signals_end;
                self.byte_size += suffix_byte_size;
            }

            (_, None) => {
                // `other` has no messages: take its `header` and `signals_end`, keep the rest.
                self.header = other.header;
                self.signals_end = other.signals_end;
            }

            (None, messages) => {
                // `self` has no messages: wholesale replace with `other`.
                self.header = other.header;
                self.messages = messages;
                self.signals_end = other.signals_end;
                self.byte_size = other.byte_size;
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
        if let Some(m) = self.messages.as_ref() {
            if m.is_empty() {
                return Err(CertifiedSliceError::InvalidPayload(EmptyMessages));
            }
        } else {
            // Nothing to prune.
            return Ok(witness.clone());
        }

        let partial_tree = Payload::pack(self.subnet_id.clone(), None, self.messages.take());
        let pruned_witness = prune_witness(witness, &partial_tree)?;
        self.messages = Payload::unpack(partial_tree).map(|(_, _, m)| m)?;
        Ok(pruned_witness)
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
            Some(mut messages) => {
                if messages.is_empty() {
                    return Err(CertifiedSliceError::InvalidPayload(EmptyMessages));
                }

                let postfix = messages.split_off(to);
                let prefix = messages;

                // Adjust the estimated size and put back the postfix if not empty.
                self.byte_size -= Self::min_byte_size(&prefix)?;
                if !postfix.is_empty() {
                    self.messages = Some(postfix);
                }

                if !prefix.is_empty() {
                    Ok(Some(prefix))
                } else {
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }

    /// Returns a lower-bound byte size estimate of a set of messages,
    /// including their labels.
    ///
    /// Returns `Err(InvalidPayload)` if `messages` is malformed.
    fn min_byte_size(messages: &PayloadTreeMap) -> CertifiedSliceResult<usize> {
        let mut byte_size = 0;
        for message in messages.values() {
            byte_size += Self::min_message_byte_size(message)?;
        }
        Ok(byte_size)
    }

    /// Returns a lower-bound byte size estimate of a message plus its label.
    ///
    /// Returns `Err(InvalidPayload)` if `message` is not a leaf.
    fn min_message_byte_size(message: &PayloadTree) -> CertifiedSliceResult<usize> {
        // 1 byte for length of label and message each, 8 bytes for label (u64).
        Ok(1 + Self::value_of_ref(message)?.len() + 1 + 8)
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
            .ok_or_else(|| CertifiedSliceError::InvalidPayload(MissingStreams))?;
        let mut streams = Self::children_of(streams_tree)?.into_iter();

        let (subnet_id, stream_tree) = streams
            .next()
            .ok_or_else(|| CertifiedSliceError::InvalidPayload(MissingStream))?;
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
    fn new_partial(&self, messages: Option<PayloadTreeMap>, byte_size: usize) -> Self {
        Self {
            subnet_id: self.subnet_id.clone(),
            header: self.header.clone(),
            messages,
            signals_end: self.signals_end,
            byte_size,
        }
    }

    /// Returns the `StreamIndex` of the first message, if any;
    /// `Err(InvalidPayload)` if `self.messages` is malformed.
    fn messages_begin(&self) -> CertifiedSliceResult<Option<StreamIndex>> {
        self.messages
            .as_ref()
            .map(|m| Self::messages_begin_impl(m))
            .transpose()
    }

    /// Returns the `StreamIndex` of the first message, if any;
    /// `Err(InvalidPayload)` if `messages` is malformed
    fn messages_begin_impl(messages: &PayloadTreeMap) -> CertifiedSliceResult<StreamIndex> {
        if messages.is_empty() {
            Err(CertifiedSliceError::InvalidPayload(EmptyMessages))
        } else {
            Ok(
                to_stream_index(&messages.keys()[0])
                    .map_err(CertifiedSliceError::InvalidPayload)?,
            )
        }
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

impl TryFrom<&[u8]> for Payload {
    type Error = CertifiedSliceError;

    fn try_from(payload_bytes: &[u8]) -> Result<Self, Self::Error> {
        let tree: PayloadTree = v1::LabeledTree::proxy_decode(payload_bytes)?;
        let (subnet_id, header, messages) = Self::unpack(tree)?;

        let header = header.ok_or_else(|| CertifiedSliceError::InvalidPayload(MissingHeader))?;
        let decoded_header = encoding::decode_stream_header(&header)?;

        Ok(Self {
            subnet_id,
            header,
            messages,
            signals_end: decoded_header.signals_end,
            byte_size: payload_bytes.len(),
        })
    }
}

impl From<Payload> for Vec<u8> {
    fn from(payload: Payload) -> Self {
        v1::LabeledTree::proxy_encode(Payload::pack(
            payload.subnet_id,
            Some(payload.header),
            payload.messages,
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

    /// Original encoded witness size, used in estimating sub-slice sizes.
    merkle_proof_byte_size: usize,

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
    ) -> CertifiedSliceResult<(Option<CertifiedStreamSlice>, Option<Self>)> {
        if let Some(byte_limit_) = byte_limit {
            let overhead_bytes = self.estimated_size() - self.payload.byte_size;
            if overhead_bytes > byte_limit_ {
                return Ok((None, Some(self)));
            }
            byte_limit = Some(byte_limit_ - overhead_bytes);
        }

        match self.payload.take_prefix(msg_limit, byte_limit)? {
            (None, None) => unreachable!("slice with no messages or signals"),

            // Nothing taken, put back the payload.
            (None, Some(payload)) => {
                self.payload = payload;
                Ok((None, Some(self)))
            }

            // All messages taken.
            (Some(payload), None) => Ok((
                Some(Self::pack(payload, self.merkle_proof, self.certification)),
                None,
            )),

            // Messages actually split or empty (header-only) prefix.
            (Some(mut prefix_payload), Some(mut postfix_payload)) => {
                let certification = self.certification.clone();
                let prefix_witness = postfix_payload.pruned_witness(&self.merkle_proof)?;

                self.payload = postfix_payload;
                if prefix_payload.messages.is_some() {
                    // Messages actually split, prune postfix witness.
                    self.merkle_proof = prefix_payload.pruned_witness(&self.merkle_proof)?;
                }

                let prefix = Self::pack(prefix_payload, prefix_witness, certification);

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
        if cutoff.signal_index >= self.payload.signals_end && self.payload.messages.is_none() {
            // All signals and messages were garbage collected.
            return Ok(None);
        }

        if let Some(pruned_tree) = pruned_tree {
            self.merkle_proof = prune_witness(&self.merkle_proof, &pruned_tree)?;
            // Assuming witness size stays about constant.
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
        let messages_begin = self.payload.messages_begin()?;
        if messages_begin.is_some() {
            if messages_begin != partial.witness_messages_begin()? {
                return Err(CertifiedSliceError::InvalidAppend(IndexMismatch));
            }
        } else if !partial.is_complete()? {
            return Err(CertifiedSliceError::InvalidAppend(IndexMismatch));
        }

        self.payload.append(partial.payload)?;
        self.merkle_proof = partial.merkle_proof;
        self.merkle_proof_byte_size = partial.merkle_proof_byte_size;
        self.certification = partial.certification;

        Ok(())
    }

    /// Tests whether this is a complete (`true`) or partial (`false`) slice.
    ///
    /// Returns `Err(InvalidPayload)` if `self.payload` is malformed. Returns
    /// `Err(InvalidWitness)` if `self.merkle_proof` is malformed.
    fn is_complete(&self) -> CertifiedSliceResult<bool> {
        Ok(self.payload.messages_begin()? == self.witness_messages_begin()?)
    }

    /// Returns the index of the first `Known` message in `self.merkle_proof`.
    ///
    /// Returns `Err(InvalidWitness)` if `self.merkle_proof` is malformed.
    fn witness_messages_begin(&self) -> CertifiedSliceResult<Option<StreamIndex>> {
        let streams = sub_witness(&self.merkle_proof, &Label::from(LABEL_STREAMS))
            .ok_or_else(|| CertifiedSliceError::InvalidWitness(MissingStreams))?;
        let (_subnet_id, stream) = first_sub_witness(streams)
            .ok_or_else(|| CertifiedSliceError::InvalidWitness(MissingStream))?;
        sub_witness(stream, &Label::from(LABEL_MESSAGES))
            .map(first_sub_witness)
            .flatten()
            .map(|first_message| {
                to_stream_index(first_message.0).map_err(CertifiedSliceError::InvalidWitness)
            })
            .transpose()
    }

    /// Produces an upper bound estimate of the serialized byte size (with an
    /// error delta of up to `2 * log(N) * 32` bytes, due to the witness
    /// possibly growing after pruning).
    pub fn estimated_size(&self) -> usize {
        self.payload.byte_size + self.merkle_proof_byte_size + self.certification.count_bytes()
    }

    /// Packs a `Payload`, `Witness` and `Certification` into a
    /// `CertifiedStreamSlice`.
    fn pack(
        payload: Payload,
        witness: Witness,
        certification: Certification,
    ) -> CertifiedStreamSlice {
        CertifiedStreamSlice {
            payload: payload.into(),
            merkle_proof: v1::Witness::proxy_encode(witness)
                .expect("failed to serialize a witness"),
            certification,
        }
    }
}

impl TryFrom<CertifiedStreamSlice> for UnpackedStreamSlice {
    type Error = CertifiedSliceError;

    fn try_from(packed: CertifiedStreamSlice) -> Result<Self, Self::Error> {
        Ok(Self {
            payload: Payload::try_from(packed.payload.as_slice())?,
            merkle_proof: v1::Witness::proxy_decode(&packed.merkle_proof)?,
            merkle_proof_byte_size: packed.merkle_proof.len(),
            certification: packed.certification,
        })
    }
}

impl From<UnpackedStreamSlice> for CertifiedStreamSlice {
    fn from(unpacked: UnpackedStreamSlice) -> Self {
        UnpackedStreamSlice::pack(
            unpacked.payload,
            unpacked.merkle_proof,
            unpacked.certification,
        )
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
    StreamIndex::from_label(label.as_bytes()).ok_or_else(|| NotAStreamIndex)
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
    ) -> CertifiedSliceResult<Option<CertifiedStreamSlice>> {
        match self.take_slice_impl(subnet_id, begin, msg_limit, byte_limit) {
            Ok(Some((slice, message_count))) => {
                self.metrics.observe_take(STATUS_SUCCESS);
                self.metrics.observe_take_message_count(message_count);
                self.metrics.observe_take_size_bytes(slice.count_bytes());
                Ok(Some(slice))
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
    /// On success, returns the certified slice and its message count.
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
    ) -> CertifiedSliceResult<Option<(CertifiedStreamSlice, usize)>> {
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

            if let Some(actual_begin) = slice.payload.messages_begin()? {
                if actual_begin != begin.message_index {
                    // Slice's `messages.begin` is past the requested stream index, bail out.
                    return Err(CertifiedSliceError::TakeBeforeSliceBegin);
                }
            }
        }

        let mut prefix_message_count = slice.payload.len();
        self.metrics
            .observe_take_messages_gced(original_message_count - prefix_message_count);
        let signals_end = slice.payload.signals_end;

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
            Ok(Some((prefix, prefix_message_count)))
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
                if let Ok(messages_begin) = slice.payload.messages_begin() {
                    (messages_begin, slice.payload.len(), slice.estimated_size())
                } else {
                    // Malformed payload, slice will be dropped on next mutation.
                    Default::default()
                }
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
        self.slices
            .values()
            .map(|slice| slice.estimated_size())
            .sum()
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
