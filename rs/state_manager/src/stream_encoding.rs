use crate::labeled_tree_visitor::LabeledTreeVisitor;
use ic_canonical_state::{
    encoding::{decode_message, decode_stream_header},
    size_limit_visitor::{Matcher, SizeLimitVisitor},
    subtree_visitor::{Pattern, SubtreeVisitor},
    traverse, LabelLike,
};
use ic_crypto_tree_hash::{FlatMap, Label, LabeledTree};
use ic_interfaces::certified_stream_store::DecodeStreamError;
use ic_protobuf::messaging::xnet::v1;
use ic_protobuf::proxy::ProtoProxy;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    xnet::{StreamHeader, StreamIndex, StreamIndexedQueue, StreamSlice},
    SubnetId,
};
use serde::Deserialize;
use std::collections::BTreeMap;

const LABEL_STREAMS: &[u8] = b"streams";
const LABEL_HEADER: &[u8] = b"header";
const LABEL_MESSAGES: &[u8] = b"messages";

fn find_path<'a>(
    t: &'a mut LabeledTree<Vec<u8>>,
    path: &[&[u8]],
) -> Option<&'a mut LabeledTree<Vec<u8>>> {
    let mut tref = t;
    for l in path.iter() {
        match tref {
            LabeledTree::Leaf(_) => return None,
            LabeledTree::SubTree(ref mut children) => {
                tref = children.get_mut(&Label::from(l))?;
            }
        }
    }
    Some(tref)
}

/// Encodes a stream slice for the specified `subnet`, consisting of available
/// messages beginning at `from` and ending before `to`, of total size at most
/// `byte_limit`, using canonical tree form.
///
/// Returns the encoded slice and the actual end index (which may be different
/// from `to` if `byte_limit` is reached).
///
/// For example, the slice for subnet `25` with messages `[5, 10)` (assuming the
/// full range of messages in the stream is `[3, 20)`) will look like this:
///
/// ```text
/// *
/// | streams
/// `---------*
///           | 25
///           `----*
///                | header
///                +-------- { begin: 3, end: 20, signals_end: ... }
///                | messages
///                `---------*
///                          | 5
///                          +---- { blob }
///                          | 6
///                          +---- { blob }
///                          |
///                          …
///                          | 9
///                          +---- { blob }
/// ```
///
/// See `ic_replicated_state::canonical::traversal` for more details on the tree
/// structure.
pub fn encode_stream_slice(
    state: &ReplicatedState,
    subnet: SubnetId,
    from: StreamIndex,
    to: StreamIndex,
    byte_limit: Option<usize>,
) -> (LabeledTree<Vec<u8>>, StreamIndex) {
    use Matcher as M;
    use Pattern as P;

    let byte_limit = byte_limit.unwrap_or(std::usize::MAX);
    let size_limit_pattern = vec![
        M::Label(LABEL_STREAMS.to_vec()),
        M::Any,
        M::Label(LABEL_MESSAGES.to_vec()),
        M::Any,
    ];
    let visitor = SizeLimitVisitor::new(
        size_limit_pattern,
        byte_limit,
        LabeledTreeVisitor::default(),
    );

    let subnet = subnet.get();
    let pattern = P::match_only(
        LABEL_STREAMS,
        P::match_only(
            subnet.into_vec(),
            P::match_any(
                vec![
                    (LABEL_HEADER, P::all()),
                    (
                        LABEL_MESSAGES,
                        P::match_range(
                            from.to_label().as_bytes(),
                            to.to_label().as_bytes(),
                            P::all(),
                        ),
                    ),
                ]
                .into_iter(),
            ),
        ),
    );

    let mut tree = traverse(state, SubtreeVisitor::new(&pattern, visitor));
    let mut actual_to = from;

    // The crypto library that constructs witnesses doesn't like empty subtrees as
    // input, so we remove `messages` if it's empty.
    if let Some(LabeledTree::SubTree(stream)) =
        find_path(&mut tree, &[LABEL_STREAMS, subnet.as_slice()])
    {
        if let Some(LabeledTree::SubTree(messages)) = stream.get(&Label::from(LABEL_MESSAGES)) {
            actual_to += (messages.len() as u64).into();
            if messages.is_empty() {
                stream.remove(&Label::from(LABEL_MESSAGES));
            }
        }
    }

    (tree, actual_to)
}

/// Creates a partial tree (structure only, empty values) in canonical tree form
/// (see [encode_stream_slice]) for a stream slice for the specified `subnet`,
/// with messages beginning at `from` (inclusive) and ending at `to`
/// (exclusive), to be used for witness generation.
pub fn stream_slice_partial_tree(
    subnet: SubnetId,
    from: StreamIndex,
    to: StreamIndex,
) -> LabeledTree<Vec<u8>> {
    let empty_leaf = LabeledTree::Leaf(vec![]);

    let stream = if to != from {
        // Non-empty messages.
        let mut messages = Vec::with_capacity((to - from).get() as usize);
        for i in from.get()..to.get() {
            messages.push((i.to_label(), empty_leaf.clone()));
        }
        let messages = FlatMap::from_key_values(messages);

        LabeledTree::SubTree(FlatMap::from_key_values(vec![
            (Label::from(LABEL_HEADER), empty_leaf),
            (Label::from(LABEL_MESSAGES), LabeledTree::SubTree(messages)),
        ]))
    } else {
        // Empty messages, leave out the messages subtree.
        LabeledTree::SubTree(FlatMap::from_key_values(vec![(
            Label::from(LABEL_HEADER),
            empty_leaf,
        )]))
    };

    let streams = LabeledTree::SubTree(FlatMap::from_key_values(vec![(
        Label::from(subnet.get().into_vec()),
        stream,
    )]));

    LabeledTree::SubTree(FlatMap::from_key_values(vec![(
        Label::from(LABEL_STREAMS),
        streams,
    )]))
}

pub fn encode_tree(t: LabeledTree<Vec<u8>>) -> Vec<u8> {
    v1::LabeledTree::proxy_encode(t).expect("failed to serialize a labeled tree")
}

/// Decodes a stream slice and the subnet it came from from a serialized
/// canonical tree.
pub fn decode_stream_slice(
    tree_bytes: &[u8],
) -> Result<(SubnetId, StreamSlice), DecodeStreamError> {
    let tree = decode_labeled_tree(tree_bytes)?;
    decode_slice_from_tree(&tree)
}

/// Decodes a labeled tree from a byte buffer.
pub fn decode_labeled_tree(bytes: &[u8]) -> Result<LabeledTree<Vec<u8>>, DecodeStreamError> {
    v1::LabeledTree::proxy_decode(bytes).map_err(|err| {
        DecodeStreamError::SerializationError(format!("failed to decode stream: {}", err))
    })
}

// Note: EncodedStream(s) structs are only used to decode tree structure into a
// form that is convenient to work with in Rust.

/// An auxiliary structure that mirrors the xnet streams data encoded in
/// canonical form, starting from the root of the tree.
#[derive(Debug, Deserialize)]
struct EncodedStreams<'a> {
    #[serde(borrow)]
    streams: BTreeMap<SubnetId, EncodedStream<'a>>,
}

/// An auxiliary structure that mirrors a single xnet stream slice encoded in
/// canonical form.
#[derive(Debug, Deserialize)]
struct EncodedStream<'a> {
    #[serde(borrow)]
    header: &'a serde_bytes::Bytes,

    #[serde(borrow)]
    #[serde(default)]
    messages: BTreeMap<StreamIndex, &'a serde_bytes::Bytes>,
}

/// Recovers a stream slice from its canonical form.
pub fn decode_slice_from_tree(
    t: &LabeledTree<Vec<u8>>,
) -> Result<(SubnetId, StreamSlice), DecodeStreamError> {
    let streams = EncodedStreams::deserialize(tree_deserializer::LabeledTreeDeserializer::new(t))
        .map_err(|err| {
        DecodeStreamError::SerializationError(format!(
            "failed to deserialize encoded streams: {}",
            err
        ))
    })?;

    if streams.streams.len() != 1 {
        return Err(DecodeStreamError::SerializationError(format!(
            "expected a stream with a single subnet, got {} subnets",
            streams.streams.len()
        )));
    }

    let (subnet, encoded_stream) = streams.streams.into_iter().next().unwrap();

    let header: StreamHeader =
        decode_stream_header(encoded_stream.header.as_ref()).map_err(|err| {
            DecodeStreamError::SerializationError(format!(
                "failed to deserialize stream header from CBOR: {}",
                err
            ))
        })?;

    let mut messages = encoded_stream
        .messages
        .keys()
        .next()
        .map(|idx| StreamIndexedQueue::with_begin(*idx));

    if let Some(ref mut queue) = messages {
        for (idx, bytes) in encoded_stream.messages.into_iter() {
            let msg = decode_message(bytes.as_ref()).map_err(|err| {
                DecodeStreamError::SerializationError(format!(
                    "failed to deserialize message {} from subnet {}: {}",
                    idx, subnet, err
                ))
            })?;

            if idx != queue.end() {
                return Err(DecodeStreamError::SerializationError(format!(
                    "non-consecutive message indices: {} follows {}",
                    idx,
                    queue.end()
                )));
            }

            queue.push(msg);
        }

        if queue.begin() < header.begin || header.end < queue.end() {
            return Err(DecodeStreamError::SerializationError(
                format!("the range of message indices [{}, {}) does not agree with the range in header [{}, {})",
                        queue.begin(), queue.end(), header.begin, header.end)
            ));
        }
    }

    Ok((subnet, StreamSlice::from_parts(header, messages)))
}

#[cfg(test)]
mod tests;
