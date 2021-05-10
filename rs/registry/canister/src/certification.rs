//! This module contains utilities for constructing hash trees and labeled trees
//! that we use for certification.

use crate::registry::{Registry, Version};
use ic_crypto_tree_hash::{
    flatmap, FlatMap, HashTreeBuilder, HashTreeBuilderImpl, Label, LabeledTree,
    WitnessGeneratorImpl,
};

/// The maximum amount of bytes a 64-bit number can occupy when encoded in
/// LEB128.
const MAX_U64_ENCODING_BYTES: usize = 10;

/// Builds a subtree using the provided builder.
fn subtree<B>(b: &mut B, f: impl FnOnce(&mut B))
where
    B: HashTreeBuilder,
{
    b.start_subtree();
    f(b);
    b.finish_subtree();
}

/// Adds a new edge labeled with `label` and pointing to a subtree built by `f`.
fn named_subtree<B>(b: &mut B, label: impl AsRef<[u8]>, f: impl FnOnce(&mut B))
where
    B: HashTreeBuilder,
{
    b.new_edge(Label::from(label));
    subtree(b, f);
}

/// Adds a new edge labeled with `label` and pointing to a leaf with `blob`
/// inside.
pub fn named_blob<B>(b: &mut B, label: impl AsRef<[u8]>, blob: impl AsRef<[u8]>)
where
    B: HashTreeBuilder,
{
    b.new_edge(Label::from(label));
    b.start_leaf();
    b.write_leaf(blob.as_ref());
    b.finish_leaf();
}

/// Builds a labeled leaf containing a number encoded in LEB128.
pub fn named_num<B>(b: &mut B, label: impl AsRef<[u8]>, n: u64)
where
    B: HashTreeBuilder,
{
    let mut buf = [0u8; MAX_U64_ENCODING_BYTES];
    let len = leb128::write::unsigned(&mut &mut buf[..], n).unwrap();
    named_blob(b, label, &buf[0..len]);
}

/// Constructs a hash tree that can be used to certify some requests concerning
/// the contents of the provided registry.
///
/// Tree structure:
///
/// ```text
/// *
/// |
/// +-- current_version -- [ LEB128-encoded VERSION ]
/// |
/// `-- delta --+-- [ big-endian encoded 1u64    ] -- [ serialized protobuf ]
///             |
///             …
///             |
///             `-- [ big-endian encoded VERSION ] -- [ serialized protobuf ]
/// ```
pub fn rebuild_tree(r: &Registry) -> WitnessGeneratorImpl {
    let mut b = HashTreeBuilderImpl::new();

    subtree(&mut b, |b| {
        named_num(b, "current_version", r.latest_version());
        named_subtree(b, "delta", |b| {
            for (version, bytes) in r.changelog().iter() {
                named_blob(b, version.to_be_bytes(), bytes);
            }
        });
    });

    b.witness_generator()
        .expect("impossible: constructed unbalanced hash tree")
}

/// Builds a leaf of a labeled tree containing LEB128 encoded integer.
pub fn num_leaf(n: u64) -> LabeledTree<Vec<u8>> {
    let mut buf = Vec::with_capacity(MAX_U64_ENCODING_BYTES);
    leb128::write::unsigned(&mut buf, n).unwrap();
    LabeledTree::Leaf(buf)
}

/// Builds a fork of a labeled tree containing a single edge labeled with
/// `label` and pointing to subtree `child`.
pub fn singleton<L: AsRef<[u8]>>(label: L, child: LabeledTree<Vec<u8>>) -> LabeledTree<Vec<u8>> {
    LabeledTree::SubTree(flatmap!(Label::from(label) => child))
}

/// Constructs a labeled tree encoding the specified range of deltas.
pub fn build_deltas_tree<'a>(
    latest_version: Version,
    deltas: impl std::iter::Iterator<Item = &'a (Version, Vec<u8>)>,
) -> LabeledTree<Vec<u8>> {
    let mut deltas_map = FlatMap::new();
    for (version, bytes) in deltas {
        deltas_map
            .try_append(
                Label::from(version.to_be_bytes()),
                LabeledTree::Leaf(bytes.clone()),
            )
            .unwrap_or_else(|(v, _)| {
                panic!(
                    "Versions must be sorted, got decreasing version sequence [{:?}, {:?}]",
                    deltas_map.last_key().unwrap(),
                    v
                )
            });
    }
    let root = flatmap!(
        Label::from("current_version") => num_leaf(latest_version),
        Label::from("delta") => LabeledTree::SubTree(deltas_map),
    );
    LabeledTree::SubTree(root)
}
