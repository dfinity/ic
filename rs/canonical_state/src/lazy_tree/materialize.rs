//! Support for materializing (part of) a [`LazyTree`] as a [`LabeledTree`].

use super::LazyTree;
use ic_crypto_tree_hash::{FlatMap, LabeledTree};
use LazyTree::*;

/// A pattern to be used for fitering the parts of a [`LazyTree`] to be
/// materialized. A [`LabeledTree`] with no values.
pub type TreePattern = LabeledTree<()>;

fn materialize(lazy_tree: &LazyTree<'_>) -> Option<LabeledTree<Vec<u8>>> {
    match lazy_tree {
        Blob(blob) => Some(LabeledTree::Leaf(blob.to_vec())),
        LazyBlob(f) => Some(LabeledTree::Leaf(f().to_vec())),
        LazyFork(f) => {
            let children: Vec<_> = f
                .labels()
                .filter_map(|l| {
                    let lazy_tree = f.edge(&l)?;
                    let t = materialize(&lazy_tree)?;
                    Some((l, t))
                })
                .collect();

            if children.is_empty() {
                None
            } else {
                Some(LabeledTree::SubTree(FlatMap::from_key_values(children)))
            }
        }
    }
}

/// This function provides materializing a LazyTree partially, including only
/// the paths whose prefixes are listed in the pattern (which is itself
/// represented as a LabeledTree, without data in the leaves).
///
/// This is used in the implementation of the `read_state` request, so a
/// specification can be found in the Interface Spec, section on Lookup in
/// certification (https://sdk.dfinity.org/docs/interface-spec/index.html#_lookup)
///
/// The spec requires that the resulting certificate also proves the absence of
/// a prefix; this is not yet implemented. Once it is implemented, remove the
/// corresponding `exclude` directives from `tests/ic-ref-test/run`.
pub fn materialize_partial(
    lazy_tree: &LazyTree<'_>,
    pattern: &TreePattern,
) -> Option<LabeledTree<Vec<u8>>> {
    match pattern {
        LabeledTree::Leaf(()) => materialize(lazy_tree),
        LabeledTree::SubTree(children) => {
            if let LazyFork(f) = lazy_tree {
                let subtrees: Vec<_> = children
                    .iter()
                    .filter_map(|(label, pattern)| {
                        let lazy_tree = f.edge(label)?;
                        let t = materialize_partial(&lazy_tree, pattern)?;
                        Some((label.clone(), t))
                    })
                    .collect();

                if subtrees.is_empty() {
                    // Prune empty subtrees
                    None
                } else {
                    Some(LabeledTree::SubTree(FlatMap::from_key_values(subtrees)))
                }
            } else {
                None
            }
        }
    }
}
