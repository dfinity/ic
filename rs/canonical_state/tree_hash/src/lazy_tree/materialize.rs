//! Support for materializing (part of) a [`LazyTree`] as a [`LabeledTree`].

use super::LazyTree;
use ic_crypto_tree_hash::{FlatMap, LabeledTree};
use LazyTree::*;

/// A pattern to be used for filtering the parts of a [`LazyTree`] to be
/// materialized. A [`LabeledTree`] with no values.
pub type TreePattern = LabeledTree<()>;

fn materialize(lazy_tree: &LazyTree<'_>) -> LabeledTree<Vec<u8>> {
    match lazy_tree {
        Blob(blob, _) => LabeledTree::Leaf(blob.to_vec()),
        LazyBlob(f) => LabeledTree::Leaf(f().to_vec()),
        LazyFork(f) => {
            let mut children = FlatMap::new();
            for (l, t) in f.children() {
                children
                    .try_append(l, materialize(&t))
                    .expect("bug: lazy tree labels aren't sorted");
            }
            LabeledTree::SubTree(children)
        }
    }
}

/// This function provides materializing a LazyTree partially, including only
/// the paths whose prefixes are listed in the pattern (which is itself
/// represented as a LabeledTree, without data in the leaves).
///
/// This is used in the implementation of the `read_state` request, so a
/// specification can be found in the Interface Spec, section on Lookup in
/// certification
/// (https://internetcomputer.org/docs/current/references/ic-interface-spec/#lookup).
pub fn materialize_partial(
    lazy_tree: &LazyTree<'_>,
    pattern: &TreePattern,
) -> LabeledTree<Vec<u8>> {
    match (pattern, lazy_tree) {
        (LabeledTree::Leaf(()), lazy_tree) => materialize(lazy_tree),
        (LabeledTree::SubTree(children), LazyFork(f)) => {
            let subtrees = children.iter().map(|(label, pattern)| {
                match f.edge(label) {
                    Some(lazy_tree) => (label.clone(), materialize_partial(&lazy_tree, pattern)),
                    None => {
                        // The label is not in the tree, but we
                        // construct a dummy node anyway to get a proof
                        // of absence.
                        (label.clone(), LabeledTree::Leaf(vec![]))
                    }
                }
            });

            let mut children = FlatMap::new();
            for (l, t) in subtrees {
                children
                    .try_append(l, t)
                    .expect("bug: lazy tree labels are not sorted");
            }

            LabeledTree::SubTree(children)
        }
        // The pattern expected the child to be a subtree, we have to reveal
        // the data to prove otherwise.
        (LabeledTree::SubTree(_), blob) => materialize(blob),
    }
}
