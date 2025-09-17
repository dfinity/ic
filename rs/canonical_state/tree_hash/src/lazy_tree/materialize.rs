//! Support for materializing (part of) a [`LazyTree`] as a [`LabeledTree`].

use super::LazyTree;
use LazyTree::*;
use ic_crypto_tree_hash::{FlatMap, Label, LabeledTree, MatchPattern};

/// A pattern to be used for filtering the parts of a [`LazyTree`] to be
/// materialized. A [`LabeledTree`] with no values.
pub type TreePattern = LabeledTree<()>;

fn materialize(
    lazy_tree: &LazyTree<'_>,
    exclusion: Option<&[MatchPattern]>,
) -> LabeledTree<Vec<u8>> {
    match lazy_tree {
        Blob(blob, _) => LabeledTree::Leaf(blob.to_vec()),
        LazyBlob(f) => LabeledTree::Leaf(f().to_vec()),
        LazyFork(f) => {
            let mut children = FlatMap::new();
            for (l, t) in f.children() {
                let exclusion = exclusion_for_label(&l, exclusion);
                if !matches!(exclusion, Some(&[])) {
                    children
                        .try_append(l, materialize(&t, exclusion))
                        .expect("bug: lazy tree labels aren't sorted");
                }
            }
            LabeledTree::SubTree(children)
        }
    }
}

/// This function provides materializing a LazyTree partially, including only
/// the paths whose prefixes are listed in the pattern (which is itself
/// represented as a LabeledTree, without data in the leaves).
///
/// Optionally, an exclusion list can be provided for paths that should be excluded
/// even when matching the pattern.
///
/// This is used in the implementation of the `read_state` request, so a
/// specification can be found in the Interface Spec, section on Lookup in
/// certification
/// (https://internetcomputer.org/docs/current/references/ic-interface-spec/#lookup).
pub fn materialize_partial(
    lazy_tree: &LazyTree<'_>,
    pattern: &TreePattern,
    exclusion: Option<&[MatchPattern]>,
) -> LabeledTree<Vec<u8>> {
    match (pattern, lazy_tree) {
        (LabeledTree::Leaf(()), lazy_tree) => materialize(lazy_tree, exclusion),
        (LabeledTree::SubTree(children), LazyFork(f)) => {
            let subtrees = children.iter().filter_map(|(label, pattern)| {
                match f.edge(label) {
                    Some(lazy_tree) => {
                        let exclusion = exclusion_for_label(label, exclusion);
                        if !matches!(exclusion, Some(&[])) {
                            Some((
                                label.clone(),
                                materialize_partial(&lazy_tree, pattern, exclusion),
                            ))
                        } else {
                            None
                        }
                    }
                    None => {
                        // The label is not in the tree, but we
                        // construct a dummy node anyway to get a proof
                        // of absence.
                        Some((label.clone(), LabeledTree::Leaf(vec![])))
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
        (LabeledTree::SubTree(_), blob) => materialize(blob, exclusion),
    }
}

/// Helper function that returns Some(tail) if the head matches the label, and `None` otherwise.
fn exclusion_for_label<'a>(
    label: &'_ Label,
    exclusion: Option<&'a [MatchPattern]>,
) -> Option<&'a [MatchPattern]> {
    exclusion.and_then(|exclusion| match exclusion {
        [] => None,
        [head, tail @ ..] => {
            if head.matches(label) {
                Some(tail)
            } else {
                None
            }
        }
    })
}
