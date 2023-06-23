//! Builders for `Witness` and `HashTree` structures, and other
//! helpers for processing these structures.

use crate::hasher::Hasher;
use crate::{
    flatmap, Digest, FlatMap, HashTree, HashTreeBuilder, Label, LabeledTree, MixedHashTree, Path,
    TreeHashError, Witness, WitnessGenerator, MAX_HASH_TREE_DEPTH,
};
use std::collections::VecDeque;
use std::convert::TryFrom;
use std::fmt;
use std::fmt::Debug;
use std::iter::Peekable;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod test_utils;

const DOMAIN_HASHTREE_LEAF: &str = "ic-hashtree-leaf";
const DOMAIN_HASHTREE_EMPTY_SUBTREE: &str = "ic-hashtree-empty";
const DOMAIN_HASHTREE_NODE: &str = "ic-hashtree-labeled";
const DOMAIN_HASHTREE_FORK: &str = "ic-hashtree-fork";

/// Limit on the depth of the tree printed via the [`Debug`] trait.
/// Currently, 50 is the limit for the depth of deserialization.
const DEBUG_PRINT_DEPTH_LIMIT: u8 = 50;

/// Indentation width, i.e., the number of leading whitespaces.
const INDENT_WIDTH: usize = 2;

// Helpers for creation of domain-separated hashers.
pub(crate) fn new_leaf_hasher() -> Hasher {
    Hasher::for_domain(DOMAIN_HASHTREE_LEAF)
}

pub(crate) fn new_fork_hasher() -> Hasher {
    Hasher::for_domain(DOMAIN_HASHTREE_FORK)
}

pub(crate) fn new_node_hasher() -> Hasher {
    Hasher::for_domain(DOMAIN_HASHTREE_NODE)
}

pub(crate) fn empty_subtree_hash() -> Digest {
    Hasher::for_domain(DOMAIN_HASHTREE_EMPTY_SUBTREE).finalize()
}

/// Wraps the given hash_tree into a [`HashTree::HashNode`].
fn into_hash_node(label: &Label, hash_tree: HashTree) -> HashTree {
    let mut hasher = new_node_hasher();
    hasher.update(label.as_bytes());
    hasher.update(&hash_tree.digest().0);
    let digest = hasher.finalize();
    HashTree::Node {
        digest,
        label: label.to_owned(),
        hash_tree: Box::new(hash_tree),
    }
}

/// Wraps the given left_tree and right_tree into [`HashTree::HashFork`].
fn into_fork(left_tree: HashTree, right_tree: HashTree) -> HashTree {
    let mut hasher = new_fork_hasher();
    hasher.update(&left_tree.digest().0);
    hasher.update(&right_tree.digest().0);
    let digest = hasher.finalize();
    HashTree::Fork {
        digest,
        left_tree: Box::new(left_tree),
        right_tree: Box::new(right_tree),
    }
}

/// Wraps the given hash_trees into a single [`HashTree`], maintaining
/// the order of the subtrees.
fn into_hash_tree(mut hash_trees: VecDeque<HashTree>) -> HashTree {
    if hash_trees.is_empty() {
        return HashTree::Leaf {
            digest: empty_subtree_hash(),
        };
    }

    let mut combined_trees = VecDeque::with_capacity((hash_trees.len() + 1) / 2);
    while hash_trees.len() != 1 {
        while let Some(left) = hash_trees.pop_front() {
            match hash_trees.pop_front() {
                Some(right) => combined_trees.push_back(into_fork(left, right)),
                None => combined_trees.push_back(left),
            }
        }
        std::mem::swap(&mut hash_trees, &mut combined_trees);
    }
    hash_trees
        .pop_front()
        .expect("Should never fail because `hash_trees.len() == 1")
}

fn write_labeled_tree<T: Debug>(
    tree: &LabeledTree<T>,
    level: u8,
    f: &mut fmt::Formatter<'_>,
) -> fmt::Result {
    // stop at level `DEBUG_PRINT_DEPTH_LIMIT` to prevent oveflows/too large debug outputs
    if level >= DEBUG_PRINT_DEPTH_LIMIT {
        return write_truncation_info(f);
    }
    let indent = " ".repeat(level as usize * INDENT_WIDTH);
    match tree {
        LabeledTree::Leaf(t) => writeln!(f, "{}\\__ leaf:{:?}", indent, t),
        LabeledTree::SubTree(children) => {
            for child in children.iter() {
                writeln!(f, "{}+-- {}:", indent, child.0)?;
                write_labeled_tree(child.1, level.saturating_add(1), f)?;
            }
            write!(f, "")
        }
    }
}

fn write_hash_tree(tree: &HashTree, level: u8, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    // stop at level `DEBUG_PRINT_DEPTH_LIMIT` to prevent oveflows/too large debug outputs
    if level >= DEBUG_PRINT_DEPTH_LIMIT {
        return write_truncation_info(f);
    }
    let indent = " ".repeat(level as usize * INDENT_WIDTH);
    match tree {
        HashTree::Leaf { digest } => writeln!(f, "{}\\__leaf:{:?}", indent, digest),
        HashTree::Fork {
            digest,
            left_tree,
            right_tree,
        } => {
            writeln!(f, "{}+-- fork:{:?}", indent, digest)?;
            write_hash_tree(left_tree, level.saturating_add(1), f)?;
            write_hash_tree(right_tree, level.saturating_add(1), f)
        }
        HashTree::Node {
            digest,
            label,
            hash_tree,
        } => {
            writeln!(f, "{}--- node: [{}], {:?}", indent, label, digest)?;
            write_hash_tree(hash_tree, level.saturating_add(1), f)
        }
    }
}

fn write_truncation_info(f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let indent = " ".repeat(DEBUG_PRINT_DEPTH_LIMIT as usize * INDENT_WIDTH);
    writeln!(
        f,
        "{indent}... Further levels of the tree are truncated because the tree depth limit
        of {DEBUG_PRINT_DEPTH_LIMIT} has been reached ..."
    )
}

/// Prunes from `witness` the given (non-empty) `LabeledTree::SubTree` children.
///
/// A non-empty `LabeledTree::Subtree` maps to a tree of zero or more
/// `Witness::Forks` with `Witness::Node` or `Witness::Known` leaves, so subtree
/// pruning is recursive.
///
/// `children` is an iterator over the `SubTree` children to be pruned, sorted
/// by label. If one or more children could not be pruned (because no such nodes
/// exist in the witness) the iterator will not be consumed and will point to
/// the first such child.
///
/// Returns a tuple containing the pruned witness and the count of all leaves
/// and empty subtrees that were "plugged into" the witness during pruning.
fn prune_witness_subtree<'a, I>(
    witness: &Witness,
    children: &mut Peekable<I>,
    curr_path: &mut Vec<Label>,
    witness_depth: usize,
) -> Result<(Witness, u64), TreeHashError>
where
    I: Iterator<Item = (&'a Label, &'a LabeledTree<Vec<u8>>)>,
{
    if witness_depth > MAX_HASH_TREE_DEPTH {
        return Err(TreeHashError::TooDeepRecursion {
            offending_path: curr_path.clone(),
        });
    }
    match witness {
        Witness::Fork {
            left_tree,
            right_tree,
        } => {
            // Disallow a `Fork` with two `Pruned` children. Even if otherwise valid,
            // we should only accept minimal witnesses.
            if let (Witness::Pruned { .. }, Witness::Pruned { .. }) =
                (left_tree.as_ref(), right_tree.as_ref())
            {
                return Err(TreeHashError::NonMinimalWitness {
                    offending_path: curr_path.clone(),
                });
            }

            let (left, count_left) =
                prune_witness_subtree(left_tree, children, curr_path, witness_depth + 1)?;
            let (right, count_right) =
                prune_witness_subtree(right_tree, children, curr_path, witness_depth + 1)?;

            match (&left, &right) {
                // Both children got pruned, replace by a `Pruned` node.
                (
                    Witness::Pruned {
                        digest: left_digest,
                    },
                    Witness::Pruned {
                        digest: right_digest,
                    },
                ) => Ok((
                    Witness::Pruned {
                        digest: compute_fork_digest(left_digest, right_digest),
                    },
                    count_left + count_right,
                )),

                // Still have some (possibly modified) non-pruned nodes, create a `Fork`.
                _ => Ok((
                    Witness::Fork {
                        left_tree: Box::new(left),
                        right_tree: Box::new(right),
                    },
                    count_left + count_right,
                )),
            }
        }

        Witness::Node { label, sub_witness } => {
            match children.peek() {
                // Labeled branch that requires some pruning.
                Some(&(tree_label, child)) if tree_label == label => {
                    children.next();

                    curr_path.push(label.to_owned());
                    let (res, count) =
                        prune_witness_impl(sub_witness, child, curr_path, witness_depth + 1)?;
                    curr_path.pop();

                    if let Witness::Pruned { digest } = res {
                        // Child was pruned, prune the `Node`.
                        Ok((
                            Witness::Pruned {
                                digest: compute_node_digest(label, &digest),
                            },
                            count,
                        ))
                    } else {
                        // Return `Node` with (possibly) modified child.
                        Ok((
                            Witness::Node {
                                label: label.to_owned(),
                                sub_witness: Box::new(res),
                            },
                            count,
                        ))
                    }
                }

                // Labeled branch to be kept.
                _ => Ok((witness.to_owned(), 0)),
            }
        }

        // Already pruned `Node` or `Fork`, all done.
        Witness::Pruned { .. } => Ok((witness.to_owned(), 0)),

        Witness::Known() => err_inconsistent_partial_tree(curr_path),
    }
}

/// Recursive implementation of `prune_witness()`.
///
/// Returns a tuple containing the pruned witness and the count of all leaves
/// and empty subtrees that were "plugged into" the witness during pruning.
fn prune_witness_impl(
    witness: &Witness,
    partial_tree: &LabeledTree<Vec<u8>>,
    curr_path: &mut Vec<Label>,
    witness_depth: usize,
) -> Result<(Witness, u64), TreeHashError> {
    if witness_depth > MAX_HASH_TREE_DEPTH {
        return Err(TreeHashError::TooDeepRecursion {
            offending_path: curr_path.clone(),
        });
    }
    match partial_tree {
        LabeledTree::SubTree(children) if children.is_empty() => {
            match witness {
                // Empty `SubTree`, prune it.
                Witness::Known() => Ok((
                    Witness::Pruned {
                        digest: empty_subtree_hash(),
                    },
                    1, // we plug in the hash for an empty subtree here, so we count it as plugged in "leaf"
                )),

                // Attempting to prune `SubTree` with children without providing them.
                _ => err_inconsistent_partial_tree(curr_path),
            }
        }

        LabeledTree::SubTree(children) if !children.is_empty() => {
            match witness {
                // Top-level `Fork` or `Node`, corresponding to a `LabeledTree::SubTree`.
                Witness::Fork { .. } | Witness::Node { .. } => {
                    let mut children = children.iter().peekable();

                    let res =
                        prune_witness_subtree(witness, &mut children, curr_path, witness_depth)?;
                    if let Some((label, _)) = children.next() {
                        curr_path.push(label.to_owned());
                        return err_inconsistent_partial_tree(curr_path);
                    }
                    Ok(res)
                }

                // Attempting to prune children of already pruned or empty `SubTree`.
                Witness::Pruned { .. } | Witness::Known() => {
                    err_inconsistent_partial_tree(curr_path)
                }
            }
        }

        LabeledTree::SubTree(_) => unreachable!(),

        LabeledTree::Leaf(v) => {
            match witness {
                // LabeledTree <-> Witness mismatch.
                Witness::Fork { .. } | Witness::Node { .. } | Witness::Pruned { .. } => {
                    err_inconsistent_partial_tree(curr_path)
                }

                // Provided 'Leaf`, prune it.
                Witness::Known() => Ok((
                    Witness::Pruned {
                        digest: compute_leaf_digest(v),
                    },
                    1,
                )),
            }
        }
    }
}

/// Counts the number of leaves and empty subtree nodes in a labeled tree.
fn count_leaves_and_empty_subtrees<T>(tree: &LabeledTree<T>) -> u64 {
    match tree {
        LabeledTree::SubTree(children) if children.is_empty() => {
            // Pruning treats empty subtree hashes in the same way as leaves
            // in that their hash is computed and plugged into the witness if
            // they are present in the labeled tree, and left in place otherwise.
            // Hence we also count them here.
            1
        }
        LabeledTree::SubTree(children) if !children.is_empty() => children
            .iter()
            .map(|(_, tree)| count_leaves_and_empty_subtrees(tree))
            .sum(),
        LabeledTree::SubTree(_) => unreachable!(),
        LabeledTree::Leaf(_) => 1,
    }
}

/// Prunes from `witness` the nodes in `partial_tree`. If `partial_tree` is
/// inconsistent with `witness`, e.g. includes nodes not covered by `witness`;
/// or attempts to prune a non-empty `SubTree` by providing an empty one; an
/// error is returned.
///
/// This is useful e.g. for selecting the prefix of a certified stream slice for
/// inclusion into a block; or discarding it when already included in an earlier
/// block.
///
/// Does not panic.
pub fn prune_witness(
    witness: &Witness,
    partial_tree: &LabeledTree<Vec<u8>>,
) -> Result<Witness, TreeHashError> {
    let mut curr_path = Vec::new();
    let (pruned, plugged_in_count) = prune_witness_impl(witness, partial_tree, &mut curr_path, 1)?;

    if plugged_in_count != count_leaves_and_empty_subtrees(partial_tree) {
        debug_assert!(
            false,
            "Prune witness leaf count mismatch. Labeled tree {:?}, Witness {:?}",
            partial_tree, witness
        );
        return Err(TreeHashError::InconsistentPartialTree {
            offending_path: vec![],
        });
    }

    Ok(pruned)
}

pub(crate) fn compute_leaf_digest(contents: &[u8]) -> Digest {
    let mut hasher = new_leaf_hasher();
    hasher.update(contents);
    hasher.finalize()
}

pub(crate) fn compute_node_digest(label: &Label, subtree_digest: &Digest) -> Digest {
    let mut hasher = new_node_hasher();
    hasher.update(label.as_bytes());
    hasher.update(&subtree_digest.0);
    hasher.finalize()
}

pub(crate) fn compute_fork_digest(left_digest: &Digest, right_digest: &Digest) -> Digest {
    let mut hasher = new_fork_hasher();
    hasher.update(&left_digest.0);
    hasher.update(&right_digest.0);
    hasher.finalize()
}

/// Recursively searches for the first `Witness::Known` node and returns its
/// path.
fn path_to_first_known(witness: &Witness) -> Option<Vec<Label>> {
    match witness {
        Witness::Known() => Some(vec![]),
        Witness::Fork {
            left_tree,
            right_tree,
        } => path_to_first_known(left_tree).or_else(|| path_to_first_known(right_tree)),
        Witness::Node { label, sub_witness } => path_to_first_known(sub_witness).map(|mut path| {
            path.insert(0, label.to_owned());
            path
        }),
        _ => None,
    }
}

/// Computes and returns a digest for (partial) data given in
/// `partial_tree`, using information from `witness` to compensate for
/// the missing data in the tree. If `partial_tree` is inconsistent with
/// 'witness', i.e. if `witness` does not contain enough information for
/// digest-computation, an error is returned.
///
/// Does not `panic!`.
pub fn recompute_digest(
    partial_tree: &LabeledTree<Vec<u8>>,
    witness: &Witness,
) -> Result<Digest, TreeHashError> {
    let pruned = prune_witness(witness, partial_tree)?;
    match pruned {
        Witness::Pruned { digest } => Ok(digest),
        Witness::Fork { .. } | Witness::Node { .. } | Witness::Known() => {
            Err(TreeHashError::InconsistentPartialTree {
                offending_path: path_to_first_known(&pruned).unwrap_or_default(),
            })
        }
    }
}

/// Returns the direct sub-witness with the given label, if present.
///
/// This is the equivalent of looking up the label in the `LabeledTree::SubTree`
/// that this `Witness` was created from, pruned children excluded.
pub fn sub_witness<'a>(witness: &'a Witness, lbl: &Label) -> Option<&'a Witness> {
    match witness {
        Witness::Fork {
            left_tree,
            right_tree,
        } => sub_witness(left_tree, lbl).or_else(|| sub_witness(right_tree, lbl)),

        Witness::Node { label, sub_witness } if label == lbl => Some(sub_witness),

        _ => None,
    }
}

/// Returns the leftmost direct labeled sub-witness, if any, and its label.
///
/// This is the equivalent of returning the first not-pruned child of the
/// `LabeledTree::SubTree` that this `Witness` was created from.
pub fn first_sub_witness(witness: &Witness) -> Option<(&Label, &Witness)> {
    match witness {
        Witness::Fork {
            left_tree,
            right_tree,
        } => first_sub_witness(left_tree).or_else(|| first_sub_witness(right_tree)),

        Witness::Node { label, sub_witness } => Some((label, sub_witness)),

        _ => None,
    }
}

/// An implementation of the [`WitnessGenerator`]-trait.
#[derive(PartialEq, Eq, Clone)]
pub struct WitnessGeneratorImpl {
    orig_tree: LabeledTree<Digest>,
    hash_tree: HashTree,
}

/// Error that a `HashTree` does not represent a [`LabeledTree::SubTree`]
pub struct HashTreeIsNotALabeledTreeSubTree {}

/// Returns the smallest label in `hash_tree` assuming that it represents a
/// [`LabeledTree::SubTree`], returns `None` if the tree is inconsistent.
///
/// # Errors
/// * [`HashTreeIsNotALabeledTreeSubTree`] if `hash_tree` does not represent a
///   [`LabeledTree::SubTree`]
fn smallest_label_in_subtree(
    hash_tree: &HashTree,
) -> Result<Label, HashTreeIsNotALabeledTreeSubTree> {
    let mut smallest = hash_tree;
    while let HashTree::Fork { left_tree, .. } = smallest {
        smallest = left_tree.as_ref()
    }
    match smallest {
        HashTree::Node { label, .. } => Ok(label.to_owned()),
        _ => Err(HashTreeIsNotALabeledTreeSubTree {}),
    }
}

/// Returns the lagest label in `hash_tree` assuming that it represents a
/// [`LabeledTree::SubTree`].
///
/// # Errors
/// * [`HashTreeIsNotALabeledTreeSubTree`] if `hash_tree` does not represent a
///   [`LabeledTree::SubTree`]
fn largest_label_in_subtree(
    hash_tree: &HashTree,
) -> Result<Label, HashTreeIsNotALabeledTreeSubTree> {
    let mut largest = hash_tree;
    while let HashTree::Fork { right_tree, .. } = largest {
        largest = right_tree.as_ref()
    }
    match largest {
        HashTree::Node { label, .. } => Ok(label.to_owned()),
        // Inconsistent HashTree, expected HashTree::Node
        _ => Err(HashTreeIsNotALabeledTreeSubTree {}),
    }
}

// Returns true iff any of the labels in `labels` is within the range defined by
// the given `hash_tree` interpreted as a [`LabeledTree::SubTree`], i.e., a set
// of `Fork`s followed by `Node`s.
///
/// # Errors
/// * [`HashTreeIsNotALabeledTreeSubTree`] if `hash_tree` does not represent a
///   [`LabeledTree::SubTree`]
fn any_is_in_subtree_range(
    hash_tree: &HashTree,
    labels: &[Label],
) -> Result<bool, HashTreeIsNotALabeledTreeSubTree> {
    let smallest = smallest_label_in_subtree(hash_tree)?;
    let largest = largest_label_in_subtree(hash_tree)?;
    Ok(labels
        .iter()
        .any(|label| (smallest <= *label) && (*label <= largest)))
}

/// Checks whether any of `needed_labels` is missing in the given `map` of
/// available labels.
/// Returns the first missing label, if any is indeed missing or `None`
/// otherwise.
fn first_missing_label(
    needed_labels: &[Label],
    available_labels: &FlatMap<Label, LabeledTree<Digest>>,
) -> Option<Label> {
    for label in needed_labels {
        if available_labels.get(label).is_none() {
            return Some(label.to_owned());
        }
    }
    None
}

/// WitnessBuilder abstracts away a specific representation of the witness
/// structure and allows us to use the same algorithm to construct both
/// witnesses that don't contain the data (e.g., for XNet) and the ones that do
/// contain it (e.g., for certified reads).
pub trait WitnessBuilder {
    /// Type of the trees that this builder produces.
    type Tree;

    /// Creates a witness for an empty tree.
    fn make_empty() -> Self::Tree;

    /// Constructs a witness for a labeled tree node pointing to the specified
    /// subtree.
    fn make_node(label: Label, subtree: Self::Tree) -> Self::Tree;

    /// Constructs a witness for a fork given the witnesses for left and right
    /// subtrees.
    fn make_fork(lhs: Self::Tree, rhs: Self::Tree) -> Self::Tree;

    /// Constructs a witness for a leaf containing the specified data.
    fn make_leaf(data: &[u8]) -> Self::Tree;

    /// Constructs a witness that only reveals a subtree hash.
    fn make_pruned(digest: Digest) -> Self::Tree;

    /// Merges two witnesses for the same tree.
    fn merge_trees(lhs: Self::Tree, lhs: Self::Tree) -> Self::Tree;
}

impl WitnessBuilder for Witness {
    type Tree = Self;

    fn make_empty() -> Self {
        Self::Known()
    }

    fn make_node(label: Label, subtree: Self) -> Self {
        Self::Node {
            label,
            sub_witness: Box::new(subtree),
        }
    }

    fn make_fork(lhs: Self, rhs: Self) -> Self {
        Self::Fork {
            left_tree: Box::new(lhs),
            right_tree: Box::new(rhs),
        }
    }

    fn make_leaf(_data: &[u8]) -> Self {
        Self::Known()
    }

    fn make_pruned(digest: Digest) -> Self {
        Self::Pruned { digest }
    }

    fn merge_trees(lhs: Self, rhs: Self) -> Self {
        Self::merge(lhs, rhs)
    }
}

impl WitnessBuilder for MixedHashTree {
    type Tree = Self;

    fn make_empty() -> Self {
        Self::Empty
    }

    fn make_node(label: Label, subtree: Self) -> Self {
        Self::Labeled(label, Box::new(subtree))
    }

    fn make_fork(lhs: Self, rhs: Self) -> Self {
        Self::Fork(Box::new((lhs, rhs)))
    }

    fn make_leaf(data: &[u8]) -> Self {
        Self::Leaf(data.to_vec())
    }

    fn make_pruned(digest: Digest) -> Self {
        Self::Pruned(digest)
    }

    fn merge_trees(lhs: Self, rhs: Self) -> Self {
        Self::merge(lhs, rhs)
    }
}

/// Errors returned by the [`find_subtree_node`] function
pub enum FindSubtreeNodeError {
    HashTreeIsNotALabeledTreeSubTree,
    LabelNotFound,
}

/// Finds in the given `hash_tree` (interpreted as a [`LabeledTree::Subtree`],
/// i.e., a set of `Fork`s followed by `Node`s) a HashTree::Node that contains
/// the given `target_label`, and returns the corresponding [`HashTree`] of that
/// node.
///
/// # Errors
/// * [`FindSubtreeNodeError::HashTreeIsNotALabeledTreeSubTree`] if `hash_tree`
///   does not represent a [`LabeledTree::HashTreeIsNotALabeledTreeSubTree`]
/// * [`FindSubtreeNodeError::LabelNotFound`] if the label was not found
//
// TODO(CRP-426) currently the running time is O((log n)^2); make it O(log(n))
//     via binary search on the list of all labels in `hash_tree`.
fn find_subtree_node<'a>(
    target_label: &Label,
    hash_tree: &'a HashTree,
) -> Result<&'a HashTree, FindSubtreeNodeError> {
    match hash_tree {
        HashTree::Node {
            label, hash_tree, ..
        } => {
            if target_label == label {
                Ok(hash_tree.as_ref())
            } else {
                // Pre-condition failed, hash tree does not contain the label
                Err(FindSubtreeNodeError::LabelNotFound)
            }
        }
        HashTree::Fork {
            left_tree,
            right_tree,
            ..
        } => {
            let largest_left = largest_label_in_subtree(left_tree)
                .map_err(|_e| FindSubtreeNodeError::HashTreeIsNotALabeledTreeSubTree)?;
            if *target_label <= largest_left {
                find_subtree_node(target_label, left_tree)
            } else {
                find_subtree_node(target_label, right_tree)
            }
        }
        HashTree::Leaf { .. } => {
            // Inconsistent state, unexpectedly reached leaf
            Err(FindSubtreeNodeError::HashTreeIsNotALabeledTreeSubTree)
        }
    }
}

/// Generates a witness for a HashTree that represents a single
/// LabeledTree::SubTree node, and uses the given sub_witnesses
/// for the children of the node (if provided).
fn witness_for_subtree<Builder: WitnessBuilder>(
    hash_tree: &HashTree,
    sub_witnesses: &mut FlatMap<Label, Builder::Tree>,
) -> Result<Builder::Tree, HashTreeIsNotALabeledTreeSubTree> {
    if any_is_in_subtree_range(hash_tree, sub_witnesses.keys())? {
        match hash_tree {
            HashTree::Fork {
                // inside HashTree, recurse to subtrees
                left_tree,
                right_tree,
                ..
            } => {
                let left_witness = witness_for_subtree::<Builder>(left_tree, sub_witnesses)?;
                let right_witness = witness_for_subtree::<Builder>(right_tree, sub_witnesses)?;
                Ok(Builder::make_fork(left_witness, right_witness))
            }
            HashTree::Node {
                // bottom of the HashTree, stop recursion
                digest,
                label,
                ..
            } => {
                if let Some(sub_witness) = sub_witnesses.remove(label) {
                    Ok(Builder::make_node(label.to_owned(), sub_witness))
                } else {
                    Ok(Builder::make_pruned(digest.to_owned()))
                }
            }
            HashTree::Leaf { .. } => unreachable!(),
        }
    } else {
        Ok(Builder::make_pruned(hash_tree.digest().to_owned()))
    }
}

impl WitnessGeneratorImpl {
    fn witness_impl<Builder: WitnessBuilder, T: std::convert::AsRef<[u8]> + Debug>(
        partial_tree: &LabeledTree<T>,
        orig_tree: &LabeledTree<Digest>,
        hash_tree: &HashTree,
        curr_path: &mut Vec<Label>,
    ) -> Result<Builder::Tree, TreeHashError> {
        match partial_tree {
            LabeledTree::SubTree(children) if children.is_empty() => {
                // An empty SubTree-node in partial tree is allowed only if
                // the corresponding node in the original tree is also empty.
                match orig_tree {
                    LabeledTree::SubTree(orig_children) => {
                        if orig_children.is_empty() {
                            Ok(Builder::make_empty())
                        } else {
                            err_inconsistent_partial_tree(curr_path)
                        }
                    }
                    LabeledTree::Leaf(_) => err_inconsistent_partial_tree(curr_path),
                }
            }
            LabeledTree::SubTree(children) if !children.is_empty() => {
                if let LabeledTree::SubTree(orig_children) = orig_tree {
                    // check the consistency of the root of `partial_tree` and `orig_tree`
                    {
                        let needed_labels: Vec<Label> = children.keys().to_vec();
                        if let Some(missing_label) =
                            first_missing_label(&needed_labels, orig_children)
                        {
                            // a label from `partial_tree` is missing in the `orig_tree`
                            curr_path.push(missing_label);
                            return err_inconsistent_partial_tree(curr_path);
                        }
                    }
                    // Recursively generate sub-witnesses for each child
                    // of the current LabeledTree::SubTree.
                    // TODO(CRP-426) remove the multiple traversal of the subtree-HashTree
                    //   (in find_subtree_node() and in witness_for_subtree()).
                    let mut sub_witnesses = FlatMap::new();
                    for label in children.keys() {
                        curr_path.push(label.to_owned());
                        let target_node = find_subtree_node(label, hash_tree)
                            .or_else(|_e| err_inconsistent_partial_tree(curr_path))?;
                        let sub_witness = Self::witness_impl::<Builder, _>(
                            children.get(label).expect("Should never panic because label is in the keys"),
                            orig_children.get(label).expect("Should never panic because an error is returned in case a label is missing"),
                            target_node,
                            curr_path,
                        )?;
                        if let Err(_err) = sub_witnesses.try_append(label.to_owned(), sub_witness) {
                            // Tree is not sorted
                            return err_inconsistent_partial_tree(curr_path);
                        };
                        curr_path.pop();
                    }

                    // `children` is a subset of `orig_children`
                    witness_for_subtree::<Builder>(hash_tree, &mut sub_witnesses)
                        .or_else(|_e| err_inconsistent_partial_tree(curr_path))
                } else {
                    err_inconsistent_partial_tree(curr_path)
                }
            }
            LabeledTree::SubTree(_) => unreachable!(),
            LabeledTree::Leaf(data) => match orig_tree {
                LabeledTree::Leaf(_) => Ok(Builder::make_leaf(data.as_ref())),
                LabeledTree::SubTree(_) => {
                    // inconsistent structures, not a leaf in the original labeled tree
                    err_inconsistent_partial_tree(curr_path)
                }
            },
        }
    }
}

impl fmt::Debug for WitnessGeneratorImpl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "***** labeled tree:")?;
        write_labeled_tree(&self.orig_tree, 0, f)?;
        writeln!(f, "***** hash tree:")?;
        write_hash_tree(&self.hash_tree, 0, f)
    }
}

fn path_as_string(path: &[Label]) -> String {
    let mut str = String::new();
    str.push('[');
    for label in path {
        str.push_str(&label.to_string())
    }
    str.push(']');
    str
}

fn labeled_tree_from_hashtree(
    hash_tree: &HashTree,
    curr_path: &mut Vec<Label>,
) -> Result<LabeledTree<Digest>, TreeHashError> {
    /// Traverses the first level of labeled Nodes reacheable from the specified
    /// tree root, recursively converts those into labeled trees and
    /// collects them into a map indexed by the corresponding label.
    fn collect_children(
        tree: &HashTree,
        path: &mut Vec<Label>,
        map: &mut FlatMap<Label, LabeledTree<Digest>>,
    ) -> Result<(), TreeHashError> {
        match tree {
            HashTree::Leaf { .. } => Err(TreeHashError::InvalidArgument {
                info: format!(
                    "subtree leaf without a node at path {}",
                    path_as_string(path)
                ),
            }),

            HashTree::Node {
                label, hash_tree, ..
            } => {
                path.push(label.clone());
                let child = labeled_tree_from_hashtree(hash_tree, path)?;
                path.pop();
                map.try_append(label.clone(), child)
                    .map_err(|_| TreeHashError::InvalidArgument {
                        info: format!(
                            "non-sorted labels in a subtree at path {}",
                            path_as_string(path)
                        ),
                    })
            }

            HashTree::Fork {
                ref left_tree,
                ref right_tree,
                ..
            } => {
                collect_children(left_tree, path, map)?;
                collect_children(right_tree, path, map)
            }
        }
    }

    match hash_tree {
        HashTree::Leaf { digest } => {
            if *digest == empty_subtree_hash() {
                Ok(LabeledTree::SubTree(FlatMap::new()))
            } else {
                Ok(LabeledTree::Leaf(digest.to_owned()))
            }
        }
        HashTree::Node {
            label,
            hash_tree: hash_subtree,
            ..
        } => {
            curr_path.push(label.to_owned());
            let labeled_subtree = labeled_tree_from_hashtree(hash_subtree, curr_path)?;
            curr_path.pop();
            let map = flatmap!(label.to_owned() => labeled_subtree);
            Ok(LabeledTree::SubTree(map))
        }

        HashTree::Fork {
            left_tree,
            right_tree,
            ..
        } => {
            let mut children = FlatMap::new();
            collect_children(left_tree, curr_path, &mut children)?;
            collect_children(right_tree, curr_path, &mut children)?;

            Ok(LabeledTree::SubTree(children))
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct TooLongPathError;

/// Converts a list of `Path`s into a sparse `LabeledTree`.
///
/// The produced `LabeledTree` is considered "sparse" because, if one path is a
/// prefix of another, then only the prefix is returned.
///
/// Example:
///
/// ```text
///     paths = [
///         ["a", "b"],
///         ["a", "c"],
///     ];
///
///               |
///               a
///              /  \
///             b    c
/// ```
///
/// Example (two paths, one is a prefix of the other):
///
/// ```text
///     paths = [
///         ["a", "b"],
///         ["a", "b", "c"],
///     ]
///
///               |
///               a
///              /
///             b
/// ```
///
/// # Errors
/// If the length of any path in `paths` exceeds `MAX_HASH_TREE_DEPTH` - 1
/// (currently 127).
pub fn sparse_labeled_tree_from_paths(paths: &[Path]) -> Result<LabeledTree<()>, TooLongPathError> {
    for path in paths {
        if path.len() >= MAX_HASH_TREE_DEPTH {
            return Err(TooLongPathError {});
        }
    }
    // Sort all the paths. That way, if one path is a prefix of another, the prefix
    // is always first.
    let sorted_paths = {
        let mut paths_ref_vec: Vec<&Path> = paths.iter().collect();
        paths_ref_vec.sort_unstable();
        paths_ref_vec
    };

    let mut root = LabeledTree::SubTree(FlatMap::new());

    for path in sorted_paths {
        let mut tree = &mut root;
        for (i, label) in path.iter().enumerate() {
            match tree {
                LabeledTree::Leaf(()) => {
                    // We reached a leaf. That means there was a shared prefix in the paths.
                    // Stop now.
                    break;
                }
                LabeledTree::SubTree(map) => {
                    if !map.contains_key(label) {
                        let tree_to_append = if i < path.len() - 1 {
                            // Add a subtree for the label on the path.
                            LabeledTree::SubTree(FlatMap::new())
                        } else {
                            // The last label on the path is always a leaf.
                            LabeledTree::Leaf(())
                        };
                        map.try_append(label.clone(), tree_to_append)
                            .expect("Should never fail because labels are guaranteed to be sorted");
                    }
                    // Descend into the tree.
                    // Should never fail because it is guaranteed that the child with
                    // `label` was added.
                    tree = match map.get_mut(label) {
                        Some(subtree) => subtree,
                        None => unreachable!(),
                    }
                }
            }
        }
    }

    if root == LabeledTree::SubTree(FlatMap::new()) {
        root = LabeledTree::Leaf(())
    }

    Ok(root)
}

impl TryFrom<HashTree> for WitnessGeneratorImpl {
    type Error = TreeHashError;

    /// Creates a `WitnessGenerator` from a `HashTree`, that must have
    /// a structure matching a valid `LabeledTree`.
    /// Returns an error if the given hash tree doesn't match a valid
    /// `LabeledTree`, e.g. if the hash tree has only some `HashTree::Fork`-
    /// and `HashTree::Leaf`-elements, but none `HashTree::Node`-elements.
    fn try_from(hash_tree: HashTree) -> Result<Self, Self::Error> {
        let mut curr_path = Vec::new();
        let labeled_tree = labeled_tree_from_hashtree(&hash_tree, &mut curr_path)?;
        Ok(WitnessGeneratorImpl {
            orig_tree: labeled_tree,
            hash_tree,
        })
    }
}

impl WitnessGenerator for WitnessGeneratorImpl {
    fn hash_tree(&self) -> &HashTree {
        &self.hash_tree
    }

    fn witness(&self, partial_tree: &LabeledTree<Vec<u8>>) -> Result<Witness, TreeHashError> {
        let mut path = Vec::new();
        Self::witness_impl::<Witness, _>(partial_tree, &self.orig_tree, &self.hash_tree, &mut path)
    }

    fn mixed_hash_tree(
        &self,
        partial_tree: &LabeledTree<Vec<u8>>,
    ) -> Result<MixedHashTree, TreeHashError> {
        let mut path = Vec::new();
        Self::witness_impl::<MixedHashTree, _>(
            partial_tree,
            &self.orig_tree,
            &self.hash_tree,
            &mut path,
        )
    }
}

/// Internal state of HashTreeBuilder.
/// ActiveNode corresponds to a single node that is under construction, and an
/// intermediate state of the builder consists of a vector of ActiveNodes, that
/// correspond to the path from the root to the current node under construction.
/// Each variant of ActiveNode holds a label, which corresponds to the edge from
/// the parent of the node to this ActiveNode.  This label will be then used
/// in the constructed LabeledTree.
enum ActiveNode {
    Leaf {
        hasher: Hasher,
        label: Label,
    },
    SubTree {
        children: Vec<(Label, LabeledTree<Digest>)>,
        label: Label,
        hash_nodes: Vec<(Label, HashTree)>,
    },
    Undefined {
        label: Label,
    },
}

/// An implementation of the [`HashTreeBuilder`]-trait.
pub struct HashTreeBuilderImpl {
    labeled_tree: Option<LabeledTree<Digest>>,
    hash_tree: Option<HashTree>,
    curr_path: Vec<ActiveNode>,
}

impl Default for HashTreeBuilderImpl {
    fn default() -> Self {
        Self {
            labeled_tree: None,
            hash_tree: None,
            curr_path: vec![ActiveNode::Undefined {
                label: Label::from("ROOT"),
            }],
        }
    }
}

impl HashTreeBuilderImpl {
    pub fn new() -> Self {
        Self::default()
    }

    // /////////////////////////////////////////////////////////
    // API for obtaining the constructed structures.

    /// Like `into_hash_tree`, but returns a copy of the hash tree.
    /// Does not `panic!`.
    #[allow(dead_code)]
    pub fn as_hash_tree(&self) -> Option<HashTree> {
        self.hash_tree
            .as_ref()
            .map(|hash_tree| (*hash_tree).to_owned())
    }

    /// Returns the HashTree corresponding to the traversed tree if the
    /// construction is complete, and None otherwise.
    pub fn into_hash_tree(self) -> Option<HashTree> {
        self.hash_tree
    }

    /// Returns the constructed LabeledTree if the construction
    /// is complete, and `None` otherwise.
    /// Does not `panic!`.
    #[allow(dead_code)]
    pub fn as_labeled_tree(&self) -> Option<LabeledTree<Digest>> {
        self.labeled_tree
            .as_ref()
            .map(|labeled_tree| labeled_tree.to_owned())
    }
}

impl fmt::Debug for HashTreeBuilderImpl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "***** aux_state: ")?;
        for (pos, node) in self.curr_path.iter().enumerate() {
            match node {
                ActiveNode::Undefined { label } => {
                    write!(f, "([{}]: '{}') ", pos, label)?;
                }
                ActiveNode::Leaf { label, .. } => {
                    write!(f, "([{}]: '{}' '[hasher]') ", pos, label)?;
                }
                ActiveNode::SubTree {
                    children, label, ..
                } => {
                    write!(f, "[{}]: {} ", pos, label)?;
                    for (label, child) in children.iter() {
                        write!(f, " child({}, {:?}) ", label, child)?;
                    }
                }
            }
        }
        writeln!(f)?;
        if let Some(tree) = self.labeled_tree.as_ref() {
            writeln!(f, "***** labeled tree:")?;
            write_labeled_tree(tree, 0, f)?;
        }
        if let Some(tree) = self.hash_tree.as_ref() {
            writeln!(f, "***** hash tree:")?;
            write_hash_tree(tree, 0, f)?;
        }
        writeln!(f)
    }
}

impl HashTreeBuilder for HashTreeBuilderImpl {
    type WitnessGenerator = WitnessGeneratorImpl;

    fn start_leaf(&mut self) {
        let head = self.curr_path.pop().expect("Construction completed.");
        match head {
            ActiveNode::Undefined { label } => {
                self.curr_path.push(ActiveNode::Leaf {
                    hasher: new_leaf_hasher(),
                    label,
                });
            }
            _ => panic!("Invalid operation, expected Undefined-node."),
        }
    }

    fn write_leaf<T: AsRef<[u8]>>(&mut self, bytes: T) {
        let bytes = bytes.as_ref();
        let head = self.curr_path.pop().expect("Construction completed.");
        match head {
            ActiveNode::Leaf { mut hasher, label } => {
                hasher.update(bytes);
                self.curr_path.push(ActiveNode::Leaf { hasher, label })
            }
            _ => panic!("Invalid operation, expected Leaf-node."),
        }
    }

    fn finish_leaf(&mut self) {
        let head = self.curr_path.pop().expect("Construction completed.");
        match head {
            ActiveNode::Leaf {
                hasher,
                label: child_label,
            } => {
                let digest = hasher.finalize();
                if self.curr_path.is_empty() {
                    // At root.
                    self.labeled_tree = Some(LabeledTree::Leaf(digest.to_owned()));
                    self.hash_tree = Some(HashTree::Leaf { digest });
                } else {
                    // In a subtree.
                    match self.curr_path.pop().expect("Path was empty") {
                        ActiveNode::SubTree {
                            mut children,
                            label,
                            mut hash_nodes,
                        } => {
                            children.push((
                                child_label.to_owned(),
                                LabeledTree::Leaf(digest.to_owned()),
                            ));
                            let hash_node = into_hash_node(&child_label, HashTree::Leaf { digest });
                            hash_nodes.push((child_label, hash_node));
                            self.curr_path.push(ActiveNode::SubTree {
                                children,
                                label,
                                hash_nodes,
                            });
                        }
                        _ => panic!("Invalid state, expected SubTree-node."),
                    }
                }
            }
            _ => panic!("Invalid operation, expected Leaf-node."),
        }
    }

    fn start_subtree(&mut self) {
        let head = self.curr_path.pop().expect("Construction completed.");
        match head {
            ActiveNode::Undefined { label } => {
                self.curr_path.push(ActiveNode::SubTree {
                    children: Default::default(),
                    label,
                    hash_nodes: Default::default(),
                });
            }
            _ => panic!("Invalid operation, expected Undefined-node."),
        }
    }

    fn new_edge<T: Into<Label>>(&mut self, edge_label: T) {
        let edge_label = edge_label.into();
        let head = self.curr_path.pop().expect("Construction completed.");
        match head {
            ActiveNode::SubTree {
                children,
                label,
                hash_nodes,
            } => {
                self.curr_path.push(ActiveNode::SubTree {
                    children,
                    label,
                    hash_nodes,
                });
                self.curr_path
                    .push(ActiveNode::Undefined { label: edge_label });
            }
            _ => panic!("Invalid operation, expected SubTree-node."),
        }
    }

    fn finish_subtree(&mut self) {
        let head = self.curr_path.pop().expect("Construction completed.");
        match head {
            ActiveNode::SubTree {
                children: finished_children,
                label: finished_label,
                hash_nodes: finished_hash_nodes,
            } => {
                let finished_children_map = FlatMap::from_key_values(finished_children);
                let finished_hash_nodes_map = FlatMap::from_key_values(finished_hash_nodes);

                let hash_trees: VecDeque<_> = finished_hash_nodes_map
                    .into_iter()
                    .map(|(_k, v)| v)
                    .collect();

                let hash_tree = into_hash_tree(hash_trees);

                if self.curr_path.is_empty() {
                    // At root.
                    self.labeled_tree = Some(LabeledTree::SubTree(finished_children_map));
                    self.hash_tree = Some(hash_tree);
                } else {
                    // In a subtree.
                    match self.curr_path.pop().expect("Path was empty") {
                        ActiveNode::SubTree {
                            mut children,
                            label,
                            mut hash_nodes,
                        } => {
                            children.push((
                                finished_label.to_owned(),
                                LabeledTree::SubTree(finished_children_map),
                            ));
                            let hash_node = into_hash_node(&finished_label, hash_tree);
                            hash_nodes.push((finished_label, hash_node));

                            self.curr_path.push(ActiveNode::SubTree {
                                children,
                                label,
                                hash_nodes,
                            });
                        }
                        _ => panic!("Invalid state, expected SubTree-node."),
                    }
                }
            }
            _ => panic!("Invalid operation, expected SubTree-node."),
        }
    }

    fn witness_generator(&self) -> Option<Self::WitnessGenerator> {
        match (self.as_labeled_tree(), self.as_hash_tree()) {
            (Some(orig_tree), Some(hash_tree)) => Some(WitnessGeneratorImpl {
                orig_tree,
                hash_tree,
            }),
            _ => None,
        }
    }
}

/// Returns an `Err(InconsistentPartialTree)` with the given `offending_path`.
fn err_inconsistent_partial_tree<T>(offending_path: &Vec<Label>) -> Result<T, TreeHashError> {
    Err(TreeHashError::InconsistentPartialTree {
        offending_path: offending_path.to_owned(),
    })
}
