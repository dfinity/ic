//! Builders for `Witness` and `HashTree` structures, and other
//! helpers for processing these structures.

use crate::hasher::Hasher;
use crate::{
    Digest, FlatMap, HashTree, HashTreeBuilder, Label, LabeledTree, MixedHashTree, Path,
    TreeHashError, Witness, WitnessGenerationError, WitnessGenerator, MAX_HASH_TREE_DEPTH,
};
use std::collections::VecDeque;
use std::fmt;
use std::fmt::Debug;
use std::iter::Peekable;

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
    witness_depth: u8,
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
    witness_depth: u8,
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

/// WitnessBuilder abstracts away a specific representation of the witness
/// structure and allows us to use the same algorithm to construct both
/// witnesses that don't contain the data (e.g., for XNet) and the ones that do
/// contain it (e.g., for certified reads).
pub trait WitnessBuilder {
    /// Creates a witness for an empty tree.
    fn make_empty() -> Self;

    /// Constructs a witness for a labeled tree node pointing to the specified
    /// subtree.
    fn make_node(label: Label, subtree: Self) -> Self;

    /// Constructs a witness for a fork given the witnesses for left and right
    /// subtrees.
    fn make_fork(lhs: Self, rhs: Self) -> Self;

    /// Constructs a witness for a leaf containing the specified data.
    fn make_leaf(data: &[u8]) -> Self;

    /// Constructs a witness that only reveals a subtree hash.
    fn make_pruned(digest: Digest) -> Self;

    /// Merges two witnesses produced from the same tree.
    ///
    /// Precondition:
    ///
    /// ```text
    ///     ∃ t : Ok(h) = recompute_digest(lhs, t)
    ///         ∧ Ok(h) = recompute_digest(rhs, t)
    /// ```
    ///
    /// Postcondition:
    ///
    /// ```text
    ///     ∀ t : Ok(h) = recompute_digest(lhs, t)
    ///         ∧ Ok(h) = recompute_digest(rhs, t)
    ///         ⇒ recompute_digest(merge(lhs, rhs)) == Ok(h)
    /// ```
    ///
    /// This function errors if the structure of the passed
    /// [`WitnessBuilder::Tree`]s is inconsistent and produces
    /// an invalid tree if the precondition is otherwise not met.
    ///
    /// # Errors
    ///
    /// * If the recursion depth is too large.
    /// * If `lhs` and `rhs` do not match.
    fn merge_trees(lhs: Self, rhs: Self) -> Result<Self, WitnessGenerationError<Self>>
    where
        Self: Sized;
}

impl WitnessBuilder for Witness {
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

    fn merge_trees(lhs: Self, rhs: Self) -> Result<Self, WitnessGenerationError<Self>> {
        fn merge_trees_impl(
            lhs: Witness,
            rhs: Witness,
            depth: u8,
        ) -> Result<Witness, WitnessGenerationError<Witness>> {
            use Witness::*;

            if depth > MAX_HASH_TREE_DEPTH {
                return Err(WitnessGenerationError::<Witness>::TooDeepRecursion(depth));
            }

            let result = match (lhs, rhs) {
                (Pruned { digest: l }, Pruned { digest: r }) if l != r => {
                    return Err(
                        WitnessGenerationError::<Witness>::MergingInconsistentWitnesses(
                            Pruned { digest: l },
                            Pruned { digest: r },
                        ),
                    )
                }
                (Pruned { .. }, r) => r,
                (l, Pruned { .. }) => l,
                (Known(), Known()) => Known(),
                (
                    Fork {
                        left_tree: ll,
                        right_tree: lr,
                    },
                    Fork {
                        left_tree: rl,
                        right_tree: rr,
                    },
                ) => Fork {
                    left_tree: Box::new(merge_trees_impl(*ll, *rl, depth + 1)?),
                    right_tree: Box::new(merge_trees_impl(*lr, *rr, depth + 1)?),
                },
                (
                    Node {
                        label: ll,
                        sub_witness: lw,
                    },
                    Node {
                        label: rl,
                        sub_witness: rw,
                    },
                ) if ll == rl => Node {
                    label: ll,
                    sub_witness: Box::new(merge_trees_impl(*lw, *rw, depth + 1)?),
                },
                (l, r) => {
                    return Err(
                        WitnessGenerationError::<Witness>::MergingInconsistentWitnesses(l, r),
                    )
                }
            };
            Ok(result)
        }

        merge_trees_impl(lhs, rhs, 1)
    }
}

impl WitnessBuilder for MixedHashTree {
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

    fn merge_trees(lhs: Self, rhs: Self) -> Result<Self, WitnessGenerationError<Self>> {
        fn merge_trees_impl(
            lhs: MixedHashTree,
            rhs: MixedHashTree,
            depth: u8,
        ) -> Result<MixedHashTree, WitnessGenerationError<MixedHashTree>> {
            use MixedHashTree::*;

            if depth > MAX_HASH_TREE_DEPTH {
                return Err(WitnessGenerationError::<MixedHashTree>::TooDeepRecursion(
                    depth,
                ));
            }

            let result = match (lhs, rhs) {
                (Pruned(l), Pruned(r)) if l != r => {
                    return Err(
                        WitnessGenerationError::<MixedHashTree>::MergingInconsistentWitnesses(
                            Pruned(l),
                            Pruned(r),
                        ),
                    )
                }
                (Pruned(_), r) => r,
                (l, Pruned(_)) => l,
                (Empty, Empty) => Empty,
                (Fork(l), Fork(r)) => Fork(Box::new((
                    merge_trees_impl(l.0, r.0, depth + 1)?,
                    merge_trees_impl(l.1, r.1, depth + 1)?,
                ))),
                (Labeled(label, l), Labeled(rlabel, r)) if label == rlabel => {
                    Labeled(label, Box::new(merge_trees_impl(*l, *r, depth + 1)?))
                }
                (Leaf(l), Leaf(r)) if l == r => Leaf(l),
                (l, r) => {
                    return Err(
                        WitnessGenerationError::<MixedHashTree>::MergingInconsistentWitnesses(l, r),
                    )
                }
            };

            Ok(result)
        }
        merge_trees_impl(lhs, rhs, 1)
    }
}

impl WitnessGeneratorImpl {
    /// Creates a path from the root of the `hash_tree` - representing a subtree
    /// with `subtre_size` children - to the node at position `pos` pruning all
    /// children not relevant for the node at position `pos`, and appends
    /// `subwitness` at the end of the path.
    ///
    /// # Preconditions
    /// * It must apply that `pos < subtree_size`. Otherwise, `subwitness` is
    ///   plugged into the wrong position. (This is checked via a debug assertion.)
    /// * It must apply that `subtree_size` is the size of the `hash_tree`
    ///   interpreted as a subtree, i.e., the number of nodes in the subtree.
    ///   Otherwise, the `subwitness` is plugged into the wrong position.
    ///   (This is checked via a debug assertion.)
    ///
    /// # Panics
    /// * If `hash_tree` is not a well-formed subtree, e.g., if it contains forks
    ///   followed by leaves.
    /// * If `hash_tree` is empty.
    fn pruned_for_all_but_pos<Builder: WitnessBuilder>(
        hash_tree: &HashTree,
        subwitness: Builder,
        pos: usize,
        subtree_size: usize,
    ) -> Builder {
        /// Returns the number of leaves in the left subtree for the given tree
        /// size, where the left subtree is always a full tree. For example, for
        /// trees of sizes 5 to 8, the result is 4, for trees of sizes 9 to 16,
        /// the result is 8, etc.s
        #[inline]
        fn left_subtree_size(subtree_size: usize) -> usize {
            match subtree_size {
                0 => panic!("bug: the tree size must be non-zero"),
                1 => 1,
                s => s.next_power_of_two() / 2,
            }
        }

        // debug-check preconditions
        debug_assert!(
            pos < subtree_size,
            "pos={pos} >= subtree_size={subtree_size}"
        );
        debug_assert_eq!(
            {
                let mut v = vec![hash_tree];
                let mut size = 0;
                while let Some(t) = v.pop() {
                    match t {
                        HashTree::Node {
                            digest: _,
                            label: _,
                            hash_tree: _,
                        } => size += 1,
                        HashTree::Fork {
                            digest: _,
                            left_tree,
                            right_tree,
                        } => {
                            v.push(left_tree.as_ref());
                            v.push(right_tree.as_ref());
                        }
                        HashTree::Leaf { digest: _ } => {
                            panic!("bug: a leaf can only exist after a node")
                        }
                    }
                }
                size
            },
            subtree_size,
            "subtree_size is wrong for the given hash_tree"
        );

        match hash_tree {
            HashTree::Node {
                digest: _,
                label: _,
                hash_tree: _,
            } => {
                debug_assert_eq!(subtree_size, 1);
                subwitness
            }
            HashTree::Fork {
                digest: _,
                left_tree,
                right_tree,
            } => {
                // Compute the size of the left subtree and determine whether
                // the position falls into that range. If it does, we descend
                // into the left subtree and in the right subtree otherwise.
                let left_subtree_size = left_subtree_size(subtree_size);
                let go_left = pos < left_subtree_size;

                if go_left {
                    Builder::make_fork(
                        Self::pruned_for_all_but_pos::<Builder>(
                            left_tree.as_ref(),
                            subwitness,
                            pos,
                            left_subtree_size,
                        ),
                        Builder::make_pruned(right_tree.digest().clone()),
                    )
                } else {
                    Builder::make_fork(
                        Builder::make_pruned(left_tree.digest().clone()),
                        Self::pruned_for_all_but_pos::<Builder>(
                            right_tree.as_ref(),
                            subwitness,
                            pos - left_subtree_size,
                            subtree_size - left_subtree_size,
                        ),
                    )
                }
            }
            HashTree::Leaf { digest: _ } => panic!("bug: a leaf can only exist after a node"),
        }
    }

    fn flatten_forks<'a>(hash_tree: &'a HashTree, result: &mut Vec<&'a HashTree>) {
        match hash_tree {
            HashTree::Leaf { digest: _ } => panic!("bug: passed a leaf to flatten_forks"),
            HashTree::Node {
                digest: _,
                label: _,
                hash_tree,
            } => result.push(hash_tree.as_ref()),
            HashTree::Fork {
                digest: _,
                left_tree,
                right_tree,
            } => {
                Self::flatten_forks(left_tree.as_ref(), result);
                Self::flatten_forks(right_tree.as_ref(), result);
            }
        }
    }

    fn witness_impl<Builder, T>(
        partial_tree: &LabeledTree<T>,
        orig_tree: &LabeledTree<Digest>,
        hash_tree: &HashTree,
        current_depth: u8,
    ) -> Result<Builder, WitnessGenerationError<Builder>>
    where
        Builder: WitnessBuilder,
        T: std::convert::AsRef<[u8]> + Debug,
    {
        if current_depth > MAX_HASH_TREE_DEPTH {
            return Err(WitnessGenerationError::TooDeepRecursion(current_depth));
        }

        let result = match partial_tree {
            LabeledTree::SubTree(children) => {
                match orig_tree {
                    LabeledTree::SubTree(orig_children) => {
                        if orig_children.is_empty() {
                            return Ok(Builder::make_empty());
                        }

                        let mut result = Builder::make_pruned(hash_tree.digest().clone());

                        if children.is_empty() {
                            return Ok(result);
                        }

                        let mut nodes = Vec::with_capacity(orig_children.len());
                        Self::flatten_forks(hash_tree, &mut nodes);
                        debug_assert_eq!(orig_children.len(), nodes.len());

                        // if in target_labels, then descend
                        // else if borders with >=1 l in target_labels, prune what's under the node
                        // otherwise, prune the node
                        for target_label in children.keys() {
                            match orig_children.keys().binary_search(target_label) {
                                // Membership witness case.
                                // Descend into `nodes[target_hash_tree_index]`
                                // and merge the produced subwitness into `result`.
                                Ok(target_hash_tree_index) => {
                                    let target_hash_tree = nodes[target_hash_tree_index];
                                    let child_witness = Self::witness_impl::<Builder, _>(
                                        children.get(target_label).expect("Could not get label"),
                                        orig_children
                                            .get(target_label)
                                            .expect("Could not get label"),
                                        target_hash_tree,
                                        current_depth + 1,
                                    )?;
                                    result = Builder::merge_trees(
                                        result,
                                        // `orig_tree` and `hash_tree` are well-formed, since the only way to
                                        // create a `WitnessGeneratorImpl` is via `try_from` or from a
                                        // `HashTreeBuilderImpl`, which both ensure the validity. Also,
                                        // `hash_tree` cannot be empty since this case is handled at the
                                        // beginning of this function. Therefore, `pruned_for_all_but_pos`
                                        // cannot panic here and in other places in this function.
                                        Self::pruned_for_all_but_pos::<Builder>(
                                            hash_tree,
                                            Builder::make_node(target_label.clone(), child_witness),
                                            target_hash_tree_index,
                                            nodes.len(),
                                        ),
                                    )?;
                                }
                                // Absence witness case.
                                // If the label is not present in the original
                                // tree, we need to include (pruned) subwitness(es) at `target_offset`, e.g.,
                                // if `target_offset == 0`, we include `nodes[0]`,
                                // if `target_offset == 1`, we include `nodes[0]` and `nodes[1]`.
                                Err(target_offset) => {
                                    let absence_witness_from_node_at = |i: usize| -> Builder {
                                        let subwitness = Builder::make_node(
                                            orig_children.keys()[i].clone(),
                                            Builder::make_pruned(nodes[i].digest().clone()),
                                        );
                                        Self::pruned_for_all_but_pos::<Builder>(
                                            hash_tree,
                                            subwitness,
                                            i,
                                            nodes.len(),
                                        )
                                    };

                                    if target_offset == 0 || target_offset == orig_children.len() {
                                        // Missing label that is smaller than
                                        // minimum or larger than maximum label in `nodes.
                                        let offset = target_offset.saturating_sub(1);
                                        result = Builder::merge_trees(
                                            result,
                                            absence_witness_from_node_at(offset),
                                        )?;
                                    } else {
                                        // Missing label between two subsequent
                                        // labels in `nodes`.
                                        result = Builder::merge_trees(
                                            result,
                                            absence_witness_from_node_at(target_offset - 1),
                                        )?;
                                        result = Builder::merge_trees(
                                            result,
                                            absence_witness_from_node_at(target_offset),
                                        )?;
                                    }
                                }
                            }
                        }
                        result
                    }
                    LabeledTree::Leaf(_) => Builder::make_pruned(hash_tree.digest().clone()),
                }
            }
            LabeledTree::Leaf(data) => match orig_tree {
                LabeledTree::Leaf(_) => Builder::make_leaf(data.as_ref()),
                LabeledTree::SubTree(children) if children.is_empty() => Builder::make_empty(),
                LabeledTree::SubTree(_) => Builder::make_pruned(hash_tree.digest().clone()),
            },
        };
        Ok(result)
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
        if path.len() >= (MAX_HASH_TREE_DEPTH as usize) {
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

impl WitnessGenerator for WitnessGeneratorImpl {
    fn hash_tree(&self) -> &HashTree {
        &self.hash_tree
    }

    fn witness(
        &self,
        partial_tree: &LabeledTree<Vec<u8>>,
    ) -> Result<Witness, WitnessGenerationError<Witness>> {
        Self::witness_impl::<Witness, _>(partial_tree, &self.orig_tree, &self.hash_tree, 1)
    }

    fn mixed_hash_tree(
        &self,
        partial_tree: &LabeledTree<Vec<u8>>,
    ) -> Result<MixedHashTree, WitnessGenerationError<MixedHashTree>> {
        Self::witness_impl::<MixedHashTree, _>(partial_tree, &self.orig_tree, &self.hash_tree, 1)
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
