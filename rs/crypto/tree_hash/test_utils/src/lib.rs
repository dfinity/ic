use assert_matches::assert_matches;
use ic_crypto_tree_hash::hasher::Hasher;
use ic_crypto_tree_hash::*;

pub mod arbitrary;

pub const MAX_HASH_TREE_DEPTH: u8 = 128;

const DOMAIN_HASHTREE_LEAF: &str = "ic-hashtree-leaf";
const DOMAIN_HASHTREE_EMPTY_SUBTREE: &str = "ic-hashtree-empty";
const DOMAIN_HASHTREE_NODE: &str = "ic-hashtree-labeled";
const DOMAIN_HASHTREE_FORK: &str = "ic-hashtree-fork";

/// Returns the number of leaves and empty subtrees in an arbitrary [`LabeledTree`].
pub fn get_num_leaves_and_empty_subtrees<T>(labeled_tree: &LabeledTree<T>) -> usize {
    match labeled_tree {
        LabeledTree::SubTree(labeled_subtree) if labeled_subtree.is_empty() => 1,
        LabeledTree::SubTree(labeled_subtree) => labeled_subtree
            .iter()
            .map(|(_label, subtree)| get_num_leaves_and_empty_subtrees(subtree))
            .sum(),
        LabeledTree::Leaf(_) => 1,
    }
}

/// Generates a random [`LabeledTree`] using `rng`.
///
/// `max_depth` and `min_leaves` are hard limits. `desired_size` is not.
///
/// Note that if `min_leaves` is set unrealistically high, call to this
/// function will result in an infinite loop.
pub fn new_random_labeled_tree<R: rand::Rng>(
    rng: &mut R,
    max_depth: u32,
    desired_size: u32,
    min_leaves: u32,
) -> LabeledTree<Vec<u8>> {
    use arbitrary::arbitrary_well_formed_mixed_hash_tree_with_params;
    use proptest::strategy::{Strategy, ValueTree};
    loop {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let test_rng = proptest::test_runner::TestRng::from_seed(
            proptest::test_runner::RngAlgorithm::ChaCha,
            &seed,
        );
        let mut runner = proptest::test_runner::TestRunner::new_with_rng(
            proptest::test_runner::Config::default(),
            test_rng,
        );
        let tree_generator =
            arbitrary_well_formed_mixed_hash_tree_with_params(max_depth, desired_size, 1)
                .new_tree(&mut runner)
                .expect("Failed to generate a ValueTree for generating a MixedHashTree");
        let mixed_hash_tree = tree_generator.current();
        let labeled_tree: LabeledTree<Vec<u8>> = mixed_hash_tree
            .try_into()
            .expect("Failed to convert a proptest-generated MixedHashTree to a LabeledTree");
        if get_num_leaves_and_empty_subtrees(&labeled_tree) >= min_leaves as usize {
            return labeled_tree;
        }
    }
}

/// Check that leaves and empty subtrees in `labeled_tree` are
/// [`Witness::Known`] and that any found [`Witness::Pruned`] do not correspond
/// to any leaf or empty subtree in `labeled_tree.
///
/// Returns the number of traversed [`Witness::Known`] nodes.
pub fn check_leaves_and_empty_subtrees_are_known(
    labeled_tree: &LabeledTree<Vec<u8>>,
    witness: &Witness,
) -> usize {
    let mut labels_on_path = vec![];
    check_leaves_and_empty_subtrees_are_known_impl(labeled_tree, witness, &mut labels_on_path)
}

fn check_leaves_and_empty_subtrees_are_known_impl(
    labeled_tree: &LabeledTree<Vec<u8>>,
    witness: &Witness,
    labels_on_path: &mut Vec<Vec<u8>>,
) -> usize {
    match witness {
        Witness::Fork {
            left_tree,
            right_tree,
        } => {
            let lhs_num_known = check_leaves_and_empty_subtrees_are_known_impl(
                labeled_tree,
                left_tree.as_ref(),
                labels_on_path,
            );
            let rhs_num_known = check_leaves_and_empty_subtrees_are_known_impl(
                labeled_tree,
                right_tree.as_ref(),
                labels_on_path,
            );
            lhs_num_known + rhs_num_known
        }
        Witness::Node { label, sub_witness } => {
            labels_on_path.push(label.clone().into_vec());
            let num_known = check_leaves_and_empty_subtrees_are_known_impl(
                labeled_tree,
                sub_witness.as_ref(),
                labels_on_path,
            );
            labels_on_path.pop();
            num_known
        }
        Witness::Pruned { digest: _ } => {
            // all pruned nodes should not correspond to a `Leaf` in `labeled_tree`
            let lookup_result = lookup_path(
                labeled_tree,
                &labels_on_path
                    .iter()
                    .map(|label| &label[..])
                    .collect::<Vec<_>>()[..],
            );
            assert!(
                !matches!(lookup_result, Some(LabeledTree::Leaf(_))),
                "Private data in path {labels_on_path:?} included in the witness {witness:?} as Pruned,
                but was found in {labeled_tree:?}"
            );
            0
        }
        Witness::Known() => {
            // all known nodes should be successfully looked up in
            // `labeled_tree`'s leaves or empty subtrees
            let leaf_or_empty_subtree = lookup_path(
                labeled_tree,
                &labels_on_path
                    .iter()
                    .map(|label| &label[..])
                    .collect::<Vec<_>>()[..],
            )
            .expect("Failed to find a leaf in LabeledTree that corresponds to a Witness::Known");

            match leaf_or_empty_subtree {
                LabeledTree::Leaf(_) => 1,
                LabeledTree::SubTree(children) if children.is_empty() => 1,
                _ => panic!(
                        "The witness expects a known value in path {labels_on_path:?} but a corresponding
                        leaf or empty subtree is not included in the labeled tree. Got {leaf_or_empty_subtree:?} instead."
                     ),
            }
        }
    }
}

/// Replaces a random [`Witness::Known`] node with a [`Witness::Pruned`] and returns
/// the path to the replaced node.
pub fn replace_random_known_with_dummy_pruned<R: rand::Rng>(
    witness: &mut Witness,
    rng: &mut R,
) -> Vec<Label> {
    fn paths_to_all_known<'a>(
        curr_path: &mut Vec<&'a Label>,
        result: &mut Vec<Vec<&'a Label>>,
        witness: &'a Witness,
    ) {
        match witness {
            Witness::Fork {
                left_tree,
                right_tree,
            } => {
                paths_to_all_known(curr_path, result, left_tree.as_ref());
                paths_to_all_known(curr_path, result, right_tree.as_ref());
            }
            Witness::Node { label, sub_witness } => {
                curr_path.push(label);
                paths_to_all_known(curr_path, result, sub_witness.as_ref());
                curr_path.pop();
            }
            Witness::Pruned { digest: _ } => {}
            Witness::Known() => {
                result.push(curr_path.clone());
            }
        }
    }

    fn replace_known_with_dummy_pruned_in_path(
        target_path: &[Label],
        witness: &mut Witness,
    ) -> bool {
        match witness {
            Witness::Fork {
                left_tree,
                right_tree,
            } => {
                replace_known_with_dummy_pruned_in_path(target_path, left_tree.as_mut())
                    || replace_known_with_dummy_pruned_in_path(target_path, right_tree.as_mut())
            }
            Witness::Node { label, sub_witness } => {
                if label == &target_path[0] {
                    replace_known_with_dummy_pruned_in_path(&target_path[1..], sub_witness.as_mut())
                } else {
                    false
                }
            }
            Witness::Pruned { digest: _ } => false,
            Witness::Known() => {
                if target_path.is_empty() {
                    *witness = Witness::Pruned {
                        digest: Digest([0u8; 32]),
                    };
                    true
                } else {
                    false
                }
            }
        }
    }

    let mut paths = vec![];
    paths_to_all_known(&mut vec![], &mut paths, witness);
    let target_path: Vec<Label> = paths[rng.gen_range(0..paths.len())]
        .iter()
        .map(|&l| l.clone())
        .collect();

    assert!(replace_known_with_dummy_pruned_in_path(
        &target_path[..],
        witness
    ));

    target_path
}

pub fn labeled_tree_contains_prefix(labeled_tree: &LabeledTree<Vec<u8>>, prefix: &[Label]) -> bool {
    if prefix.is_empty() {
        return true;
    }

    match labeled_tree {
        LabeledTree::SubTree(tree) => match tree.get(&prefix[0]) {
            Some(subtree) => labeled_tree_contains_prefix(subtree, &prefix[1..]),
            None => false,
        },
        LabeledTree::Leaf(_) => false,
    }
}

/// Creates a copy of `labeled_tree` with `path` to leaf or empty subtree
/// removed from it. Panics on inconsistent `labeled_tree`/`path`.
pub fn labeled_tree_without_leaf_or_empty_subtree(
    labeled_tree: &LabeledTree<Vec<u8>>,
    path: &LabeledTree<Vec<u8>>,
) -> LabeledTree<Vec<u8>> {
    let mut result = labeled_tree.clone();
    labeled_tree_without_leaf_or_empty_subtree_impl(&mut result, path);
    result
}

/// Takes a mutable reference to a `labeled_tree` and attempts to remove `path`
/// to a leaf or empty subtree from it.
fn labeled_tree_without_leaf_or_empty_subtree_impl(
    labeled_tree: &mut LabeledTree<Vec<u8>>,
    path: &LabeledTree<Vec<u8>>,
) {
    match (labeled_tree, path) {
        (LabeledTree::SubTree(tree_children), LabeledTree::SubTree(path_children))
            if path_children.len() == 1 && tree_children.contains_key(&path_children.keys()[0]) =>
        {
            let path_child_is_empty_subtree = matches!(&path_children.values()[0], LabeledTree::SubTree(children) if children.is_empty());
            let path_child_is_leaf = matches!(&path_children.values()[0], LabeledTree::Leaf(_));

            if path_child_is_empty_subtree || path_child_is_leaf {
                assert_matches!(tree_children.remove(&path_children.keys()[0]), Some(_));
                return;
            }

            let tree_child = tree_children
                .get_mut(&path_children.keys()[0])
                .expect("Failed to retrieve a subtree");
            labeled_tree_without_leaf_or_empty_subtree_impl(tree_child, &path_children.values()[0]);

            // if the tree's child in path has become an empty subtree, then
            // remove it
            let tree_child_has_become_empty_subtree =
                matches!(tree_child, LabeledTree::SubTree(children) if children.is_empty());
            if tree_child_has_become_empty_subtree {
                assert_matches!(tree_children.remove(&path_children.keys()[0]), Some(LabeledTree::SubTree(ref children)) if children.is_empty());
            }
        }
        (LabeledTree::Leaf(_), LabeledTree::Leaf(_)) => {
            unreachable!("We never descend into children for valid trees");
        }
        (p, t) => {
            panic!(
                "Mismatching structure by truncating {p:?} from {t:?} or less than 2 leaves/empty subtrees"
            );
        }
    }
}

pub fn witness_contains_only_nodes_and_known(witness: &Witness) -> bool {
    match witness {
        Witness::Fork {
            left_tree: _,
            right_tree: _,
        } => false,
        Witness::Node {
            label: _,
            sub_witness,
        } => witness_contains_only_nodes_and_known(sub_witness.as_ref()),
        Witness::Pruned { digest: _ } => false,
        Witness::Known() => true,
    }
}

/// Returns complete partial trees for each leaf and empty subtree in `tree`.
///
/// For example, for `tree` of form
///
/// ```text
/// + -- 1 -- Leaf(())
/// |
/// | -- 2 -- Leaf(())
/// |
/// | -- 3 -- EMPTY_SUBTREE
/// |
/// | -- 4 -- + -- 5 -- Leaf(())
///           |
///           | -- 6 -- EMPTY_SUBTREE
/// ```
///
/// the result would contain
///
///  ```text
/// + -- 1 -- Leaf(())
///
/// + -- 2 -- Leaf(())
///
/// + -- 3 -- EMPTY_SUBTREE
///
/// + -- 4 -- + -- 5 -- Leaf(())
///
/// + -- 4 -- + -- 6 -- EMPTY_SUBTREE
/// ```
pub fn partial_trees_to_leaves_and_empty_subtrees(
    tree: &LabeledTree<Vec<u8>>,
) -> Vec<LabeledTree<Vec<u8>>> {
    let mut result = vec![];
    partial_trees_to_leaves_and_empty_subtrees_impl(tree, &mut vec![], &mut result);
    result
}

fn partial_trees_to_leaves_and_empty_subtrees_impl<'a>(
    tree: &'a LabeledTree<Vec<u8>>,
    curr_path: &mut Vec<&'a Label>,
    result: &mut Vec<LabeledTree<Vec<u8>>>,
) {
    match tree {
        LabeledTree::SubTree(children) if !children.is_empty() => {
            for (label, child) in children.iter() {
                curr_path.push(label);
                partial_trees_to_leaves_and_empty_subtrees_impl(child, curr_path, result);
                curr_path.pop();
            }
        }
        LabeledTree::SubTree(_) | LabeledTree::Leaf(_) => {
            let path_tree = curr_path.iter().rev().fold(tree.clone(), |acc, &label| {
                LabeledTree::SubTree(flatmap!(label.clone() => acc))
            });
            result.push(path_tree);
        }
    }
}

/// Merges a path (i.e., a one node wide [`LabeledTree`] ending with a
/// [`LabeledTree::Leaf`] or empty [`LabeledTree::SubTree`]) into the `agg` by
/// appending the missing node/subtree from `path`.
///
/// Panics if the appended label from `path` is not larger than the largest
/// label in the respective subtree.
pub fn merge_path_into_labeled_tree<T: core::fmt::Debug + std::cmp::PartialEq + Clone>(
    agg: &mut LabeledTree<T>,
    path: &LabeledTree<T>,
) {
    match (agg, path) {
        (LabeledTree::SubTree(subtree_agg), LabeledTree::SubTree(subtree_path)) => {
            if subtree_path.is_empty() {
                // path with an empty subtree at the end
                return;
            }
            assert_eq!(
                subtree_path.len(),
                1,
                "`path` should always contain only exactly one label/tree pair in each subtree but got {subtree_path:?}"
            );
            let (path_label, subpath) = subtree_path
                .iter()
                .next()
                .expect("should contain exactly one child");
            // if the left subtree contains the label from the right subtree, go one level deeper,
            // otherwise append the right subtree to the left subtree
            if let Some(subagg) = subtree_agg.get_mut(path_label) {
                merge_path_into_labeled_tree(subagg, subpath);
            } else {
                subtree_agg
                    .try_append(path_label.clone(), subpath.clone())
                    .expect(
                        "bug: the path label is unsorted w.r.t. to the tree and cannot be appended",
                    );
            }
        }
        _ => panic!("Trying to merge into existing tree path"),
    }
}

/// Creates a HashTreeBuilderImpl for the passed `labeled_tree`.
pub fn hash_tree_builder_from_labeled_tree(
    labeled_tree: &LabeledTree<Vec<u8>>,
) -> HashTreeBuilderImpl {
    let mut builder = HashTreeBuilderImpl::new();
    hash_tree_builder_from_labeled_tree_impl(labeled_tree, &mut builder);
    builder
}

fn hash_tree_builder_from_labeled_tree_impl(
    labeled_tree: &LabeledTree<Vec<u8>>,
    builder: &mut HashTreeBuilderImpl,
) {
    match labeled_tree {
        LabeledTree::<Vec<u8>>::SubTree(labeled_subtree) => {
            builder.start_subtree();
            for (label, subtree) in labeled_subtree.iter() {
                builder.new_edge(label.clone());
                hash_tree_builder_from_labeled_tree_impl(subtree, builder);
            }
            builder.finish_subtree();
        }
        LabeledTree::<Vec<u8>>::Leaf(content) => {
            builder.start_leaf();
            builder.write_leaf(content.clone());
            builder.finish_leaf();
        }
    }
}

pub fn compute_leaf_digest(contents: &[u8]) -> Digest {
    let mut hasher = Hasher::for_domain(DOMAIN_HASHTREE_LEAF);
    hasher.update(contents);
    hasher.finalize()
}

pub fn compute_node_digest(label: &Label, subtree_digest: &Digest) -> Digest {
    let mut hasher = Hasher::for_domain(DOMAIN_HASHTREE_NODE);
    hasher.update(label.as_bytes());
    hasher.update(&subtree_digest.0);
    hasher.finalize()
}

pub fn compute_fork_digest(left_digest: &Digest, right_digest: &Digest) -> Digest {
    let mut hasher = Hasher::for_domain(DOMAIN_HASHTREE_FORK);
    hasher.update(&left_digest.0);
    hasher.update(&right_digest.0);
    hasher.finalize()
}

pub fn empty_subtree_hash() -> Digest {
    Hasher::for_domain(DOMAIN_HASHTREE_EMPTY_SUBTREE).finalize()
}

/// This error indicates that the algorithm exceeded the recursion depth limit.
#[derive(PartialEq, Debug, thiserror::Error)]
#[error("The algorithm failed due to too deep recursion (depth={0})")]
pub struct TooDeepRecursion(pub u8);

/// Recomputes root hash of the full tree that this mixed tree was
/// constructed from.
pub fn mixed_hash_tree_digest_recursive(tree: &MixedHashTree) -> Result<Digest, TooDeepRecursion> {
    fn digest_impl(t: &MixedHashTree, depth: u8) -> Result<Digest, TooDeepRecursion> {
        if depth > MAX_HASH_TREE_DEPTH {
            return Err(TooDeepRecursion(depth));
        }
        let result = match t {
            MixedHashTree::Empty => empty_subtree_hash(),
            MixedHashTree::Fork(lr) => compute_fork_digest(
                &digest_impl(&lr.0, depth + 1)?,
                &digest_impl(&lr.1, depth + 1)?,
            ),
            MixedHashTree::Labeled(label, subtree) => {
                compute_node_digest(label, &digest_impl(subtree, depth + 1)?)
            }
            MixedHashTree::Leaf(buf) => compute_leaf_digest(&buf[..]),
            MixedHashTree::Pruned(digest) => digest.clone(),
        };
        Ok(result)
    }

    digest_impl(tree, 1)
}
