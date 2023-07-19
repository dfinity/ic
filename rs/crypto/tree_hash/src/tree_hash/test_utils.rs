use crate::*;
use assert_matches::assert_matches;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;

/// Returns the number of leaves and empty subtrees in an arbitrary [`LabeledTree`].
pub(crate) fn get_num_leaves_and_empty_subtrees<T>(labeled_tree: &LabeledTree<T>) -> usize {
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
pub(crate) fn new_random_labeled_tree<R: rand::Rng>(
    rng: &mut R,
    max_depth: u32,
    desired_size: u32,
    min_leaves: u32,
) -> LabeledTree<Vec<u8>> {
    use crate::arbitrary::arbitrary_well_formed_mixed_hash_tree_with_params;
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
pub(crate) fn check_leaves_and_empty_subtrees_are_known(
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
            labels_on_path.push(label.clone().to_vec());
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
            let lookup_result = crate::lookup_path(
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
            let leaf_or_empty_subtree = crate::lookup_path(
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
pub(crate) fn replace_random_known_with_dummy_pruned<R: rand::Rng>(
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

pub(crate) fn labeled_tree_contains_prefix(
    labeled_tree: &LabeledTree<Vec<u8>>,
    prefix: &[Label],
) -> bool {
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
pub(crate) fn labeled_tree_without_leaf_or_empty_subtree(
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
                assert_matches!(tree_children.remove(&path_children.keys()[0]), Some(LabeledTree::SubTree(children)) if children.is_empty());
            }
        }
        (LabeledTree::Leaf(_), LabeledTree::Leaf(_)) => {
            unreachable!("We never descend into children for valid trees");
        }
        (p, t) => {
            panic!("Mismatching structure by truncating {p:?} from {t:?} or less than 2 leaves/empty subtrees");
        }
    }
}

#[test]
fn leaf_and_empty_subtree_traverser_works_correctly() {
    let tree = LabeledTree::Leaf(vec![]);
    assert_eq!(
        test_utils::partial_trees_to_leaves_and_empty_subtrees(&tree),
        [tree]
    );

    let tree = LabeledTree::<Vec<u8>>::SubTree(FlatMap::new());
    assert_eq!(
        test_utils::partial_trees_to_leaves_and_empty_subtrees(&tree),
        [tree]
    );

    // Construct a more complex labeled tree of the form
    //
    // + -- 1 -- Leaf(())
    // |
    // | -- 2 -- Leaf(())
    // |
    // | -- 3 -- EMPTY_SUBTREE
    // |
    // | -- 4 -- + -- 5 -- Leaf(())
    //           |
    //           | -- 6 -- EMPTY_SUBTREE
    //           |
    //           | -- 7 -- + -- 8 -- Leaf(())
    //           |
    //           | -- 9 -- + -- 10 -- Leaf(())
    //                     |
    //                     | -- 11 -- Leaf(())
    //
    let tree = LabeledTree::SubTree(FlatMap::from_key_values(vec![
        ("1".into(), LabeledTree::Leaf(vec![])),
        ("2".into(), LabeledTree::Leaf(vec![])),
        ("3".into(), LabeledTree::SubTree(FlatMap::new())),
        (
            "4".into(),
            LabeledTree::SubTree(FlatMap::from_key_values(vec![
                ("5".into(), LabeledTree::Leaf(vec![])),
                ("6".into(), LabeledTree::SubTree(FlatMap::new())),
                (
                    "7".into(),
                    LabeledTree::SubTree(FlatMap::from_key_values(vec![(
                        "8".into(),
                        LabeledTree::Leaf(vec![]),
                    )])),
                ),
                (
                    "9".into(),
                    LabeledTree::SubTree(FlatMap::from_key_values(vec![
                        ("10".into(), LabeledTree::Leaf(vec![])),
                        ("11".into(), LabeledTree::Leaf(vec![])),
                    ])),
                ),
            ])),
        ),
    ]));

    let mut iter = test_utils::partial_trees_to_leaves_and_empty_subtrees(&tree).into_iter();
    assert_eq!(
        iter.next().expect("available path"),
        LabeledTree::SubTree(FlatMap::from_key_values(vec![(
            "1".into(),
            LabeledTree::Leaf(vec![])
        )]))
    );
    assert_eq!(
        iter.next().expect("available path"),
        LabeledTree::SubTree(FlatMap::from_key_values(vec![(
            "2".into(),
            LabeledTree::Leaf(vec![])
        )]))
    );
    assert_eq!(
        iter.next().expect("available path"),
        LabeledTree::SubTree(FlatMap::from_key_values(vec![(
            "3".into(),
            LabeledTree::SubTree(FlatMap::new())
        )]))
    );

    assert_eq!(
        iter.next().expect("available path"),
        LabeledTree::SubTree(FlatMap::from_key_values(vec![(
            "4".into(),
            LabeledTree::SubTree(FlatMap::from_key_values(vec![(
                "5".into(),
                LabeledTree::Leaf(vec![]),
            )])),
        )]))
    );

    assert_eq!(
        iter.next().expect("available path"),
        LabeledTree::SubTree(FlatMap::from_key_values(vec![(
            "4".into(),
            LabeledTree::SubTree(FlatMap::from_key_values(vec![(
                "6".into(),
                LabeledTree::SubTree(FlatMap::new()),
            )])),
        )]))
    );

    assert_eq!(
        iter.next().expect("available path"),
        LabeledTree::SubTree(FlatMap::from_key_values(vec![(
            "4".into(),
            LabeledTree::SubTree(FlatMap::from_key_values(vec![(
                "7".into(),
                LabeledTree::SubTree(FlatMap::from_key_values(vec![(
                    "8".into(),
                    LabeledTree::Leaf(vec![]),
                )])),
            ),])),
        )]))
    );

    assert_eq!(
        iter.next().expect("available path"),
        LabeledTree::SubTree(FlatMap::from_key_values(vec![(
            "4".into(),
            LabeledTree::SubTree(FlatMap::from_key_values(vec![(
                "9".into(),
                LabeledTree::SubTree(FlatMap::from_key_values(vec![(
                    "10".into(),
                    LabeledTree::Leaf(vec![]),
                )])),
            ),])),
        )]))
    );

    assert_eq!(
        iter.next().expect("available path"),
        LabeledTree::SubTree(FlatMap::from_key_values(vec![(
            "4".into(),
            LabeledTree::SubTree(FlatMap::from_key_values(vec![(
                "9".into(),
                LabeledTree::SubTree(FlatMap::from_key_values(vec![(
                    "11".into(),
                    LabeledTree::Leaf(vec![]),
                )])),
            ),])),
        )]))
    );

    assert_eq!(iter.next(), None);
}

pub(crate) fn witness_contains_only_nodes_and_known(witness: &Witness) -> bool {
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

#[test]
fn labeled_tree_without_leaf_or_empty_subtree_works_correctly() {
    for tree in [
        LabeledTree::SubTree(FlatMap::from_key_values(vec![(
            "1".into(),
            LabeledTree::Leaf(vec![]),
        )])),
        LabeledTree::SubTree(FlatMap::from_key_values(vec![(
            "1".into(),
            LabeledTree::SubTree(FlatMap::new()),
        )])),
        LabeledTree::SubTree(FlatMap::from_key_values(vec![(
            "1".into(),
            LabeledTree::SubTree(FlatMap::from_key_values(vec![(
                "2".into(),
                LabeledTree::Leaf(vec![]),
            )])),
        )])),
        LabeledTree::SubTree(FlatMap::from_key_values(vec![(
            "1".into(),
            LabeledTree::SubTree(FlatMap::from_key_values(vec![(
                "2".into(),
                LabeledTree::SubTree(FlatMap::new()),
            )])),
        )])),
    ] {
        assert_eq!(
            labeled_tree_without_leaf_or_empty_subtree(&tree, &tree),
            LabeledTree::SubTree(FlatMap::new())
        );
    }

    use rand::Rng;
    const RANDOM_TREE_MAX_DEPTH: u32 = 20;
    const RANDOM_TREE_DESIRED_SIZE: u32 = 100;
    const RANDOM_TREE_MIN_LEAVES: u32 = 70;

    let mut rng = reproducible_rng();
    let mut tree = new_random_labeled_tree(
        &mut rng,
        RANDOM_TREE_MAX_DEPTH,
        RANDOM_TREE_DESIRED_SIZE,
        RANDOM_TREE_MIN_LEAVES,
    );

    let mut leaves_and_empty_subtrees =
        test_utils::partial_trees_to_leaves_and_empty_subtrees(&tree);
    let initial_num_leaves_and_empty_subtrees = leaves_and_empty_subtrees.len();
    let mut counter: usize = 0;
    while leaves_and_empty_subtrees != vec![LabeledTree::SubTree(FlatMap::new())] {
        let index_to_remove = rng.gen_range(0..leaves_and_empty_subtrees.len());
        let path_to_remove = &leaves_and_empty_subtrees[index_to_remove];
        let tree_with_removed_path =
            labeled_tree_without_leaf_or_empty_subtree(&tree, path_to_remove);
        let leaves_and_empty_subtrees_with_removed_path =
            test_utils::partial_trees_to_leaves_and_empty_subtrees(&tree_with_removed_path);
        for not_removed_path in leaves_and_empty_subtrees
            .iter()
            .filter(|&path| path != path_to_remove)
        {
            assert!(leaves_and_empty_subtrees_with_removed_path.contains(not_removed_path));
        }
        assert!(!leaves_and_empty_subtrees_with_removed_path.contains(path_to_remove));
        let only_empty_root_left = leaves_and_empty_subtrees_with_removed_path
            == vec![LabeledTree::SubTree(FlatMap::new())];
        // if truncated to empty root, the size of the vector does not decrease
        assert_eq!(
            leaves_and_empty_subtrees_with_removed_path.len() + (!only_empty_root_left as usize),
            leaves_and_empty_subtrees.len()
        );
        leaves_and_empty_subtrees = leaves_and_empty_subtrees_with_removed_path;
        tree = tree_with_removed_path;
        counter += 1;
    }
    assert_eq!(counter, initial_num_leaves_and_empty_subtrees);
}
