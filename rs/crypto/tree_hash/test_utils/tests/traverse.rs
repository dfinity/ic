use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_crypto_tree_hash::{FlatMap, LabeledTree};
use ic_crypto_tree_hash_test_utils::{
    labeled_tree_without_leaf_or_empty_subtree, new_random_labeled_tree,
    partial_trees_to_leaves_and_empty_subtrees,
};

#[test]
fn partial_trees_to_leaves_and_empty_subtrees_works_correctly() {
    let tree = LabeledTree::Leaf(vec![]);
    assert_eq!(partial_trees_to_leaves_and_empty_subtrees(&tree), [tree]);

    let tree = LabeledTree::<Vec<u8>>::SubTree(FlatMap::new());
    assert_eq!(partial_trees_to_leaves_and_empty_subtrees(&tree), [tree]);

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

    let mut iter = partial_trees_to_leaves_and_empty_subtrees(&tree).into_iter();
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

    let rng = &mut reproducible_rng();
    let mut tree = new_random_labeled_tree(
        rng,
        RANDOM_TREE_MAX_DEPTH,
        RANDOM_TREE_DESIRED_SIZE,
        RANDOM_TREE_MIN_LEAVES,
    );

    let mut leaves_and_empty_subtrees = partial_trees_to_leaves_and_empty_subtrees(&tree);
    let initial_num_leaves_and_empty_subtrees = leaves_and_empty_subtrees.len();
    let mut counter: usize = 0;
    while leaves_and_empty_subtrees != vec![LabeledTree::SubTree(FlatMap::new())] {
        let index_to_remove = rng.random_range(0..leaves_and_empty_subtrees.len());
        let path_to_remove = &leaves_and_empty_subtrees[index_to_remove];
        let tree_with_removed_path =
            labeled_tree_without_leaf_or_empty_subtree(&tree, path_to_remove);
        let leaves_and_empty_subtrees_with_removed_path =
            partial_trees_to_leaves_and_empty_subtrees(&tree_with_removed_path);
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
