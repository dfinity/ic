#![allow(clippy::unwrap_used)]
use super::*;

#[test]
fn witness_generator_from_hash_tree_empty_tree() {
    let hash_tree = HashTree::Leaf {
        digest: empty_subtree_hash(),
    };
    let expected_labeled_tree = LabeledTree::SubTree(FlatMap::new());

    let witness_generator = WitnessGeneratorImpl::try_from(hash_tree).unwrap();
    assert_eq!(expected_labeled_tree, witness_generator.orig_tree);
}

#[test]
fn witness_generator_from_hash_tree_single_leaf_tree() {
    let leaf_contents = b"some leaf contents";
    let hash_tree = HashTree::Leaf {
        digest: compute_leaf_digest(leaf_contents),
    };
    let expected_labeled_tree = LabeledTree::Leaf(compute_leaf_digest(leaf_contents));

    let witness_generator = WitnessGeneratorImpl::try_from(hash_tree).unwrap();
    assert_eq!(expected_labeled_tree, witness_generator.orig_tree);
}
