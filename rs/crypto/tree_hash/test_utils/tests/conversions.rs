use assert_matches::assert_matches;
use ic_crypto_tree_hash::{HashTreeBuilder, LabeledTree, Witness, WitnessGenerator, prune_witness};
use ic_crypto_tree_hash_test_utils::{
    arbitrary::arbitrary_labeled_tree, hash_tree_builder_from_labeled_tree,
};

#[test_strategy::proptest]
fn hash_tree_builder_from_labeled_tree_works_correctly(
    #[strategy(arbitrary_labeled_tree())] tree: LabeledTree<Vec<u8>>,
) {
    let builder = hash_tree_builder_from_labeled_tree(&tree);
    // check that the witness is correct by pruning it completely
    let wg = builder
        .witness_generator()
        .expect("Failed to retrieve a witness constructor");
    let witness = wg
        .witness(&tree)
        .expect("Failed to build a witness for the whole tree");
    let witness = prune_witness(&witness, &tree).expect("failed to prune witness");
    assert_matches!(witness, Witness::Pruned { digest: _ });
}
