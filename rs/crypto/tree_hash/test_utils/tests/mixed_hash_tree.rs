use assert_matches::assert_matches;
use ic_crypto_tree_hash::MixedHashTree;
use ic_crypto_tree_hash_test_utils::{
    MAX_HASH_TREE_DEPTH, TooDeepRecursion, mixed_hash_tree_digest_recursive,
};

#[test]
fn mixed_hash_tree_recursive_digest_errors_on_too_deep_trees() {
    let mut tree = MixedHashTree::Empty;
    for _ in 1..MAX_HASH_TREE_DEPTH {
        tree = MixedHashTree::Fork(Box::new((tree.clone(), MixedHashTree::Empty)));
    }

    assert_matches!(mixed_hash_tree_digest_recursive(&tree), Ok(_));

    tree = MixedHashTree::Fork(Box::new((tree.clone(), MixedHashTree::Empty)));
    assert_eq!(
        mixed_hash_tree_digest_recursive(&tree),
        Err(TooDeepRecursion(MAX_HASH_TREE_DEPTH + 1))
    );
}
