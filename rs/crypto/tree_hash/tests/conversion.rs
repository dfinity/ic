use assert_matches::assert_matches;
use ic_crypto_tree_hash::{
    Digest, Label, LabeledTree, MixedHashTree, MixedHashTreeConversionError, flatmap,
};
use ic_crypto_tree_hash_test_utils::{
    MAX_HASH_TREE_DEPTH, arbitrary::arbitrary_well_formed_mixed_hash_tree,
};
use std::convert::TryInto;

type TreeOfBlobs = LabeledTree<Vec<u8>>;

fn must_convert(t: MixedHashTree) -> TreeOfBlobs {
    t.try_into().expect("failed to convert mixed hash tree")
}

fn label<T: Into<Label>>(l: T) -> Label {
    l.into()
}

fn labeled(s: &str, b: &[u8]) -> MixedHashTree {
    MixedHashTree::Labeled(s.into(), Box::new(MixedHashTree::Leaf(b.to_vec())))
}

#[test_strategy::proptest]
fn prop_well_formed_trees_are_convertible(
    #[strategy(arbitrary_well_formed_mixed_hash_tree())] t: MixedHashTree,
) {
    let r: Result<TreeOfBlobs, _> = t.clone().try_into();
    assert!(
        r.is_ok(),
        "Failed to convert a well-formed mixed hash tree {t:?} into a labeled tree: {r:?}"
    );
}

type T = TreeOfBlobs;
type M = MixedHashTree;

#[test]
fn convert_empty_tree() {
    assert_eq!(must_convert(M::Empty), T::SubTree(flatmap!()));
}

#[test]
fn convert_one_leaf() {
    assert_eq!(
        must_convert(M::Leaf(b"test".to_vec())),
        T::Leaf(b"test".to_vec())
    );
}

#[test]
fn convert_small_tree() {
    assert_eq!(
        must_convert(labeled("a", b"123")),
        T::SubTree(flatmap!(label("a") => T::Leaf(b"123".to_vec()))),
    );
}

#[test]
fn convert_small_nested_tree() {
    assert_eq!(
        must_convert(M::Fork(Box::new((labeled("a", b"1"), labeled("b", b"2"))))),
        T::SubTree(
            flatmap!(label("a") => T::Leaf(b"1".to_vec()), label("b") => T::Leaf(b"2".to_vec()))
        ),
    );
}

#[test]
fn convert_malformed_tree() {
    let malformed_tree = M::Fork(Box::new((M::Leaf(b"1".to_vec()), M::Leaf(b"2".to_vec()))));
    let r: Result<T, MixedHashTreeConversionError> = malformed_tree.try_into();
    assert_eq!(r, Err(MixedHashTreeConversionError::UnlabeledLeaf));
}

#[test]
fn convert_too_deep_tree() {
    fn dummy_mixed_hash_tree_of_depth(depth: u8) -> M {
        let mut result = M::Empty;
        assert!(depth > 0);
        for _ in 0..depth - 1 {
            result = M::Fork(Box::new((result, M::Pruned(Digest([0u8; 32])))));
        }
        result
    }

    const LIMIT: u8 = MAX_HASH_TREE_DEPTH;

    for depth in [1, 2, LIMIT - 1, LIMIT] {
        let result: Result<T, MixedHashTreeConversionError> =
            dummy_mixed_hash_tree_of_depth(depth).try_into();
        assert_matches!(result, Ok(_));
    }

    for depth in [LIMIT + 1, LIMIT + 10] {
        let mixed_tree = dummy_mixed_hash_tree_of_depth(depth);

        assert_matches!(
            serde_cbor::from_slice::<MixedHashTree>(
                serde_cbor::to_vec(&mixed_tree)
                    .expect("Failed to serialize mixed hash tree")
                    .as_slice()
            ),
            Err(e) if format!("{e:?}").contains("RecursionLimitExceeded")
        );

        let result: Result<T, MixedHashTreeConversionError> = mixed_tree.try_into();
        assert_eq!(result, Err(MixedHashTreeConversionError::TooDeepRecursion));
    }
}
