use crate::{
    arbitrary::arbitrary_well_formed_mixed_hash_tree, flatmap, InvalidHashTreeError, Label,
    LabeledTree, MixedHashTree,
};
use proptest::prelude::*;
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

proptest! {
    #[test]
    fn prop_well_formed_trees_are_convertible(t in arbitrary_well_formed_mixed_hash_tree()) {
        let r: Result<TreeOfBlobs, _> = t.clone().try_into();
        assert!(r.is_ok(), "Failed to convert a well-formed mixed hash tree {:?} into a labeled tree: {:?}", t, r);
    }
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
    let r: Result<T, InvalidHashTreeError> = malformed_tree.try_into();
    assert_eq!(r, Err(InvalidHashTreeError::UnlabeledLeaf));
}
