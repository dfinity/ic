use assert_matches::assert_matches;
use ic_canonical_state_tree_hash::hash_tree::{HashTreeError, hash_lazy_tree};
use ic_canonical_state_tree_hash_test_utils::{as_lazy, test_membership_witness};
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_crypto_tree_hash::{FlatMap, Label, LabeledTree, MixedHashTree, flatmap};
use ic_crypto_tree_hash_test_utils::arbitrary::arbitrary_labeled_tree;
use proptest::prelude::*;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// The maximum number of allowed recursions during hash tree calculation
/// Note that in the current implementation the recursion depth corresponds to
/// the depth of the lazy tree.
const MAX_RECURSION_DEPTH: u32 = 128;

#[test]
fn test_empty_subtree() {
    let rng = &mut reproducible_rng();
    let t = LabeledTree::SubTree(flatmap! {});

    test_membership_witness(&t, rng);
}

#[test]
fn test_one_level_tree() {
    let rng = &mut reproducible_rng();
    let t = LabeledTree::SubTree(flatmap! {
        Label::from([0]) => LabeledTree::SubTree(flatmap!{
            Label::from([0]) => LabeledTree::Leaf(vec![0]),
        })
    });

    test_membership_witness(&t, rng);
}

#[test]
fn test_simple_tree() {
    let rng = &mut reproducible_rng();
    let t = LabeledTree::SubTree(flatmap! {
        Label::from("a") => LabeledTree::Leaf(b"12345".to_vec()),
        Label::from("b") => LabeledTree::SubTree(flatmap! {
            Label::from("c") => LabeledTree::Leaf(b"abcde".to_vec()),
            Label::from("d") => LabeledTree::Leaf(b"abdde".to_vec()),
            Label::from("e") => LabeledTree::Leaf(b"abede".to_vec()),
            Label::from("f") => LabeledTree::Leaf(b"abfde".to_vec()),
        }),
    });

    test_membership_witness(&t, rng);
}

#[test]
fn test_many_children() {
    let rng = &mut reproducible_rng();
    let vec: Vec<(Label, LabeledTree<_>)> = (1..1000)
        .map(|i| Label::from(i.to_string()))
        .zip(std::iter::repeat(LabeledTree::Leaf(b"abcde".to_vec())))
        .collect::<Vec<_>>();
    let large_flatmap = FlatMap::from_key_values(vec);
    let t = LabeledTree::SubTree(flatmap! {
        Label::from("a") => LabeledTree::SubTree(large_flatmap.clone()),
        Label::from("c") => LabeledTree::SubTree(large_flatmap),
    });

    test_membership_witness(&t, rng);
}

#[test]
fn test_too_many_recursions_error() {
    // No error at the maximum allowed depth
    let mut tree = LabeledTree::Leaf(b"12345".to_vec());
    for i in 1..=MAX_RECURSION_DEPTH {
        tree = LabeledTree::SubTree(flatmap! {
            Label::from(i.to_string()) => tree,
        });
    }

    assert!(hash_lazy_tree(&as_lazy(&tree)).is_ok());

    // Error with one extra depth
    tree = LabeledTree::SubTree(flatmap! {
        Label::from(b"BOOM") => tree,
    });

    assert_matches!(
        hash_lazy_tree(&as_lazy(&tree)),
        Err(HashTreeError::RecursionTooDeep(MAX_RECURSION_DEPTH))
    );
}

#[test]
fn test_non_existence_proof() {
    let t = LabeledTree::SubTree(flatmap! {
        Label::from("a") => LabeledTree::Leaf(b"12345".to_vec()),
        Label::from("c") => LabeledTree::SubTree(flatmap! {
            Label::from("c") => LabeledTree::Leaf(b"abcde".to_vec()),
            Label::from("d") => LabeledTree::Leaf(b"abdde".to_vec()),
            Label::from("e") => LabeledTree::Leaf(b"abede".to_vec()),
            Label::from("f") => LabeledTree::Leaf(b"abfde".to_vec()),
        }),
    });

    let hash_tree = hash_lazy_tree(&as_lazy(&t)).unwrap();
    let ht_witness = hash_tree
        .witness::<MixedHashTree>(&LabeledTree::SubTree(
            flatmap! { Label::from("Z") => LabeledTree::Leaf(b"12345".to_vec()) },
        ))
        .expect("Failed to generate witness.");

    assert_eq!(&ht_witness.digest(), hash_tree.root_hash());

    assert!(
        ht_witness.lookup(&[b"Z"]).is_absent(),
        "witness: {ht_witness:?}"
    );
    assert!(
        ht_witness.lookup(&[b"a"]).is_found(),
        "witness: {ht_witness:?}"
    );
    assert!(
        ht_witness.lookup(&[b"c"]).is_unknown(),
        "witness: {ht_witness:?}"
    );

    let ht_witness = hash_tree
        .witness::<MixedHashTree>(&LabeledTree::SubTree(
            flatmap! { Label::from("b") => LabeledTree::Leaf(b"12345".to_vec()) },
        ))
        .expect("Failed to generate witness.");

    assert_eq!(&ht_witness.digest(), hash_tree.root_hash());

    assert!(
        ht_witness.lookup(&[b"a"]).is_found(),
        "witness: {ht_witness:?}"
    );
    assert!(
        ht_witness.lookup(&[b"b"]).is_absent(),
        "witness: {ht_witness:?}"
    );
    assert!(
        ht_witness.lookup(&[b"c"]).is_found(),
        "witness: {ht_witness:?}"
    );

    let ht_witness = hash_tree
        .witness::<MixedHashTree>(&LabeledTree::SubTree(
            flatmap! { Label::from("d") => LabeledTree::Leaf(b"12345".to_vec()) },
        ))
        .expect("Failed to generate witness.");

    assert_eq!(&ht_witness.digest(), hash_tree.root_hash());

    assert!(
        ht_witness.lookup(&[b"a"]).is_unknown(),
        "witness: {ht_witness:?}"
    );
    assert!(
        ht_witness.lookup(&[b"c"]).is_found(),
        "witness: {ht_witness:?}"
    );
    assert!(
        ht_witness.lookup(&[b"d"]).is_absent(),
        "witness: {ht_witness:?}"
    );
}

#[test_strategy::proptest]
fn same_witness(
    #[strategy(arbitrary_labeled_tree())] t: LabeledTree<Vec<u8>>,
    #[strategy(prop::array::uniform32(any::<u8>()))] seed: [u8; 32],
) {
    let rng = &mut ChaCha20Rng::from_seed(seed);
    test_membership_witness(&t, rng);
}
