use ic_crypto_tree_hash::{Digest, FlatMap, Label, LabeledTree, MixedHashTree as T, flatmap};
use proptest::collection::btree_map;
use proptest::prelude::*;

pub fn arbitrary_mixed_hash_tree_leaf() -> impl Strategy<Value = T> {
    prop::collection::vec(any::<u8>(), 0..100).prop_map(T::Leaf)
}

/// Changes labels in the tree without changing the tree structure.
/// This is needed to make randomly generated trees satisfy type invariants:
/// labels must be unique and sorted.
fn fix_labels(mut t: T) -> T {
    fn prepend(l: &mut Label, n: u64) {
        let mut buf = n.to_be_bytes().to_vec();
        buf.extend_from_slice(l.as_bytes());
        *l = Label::from(buf);
    }
    fn relabel(t: &mut T, id: &mut u64) {
        match t {
            T::Empty | T::Leaf(_) | T::Pruned(_) => (),
            T::Fork(lr) => {
                relabel(&mut lr.0, id);
                relabel(&mut lr.1, id);
            }
            T::Labeled(l, t) => {
                prepend(l, *id);
                *id += 1;
                relabel(t, id);
            }
        }
    }

    let mut id = 0;
    relabel(&mut t, &mut id);
    t
}

pub fn arbitrary_mixed_hash_tree() -> impl Strategy<Value = T> {
    let leaf = prop_oneof![
        Just(T::Empty),
        arbitrary_mixed_hash_tree_leaf(),
        any::<[u8; 32]>().prop_map(Digest).prop_map(T::Pruned),
    ];

    leaf.prop_recursive(
        /* depth= */ 8,
        /* max_size= */ 256,
        /* items_per_collection= */ 1,
        |inner| {
            prop_oneof![
                (inner.clone(), inner.clone()).prop_map(|(l, r)| T::Fork(Box::new((l, r)))),
                (".*", inner).prop_map(|(l, t)| T::Labeled(Label::from(l), Box::new(t))),
            ]
        },
    )
    .prop_map(fix_labels)
}

pub fn arbitrary_well_formed_mixed_hash_tree() -> impl Strategy<Value = T> {
    arbitrary_well_formed_mixed_hash_tree_with_params(8, 256, 1)
}

pub fn arbitrary_well_formed_mixed_hash_tree_with_params(
    max_depth: u32,
    expected_size: u32,
    expected_items_per_collection: u32,
) -> impl Strategy<Value = T> {
    let labeled_leaf = (
        ".*",
        prop_oneof!(arbitrary_mixed_hash_tree_leaf(), Just(T::Empty)),
    )
        .prop_map(|(label, leaf)| T::Labeled(Label::from(label), Box::new(leaf)));
    let tree = labeled_leaf.prop_recursive(
        max_depth,
        expected_size,
        expected_items_per_collection,
        |inner| {
            prop_oneof![
                3 => (inner.clone(), inner.clone()).prop_map(|(l, r)| T::Fork(Box::new((l, r)))),
                1 => (".*", inner).prop_map(|(label, t)| T::Labeled(Label::from(label), Box::new(t))),
            ]
        },
    );

    prop_oneof![Just(T::Empty), arbitrary_mixed_hash_tree_leaf(), tree,].prop_map(fix_labels)
}

pub fn arbitrary_labeled_tree() -> impl Strategy<Value = LabeledTree<Vec<u8>>> {
    let leaf = prop_oneof![
        Just(LabeledTree::SubTree::<Vec<u8>>(flatmap!())),
        arbitrary_labeled_tree_leaf(),
    ];
    leaf.prop_recursive(
        /* depth= */ 8,
        /* max_size= */ 256,
        /* items_per_collection= */ 3,
        |inner| {
            prop_oneof![
                (btree_map(arbitrary_label(), inner.clone(), 1..10)).prop_map(|m| {
                    LabeledTree::SubTree(FlatMap::from_key_values(
                        m.iter().map(|(l, t)| (l.clone(), t.clone())).collect(),
                    ))
                }),
                inner.prop_map(|t| t),
            ]
        },
    )
}

pub fn arbitrary_label() -> impl Strategy<Value = Label> {
    prop::collection::vec(any::<u8>(), 0..100).prop_map(Label::from)
}

pub fn arbitrary_labeled_tree_leaf() -> impl Strategy<Value = LabeledTree<Vec<u8>>> {
    prop::collection::vec(any::<u8>(), 0..100).prop_map(LabeledTree::Leaf)
}
