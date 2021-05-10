use crate::{Digest, Label, MixedHashTree as T};
use proptest::prelude::*;

pub(crate) fn arbitrary_leaf() -> impl Strategy<Value = T> {
    prop::collection::vec(any::<u8>(), 1..100).prop_map(T::Leaf)
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
            T::Fork(ref mut lr) => {
                relabel(&mut lr.0, id);
                relabel(&mut lr.1, id);
            }
            T::Labeled(ref mut l, ref mut t) => {
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

pub(crate) fn arbitrary_mixed_hash_tree() -> impl Strategy<Value = T> {
    let leaf = prop_oneof![
        Just(T::Empty),
        arbitrary_leaf(),
        any::<[u8; 32]>().prop_map(Digest).prop_map(T::Pruned),
    ];

    leaf.prop_recursive(
        /* depth= */ 8,
        /* max_size= */ 256,
        /* items_per_collection= */ 10,
        |inner| {
            prop_oneof![
                (inner.clone(), inner.clone()).prop_map(|(l, r)| T::Fork(Box::new((l, r)))),
                (".*", inner).prop_map(|(l, t)| T::Labeled(Label::from(l), Box::new(t))),
            ]
        },
    )
    .prop_map(fix_labels)
}

pub(crate) fn arbitrary_well_formed_mixed_hash_tree() -> impl Strategy<Value = T> {
    let labeled_leaf = (".*", arbitrary_leaf())
        .prop_map(|(label, leaf)| T::Labeled(Label::from(label), Box::new(leaf)));
    let tree = labeled_leaf.prop_recursive(
        /* depth= */ 5,
        /* max_size= */ 64,
        /* items_per_collection */ 5,
        |inner| {
            prop_oneof![
                (inner.clone(), inner.clone()).prop_map(|(l, r)| T::Fork(Box::new((l, r)))),
                (".*", inner).prop_map(|(label, t)| T::Labeled(Label::from(label), Box::new(t))),
            ]
        },
    );

    prop_oneof![Just(T::Empty), arbitrary_leaf(), tree,].prop_map(fix_labels)
}
