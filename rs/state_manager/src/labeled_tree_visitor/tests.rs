use super::*;
use ic_canonical_state::visitor::{named_blob, named_num, named_subtree, subtree};
use ic_crypto_tree_hash::{flatmap, FlatMap, LabeledTree::*};
use proptest::prelude::*;

// Sample tree traversal:
//
// *
// |
// +- blobs
// |  +- cafebabe → [0xcafebabe]
// |  `- deadbeef → [0xdeadbeef]
// `- nums
//    +- 1 → 1
//    `- 2 → 2
fn traverse_sample_tree<V: Visitor>(mut v: V) -> V::Output {
    let cafebabe = [0xca, 0xfe, 0xba, 0xbe];
    let deadbeef = [0xde, 0xad, 0xbe, 0xef];

    let t = subtree(&mut v, |v| {
        named_subtree(v, "blobs", |v| {
            named_blob(v, "cafebabe", &cafebabe[..])?;
            named_blob(v, "deadbeef", &deadbeef[..])
        })?;
        named_subtree(v, "nums", |v| {
            named_num(v, "1", 1)?;
            named_num(v, "2", 2)
        })
    });

    match t {
        Err(output) => output,
        _ => v.finish(),
    }
}

fn traverse_labeled_tree<V: Visitor>(
    t: &LabeledTree<Vec<u8>>,
    visitor: &mut V,
) -> Result<(), V::Output> {
    match t {
        Leaf(v) => visitor.visit_blob(&v[..]),
        SubTree(t) => {
            visitor.start_subtree()?;
            for (k, v) in t.iter() {
                match visitor.enter_edge(k.as_bytes())? {
                    Control::Continue => traverse_labeled_tree(v, visitor)?,
                    Control::Skip => continue,
                }
            }
            visitor.end_subtree()
        }
    }
}

#[test]
fn sample_traversal_produces_a_map() {
    assert_eq!(
        traverse_sample_tree(LabeledTreeVisitor::default()),
        SubTree(flatmap![
            Label::from("blobs") => SubTree(flatmap![
                Label::from("cafebabe") => Leaf(vec![0xca, 0xfe, 0xba, 0xbe]),
                Label::from("deadbeef") => Leaf(vec![0xde, 0xad, 0xbe, 0xef]),
            ]),
            Label::from("nums") => SubTree(flatmap![
                Label::from("1") => Leaf(1u64.to_be_bytes().to_vec()),
                Label::from("2") => Leaf(2u64.to_be_bytes().to_vec()),
            ]),
        ])
    );
}

#[test]
#[should_panic(expected = "empty")]
fn empty_tree_traversal_yields_null() {
    LabeledTreeVisitor::default().finish();
}

#[test]
fn traverse_no_leaves() {
    let mut v = LabeledTreeVisitor::default();

    let _ = subtree(&mut v, |v| named_subtree(v, "test", |_| Ok(())));

    assert_eq!(
        SubTree(flatmap![Label::from("test") => SubTree(flatmap![])]),
        v.finish()
    );
}

fn arb_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 2..10)
}

fn arb_label() -> impl Strategy<Value = Label> {
    arb_bytes().prop_map(Label::from)
}

fn arb_tree() -> impl Strategy<Value = LabeledTree<Vec<u8>>> {
    arb_bytes().prop_map(Leaf).prop_recursive(
        /* levels */ 3,
        /* max nodes */ 32,
        /* items per collection */ 10,
        |inner| {
            prop::collection::vec((arb_label(), inner), 1..10)
                .prop_map(|kv| SubTree(FlatMap::from_key_values(kv)))
        },
    )
}

proptest! {
    #[test]
    fn roundtrip(t in arb_tree()) {
        let mut v = LabeledTreeVisitor::default();
        let _ = traverse_labeled_tree(&t, &mut v);
        prop_assert_eq!(v.finish(), t);
    }
}
