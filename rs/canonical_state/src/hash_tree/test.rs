use super::*;
use crate::lazy_tree::LazyFork;
use assert_matches::assert_matches;
use crypto::recompute_digest;
use ic_base_types::NumBytes;
use ic_crypto_tree_hash::{
    flatmap, FlatMap, HashTreeBuilder, HashTreeBuilderImpl, Label, LabeledTree, MixedHashTree,
    Witness, WitnessGenerator, WitnessGeneratorImpl,
};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::ReplicatedState;
use ic_test_utilities::{
    mock_time,
    state::insert_dummy_canister,
    types::ids::{canister_test_id, message_test_id, subnet_test_id, user_test_id},
};
use ic_types::ingress::{IngressState, IngressStatus, WasmResult};
use proptest::prelude::*;
use std::sync::Arc;

fn arbitrary_leaf() -> impl Strategy<Value = LabeledTree<Vec<u8>>> {
    prop::collection::vec(any::<u8>(), 1..100).prop_map(LabeledTree::Leaf)
}

fn arbitrary_labeled_tree() -> impl Strategy<Value = LabeledTree<Vec<u8>>> {
    arbitrary_leaf().prop_recursive(
        /* depth= */ 4,
        /* max_size= */ 1000,
        /* items_per_collection= */ 130,
        |inner| {
            prop::collection::btree_map(
                prop::collection::vec(any::<u8>(), 1..15).prop_map(Label::from),
                inner,
                0..130,
            )
            .prop_map(|children| {
                LabeledTree::SubTree(FlatMap::from_key_values(children.into_iter().collect()))
            })
        },
    )
}

struct FlatMapFork<'a>(&'a FlatMap<Label, LabeledTree<Vec<u8>>>);

impl<'a> LazyFork<'a> for FlatMapFork<'a> {
    fn edge(&self, l: &Label) -> Option<LazyTree<'a>> {
        self.0.get(l).map(as_lazy)
    }

    fn labels(&self) -> Box<dyn Iterator<Item = Label> + '_> {
        Box::new(self.0.keys().iter().cloned())
    }

    fn children(&self) -> Box<dyn Iterator<Item = (Label, LazyTree<'a>)> + 'a> {
        Box::new(self.0.iter().map(|(l, t)| (l.clone(), as_lazy(t))))
    }

    fn len(&self) -> usize {
        self.0.len()
    }
}

fn as_lazy(t: &LabeledTree<Vec<u8>>) -> LazyTree<'_> {
    match t {
        LabeledTree::Leaf(b) => LazyTree::Blob(&b[..], None),
        LabeledTree::SubTree(cs) => LazyTree::LazyFork(Arc::new(FlatMapFork(cs))),
    }
}

fn build_witness_gen(t: &LabeledTree<Vec<u8>>) -> WitnessGeneratorImpl {
    fn go(t: &LabeledTree<Vec<u8>>, b: &mut HashTreeBuilderImpl) {
        match t {
            LabeledTree::Leaf(bytes) => {
                b.start_leaf();
                b.write_leaf(&bytes[..]);
                b.finish_leaf();
            }
            LabeledTree::SubTree(cs) => {
                b.start_subtree();
                for (k, v) in cs.iter() {
                    b.new_edge(k.as_bytes());
                    go(v, b);
                }
                b.finish_subtree();
            }
        }
    }
    let mut builder = HashTreeBuilderImpl::new();
    go(t, &mut builder);
    builder.witness_generator().unwrap()
}

fn enumerate_leaves_and_empty_subtrees(
    t: &LabeledTree<Vec<u8>>,
    mut f: impl FnMut(LabeledTree<Vec<u8>>),
) {
    fn go<'a>(
        t: &'a LabeledTree<Vec<u8>>,
        path: &mut Vec<&'a Label>,
        f: &mut impl FnMut(LabeledTree<Vec<u8>>),
    ) {
        match t {
            LabeledTree::SubTree(children) if !children.is_empty() => {
                for (k, v) in children.iter() {
                    path.push(k);
                    go(v, path, f);
                    path.pop();
                }
            }
            LabeledTree::Leaf(_) | LabeledTree::SubTree(_) => {
                let subtree = path.iter().rev().fold(t.clone(), |acc, &label| {
                    LabeledTree::SubTree(flatmap! {
                        label.clone() => acc,
                    })
                });
                f(subtree)
            }
        }
    }
    let mut path = vec![];
    go(t, &mut path, &mut f)
}

fn assert_same_witness(ht: &HashTree, wg: &WitnessGeneratorImpl, data: &LabeledTree<Vec<u8>>) {
    let ht_witness = ht
        .witness::<Witness>(data)
        .expect("Failed to construct a witness.");
    let wg_witness = wg.witness(data).expect("failed to construct a witness");

    assert_eq!(
        wg_witness, ht_witness,
        "labeled tree: {:?}, hash_tree: {:?}",
        data, ht
    );

    assert_eq!(
        recompute_digest(data, &wg_witness).unwrap(),
        recompute_digest(data, &ht_witness).unwrap()
    );
}

/// Check that for each leaf or empty subtree, and the tree as a whole, the
/// witness looks the same as with the old way of generating witnesses.
///
/// Also check that the new and old way of computing hash trees are equivalent.
fn test_tree(t: &LabeledTree<Vec<u8>>) {
    let hash_tree = hash_lazy_tree(&as_lazy(t)).unwrap();
    let witness_gen = build_witness_gen(t);
    enumerate_leaves_and_empty_subtrees(t, |subtree| {
        assert_same_witness(&hash_tree, &witness_gen, &subtree);
    });

    assert_same_witness(&hash_tree, &witness_gen, t);

    let crypto_tree = crypto_hash_lazy_tree(&as_lazy(t));
    assert_eq!(hash_tree, crypto_tree);
}

#[test]
fn test_empty_subtree() {
    let t = LabeledTree::SubTree(flatmap! {});

    test_tree(&t);
}

#[test]
fn test_one_level_tree() {
    let t = LabeledTree::SubTree(flatmap! {
        Label::from([0]) => LabeledTree::SubTree(flatmap!{
            Label::from([0]) => LabeledTree::Leaf(vec![0]),
        })
    });

    test_tree(&t);
}

#[test]
fn test_simple_tree() {
    let t = LabeledTree::SubTree(flatmap! {
        Label::from("a") => LabeledTree::Leaf(b"12345".to_vec()),
        Label::from("b") => LabeledTree::SubTree(flatmap! {
            Label::from("c") => LabeledTree::Leaf(b"abcde".to_vec()),
            Label::from("d") => LabeledTree::Leaf(b"abdde".to_vec()),
            Label::from("e") => LabeledTree::Leaf(b"abede".to_vec()),
            Label::from("f") => LabeledTree::Leaf(b"abfde".to_vec()),
        }),
    });

    test_tree(&t);
}

#[test]
fn test_many_children() {
    let vec: Vec<(Label, LabeledTree<_>)> = (1..1000)
        .map(|i| Label::from(i.to_string()))
        .zip(std::iter::repeat(LabeledTree::Leaf(b"abcde".to_vec())))
        .collect::<Vec<_>>();
    let large_flatmap = FlatMap::from_key_values(vec);
    let t = LabeledTree::SubTree(flatmap! {
        Label::from("a") => LabeledTree::SubTree(large_flatmap.clone()),
        Label::from("c") => LabeledTree::SubTree(large_flatmap),
    });

    test_tree(&t);
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
        "witness: {:?}",
        ht_witness
    );
    assert!(
        ht_witness.lookup(&[b"a"]).is_found(),
        "witness: {:?}",
        ht_witness
    );
    assert!(
        ht_witness.lookup(&[b"c"]).is_unknown(),
        "witness: {:?}",
        ht_witness
    );

    let ht_witness = hash_tree
        .witness::<MixedHashTree>(&LabeledTree::SubTree(
            flatmap! { Label::from("b") => LabeledTree::Leaf(b"12345".to_vec()) },
        ))
        .expect("Failed to generate witness.");

    assert_eq!(&ht_witness.digest(), hash_tree.root_hash());

    assert!(
        ht_witness.lookup(&[b"a"]).is_found(),
        "witness: {:?}",
        ht_witness
    );
    assert!(
        ht_witness.lookup(&[b"b"]).is_absent(),
        "witness: {:?}",
        ht_witness
    );
    assert!(
        ht_witness.lookup(&[b"c"]).is_found(),
        "witness: {:?}",
        ht_witness
    );

    let ht_witness = hash_tree
        .witness::<MixedHashTree>(&LabeledTree::SubTree(
            flatmap! { Label::from("d") => LabeledTree::Leaf(b"12345".to_vec()) },
        ))
        .expect("Failed to generate witness.");

    assert_eq!(&ht_witness.digest(), hash_tree.root_hash());

    assert!(
        ht_witness.lookup(&[b"a"]).is_unknown(),
        "witness: {:?}",
        ht_witness
    );
    assert!(
        ht_witness.lookup(&[b"c"]).is_found(),
        "witness: {:?}",
        ht_witness
    );
    assert!(
        ht_witness.lookup(&[b"d"]).is_absent(),
        "witness: {:?}",
        ht_witness
    );
}

proptest! {
    #[test]
    fn same_witness(t in arbitrary_labeled_tree()) {
        test_tree(&t);
    }
}

#[test]
fn simple_state_old_vs_new_hashing() {
    let state = ReplicatedState::new(subnet_test_id(1), SubnetType::Application);

    let hash_tree = hash_lazy_tree(&LazyTree::from(&state)).unwrap();
    let crypto_hash_tree = crypto_hash_lazy_tree(&LazyTree::from(&state));

    assert_eq!(hash_tree, crypto_hash_tree);
}

#[test]
fn many_canister_state_old_vs_new_hashing() {
    let mut state = ReplicatedState::new(subnet_test_id(1), SubnetType::Application);
    for i in 1..1000 {
        insert_dummy_canister(&mut state, canister_test_id(i), user_test_id(24).get());
    }

    let hash_tree = hash_lazy_tree(&LazyTree::from(&state)).unwrap();
    let crypto_hash_tree = crypto_hash_lazy_tree(&LazyTree::from(&state));

    assert_eq!(hash_tree, crypto_hash_tree);
}

#[test]
fn large_history_state_old_vs_new_hashing() {
    let mut state = ReplicatedState::new(subnet_test_id(1), SubnetType::Application);
    for i in 1..1000 {
        state.set_ingress_status(
            message_test_id(i),
            IngressStatus::Known {
                receiver: canister_test_id(i).get(),
                user_id: user_test_id(i),
                time: mock_time(),
                state: IngressState::Completed(WasmResult::Reply(b"done".to_vec())),
            },
            NumBytes::from(u64::MAX),
        );
    }

    let hash_tree = hash_lazy_tree(&LazyTree::from(&state)).unwrap();
    let crypto_hash_tree = crypto_hash_lazy_tree(&LazyTree::from(&state));

    assert_eq!(hash_tree, crypto_hash_tree);
}

#[test]
fn large_history_and_canisters_state_old_vs_new_hashing() {
    let mut state = ReplicatedState::new(subnet_test_id(1), SubnetType::Application);
    for i in 1..1000 {
        insert_dummy_canister(&mut state, canister_test_id(i), user_test_id(24).get());

        state.set_ingress_status(
            message_test_id(i),
            IngressStatus::Known {
                receiver: canister_test_id(i).get(),
                user_id: user_test_id(i),
                time: mock_time(),
                state: IngressState::Completed(WasmResult::Reply(b"done".to_vec())),
            },
            NumBytes::from(u64::MAX),
        );
    }

    let hash_tree = hash_lazy_tree(&LazyTree::from(&state)).unwrap();
    let crypto_hash_tree = crypto_hash_lazy_tree(&LazyTree::from(&state));

    assert_eq!(hash_tree, crypto_hash_tree);
}
