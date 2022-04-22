use super::*;
use crate::lazy_tree::LazyFork;
use ic_crypto_tree_hash::{
    flatmap, lookup_path, FlatMap, HashTreeBuilder, HashTreeBuilderImpl, Label, LabeledTree,
    MixedHashTree, Witness, WitnessGenerator, WitnessGeneratorImpl,
};
use proptest::prelude::*;
use std::convert::TryInto;
use std::sync::Arc;

fn arbitrary_leaf() -> impl Strategy<Value = LabeledTree<Vec<u8>>> {
    prop::collection::vec(any::<u8>(), 1..100).prop_map(LabeledTree::Leaf)
}

fn arbitrary_labeled_tree() -> impl Strategy<Value = LabeledTree<Vec<u8>>> {
    arbitrary_leaf().prop_recursive(
        /* depth= */ 4,
        /* max_size= */ 256,
        /* items_per_collection= */ 10,
        |inner| {
            prop::collection::btree_map(
                prop::collection::vec(any::<u8>(), 1..15).prop_map(Label::from),
                inner,
                0..10,
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
}

fn as_lazy(t: &LabeledTree<Vec<u8>>) -> LazyTree<'_> {
    match t {
        LabeledTree::Leaf(b) => LazyTree::Blob(&b[..]),
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

fn enumerate_leaves(t: &LabeledTree<Vec<u8>>, mut f: impl FnMut(LabeledTree<Vec<u8>>)) {
    fn go<'a>(
        t: &'a LabeledTree<Vec<u8>>,
        path: &mut Vec<&'a Label>,
        f: &mut impl FnMut(LabeledTree<Vec<u8>>),
    ) {
        match t {
            LabeledTree::Leaf(_) => {
                let mut subtree = t.clone();
                #[allow(clippy::unnecessary_to_owned)]
                for label in path.iter().rev().cloned() {
                    subtree = LabeledTree::SubTree(flatmap! {
                        label.clone() => subtree,
                    });
                }
                f(subtree)
            }
            LabeledTree::SubTree(children) => {
                for (k, v) in children.iter() {
                    path.push(k);
                    go(v, path, f);
                    path.pop();
                }
            }
        }
    }
    let mut path = vec![];
    go(t, &mut path, &mut f)
}

fn assert_same_witness(ht: &HashTree, wg: &WitnessGeneratorImpl, data: &LabeledTree<Vec<u8>>) {
    let ht_witness = ht.witness::<Witness>(data);
    let wg_witness = wg.witness(data).expect("failed to construct a witness");
    assert_eq!(
        wg_witness, ht_witness,
        "labeled tree: {:?}, hash_tree: {:?}",
        data, ht
    )
}

#[test]
fn test_one_level_tree() {
    let t = LabeledTree::SubTree(flatmap! {
        Label::from([0]) => LabeledTree::SubTree(flatmap!{
            Label::from([0]) => LabeledTree::Leaf(vec![0]),
        })
    });
    let hash_tree = hash_lazy_tree(&as_lazy(&t));
    let witness_gen = build_witness_gen(&t);
    assert_same_witness(&hash_tree, &witness_gen, &t);
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

    let hash_tree = hash_lazy_tree(&as_lazy(&t));
    let witness_gen = build_witness_gen(&t);
    enumerate_leaves(&t, |subtree| {
        assert_same_witness(&hash_tree, &witness_gen, &subtree);
    })
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

    let hash_tree = hash_lazy_tree(&as_lazy(&t));
    let ht_witness = hash_tree.witness::<MixedHashTree>(&LabeledTree::SubTree(
        flatmap! { Label::from("Z") => LabeledTree::Leaf(b"12345".to_vec()) },
    ));

    assert_eq!(&ht_witness.digest(), hash_tree.root_hash());

    let t: LabeledTree<_> = ht_witness.clone().try_into().unwrap();
    assert!(
        lookup_path(&t, &[b"Z"]).is_none(),
        "witness: {:?}",
        ht_witness
    );
    assert!(
        lookup_path(&t, &[b"a"]).is_some(),
        "witness: {:?}",
        ht_witness
    );
    assert!(
        lookup_path(&t, &[b"c"]).is_none(),
        "witness: {:?}",
        ht_witness
    );

    let ht_witness = hash_tree.witness::<MixedHashTree>(&LabeledTree::SubTree(
        flatmap! { Label::from("b") => LabeledTree::Leaf(b"12345".to_vec()) },
    ));

    assert_eq!(&ht_witness.digest(), hash_tree.root_hash());

    let t: LabeledTree<_> = ht_witness.clone().try_into().unwrap();
    assert!(
        lookup_path(&t, &[b"a"]).is_some(),
        "witness: {:?}",
        ht_witness
    );
    assert!(
        lookup_path(&t, &[b"b"]).is_none(),
        "witness: {:?}",
        ht_witness
    );
    assert!(
        lookup_path(&t, &[b"c"]).is_some(),
        "witness: {:?}",
        ht_witness
    );

    let ht_witness = hash_tree.witness::<MixedHashTree>(&LabeledTree::SubTree(
        flatmap! { Label::from("d") => LabeledTree::Leaf(b"12345".to_vec()) },
    ));

    assert_eq!(&ht_witness.digest(), hash_tree.root_hash());

    let t: LabeledTree<_> = ht_witness.clone().try_into().unwrap();
    assert!(
        lookup_path(&t, &[b"a"]).is_none(),
        "witness: {:?}",
        ht_witness
    );
    assert!(
        lookup_path(&t, &[b"c"]).is_some(),
        "witness: {:?}",
        ht_witness
    );
    assert!(
        lookup_path(&t, &[b"d"]).is_none(),
        "witness: {:?}",
        ht_witness
    );
}

proptest! {
    #[test]
    fn same_witness_on_all_leaves(t in arbitrary_labeled_tree()) {
        let hash_tree = hash_lazy_tree(&as_lazy(&t));
        let witness_gen = build_witness_gen(&t);
        enumerate_leaves(&t, |subtree| {
            assert_same_witness(&hash_tree, &witness_gen, &subtree);
        });
    }
}
