//! Tests for reusable subtree nodes.
//!
//! When building a [`HashTree`] from a [`LazyTree`], every subtree that carries
//! a [`LazyFork::subtree_id`] (here a per-canister fork, mirroring `CanisterFork`
//! in production) is built as a standalone tree and stored as a self-contained
//! [`NodeKind::Subtree`] node holding an `Arc<HashTree>`. Such a tree:
//!
//!   * has the exact same root hash as a fully materialized build, and
//!   * serves witnesses without any external source (it is self-contained), and
//!   * when built with a baseline ([`hash_lazy_tree_with_baseline`]), reuses the
//!     `Arc<HashTree>` of every unchanged subtree (matched by `SubtreeId`).

use ic_canonical_state_tree_hash::hash_tree::{
    HashTree, hash_lazy_tree, hash_lazy_tree_with_baseline,
};
use ic_canonical_state_tree_hash::lazy_tree::{LazyFork, LazyTree, SubtreeId, fork};
use ic_canonical_state_tree_hash_test_utils::as_lazy;
use ic_crypto_tree_hash::{FlatMap, Label, LabeledTree, MixedHashTree, Witness, flatmap};
use std::collections::BTreeMap;
use std::sync::Arc;

const CANISTER_LABEL: &[u8] = b"canister";
const TIME_LABEL: &[u8] = b"time";

/// Number of canisters; >100 so that the parallel build path is exercised.
const NUM_CANISTERS: usize = 150;

const TIME: &[u8] = &[1, 2, 3, 4];

fn certified_data(i: usize) -> Vec<u8> {
    vec![i as u8; 4]
}
fn controllers(i: usize) -> Vec<u8> {
    format!("controllers-{i}").into_bytes()
}
fn custom_section(i: usize) -> Vec<u8> {
    format!("section-{i}").into_bytes()
}
fn module_hash(i: usize) -> Vec<u8> {
    vec![(i % 251) as u8; 32]
}

fn canister_id_label(i: usize) -> Label {
    Label::from(format!("{i:04}"))
}

/// The certified subtree of a single canister (mirrors the real canonical
/// encoding: certified_data, controllers, metadata, module_hash).
fn canister_subtree(i: usize) -> LabeledTree<Vec<u8>> {
    LabeledTree::SubTree(flatmap! {
        Label::from("certified_data") => LabeledTree::Leaf(certified_data(i)),
        Label::from("controllers") => LabeledTree::Leaf(controllers(i)),
        Label::from("metadata") => LabeledTree::SubTree(flatmap!{
            Label::from("public_section") => LabeledTree::Leaf(custom_section(i)),
        }),
        Label::from("module_hash") => LabeledTree::Leaf(module_hash(i)),
    })
}

/// A collection of canisters, each behind its own `Arc` (as in production).
type Canisters = BTreeMap<Label, Arc<LabeledTree<Vec<u8>>>>;

fn canisters() -> Canisters {
    (0..NUM_CANISTERS)
        .map(|i| (canister_id_label(i), Arc::new(canister_subtree(i))))
        .collect()
}

/// A `LazyFork` over the certified subtree of a single canister.
///
/// `subtree_id` mirrors `CanisterFork::subtree_id` in production: it returns the
/// identity of the backing `Arc`, so each canister is stored as a self-contained,
/// reusable subtree node.
struct CanisterArcFork<'a> {
    canister: &'a Arc<LabeledTree<Vec<u8>>>,
}

impl<'a> CanisterArcFork<'a> {
    fn children_map(&self) -> &'a FlatMap<Label, LabeledTree<Vec<u8>>> {
        match &**self.canister {
            LabeledTree::SubTree(cs) => cs,
            LabeledTree::Leaf(_) => panic!("a canister must be a subtree"),
        }
    }
}

impl<'a> LazyFork<'a> for CanisterArcFork<'a> {
    fn edge(&self, l: &Label) -> Option<LazyTree<'a>> {
        self.children_map().get(l).map(as_lazy)
    }

    fn labels(&self) -> Box<dyn Iterator<Item = Label> + '_> {
        Box::new(self.children_map().keys().iter().cloned())
    }

    fn children(&self) -> Box<dyn Iterator<Item = (Label, LazyTree<'a>)> + 'a> {
        Box::new(self.children_map().iter().map(|(l, t)| (l.clone(), as_lazy(t))))
    }

    fn len(&self) -> usize {
        self.children_map().len()
    }

    fn subtree_id(&self) -> Option<SubtreeId> {
        Some(SubtreeId::new(Arc::clone(self.canister)))
    }
}

/// A `LazyFork` over the `/canister` subtree.
struct CanistersFork<'a> {
    canisters: &'a Canisters,
}

fn canister_fork(arc: &Arc<LabeledTree<Vec<u8>>>) -> LazyTree<'_> {
    fork(CanisterArcFork { canister: arc })
}

impl<'a> LazyFork<'a> for CanistersFork<'a> {
    fn edge(&self, l: &Label) -> Option<LazyTree<'a>> {
        self.canisters.get(l).map(canister_fork)
    }

    fn labels(&self) -> Box<dyn Iterator<Item = Label> + '_> {
        Box::new(self.canisters.keys().cloned())
    }

    fn children(&self) -> Box<dyn Iterator<Item = (Label, LazyTree<'a>)> + 'a> {
        Box::new(
            self.canisters
                .iter()
                .map(|(l, arc)| (l.clone(), canister_fork(arc))),
        )
    }

    fn len(&self) -> usize {
        self.canisters.len()
    }
}

/// The top-level state fork: `{canister: {...}, time: <blob>}`.
struct StateFork<'a> {
    canisters: &'a Canisters,
    time: &'a [u8],
}

fn canisters_fork(canisters: &Canisters) -> LazyTree<'_> {
    fork(CanistersFork { canisters })
}

impl<'a> LazyFork<'a> for StateFork<'a> {
    fn edge(&self, l: &Label) -> Option<LazyTree<'a>> {
        match l.as_bytes() {
            CANISTER_LABEL => Some(canisters_fork(self.canisters)),
            TIME_LABEL => Some(LazyTree::Blob(self.time, None)),
            _ => None,
        }
    }

    fn labels(&self) -> Box<dyn Iterator<Item = Label> + '_> {
        Box::new([Label::from(CANISTER_LABEL), Label::from(TIME_LABEL)].into_iter())
    }

    fn children(&self) -> Box<dyn Iterator<Item = (Label, LazyTree<'a>)> + 'a> {
        Box::new(
            [
                (Label::from(CANISTER_LABEL), canisters_fork(self.canisters)),
                (Label::from(TIME_LABEL), LazyTree::Blob(self.time, None)),
            ]
            .into_iter(),
        )
    }

    fn len(&self) -> usize {
        2
    }
}

/// A `LazyTree` over the whole state.
fn state_tree<'a>(canisters: &'a Canisters, time: &'a [u8]) -> LazyTree<'a> {
    fork(StateFork { canisters, time })
}

/// Asserts that `tree` produces exactly the same witness (both as
/// `MixedHashTree` and `Witness`) as the `reference` full build, with no
/// external source (the tree is self-contained).
fn assert_same_witness(reference: &HashTree, tree: &HashTree, partial: &LabeledTree<Vec<u8>>) {
    let reference_mixed = reference
        .witness::<MixedHashTree>(partial)
        .expect("reference MixedHashTree");
    let tree_mixed = tree
        .witness::<MixedHashTree>(partial)
        .expect("MixedHashTree");
    assert_eq!(
        reference_mixed, tree_mixed,
        "MixedHashTree mismatch for partial {partial:?}"
    );
    assert_eq!(
        &tree_mixed.digest(),
        reference.root_hash(),
        "witness digest mismatch for partial {partial:?}"
    );

    let reference_witness = reference
        .witness::<Witness>(partial)
        .expect("reference Witness");
    let tree_witness = tree.witness::<Witness>(partial).expect("Witness");
    assert_eq!(
        reference_witness, tree_witness,
        "Witness mismatch for partial {partial:?}"
    );
}

/// Builds a partial tree `{canister: {<id>: inner}}`.
fn canister_query(i: usize, inner: LabeledTree<Vec<u8>>) -> LabeledTree<Vec<u8>> {
    LabeledTree::SubTree(flatmap! {
        Label::from(CANISTER_LABEL) => LabeledTree::SubTree(flatmap!{
            canister_id_label(i) => inner,
        }),
    })
}

/// The full canister subtree of canister `i`, used to request witnesses for
/// every leaf.
fn canister_partial(i: usize) -> LabeledTree<Vec<u8>> {
    canister_query(i, canister_subtree(i))
}

#[test]
fn every_canister_is_a_subtree() {
    let canisters = canisters();
    let tree = hash_lazy_tree(&state_tree(&canisters, TIME)).unwrap();

    assert_eq!(
        tree.subtree_count(),
        NUM_CANISTERS,
        "every canister should be stored as a reusable subtree node"
    );
}

#[test]
fn witnesses_into_canisters_are_self_contained() {
    let canisters = canisters();
    let tree = hash_lazy_tree(&state_tree(&canisters, TIME)).unwrap();

    // Whole-canister witnesses across both the sequential and parallel ranges.
    for i in [0usize, 1, 99, 100, 101, NUM_CANISTERS - 1] {
        let partial = canister_partial(i);
        let mixed = tree
            .witness::<MixedHashTree>(&partial)
            .expect("self-contained witness");
        assert_eq!(&mixed.digest(), tree.root_hash());
        // The requested leaves must be present (not pruned).
        assert!(
            mixed
                .lookup(&[CANISTER_LABEL, canister_id_label(i).as_bytes(), b"module_hash"])
                .is_found(),
            "expected canister {i} module_hash in the witness"
        );
    }

    // A single leaf inside a canister.
    let partial = canister_query(
        77,
        LabeledTree::SubTree(flatmap! {
            Label::from("module_hash") => LabeledTree::Leaf(module_hash(77)),
        }),
    );
    let mixed = tree.witness::<MixedHashTree>(&partial).unwrap();
    assert_eq!(&mixed.digest(), tree.root_hash());
}

#[test]
fn absence_witnesses_are_self_contained() {
    let canisters = canisters();
    let tree = hash_lazy_tree(&state_tree(&canisters, TIME)).unwrap();

    // Absent canister id.
    let partial = LabeledTree::SubTree(flatmap! {
        Label::from(CANISTER_LABEL) => LabeledTree::SubTree(flatmap!{
            Label::from("zzzz") => LabeledTree::Leaf(vec![]),
        }),
    });
    let mixed = tree.witness::<MixedHashTree>(&partial).unwrap();
    assert_eq!(&mixed.digest(), tree.root_hash());
    assert!(
        mixed.lookup(&[CANISTER_LABEL, b"zzzz"]).is_absent(),
        "expected absence proof, got {mixed:?}"
    );

    // Absent label *inside* a canister (descends into the subtree node).
    for i in [3usize, 110] {
        let partial = canister_query(
            i,
            LabeledTree::SubTree(flatmap! {
                Label::from("nonexistent") => LabeledTree::Leaf(vec![]),
            }),
        );
        let mixed = tree.witness::<MixedHashTree>(&partial).unwrap();
        assert_eq!(&mixed.digest(), tree.root_hash());
        assert!(
            mixed
                .lookup(&[CANISTER_LABEL, canister_id_label(i).as_bytes(), b"nonexistent"])
                .is_absent(),
            "expected absence proof inside canister {i}, got {mixed:?}"
        );
    }
}

/// Building with a baseline yields a tree identical to one built from scratch.
#[test]
fn baseline_build_matches_from_scratch() {
    let canisters = canisters();
    let baseline = hash_lazy_tree(&state_tree(&canisters, TIME)).unwrap();

    // Mutate a single canister (fresh `Arc`) and change `time`; keep the rest.
    let mut next = canisters.clone();
    next.insert(canister_id_label(50), Arc::new(canister_subtree(9999)));
    let new_time: &[u8] = &[9, 9, 9, 9];

    let from_scratch = hash_lazy_tree(&state_tree(&next, new_time)).unwrap();
    let with_baseline =
        hash_lazy_tree_with_baseline(&state_tree(&next, new_time), &baseline).unwrap();

    assert_eq!(
        from_scratch.root_hash(),
        with_baseline.root_hash(),
        "baseline build must have the same root hash as a from-scratch build"
    );

    // Witnesses must match between the two builds for the changed canister
    // (whose contents are now those of `canister_subtree(9999)`), an unchanged
    // canister, and the changed `time` leaf.
    for partial in [
        canister_query(50, canister_subtree(9999)),
        canister_partial(7),
        LabeledTree::SubTree(flatmap! {
            Label::from(TIME_LABEL) => LabeledTree::Leaf(new_time.to_vec()),
        }),
    ] {
        assert_same_witness(&from_scratch, &with_baseline, &partial);
    }
}

/// Building with a baseline reuses the `Arc<HashTree>` of every unchanged
/// canister, and rebuilds only the changed one.
#[test]
fn baseline_build_reuses_unchanged_subtrees() {
    let canisters = canisters();
    let baseline = hash_lazy_tree(&state_tree(&canisters, TIME)).unwrap();

    // A `BTreeMap` clone shares the canister `Arc`s; only canister 50 gets a
    // fresh `Arc` (a real mutation), so only it should be rebuilt.
    let mut next = canisters.clone();
    next.insert(canister_id_label(50), Arc::new(canister_subtree(50)));

    let with_baseline = hash_lazy_tree_with_baseline(&state_tree(&next, TIME), &baseline).unwrap();

    assert_eq!(with_baseline.subtree_count(), NUM_CANISTERS);
    assert_eq!(
        with_baseline.reused_subtree_count(&baseline),
        NUM_CANISTERS - 1,
        "every unchanged canister should reuse its baseline subtree"
    );

    // Sanity: a from-scratch build (no baseline) shares nothing with the baseline.
    let from_scratch = hash_lazy_tree(&state_tree(&next, TIME)).unwrap();
    assert_eq!(from_scratch.reused_subtree_count(&baseline), 0);
}

/// Reuse must be by identity, not by value: two canisters with identical
/// contents but distinct `Arc`s do not reuse each other's subtree.
#[test]
fn reuse_is_by_identity_not_by_value() {
    let canisters = canisters();
    let baseline = hash_lazy_tree(&state_tree(&canisters, TIME)).unwrap();

    // Replace *every* canister with a fresh `Arc` of the same contents.
    let next: Canisters = (0..NUM_CANISTERS)
        .map(|i| (canister_id_label(i), Arc::new(canister_subtree(i))))
        .collect();

    let with_baseline = hash_lazy_tree_with_baseline(&state_tree(&next, TIME), &baseline).unwrap();

    // Same root hash (contents unchanged) ...
    assert_eq!(with_baseline.root_hash(), baseline.root_hash());
    // ... but nothing is reused, since every `Arc` is fresh.
    assert_eq!(with_baseline.reused_subtree_count(&baseline), 0);
}
