//! Tests for reusable subtree (stub) nodes.
//!
//! When building a [`HashTree`] from a [`LazyTree`], every subtree that carries
//! a [`LazyFork::subtree_source`] (here a per-canister fork, mirroring `CanisterFork`
//! in production) is collapsed to a digest-only [`NodeKind::Stub`].
//! Such a tree:
//!
//!   * has the exact same root hash as a fully materialized build,
//!   * serves witnesses by expanding the stub on demand from the source `Arc`
//!     it holds (via its [`SubtreeExpander`]), with no external source, and
//!   * when built with a baseline ([`hash_lazy_tree_with_baseline`]), reuses the
//!     stored digest of every unchanged subtree (matched by `SubtreeSource`).

use ic_canonical_state_tree_hash::hash_tree::{
    HashTree, HashTreeError, PARALLEL_MIN_CHILDREN, hash_lazy_tree, hash_lazy_tree_with_baseline,
};
use ic_canonical_state_tree_hash::lazy_tree::{LazyFork, LazyTree, SubtreeSource, fork};
use ic_canonical_state_tree_hash_test_utils::as_lazy;
use ic_crypto_tree_hash::{FlatMap, Label, LabeledTree, MixedHashTree, Witness, flatmap};
use std::collections::BTreeMap;
use std::sync::Arc;

const CANISTER_LABEL: &[u8] = b"canister";
const TIME_LABEL: &[u8] = b"time";

/// Number of canisters; `> PARALLEL_MIN_CHILDREN` so that the parallel build
/// path is exercised.
const NUM_CANISTERS: usize = PARALLEL_MIN_CHILDREN * 2;

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
/// `subtree_source` mirrors `CanisterFork::subtree_source` in production: it
/// returns the backing `Arc`, so each canister is stored as a self-contained,
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
        Box::new(
            self.children_map()
                .iter()
                .map(|(l, t)| (l.clone(), as_lazy(t))),
        )
    }

    fn len(&self) -> usize {
        self.children_map().len()
    }

    fn subtree_source(&self) -> Option<SubtreeSource> {
        Some(SubtreeSource::new(self.canister, expand_test_canister))
    }
}

/// Rebuilds a test canister's stubbed subtree from its `SubtreeSource` (mirrors
/// `expand_canister` in production, minus the certification version).
fn expand_test_canister(source: &SubtreeSource) -> Result<HashTree, HashTreeError> {
    let canister = source.downcast::<LabeledTree<Vec<u8>>>();
    hash_lazy_tree(&canister_fork(&canister))
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
/// `MixedHashTree` and `Witness`) as the `reference` full build. Stubbed
/// subtrees expand themselves from the source `Arc` they hold.
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
        tree.stub_count(),
        NUM_CANISTERS,
        "every canister should be stored as a stub"
    );
}

#[test]
fn witnesses_into_canisters_expand_from_source() {
    let canisters = canisters();
    let source = state_tree(&canisters, TIME);
    let tree = hash_lazy_tree(&source).unwrap();

    // Whole-canister witnesses across both the sequential and parallel ranges.
    for i in [
        0usize,
        1,
        PARALLEL_MIN_CHILDREN - 1,
        PARALLEL_MIN_CHILDREN + 1,
        NUM_CANISTERS - 1,
    ] {
        let partial = canister_partial(i);
        let mixed = tree
            .witness::<MixedHashTree>(&partial)
            .expect("witness expanded from source");
        assert_eq!(&mixed.digest(), tree.root_hash());
        // The requested leaves must be present (not pruned).
        assert!(
            mixed
                .lookup(&[
                    CANISTER_LABEL,
                    canister_id_label(i).as_bytes(),
                    b"module_hash"
                ])
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
fn absence_witnesses_expand_from_source() {
    let canisters = canisters();
    let source = state_tree(&canisters, TIME);
    let tree = hash_lazy_tree(&source).unwrap();

    // Absent canister id (proven at the `/canister` node, no stub descent).
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

    // Absent label *inside* a canister (descends into the subtree stub).
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
                .lookup(&[
                    CANISTER_LABEL,
                    canister_id_label(i).as_bytes(),
                    b"nonexistent"
                ])
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
    // canister, and the changed `time` leaf. Stubs expand themselves.
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

/// Building with a baseline (reusing the stored digest of every unchanged
/// canister, rebuilding only the changed one) must produce exactly the same tree
/// as a from-scratch build. Digest reuse is an internal optimization and is not
/// observable in the result.
#[test]
fn baseline_build_with_partial_change_matches_from_scratch() {
    let canisters = canisters();
    let baseline = hash_lazy_tree(&state_tree(&canisters, TIME)).unwrap();

    // A `BTreeMap` clone shares the canister `Arc`s; only canister 50 gets a
    // fresh `Arc` (a real mutation), so only it is rebuilt.
    let mut next = canisters.clone();
    next.insert(canister_id_label(50), Arc::new(canister_subtree(50)));

    let with_baseline = hash_lazy_tree_with_baseline(&state_tree(&next, TIME), &baseline).unwrap();
    let from_scratch = hash_lazy_tree(&state_tree(&next, TIME)).unwrap();

    assert_eq!(with_baseline.stub_count(), NUM_CANISTERS);
    assert_eq!(with_baseline.root_hash(), from_scratch.root_hash());
}

/// Whether `a` and `b` hold the same stub [`SubtreeSource`]s by identity: each
/// canister's stub points to the same source `Arc` in both trees.
fn same_stub_sources(a: &HashTree, b: &HashTree) -> bool {
    // Stubs are stored in label order in every tree
    a.stub_sources().eq(b.stub_sources())
}

/// Whether every canister's stub in `a` references a *different* source `Arc`
/// than its counterpart in `b` (i.e. nothing could have been reused by identity).
fn disjoint_stub_sources(a: &HashTree, b: &HashTree) -> bool {
    a.stub_count() == b.stub_count() && a.stub_sources().zip(b.stub_sources()).all(|(x, y)| x != y)
}

/// Reuse is by identity, not by value: replacing every canister with a fresh
/// `Arc` of identical contents skips all digest reuse, yet still yields the same
/// root hash (the canonical encoding depends only on the contents).
#[test]
fn reuse_is_by_identity_not_by_value() {
    let canisters = canisters();
    let baseline = hash_lazy_tree(&state_tree(&canisters, TIME)).unwrap();

    // Rebuilding against the baseline with the *same* `Arc`s: every stub holds the
    // very same source allocation as the baseline (identity is preserved).
    let unchanged = hash_lazy_tree_with_baseline(&state_tree(&canisters, TIME), &baseline).unwrap();
    assert!(same_stub_sources(&baseline, &unchanged));

    // Replace *every* canister with a fresh `Arc` of the same contents.
    let next: Canisters = (0..NUM_CANISTERS)
        .map(|i| (canister_id_label(i), Arc::new(canister_subtree(i))))
        .collect();

    let with_baseline = hash_lazy_tree_with_baseline(&state_tree(&next, TIME), &baseline).unwrap();

    // No stub shares a source `Arc` with the baseline, so no digest could have been
    // reused (every `Arc` is fresh, so no identity matches).
    assert!(disjoint_stub_sources(&baseline, &with_baseline));

    // Same root hash nonetheless: the canonical encoding depends only on contents.
    assert_eq!(with_baseline.root_hash(), baseline.root_hash());
}
