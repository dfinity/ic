use ic_canonical_state_tree_hash::{
    hash_tree::{HashTree, hash_lazy_tree},
    lazy_tree::{LazyFork, LazyTree},
};
use ic_crypto_tree_hash::{
    Digest, FlatMap, HashTree as CryptoHashTree, HashTreeBuilder, HashTreeBuilderImpl, Label,
    LabeledTree, MixedHashTree, Witness, WitnessGenerator, WitnessGeneratorImpl, hasher::Hasher,
};
use ic_crypto_tree_hash_test_utils::{
    merge_path_into_labeled_tree, partial_trees_to_leaves_and_empty_subtrees,
};
use rand::{CryptoRng, Rng};
use std::collections::VecDeque;
use std::sync::Arc;

/// SHA256 of the domain separator "ic-hashtree-empty"
const EMPTY_HASH: Digest = Digest([
    0x4e, 0x3e, 0xd3, 0x5c, 0x4e, 0x2d, 0x1e, 0xe8, 0x99, 0x96, 0x48, 0x3f, 0xb6, 0x26, 0x0a, 0x64,
    0xcf, 0xfb, 0x6c, 0x47, 0xdb, 0xab, 0x21, 0x6e, 0x79, 0x30, 0xe8, 0x2f, 0x81, 0x90, 0xd1, 0x20,
]);

/// Check that for each leaf or empty subtree, the tree as a whole, and some
/// random subtrees generated from `full_tree`, the witness looks the same as
/// with the old way of generating witnesses.
///
/// Also check that the new and old way of computing hash trees are equivalent.
pub fn test_membership_witness<R: Rng + CryptoRng>(full_tree: &LabeledTree<Vec<u8>>, rng: &mut R) {
    let hash_tree = hash_lazy_tree(&as_lazy(full_tree)).unwrap();
    let witness_gen = build_witness_gen(full_tree);

    let paths = partial_trees_to_leaves_and_empty_subtrees(full_tree);

    // prune each path (1 node in each level) from `full_tree`
    for path in paths.iter() {
        assert_same_witness(&hash_tree, &witness_gen, path);
    }

    // prune randomly combined paths
    const MAX_COMBINED_PATHS: usize = 10;
    for num_leaves_and_empty_subtrees in 2..MAX_COMBINED_PATHS.min(paths.len()) {
        let mut indices =
            rand::seq::index::sample(rng, paths.len(), num_leaves_and_empty_subtrees).into_vec();
        indices.sort_unstable();

        let mut partial_tree = paths[indices[0]].clone();

        for index in indices[1..].iter() {
            merge_path_into_labeled_tree(&mut partial_tree, &paths[*index]);
        }
        assert_same_witness(&hash_tree, &witness_gen, &partial_tree);
    }

    // prune the full tree
    assert_same_witness(&hash_tree, &witness_gen, full_tree);

    // create a hash tree for the full tree
    let crypto_tree = crypto_hash_lazy_tree(&as_lazy(full_tree));
    assert_eq!(hash_tree, crypto_tree);
}

/// Computes [`Witness`] and [`MixedHashTree`] for the given `data` (partial
/// tree) using both implementation: 1) in `canonical_state` and 2) in `crypto`.
/// Then, asserts that the results are the same for both implementations.
pub fn assert_same_witness(ht: &HashTree, wg: &WitnessGeneratorImpl, data: &LabeledTree<Vec<u8>>) {
    let crypto_witness = wg
        .mixed_hash_tree(data)
        .expect("failed to construct a MixedHashTree");
    let canonical_state_witness = ht
        .witness::<MixedHashTree>(data)
        .expect("failed to construct a MixedHashTree");

    assert_eq!(
        crypto_witness, canonical_state_witness,
        "labeled tree: {data:?}, hash_tree: {ht:?}, wg: {wg:?}",
    );

    let crypto_witness = wg.witness(data).expect("failed to construct a witness");
    let canonical_state_witness = ht
        .witness::<Witness>(data)
        .expect("failed to construct a witness");

    assert_eq!(
        crypto_witness, canonical_state_witness,
        "labeled tree: {data:?}, hash_tree: {ht:?}, wg: {wg:?}",
    );
}

/// Builds [`WitnessGeneratorImpl`] for the given [`LabeledTree`].
pub fn build_witness_gen(t: &LabeledTree<Vec<u8>>) -> WitnessGeneratorImpl {
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

/// Convert [`LabeledTree`] into [`LazyTree`].
pub fn as_lazy(t: &LabeledTree<Vec<u8>>) -> LazyTree<'_> {
    match t {
        LabeledTree::Leaf(b) => LazyTree::Blob(&b[..], None),
        LabeledTree::SubTree(cs) => LazyTree::LazyFork(Arc::new(FlatMapFork(cs))),
    }
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

/// Constructs a hash tree corresponding to the specified lazy tree.
/// This function is only used for benchmarks.
pub fn crypto_hash_lazy_tree(t: &LazyTree<'_>) -> CryptoHashTree {
    fn go(t: &LazyTree<'_>) -> CryptoHashTree {
        match t {
            LazyTree::Blob(b, None) => {
                let mut h = Hasher::for_domain("ic-hashtree-leaf");
                h.update(b);
                CryptoHashTree::Leaf {
                    digest: h.finalize(),
                }
            }
            LazyTree::Blob(_, Some(h)) => CryptoHashTree::Leaf { digest: Digest(*h) },
            LazyTree::LazyBlob(f) => {
                let b = f();
                let mut h = Hasher::for_domain("ic-hashtree-leaf");
                h.update(&b);
                CryptoHashTree::Leaf {
                    digest: h.finalize(),
                }
            }
            LazyTree::LazyFork(f) => {
                let mut children = VecDeque::new();
                for label in f.labels() {
                    let child = go(&f.edge(&label).expect("missing fork tree"));
                    let mut h = Hasher::for_domain("ic-hashtree-labeled");
                    h.update(label.as_bytes());
                    h.update(child.digest().as_bytes());
                    children.push_back(CryptoHashTree::Node {
                        digest: h.finalize(),
                        label,
                        hash_tree: Box::new(child),
                    });
                }

                if children.is_empty() {
                    return CryptoHashTree::Leaf { digest: EMPTY_HASH };
                }

                let mut next = VecDeque::new();
                loop {
                    while let Some(l) = children.pop_front() {
                        if let Some(r) = children.pop_front() {
                            let mut h = Hasher::for_domain("ic-hashtree-fork");
                            h.update(l.digest().as_bytes());
                            h.update(r.digest().as_bytes());
                            next.push_back(CryptoHashTree::Fork {
                                digest: h.finalize(),
                                left_tree: Box::new(l),
                                right_tree: Box::new(r),
                            });
                        } else {
                            next.push_back(l);
                        }
                    }

                    if next.len() == 1 {
                        return next.pop_front().unwrap();
                    }
                    std::mem::swap(&mut children, &mut next);
                }
            }
        }
    }
    go(t)
}
