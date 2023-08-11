use ic_canonical_state::hash_tree::{crypto_hash_lazy_tree, hash_lazy_tree, HashTree};
use ic_canonical_state::lazy_tree::{LazyFork, LazyTree};
use ic_crypto_tree_hash::{
    flatmap, FlatMap, HashTreeBuilder, HashTreeBuilderImpl, Label, LabeledTree, Witness,
    WitnessGenerator, WitnessGeneratorImpl,
};
use ic_crypto_tree_hash_test_utils::{
    merge_path_into_labeled_tree, partial_trees_to_leaves_and_empty_subtrees,
};
use rand::{CryptoRng, Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::sync::Arc;

#[cfg(test)]
mod tests;

/// Check that for each leaf, the witness looks the same for both implementations
/// Also check that the new and old way of computing hash trees are equivalent
pub fn test_tree<R: Rng + CryptoRng>(full_tree: &LabeledTree<Vec<u8>>, rng: &mut R) {
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

fn assert_same_witness(ht: &HashTree, wg: &WitnessGeneratorImpl, data: &LabeledTree<Vec<u8>>) {
    let ht_witness = ht
        .witness::<Witness>(data)
        .expect("failed to construct a witness");
    let wg_witness = wg.witness(data).expect("failed to construct a witness");

    assert_eq!(
        wg_witness, ht_witness,
        "labeled tree: {data:?}, hash_tree: {ht:?}, wg: {wg:?}",
    );
}

fn as_lazy(t: &LabeledTree<Vec<u8>>) -> LazyTree<'_> {
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

pub fn rng_from_u32(seed: u32) -> ChaCha20Rng {
    const CHACHA_SEED_LEN: usize = 32;
    let seed_bytes: Vec<u8> = seed
        .to_le_bytes()
        .into_iter()
        .chain([0u8; CHACHA_SEED_LEN - std::mem::size_of::<u32>()])
        .collect();
    ChaCha20Rng::from_seed(
        seed_bytes
            .try_into()
            .expect("Failed to convert fuzzer's seed bytes"),
    )
}

pub fn try_remove_leaf<R: Rng + CryptoRng>(tree: &mut LabeledTree<Vec<u8>>, rng: &mut R) -> bool {
    let num_leaves = get_num_leaves(tree);
    if num_leaves != 0 {
        remove_leaf(tree, rng.gen_range(0..num_leaves));
        true
    } else {
        false
    }
}

fn remove_leaf(tree: &mut LabeledTree<Vec<u8>>, leaf_index: usize) {
    let mut num_traversed_leaves = 0;
    remove_leaf_impl(tree, leaf_index, &mut num_traversed_leaves);
    assert!(num_traversed_leaves <= leaf_index + 1,
        "num_traversed_leaves should be at most leaf_index + 1 = {}, but got {num_traversed_leaves}",
        leaf_index + 1);
}

fn remove_leaf_impl(
    tree: &mut LabeledTree<Vec<u8>>,
    leaf_index: usize,
    num_traversed_leaves: &mut usize,
) {
    match tree {
        LabeledTree::SubTree(children) => {
            let labels: Vec<Label> = children.keys().to_vec();
            for label in labels.into_iter() {
                if let LabeledTree::Leaf(_) = children
                    .get(&label)
                    .expect("Failed to retrieve the child in the subtree")
                {
                    *num_traversed_leaves += 1;
                    if *num_traversed_leaves == leaf_index + 1 {
                        children.remove(&label).expect("Failed to remove leaf");
                        return;
                    }
                } else {
                    remove_leaf_impl(
                        children
                            .get_mut(&label)
                            .expect("Failed to retrieve the child in the subtree"),
                        leaf_index,
                        num_traversed_leaves,
                    );
                    if *num_traversed_leaves == leaf_index + 1 {
                        return;
                    }
                }
            }
        }
        LabeledTree::Leaf(_) => unreachable!(),
    }
}

pub fn try_remove_empty_subtree<R: Rng + CryptoRng>(
    tree: &mut LabeledTree<Vec<u8>>,
    rng: &mut R,
) -> bool {
    let path: Vec<Label> = {
        let paths_to_empty_subtrees = paths_to_empty_subtrees(tree);
        if paths_to_empty_subtrees.is_empty() {
            // we cannot remove the empty subtree in the root
            return false;
        }

        paths_to_empty_subtrees[rng.gen_range(0..paths_to_empty_subtrees.len())]
            .iter()
            .map(|&l| l.clone())
            .collect()
    };

    remove_empty_subtree_in_path(tree, &path[..])
}

fn remove_empty_subtree_in_path(tree: &mut LabeledTree<Vec<u8>>, path: &[Label]) -> bool {
    assert!(!path.is_empty());
    match tree {
        LabeledTree::SubTree(children) => {
            if path.len() == 1 {
                let result = children.remove(&path[0]);
                if let Some(LabeledTree::SubTree(children)) = result {
                    assert!(children.is_empty());
                    true
                } else {
                    panic!("Failed to remove a supposedly empty subtree");
                }
            } else {
                let child = children.get_mut(&path[0]);
                remove_empty_subtree_in_path(
                    child.expect("Failed to retrieve a subtree child"),
                    &path[1..],
                )
            }
        }
        LabeledTree::Leaf(_) => unreachable!(),
    }
}

fn paths_to_empty_subtrees(tree: &LabeledTree<Vec<u8>>) -> Vec<Vec<&Label>> {
    let mut prefix = vec![];
    let mut result = vec![];
    paths_to_empty_subtrees_impl(tree, &mut prefix, &mut result);
    result
}

fn paths_to_empty_subtrees_impl<'a>(
    tree: &'a LabeledTree<Vec<u8>>,
    prefix: &mut Vec<&'a Label>,
    result: &mut Vec<Vec<&'a Label>>,
) {
    match tree {
        LabeledTree::SubTree(children) => {
            for (label, child) in children.iter() {
                prefix.push(label);
                match child {
                    LabeledTree::SubTree(sub_children) => {
                        if sub_children.is_empty() {
                            result.push(prefix.clone());
                        } else {
                            paths_to_empty_subtrees_impl(child, prefix, result);
                        }
                    }
                    LabeledTree::Leaf(_) => {}
                }
                prefix.pop();
            }
        }
        LabeledTree::Leaf(_) => unreachable!(),
    }
}

pub fn add_leaf<R: Rng + CryptoRng>(tree: &mut LabeledTree<Vec<u8>>, rng: &mut R) -> bool {
    let leaf = LabeledTree::<Vec<u8>>::Leaf(random_bytes(0..5, rng));
    add_subtree(tree, rng, leaf);
    true
}

pub fn add_empty_subtree<R: Rng + CryptoRng>(tree: &mut LabeledTree<Vec<u8>>, rng: &mut R) -> bool {
    add_subtree(tree, rng, LabeledTree::<Vec<u8>>::SubTree(flatmap!()));
    true
}

/// randomly adds the provided `subtree` with a randomly generated `Label`
fn add_subtree<R: Rng + CryptoRng>(
    tree: &mut LabeledTree<Vec<u8>>,
    rng: &mut R,
    subtree: LabeledTree<Vec<u8>>,
) {
    let path: Vec<Label> = {
        let subtrees = all_subtrees(tree);
        assert!(!subtrees.is_empty());
        subtrees[rng.gen_range(0..subtrees.len())]
            .iter()
            .map(|&l| l.clone())
            .collect()
    };
    add_subtree_in_path(tree, &path[..], random_label(0..5, rng), subtree);
}

fn add_subtree_in_path(
    tree: &mut LabeledTree<Vec<u8>>,
    path: &[Label],
    label: Label,
    subtree: LabeledTree<Vec<u8>>,
) {
    match tree {
        LabeledTree::SubTree(ref mut children) => {
            if path.is_empty() {
                let mut label = label;
                while children.contains_key(&label) {
                    label = Label::from(
                        label
                            .to_vec()
                            .iter()
                            .chain(&[0u8])
                            .cloned()
                            .collect::<Vec<_>>(),
                    );
                }
                let new_children = FlatMap::from_key_values(
                    children
                        .iter()
                        .chain([(&label, &subtree)])
                        .map(|(l, s)| (l.clone(), s.clone()))
                        .collect(),
                );
                *children = new_children;
            } else {
                let child = children
                    .get_mut(&path[0])
                    .expect("Failed to retrieve a child in a subtree");
                add_subtree_in_path(child, &path[1..], label, subtree);
            }
        }
        LabeledTree::Leaf(_) => unreachable!(),
    }
}

fn random_label<R: Rng + CryptoRng>(range: std::ops::Range<usize>, rng: &mut R) -> Label {
    Label::from(random_bytes(range, rng))
}

fn random_bytes<R: Rng + CryptoRng>(range: std::ops::Range<usize>, rng: &mut R) -> Vec<u8> {
    let len = rng.gen_range(range);
    let mut result = vec![0u8; len];
    rng.fill_bytes(&mut result[..]);
    result
}

fn all_subtrees(tree: &LabeledTree<Vec<u8>>) -> Vec<Vec<&Label>> {
    let mut result = vec![];
    all_subtrees_impl(tree, &mut vec![], &mut result);
    result
}

fn all_subtrees_impl<'a>(
    tree: &'a LabeledTree<Vec<u8>>,
    prefix: &mut Vec<&'a Label>,
    result: &mut Vec<Vec<&'a Label>>,
) {
    match tree {
        LabeledTree::SubTree(children) => {
            result.push(prefix.clone());
            for label in children.keys() {
                prefix.push(label);
                all_subtrees_impl(
                    children
                        .get(label)
                        .expect("Failed to retrieve a reference to child"),
                    prefix,
                    result,
                );
                prefix.pop();
            }
        }
        LabeledTree::Leaf(_) => {}
    }
}

pub fn try_randomly_change_bytes_leaf_value<F: Fn(&mut Vec<u8>), R: Rng + CryptoRng>(
    tree: &mut LabeledTree<Vec<u8>>,
    rng: &mut R,
    modify_bytes_fn: &F,
) -> bool {
    let num_leaves = get_num_leaves(tree);
    if num_leaves != 0 {
        modify_leaf(tree, rng.gen_range(0..num_leaves), modify_bytes_fn);
        true
    } else {
        false
    }
}

fn get_num_leaves(tree: &LabeledTree<Vec<u8>>) -> usize {
    match tree {
        LabeledTree::SubTree(children) => {
            let mut num_leaves = 0;
            for (_label, child) in children.iter() {
                num_leaves += get_num_leaves(child);
            }
            num_leaves
        }
        LabeledTree::Leaf(_) => 1,
    }
}

fn modify_leaf<F: Fn(&mut Vec<u8>)>(
    tree: &mut LabeledTree<Vec<u8>>,
    leaf_index: usize,
    modify_bytes_fn: &F,
) {
    let mut num_traversed_leaves = 0;
    assert!(modify_leaf_impl(
        tree,
        leaf_index,
        &mut num_traversed_leaves,
        modify_bytes_fn
    ));
    assert!(
        num_traversed_leaves == leaf_index,
        "num_traversed_leaves should be exactly equal to leaf_index={leaf_index}, but got {num_traversed_leaves}"
    );
}

fn modify_leaf_impl<F: Fn(&mut Vec<u8>)>(
    tree: &mut LabeledTree<Vec<u8>>,
    leaf_index: usize,
    num_traversed_leaves: &mut usize,
    modify_bytes_fn: &F,
) -> bool {
    if *num_traversed_leaves == leaf_index + 1 {
        panic!("Failed to modify the leaf at index {leaf_index}");
    }
    match tree {
        LabeledTree::SubTree(children) => {
            let labels: Vec<Label> = children.keys().to_vec();
            for label in labels.into_iter() {
                let success = modify_leaf_impl(
                    children
                        .get_mut(&label)
                        .expect("Failed to retrieve a child by iterating through labels"),
                    leaf_index,
                    num_traversed_leaves,
                    modify_bytes_fn,
                );
                if success {
                    return success;
                }
            }
            false
        }
        LabeledTree::Leaf(ref mut value) => {
            if *num_traversed_leaves == leaf_index {
                modify_bytes_fn(value);
                true
            } else {
                *num_traversed_leaves += 1;
                false
            }
        }
    }
}

pub fn try_randomly_change_bytes_label<F: Fn(&mut Vec<u8>), R: Rng + CryptoRng>(
    tree: &mut LabeledTree<Vec<u8>>,
    rng: &mut R,
    modify_bytes_fn: &F,
) -> bool {
    let num_labels = get_num_labels(tree);
    if num_labels != 0 {
        modify_label(tree, rng.gen_range(0..num_labels), modify_bytes_fn);
        true
    } else {
        false
    }
}

fn get_num_labels(tree: &LabeledTree<Vec<u8>>) -> usize {
    match tree {
        LabeledTree::SubTree(children) => {
            let mut num_labels = 0;
            for (_label, child) in children.iter() {
                num_labels += get_num_labels(child) + 1;
            }
            num_labels
        }
        LabeledTree::Leaf(_) => 0,
    }
}

fn modify_label<F: Fn(&mut Vec<u8>)>(
    tree: &mut LabeledTree<Vec<u8>>,
    label_index: usize,
    modify_bytes_fn: &F,
) {
    let mut num_traversed_labels = 0;
    assert!(
        modify_label_impl(
            tree,
            label_index,
            &mut num_traversed_labels,
            modify_bytes_fn,
        ),
        "Failed to modify label at index {label_index}"
    );
}

fn modify_label_impl<F: Fn(&mut Vec<u8>)>(
    tree: &mut LabeledTree<Vec<u8>>,
    label_index: usize,
    num_traversed_labels: &mut usize,
    modify_bytes_fn: &F,
) -> bool {
    if *num_traversed_labels == label_index + 1 {
        panic!("Failed to modify the label at index {label_index}");
    }
    match tree {
        LabeledTree::SubTree(children) => {
            let labels: Vec<Label> = children.keys().to_vec();

            for label in labels.into_iter() {
                if *num_traversed_labels == label_index {
                    let mut new_label_raw = label.to_vec();
                    modify_bytes_fn(&mut new_label_raw);
                    let new_child = (
                        Label::from(new_label_raw),
                        children
                            .get(&label)
                            .expect("Failed to retrieve a child by its label")
                            .clone(),
                    );
                    let new_children: Vec<(Label, LabeledTree<Vec<u8>>)> = children
                        .iter()
                        .filter(|(k, _v)| **k != label)
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .chain([new_child])
                        .collect();
                    *children = FlatMap::from_key_values(new_children);
                    return true;
                } else {
                    *num_traversed_labels += 1;
                    let success = modify_label_impl(
                        children
                            .get_mut(&label)
                            .expect("Failed to retrieve a child by iterating through labels"),
                        label_index,
                        num_traversed_labels,
                        modify_bytes_fn,
                    );
                    if success {
                        return success;
                    }
                }
            }
            false
        }
        LabeledTree::Leaf(_) => false,
    }
}
