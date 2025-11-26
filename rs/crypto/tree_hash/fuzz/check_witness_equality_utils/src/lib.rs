use ic_canonical_state_tree_hash::hash_tree::hash_lazy_tree;
use ic_canonical_state_tree_hash_test_utils::{
    as_lazy, assert_same_witness, build_witness_gen, crypto_hash_lazy_tree,
};
use ic_crypto_tree_hash::{FlatMap, Label, LabeledTree, flatmap};
use ic_crypto_tree_hash_test_utils::{
    merge_path_into_labeled_tree, partial_trees_to_leaves_and_empty_subtrees,
};
use rand::{CryptoRng, Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::cmp::Ordering;

#[cfg(test)]
mod tests;

/// Check that
/// - for each path to an absent range
/// - multiple combinations of such paths
/// - and combinations of the former with existing paths in the tree
///   the witness looks the same for both implementations.
pub fn test_absence_witness<R: Rng + CryptoRng>(full_tree: &LabeledTree<Vec<u8>>, rng: &mut R) {
    let hash_tree = hash_lazy_tree(&as_lazy(full_tree)).expect("failed to create hash tree");
    let witness_gen = build_witness_gen(full_tree);

    // Traverse the tree and produce a list of paths and absent ranges,
    // e.g., for a tree `[label_a -> leaf, label_b -> leaf]`, we would
    // produce the following ranges (all in the root):
    // [] -> Lt("label_a"), [] -> Between("label_a", "label_b"), [] -> Gt("label_b").
    let paths_to_absent_ranges = paths_to_absent_ranges(full_tree);
    let existing_paths = partial_trees_to_leaves_and_empty_subtrees(full_tree);

    // assert same witness for each path and absent range in the tree
    for (path, range) in paths_to_absent_ranges.iter() {
        assert_same_witness(
            &hash_tree,
            &witness_gen,
            &new_subtree_in_range(&path[..], range, rng),
        );
    }

    // assert same witness for combinations of paths and absent ranges in the
    // tree, probabilistically also include existing paths
    const MAX_COMBINED_PATHS: usize = 10;
    for num_paths in 2..MAX_COMBINED_PATHS.min(existing_paths.len()) {
        let num_absent_paths = rng.random_range(1..=num_paths.min(paths_to_absent_ranges.len()));
        let num_existing_paths = num_paths - num_absent_paths;

        assert!(
            num_existing_paths <= existing_paths.len(),
            "amount={num_existing_paths} length={}, num_absent_paths={num_absent_paths}, num_paths=num_paths",
            existing_paths.len()
        );

        let indices =
            rand::seq::index::sample(rng, existing_paths.len(), num_existing_paths).into_vec();
        let selected_existing_paths = indices.into_iter().map(|i| &existing_paths[i]);

        let indices = rand::seq::index::sample(rng, paths_to_absent_ranges.len(), num_absent_paths)
            .into_vec();
        let selected_absent_paths: Vec<LabeledTree<_>> = indices
            .into_iter()
            .map(|i| {
                let (path, range) = &paths_to_absent_ranges[i];
                new_subtree_in_range(&path[..], range, rng)
            })
            .collect();

        let mut paths: Vec<_> = selected_existing_paths
            .chain(selected_absent_paths.iter())
            .collect();
        paths.sort_unstable_by(|&lhs, &rhs| cmp_paths(lhs, rhs));

        let mut partial_tree = paths[0].clone();

        for &path in paths[1..].iter() {
            merge_path_into_labeled_tree(&mut partial_tree, path);
        }
        assert_same_witness(&hash_tree, &witness_gen, &partial_tree);
    }

    // create a hash tree for the full tree
    let crypto_tree = crypto_hash_lazy_tree(&as_lazy(full_tree));
    assert_eq!(hash_tree, crypto_tree);
}

/// Compares two paths represented as [`LabeledTree`]s. A path is defined as a
/// sequence of subtrees with exactly one child, ending with a leaf or an empty
/// subtree. The sequence is allowed to be empty, i.e., the path only contains a
/// child.
///
/// # Returns
/// Paths are compared by comparing their labels, starting from the root until
/// the first label mismatch is found, or one path is exhausted. Longer path is
/// defined to be greater. If the labels in both trees are equal, `lhs` and
/// `rhs` are defined to be equal. Empty subtrees and any leaf values are equal.
///
/// # Panics
/// If either subtree is not a path, i.e., contains more than one child in any
/// subtree.
fn cmp_paths(lhs: &LabeledTree<Vec<u8>>, rhs: &LabeledTree<Vec<u8>>) -> Ordering {
    use LabeledTree::*;
    use Ordering::*;
    match (lhs, rhs) {
        (SubTree(lhs), SubTree(rhs)) if lhs.is_empty() && rhs.is_empty() => Equal,
        (SubTree(lhs), SubTree(rhs)) if lhs.is_empty() && rhs.len() == 1 => Less,
        (SubTree(lhs), SubTree(rhs)) if lhs.len() == 1 && rhs.is_empty() => Greater,
        (SubTree(lhs), Leaf(_)) if lhs.len() == 1 => Greater,
        (SubTree(lhs), Leaf(_)) if lhs.is_empty() => Equal,
        (Leaf(_), SubTree(rhs)) if rhs.len() == 1 => Less,
        (Leaf(_), SubTree(rhs)) if rhs.is_empty() => Equal,
        (Leaf(_), Leaf(_)) => Equal,
        (SubTree(lhs_children), SubTree(rhs_children))
            if lhs_children.len() == 1 && rhs_children.len() == 1 =>
        {
            let lhs_label = &lhs_children.keys()[0];
            let rhs_label = &rhs_children.keys()[0];

            let cmp = lhs_label.cmp(rhs_label);
            if cmp != Equal {
                return cmp;
            }

            let lhs_subtree = &lhs_children.values()[0];
            let rhs_subtree = &rhs_children.values()[0];
            cmp_paths(lhs_subtree, rhs_subtree)
        }
        (SubTree(lhs), SubTree(rhs)) if lhs.len() > 1 || rhs.len() > 1 => {
            panic!("bug: path with >1 argument lhs={lhs:?} rhs={rhs:?}")
        }
        (lhs, rhs) => unreachable!("lhs={lhs:?} rhs={rhs:?}"),
    }
}

/// Label range that is not present in the [`SubTree`].
pub enum AbsentLabelRange<'a> {
    /// The [`SubTree`] is empty, so any label is not in the range.
    Any,
    /// Range that is smaller than any label in the [`SubTree`].
    Lt(&'a Label),
    /// Range that is larger than any label in the [`SubTree`].
    Gt(&'a Label),
    /// Exclusive range between two consecutive labels in the [`SubTree`].
    Between(&'a Label, &'a Label),
}

fn paths_to_absent_ranges(tree: &LabeledTree<Vec<u8>>) -> Vec<(Vec<&Label>, AbsentLabelRange<'_>)> {
    fn paths_to_ranges_impl<'a>(
        tree: &'a LabeledTree<Vec<u8>>,
        path: &mut Vec<&'a Label>,
        result: &mut Vec<(Vec<&'a Label>, AbsentLabelRange<'a>)>,
    ) {
        match tree {
            LabeledTree::SubTree(children) if children.is_empty() => {
                result.push((path.clone(), AbsentLabelRange::Any));
            }
            LabeledTree::SubTree(children) /*if !children.is_empty()*/
            => {
                // Collect ranges
                let first = children.keys().first().unwrap();
                if !first.as_bytes().is_empty(){
                    // generate a `Lt` only if there exists a label that is
                    // small (only excludes the empty label)
                    result.push((path.clone(), AbsentLabelRange::Lt(first)));
                }
                for w in children.keys()[..].windows(2){
                    assert!(w[0] < w[1]);
                    // generate a `Between` only if there exists a label that
                    // can be generated between both labels
                    if is_not_minimally_larger(&w[0], &w[1]){
                        result.push((path.clone(), AbsentLabelRange::Between(&w[0], &w[1])));}
                    }
                result.push((path.clone(), AbsentLabelRange::Gt(children.keys().last().unwrap())));

                // Descend into children
                for (label, child) in children.iter() {
                    path.push(label);
                    paths_to_ranges_impl(child, path, result);
                    path.pop();
                }
            }
            LabeledTree::Leaf(_) => {}
        }
    }

    let mut result = vec![];
    paths_to_ranges_impl(tree, &mut vec![], &mut result);
    result
}

/// For any label `l` the minimally larger label is `l` concatenated with the
/// lexicographically minimal symbol, i.e., `0u8`. See
/// https://doc.rust-lang.org/std/cmp/trait.Ord.html#lexicographical-comparison
/// for more details.
fn is_not_minimally_larger(small: &Label, large: &Label) -> bool {
    let sb = small.as_bytes();
    let lb = large.as_bytes();
    sb.len() + 1 != lb.len() || sb[..] != lb[..sb.len()] || *lb.last().unwrap() != u8::MIN
}

/// Generates a [`SubTree`] for `path` and adds a random label in `range` at its
/// end and probabilistically appends a random (small) [`SubTree`].
fn new_subtree_in_range<R: Rng + CryptoRng>(
    path: &[&Label],
    range: &AbsentLabelRange,
    rng: &mut R,
) -> LabeledTree<Vec<u8>> {
    let absent_label = random_label_in_range(range, rng);
    let with_random_subtree = rng.random_bool(0.5);
    let mut tree = if with_random_subtree {
        random_subtree_maybe_with_leaf(rng)
    } else {
        LabeledTree::<Vec<u8>>::Leaf(random_bytes(0..10, rng))
    };
    tree = LabeledTree::SubTree(flatmap!(absent_label => tree));

    for &l in path.iter().rev() {
        tree = LabeledTree::SubTree(flatmap!(l.clone() => tree));
    }
    tree
}

/// Generates a random label in the given range. Assumes that generating the
/// label is possible given the range (for `AbsentLabelRange::Lt(l)`, `l` is
/// not an empty label, and for `AbsentLabelRange::Between(small, large)`
/// `large` is not minimally larger than `small`) and is thus infallible.
fn random_label_in_range<R: Rng + CryptoRng>(range: &AbsentLabelRange, rng: &mut R) -> Label {
    let label_bytes = match range {
        AbsentLabelRange::Any => random_bytes(0..20, rng),
        AbsentLabelRange::Lt(l) => {
            assert!(!l.as_bytes().is_empty());
            if l.as_bytes().iter().any(|b| *b != 0) {
                let mut result = l
                    .as_bytes()
                    .iter()
                    .map(|b| if *b != 0 { rng.random_range(0..*b) } else { 0 })
                    .collect();
                append_bytes(&mut result, 0..5, rng);
                assert!(
                    l.as_bytes() > &result[..],
                    "l={l} should be greater than result={result:?}, but it is not"
                );
                result
            } else {
                // `split_last()` strips the last byte from the label; doesn't
                // panic if the label contains only one byte
                l.as_bytes().split_last().unwrap().1.to_vec()
            }
        }
        AbsentLabelRange::Gt(l) => {
            if !l.as_bytes().is_empty() {
                let mut result = l
                    .as_bytes()
                    .iter()
                    .map(|b| rng.random_range((*b).saturating_add(1)..=u8::MAX))
                    .collect();
                append_bytes(&mut result, 0..5, rng);
                // if we accidentally generated `l`, create a label that is
                // minimally larger
                if l.as_bytes() == &result[..] {
                    result.push(0);
                }
                assert!(l.as_bytes() < &result[..]);
                result
            } else {
                random_bytes(1..20, rng)
            }
        }
        AbsentLabelRange::Between(small, large) => {
            let sb = small.as_bytes();
            let lb = large.as_bytes();
            assert!(
                is_not_minimally_larger(small, large),
                "small={small}, large={large}"
            );
            let mut result = Vec::with_capacity(sb.len());
            for i in 0..std::cmp::max(sb.len(), lb.len()) {
                let s = if i < sb.len() { sb[i] } else { 0 };
                let l = if i < lb.len() { lb[i] } else { u8::MAX };
                if s <= l {
                    result.push(rng.random_range(s..=l));
                } else {
                    result.push(rng.r#gen::<u8>());
                }
            }
            // if we accidentally generated out of bounds, create a label
            // that is minimally larger than small
            if &result[..] <= sb || &result[..] >= lb {
                result = sb.iter().chain([0].iter()).cloned().collect();
            }

            assert!(
                sb < &result[..] && lb > &result[..],
                "small={sb:?}, large={lb:?}, result={result:?}"
            );
            result
        }
    };

    Label::from(label_bytes)
}

fn random_subtree_maybe_with_leaf<R: Rng + CryptoRng>(rng: &mut R) -> LabeledTree<Vec<u8>> {
    let with_leaf = rng.random_bool(0.5);
    if with_leaf {
        LabeledTree::SubTree(
            flatmap!(Label::from(random_bytes(0..10, rng)) => LabeledTree::Leaf(random_bytes(0..10, rng))),
        )
    } else {
        LabeledTree::SubTree(flatmap!())
    }
}

fn append_bytes<Range: rand::distributions::uniform::SampleRange<usize>, R: Rng + CryptoRng>(
    vec: &mut Vec<u8>,
    range: Range,
    rng: &mut R,
) {
    let num_bytes = rng.random_range(range);
    for _ in 0..num_bytes {
        vec.push(rng.r#gen::<u8>());
    }
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
        remove_leaf(tree, rng.random_range(0..num_leaves));
        true
    } else {
        false
    }
}

fn remove_leaf(tree: &mut LabeledTree<Vec<u8>>, leaf_index: usize) {
    let mut num_traversed_leaves = 0;
    remove_leaf_impl(tree, leaf_index, &mut num_traversed_leaves);
    assert!(
        num_traversed_leaves <= leaf_index + 1,
        "num_traversed_leaves should be at most leaf_index + 1 = {}, but got {num_traversed_leaves}",
        leaf_index + 1
    );
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

        paths_to_empty_subtrees[rng.random_range(0..paths_to_empty_subtrees.len())]
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
                if let Some(LabeledTree::SubTree(children)) = &result {
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
        subtrees[rng.random_range(0..subtrees.len())]
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
        LabeledTree::SubTree(children) => {
            if path.is_empty() {
                let mut label = label;
                while children.contains_key(&label) {
                    let mut data = label.into_vec();
                    data.push(0u8);
                    label = Label::from(data);
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
    let len = rng.random_range(range);
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
        modify_leaf(tree, rng.random_range(0..num_leaves), modify_bytes_fn);
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
        LabeledTree::Leaf(value) => {
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
        modify_label(tree, rng.random_range(0..num_labels), modify_bytes_fn);
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
                    let mut new_label_raw = label.clone().into_vec();
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
