#![allow(dead_code)]
use ic_crypto_tree_hash::{Digest, HashTree, Label, Path};
use ic_types::crypto::CryptoHash;
use std::collections::BTreeMap;
use std::fmt;

/// `RoseHashTree` is a "flattened" version of the binary HashTree, i.e. with
/// all the binary forks removed.
///
/// It's much easier to compute diffs on labeled rose trees comparing to
/// HashTrees provided by the crypto.
#[derive(Clone, PartialEq, Eq)]
pub enum RoseHashTree {
    Leaf(Digest),
    Fork {
        digest: Digest,
        children: BTreeMap<Label, RoseHashTree>,
    },
}

impl RoseHashTree {
    pub(crate) fn digest(&self) -> &Digest {
        match self {
            Self::Leaf(digest) => digest,
            Self::Fork { digest, .. } => digest,
        }
    }

    pub fn crypto_hash(&self) -> CryptoHash {
        CryptoHash(self.digest().0.to_vec())
    }
}

impl fmt::Debug for RoseHashTree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RoseHashTree::Leaf(digest) => write!(f, "{}", digest),
            RoseHashTree::Fork { digest, children } => {
                let mut s = f.debug_struct(&format!("fork@{}", digest));
                for (label, child) in children {
                    s.field(&format!("{}", label), child);
                }
                s.finish()
            }
        }
    }
}

impl From<&HashTree> for RoseHashTree {
    fn from(root: &HashTree) -> Self {
        fn collect_children(t: &HashTree, children: &mut BTreeMap<Label, RoseHashTree>) {
            match t {
                HashTree::Leaf { .. } => panic!("Unlabeled non-root leaves are not allowed"),
                HashTree::Node {
                    label, hash_tree, ..
                } => {
                    children.insert(label.clone(), RoseHashTree::from(&**hash_tree));
                }
                HashTree::Fork {
                    left_tree,
                    right_tree,
                    ..
                } => {
                    collect_children(&*left_tree, children);
                    collect_children(&*right_tree, children);
                }
            }
        }

        match root {
            HashTree::Leaf { digest } => RoseHashTree::Leaf(digest.clone()),
            HashTree::Node { digest, .. } | HashTree::Fork { digest, .. } => {
                let mut children = BTreeMap::new();
                collect_children(root, &mut children);

                RoseHashTree::Fork {
                    digest: digest.clone(),
                    children,
                }
            }
        }
    }
}

/// A change to perform on a sub-tree addressed by some path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    /// Insert a leaf with the specified hash at the path.  If the path already
    /// existed before, replace it.
    InsertLeaf(Digest),
    /// Insert a fork with no children at the path.  If the path already existed
    /// before, replace it.  Hash is not specified as all empty forks have the
    /// same hash.
    InsertEmptyFork,
    /// Delete the whole subtree rooted at the path and the labeled edge
    /// pointing into it.
    DeleteSubtree,
}

/// A type representing changes between two trees.
pub type Changes = BTreeMap<Path, Change>;

impl std::fmt::Display for Change {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsertLeaf(h) => write!(f, "→ {}", h),
            Self::InsertEmptyFork => write!(f, "→ ∅"),
            Self::DeleteSubtree => write!(f, "✗"),
        }
    }
}

/// A helper type to display paths in a nice way.
struct PathDisplay<'a>(&'a Path);

impl fmt::Display for PathDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for label in self.0.iter() {
            write!(f, "/{}", label)?;
        }
        Ok(())
    }
}

/// A helper type to display changes in a nice way.
pub struct PrettyPrintedChanges<'a>(pub &'a Changes);

impl fmt::Display for PrettyPrintedChanges<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (path, change) in self.0.iter() {
            writeln!(f, "{} {}", PathDisplay(path), change)?;
        }
        Ok(())
    }
}

/// Computes a difference between 2 labeled hash trees.
///
/// # Complexity
///
/// `O(N + M)` where `N` and `M` are sizes of the input trees.
///
/// # Panics
///
/// Let's call a hash tree "properly labeled tree" if one of the following
/// condition holds:
///
///   1. The tree consists of a single leaf.
///   2. The parent of every leaf node is a HashTree::Node.
///
/// This function panics if one of the trees is not a properly labeled tree.
pub fn diff(lhs: &HashTree, rhs: &HashTree) -> Changes {
    diff_rose_trees(&lhs.into(), &rhs.into())
}

/// Produces a set of changes required to transform Merkle tree `lhs` to Merkle
/// tree `rhs`.
///
/// The change set is not guaranteed to be the shortest one.  I.e. it could be
/// possible that there is a shorter sequence of changes having the same effect.
///
/// # Prerequisites
///
/// The trees are expected to be proper Merkle trees built using SHA-256 hashes:
/// if two nodes are not equal, their hashes must be different.
///
/// # Complexity
///
/// `O(N + M)` where `N` and `M` are sizes of the input trees.
///
/// # Panics
///
/// This function uses recursive calls and can panic on deep hash trees.
fn diff_rose_trees(lhs: &RoseHashTree, rhs: &RoseHashTree) -> Changes {
    fn insert_subtree(t: &RoseHashTree, path: &mut Path, changes: &mut Changes) {
        match t {
            RoseHashTree::Leaf(hash) => {
                changes.insert(path.clone(), Change::InsertLeaf(hash.clone()));
            }
            RoseHashTree::Fork { children, .. } => {
                if children.is_empty() {
                    changes.insert(path.clone(), Change::InsertEmptyFork);
                } else {
                    for (label, child) in children.iter() {
                        path.push(label.clone());
                        insert_subtree(child, path, changes);
                        path.pop();
                    }
                }
            }
        }
    }

    fn go_rec(lhs: &RoseHashTree, rhs: &RoseHashTree, path: &mut Path, changes: &mut Changes) {
        match (lhs, rhs) {
            (RoseHashTree::Leaf(lhash), RoseHashTree::Leaf(rhash)) => {
                if lhash != rhash {
                    changes.insert(path.clone(), Change::InsertLeaf(rhash.clone()));
                }
            }
            (RoseHashTree::Leaf(_), RoseHashTree::Fork { children, .. }) => {
                if children.is_empty() {
                    changes.insert(path.clone(), Change::InsertEmptyFork);
                } else {
                    changes.insert(path.clone(), Change::DeleteSubtree);
                    for (label, rchild) in children {
                        path.push(label.clone());
                        insert_subtree(rchild, path, changes);
                        path.pop();
                    }
                }
            }
            (RoseHashTree::Fork { .. }, RoseHashTree::Leaf(digest)) => {
                changes.insert(path.clone(), Change::InsertLeaf(digest.clone()));
            }
            (
                RoseHashTree::Fork {
                    digest: lhash,
                    children: lchildren,
                },
                RoseHashTree::Fork {
                    digest: rhash,
                    children: rchildren,
                },
            ) => {
                if lhash != rhash {
                    // Traverse the left tree to find changed and deleted nodes.
                    for (llabel, lchild) in lchildren.iter() {
                        path.push(llabel.clone());
                        match rchildren.get(llabel) {
                            Some(rchild) => {
                                go_rec(lchild, rchild, path, changes);
                            }
                            None => {
                                changes.insert(path.clone(), Change::DeleteSubtree);
                            }
                        }
                        path.pop();
                    }
                    // Traverse the right tree to find newly added nodes.
                    for (rlabel, rchild) in rchildren.iter() {
                        if lchildren.get(rlabel).is_none() {
                            path.push(rlabel.clone());
                            insert_subtree(rchild, path, changes);
                            path.pop();
                        }
                    }
                }
            }
        }
    }

    let mut path = Path::new(vec![]);
    let mut changes = BTreeMap::new();

    go_rec(lhs, rhs, &mut path, &mut changes);

    changes
}

#[cfg(test)]
mod tests {
    use super::RoseHashTree::Leaf;
    use super::*;
    use ic_crypto_sha::Sha256;
    use proptest::collection::btree_map;
    use proptest::prelude::*;

    trait IntoLabel {
        fn into_label(self) -> Label;
    }

    impl IntoLabel for Label {
        fn into_label(self) -> Label {
            self
        }
    }

    impl IntoLabel for &str {
        fn into_label(self) -> Label {
            Label::from(self.as_bytes())
        }
    }

    fn rehash(t: &mut RoseHashTree) {
        match t {
            RoseHashTree::Leaf(_) => (),
            RoseHashTree::Fork {
                children,
                ref mut digest,
            } => {
                let mut hasher = Sha256::new();
                for (label, child) in children.iter_mut() {
                    rehash(child);
                    hasher.write(label.as_bytes());
                    hasher.write(&child.digest().0[..]);
                }
                *digest = Digest(hasher.finish());
            }
        }
    }

    fn rehashed(mut t: RoseHashTree) -> RoseHashTree {
        rehash(&mut t);
        t
    }

    fn num_leaves(t: &RoseHashTree) -> usize {
        match t {
            RoseHashTree::Leaf(_) => 1,
            RoseHashTree::Fork { children, .. } => {
                children.iter().map(|(_, t)| num_leaves(t)).sum()
            }
        }
    }

    fn num_edges(t: &RoseHashTree) -> usize {
        match t {
            RoseHashTree::Leaf(_) => 0,
            RoseHashTree::Fork { children, .. } => {
                children.len() + children.iter().map(|(_, t)| num_edges(t)).sum::<usize>()
            }
        }
    }

    /// Modify the leaf at the given index. The leaves are counted according to
    /// their in-order traveral.
    fn modify_leaf_at_index(t: &mut RoseHashTree, idx: usize, h: Digest) -> Option<(Path, Digest)> {
        fn go_rec(
            t: &mut RoseHashTree,
            idx: usize,
            new_hash: Digest,
            path: &mut Path,
        ) -> Result<(Path, Digest), usize> {
            match t {
                RoseHashTree::Leaf(ref mut hash) if idx == 0 => {
                    let old_hash = std::mem::replace(hash, new_hash);
                    Ok((path.clone(), old_hash))
                }
                RoseHashTree::Leaf(_) => Err(idx - 1),
                RoseHashTree::Fork { children, .. } => {
                    let mut i = idx;
                    for (label, mut child) in children.iter_mut() {
                        path.push(label.clone());
                        match go_rec(&mut child, i, new_hash.clone(), path) {
                            Ok(result) => return Ok(result),
                            Err(new_index) => i = new_index,
                        }
                        path.pop();
                    }
                    Err(i)
                }
            }
        }

        let mut path = Path::new(vec![]);

        match go_rec(t, idx, h, &mut path) {
            Ok(result) => {
                rehash(t);
                Some(result)
            }
            Err(_) => None,
        }
    }

    /// Removes the edge with the given index.  The edges are counted according
    /// to the in-order traversal of the tree.
    fn remove_edge_at_index(t: &mut RoseHashTree, idx: usize) -> Option<(Path, RoseHashTree)> {
        fn go_rec(
            t: &mut RoseHashTree,
            idx: usize,
            path: &mut Path,
        ) -> Result<(Path, RoseHashTree), usize> {
            match t {
                RoseHashTree::Leaf(_) => Err(idx),
                RoseHashTree::Fork { children, .. } => {
                    let mut i = idx;
                    let mut removed_child = None;

                    for (label, mut child) in children.iter_mut() {
                        if i == 0 {
                            removed_child = Some(label.clone());
                            break;
                        }

                        i -= 1;

                        path.push(label.clone());
                        match go_rec(&mut child, i, path) {
                            Ok(result) => return Ok(result),
                            Err(new_index) => i = new_index,
                        }
                        path.pop();
                    }

                    match removed_child {
                        Some(label) => {
                            let t = children.remove(&label).unwrap();
                            path.push(label);
                            Ok((path.clone(), t))
                        }
                        None => Err(i),
                    }
                }
            }
        }

        let mut path = Path::new(vec![]);

        match go_rec(t, idx, &mut path) {
            Ok(result) => {
                rehash(t);
                Some(result)
            }
            Err(_) => None,
        }
    }

    /// A utility to build a fork node.
    fn fork(hash: [u8; 32], children_vec: Vec<(&str, RoseHashTree)>) -> RoseHashTree {
        let children = children_vec
            .into_iter()
            .map(|(s, t)| (s.into_label(), t))
            .collect();
        RoseHashTree::Fork {
            digest: Digest(hash),
            children,
        }
    }

    /// Utility function to build HashTrees in a more concise way.
    fn hash_fork(digest: [u8; 32], l: HashTree, r: HashTree) -> HashTree {
        HashTree::Fork {
            digest: Digest(digest),
            left_tree: Box::new(l),
            right_tree: Box::new(r),
        }
    }

    fn hash_node<L: AsRef<[u8]>>(digest: [u8; 32], label: L, child: HashTree) -> HashTree {
        HashTree::Node {
            digest: Digest(digest),
            label: Label::from(label),
            hash_tree: Box::new(child),
        }
    }

    fn hash_leaf(digest: [u8; 32]) -> HashTree {
        HashTree::Leaf {
            digest: Digest(digest),
        }
    }

    fn changes(slice: &[(Path, Change)]) -> Changes {
        slice
            .iter()
            .map(|(path, c)| {
                (
                    path.iter()
                        .map(|s| s.clone().into_label())
                        .collect::<Path>(),
                    c.clone(),
                )
            })
            .collect()
    }

    prop_compose! {
        fn arb_size(n: usize)(size in 0..n) -> usize {
            size
        }
    }

    fn arb_tree(max_height: usize, max_width: usize) -> BoxedStrategy<RoseHashTree> {
        (any::<[u8; 32]>().prop_map(Digest), arb_size(max_height))
            .prop_flat_map(move |(digest, height)| {
                if height == 0 {
                    Just(RoseHashTree::Leaf(digest)).boxed()
                } else {
                    btree_map(
                        "[a-zA-Z0-9_]{10,50}".prop_map(|s| Label::from(s.as_bytes())),
                        arb_tree(max_height - 1, max_width),
                        1..max_width,
                    )
                    .prop_map(move |children| RoseHashTree::Fork {
                        digest: digest.clone(),
                        children,
                    })
                    .boxed()
                }
            })
            .boxed()
    }

    fn arb_tree_and_leaf_index(
        max_height: usize,
        max_width: usize,
    ) -> BoxedStrategy<(RoseHashTree, usize)> {
        arb_tree(max_height, max_width)
            .prop_filter("has_leaves", |t| num_leaves(t) > 0)
            .prop_flat_map(|t| {
                let size = num_leaves(&t);
                (Just(t), 0..size)
            })
            .boxed()
    }

    fn arb_tree_and_edge_index(
        max_height: usize,
        max_width: usize,
    ) -> BoxedStrategy<(RoseHashTree, usize)> {
        arb_tree(max_height, max_width)
            .prop_filter("has_edges", |t| match t {
                RoseHashTree::Leaf(_) => false,
                RoseHashTree::Fork { children, .. } => !children.is_empty(),
            })
            .prop_flat_map(|t| {
                let size = num_edges(&t);
                (Just(t), 0..size)
            })
            .boxed()
    }

    proptest! {
        #[test]
        fn tree_diff_against_self_is_empty(tree in arb_tree(4, 3)) {
            prop_assert!(diff_rose_trees(&tree, &tree).is_empty());
        }

        #[test]
        fn tree_diff_detects_changing_single_hash((tree, idx) in arb_tree_and_leaf_index(4, 3),
                                                  new_hash in any::<[u8; 32]>().prop_map(Digest)) {
            let size = num_leaves(&tree);
            prop_assume!(idx < size);
            let mut tree_2 = tree.clone();
            let (path, _old_hash) = modify_leaf_at_index(&mut tree_2, idx, new_hash.clone()).unwrap();
            let expected_diff = changes(&[(path, Change::InsertLeaf(new_hash))][..]);
            assert_eq!(diff_rose_trees(&tree, &tree_2), expected_diff);
        }

        #[test]
        fn tree_diff_detects_removing_a_node((tree, idx) in arb_tree_and_edge_index(4, 3)) {
            let mut tree_2 = tree.clone();
            let (path, _node) = remove_edge_at_index(&mut tree_2, idx).unwrap();
            let expected_diff = changes(&[(path, Change::DeleteSubtree)][..]);
            assert_eq!(diff_rose_trees(&tree, &tree_2), expected_diff);
        }
    }

    #[test]
    fn tree_diff_detects_multiple_changes() {
        let a = rehashed(fork(
            [0; 32],
            vec![
                (
                    "a",
                    fork(
                        [0; 32],
                        vec![("b", Leaf(Digest([1; 32]))), ("c", Leaf(Digest([2; 32])))],
                    ),
                ),
                ("e", fork([0; 32], vec![("f", fork([0; 32], vec![]))])),
            ],
        ));
        let b = rehashed(fork(
            [0; 32],
            vec![(
                "a",
                fork(
                    [0; 32],
                    vec![("b", Leaf(Digest([1; 32]))), ("d", Leaf(Digest([3; 32])))],
                ),
            )],
        ));

        let expected_diff = changes(
            &[
                (
                    Path::new(vec!["a".into(), "c".into()]),
                    Change::DeleteSubtree,
                ),
                (Path::new(vec!["e".into()]), Change::DeleteSubtree),
                (
                    Path::new(vec!["a".into(), "d".into()]),
                    Change::InsertLeaf(Digest([3; 32])),
                ),
            ][..],
        );

        assert_eq!(diff_rose_trees(&a, &b), expected_diff);
    }

    #[test]
    fn tree_diff_replace_a_leaf_with_a_non_empty_fork() {
        let a = rehashed(fork([0; 32], vec![("a", Leaf(Digest([1; 32])))]));
        let b = rehashed(fork(
            [0; 32],
            vec![("a", fork([0; 32], vec![("b", Leaf(Digest([2; 32])))]))],
        ));

        let expected_diff = changes(
            &[
                (Path::new(vec!["a".into()]), Change::DeleteSubtree),
                (
                    Path::new(vec!["a".into(), "b".into()]),
                    Change::InsertLeaf(Digest([2; 32])),
                ),
            ][..],
        );

        assert_eq!(diff_rose_trees(&a, &b), expected_diff);
    }

    #[test]
    fn tree_diff_replace_a_leaf_with_an_empty_fork() {
        let a = rehashed(fork([0; 32], vec![("a", Leaf(Digest([1; 32])))]));
        let b = rehashed(fork([0; 32], vec![("a", fork([0; 32], vec![]))]));

        let expected_diff = changes(&[(Path::new(vec!["a".into()]), Change::InsertEmptyFork)][..]);

        assert_eq!(diff_rose_trees(&a, &b), expected_diff);
    }

    #[test]
    fn tree_diff_replace_a_fork_with_a_leaf() {
        let a = rehashed(fork(
            [0; 32],
            vec![("a", fork([0; 32], vec![("b", Leaf(Digest([2; 32])))]))],
        ));
        let b = rehashed(fork([0; 32], vec![("a", Leaf(Digest([1; 32])))]));

        let expected_diff = changes(
            &[(
                Path::new(vec!["a".into()]),
                Change::InsertLeaf(Digest([1; 32])),
            )][..],
        );

        assert_eq!(diff_rose_trees(&a, &b), expected_diff);
    }

    #[test]
    fn tree_diff_remove_children() {
        let a = rehashed(fork(
            [0; 32],
            vec![(
                "root",
                fork(
                    [0; 32],
                    vec![("a", Leaf(Digest([1; 32]))), ("b", Leaf(Digest([2; 32])))],
                ),
            )],
        ));
        let b = rehashed(fork([0; 32], vec![("root", fork([0; 32], vec![]))]));

        // NOTE(roman): this diff is not optimal. The optimal one would be
        // "root" => InsertEmptyFork
        let expected_diff = changes(
            &[
                (
                    Path::new(vec!["root".into(), "a".into()]),
                    Change::DeleteSubtree,
                ),
                (
                    Path::new(vec!["root".into(), "b".into()]),
                    Change::DeleteSubtree,
                ),
            ][..],
        );

        assert_eq!(diff_rose_trees(&a, &b), expected_diff);
    }

    #[test]
    fn hash_tree_to_rose_tree() {
        let t = hash_fork(
            [1; 32],
            hash_fork(
                [2; 32],
                hash_node([3; 32], "x", hash_leaf([4; 32])),
                hash_node([5; 32], "y", hash_leaf([6; 32])),
            ),
            hash_node([7; 32], "z", hash_leaf([8; 32])),
        );

        let expected = fork(
            [1; 32],
            vec![
                ("x", Leaf(Digest([4; 32]))),
                ("y", Leaf(Digest([6; 32]))),
                ("z", Leaf(Digest([8; 32]))),
            ],
        );

        assert_eq!(RoseHashTree::from(&t), expected);
    }
}
