use crate::hashtree::{
    Hash,
    HashTree::{self, Empty, Leaf, Pruned},
    fork, fork_hash, labeled, labeled_hash, leaf_hash,
};
use std::borrow::Cow;
use std::cmp::Ordering::{self, Equal, Greater, Less};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Color {
    Red,
    Black,
}

impl Color {
    fn flip_assign(&mut self) {
        *self = self.flip();
    }

    fn flip(self) -> Self {
        match self {
            Self::Red => Self::Black,
            Self::Black => Self::Red,
        }
    }
}

/// Types that can be converted into a [`HashTree`].
pub trait AsHashTree {
    /// Returns the root hash of the tree without constructing it.
    /// Must be equivalent to `as_hash_tree().reconstruct()`.
    fn root_hash(&self) -> Hash;

    /// Constructs a hash tree corresponding to the data.
    fn as_hash_tree(&self) -> HashTree<'_>;
}

impl AsHashTree for Vec<u8> {
    fn root_hash(&self) -> Hash {
        leaf_hash(&self[..])
    }

    fn as_hash_tree(&self) -> HashTree<'_> {
        Leaf(Cow::from(&self[..]))
    }
}

impl AsHashTree for Hash {
    fn root_hash(&self) -> Hash {
        leaf_hash(&self[..])
    }

    fn as_hash_tree(&self) -> HashTree<'_> {
        Leaf(Cow::from(&self[..]))
    }
}

impl<K: AsRef<[u8]>, V: AsHashTree> AsHashTree for RbTree<K, V> {
    fn root_hash(&self) -> Hash {
        match self.root.as_ref() {
            None => Empty.reconstruct(),
            Some(n) => n.subtree_hash,
        }
    }

    fn as_hash_tree(&self) -> HashTree<'_> {
        Node::full_witness_tree(&self.root, Node::data_tree)
    }
}

#[derive(PartialEq, Debug, Clone, Copy)]
enum KeyBound<'a> {
    Exact(&'a [u8]),
    Neighbor(&'a [u8]),
}

impl<'a> AsRef<[u8]> for KeyBound<'a> {
    fn as_ref(&self) -> &'a [u8] {
        match self {
            KeyBound::Exact(key) => key,
            KeyBound::Neighbor(key) => key,
        }
    }
}

type NodeRef<K, V> = Option<Box<Node<K, V>>>;

// 1. All leaves are black.
// 2. Children of a red node are black.
// 3. Every path from a node goes through the same number of black
//    nodes.
#[derive(Clone, Debug)]
struct Node<K, V> {
    key: K,
    value: V,
    left: NodeRef<K, V>,
    right: NodeRef<K, V>,
    color: Color,

    /// Hash of the full hash tree built from this node and its
    /// children. It needs to be recomputed after every rotation.
    subtree_hash: Hash,
}

impl<K: AsRef<[u8]>, V: AsHashTree> Node<K, V> {
    fn new(key: K, value: V) -> Box<Node<K, V>> {
        let value_hash = value.root_hash();
        let data_hash = labeled_hash(key.as_ref(), &value_hash);
        Box::new(Self {
            key,
            value,
            left: None,
            right: None,
            color: Color::Red,
            subtree_hash: data_hash,
        })
    }

    fn data_hash(&self) -> Hash {
        labeled_hash(self.key.as_ref(), &self.value.root_hash())
    }

    fn left_hash_tree(&self) -> HashTree<'_> {
        match self.left.as_ref() {
            None => Empty,
            Some(l) => Pruned(l.subtree_hash),
        }
    }

    fn right_hash_tree(&self) -> HashTree<'_> {
        match self.right.as_ref() {
            None => Empty,
            Some(r) => Pruned(r.subtree_hash),
        }
    }

    fn visit<'a, F>(n: &'a NodeRef<K, V>, f: &mut F)
    where
        F: 'a + FnMut(&'a [u8], &'a V),
    {
        if let Some(n) = n {
            Self::visit(&n.left, f);
            (*f)(n.key.as_ref(), &n.value);
            Self::visit(&n.right, f);
        }
    }

    fn data_tree(&self) -> HashTree<'_> {
        labeled(self.key.as_ref(), self.value.as_hash_tree())
    }

    fn subtree_with<'a>(&'a self, f: impl FnOnce(&'a V) -> HashTree<'a>) -> HashTree<'a> {
        labeled(self.key.as_ref(), f(&self.value))
    }

    fn witness_tree(&self) -> HashTree<'_> {
        labeled(self.key.as_ref(), Pruned(self.value.root_hash()))
    }

    fn full_witness_tree<'a>(
        n: &'a NodeRef<K, V>,
        f: fn(&'a Node<K, V>) -> HashTree<'a>,
    ) -> HashTree<'a> {
        match n {
            None => Empty,
            Some(n) => three_way_fork(
                Self::full_witness_tree(&n.left, f),
                f(n),
                Self::full_witness_tree(&n.right, f),
            ),
        }
    }

    fn update_subtree_hash(&mut self) {
        self.subtree_hash = self.compute_subtree_hash();
    }

    fn compute_subtree_hash(&self) -> Hash {
        let h = self.data_hash();

        match (self.left.as_ref(), self.right.as_ref()) {
            (None, None) => h,
            (Some(l), None) => fork_hash(&l.subtree_hash, &h),
            (None, Some(r)) => fork_hash(&h, &r.subtree_hash),
            (Some(l), Some(r)) => fork_hash(&l.subtree_hash, &fork_hash(&h, &r.subtree_hash)),
        }
    }
}

#[derive(PartialEq, Debug)]
enum Visit {
    Pre,
    In,
    Post,
}

/// Iterator over a `RbTree`.
#[derive(Debug)]
pub struct Iter<'a, K, V> {
    /// Invariants:
    /// 1. visit == Pre: none of the nodes in parents were visited yet.
    /// 2. visit == In:  the last node in parents and all its left children are visited.
    /// 3. visit == Post: all the nodes reachable from the last node in parents are visited.
    visit: Visit,
    parents: Vec<&'a Node<K, V>>,
}

impl<K, V> Iter<'_, K, V> {
    /// This function is an adaptation of the `traverse_step` procedure described in
    /// section 7.2 "Bidirectional Bifurcate Coordinates" of
    /// "Elements of Programming" by A. Stepanov and P. McJones, p. 118.
    /// <http://elementsofprogramming.com/eop.pdf>
    ///
    /// The main difference is that our nodes don't have parent links for two reasons:
    /// 1. They don't play well with safe Rust ownership model.
    /// 2. Iterating a tree shouldn't be an operation common enough to complicate the code.
    fn step(&mut self) -> bool {
        match self.parents.last() {
            Some(tip) => {
                match self.visit {
                    Visit::Pre => {
                        if let Some(l) = &tip.left {
                            self.parents.push(l);
                        } else {
                            self.visit = Visit::In;
                        }
                    }
                    Visit::In => {
                        if let Some(r) = &tip.right {
                            self.parents.push(r);
                            self.visit = Visit::Pre;
                        } else {
                            self.visit = Visit::Post;
                        }
                    }
                    Visit::Post => {
                        let tip = self.parents.pop().unwrap();
                        if let Some(parent) = self.parents.last() {
                            if parent
                                .left
                                .as_ref()
                                .is_some_and(|l| std::ptr::eq(l.as_ref(), tip))
                            {
                                self.visit = Visit::In;
                            }
                        }
                    }
                }
                true
            }
            None => false,
        }
    }
}

impl<'a, K, V> std::iter::Iterator for Iter<'a, K, V> {
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        while self.step() {
            if self.visit == Visit::In {
                return self.parents.last().map(|n| (&n.key, &n.value));
            }
        }
        None
    }
}

/// Implements mutable left-leaning red-black trees as defined in
/// <https://www.cs.princeton.edu/~rs/talks/LLRB/LLRB.pdf>
#[derive(Default, Clone)]
pub struct RbTree<K, V> {
    root: NodeRef<K, V>,
}

impl<K, V> PartialEq for RbTree<K, V>
where
    K: AsRef<[u8]> + PartialEq,
    V: AsHashTree + PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.iter().eq(other.iter())
    }
}

impl<K, V> Eq for RbTree<K, V>
where
    K: AsRef<[u8]> + Eq,
    V: AsHashTree + Eq,
{
}

impl<K, V> PartialOrd for RbTree<K, V>
where
    K: AsRef<[u8]> + PartialOrd,
    V: AsHashTree + PartialOrd,
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.iter().partial_cmp(other.iter())
    }
}

impl<K, V> Ord for RbTree<K, V>
where
    K: AsRef<[u8]> + Ord,
    V: AsHashTree + Ord,
{
    fn cmp(&self, other: &Self) -> Ordering {
        self.iter().cmp(other.iter())
    }
}

impl<K, V> std::iter::FromIterator<(K, V)> for RbTree<K, V>
where
    K: AsRef<[u8]>,
    V: AsHashTree,
{
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = (K, V)>,
    {
        let mut t = RbTree::<K, V>::new();
        for (k, v) in iter {
            t.insert(k, v);
        }
        t
    }
}

impl<K, V> std::fmt::Debug for RbTree<K, V>
where
    K: AsRef<[u8]> + std::fmt::Debug,
    V: AsHashTree + std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[")?;
        let mut first = true;
        for (k, v) in self {
            if !first {
                write!(f, ", ")?;
            }
            first = false;
            write!(f, "({k:?}, {v:?})")?;
        }
        write!(f, "]")
    }
}

impl<K, V> RbTree<K, V> {
    /// Constructs a new empty tree.
    pub const fn new() -> Self {
        Self { root: None }
    }

    /// Returns true if the map is empty.
    pub const fn is_empty(&self) -> bool {
        self.root.is_none()
    }
}

impl<K: AsRef<[u8]>, V: AsHashTree> RbTree<K, V> {
    /// Looks up the key in the map and returns the associated value, if there is one.
    pub fn get(&self, key: &[u8]) -> Option<&V> {
        let mut root = self.root.as_ref();
        while let Some(n) = root {
            match key.cmp(n.key.as_ref()) {
                Equal => return Some(&n.value),
                Less => root = n.left.as_ref(),
                Greater => root = n.right.as_ref(),
            }
        }
        None
    }

    /// Updates the value corresponding to the specified key.
    pub fn modify(&mut self, key: &[u8], f: impl FnOnce(&mut V)) {
        fn go<'t, K: 't + AsRef<[u8]>, V: AsHashTree + 't>(
            h: &mut NodeRef<K, V>,
            k: &[u8],
            f: impl FnOnce(&mut V),
        ) {
            if let Some(h) = h {
                match k.as_ref().cmp(h.key.as_ref()) {
                    Equal => {
                        f(&mut h.value);
                        h.update_subtree_hash();
                    }
                    Less => {
                        go(&mut h.left, k, f);
                        h.update_subtree_hash();
                    }
                    Greater => {
                        go(&mut h.right, k, f);
                        h.update_subtree_hash();
                    }
                }
            }
        }
        go(&mut self.root, key, f);
    }

    fn range_witness<'a>(
        &'a self,
        left: Option<KeyBound<'a>>,
        right: Option<KeyBound<'a>>,
        f: fn(&'a Node<K, V>) -> HashTree<'a>,
    ) -> HashTree<'a> {
        match (left, right) {
            (None, None) => Node::full_witness_tree(&self.root, f),
            (Some(l), None) => self.witness_range_above(l, f),
            (None, Some(r)) => self.witness_range_below(r, f),
            (Some(l), Some(r)) => self.witness_range_between(l, r, f),
        }
    }

    /// Constructs a hash tree that acts as a proof that there is a
    /// entry with the specified key in this map.  The proof also
    /// contains the value in question.
    ///
    /// If the key is not in the map, returns a proof of absence.
    pub fn witness<'a>(&'a self, key: &[u8]) -> HashTree<'a> {
        self.nested_witness(key, |v| v.as_hash_tree())
    }

    /// Like `witness`, but gives the caller more control over the
    /// construction of the value witness.  This method is useful for
    /// constructing witnesses for nested certified maps.
    pub fn nested_witness<'a>(
        &'a self,
        key: &[u8],
        f: impl FnOnce(&'a V) -> HashTree<'a>,
    ) -> HashTree<'a> {
        if let Some(t) = self.lookup_and_build_witness(key, f) {
            return t;
        }
        self.range_witness(
            self.lower_bound(key),
            self.upper_bound(key),
            Node::witness_tree,
        )
    }

    /// Returns a witness enumerating all the keys in this map.  The
    /// resulting tree doesn't include values, they are replaced with
    /// "Pruned" nodes.
    pub fn keys(&self) -> HashTree<'_> {
        Node::full_witness_tree(&self.root, Node::witness_tree)
    }

    /// Returns a witness for the keys in the specified range.  The
    /// resulting tree doesn't include values, they are replaced with
    /// "Pruned" nodes.
    pub fn key_range(&self, first: &[u8], last: &[u8]) -> HashTree<'_> {
        self.range_witness(
            self.lower_bound(first),
            self.upper_bound(last),
            Node::witness_tree,
        )
    }

    /// Returns a witness for the key-value pairs in the specified range.
    /// The resulting tree contains both keys and values.
    pub fn value_range(&self, first: &[u8], last: &[u8]) -> HashTree<'_> {
        self.range_witness(
            self.lower_bound(first),
            self.upper_bound(last),
            Node::data_tree,
        )
    }

    /// Returns a witness that enumerates all the keys starting with
    /// the specified prefix.
    pub fn keys_with_prefix(&self, prefix: &[u8]) -> HashTree<'_> {
        self.range_witness(
            self.lower_bound(prefix),
            self.right_prefix_neighbor(prefix),
            Node::witness_tree,
        )
    }

    /// Creates an iterator over the map's keys and values.
    pub fn iter(&self) -> Iter<'_, K, V> {
        match &self.root {
            None => Iter {
                visit: Visit::Pre,
                parents: vec![],
            },
            Some(n) => Iter {
                visit: Visit::Pre,
                parents: vec![n],
            },
        }
    }

    /// Enumerates all the key-value pairs in the tree.
    pub fn for_each<'a, F>(&'a self, mut f: F)
    where
        F: 'a + FnMut(&'a [u8], &'a V),
    {
        Node::visit(&self.root, &mut f);
    }

    fn witness_range_above<'a>(
        &'a self,
        lo: KeyBound<'a>,
        f: fn(&'a Node<K, V>) -> HashTree<'a>,
    ) -> HashTree<'a> {
        fn go<'a, 't, K: 't + AsRef<[u8]>, V: AsHashTree + 't>(
            n: &'a NodeRef<K, V>,
            lo: KeyBound<'a>,
            f: fn(&'a Node<K, V>) -> HashTree<'a>,
        ) -> HashTree<'a> {
            match n {
                None => Empty,
                Some(n) => match n.key.as_ref().cmp(lo.as_ref()) {
                    Equal => three_way_fork(
                        n.left_hash_tree(),
                        match lo {
                            KeyBound::Exact(_) => f(n),
                            KeyBound::Neighbor(_) => n.witness_tree(),
                        },
                        Node::full_witness_tree(&n.right, f),
                    ),
                    Less => three_way_fork(
                        n.left_hash_tree(),
                        Pruned(n.data_hash()),
                        go(&n.right, lo, f),
                    ),
                    Greater => three_way_fork(
                        go(&n.left, lo, f),
                        f(n),
                        Node::full_witness_tree(&n.right, f),
                    ),
                },
            }
        }
        go(&self.root, lo, f)
    }

    fn witness_range_below<'a>(
        &'a self,
        hi: KeyBound<'a>,
        f: fn(&'a Node<K, V>) -> HashTree<'a>,
    ) -> HashTree<'a> {
        fn go<'a, 't, K: 't + AsRef<[u8]>, V: AsHashTree + 't>(
            n: &'a NodeRef<K, V>,
            hi: KeyBound<'a>,
            f: fn(&'a Node<K, V>) -> HashTree<'a>,
        ) -> HashTree<'a> {
            match n {
                None => Empty,
                Some(n) => match n.key.as_ref().cmp(hi.as_ref()) {
                    Equal => three_way_fork(
                        Node::full_witness_tree(&n.left, f),
                        match hi {
                            KeyBound::Exact(_) => f(n),
                            KeyBound::Neighbor(_) => n.witness_tree(),
                        },
                        n.right_hash_tree(),
                    ),
                    Greater => three_way_fork(
                        go(&n.left, hi, f),
                        Pruned(n.data_hash()),
                        n.right_hash_tree(),
                    ),
                    Less => three_way_fork(
                        Node::full_witness_tree(&n.left, f),
                        f(n),
                        go(&n.right, hi, f),
                    ),
                },
            }
        }
        go(&self.root, hi, f)
    }

    fn witness_range_between<'a>(
        &'a self,
        lo: KeyBound<'a>,
        hi: KeyBound<'a>,
        f: fn(&'a Node<K, V>) -> HashTree<'a>,
    ) -> HashTree<'a> {
        debug_assert!(
            lo.as_ref() <= hi.as_ref(),
            "lo = {:?} > hi = {:?}",
            lo.as_ref(),
            hi.as_ref()
        );
        fn go<'a, 't, K: 't + AsRef<[u8]>, V: AsHashTree + 't>(
            n: &'a NodeRef<K, V>,
            lo: KeyBound<'a>,
            hi: KeyBound<'a>,
            f: fn(&'a Node<K, V>) -> HashTree<'a>,
        ) -> HashTree<'a> {
            match n {
                None => Empty,
                Some(n) => {
                    let k = n.key.as_ref();
                    match (lo.as_ref().cmp(k), k.cmp(hi.as_ref())) {
                        (Less, Less) => {
                            three_way_fork(go(&n.left, lo, hi, f), f(n), go(&n.right, lo, hi, f))
                        }
                        (Equal, Equal) => three_way_fork(
                            n.left_hash_tree(),
                            match (lo, hi) {
                                (KeyBound::Exact(_), _) => f(n),
                                (_, KeyBound::Exact(_)) => f(n),
                                _ => n.witness_tree(),
                            },
                            n.right_hash_tree(),
                        ),
                        (_, Equal) => three_way_fork(
                            go(&n.left, lo, hi, f),
                            match hi {
                                KeyBound::Exact(_) => f(n),
                                KeyBound::Neighbor(_) => n.witness_tree(),
                            },
                            n.right_hash_tree(),
                        ),
                        (Equal, _) => three_way_fork(
                            n.left_hash_tree(),
                            match lo {
                                KeyBound::Exact(_) => f(n),
                                KeyBound::Neighbor(_) => n.witness_tree(),
                            },
                            go(&n.right, lo, hi, f),
                        ),
                        (Less, Greater) => three_way_fork(
                            go(&n.left, lo, hi, f),
                            Pruned(n.data_hash()),
                            n.right_hash_tree(),
                        ),
                        (Greater, Less) => three_way_fork(
                            n.left_hash_tree(),
                            Pruned(n.data_hash()),
                            go(&n.right, lo, hi, f),
                        ),
                        _ => Pruned(n.subtree_hash),
                    }
                }
            }
        }
        go(&self.root, lo, hi, f)
    }

    fn lower_bound(&self, key: &[u8]) -> Option<KeyBound<'_>> {
        fn go<'a, 't, K: 't + AsRef<[u8]>, V>(
            n: &'a NodeRef<K, V>,
            key: &[u8],
        ) -> Option<KeyBound<'a>> {
            n.as_ref().and_then(|n| {
                let node_key = n.key.as_ref();
                match node_key.cmp(key) {
                    Less => go(&n.right, key).or(Some(KeyBound::Neighbor(node_key))),
                    Equal => Some(KeyBound::Exact(node_key)),
                    Greater => go(&n.left, key),
                }
            })
        }
        go(&self.root, key)
    }

    fn upper_bound(&self, key: &[u8]) -> Option<KeyBound<'_>> {
        fn go<'a, 't, K: 't + AsRef<[u8]>, V>(
            n: &'a NodeRef<K, V>,
            key: &[u8],
        ) -> Option<KeyBound<'a>> {
            n.as_ref().and_then(|n| {
                let node_key = n.key.as_ref();
                match node_key.cmp(key) {
                    Less => go(&n.right, key),
                    Equal => Some(KeyBound::Exact(node_key)),
                    Greater => go(&n.left, key).or(Some(KeyBound::Neighbor(node_key))),
                }
            })
        }
        go(&self.root, key)
    }

    fn right_prefix_neighbor(&self, prefix: &[u8]) -> Option<KeyBound<'_>> {
        fn is_prefix_of(p: &[u8], x: &[u8]) -> bool {
            if p.len() > x.len() {
                return false;
            }
            &x[0..p.len()] == p
        }
        fn go<'a, 't, K: 't + AsRef<[u8]>, V>(
            n: &'a NodeRef<K, V>,
            prefix: &[u8],
        ) -> Option<KeyBound<'a>> {
            n.as_ref().and_then(|n| {
                let node_key = n.key.as_ref();
                match node_key.cmp(prefix) {
                    Greater if is_prefix_of(prefix, node_key) => go(&n.right, prefix),
                    Greater => go(&n.left, prefix).or(Some(KeyBound::Neighbor(node_key))),
                    Less | Equal => go(&n.right, prefix),
                }
            })
        }
        go(&self.root, prefix)
    }

    fn lookup_and_build_witness<'a>(
        &'a self,
        key: &[u8],
        f: impl FnOnce(&'a V) -> HashTree<'a>,
    ) -> Option<HashTree<'a>> {
        fn go<'a, 't, K: 't + AsRef<[u8]>, V: AsHashTree + 't>(
            n: &'a NodeRef<K, V>,
            key: &[u8],
            f: impl FnOnce(&'a V) -> HashTree<'a>,
        ) -> Option<HashTree<'a>> {
            n.as_ref().and_then(|n| match key.cmp(n.key.as_ref()) {
                Equal => Some(three_way_fork(
                    n.left_hash_tree(),
                    n.subtree_with(f),
                    n.right_hash_tree(),
                )),
                Less => {
                    let subtree = go(&n.left, key, f)?;
                    Some(three_way_fork(
                        subtree,
                        Pruned(n.data_hash()),
                        n.right_hash_tree(),
                    ))
                }
                Greater => {
                    let subtree = go(&n.right, key, f)?;
                    Some(three_way_fork(
                        n.left_hash_tree(),
                        Pruned(n.data_hash()),
                        subtree,
                    ))
                }
            })
        }
        go(&self.root, key, f)
    }

    /// Inserts a key-value entry into the map.
    pub fn insert(&mut self, key: K, value: V) {
        fn go<'t, K: 't + AsRef<[u8]>, V: AsHashTree + 't>(
            h: NodeRef<K, V>,
            k: K,
            v: V,
        ) -> Box<Node<K, V>> {
            match h {
                None => Node::new(k, v),
                Some(mut h) => {
                    match k.as_ref().cmp(h.key.as_ref()) {
                        Equal => {
                            h.value = v;
                        }
                        Less => {
                            h.left = Some(go(h.left, k, v));
                        }
                        Greater => {
                            h.right = Some(go(h.right, k, v));
                        }
                    }
                    h.update_subtree_hash();
                    balance(h)
                }
            }
        }
        let mut root = go(self.root.take(), key, value);
        root.color = Color::Black;
        self.root = Some(root);

        #[cfg(test)]
        debug_assert!(
            is_balanced(&self.root),
            "the tree is not balanced:\n{:?}",
            DebugView(&self.root)
        );
    }

    /// Removes the specified key from the map.
    pub fn delete(&mut self, key: &[u8]) {
        fn move_red_left<'t, K: 't + AsRef<[u8]>, V: AsHashTree + 't>(
            mut h: Box<Node<K, V>>,
        ) -> Box<Node<K, V>> {
            flip_colors(&mut h);
            if is_red(&h.right.as_ref().unwrap().left) {
                h.right = Some(rotate_right(h.right.take().unwrap()));
                h = rotate_left(h);
                flip_colors(&mut h);
            }
            h
        }

        fn move_red_right<'t, K: 't + AsRef<[u8]>, V: AsHashTree + 't>(
            mut h: Box<Node<K, V>>,
        ) -> Box<Node<K, V>> {
            flip_colors(&mut h);
            if is_red(&h.left.as_ref().unwrap().left) {
                h = rotate_right(h);
                flip_colors(&mut h);
            }
            h
        }

        #[inline]
        fn min<'t, K: 't + AsRef<[u8]>, V: AsHashTree + 't>(
            mut h: &mut Box<Node<K, V>>,
        ) -> &mut Box<Node<K, V>> {
            while h.left.is_some() {
                h = h.left.as_mut().unwrap();
            }
            h
        }

        fn delete_min<'t, K: 't + AsRef<[u8]>, V: AsHashTree + 't>(
            mut h: Box<Node<K, V>>,
        ) -> NodeRef<K, V> {
            if h.left.is_none() {
                debug_assert!(h.right.is_none());
                drop(h);
                return None;
            }
            if !is_red(&h.left) && !is_red(&h.left.as_ref().unwrap().left) {
                h = move_red_left(h);
            }
            h.left = delete_min(h.left.unwrap());
            h.update_subtree_hash();
            Some(balance(h))
        }

        fn go<'t, K: 't + AsRef<[u8]>, V: AsHashTree + 't>(
            mut h: Box<Node<K, V>>,
            key: &[u8],
        ) -> NodeRef<K, V> {
            if key < h.key.as_ref() {
                debug_assert!(h.left.is_some(), "the key must be present in the tree");
                if !is_red(&h.left) && !is_red(&h.left.as_ref().unwrap().left) {
                    h = move_red_left(h);
                }
                h.left = go(h.left.take().unwrap(), key);
            } else {
                if is_red(&h.left) {
                    h = rotate_right(h);
                }
                if key == h.key.as_ref() && h.right.is_none() {
                    debug_assert!(h.left.is_none());
                    drop(h);
                    return None;
                }

                if !is_red(&h.right) && !is_red(&h.right.as_ref().unwrap().left) {
                    h = move_red_right(h);
                }

                if key == h.key.as_ref() {
                    let m = min(h.right.as_mut().unwrap());
                    std::mem::swap(&mut h.key, &mut m.key);
                    std::mem::swap(&mut h.value, &mut m.value);
                    h.right = delete_min(h.right.take().unwrap());
                } else {
                    h.right = go(h.right.take().unwrap(), key);
                }
            }
            h.update_subtree_hash();
            Some(balance(h))
        }

        if self.get(key).is_none() {
            return;
        }

        if !is_red(&self.root.as_ref().unwrap().left) && !is_red(&self.root.as_ref().unwrap().right)
        {
            self.root.as_mut().unwrap().color = Color::Red;
        }
        self.root = go(self.root.take().unwrap(), key);
        if let Some(n) = self.root.as_mut() {
            n.color = Color::Black;
        }

        #[cfg(test)]
        debug_assert!(
            is_balanced(&self.root),
            "unbalanced map: {:?}",
            DebugView(&self.root)
        );

        debug_assert!(self.get(key).is_none());
    }
}

impl<'a, K: AsRef<[u8]>, V: AsHashTree> IntoIterator for &'a RbTree<K, V> {
    type Item = (&'a K, &'a V);
    type IntoIter = Iter<'a, K, V>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

use candid::CandidType;

impl<K, V> CandidType for RbTree<K, V>
where
    K: CandidType + AsRef<[u8]>,
    V: CandidType + AsHashTree,
{
    fn _ty() -> candid::types::internal::Type {
        <Vec<(&K, &V)> as CandidType>::_ty()
    }
    fn idl_serialize<S: candid::types::Serializer>(&self, serializer: S) -> Result<(), S::Error> {
        let collect_as_vec = self.iter().collect::<Vec<(&K, &V)>>();
        <Vec<(&K, &V)> as CandidType>::idl_serialize(&collect_as_vec, serializer)
    }
}

use serde::{
    de::{Deserialize, Deserializer, MapAccess, Visitor},
    ser::{Serialize, SerializeMap, Serializer},
};
use std::marker::PhantomData;

impl<K, V> Serialize for RbTree<K, V>
where
    K: Serialize + AsRef<[u8]>,
    V: Serialize + AsHashTree,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.iter().count()))?;
        for (k, v) in self {
            map.serialize_entry(k, v)?;
        }
        map.end()
    }
}

// The PhantomData keeps the compiler from complaining about unused generic type parameters.
struct RbTreeSerdeVisitor<K, V> {
    marker: PhantomData<fn() -> RbTree<K, V>>,
}

impl<K, V> RbTreeSerdeVisitor<K, V> {
    fn new() -> Self {
        RbTreeSerdeVisitor {
            marker: PhantomData,
        }
    }
}

impl<'de, K, V> Visitor<'de> for RbTreeSerdeVisitor<K, V>
where
    K: Deserialize<'de> + AsRef<[u8]>,
    V: Deserialize<'de> + AsHashTree,
{
    type Value = RbTree<K, V>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a map")
    }

    fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut t = RbTree::<K, V>::new();
        while let Some((key, value)) = access.next_entry()? {
            t.insert(key, value);
        }
        Ok(t)
    }
}

impl<'de, K, V> Deserialize<'de> for RbTree<K, V>
where
    K: Deserialize<'de> + AsRef<[u8]>,
    V: Deserialize<'de> + AsHashTree,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(RbTreeSerdeVisitor::new())
    }
}

fn three_way_fork<'a>(l: HashTree<'a>, m: HashTree<'a>, r: HashTree<'a>) -> HashTree<'a> {
    match (l, m, r) {
        (Empty, m, Empty) => m,
        (l, m, Empty) => fork(l, m),
        (Empty, m, r) => fork(m, r),
        (Pruned(lhash), Pruned(mhash), Pruned(rhash)) => {
            Pruned(fork_hash(&lhash, &fork_hash(&mhash, &rhash)))
        }
        (l, Pruned(mhash), Pruned(rhash)) => fork(l, Pruned(fork_hash(&mhash, &rhash))),
        (l, m, r) => fork(l, fork(m, r)),
    }
}

// helper functions
fn is_red<K, V>(x: &NodeRef<K, V>) -> bool {
    x.as_ref().is_some_and(|h| h.color == Color::Red)
}

fn balance<'t, K: AsRef<[u8]> + 't, V: AsHashTree + 't>(mut h: Box<Node<K, V>>) -> Box<Node<K, V>> {
    if is_red(&h.right) && !is_red(&h.left) {
        h = rotate_left(h);
    }
    if is_red(&h.left) && is_red(&h.left.as_ref().unwrap().left) {
        h = rotate_right(h);
    }
    if is_red(&h.left) && is_red(&h.right) {
        flip_colors(&mut h);
    }
    h
}

/// Make a left-leaning link lean to the right.
fn rotate_right<'t, K: 't + AsRef<[u8]>, V: AsHashTree + 't>(
    mut h: Box<Node<K, V>>,
) -> Box<Node<K, V>> {
    debug_assert!(is_red(&h.left));

    let mut x = h.left.take().unwrap();
    h.left = x.right.take();
    h.update_subtree_hash();

    x.right = Some(h);
    x.color = x.right.as_ref().unwrap().color;
    x.right.as_mut().unwrap().color = Color::Red;
    x.update_subtree_hash();

    x
}

fn rotate_left<'t, K: 't + AsRef<[u8]>, V: AsHashTree + 't>(
    mut h: Box<Node<K, V>>,
) -> Box<Node<K, V>> {
    debug_assert!(is_red(&h.right));

    let mut x = h.right.take().unwrap();
    h.right = x.left.take();
    h.update_subtree_hash();

    x.left = Some(h);
    x.color = x.left.as_ref().unwrap().color;
    x.left.as_mut().unwrap().color = Color::Red;
    x.update_subtree_hash();

    x
}

fn flip_colors<K, V>(h: &mut Box<Node<K, V>>) {
    h.color.flip_assign();
    h.left.as_mut().unwrap().color.flip_assign();
    h.right.as_mut().unwrap().color.flip_assign();
}

#[cfg(test)]
fn is_balanced<K, V>(root: &NodeRef<K, V>) -> bool {
    fn go<K, V>(node: &NodeRef<K, V>, mut num_black: usize) -> bool {
        match node {
            None => num_black == 0,
            Some(n) => {
                if !is_red(node) {
                    debug_assert!(num_black > 0);
                    num_black -= 1;
                } else {
                    assert!(!is_red(&n.left));
                    assert!(!is_red(&n.right));
                }
                go(&n.left, num_black) && go(&n.right, num_black)
            }
        }
    }

    let mut num_black = 0;
    let mut x = root;
    while let Some(n) = x {
        if !is_red(x) {
            num_black += 1;
        }
        x = &n.left;
    }
    go(root, num_black)
}

#[allow(dead_code)]
struct DebugView<'a, K, V>(&'a NodeRef<K, V>);

impl<K: AsRef<[u8]>, V> fmt::Debug for DebugView<'_, K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn go<K: AsRef<[u8]>, V>(
            f: &mut fmt::Formatter<'_>,
            node: &NodeRef<K, V>,
            offset: usize,
        ) -> fmt::Result {
            match node {
                None => writeln!(f, "{:width$}[B] <null>", "", width = offset),
                Some(h) => {
                    writeln!(
                        f,
                        "{:width$}[{}] {:?}",
                        "",
                        if is_red(node) { "R" } else { "B" },
                        h.key.as_ref(),
                        width = offset
                    )?;
                    go(f, &h.left, offset + 2)?;
                    go(f, &h.right, offset + 2)
                }
            }
        }
        go(f, self.0, 0)
    }
}

#[cfg(test)]
mod test;
