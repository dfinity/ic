//! This module provides an implementation of a persistent map with integer
//! keys.
#[cfg(test)]
mod test;

use ic_validate_eq::ValidateEq;
use phantom_newtype::Id;
use std::cmp::Ordering;
use std::fmt::Debug;
use std::ops::{BitAnd, BitOr, BitXor, Not, Shl, Sub};
use std::sync::Arc;

/// Big-endian patricia trees.
///
/// `K` and `V` are the key and value types, respectively, where `K` can be
/// represented as an unsigned integer type (`u64` or `u128`).
#[derive(Clone, Debug, Default)]
enum Tree<K: AsInt, V> {
    /// An empty tree.
    ///
    /// Allowing empty trees simplifies the code a bit.
    #[default]
    Empty,

    /// A key-value pair.
    Leaf(K, V),

    /// A binary fork.
    ///
    /// Invariants:
    ///
    ///   * Both left and right subtrees aren't empty, i.e.,
    ///     ```
    ///     left.len() > 0 && right.len() > 0
    ///     ```
    ///
    ///   * For each leaf `L` in `left` and `right`, the key bits match the prefix
    ///     up to but not including the branching bit, i.e.,
    ///     ```
    ///     matches_prefix(L.key, prefix, branching_bit) == true
    ///     ```
    ///
    ///   * For each leaf `L` in the left subtree:
    ///     ```
    ///     L.key & (1 << branching_bit) == 0
    ///     ```
    ///
    ///   * For each leaf `L` in the right subtree:
    ///     ```
    ///     L.key & (1 << branching_bit) != 0
    ///     ```
    ///
    ///   * ```
    ///     0 ≤ branching_bit < K::Repr::size_bits().
    ///     ```
    Branch {
        prefix: K::Repr,
        branching_bit: u8,
        left: Arc<Tree<K, V>>,
        right: Arc<Tree<K, V>>,
    },
}

/// Creates a branch node having subtrees `t0` and `t1` as children.
///
/// Precondition: `p0 ≠ p1`
#[inline]
fn join<K: AsInt, V>(
    p0: K::Repr,
    t0: Arc<Tree<K, V>>,
    p1: K::Repr,
    t1: Arc<Tree<K, V>>,
) -> Tree<K, V> {
    debug_assert_eq!(
        p0,
        match t0.as_ref() {
            Tree::Leaf(k, _) => k.as_int(),
            Tree::Branch { prefix, .. } => *prefix,
            Tree::Empty => panic!("expected a leaf or branch"),
        }
    );
    debug_assert_eq!(
        p1,
        match t1.as_ref() {
            Tree::Leaf(k, _) => k.as_int(),
            Tree::Branch { prefix, .. } => *prefix,
            Tree::Empty => panic!("expected a leaf or branch"),
        }
    );

    let branching_bit = branching_bit(p0, p1);
    let prefix = mask(p0, branching_bit);

    // NB: This assumes that `K::Repr` is an unsigned integer type. This is ensured
    // by the `IntKey` extending `sealed::UnsignedInt` (which is only implemented
    // for unsigned integer types).
    if p0 < p1 {
        Tree::Branch {
            prefix,
            branching_bit,
            left: t0,
            right: t1,
        }
    } else {
        Tree::Branch {
            prefix,
            branching_bit,
            left: t1,
            right: t0,
        }
    }
}

/// Modifies the contents of an `Arc`, creating a copy if necessary.
#[inline]
fn with_arc<T: Clone + Default>(mut p: Arc<T>, f: impl FnOnce(T) -> T) -> Arc<T> {
    let dst = Arc::make_mut(&mut p);
    *dst = f(std::mem::take(dst));
    p
}

/// Calls the given function on the mutable contents of an `Arc`, creating a
/// copy if necessary.
#[inline]
fn with_arc2<T: Clone + Default, V>(mut p: Arc<T>, f: impl FnOnce(T) -> (T, V)) -> (Arc<T>, V) {
    let dst = Arc::make_mut(&mut p);
    let v;
    (*dst, v) = f(std::mem::take(dst));
    (p, v)
}

/// Extracts a value from an `Arc`, cloning its content if necessary.
#[inline]
fn take_arc<T: Clone>(p: Arc<T>) -> T {
    match Arc::try_unwrap(p) {
        Ok(x) => x,
        Err(arc) => (*arc).clone(),
    }
}

/// The return type of the `bounds()` method.
///
/// See the comments of the public `bounds()` method.
pub(crate) type Bounds<'a, K, V> = (Option<(&'a K, &'a V)>, Option<(&'a K, &'a V)>);

mod int_key {
    /// Limit the types that can be used as `IntKey` to unsigned integer types.
    ///
    /// Warning! Do not implement this trait for other types.
    pub(super) trait UnsignedInt {}

    impl UnsignedInt for u64 {}
    impl UnsignedInt for u128 {}
}

/// An integer key type for `IntMap` (implemented for `u64` and `u128`).
#[allow(private_bounds)]
pub trait IntKey:
    Sized
    + Eq
    + Ord
    + Copy
    + Sub<Self, Output = Self>
    + BitAnd<Self, Output = Self>
    + BitOr<Self, Output = Self>
    + BitXor<Self, Output = Self>
    + Not<Output = Self>
    + Shl<u8, Output = Self>
    + Debug
    + int_key::UnsignedInt
{
    /// The type's zero value.
    fn zero() -> Self;

    /// The type's unit value.
    fn one() -> Self;

    /// The type's maximum value.
    fn max_value() -> Self;

    /// The type's size in bits.
    #[inline]
    fn size_bits() -> u8 {
        size_of::<Self>() as u8 * 8
    }

    /// Returns the number of leading zeros in the binary representation of `self`.
    fn leading_zeros(self) -> u32;
}

impl IntKey for u64 {
    #[inline]
    fn zero() -> Self {
        0
    }

    #[inline]
    fn one() -> Self {
        1
    }

    #[inline]
    fn max_value() -> Self {
        Self::MAX
    }

    #[inline]
    fn leading_zeros(self) -> u32 {
        self.leading_zeros()
    }
}

impl IntKey for u128 {
    #[inline]
    fn zero() -> Self {
        0
    }

    #[inline]
    fn one() -> Self {
        1
    }

    #[inline]
    fn max_value() -> Self {
        Self::MAX
    }

    #[inline]
    fn leading_zeros(self) -> u32 {
        self.leading_zeros()
    }
}

/// Conversion from actual key type (`K`) to `IntKey`.
///
/// The compiler doesn't like us using `From` / `Into` for this, so we define
/// our own trait instead.
pub trait AsInt: Copy + Ord {
    type Repr: IntKey;

    fn as_int(&self) -> Self::Repr;
}

impl AsInt for u64 {
    type Repr = u64;

    #[inline]
    fn as_int(&self) -> u64 {
        *self
    }
}

impl<Entity> AsInt for Id<Entity, u64> {
    type Repr = u64;

    #[inline]
    fn as_int(&self) -> u64 {
        self.get()
    }
}

impl<K: AsInt, V: Clone> Tree<K, V> {
    fn get(&self, key: K::Repr) -> Option<&V> {
        match self {
            Tree::Empty => None,

            Tree::Leaf(k, v) => {
                if key == k.as_int() {
                    Some(v)
                } else {
                    None
                }
            }

            Tree::Branch {
                prefix,
                branching_bit,
                left,
                right,
            } => {
                if !matches_prefix(key, *prefix, *branching_bit) {
                    None
                } else if key & (K::Repr::one() << *branching_bit) == K::Repr::zero() {
                    (*left).get(key)
                } else {
                    (*right).get(key)
                }
            }
        }
    }

    /// See the comments of the public `bounds()` method.
    fn bounds(&self, key: &K) -> Bounds<'_, K, V> {
        match self {
            Tree::Empty => (None, None),

            Tree::Leaf(k, v) => match key.cmp(k) {
                Ordering::Less => (None, Some((k, v))),
                Ordering::Equal => (Some((k, v)), Some((k, v))),
                Ordering::Greater => (Some((k, v)), None),
            },

            Tree::Branch {
                prefix,
                branching_bit,
                left,
                right,
            } => {
                let key_int = key.as_int();
                match mask(key_int, *branching_bit).cmp(prefix) {
                    Ordering::Less => (None, (*left).min()),
                    Ordering::Greater => ((*right).max(), None),
                    Ordering::Equal => {
                        if key_int & (K::Repr::one() << *branching_bit) == K::Repr::zero() {
                            let (start, end) = (*left).bounds(key);
                            if end.is_none() {
                                (start, (*right).min())
                            } else {
                                (start, end)
                            }
                        } else {
                            let (start, end) = (*right).bounds(key);
                            if start.is_none() {
                                ((*left).max(), end)
                            } else {
                                (start, end)
                            }
                        }
                    }
                }
            }
        }
    }

    /// Returns the smallest key/value pair in this tree.
    /// If the tree is empty, then it returns `None`.
    fn min(&self) -> Option<(&K, &V)> {
        let mut node = self;
        loop {
            match node {
                Tree::Empty => {
                    return None;
                }

                Tree::Leaf(k, v) => {
                    return Some((k, v));
                }

                Tree::Branch {
                    prefix: _,
                    branching_bit: _,
                    left,
                    right: _,
                } => {
                    node = left.as_ref();
                }
            }
        }
    }

    /// Returns the largest key/value pair in this tree.
    /// If the tree is empty, then it returns `None`.
    fn max(&self) -> Option<(&K, &V)> {
        let mut node = self;
        loop {
            match node {
                Tree::Empty => {
                    return None;
                }

                Tree::Leaf(k, v) => {
                    return Some((k, v));
                }

                Tree::Branch {
                    prefix: _,
                    branching_bit: _,
                    left: _,
                    right,
                } => {
                    node = right.as_ref();
                }
            }
        }
    }

    fn insert(self, key: K, value: V) -> (Self, Option<V>) {
        match self {
            Tree::Empty => (Tree::Leaf(key, value), None),

            Tree::Leaf(k, v) => {
                if k == key {
                    (Tree::Leaf(k, value), Some(v))
                } else {
                    (
                        join(
                            key.as_int(),
                            Arc::new(Tree::Leaf(key, value)),
                            k.as_int(),
                            Arc::new(Tree::Leaf(k, v)),
                        ),
                        None,
                    )
                }
            }

            Tree::Branch {
                prefix,
                branching_bit,
                left,
                right,
            } => {
                let key_int = key.as_int();
                if matches_prefix(key_int, prefix, branching_bit) {
                    if key_int & (K::Repr::one() << branching_bit) == K::Repr::zero() {
                        let (left, res) = with_arc2(left, |l| l.insert(key, value));
                        (
                            Tree::Branch {
                                prefix,
                                branching_bit,
                                left,
                                right,
                            },
                            res,
                        )
                    } else {
                        let (right, res) = with_arc2(right, |r| r.insert(key, value));
                        (
                            Tree::Branch {
                                prefix,
                                branching_bit,
                                left,
                                right,
                            },
                            res,
                        )
                    }
                } else {
                    (
                        join(
                            key_int,
                            Arc::new(Tree::Leaf(key, value)),
                            prefix,
                            Arc::new(Tree::Branch {
                                prefix,
                                branching_bit,
                                left,
                                right,
                            }),
                        ),
                        None,
                    )
                }
            }
        }
    }

    fn remove(self, key: &K) -> (Self, Option<V>) {
        match self {
            Tree::Empty => (Tree::Empty, None),

            Tree::Leaf(k, v) if &k == key => (Tree::Empty, Some(v)),

            Tree::Leaf(..) => (self, None),

            Tree::Branch {
                prefix,
                branching_bit,
                left,
                right,
            } if matches_prefix(key.as_int(), prefix, branching_bit) => {
                if key.as_int() & (K::Repr::one() << branching_bit) == K::Repr::zero() {
                    let (left, res) = take_arc(left).remove(key);
                    match left {
                        Tree::Empty => (take_arc(right), res),
                        _ => (
                            Tree::Branch {
                                prefix,
                                branching_bit,
                                left: Arc::new(left),
                                right,
                            },
                            res,
                        ),
                    }
                } else {
                    let (right, res) = take_arc(right).remove(key);
                    match right {
                        Tree::Empty => (take_arc(left), res),
                        _ => (
                            Tree::Branch {
                                prefix,
                                branching_bit,
                                left,
                                right: Arc::new(right),
                            },
                            res,
                        ),
                    }
                }
            }

            Tree::Branch { .. } => (self, None),
        }
    }

    fn union(self, other: Self) -> Self {
        match (self, other) {
            (Tree::Empty, t) | (t, Tree::Empty) => t,

            (Tree::Leaf(k, v), t) => t.insert(k, v).0,

            (t, Tree::Leaf(k, v)) => {
                if t.get(k.as_int()).is_some() {
                    // In case of collision, retain the value in `self`.
                    t
                } else {
                    t.insert(k, v).0
                }
            }

            (
                Tree::Branch {
                    prefix: p0,
                    branching_bit: b0,
                    left: left0,
                    right: right0,
                },
                Tree::Branch {
                    prefix: p1,
                    branching_bit: b1,
                    left: left1,
                    right: right1,
                },
            ) => {
                if p0 == p1 && b0 == b1 {
                    // The trees have the same prefix. Merge the subtrees
                    Tree::Branch {
                        prefix: p0,
                        branching_bit: b0,
                        left: with_arc(left0, move |l| l.union(take_arc(left1))),
                        right: with_arc(right0, move |r| r.union(take_arc(right1))),
                    }
                } else if b0 > b1 && matches_prefix(p1, p0, b0) {
                    // Pattern p1 contains p0 as a sub-pattern.
                    let t = Tree::Branch {
                        prefix: p1,
                        branching_bit: b1,
                        left: left1,
                        right: right1,
                    };
                    if p1 & (K::Repr::one() << b0) == K::Repr::zero() {
                        Tree::Branch {
                            prefix: p0,
                            branching_bit: b0,
                            left: with_arc(left0, move |l| l.union(t)),
                            right: right0,
                        }
                    } else {
                        Tree::Branch {
                            prefix: p0,
                            branching_bit: b0,
                            left: left0,
                            right: with_arc(right0, move |r| r.union(t)),
                        }
                    }
                } else if b1 > b0 && matches_prefix(p0, p1, b1) {
                    // Pattern p0 contains p1 as a sub-pattern.
                    let s = Tree::Branch {
                        prefix: p0,
                        branching_bit: b0,
                        left: left0,
                        right: right0,
                    };
                    if p0 & (K::Repr::one() << b1) == K::Repr::zero() {
                        Tree::Branch {
                            prefix: p1,
                            branching_bit: b1,
                            left: with_arc(left1, move |l| s.union(l)),
                            right: right1,
                        }
                    } else {
                        Tree::Branch {
                            prefix: p1,
                            branching_bit: b1,
                            left: left1,
                            right: with_arc(right1, move |r| s.union(r)),
                        }
                    }
                } else {
                    let s = Tree::Branch {
                        prefix: p0,
                        branching_bit: b0,
                        left: left0,
                        right: right0,
                    };
                    let t = Tree::Branch {
                        prefix: p1,
                        branching_bit: b1,
                        left: left1,
                        right: right1,
                    };
                    join(p0, Arc::new(s), p1, Arc::new(t))
                }
            }
        }
    }

    /// Splits the tree in two just before the given key.
    pub fn split(self, key: &K) -> (Self, Self) {
        match self {
            Tree::Empty => (Tree::Empty, Tree::Empty),

            Tree::Leaf(k, _) if k.as_int() < key.as_int() => (self, Tree::Empty),

            Tree::Leaf(..) => (Tree::Empty, self),

            Tree::Branch {
                prefix,
                branching_bit,
                left,
                right,
            } if matches_prefix(key.as_int(), prefix, branching_bit) => {
                if key.as_int() & (K::Repr::one() << branching_bit) == K::Repr::zero() {
                    let (ll, lr) = take_arc(left).split(key);
                    (ll, lr.union(take_arc(right)))
                } else {
                    let (rl, rr) = take_arc(right).split(key);
                    (take_arc(left).union(rl), rr)
                }
            }

            Tree::Branch { prefix, .. } => {
                if prefix < key.as_int() {
                    (self, Tree::Empty)
                } else {
                    (Tree::Empty, self)
                }
            }
        }
    }

    fn len(&self) -> usize {
        match self {
            Tree::Empty => 0,

            Tree::Leaf(_, _) => 1,

            Tree::Branch { left, right, .. } => left.len() + right.len(),
        }
    }
}

impl<K, V> ValidateEq for Tree<K, V>
where
    K: AsInt + PartialEq + std::fmt::Debug,
    V: ValidateEq + Clone,
{
    fn validate_eq(&self, rhs: &Self) -> Result<(), String> {
        let mut left_iter = IntMapIter::new(self);
        let mut right_iter = IntMapIter::new(rhs);

        loop {
            match (left_iter.next(), right_iter.next()) {
                (None, None) => return Ok(()),

                (Some((lk, lv)), Some((rk, rv))) => {
                    if lk != rk {
                        return Err(format!("Key divergence: {lk:#?} != {rk:#?}"));
                    }
                    if let Err(err) = lv.validate_eq(rv) {
                        return Err(format!("Value divergence @{lk:#?}: {err}"));
                    }
                }

                _ => {
                    return Err(format!(
                        "Length divergence: {} != {}",
                        self.len(),
                        rhs.len()
                    ));
                }
            }
        }
    }
}

/// Purely functional persistent sorted map with an integer-like key.
///
/// Persistence means that the map can be cheaply cloned (in `O(1)`), and each
/// version can be modified independently.
///
/// This data structure provides blazingly fast lookups (often comparable to or
/// surpassing a `HashMap`) with relatively expensive inserts (2-10x slower than
/// a `HashMap`, depending on the size of the value and the map).
///
/// The implementation is based on big-endian patricia trees.
///
/// Chris Okasaki and Andy Gill, "Fast Mergeable Integer Maps", Workshop on ML,
/// September 1998, pages 77-86,
/// http://citeseerx.ist.psu.edu/viewdoc/summary?doi=10.1.1.37.5452
#[derive(Clone, Debug)]
pub struct IntMap<K: AsInt, V>(Tree<K, V>);

impl<K: AsInt, V> Default for IntMap<K, V> {
    fn default() -> Self {
        Self(Tree::Empty)
    }
}

impl<K: AsInt, V: Clone> IntMap<K, V> {
    /// Creates a new empty map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Looks up a value by key.
    ///
    /// Complexity: `O(min(N, |key|))`.
    pub fn get(&self, key: &K) -> Option<&V> {
        self.0.get(key.as_int())
    }

    /// Returns `true` if the map contains the specified key.
    ///
    /// Complexity: `O(min(N, |key|))`.
    pub fn contains_key(&self, key: &K) -> bool {
        self.0.get(key.as_int()).is_some()
    }

    /// Returns `(lower, upper)` inclusive bounds for the given key such that:
    /// - `lower` is the largest key/value pair in the tree that is smaller than
    ///   or equal to the given key. If such a key doesn't exist, then
    ///   `lower = None`.
    /// - `upper` is the smallest key/value pair in the tree that is larger than
    ///   or equal to the given key. If such a key doesn't exist, then
    ///   `upper = None`.
    ///
    /// In all cases the following post-conditions hold:
    /// - `lower.0 <= key <= upper.0`,
    /// - `for all i in [lower.0 + 1..upper.0 - 1]: self.get(i) == None`,
    /// - `lower == Some((k, v))` implies `self.get(k) == v`,
    /// - `upper == Some((k, v))` implies `self.get(k) == v`,
    ///
    /// Complexity: `O(min(N, |key|))`.
    pub fn bounds(&self, key: &K) -> Bounds<'_, K, V> {
        self.0.bounds(key)
    }

    /// Inserts a new entry into this map. Returns the mutated map and the previous
    /// value for the key, if any.
    ///
    /// Complexity: `O(min(N, |key|))`.
    pub fn insert(self, key: K, value: V) -> (Self, Option<V>) {
        let (tree, res) = self.0.insert(key, value);
        (Self(tree), res)
    }

    /// Removes the entry with the given key from this map. Returns the mutated map
    /// and the removed value, if any.
    ///
    /// Complexity: `O(min(N, |key|))`.
    pub fn remove(self, key: &K) -> (Self, Option<V>) {
        let (tree, res) = self.0.remove(key);
        (Self(tree), res)
    }

    /// Unions two maps, preferring entries from self in case of a collision.
    ///
    /// Complexity: `O(N + M)`
    pub fn union(self, other: Self) -> Self {
        Self(self.0.union(other.0))
    }

    /// Returns an iterator over key-value pairs.
    /// The keys are guaranteed to be sorted.
    ///
    /// A full traversal requires `O(N)` operations.
    pub fn iter(&self) -> IntMapIter<'_, K, V> {
        IntMapIter::new(&self.0)
    }

    /// Returns an iterator over the keys.
    /// The keys are guaranteed to be sorted.
    ///
    /// A full traversal requires `O(N)` operations.
    pub fn keys(&self) -> impl Iterator<Item = &K> {
        IntMapIter::new(&self.0).map(|(k, _v)| k)
    }

    /// Returns the number of entries in this map.
    ///
    /// Complexity: `O(N)`
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if this map is empty.
    ///
    /// Complexity: `O(1)`
    pub fn is_empty(&self) -> bool {
        matches!(self.0, Tree::Empty)
    }

    /// Returns the largest key in this map.
    /// If the tree is empty, then it returns `None`.
    ///
    /// Complexity: `O(min(N, |key|))`.
    pub fn max_key(&self) -> Option<&K> {
        self.0.max().map(|(k, _v)| k)
    }
}

impl<K: AsInt, V: Clone> std::iter::FromIterator<(K, V)> for IntMap<K, V> {
    fn from_iter<Iter>(iter: Iter) -> Self
    where
        Iter: IntoIterator<Item = (K, V)>,
    {
        let mut m = Self::new();
        for (k, v) in iter {
            m = m.insert(k, v).0;
        }
        m
    }
}

impl<K: AsInt + PartialEq, V: PartialEq + Clone> PartialEq for IntMap<K, V> {
    fn eq(&self, other: &Self) -> bool {
        self.iter().eq(other.iter())
    }
}
impl<K: AsInt + Eq, V: Eq + Clone> Eq for IntMap<K, V> {}

impl<K, V> ValidateEq for IntMap<K, V>
where
    K: AsInt + PartialEq + std::fmt::Debug,
    V: ValidateEq + Clone,
{
    fn validate_eq(&self, rhs: &Self) -> Result<(), String> {
        self.0.validate_eq(&rhs.0)
    }
}

/// An internally mutable variant of `IntMap`.
///
/// The underlying tree is still a persistent data structure, so different
/// copies of the same `MutableIntMap` can be modified independently. And the
/// performance is similar, since it's based on the same internals.
#[derive(Clone, Debug)]
pub struct MutableIntMap<K: AsInt, V> {
    tree: Tree<K, V>,
    len: usize,
}

impl<K: AsInt, V> Default for MutableIntMap<K, V> {
    fn default() -> Self {
        Self {
            tree: Tree::Empty,
            len: 0,
        }
    }
}

impl<K: AsInt, V: Clone> MutableIntMap<K, V> {
    /// Creates a new empty map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Looks up a value by integer key.
    ///
    /// Complexity: `O(min(N, |key|))`.
    pub fn get(&self, key: &K) -> Option<&V> {
        self.tree.get(key.as_int())
    }

    /// Returns `true` if the map contains a value for the specified key.
    ///
    /// Complexity: `O(min(N, |key|))`.
    pub fn contains_key(&self, key: &K) -> bool {
        self.tree.get(key.as_int()).is_some()
    }

    /// Returns `(lower, upper)` inclusive bounds for the given key such that:
    /// - `lower` is the largest key/value pair in the tree that is smaller than
    ///   or equal to the given key. If such a key doesn't exist, then
    ///   `lower = None`.
    /// - `upper` is the smallest key/value pair in the tree that is larger than
    ///   or equal to the given key. If such a key doesn't exist, then
    ///   `upper = None`.
    ///
    /// In all cases the following post-conditions hold:
    /// - `lower.0 <= key <= upper.0`,
    /// - `for all i in [lower.0 + 1..upper.0 - 1]: self.get(i) == None`,
    /// - `lower == Some((k, v))` implies `self.get(k) == v`,
    /// - `upper == Some((k, v))` implies `self.get(k) == v`,
    ///
    /// Complexity: `O(min(N, |key|))`.
    pub fn bounds(&self, key: &K) -> Bounds<'_, K, V> {
        self.tree.bounds(key)
    }

    /// Inserts a new entry into this map. Returns the previous value for the key,
    /// if any.
    ///
    /// Complexity: `O(min(N, |key|))`.
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        let tree = std::mem::take(&mut self.tree);
        let res;
        (self.tree, res) = tree.insert(key, value);

        if res.is_none() {
            self.len += 1;
        }
        debug_assert_eq!(self.tree.len(), self.len);

        res
    }

    /// Removes and returns the entry with the given key, if any, from this map.
    ///
    /// Complexity: `O(min(N, |key|))`.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        let tree = std::mem::take(&mut self.tree);
        let res;
        (self.tree, res) = tree.remove(key);

        if res.is_some() {
            self.len -= 1;
        }
        debug_assert_eq!(self.tree.len(), self.len);

        res
    }

    /// Unions two maps, preferring entries from `self`` in case of a collision.
    ///
    /// Complexity: `O(N + M)`
    pub fn union(&mut self, other: Self) {
        let tree = std::mem::take(&mut self.tree);
        self.tree = tree.union(other.tree);
        // TODO(MR-645): Have `Tree::union()` also return the new length.
        self.len = self.tree.len();
    }

    /// Splits the collection into two at the given key. Returns everything after
    /// the given key, including the key.
    ///
    /// Complexity: `O(min(N, |key|))`.
    pub fn split_off(&mut self, key: &K) -> Self {
        let tree = std::mem::take(&mut self.tree);
        let right;
        (self.tree, right) = tree.split(key);

        let old_len = self.len;
        // TODO(MR-645): Have `Tree::split()` also return the new lengths.
        self.len = self.tree.len();

        Self {
            tree: right,
            len: old_len - self.len,
        }
    }

    /// Returns an iterator over key-value pairs.
    /// The keys are guaranteed to be sorted.
    ///
    /// A full traversal requires O(N) operations.
    pub fn iter(&self) -> IntMapIter<'_, K, V> {
        IntMapIter::new(&self.tree)
    }

    /// Returns an iterator over the keys.
    /// The keys are guaranteed to be sorted.
    ///
    /// A full traversal requires O(N) operations.
    pub fn keys(&self) -> impl Iterator<Item = &K> {
        IntMapIter::new(&self.tree).map(|(k, _v)| k)
    }

    /// Returns an iterator over the values, in order by key.
    ///
    /// A full traversal requires O(N) operations.
    pub fn values(&self) -> impl Iterator<Item = &V> {
        IntMapIter::new(&self.tree).map(|(_k, v)| v)
    }

    /// Returns the number of entries in this map.
    ///
    /// Complexity: `O(1)`
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns true if this map is empty.
    ///
    /// Complexity: `O(1)`
    pub fn is_empty(&self) -> bool {
        matches!(self.tree, Tree::Empty)
    }

    /// Returns the smallest key in this map.
    /// If the tree is empty, then it returns `None`.
    ///
    /// Complexity: `O(min(N, |key|))`.
    pub fn min_key(&self) -> Option<&K> {
        self.tree.min().map(|(k, _v)| k)
    }

    /// Returns the largest key in this map.
    /// If the tree is empty, then it returns `None`.
    ///
    /// Complexity: `O(min(N, |key|))`.
    pub fn max_key(&self) -> Option<&K> {
        self.tree.max().map(|(k, _v)| k)
    }
}

impl<K: AsInt, V: Clone> std::iter::FromIterator<(K, V)> for MutableIntMap<K, V> {
    fn from_iter<Iter>(iter: Iter) -> Self
    where
        Iter: IntoIterator<Item = (K, V)>,
    {
        let mut m = Self::new();
        for (k, v) in iter {
            m.insert(k, v);
        }
        m
    }
}

impl<K: AsInt + PartialEq, V: PartialEq + Clone> PartialEq for MutableIntMap<K, V> {
    fn eq(&self, other: &Self) -> bool {
        self.iter().eq(other.iter())
    }
}
impl<K: AsInt + Eq, V: Eq + Clone> Eq for MutableIntMap<K, V> {}

impl<K, V> ValidateEq for MutableIntMap<K, V>
where
    K: AsInt + PartialEq + std::fmt::Debug,
    V: ValidateEq + Clone,
{
    fn validate_eq(&self, rhs: &Self) -> Result<(), String> {
        if self.len != rhs.len {
            return Err(format!("Length divergence: {} != {}", self.len, rhs.len));
        }
        self.tree.validate_eq(&rhs.tree)
    }
}

/// Iterates over an `IntMap`, visiting keys in sorted order.
pub struct IntMapIter<'a, K: AsInt, V>(
    /// The stack of subtrees we haven't visited yet.
    /// Trees in the back are visited first.
    Vec<&'a Tree<K, V>>,
);

impl<'a, K: AsInt, V> IntMapIter<'a, K, V> {
    fn new(root: &'a Tree<K, V>) -> Self {
        Self(vec![root])
    }
}

impl<'a, K: AsInt, V: Clone> std::iter::Iterator for IntMapIter<'a, K, V> {
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        let mut p = self.0.pop()?;
        // Find the leftmost subtree, pushing all the right hand side nodes onto the
        // stack.
        while let Tree::Branch { left, right, .. } = p {
            self.0.push(right);
            p = left;
        }
        match p {
            Tree::Empty => None,
            Tree::Leaf(k, v) => Some((k, v)),
            Tree::Branch { .. } => unreachable!(),
        }
    }
}

/// Consuming iterator over an `IntMap`, visiting keys in sorted order.
///
/// A full traversal requires `O(N)` operations.
pub struct IntMapIntoIter<K: AsInt, V>(
    /// The stack of subtrees we haven't visited yet.
    /// Trees in the back should be visited first.
    Vec<Tree<K, V>>,
);

impl<K: AsInt, V> IntMapIntoIter<K, V> {
    fn new(root: Tree<K, V>) -> Self {
        Self(vec![root])
    }
}

impl<K: AsInt, V: Clone> std::iter::Iterator for IntMapIntoIter<K, V> {
    type Item = (K, V);

    fn next(&mut self) -> Option<Self::Item> {
        let mut p = self.0.pop()?;
        // Find the leftmost subtree, pushing all the right hand side nodes onto the
        // stack.
        while let Tree::Branch { left, right, .. } = p {
            self.0.push(take_arc(right));
            p = take_arc(left);
        }
        match p {
            Tree::Empty => None,
            Tree::Leaf(k, v) => Some((k, v)),
            Tree::Branch { .. } => unreachable!(),
        }
    }
}

impl<K: AsInt, V: Clone> IntoIterator for MutableIntMap<K, V> {
    type Item = (K, V);
    type IntoIter = IntMapIntoIter<K, V>;

    fn into_iter(self) -> Self::IntoIter {
        IntMapIntoIter::new(self.tree)
    }
}

/// Finds the most significant bit in which two bit patterns disagree.
#[inline]
fn branching_bit<I: IntKey>(p0: I, p1: I) -> u8 {
    debug_assert_ne!(p0, p1);
    let zs = (p0 ^ p1).leading_zeros() as u8;
    I::size_bits() - 1 - zs
}

/// Clears all the key bits at or lower than the branching bit.
#[inline]
fn mask<I: IntKey>(key: I, branching_bit: u8) -> I {
    debug_assert!(branching_bit < I::size_bits());

    // FYI: Using precomputed masks here and when testing the branching bit improves
    // `u128` performance by about 20%, but has no effect on `u64` performance.
    // Because two `[u128; 128]` arrays are potentially large for the CPU cache (2
    // KiB each), it is probably best to stick with computing the masks on the fly.
    key & ((I::max_value() << 1) << branching_bit)
}

/// Checks if the key matches the branch prefix.
#[inline]
fn matches_prefix<I: IntKey>(key: I, branch_prefix: I, branching_bit: u8) -> bool {
    mask(key, branching_bit) == branch_prefix
}
