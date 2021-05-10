//! This module provides an implementation of a persistent map with integer
//! keys.
#[cfg(test)]
mod test;

use std::sync::Arc;

/// Big-endian patricia trees.
#[derive(Clone, Debug)]
enum Tree<T> {
    /// An empty tree.
    /// Allowing empty trees simplifies the code a bit.
    Empty,
    /// A key-value pair.
    Leaf(u64, T),
    /// A binary fork.
    ///
    /// Invariants:
    ///
    ///   * Both left and right subtrees aren't empty, i.e.,
    ///
    ///     left.len() > 0 && right.len() > 0
    ///
    ///   * For each leaf L in left and right, the key bits match the prefix up
    ///     to but not including the branching bit, i.e.,
    ///
    ///     matches_prefix(L.key, prefix, branching_bit) == true.
    ///
    ///   * For each leaf L in the left subtree:
    ///
    ///     L.key & (1 << branching_bit) == 0.
    ///
    ///   * For each leaf L in the right subtree:
    ///
    ///     L.key & (1 << branching_bit) == 1.
    ///
    ///   * 0 ≤ branching_bit ≤ 63.
    Branch {
        prefix: u64,
        branching_bit: u8,
        left: Arc<Tree<T>>,
        right: Arc<Tree<T>>,
    },
}

impl<T> Default for Tree<T> {
    fn default() -> Self {
        Tree::Empty
    }
}

/// Creates a branch node having subtrees t0 and t1 as children.
///
/// Precondition: p0 ≠ p1
#[inline]
fn join<T>(p0: u64, t0: Arc<Tree<T>>, p1: u64, t1: Arc<Tree<T>>) -> Tree<T> {
    let b = branching_bit(p0, p1);

    if p0 & (1 << b) == 0 {
        Tree::Branch {
            prefix: mask(p0, b),
            branching_bit: b,
            left: t0,
            right: t1,
        }
    } else {
        Tree::Branch {
            prefix: mask(p0, b),
            branching_bit: b,
            left: t1,
            right: t0,
        }
    }
}

/// Modifies the contents of an Arc, creating a copy if necessary.
#[inline]
fn with_arc<T: Clone + Default>(mut p: Arc<T>, f: impl FnOnce(T) -> T) -> Arc<T> {
    let dst = Arc::make_mut(&mut p);
    *dst = f(std::mem::take(dst));
    p
}

/// Extracts a value from an Arc, cloning its content if necessary.
#[inline]
fn take_arc<T: Clone>(p: Arc<T>) -> T {
    match Arc::try_unwrap(p) {
        Ok(x) => x,
        Err(arc) => (*arc).clone(),
    }
}

impl<T: Clone> Tree<T> {
    fn get(&self, key: u64) -> Option<&T> {
        match self {
            Tree::Empty => None,
            Tree::Leaf(k, v) => {
                if key == *k {
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
                } else if key & (1 << branching_bit) == 0 {
                    (*left).get(key)
                } else {
                    (*right).get(key)
                }
            }
        }
    }

    fn insert(self, key: u64, value: T) -> Self {
        match self {
            Tree::Empty => Tree::Leaf(key, value),
            Tree::Leaf(k, v) => {
                if k == key {
                    Tree::Leaf(k, value)
                } else {
                    join(
                        key,
                        Arc::new(Tree::Leaf(key, value)),
                        k,
                        Arc::new(Tree::Leaf(k, v)),
                    )
                }
            }
            Tree::Branch {
                prefix,
                branching_bit,
                left,
                right,
            } => {
                if matches_prefix(key, prefix, branching_bit) {
                    if key & (1 << branching_bit) == 0 {
                        Tree::Branch {
                            prefix,
                            branching_bit,
                            left: with_arc(left, |l| l.insert(key, value)),
                            right,
                        }
                    } else {
                        Tree::Branch {
                            prefix,
                            branching_bit,
                            left,
                            right: with_arc(right, |r| r.insert(key, value)),
                        }
                    }
                } else {
                    join(
                        key,
                        Arc::new(Tree::Leaf(key, value)),
                        prefix,
                        Arc::new(Tree::Branch {
                            prefix,
                            branching_bit,
                            left,
                            right,
                        }),
                    )
                }
            }
        }
    }

    fn union(self, other: Self) -> Self {
        match (self, other) {
            (Tree::Empty, t) | (t, Tree::Empty) => t,
            (Tree::Leaf(k, v), t) => t.insert(k, v),
            (t, Tree::Leaf(k, v)) => {
                if t.get(k).is_some() {
                    // In case of collision, retain the value in `self`.
                    t
                } else {
                    t.insert(k, v)
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
                    let t = Tree::Branch {
                        prefix: p1,
                        branching_bit: b1,
                        left: left1,
                        right: right1,
                    };
                    // Pattern p1 contains p0 as a sub-pattern.
                    if p1 & (1 << b0) == 0 {
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
                    if p0 & (1 << b1) == 0 {
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

    fn len(&self) -> usize {
        match self {
            Tree::Empty => 0,
            Tree::Leaf(_, _) => 1,
            Tree::Branch { left, right, .. } => left.len() + right.len(),
        }
    }
}

/// Purely functional persistent sorted map with an integer key.
///
/// Persistence means that the map can be cheaply (in O(1)) cloned, and each
/// version can be modified independently.
///
/// This data structure provides blazingly fast lookups (often comparable to or
/// surpassing a HashMap), while inserts are relatively expensive (2-10x slower
/// than a HashMap, depending on the size of the value and the map).
///
/// The implementation is based on big-endian patricia trees.
///
/// Chris Okasaki and Andy Gill, "Fast Mergeable Integer Maps", Workshop on ML,
/// September 1998, pages 77-86,
/// http://citeseerx.ist.psu.edu/viewdoc/summary?doi=10.1.1.37.5452
#[derive(Clone, Debug)]
pub struct IntMap<T>(Tree<T>);

impl<T> Default for IntMap<T> {
    fn default() -> Self {
        Self(Tree::Empty)
    }
}

impl<T: Clone> IntMap<T> {
    /// Creates a new empty map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Looks up a value by integer key.
    ///
    /// Complexity: O(min(N, 64))
    pub fn get(&self, key: u64) -> Option<&T> {
        self.0.get(key)
    }

    /// Inserts a new entry into this map.
    ///
    /// Complexity: O(min(N, 64))
    pub fn insert(self, key: u64, value: T) -> Self {
        Self(self.0.insert(key, value))
    }

    /// Unions two maps, preferring entries from self in case of a collision.
    ///
    /// Complexity: O(N + M)
    pub fn union(self, other: Self) -> Self {
        Self(self.0.union(other.0))
    }

    /// Returns an iterator over key-value pairs.
    /// The keys are guaranteed to be sorted.
    ///
    /// A full traversal requires O(N) operations.
    pub fn iter(&self) -> IntMapIter<'_, T> {
        IntMapIter::new(&self.0)
    }

    /// Returns the number of entries in this map.
    ///
    /// Complexity: O(N)
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if this map is empty.
    ///
    /// Complexity: O(1)
    pub fn is_empty(&self) -> bool {
        if let Tree::Empty = self.0 {
            true
        } else {
            false
        }
    }
}

impl<T: Clone> std::iter::FromIterator<(u64, T)> for IntMap<T> {
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = (u64, T)>,
    {
        let mut m = Self::new();
        for (k, v) in iter {
            m = m.insert(k, v);
        }
        m
    }
}

/// Iterates over an IntMap, visiting keys in sorted order.
pub struct IntMapIter<'a, T>(
    /// The stack of subtrees we haven't visited yet.
    /// Trees in the back should be visited first.
    Vec<&'a Tree<T>>,
);

impl<'a, T> IntMapIter<'a, T> {
    fn new(root: &'a Tree<T>) -> Self {
        Self(vec![root])
    }
}

impl<'a, T> std::iter::Iterator for IntMapIter<'a, T> {
    type Item = (u64, &'a T);

    fn next(&mut self) -> Option<Self::Item> {
        let mut p = self.0.pop()?;
        // Find the most-left subtree, pushing all the right nodes onto the
        // stack.
        while let Tree::Branch { left, right, .. } = p {
            self.0.push(&right);
            p = left;
        }
        match p {
            Tree::Empty => None,
            Tree::Leaf(k, v) => Some((*k, v)),
            Tree::Branch { .. } => unreachable!(),
        }
    }
}

/// Finds the most significant bit in which two bit patterns disagree.
#[inline]
fn branching_bit(p0: u64, p1: u64) -> u8 {
    debug_assert_ne!(p0, p1);
    let zs = (p0 ^ p1).leading_zeros();
    (63 - zs) as u8
}

/// Clears all the key bits at or lower than the branching bit.
#[inline]
fn mask(key: u64, branching_bit: u8) -> u64 {
    debug_assert!(branching_bit <= 63);
    let m = 1 << branching_bit;
    key & !(m | (m - 1))
}

/// Checks if the key matches the branch prefix.
#[inline]
fn matches_prefix(key: u64, branch_prefix: u64, branching_bit: u8) -> bool {
    mask(key, branching_bit) == branch_prefix
}
