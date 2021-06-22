//! Canonical State traversal using lazy trees, i.e. a tree with nodes that are
//! lazily initialized if and when traversed.
//!
//! Lazy trees allow e.g. comparing 2 Canonical States without materializing
//! them; certified ingress history access in O(log N); and they make the
//! algorithms on Canonical State easier to write and understand.

pub mod conversion;
pub mod materialize;

use ic_crypto_tree_hash::Label;
use std::sync::Arc;

/// A type alias for a ref-counted stateless function.
pub type ArcFn<'a, T> = Arc<dyn Fn() -> T + 'a>;

/// Lazy is either a computed value or a function that knows how to compute one.
#[derive(Clone)]
pub enum Lazy<'a, T> {
    Value(T),
    Func(ArcFn<'a, T>),
}

impl<'a, T: Clone> Lazy<'a, T> {
    pub fn force(&self) -> T {
        match self {
            Self::Value(v) => v.clone(),
            Self::Func(t) => t(),
        }
    }
}

/// The trait representing interface of a fork in the lazy tree.
pub trait LazyFork<'a> {
    /// Retrieves a subtree with the specified `label`.
    fn edge(&self, label: &Label) -> Option<LazyTree<'a>>;
    /// Enumerates all the labels reachable from this fork.
    fn labels(&self) -> Box<dyn Iterator<Item = Label> + '_>;
}

/// A tree that can lazily expand while it's being traversed.
///
/// Note that the visited nodes are not memoized, but recomputed every time they
/// are accessed.  This is intentional: we typically traverse the tree only
/// once, so memoization would result in unnecessary memory consumption.
///
/// The generic lifetime argument allows us to borrow data directly from the
/// replicated state, which makes traversing the tree more efficient.
#[derive(Clone)]
pub enum LazyTree<'a> {
    // materialized tree
    Blob(&'a [u8]),

    // suspended tree
    LazyBlob(ArcFn<'a, Vec<u8>>),
    LazyFork(Arc<dyn LazyFork<'a> + 'a>),
}

/// A helper function to construct a fork of a lazy tree.
pub fn fork<'a>(f: impl LazyFork<'a> + 'a) -> LazyTree<'a> {
    LazyTree::LazyFork(Arc::new(f))
}

/// A helper function that constructs a leaf with a lazy blob.
pub fn blob<'a>(f: impl Fn() -> Vec<u8> + 'a) -> LazyTree<'a> {
    LazyTree::LazyBlob(Arc::new(f))
}

/// A helper function that construct a leaf from a string.
pub fn string(s: &str) -> LazyTree<'_> {
    LazyTree::Blob(s.as_bytes())
}

/// A helper function that construct a leaf from a number.
pub fn num<'a>(n: u64) -> LazyTree<'a> {
    LazyTree::<'a>::LazyBlob(Arc::new(move || {
        let mut buf = Vec::with_capacity(10);
        leb128::write::unsigned(&mut buf, n).expect("failed to encode a number as LEB128");
        buf
    }))
}

/// A function that extracts a value from the lazy tree by the specified path.
pub fn follow_path<'a>(t: &LazyTree<'a>, path: &[&[u8]]) -> Option<LazyTree<'a>> {
    if path.is_empty() {
        return Some(t.clone());
    }
    match t {
        LazyTree::LazyFork(f) => {
            let node = f.edge(&Label::from(path[0]))?;
            follow_path(&node, &path[1..])
        }
        _ => None,
    }
}
