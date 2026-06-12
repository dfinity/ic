//! Canonical State traversal using lazy trees, i.e. a tree with nodes that are
//! lazily initialized if and when traversed.
//!
//! Lazy trees allow e.g. comparing 2 Canonical States without materializing
//! them; certified ingress history access in O(log N); and they make the
//! algorithms on Canonical State easier to write and understand.

pub mod materialize;

use ic_crypto_tree_hash::Label;
use std::any::Any;
use std::fmt;
use std::sync::Arc;

/// A hash of the tree leaf contents according to the IC interface spec.  See
/// the definition of "reconstruct" function on
/// https://internetcomputer.org/docs/current/references/ic-interface-spec/#certificate.
pub type Hash = [u8; 32];

/// An opaque, type-erased identity for a lazy subtree, backed by a shared
/// pointer into the source state it was derived from (e.g. an
/// `Arc<CanisterState>`).
///
/// Two IDs are equal iff they point to the same allocation. Because the source
/// is copy-on-write (a mutation produces a fresh `Arc`), equal IDs imply the
/// subtrees encode identically — **provided all ambient encoding parameters
/// (e.g. the certification version) match** — which is what lets an unchanged
/// subtree's already-built [`crate::hash_tree::HashTree`] be reused across
/// builds. The held `Arc` also keeps the source alive, so the address can never
/// be recycled for a different object while the ID exists (no ABA).
#[derive(Clone)]
pub struct SubtreeId(Arc<dyn Any + Send + Sync>);

impl SubtreeId {
    /// Creates a subtree ID from a shared pointer to the subtree's source.
    pub fn new<T: Any + Send + Sync>(source: Arc<T>) -> Self {
        Self(source)
    }

    /// The address of the underlying allocation, used for identity comparison.
    fn addr(&self) -> *const () {
        Arc::as_ptr(&self.0) as *const ()
    }
}

impl PartialEq for SubtreeId {
    fn eq(&self, other: &Self) -> bool {
        self.addr() == other.addr()
    }
}
impl Eq for SubtreeId {}

impl fmt::Debug for SubtreeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SubtreeId({:p})", self.addr())
    }
}

/// A type alias for a ref-counted stateless function.
pub type ArcFn<'a, T> = Arc<dyn Fn() -> T + 'a + Send + Sync>;

/// Lazy is either a computed value or a function that knows how to compute one.
#[derive(Clone)]
pub enum Lazy<'a, T> {
    Value(T),
    Func(ArcFn<'a, T>),
}

impl<T: Clone> Lazy<'_, T> {
    pub fn force(&self) -> T {
        match self {
            Self::Value(v) => v.clone(),
            Self::Func(t) => t(),
        }
    }
}

/// The trait representing interface of a fork in the lazy tree.
pub trait LazyFork<'a>: Send + Sync {
    /// Retrieves a subtree with the specified `label`.
    ///
    /// ∀ l ∈ self.labels : self.edge(&l).is_some() == true
    fn edge(&self, label: &Label) -> Option<LazyTree<'a>>;

    /// Enumerates all the labels reachable from this fork.
    fn labels(&self) -> Box<dyn Iterator<Item = Label> + '_>;

    /// Enumerates all the children in this fork and their labels.
    fn children(&self) -> Box<dyn Iterator<Item = (Label, LazyTree<'a>)> + '_>;

    /// The number of children
    fn len(&self) -> usize;

    /// True if there are no children
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns a stable identity for the subtree rooted at this fork if it
    /// should be stored as a self-contained, reusable subtree node (an
    /// `Arc<HashTree>`) in the [`crate::hash_tree::HashTree`].
    ///
    /// Defaults to `None` (materialize the subtree inline). Forks that wrap
    /// shared, copy-on-write state (e.g. an `Arc<CanisterState>`) should
    /// override this to return that `Arc` as a [`SubtreeId`]. Such subtrees are
    /// built once as standalone trees and, when an unchanged subtree (same
    /// `SubtreeId`) is found in a baseline tree, its `Arc<HashTree>` is reused
    /// verbatim. See [`crate::hash_tree::hash_lazy_tree_with_baseline`].
    fn subtree_id(&self) -> Option<SubtreeId> {
        None
    }
}

/// A tree that can lazily expand while it's being traversed.
///
/// Note that the visited nodes are not memoized, but recomputed every time they
/// are accessed.  This is intentional: we typically traverse the tree only
/// once, so memoization would result in unnecessary memory consumption.
///
/// The generic lifetime argument allows us to borrow data directly from the
/// replicated state, which makes traversing the tree more efficient.
///
/// The tree might store precomputed hashes for some leaves, so the [Blob]
/// variant might contain the computed hash to speed up the hash tree
/// construction. If the hash is present, it must be equal to
/// `H(domain_sep("ic-hashtree-leaf") · contents)`.
#[derive(Clone)]
pub enum LazyTree<'a> {
    // materialized tree
    Blob(&'a [u8], Option<Hash>),

    // suspended trees
    LazyBlob(ArcFn<'a, Vec<u8>>),
    LazyFork(Arc<dyn LazyFork<'a> + 'a + Send + Sync>),
}

/// A helper function to construct a fork of a lazy tree.
pub fn fork<'a>(f: impl LazyFork<'a> + 'a) -> LazyTree<'a> {
    LazyTree::LazyFork(Arc::new(f))
}

/// A helper function that constructs a leaf with a lazy blob.
pub fn blob<'a>(f: impl Fn() -> Vec<u8> + 'a + Send + Sync) -> LazyTree<'a> {
    LazyTree::LazyBlob(Arc::new(f))
}

/// A helper function that construct a leaf from a string.
pub fn string(s: &str) -> LazyTree<'_> {
    LazyTree::Blob(s.as_bytes(), None)
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
