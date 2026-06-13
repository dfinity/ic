//! Canonical State traversal using lazy trees, i.e. a tree with nodes that are
//! lazily initialized if and when traversed.
//!
//! Lazy trees allow e.g. comparing 2 Canonical States without materializing
//! them; certified ingress history access in O(log N); and they make the
//! algorithms on Canonical State easier to write and understand.

pub mod materialize;

use ic_crypto_tree_hash::Label;
use std::any::Any;
use std::sync::Arc;

/// A hash of the tree leaf contents according to the IC interface spec.  See
/// the definition of "reconstruct" function on
/// https://internetcomputer.org/docs/current/references/ic-interface-spec/#certificate.
pub type Hash = [u8; 32];

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

    /// A cheap, copyable identity for the subtree rooted at this fork, present iff
    /// the subtree should be stored as a self-contained, reusable subtree node in
    /// the [`HashTree`](crate::hash_tree::HashTree).
    ///
    /// Defaults to `None` (materialize the subtree inline). Forks that wrap shared,
    /// copy-on-write state (e.g. an `Arc<CanisterState>`) should override this to
    /// return that `Arc`'s identity as a [`SubtreeId`]. Such subtrees are built
    /// once as standalone trees and, when an unchanged subtree (same identity) is
    /// found in a baseline tree, its node is reused verbatim. See
    /// [`hash_lazy_tree_with_baseline`](crate::hash_tree::hash_lazy_tree_with_baseline).
    ///
    /// MUST be consistent with [`subtree_source`](Self::subtree_source): both
    /// `None`; or both`Some` and `self.subtree_source().unwrap().id() ==
    /// self.subtree_id().unwrap()`.
    fn subtree_id(&self) -> Option<SubtreeId> {
        None
    }

    /// The owned source handle stored in a reusable subtree node; see
    /// [`SubtreeSource`] and [`subtree_id`](Self::subtree_id). Called to clone the
    /// source `Arc` only when the subtree is being (re)built.
    fn subtree_source(&self) -> Option<SubtreeSource> {
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

/// A cheap, copyable identity for a lazy subtree: the bare address of the source
/// allocation it was derived from (e.g. an `Arc<CanisterState>`), with no
/// refcount bump.
///
/// Used to detect whether a subtree is unchanged (and can be reused from a
/// baseline) without cloning the source `Arc`; the clone is only paid, via a
/// [`SubtreeSource`], when a subtree is actually (re)built. A `SubtreeId`
/// compares equal to the one derived from the same source, including the one
/// obtained from the [`SubtreeSource`] kept by a reusable subtree node (see
/// [`SubtreeSource::id`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SubtreeId(*const ());

impl SubtreeId {
    /// Creates a subtree ID from a shared pointer to the `source`, without
    /// cloning it (no refcount bump).
    pub fn new<T>(source: &Arc<T>) -> Self {
        Self(Arc::as_ptr(source) as *const ())
    }
}

/// An owned, type-erased handle that keeps a lazy subtree's source alive, backed
/// by a shared pointer into the state it was derived from (e.g. an
/// `Arc<CanisterState>`).
///
/// The held `Arc` keeps the source allocation alive, so the [`SubtreeId`] it
/// yields can never be recycled for a different object while the handle exists
/// (no ABA hazard). A `SubtreeSource` is stored inside a reusable subtree node
/// and is only created when that node is actually (re)built; cheap reuse checks
/// go through [`SubtreeId`] instead, avoiding the `Arc::clone` refcount bump.
#[derive(Clone, Debug)]
pub struct SubtreeSource(Arc<dyn Any + Send + Sync>);

impl SubtreeSource {
    /// Creates a handle that shares ownership of the subtree's `source`.
    pub fn new<T: Any + Send + Sync>(source: &Arc<T>) -> Self {
        Self(Arc::clone(source) as Arc<dyn Any + Send + Sync>)
    }

    /// The cheap, copyable [`SubtreeId`] of this source, for equality comparison
    /// without a refcount bump.
    pub fn id(&self) -> SubtreeId {
        SubtreeId(Arc::as_ptr(&self.0) as *const ())
    }
}
