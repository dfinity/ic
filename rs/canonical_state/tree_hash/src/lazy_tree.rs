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

    /// The source that the subtree rooted at this fork is derived from, including
    /// the [`SubtreeExpander`] that rebuilds it; produced iff the subtree should
    /// be collapsed to a digest-only, reusable subtree node in the
    /// [`HashTree`](crate::hash_tree::HashTree).
    ///
    /// Defaults to `None` (materialize the subtree inline). Forks that wrap shared,
    /// copy-on-write state (e.g. an `Arc<CanisterState>`) should override this to
    /// return that `Arc`, together with an expander that bakes in the certification
    /// version, as a [`SubtreeSource`]. Such subtrees are hashed once and, when an
    /// unchanged subtree (same source) is found in a baseline tree, its digest is
    /// reused instead of being recomputed. See
    /// [`hash_lazy_tree_with_baseline`](crate::hash_tree::hash_lazy_tree_with_baseline).
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

/// An owned, type-erased handle to the source that a reusable lazy subtree was
/// derived from (e.g. an `Arc<CanisterState>`), paired with the
/// [`SubtreeExpander`] that rebuilds the subtree from it.
///
/// The held `Arc` keeps the source allocation alive, so its address cannot be
/// recycled for a different object while the handle exists (no ABA), and the
/// source stays available to [`expand`](Self::expand) the subtree for witnesses.
///
/// Equality is a conservative reuse-gate, *not* a general-purpose comparison:
/// two `SubtreeSource`s are equal iff they point to the same source allocation
/// **and** carry the same expander. The expander encodes the producer's
/// certification version (baked into a version-specific monomorphization), so
/// equality implies the two subtrees would hash identically. The function
/// pointer comparison ([`std::ptr::fn_addr_eq`]) is best-effort: it may report
/// `false` for two pointers that are in fact the same function, but never `true`
/// for genuinely different ones. The sole consumer (baseline reuse) treats
/// inequality as "rebuild the subtree", so a false negative only costs a
/// recomputation and never compromises correctness.
#[derive(Clone)]
pub struct SubtreeSource {
    source: Arc<dyn Any + Send + Sync>,
    expander: SubtreeExpander,
}

/// Rebuilds a stubbed subtree's [`HashTree`](crate::hash_tree::HashTree) from
/// its type-erased [`SubtreeSource`], by [downcasting](SubtreeSource::downcast)
/// the held `Arc` back to its concrete source and re-materializing it. Used to
/// expand a [`NodeKind::Stub`](crate::hash_tree::HashTree) on demand during
/// witness generation.
///
/// It is a plain function pointer (not a closure), so the producer of the stub
/// must bake the certification version into it. The pointer alone fully
/// determines the expansion so it can be safely used as a conservative equality
/// gate for subtree reuse.
pub type SubtreeExpander =
    fn(&SubtreeSource) -> Result<crate::hash_tree::HashTree, crate::hash_tree::HashTreeError>;

impl SubtreeSource {
    /// Creates a handle that shares ownership of the subtree's `source` and can
    /// rebuild the subtree from it, via the `expander`.
    pub fn new<T: Any + Send + Sync>(source: &Arc<T>, expander: SubtreeExpander) -> Self {
        let this = Self {
            source: Arc::clone(source) as Arc<dyn Any + Send + Sync>,
            expander,
        };
        debug_assert!(expander(&this).is_ok());
        this
    }

    /// The bare address of the source allocation, used for identity comparison.
    fn addr(&self) -> *const () {
        Arc::as_ptr(&self.source) as *const ()
    }

    /// Recovers shared ownership of the source as an `Arc<T>`. Used by a
    /// [`SubtreeExpander`] to rebuild the subtree from its source.
    ///
    /// Panics if this handle was not created from an `Arc<T>`.
    pub fn downcast<T: Any + Send + Sync>(&self) -> Arc<T> {
        Arc::clone(&self.source)
            .downcast::<T>()
            .unwrap_or_else(|_| {
                panic!(
                    "subtree source is not an Arc<{}>",
                    std::any::type_name::<T>()
                )
            })
    }

    /// Rebuilds the subtree's [`HashTree`](crate::hash_tree::HashTree) from this
    /// source, to expand a stub on demand during witness generation.
    pub fn expand(&self) -> Result<crate::hash_tree::HashTree, crate::hash_tree::HashTreeError> {
        (self.expander)(self)
    }
}

impl PartialEq for SubtreeSource {
    /// A conservative, false-negative-only reuse-gate; see the type-level note.
    fn eq(&self, other: &Self) -> bool {
        self.addr() == other.addr() && std::ptr::fn_addr_eq(self.expander, other.expander)
    }
}

impl Eq for SubtreeSource {}

impl fmt::Debug for SubtreeSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SubtreeSource({:p})", self.addr())
    }
}
