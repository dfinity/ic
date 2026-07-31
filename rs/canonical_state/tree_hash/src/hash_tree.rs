use crate::lazy_tree::{LazyTree, SubtreeSource};
use crypto::WitnessGenerationError;
use ic_crypto_tree_hash::{
    self as crypto, Digest, Label, LabeledTree, WitnessBuilder, hasher::Hasher,
};
use ic_utils::iter::left_outer_join;
use itertools::izip;
use std::fmt;
use std::iter::repeat_with;
use std::ops::Range;

/// The number of threads we use for building HashTree
const NUMBER_OF_CERTIFICATION_THREADS: u32 = 16;

/// The maximum number of allowed recursions during hash tree calculation
/// Note that in the current implementation the recursion depth corresponds to
/// the depth of the lazy tree.
const MAX_RECURSION_DEPTH: u32 = 128;

/// A fork with fewer than this many (expensive to build) children is always
/// built sequentially: it is too small for the thread pool to pay for itself.
pub const PARALLEL_MIN_CHILDREN: usize = 1000;

/// Forks start being built sequentially. In the meantime, we track how many
/// children have been materialized and hashed — as opposed to cheaply reused
/// from the baseline.
///
/// Once we've sampled at least this many children, if the projected number of
/// expensively built children exceeds `PARALLEL_MIN_CHILDREN`, we switch to
/// building in parallel.
const ADAPTIVE_WARMUP_CHILDREN: usize = 500;

/// SHA256 of the domain separator "ic-hashtree-empty"
const EMPTY_HASH: Digest = Digest([
    0x4e, 0x3e, 0xd3, 0x5c, 0x4e, 0x2d, 0x1e, 0xe8, 0x99, 0x96, 0x48, 0x3f, 0xb6, 0x26, 0x0a, 0x64,
    0xcf, 0xfb, 0x6c, 0x47, 0xdb, 0xab, 0x21, 0x6e, 0x79, 0x30, 0xe8, 0x2f, 0x81, 0x90, 0xd1, 0x20,
]);

/// Hash of an empty leaf, i.e. the digest of the domain separator
/// "ic-hashtree-leaf" with no body bytes.
const EMPTY_LEAF_HASH: Digest = Digest([
    0xd0, 0x01, 0xf3, 0xe7, 0xb8, 0x21, 0x66, 0xc6, 0xd3, 0x43, 0xa1, 0xef, 0xe7, 0x76, 0xe9, 0x6a,
    0xc0, 0x2a, 0x23, 0xa5, 0x1e, 0x08, 0x98, 0xbc, 0x2c, 0x4e, 0x32, 0x3f, 0xce, 0x0e, 0x62, 0x2c,
]);

/// 29 LSBs are used to store the index
const INDEX_MASK: u32 = 0x1fff_ffff;
/// 3 MSBs are used to store the node kind
const KIND_MASK: u32 = 0xe000_0000;
const LEAF_KIND: u32 = 0x2000_0000;
const NODE_KIND: u32 = 0x4000_0000;
const FORK_KIND: u32 = 0x6000_0000;
const STUB_KIND: u32 = 0x8000_0000;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
enum NodeKind {
    Empty,
    Fork,
    Leaf,
    Node,
    Stub,
}

/// The position of a node in the HashTree data structure.
///
/// HashTree consists of several parallel vectors of vectors. The kind of node
/// is node_id.kind(), the first index is node_id.bucket(), whereas the second
/// index is node_id.index().
///
/// For example, the digest of a node_id with node_id.kind() = NodeKind::Fork
/// is stored at hash_tree.fork_digests[node_id.bucket()][node_id.index()]
///
/// The reason for storing vectors of vectors is because it lends itself to parallelism
/// when computing the HashTree.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Default)]
pub struct NodeId {
    bucket: u32,
    index_and_kind: u32,
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind() {
            NodeKind::Empty => write!(f, "Empty"),
            NodeKind::Fork => write!(f, "Fork({}, {})", self.bucket(), self.index()),
            NodeKind::Leaf => write!(f, "Leaf({}, {})", self.bucket(), self.index()),
            NodeKind::Node => write!(f, "Node({}, {})", self.bucket(), self.index()),
            NodeKind::Stub => write!(f, "Stub({}, {})", self.bucket(), self.index()),
        }
    }
}

impl NodeId {
    /// Constructs a node ID for an empty tree.
    #[inline]
    fn empty() -> Self {
        Self {
            bucket: 0,
            index_and_kind: 0,
        }
    }

    /// Constructs a node ID for a new `Fork` with the specified index.
    #[inline]
    fn fork(bucket: usize, idx: usize) -> Result<Self, HashTreeError> {
        if idx > INDEX_MASK as usize {
            Err(HashTreeError::IndexOverflow)
        } else {
            Ok(Self {
                bucket: bucket
                    .try_into()
                    .map_err(|_| HashTreeError::IndexOverflow)?,
                index_and_kind: FORK_KIND | idx as u32,
            })
        }
    }

    /// Constructs a node ID for a new `Leaf` with the specified index.
    #[inline]
    fn leaf(bucket: usize, idx: usize) -> Result<Self, HashTreeError> {
        if idx > INDEX_MASK as usize {
            Err(HashTreeError::IndexOverflow)
        } else {
            Ok(Self {
                bucket: bucket
                    .try_into()
                    .map_err(|_| HashTreeError::IndexOverflow)?,
                index_and_kind: LEAF_KIND | idx as u32,
            })
        }
    }

    /// Constructs a node ID for a new `Node` with the specified index.
    #[inline]
    fn node(bucket: usize, idx: usize) -> Result<Self, HashTreeError> {
        if idx > INDEX_MASK as usize {
            Err(HashTreeError::IndexOverflow)
        } else {
            Ok(Self {
                bucket: bucket
                    .try_into()
                    .map_err(|_| HashTreeError::IndexOverflow)?,
                index_and_kind: NODE_KIND | idx as u32,
            })
        }
    }

    /// Constructs a node ID for a new `Stub` with the specified index.
    #[inline]
    fn stub(bucket: usize, idx: usize) -> Result<Self, HashTreeError> {
        if idx > INDEX_MASK as usize {
            Err(HashTreeError::IndexOverflow)
        } else {
            Ok(Self {
                bucket: bucket
                    .try_into()
                    .map_err(|_| HashTreeError::IndexOverflow)?,
                index_and_kind: STUB_KIND | idx as u32,
            })
        }
    }

    /// Returns the component kind of this node.
    #[inline]
    fn kind(self) -> NodeKind {
        let node_index = self.index_and_kind;
        match node_index & KIND_MASK {
            FORK_KIND => NodeKind::Fork,
            NODE_KIND => NodeKind::Node,
            LEAF_KIND => NodeKind::Leaf,
            STUB_KIND => NodeKind::Stub,
            _ => NodeKind::Empty,
        }
    }

    /// Returns the index component of this node.
    #[inline]
    fn index(self) -> usize {
        (self.index_and_kind & INDEX_MASK) as usize
    }

    /// Returns the bucket of this node.
    #[inline]
    fn bucket(self) -> usize {
        self.bucket as usize
    }
}

/// A range of `NodeIds` that share the same bucket and have consecutive indices.
/// `index_range` is a half-open range, i.e., `start <= x < end`.
#[derive(Clone, Debug, Default)]
struct NodeIndexRange {
    bucket: usize,
    index_range: Range<usize>,
}

impl NodeIndexRange {
    #[cfg(debug_assertions)]
    fn indexes_into(&self, hash_tree: &HashTree) -> bool {
        self.bucket < hash_tree.node_digests.len()
            && self.index_range.end <= hash_tree.node_digests[self.bucket].len()
    }
}

/// Compact array-based hash tree representation.
///
/// Normally we'd represent this data-structure using an enum, which works fine
/// for moderately sized trees.  This tree uses a slightly more complicated
/// representation that makes it a better choice for large trees:
///
///   * It uses about 30% less memory and has better memory locality.
///
///   * It's much faster to deallocate (some benchmarks showed 2 orders of
///     magnitude difference compared to the enum representation).
///
///   * The fact that nodes of the same type are stored consecutively allows us
///     to build witnesses without any additional data structures.
///
/// The `view` function provides a convenient interface for traversing the
/// compact tree as if it was a node-based structure.
///
/// ## Notes on the tree layout
///
/// The tree is represented as a collection of parallel arrays of arrays
/// ([structure-of-arrays][1]).  For example, a tree like
///
/// ```text
/// (fork (label "x" (leaf "data1")) (label "y" (leaf "data2")))
/// ```
///
/// might be represented as:
///
/// ```text
/// root:          fork_0
/// fork_lefts:    [[node_0]]
/// fork_rights:   [[node_1]]
///
/// node_labels:   [["x",     "y"]]
/// node_children: [[leaf_0,  leaf_1]]
///
/// leaves:        [["data1", "data2"]]
/// ```
///
/// In this representation, the identifier of a node are two 32 bit unsigned
/// integers, where the first number indexes into the (outer) vector and for
/// the second number , the 3 most significant bits are used to indicate the
/// type of the node:
///
///  * (0, 0x0000...) is an empty tree.
///  * (0, 0x0010...) is a leaf.
///  * (0, 0x0100...) is a labeled node.
///  * (0, 0x0110...) is a fork.
///  * (0, 0x1000...) is a reusable stub.
///
///  This means that the tree can store at most 2^29 nodes of the same type. As
///  each tree node has a 32-byte hash associated with it, the tree needs to
///  occupy at least 16 GiB of data before the index overflows.
///
/// [1]: https://en.wikipedia.org/wiki/AoS_and_SoA
#[derive(Clone, Debug)]
pub struct HashTree {
    /// Used for parallel construction of the [`HashTree`]. Namely, when we
    /// build a hash tree for a subtree with many children, we assign different
    /// buckets to threads that build subtrees for different children. The
    /// `bucket_offset` allows to set the offset in advance to independently
    /// build subtrees without synchronization by appending buckets afterwards.
    bucket_offset: usize,
    /// Id of the root of the tree.
    root: NodeId,
    /// If the tree root is a fork or a node, root_labels_range represents a
    /// half-closed index interval [i, j) pointing into the node_labels array
    /// containing all the labels on edges of the original tree going out of the
    /// root.
    ///
    /// INVARIANT: bucket ≤ node_labels.len()
    /// index_range.0 <= index_range.1 <= node_labels[bucket].len()
    root_labels_range: NodeIndexRange,

    /// (i,j)-th element of this array contains the hash of the leaf with ID
    /// `NodeId::leaf(i,j)`.
    leaf_digests: Vec<Vec<Digest>>,

    // INVARIANT:
    // fork_digests.len() == fork_left_children.len() == fork_right_children.len().
    // forall i: fork_digest[i].len() == fork_left_children[i].len() ==
    // fork_right_children[i].len()
    /// (i,j)-th element of this array contains the hash of the fork with ID equal
    /// to `NodeId::fork(i,j)`.
    fork_digests: Vec<Vec<Digest>>,
    /// (i,j)-th element of this array contains the node ID of the left child of the
    /// fork with ID `NodeId::fork(i,j)`.
    fork_left_children: Vec<Vec<NodeId>>,
    /// (i,j)-th element of this array contains the node ID of the right child of
    /// the fork with ID `NodeId::fork(i,j)`.
    fork_right_children: Vec<Vec<NodeId>>,

    // INVARIANT:
    // node_digests.len() == node_labels.len() == node_children.len() ==
    // node_children_labels_ranges.len()
    // forall i: node_digests[i].len() == node_labels[i].len() ==
    // node_children[i].len() == node_children_labels_ranges[i].len()
    //
    // INVARIANT:
    // labels having the same parent node are stored consecutively in the same bucket.
    /// (i,j)-th element of this array contains the hash of the labeled node with ID
    /// `NodeId::node(i,j)`.
    node_digests: Vec<Vec<Digest>>,
    /// (i,j)-th element of this array contains the label of the labeled node with
    /// ID `NodeId::node(i,j)`.
    node_labels: Vec<Vec<Label>>,
    /// (i,j)-th element of this array contains the direct child of the labeled node
    /// with ID `NodeId::node(i,j)`.
    node_children: Vec<Vec<NodeId>>,
    /// (i,j)-th element of this array points to a bucket and a half-open index
    /// interval `[a, b)` in the `node_labels` array, covering all labels on edges
    /// of the original tree going out of the node with ID `NodeId::node(i,j)`.
    ///
    /// INVARIANT: bucket ≤ node_labels.len()
    /// index_range.0 <= index_range.1 <= node_labels[bucket].len()
    node_children_labels_ranges: Vec<Vec<NodeIndexRange>>,

    /// (i,j)-th element of this array contains the stub with ID `NodeId::stub(i,j)`:
    /// the subtree's root digest plus the [`SubtreeSource`] it was built from. The
    /// subtree's contents are not materialized; when needed for building a witness
    /// they are rebuilt on demand from the `SubtreeSource` (see
    /// [`HashTree::witness`]).
    stubs: Vec<Vec<StubNode>>,

    /// Number of digests (stubs) reused from a baseline during the construction of
    /// this [`HashTree`].
    reused_stubs: usize,
    /// Number of children built in parallel during the construction of this
    /// [`HashTree`].
    parallel_built_children: usize,
}

/// A reusable subtree collapsed to a single digest ("stub"), stored in a
/// [`NodeKind::Stub`] node.
///
/// Holds one `Arc` and one function pointer (inside the [`SubtreeSource`]) plus
/// a cheap [`Digest`], so it can be stored inline, avoiding extra allocation
/// and/or indirection.
#[derive(Clone, Debug)]
struct StubNode {
    /// The subtree's root digest. Its contents are not materialized; they are
    /// rebuilt on demand via [`SubtreeSource::expand`] during witness generation.
    digest: Digest,

    /// The source that this stub was built from (paired with its expander), used
    /// both to detect that an unchanged subtree can be reused from a baseline (by
    /// source identity and certification version) and to rebuild it for witnesses.
    /// Holds an `Arc` into the source, keeping it alive so the identity cannot be
    /// recycled (no ABA) and the source stays available for expansion.
    source: SubtreeSource,
}

impl HashTree {
    /// Constructs an empty tree.
    fn new() -> Self {
        Self::new_with_bucket_offset(0)
    }

    /// Constructs an empty tree with `bucket_offset`.
    fn new_with_bucket_offset(bucket_offset: usize) -> Self {
        Self {
            bucket_offset,
            root: Default::default(),
            root_labels_range: Default::default(),
            leaf_digests: vec![Default::default()],
            fork_digests: vec![Default::default()],
            fork_left_children: vec![Default::default()],
            fork_right_children: vec![Default::default()],
            node_digests: vec![Default::default()],
            node_labels: vec![Default::default()],
            node_children: vec![Default::default()],
            node_children_labels_ranges: vec![Default::default()],
            stubs: vec![Default::default()],
            reused_stubs: 0,
            parallel_built_children: 0,
        }
    }

    /// Number of digests in the `HashTree`.
    pub fn size(&self) -> usize {
        let leaf_size: usize = self.leaf_digests.iter().map(|bucket| bucket.len()).sum();
        let fork_size: usize = self.fork_digests.iter().map(|bucket| bucket.len()).sum();
        let node_size: usize = self.node_digests.iter().map(|bucket| bucket.len()).sum();
        let stub_size: usize = self.stubs.iter().map(|bucket| bucket.len()).sum();

        // Since this is for metrics only we don't care about potential overflows.
        // Note: each stub is counted as a single node; the nodes of its
        // unmaterialized subtree are not counted here.
        leaf_size + fork_size + node_size + stub_size
    }

    /// Largest index in the `HashTree`.
    pub fn max_index(&self) -> usize {
        let leaf_size = self
            .leaf_digests
            .iter()
            .map(|bucket| bucket.len())
            .max()
            .unwrap_or(0);
        let fork_size = self
            .fork_digests
            .iter()
            .map(|bucket| bucket.len())
            .max()
            .unwrap_or(0);
        let node_size = self
            .node_digests
            .iter()
            .map(|bucket| bucket.len())
            .max()
            .unwrap_or(0);
        let stub_size = self
            .stubs
            .iter()
            .map(|bucket| bucket.len())
            .max()
            .unwrap_or(0);

        leaf_size.max(fork_size).max(node_size).max(stub_size)
    }

    /// Number of subtree digests reused from a baseline `HashTree` during this
    /// tree's construction (rather than recomputed).
    pub fn reused_stubs(&self) -> usize {
        self.reused_stubs
    }

    /// Number of labeled nodes (fork children) built in parallel during this
    /// tree's construction.
    pub fn parallel_built_children(&self) -> usize {
        self.parallel_built_children
    }

    /// Number of [`NodeKind::Stub`] nodes in this tree.
    ///
    /// Diagnostics/test only.
    #[doc(hidden)]
    pub fn stub_count(&self) -> usize {
        self.stubs.iter().map(|bucket| bucket.len()).sum()
    }

    /// The [`SubtreeSource`] of every [`NodeKind::Stub`] node (in no particular
    /// order). Lets tests assert stub source identity (e.g. that reuse is by
    /// pointer, not by value).
    ///
    /// Diagnostics/test only.
    #[doc(hidden)]
    pub fn stub_sources(&self) -> impl Iterator<Item = &SubtreeSource> {
        self.stubs.iter().flatten().map(|stub| &stub.source)
    }

    /// Note that new forks are always added to fork_digests[0], but in order
    /// to access it, you use a NodeId with bucket set to self.bucket_offset.
    fn new_fork(&mut self, d: Digest, l: NodeId, r: NodeId) -> Result<NodeId, HashTreeError> {
        let id = self.fork_digests[0].len();

        self.fork_digests[0].push(d);
        self.fork_left_children[0].push(l);
        self.fork_right_children[0].push(r);

        NodeId::fork(self.bucket_offset, id)
    }

    /// Reserves space for `additional` forks.
    fn reserve_forks(&mut self, additional: usize) {
        self.fork_digests[0].reserve(additional);
        self.fork_left_children[0].reserve(additional);
        self.fork_right_children[0].reserve(additional);
    }

    /// Constructs a new leaf without a parent.
    fn new_leaf(&mut self, d: Digest) -> Result<NodeId, HashTreeError> {
        let id = self.leaf_digests[0].len();
        self.leaf_digests[0].push(d);
        NodeId::leaf(self.bucket_offset, id)
    }

    /// Constructs a new stub (either freshly hashed or reused from a baseline).
    fn new_stub(&mut self, digest: Digest, source: SubtreeSource) -> Result<NodeId, HashTreeError> {
        let idx = self.stubs[0].len();
        self.stubs[0].push(StubNode { digest, source });
        NodeId::stub(self.bucket_offset, idx)
    }

    /// Preallocates `len` nodes. Makes the new nodes root if the `parent` is
    /// `Empty`. Returns the [`NodeIndexRange`] to the allocated nodes.
    fn preallocate_nodes(
        &mut self,
        len: usize,
        parent: NodeId,
    ) -> Result<NodeIndexRange, HashTreeError> {
        if parent != NodeId::empty() {
            debug_assert_eq!(parent.bucket(), self.bucket_offset);
        }
        let old_len = self.node_labels[0].len();
        let new_len = old_len
            .checked_add(len)
            .ok_or(HashTreeError::IndexOverflow)?;

        self.node_labels[0].resize(new_len, Default::default());
        self.node_digests[0].resize(new_len, Digest([0; 32]));
        self.node_children[0].resize(new_len, NodeId::empty());
        self.node_children_labels_ranges[0].resize(new_len, Default::default());

        let range = NodeIndexRange {
            bucket: self.bucket_offset,
            index_range: old_len..new_len,
        };

        if parent == NodeId::empty() {
            self.root_labels_range = range.clone()
        } else {
            debug_assert_eq!(NodeKind::Node, parent.kind());
            self.node_children_labels_ranges[0][parent.index()] = range.clone()
        }
        Ok(range)
    }

    /// Returns [`NodeIndexRange`] to the children of `parent` or to the root children if
    /// `parent` is empty.
    fn node_labels_range(&self, parent: NodeId) -> NodeIndexRange {
        if parent == NodeId::empty() {
            self.root_labels_range.clone()
        } else {
            // This assert is true by how we construct the tree. As (sub-) tree with a bucket_offset does not have
            // any internal references to nodes in buckets < self.bucket_offset.
            debug_assert!(parent.bucket() >= self.bucket_offset);
            self.node_children_labels_ranges[parent.bucket() - self.bucket_offset][parent.index()]
                .clone()
        }
    }

    /// Returns the digest at `node_id`.
    fn digest(&self, node_id: NodeId) -> &Digest {
        match node_id.kind() {
            NodeKind::Fork => {
                &self.fork_digests[node_id.bucket() - self.bucket_offset][node_id.index()]
            }
            NodeKind::Node => {
                &self.node_digests[node_id.bucket() - self.bucket_offset][node_id.index()]
            }
            NodeKind::Leaf => {
                &self.leaf_digests[node_id.bucket() - self.bucket_offset][node_id.index()]
            }
            NodeKind::Stub => {
                &self.stubs[node_id.bucket() - self.bucket_offset][node_id.index()].digest
            }
            NodeKind::Empty => &EMPTY_HASH,
        }
    }

    /// Checks the consistency of dimensions of [`Fork`]s and [`Node`]s as a
    /// debug assertion. This is a no-op if debug assertions are not enabled.
    fn check_invariants(&self) {
        #[cfg(debug_assertions)]
        {
            fn check_same_dimensions<S, T>(l: &[Vec<S>], r: &[Vec<T>]) {
                debug_assert_eq!(l.len(), r.len());
                debug_assert!(l.iter().zip(r.iter()).all(|(l, r)| l.len() == r.len()));
            }

            debug_assert!(self.root_labels_range.indexes_into(self));

            check_same_dimensions(&self.fork_digests, &self.fork_left_children);
            check_same_dimensions(&self.fork_digests, &self.fork_right_children);

            check_same_dimensions(&self.node_digests, &self.node_labels);
            check_same_dimensions(&self.node_digests, &self.node_children);
            check_same_dimensions(&self.node_digests, &self.node_children_labels_ranges);
            debug_assert!(
                self.node_children_labels_ranges
                    .iter()
                    .all(|vec| vec.iter().all(|range| range.indexes_into(self)))
            );
        }
    }

    /// Returns a structured representation-independent view of the node with
    /// the specified ID.
    fn view(&self, node_id: NodeId) -> HashTreeView<'_> {
        let bucket = node_id.bucket() - self.bucket_offset;
        let idx = node_id.index();
        match node_id.kind() {
            NodeKind::Fork => HashTreeView::Fork(
                &self.fork_digests[bucket][idx],
                self.fork_left_children[bucket][idx],
                self.fork_right_children[bucket][idx],
            ),
            NodeKind::Node => HashTreeView::Node(
                &self.node_digests[bucket][idx],
                &self.node_labels[bucket][idx],
                self.node_children[bucket][idx],
            ),
            NodeKind::Leaf => HashTreeView::Leaf(&self.leaf_digests[bucket][idx]),
            NodeKind::Stub => HashTreeView::Stub(&self.stubs[bucket][idx].digest),
            NodeKind::Empty => HashTreeView::Empty,
        }
    }

    /// Returns the root hash of the tree.
    pub fn root_hash(&self) -> &Digest {
        self.digest(self.root)
    }

    /// Constructs a witness for the specified partial tree.
    ///
    /// Where the `partial_tree` descends into a [`NodeKind::Stub`] (e.g. into a
    /// canister), the subtree is built on demand from its [`SubtreeSource`].
    pub fn witness<B: WitnessBuilder>(
        &self,
        partial_tree: &LabeledTree<Vec<u8>>,
    ) -> Result<B, WitnessGenerationError<B>> {
        fn add_forks<B: WitnessBuilder>(
            ht: &HashTree,
            pos: NodeId,
            offset: usize,
            size: usize,
            subwitness: B,
        ) -> B {
            // WARNING: FANCY DISCRETE MATH AHEAD
            //
            // The hash trees we build have a particular structure not reflected
            // in the type: all the children of forks are either forks or nodes.
            //
            // Furthermore, because of the way we build forks (pairing vertices
            // from left to right until there is only one left), they form a
            // very specific structure that is fully determined by the number of
            // nodes we had in the beginning.  Most importantly, we can compute
            // the path to K-th node without having to search it by label.
            //
            // The main observation is that if we build a subtree out of N
            // nodes, the binary representation of N can be used to determine
            // the structure of the tree we get.
            //
            // It's easy to prove by induction that if
            //
            //   N = 2^k_1 + 2^k_2 + ... + 2^k^m  (k_1 > k_2 > ... k_m)
            //
            // where k_i corresponds to the position of i-th non-zero bit of N,
            // then the tree has a shape of _m_ full binary trees (FBTs), where
            // j-th tree has k_j leaf nodes, grouped from right to left:
            //
            //    T = FBT(k_1) ^ (FBT(k_2) ^ ( ... ^ FBT(k_m)))
            //
            // Example: if N = 7 = 0b111, we have 3 FBTs with 4, 2 and 1 leaves:
            //        ^
            //    ^      ^
            //  ^   ^   ^ `
            // 0 1 2 3 4 5 6
            //
            // So if we need to locate i-th leaf node out of N in T, we can
            // follow the following procedure locate(T, i, N):
            //
            //   locate(T, 0, 1) = T
            //   locate(T, i, N = 2^k) = if i < N/2
            //                           then locate(left(T),  i,     N/2)
            //                           else locate(right(T), i-N/2, N/2)
            //   locate(T, i, N = 2^k + M) = if i < 2^k
            //                               then locate(left(T),  i,     2^k)
            //                               else locate(right(T), i-2^k, M)
            match ht.view(pos) {
                HashTreeView::Fork(_, l, r) => {
                    if size.is_power_of_two() {
                        let h = size / 2;
                        if offset < h {
                            B::make_fork(
                                add_forks::<B>(ht, l, offset, h, subwitness),
                                B::make_pruned(ht.digest(r).clone()),
                            )
                        } else {
                            B::make_fork(
                                B::make_pruned(ht.digest(l).clone()),
                                add_forks::<B>(ht, r, offset - h, h, subwitness),
                            )
                        }
                    } else {
                        let k = 32 - (size as u32).leading_zeros();
                        let mask = 1 << (k - 1);
                        if offset < mask {
                            B::make_fork(
                                add_forks::<B>(ht, l, offset, mask, subwitness),
                                B::make_pruned(ht.digest(r).clone()),
                            )
                        } else {
                            B::make_fork(
                                B::make_pruned(ht.digest(l).clone()),
                                add_forks::<B>(ht, r, offset - mask, size - mask, subwitness),
                            )
                        }
                    }
                }
                _ => subwitness,
            }
        }

        fn child_witness<B: WitnessBuilder>(
            ht: &HashTree,
            parent: NodeId,
            pos: NodeId,
            l: &Label,
            subtree: &LabeledTree<Vec<u8>>,
        ) -> Result<B, WitnessGenerationError<B>> {
            let NodeIndexRange {
                bucket,
                index_range: label_range,
            } = ht.node_labels_range(parent);
            let len = label_range.len();
            let labels = &ht.node_labels[bucket][label_range.clone()];

            let result = match labels.binary_search(l) {
                Ok(offset) => {
                    let idx = label_range.start + offset;
                    // This expect can't fail because the same error would have occurred on ht's construction
                    let node_id = NodeId::node(bucket, idx).expect("Invalid hash tree.");
                    let subwitness = B::make_node(
                        l.clone(),
                        go::<B>(ht, node_id, ht.node_children[bucket][idx], subtree)?,
                    );
                    if pos.kind() == NodeKind::Node {
                        subwitness
                    } else {
                        add_forks::<B>(ht, pos, offset, len, subwitness)
                    }
                }
                Err(offset) => {
                    if len == 0 {
                        return Ok(match ht.view(pos) {
                            HashTreeView::Empty => B::make_empty(),
                            HashTreeView::Leaf(digest) => B::make_pruned(digest.clone()),
                            // NB. Technically, the following cases are impossible because they would imply
                            // existence of labels under `pos`. We match on that case here for completeness.
                            HashTreeView::Fork(digest, _, _) => {
                                debug_assert!(
                                    false,
                                    "a tree node without children must not be a fork"
                                );
                                B::make_pruned(digest.clone())
                            }
                            HashTreeView::Node(digest, _, _) => {
                                debug_assert!(
                                    false,
                                    "a tree node without children must not be a labeled node"
                                );
                                B::make_pruned(digest.clone())
                            }
                            HashTreeView::Stub(digest) => {
                                debug_assert!(
                                    false,
                                    "a tree node without children must not be a stub"
                                );
                                B::make_pruned(digest.clone())
                            }
                        });
                    }

                    debug_assert!(offset <= len);
                    debug_assert!(len > 0);

                    let pruned_label_at = |i| {
                        add_forks::<B>(
                            ht,
                            pos,
                            i,
                            len,
                            B::make_node(
                                ht.node_labels[bucket][label_range.start + i].clone(),
                                B::make_pruned(
                                    ht.digest(ht.node_children[bucket][label_range.start + i])
                                        .clone(),
                                ),
                            ),
                        )
                    };
                    // Build a proof of absence
                    if offset == 0 {
                        // The missing child is before the first label.
                        pruned_label_at(offset)
                    } else if offset == len {
                        // The missing child is after the last label.
                        pruned_label_at(offset - 1)
                    } else {
                        // The missing child is between two present children.
                        B::merge_trees(pruned_label_at(offset - 1), pruned_label_at(offset))?
                    }
                }
            };
            Ok(result)
        }

        fn go<B: WitnessBuilder>(
            ht: &HashTree,
            parent: NodeId,
            pos: NodeId,
            t: &LabeledTree<Vec<u8>>,
        ) -> Result<B, WitnessGenerationError<B>> {
            if pos.kind() == NodeKind::Stub {
                // A stub, only storing its root digest.
                return match t {
                    // Witness only needs the precomputed digest.
                    LabeledTree::SubTree(children) if children.is_empty() => {
                        Ok(B::make_pruned(ht.digest(pos).clone()))
                    }

                    // Requested partial tree descends into the subtree or requests its leaf value:
                    // rebuild the subtree from source and continue witness generation there. (A
                    // stubbed subtree may itself be a single leaf, e.g. a stream message, in which
                    // case `t` is a `Leaf` whose value the witness must carry.)
                    _ => {
                        // Sanity check: a complete `HashTree` has no bucket offset.
                        debug_assert_eq!(ht.bucket_offset, 0);

                        let expanded = ht.stubs[pos.bucket()][pos.index()]
                            .source
                            .expand()
                            .expect("expanding a stub should not fail");
                        go::<B>(&expanded, NodeId::empty(), expanded.root, t)
                    }
                };
            }

            match t {
                LabeledTree::Leaf(data) => Ok(match ht.view(pos) {
                    HashTreeView::Leaf(_) => B::make_leaf(&data[..]),
                    HashTreeView::Empty => B::make_empty(),
                    HashTreeView::Node(_, label, child) => {
                        B::make_node(label.clone(), B::make_pruned(ht.digest(child).clone()))
                    }
                    HashTreeView::Fork(digest, _left, _right) => B::make_pruned(digest.clone()),
                    // Intercepted above.
                    HashTreeView::Stub(_) => unreachable!(),
                }),
                LabeledTree::SubTree(children) if children.is_empty() => Ok(match ht.view(pos) {
                    HashTreeView::Empty => B::make_empty(),
                    HashTreeView::Leaf(digest) => B::make_pruned(digest.clone()),
                    HashTreeView::Fork(digest, _left, _right) => B::make_pruned(digest.clone()),
                    HashTreeView::Node(digest, _label, _child) => B::make_pruned(digest.clone()),
                    // Intercepted above.
                    HashTreeView::Stub(_) => unreachable!(),
                }),
                LabeledTree::SubTree(children) => children
                    .iter()
                    .try_fold(B::make_pruned(ht.digest(pos).clone()), |acc, (l, t)| {
                        B::merge_trees(acc, child_witness::<B>(ht, parent, pos, l, t)?)
                    }),
            }
        }

        go::<B>(self, NodeId::empty(), self.root, partial_tree)
    }

    /// Extends the current tree with the provided `subtree`. Produces an invalid
    /// tree if the bucket offset in `subtree` has `bucket_offset` not equal to
    /// the actual number of buckets in the current tree.
    fn splice_subtree(&mut self, subtree: HashTree) {
        // Leafs
        self.leaf_digests.extend(subtree.leaf_digests);

        // Forks
        self.fork_digests.extend(subtree.fork_digests);
        self.fork_left_children.extend(subtree.fork_left_children);
        self.fork_right_children.extend(subtree.fork_right_children);

        // Nodes
        self.node_digests.extend(subtree.node_digests);
        self.node_labels.extend(subtree.node_labels);
        self.node_children.extend(subtree.node_children);
        self.node_children_labels_ranges
            .extend(subtree.node_children_labels_ranges);

        // Reusable stubs
        self.stubs.extend(subtree.stubs);

        // Roll up the worker's build statistics. (`parallel_built_children` is
        // always 0 in a worker, which builds sequentially, but is folded in for
        // symmetry.)
        self.reused_stubs += subtree.reused_stubs;
        self.parallel_built_children += subtree.parallel_built_children;
    }
}

/// Comparator of HashTree with the older crypto::HashTree for tests
impl PartialEq<crypto::HashTree> for HashTree {
    fn eq(&self, other: &crypto::HashTree) -> bool {
        fn eq_recursive(ht: &HashTree, ht_root: NodeId, other: &crypto::HashTree) -> bool {
            // Sanity check: a complete `HashTree` has no bucket offset.
            debug_assert_eq!(ht.bucket_offset, 0);

            ht.digest(ht_root) == other.digest()
                && match (ht_root.kind(), other) {
                    // A stub collapses a whole subtree to its root digest. Expand it from its
                    // source and compare the materialized subtree structurally.
                    (NodeKind::Stub, _) => {
                        let expanded = ht.stubs[ht_root.bucket()][ht_root.index()]
                            .source
                            .expand()
                            .expect("expanding a stub should not fail");
                        eq_recursive(&expanded, expanded.root, other)
                    }
                    (NodeKind::Leaf | NodeKind::Empty, crypto::HashTree::Leaf { digest: _ }) => {
                        true
                    }
                    (
                        NodeKind::Fork,
                        crypto::HashTree::Fork {
                            digest: _,
                            left_tree,
                            right_tree,
                        },
                    ) => {
                        eq_recursive(
                            ht,
                            ht.fork_left_children[ht_root.bucket()][ht_root.index()],
                            left_tree,
                        ) && eq_recursive(
                            ht,
                            ht.fork_right_children[ht_root.bucket()][ht_root.index()],
                            right_tree,
                        )
                    }
                    (
                        NodeKind::Node,
                        crypto::HashTree::Node {
                            digest: _,
                            label,
                            hash_tree,
                        },
                    ) => {
                        ht.node_labels[ht_root.bucket()][ht_root.index()] == *label
                            && eq_recursive(
                                ht,
                                ht.node_children[ht_root.bucket()][ht_root.index()],
                                hash_tree,
                            )
                    }
                    _ => false,
                }
        }

        eq_recursive(self, self.root, other)
    }
}

#[derive(Debug)]
enum HashTreeView<'a> {
    Empty,
    Leaf(&'a Digest),
    Fork(&'a Digest, NodeId, NodeId),
    Node(&'a Digest, &'a Label, NodeId),
    /// A subtree reduced to its root digest.
    Stub(&'a Digest),
}

/// Error produced when computing hash trees
#[derive(Copy, Clone, PartialEq, Debug, thiserror::Error)]
pub enum HashTreeError {
    #[error("Hash tree calculation failed due to too deep recursion (depth={0})")]
    RecursionTooDeep(u32),
    #[error("Hash tree calculation failed due to an index overflowing")]
    IndexOverflow,
}

/// A cursor into a baseline [`HashTree`] that mirrors the position of the lazy
/// tree being traversed. Used to reuse subtrees with matching [`SubtreeSource`]
/// from a previously built tree, traversed in lockstep with the new tree.
#[derive(Clone, Copy)]
struct BaselineCursor<'a> {
    tree: &'a HashTree,
    /// The node at this position: `empty` for the root, otherwise the labeled
    /// node (`kind() == Node`) reached via the edge leading here.
    node: NodeId,
}

impl<'a> BaselineCursor<'a> {
    /// The subtree stored below `self.node` in the baseline tree.
    fn subtree_root(&self) -> NodeId {
        if self.node == NodeId::empty() {
            self.tree.root
        } else {
            // Sanity check: a complete `HashTree` has no bucket offset.
            debug_assert_eq!(self.tree.bucket_offset, 0);

            self.tree.node_children[self.node.bucket()][self.node.index()]
        }
    }

    /// If the baseline stored this position as a reusable [`NodeKind::Stub`],
    /// returns the stub node.
    fn stub(&self) -> Option<&'a StubNode> {
        let subtree_root = self.subtree_root();
        if subtree_root.kind() == NodeKind::Stub {
            // Sanity check: a complete `HashTree` has no bucket offset.
            debug_assert_eq!(self.tree.bucket_offset, 0);

            Some(&self.tree.stubs[subtree_root.bucket()][subtree_root.index()])
        } else {
            None
        }
    }

    /// Streams the children positions as `(label, cursor)` pairs, in label order.
    fn children(self) -> impl Iterator<Item = (&'a Label, BaselineCursor<'a>)> + 'a {
        let tree = self.tree;
        let NodeIndexRange {
            bucket,
            index_range,
        } = tree.node_labels_range(self.node);
        index_range.map(move |idx| {
            let child = NodeId::node(bucket, idx).expect("valid baseline hash tree");
            (
                &tree.node_labels[bucket][idx],
                BaselineCursor { tree, node: child },
            )
        })
    }
}

/// Materializes the provided lazy tree and builds its hash tree that can be
/// used to produce witnesses.
///
/// The children of a fork that declares
/// [`LazyFork::stub_sources`](crate::lazy_tree::LazyFork::stub_sources)
/// (e.g. canisters) are collapsed to digest-only [`NodeKind::Stub`] nodes.
/// The resulting tree has the exact same root hash as a fully materialized
/// build; witnesses that descend into a stubbed subtree rebuild it on demand
/// from the [`SubtreeSource`] held in the stub (see [`HashTree::witness`]).
///
/// If a `baseline` tree is provided, the [`NodeKind::Stub`] nodes of unchanged
/// subtrees are reused from it: the lazy tree and the baseline are traversed in
/// lockstep (children merge-joined by label), and wherever a child carries an
/// equal [`SubtreeSource`], it is reused instead of rebuilt. The result is
/// identical (same root hash, same witnesses) regardless of `baseline`; in
/// particular, a `baseline` built under a different certification version is
/// safe to pass: its subtrees carry a different expander, so none of them are
/// reused (they are simply rebuilt).
pub fn hash_lazy_tree<'a>(
    t: &LazyTree<'a>,
    baseline: Option<&'a HashTree>,
) -> Result<HashTree, HashTreeError> {
    /// A labeled node built by a worker thread, to be written into the final tree
    /// at preallocated index [`index`](Self::index) once its subtree is spliced in.
    struct SubtreeRoot {
        index: usize,
        label: Label,
        /// The labeled-node digest `H("ic-hashtree-labeled" · label · root_digest)`,
        /// computed in the worker thread (subtree digests are invariant under
        /// splicing).
        digest: Digest,
        children_range: NodeIndexRange,
        root: NodeId,
    }

    /// One child of a fork, to be turned into a labeled node in the hash tree.
    enum Child<'a> {
        /// A regular subtree, materialized inline via [`build_tree`].
        Tree(LazyTree<'a>),
        /// A reusable subtree collapsed to a [`NodeKind::Stub`], identified by its
        /// [`SubtreeSource`]. The subtree itself is materialized on demand (via the
        /// parent fork's [`LazyFork::edge`]) only when it has to be rebuilt.
        Stub(SubtreeSource),
    }

    // We only initialize thread pools lazily the first time we need them
    enum ParallelismStrategy {
        Sequential,
        Concurrent,
        ConcurrentInPool(scoped_threadpool::Pool),
    }

    impl ParallelismStrategy {
        fn pool(&mut self) -> Option<&mut scoped_threadpool::Pool> {
            match self {
                Self::Sequential => None,
                Self::Concurrent => {
                    *self = Self::ConcurrentInPool(scoped_threadpool::Pool::new(
                        NUMBER_OF_CERTIFICATION_THREADS,
                    ));
                    self.pool()
                }
                Self::ConcurrentInPool(pool) => Some(pool),
            }
        }

        fn is_concurrent(&self) -> bool {
            !matches!(self, Self::Sequential)
        }
    }

    /// Builds one labeled `child` (linked under `parent`), returning its
    /// [`NodeId`] and whether it was expensively (re)built — i.e. materialized —
    /// rather than cheaply reused from `baseline`.
    ///
    /// A [`Child::Stub`] is collapsed to a digest-only [`NodeKind::Stub`]: its
    /// digest is reused from `baseline` when the sources are equal (cheap, without
    /// materializing the child at all), else the subtree is rebuilt from its
    /// [`SubtreeSource`] (expensive). A [`Child::Tree`] is materialized normally
    /// via [`build_tree`] (expensive).
    fn build_child<'a>(
        child: Child<'a>,
        ht: &mut HashTree,
        parent: NodeId,
        parallelism_strategy: &mut ParallelismStrategy,
        recursion_depth: u32,
        baseline: Option<BaselineCursor<'a>>,
    ) -> Result<(NodeId, bool), HashTreeError> {
        match child {
            Child::Stub(source) => {
                let (digest, was_built) = match baseline.and_then(|b| b.stub()) {
                    // Unchanged: the baseline carries an equal `SubtreeSource` — same source
                    // allocation *and* same expander (hence same certification version) — so its
                    // digest is reused without materializing the child.
                    Some(stub) if stub.source == source => {
                        ht.reused_stubs += 1;
                        (stub.digest.clone(), false)
                    }

                    // New, changed, or built under a different version: rebuild the subtree from
                    // its (current) `source` only to capture its root digest; if later needed for
                    // a witness, it is rebuilt on demand the same way.
                    _ => {
                        let child_ht = source.expand().expect("failed to expand stub");
                        (child_ht.root_hash().clone(), true)
                    }
                };
                Ok((ht.new_stub(digest, source)?, was_built))
            }

            // Materialize non-stubbed child: expensive.
            Child::Tree(t) => {
                let id = build_tree(
                    &t,
                    ht,
                    parent,
                    parallelism_strategy,
                    recursion_depth + 1,
                    baseline,
                )?;
                Ok((id, true))
            }
        }
    }

    /// Materializes the hash tree for `t`, returning the [`NodeId`] of its root.
    ///
    /// This is different from [`build_child`] in that it always materializes the
    /// tree, so this is invoked for building throwaway subtrees for stub nodes.
    ///
    /// Collapsing a fork's children into digest-only [`NodeKind::Stub`] nodes
    /// happens here, driven by the parent fork's [`LazyFork::stub_sources`], via
    /// [`build_child`].
    fn build_tree<'a>(
        t: &LazyTree<'a>,
        ht: &mut HashTree,
        parent: NodeId,
        parallelism_strategy: &mut ParallelismStrategy,
        recursion_depth: u32,
        baseline: Option<BaselineCursor<'a>>,
    ) -> Result<NodeId, HashTreeError> {
        if recursion_depth > MAX_RECURSION_DEPTH {
            return Err(HashTreeError::RecursionTooDeep(MAX_RECURSION_DEPTH));
        }

        match t {
            LazyTree::Blob([], None) => ht.new_leaf(EMPTY_LEAF_HASH),
            LazyTree::Blob(b, None) => {
                let mut h = Hasher::for_domain("ic-hashtree-leaf");
                h.update(b);
                ht.new_leaf(h.finalize())
            }
            LazyTree::Blob(_b, Some(cached_hash)) => {
                #[cfg(debug_assertions)]
                {
                    let mut h = Hasher::for_domain("ic-hashtree-leaf");
                    h.update(_b);
                    assert_eq!(h.finalize(), Digest(*cached_hash));
                }
                ht.new_leaf(Digest(*cached_hash))
            }
            LazyTree::LazyBlob(f) => {
                let b = f();
                if b.is_empty() {
                    return ht.new_leaf(EMPTY_LEAF_HASH);
                }

                let mut h = Hasher::for_domain("ic-hashtree-leaf");
                h.update(&b);
                ht.new_leaf(h.finalize())
            }
            LazyTree::LazyFork(f) => {
                let num_children = f.len();
                if num_children == 0 {
                    return Ok(NodeId::empty());
                }

                let NodeIndexRange {
                    bucket,
                    index_range: range,
                } = ht.preallocate_nodes(num_children, parent)?;
                let mut nodes = Vec::with_capacity(num_children);

                // Build the children sequentially, but watch how many have to be actually built
                // (hashed) rather than cheaply reused from the baseline. After a warmup,
                // extrapolate that rate over the whole fork; if it projects too much work, hand
                // the *remaining* children to the thread pool. This covers both stubbing forks
                // (where reuse keeps the rate low) and regular forks (where every child is
                // materialized; so a large fork always parallelizes).
                //
                // We only collect the unprocessed tail into a `Vec` if and when we switch; the
                // common, all-sequential path uses the `joined` iterator directly.
                let may_parallelize =
                    num_children >= PARALLEL_MIN_CHILDREN && parallelism_strategy.is_concurrent();
                let mut do_parallelize = may_parallelize && baseline.is_none();
                let mut num_processed = 0_usize;
                let mut num_built = 0_usize;

                // If the fork declares its children reusable (a stubbing fork), iterate
                // `(label, source)` so unchanged children are reused from the baseline without
                // being materialized at all; the rest are rebuilt from their source. Otherwise
                // materialize every child inline.
                let children: Box<dyn Iterator<Item = (Label, Child<'_>)> + '_> =
                    match f.stub_sources() {
                        Some(sources) => {
                            Box::new(sources.map(|(label, source)| (label, Child::Stub(source))))
                        }
                        None => Box::new(
                            f.children()
                                .map(|(label, child)| (label, Child::Tree(child))),
                        ),
                    };

                // Merge-join the children with the baseline children (a missing baseline child
                // is `None`); each tagged with its preallocated node index.
                let mut joined = range.zip(left_outer_join(
                    children,
                    baseline.into_iter().flat_map(BaselineCursor::children),
                ));

                while !do_parallelize && let Some((i, (label, child, base))) = joined.next() {
                    let (child, was_built) = build_child(
                        child,
                        ht,
                        NodeId::node(bucket, i)?,
                        parallelism_strategy,
                        recursion_depth,
                        base,
                    )?;

                    num_built += was_built as usize;
                    num_processed += 1;
                    do_parallelize |= may_parallelize
                        // Beyond the warmup, switch to parallel once the sampled build rate
                        // (`num_built / num_processed`) projects more than the number of children
                        // required for parallel processing over all `num_children` (rearranged to avoid
                        // division).
                        && num_processed >= ADAPTIVE_WARMUP_CHILDREN
                            && num_built * num_children >= PARALLEL_MIN_CHILDREN * num_processed;

                    let mut h = Hasher::for_domain("ic-hashtree-labeled");
                    h.update(label.as_bytes());
                    h.update(ht.digest(child).as_bytes());
                    ht.node_digests[0][i] = h.finalize();
                    ht.node_children[0][i] = child;
                    ht.node_labels[0][i] = label;
                    nodes.push(NodeId::node(bucket, i)?);
                }

                // Build whatever is left of the children in parallel.
                if do_parallelize {
                    build_fork_parallel(
                        parallelism_strategy.pool().unwrap(),
                        ht,
                        &mut nodes,
                        recursion_depth,
                        bucket,
                        joined,
                        num_children - num_processed,
                    )?;
                }

                if nodes.len() == 1 {
                    return Ok(nodes[0]);
                }

                // Build a binary tree of forks on top of the labelled nodes
                let mut next = Vec::with_capacity((nodes.len() as f64 / 2.0).ceil() as usize);
                ht.reserve_forks(nodes.len() - 1);
                loop {
                    for pair in nodes.chunks_exact(2) {
                        let mut h = Hasher::for_domain("ic-hashtree-fork");
                        h.update(ht.digest(pair[0]).as_bytes());
                        h.update(ht.digest(pair[1]).as_bytes());
                        next.push(ht.new_fork(h.finalize(), pair[0], pair[1])?);
                    }
                    if nodes.len() % 2 == 1 {
                        next.push(*nodes.last().unwrap());
                    }

                    if next.len() == 1 {
                        return Ok(next[0]);
                    }

                    nodes.clear();
                    std::mem::swap(&mut nodes, &mut next);
                }
            }
        }
    }

    /// Builds the given `tail` of a fork's children across the thread pool,
    /// writing the resulting labeled nodes into `ht` and appending their
    /// [`NodeId`]s to `nodes` (in `tail` order).
    ///
    /// Each `tail` entry is `(i, (label, child, base))`, where `i` is the child's
    /// preallocated node index and `base` is its baseline counterpart (already
    /// merge-joined by the caller).
    #[allow(clippy::type_complexity)]
    fn build_fork_parallel<'a>(
        thread_pool: &mut scoped_threadpool::Pool,
        ht: &mut HashTree,
        nodes: &mut Vec<NodeId>,
        depth: u32,
        bucket: usize,
        mut tail: impl Iterator<Item = (usize, (Label, Child<'a>, Option<BaselineCursor<'a>>))>,
        tail_len: usize,
    ) -> Result<(), HashTreeError> {
        ht.parallel_built_children += tail_len;

        let bucket_offset = ht.node_children.len();
        let threads = thread_pool.thread_count() as usize;
        debug_assert!(threads > 0);
        let per_thread = ((tail_len
            .checked_add(threads)
            .ok_or(HashTreeError::IndexOverflow)?
            - 1)
            / threads)
            .max(1);
        let mut subtrees: Vec<Option<Result<HashTree, HashTreeError>>> = vec![None; threads];
        let mut roots: Vec<Vec<SubtreeRoot>> = repeat_with(|| Vec::with_capacity(per_thread))
            .take(threads)
            .collect();

        // Partition `tail` into owned, consecutive per-thread chunks (mirroring
        // `slice::chunks`, but by value) so each thread can *move* its children into
        // `build_child` rather than clone them — dropping the duplicated
        // `SubtreeSource` `Arc`s would otherwise add significant overhead.
        let mut chunks: Vec<Vec<(usize, (Label, Child<'_>, Option<BaselineCursor<'_>>))>> =
            Vec::with_capacity(threads);
        loop {
            let chunk: Vec<_> = tail.by_ref().take(per_thread).collect();
            if chunk.is_empty() {
                break;
            }
            chunks.push(chunk);
        }

        thread_pool.scoped(|scope| {
            for (i, (chunk, subtree, roots)) in
                izip!(chunks, subtrees.iter_mut(), roots.iter_mut()).enumerate()
            {
                scope.execute(move || {
                    // In each thread, we use a bucket offset b. All e.g fork digests
                    // produced by this thread will be in ht.fork_digests[b] in the final
                    // hash tree, so the NodeIds of the internal links need to reflect that.
                    // Note that we always add new nodes, leaves and forks to bucket 0.
                    // The bucket offset only comes into play when determining NodeIds and
                    // lookup based on NodeId.
                    let mut ht = HashTree::new_with_bucket_offset(bucket_offset + i);
                    let mut error: Option<HashTreeError> = None;
                    for (index, (label, child, base)) in chunk {
                        // Since the parent is outside of `ht`, we set the parent to NodeId::empty()
                        // and fix the link from `root` to the parent later. A `Child::Stub` is
                        // collapsed to a stub here.
                        //
                        match build_child(
                            child,
                            &mut ht,
                            NodeId::empty(),
                            // Run with `ParallelismStrategy::Sequential`: besides avoiding nested thread
                            // pools, this limits each worker's tree to a single bucket, which
                            // `splice_subtree` relies on to place worker `i` at bucket `bucket_offset + i`.
                            &mut ParallelismStrategy::Sequential,
                            depth,
                            base,
                        ) {
                            Ok((root, _was_built)) => {
                                // Since the node had no parent (i.e. it was "the root"), its children have been
                                // added to `root_labels_range`. Use it as the subtree's `children_range`.
                                let children_range = if root.kind() == NodeKind::Stub {
                                    // A stub has no materialized labeled children of its own, so its
                                    // `children_range` is empty.
                                    NodeIndexRange::default()
                                } else {
                                    ht.root_labels_range.clone()
                                };
                                // The subtree digest is invariant under splicing, so the labeled-node
                                // digest can be computed here (in parallel) rather than on the main
                                // thread after the splice.
                                let mut h = Hasher::for_domain("ic-hashtree-labeled");
                                h.update(label.as_bytes());
                                h.update(ht.digest(root).as_bytes());
                                roots.push(SubtreeRoot {
                                    index,
                                    label,
                                    digest: h.finalize(),
                                    children_range,
                                    root,
                                });
                            }
                            Err(err) => {
                                error = Some(err);
                                break;
                            }
                        }
                    }
                    let tree_or_error = match error {
                        Some(err) => Err(err),
                        None => Ok(ht),
                    };
                    subtree.replace(tree_or_error);
                });
            }
        });
        for subtree in subtrees.into_iter().flatten() {
            ht.splice_subtree(subtree?);
        }
        // The roots are flattened in (thread, chunk) order, i.e. ascending node index.
        for SubtreeRoot {
            index,
            label,
            digest,
            children_range,
            root,
        } in roots.into_iter().flatten()
        {
            ht.node_children_labels_ranges[bucket][index] = children_range;
            ht.node_digests[bucket][index] = digest;
            ht.node_children[bucket][index] = root;
            ht.node_labels[bucket][index] = label;
            nodes.push(NodeId::node(bucket, index)?);
        }
        Ok(())
    }

    let baseline = baseline.map(|tree| BaselineCursor {
        tree,
        node: NodeId::empty(),
    });

    let mut ht = HashTree::new();
    let strategy = &mut ParallelismStrategy::Concurrent;
    // Always materialize the root. Stubbing applies to (and is relevant for) the
    // children of potentially huge forks (e.g. `/canister` or `/request_status`).
    ht.root = build_tree(t, &mut ht, NodeId::empty(), strategy, 0, baseline)?;
    ht.check_invariants();

    Ok(ht)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_leaf_hash_matches_hasher() {
        let h = Hasher::for_domain("ic-hashtree-leaf");
        assert_eq!(h.finalize(), EMPTY_LEAF_HASH);
    }
}
