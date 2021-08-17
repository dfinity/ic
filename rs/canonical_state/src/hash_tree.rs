use crate::lazy_tree::LazyTree;
use ic_crypto_tree_hash::{
    self as crypto, hasher::Hasher, Digest, Label, LabeledTree, WitnessBuilder,
};
use std::collections::VecDeque;
use std::fmt;
use std::ops::Range;

const EMPTY_HASH: Digest = Digest([
    0x4e, 0x3e, 0xd3, 0x5c, 0x4e, 0x2d, 0x1e, 0xe8, 0x99, 0x96, 0x48, 0x3f, 0xb6, 0x26, 0x0a, 0x64,
    0xcf, 0xfb, 0x6c, 0x47, 0xdb, 0xab, 0x21, 0x6e, 0x79, 0x30, 0xe8, 0x2f, 0x81, 0x90, 0xd1, 0x20,
]);

const LEAF_MASK: u32 = 0x4000_0000;
const NODE_MASK: u32 = 0x8000_0000;
const FORK_MASK: u32 = 0xc000_0000;
const INDEX_MASK: u32 = 0x3fff_ffff;

#[derive(PartialEq, Eq, Debug)]
pub enum NodeKind {
    Empty,
    Fork,
    Leaf,
    Node,
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
pub struct NodeId(u32);

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind() {
            NodeKind::Empty => write!(f, "Empty"),
            NodeKind::Fork => write!(f, "Fork({})", self.index()),
            NodeKind::Leaf => write!(f, "Leaf({})", self.index()),
            NodeKind::Node => write!(f, "Node({})", self.index()),
        }
    }
}

impl NodeId {
    /// Constructs an empty tree.
    #[inline]
    pub fn empty() -> Self {
        Self(0)
    }

    /// Constructs a new Fork with the specified index.
    #[inline]
    pub fn fork(idx: usize) -> Self {
        Self(FORK_MASK | idx as u32)
    }

    /// Constructs a new Leaf with the specified index.
    #[inline]
    pub fn leaf(idx: usize) -> Self {
        Self(LEAF_MASK | idx as u32)
    }

    /// Constructs a new Node with the specified index.
    #[inline]
    pub fn node(idx: usize) -> Self {
        Self(NODE_MASK | idx as u32)
    }

    /// Returns the component kind of this node.
    #[inline]
    pub fn kind(self) -> NodeKind {
        let node_id = self.0;
        if node_id & FORK_MASK == FORK_MASK {
            NodeKind::Fork
        } else if node_id & NODE_MASK == NODE_MASK {
            NodeKind::Node
        } else if node_id & LEAF_MASK == LEAF_MASK {
            NodeKind::Leaf
        } else {
            NodeKind::Empty
        }
    }

    /// Returns the index component of this node.
    #[inline]
    pub fn index(self) -> usize {
        (self.0 & INDEX_MASK) as usize
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
/// The tree is represented as a collection of parallel arrays
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
/// fork_lefts:    [node_0]
/// fork_rights:   [node_1]
///
/// node_labels:   ["x",     "y"]
/// node_children: [leaf_0,  leaf_1]
///
/// leaves:        ["data1", "data2"]
/// ```
///
/// In this representation, the identifier of a node is an 32 bit unsigned
/// integer, where the 2 most significant bits are used to indicate the type of
/// the node:
///
///  * 00 is an empty tree.
///  * 01 is a leaf.
///  * 10 is a labeled node.
///  * 11 is a fork.
///
///  This means that the tree can store at most 2^30 nodes of the same type.  As
///  each tree node has a 32-byte hash associated with it, the tree needs to
///  occupy at least 32 GiB of data before the index overflows.
///
/// [1]: https://en.wikipedia.org/wiki/AoS_and_SoA
#[derive(Clone, Debug, Default)]
pub struct HashTree {
    /// Id of the root of the tree.
    root: NodeId,
    /// If the tree root is a fork or a node, root_labels_range represents a
    /// half-closed index interval [i, j) pointing into the node_labels array
    /// containing all the labels on edges of the original tree going out of the
    /// root.
    ///
    /// INVARIANT: i ≤ j ≤ node_labels.len()
    root_labels_range: (usize, usize),

    /// i-th element of this array contains the hash of the leaf with id
    /// `NodeId::leaf(i)`.
    leaf_digests: Vec<Digest>,

    // INVARIANT:
    // fork_digests.len() == fork_left_children.len() == fork_right_children_len().
    /// i-th element of this array contains the hash of the fork with id equal
    /// to `NodeId::fork(i)`.
    fork_digests: Vec<Digest>,
    /// i-th element of this array contains the node id of the left child of the
    /// fork with id `NodeId::fork(i)`.
    fork_left_children: Vec<NodeId>,
    /// i-th element of this array contains the node id of the right child of
    /// the fork with id `NodeId::fork(i)`.
    fork_right_children: Vec<NodeId>,

    // INVARIANT:
    // node_digests.len() == node_labels.len() == node_children.len() ==
    // node_children_labels_ranges.len()
    //
    // INVARIANT:
    // labels having the same parent node are stored consecutively.
    /// i-th element of this array contains the hash of the labeled node with id
    /// `NodeId::node(i)`.
    node_digests: Vec<Digest>,
    /// i-th element of this array contains the label of the labeled node with
    /// id `NodeId::node(i)`.
    node_labels: Vec<Label>,
    /// i-th element of this array contains the direct child of the labeled node
    /// with id `NodeId::node(i)`.
    node_children: Vec<NodeId>,
    /// i-th element of this array contains a half-closed index interval [i, j)
    /// pointing into the node_labels array containing all the labels on edges
    /// of the original tree going out of the node with id `NodeId::node(i)`.
    ///
    /// INVARIANT: i ≤ j ≤ node_labels.len()
    node_children_labels_ranges: Vec<(usize, usize)>,
}

impl HashTree {
    fn new_fork(&mut self, d: Digest, l: NodeId, r: NodeId) -> NodeId {
        let id = self.fork_digests.len();

        self.fork_digests.push(d);
        self.fork_left_children.push(l);
        self.fork_right_children.push(r);

        NodeId::fork(id)
    }

    fn new_leaf(&mut self, d: Digest) -> NodeId {
        let id = self.leaf_digests.len();
        self.leaf_digests.push(d);
        NodeId::leaf(id)
    }

    fn preallocate_nodes(
        &mut self,
        labels: impl Iterator<Item = Label>,
        parent: NodeId,
    ) -> Range<usize> {
        let old_len = self.node_labels.len();
        for label in labels {
            self.node_labels.push(label)
        }
        let new_len = self.node_labels.len();

        self.node_digests.resize(new_len, Digest([0; 32]));
        self.node_children.resize(new_len, NodeId::empty());
        self.node_children_labels_ranges.resize(new_len, (0, 0));

        if parent == NodeId::empty() {
            self.root_labels_range = (old_len, new_len);
        } else {
            debug_assert_eq!(NodeKind::Node, parent.kind());
            self.node_children_labels_ranges[parent.index()] = (old_len, new_len);
        }
        old_len..new_len
    }

    fn node_labels_range(&self, parent: NodeId) -> Range<usize> {
        if parent == NodeId::empty() {
            let (begin, end) = self.root_labels_range;
            begin..end
        } else {
            let (begin, end) = self.node_children_labels_ranges[parent.index()];
            begin..end
        }
    }

    fn digest(&self, node_id: NodeId) -> &Digest {
        match node_id.kind() {
            NodeKind::Fork => &self.fork_digests[node_id.index()],
            NodeKind::Node => &self.node_digests[node_id.index()],
            NodeKind::Leaf => &self.leaf_digests[node_id.index()],
            NodeKind::Empty => &EMPTY_HASH,
        }
    }

    fn check_invariants(&self) {
        debug_assert!(self.root_labels_range.0 <= self.root_labels_range.1);
        debug_assert!(self.root_labels_range.1 <= self.node_labels.len());

        debug_assert_eq!(self.fork_digests.len(), self.fork_left_children.len());
        debug_assert_eq!(self.fork_digests.len(), self.fork_right_children.len());

        debug_assert_eq!(self.node_digests.len(), self.node_labels.len());
        debug_assert_eq!(self.node_digests.len(), self.node_children.len());
        debug_assert_eq!(
            self.node_digests.len(),
            self.node_children_labels_ranges.len()
        );
        debug_assert!(self
            .node_children_labels_ranges
            .iter()
            .all(|(i, j)| i <= j && j <= &self.node_labels.len()));
    }

    /// Returns the estimate of the size occupied by this data structure in
    /// bytes.
    pub fn size_estimate(&self) -> usize {
        fn slice_size<T>(s: &[T]) -> usize {
            s.len() * std::mem::size_of::<T>()
        }
        std::mem::size_of_val(self)
            + slice_size(&self.leaf_digests)
            + slice_size(&self.fork_digests)
            + slice_size(&self.fork_left_children)
            + slice_size(&self.fork_right_children)
            + slice_size(&self.node_digests)
            + slice_size(&self.node_labels)
            + slice_size(&self.node_children)
            + slice_size(&self.node_children_labels_ranges)
    }

    /// Returns a structured representation-independent view of the node with
    /// the specified ID.
    pub fn view(&self, node_id: NodeId) -> HashTreeView<'_> {
        let idx = node_id.index();
        match node_id.kind() {
            NodeKind::Fork => HashTreeView::Fork(
                &self.fork_digests[idx],
                self.fork_left_children[idx],
                self.fork_right_children[idx],
            ),
            NodeKind::Node => HashTreeView::Node(
                &self.node_digests[idx],
                &self.node_labels[idx],
                self.node_children[idx],
            ),
            NodeKind::Leaf => HashTreeView::Leaf(&self.leaf_digests[idx]),
            NodeKind::Empty => HashTreeView::Empty,
        }
    }

    /// Returns the root hash of the tree.
    pub fn root_hash(&self) -> &Digest {
        self.digest(self.root)
    }

    /// Constructs a witness for the specified partial tree.
    ///
    /// # Panics
    ///
    /// Panics if the partial tree a structure that is different from the
    /// labeled tree that was used to construct this hash tree.
    pub fn witness<B: WitnessBuilder>(&self, partial_tree: &LabeledTree<Vec<u8>>) -> B::Tree {
        fn add_forks<B: WitnessBuilder>(
            ht: &HashTree,
            pos: NodeId,
            offset: usize,
            size: usize,
            subwitness: B::Tree,
        ) -> B::Tree {
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
        ) -> B::Tree {
            let label_range = ht.node_labels_range(parent);
            let len = label_range.end - label_range.start;
            let labels = &ht.node_labels[label_range.clone()];

            match labels.binary_search(l) {
                Ok(offset) => {
                    let idx = label_range.start + offset;
                    let node_id = NodeId::node(idx);
                    let subwitness = B::make_node(
                        l.clone(),
                        go::<B>(ht, node_id, ht.node_children[idx], subtree),
                    );
                    if pos.kind() == NodeKind::Node {
                        subwitness
                    } else {
                        add_forks::<B>(ht, pos, offset, len, subwitness)
                    }
                }
                Err(offset) => {
                    let pruned_label_at = |o| {
                        add_forks::<B>(
                            ht,
                            pos,
                            o,
                            len,
                            B::make_node(
                                ht.node_labels[label_range.start + o].clone(),
                                B::make_pruned(
                                    ht.digest(ht.node_children[label_range.start + o]).clone(),
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
                        B::merge_trees(pruned_label_at(offset - 1), pruned_label_at(offset))
                    }
                }
            }
        }

        fn go<B: WitnessBuilder>(
            ht: &HashTree,
            parent: NodeId,
            pos: NodeId,
            t: &LabeledTree<Vec<u8>>,
        ) -> B::Tree {
            match t {
                LabeledTree::Leaf(data) => {
                    if pos.kind() == NodeKind::Leaf {
                        B::make_leaf(&data[..])
                    } else {
                        panic!(
                            "inconsistent tree structure: not a leaf in the original tree, \
                             parent = {:?}, pos = {:?}, hash_tree = {:?}, labeled_tree = {:?}",
                            parent, pos, ht, t
                        );
                    }
                }
                LabeledTree::SubTree(children) => children
                    .iter()
                    .map(|(l, t)| child_witness::<B>(ht, parent, pos, l, t))
                    .fold(B::make_pruned(ht.digest(pos).clone()), B::merge_trees),
            }
        }

        go::<B>(self, NodeId::empty(), self.root, partial_tree)
    }
}

#[derive(Debug)]
pub enum HashTreeView<'a> {
    Empty,
    Leaf(&'a Digest),
    Fork(&'a Digest, NodeId, NodeId),
    Node(&'a Digest, &'a Label, NodeId),
}

/// Materializes the provided lazy tree and builds its hash tree that can be
/// used to produce witnesses.
pub fn hash_lazy_tree(t: &LazyTree<'_>) -> HashTree {
    fn go(t: &LazyTree<'_>, ht: &mut HashTree, parent: NodeId) -> NodeId {
        match t {
            LazyTree::Blob(b) => {
                let mut h = Hasher::for_domain("ic-hashtree-leaf");
                h.update(b);
                ht.new_leaf(h.finalize())
            }
            LazyTree::LazyBlob(f) => {
                let b = f();
                let mut h = Hasher::for_domain("ic-hashtree-leaf");
                h.update(&b);
                ht.new_leaf(h.finalize())
            }
            LazyTree::LazyFork(f) => {
                let range = ht.preallocate_nodes(f.labels(), parent);
                let mut nodes = VecDeque::new();

                for i in range {
                    let child = go(
                        &f.edge(&ht.node_labels[i]).expect("missing fork tree"),
                        ht,
                        NodeId::node(i),
                    );
                    let mut h = Hasher::for_domain("ic-hashtree-labeled");
                    h.update(ht.node_labels[i].as_bytes());
                    h.update(ht.digest(child).as_bytes());
                    ht.node_digests[i] = h.finalize();
                    ht.node_children[i] = child;
                    nodes.push_back(NodeId::node(i));
                }

                if nodes.is_empty() {
                    return NodeId::empty();
                }

                let mut next = VecDeque::new();
                loop {
                    while let Some(l) = nodes.pop_front() {
                        if let Some(r) = nodes.pop_front() {
                            let mut h = Hasher::for_domain("ic-hashtree-fork");
                            h.update(ht.digest(l).as_bytes());
                            h.update(ht.digest(r).as_bytes());
                            next.push_back(ht.new_fork(h.finalize(), l, r));
                        } else {
                            next.push_back(l);
                        }
                    }

                    if next.len() == 1 {
                        return next.pop_front().unwrap();
                    }
                    std::mem::swap(&mut nodes, &mut next);
                }
            }
        }
    }
    let mut ht = HashTree::default();
    ht.root = go(t, &mut ht, NodeId::empty());
    ht.check_invariants();
    ht
}

/// Constructs a hash tree corresponding to the specified lazy tree.
/// This function is only used for benchmarks.
pub fn crypto_hash_lazy_tree(t: &LazyTree<'_>) -> crypto::HashTree {
    use crypto::HashTree;

    fn go(t: &LazyTree<'_>) -> HashTree {
        match t {
            LazyTree::Blob(b) => {
                let mut h = Hasher::for_domain("ic-hashtree-leaf");
                h.update(b);
                HashTree::Leaf {
                    digest: h.finalize(),
                }
            }
            LazyTree::LazyBlob(f) => {
                let b = f();
                let mut h = Hasher::for_domain("ic-hashtree-leaf");
                h.update(&b);
                HashTree::Leaf {
                    digest: h.finalize(),
                }
            }
            LazyTree::LazyFork(f) => {
                let mut children = VecDeque::new();
                for label in f.labels() {
                    let child = go(&f.edge(&label).expect("missing fork tree"));
                    let mut h = Hasher::for_domain("ic-hashtree-labeled");
                    h.update(label.as_bytes());
                    h.update(child.digest().as_bytes());
                    children.push_back(HashTree::Node {
                        digest: h.finalize(),
                        label,
                        hash_tree: Box::new(child),
                    });
                }

                if children.is_empty() {
                    return HashTree::Leaf { digest: EMPTY_HASH };
                }

                let mut next = VecDeque::new();
                loop {
                    while let Some(l) = children.pop_front() {
                        if let Some(r) = children.pop_front() {
                            let mut h = Hasher::for_domain("ic-hashtree-fork");
                            h.update(l.digest().as_bytes());
                            h.update(r.digest().as_bytes());
                            next.push_back(HashTree::Fork {
                                digest: h.finalize(),
                                left_tree: Box::new(l),
                                right_tree: Box::new(r),
                            });
                        } else {
                            next.push_back(l);
                        }
                    }

                    if next.len() == 1 {
                        return next.pop_front().unwrap();
                    }
                    std::mem::swap(&mut children, &mut next);
                }
            }
        }
    }
    go(t)
}

#[cfg(test)]
mod test;
