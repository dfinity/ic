#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]

use ic_crypto_sha2::Sha256;
use serde::{ser::SerializeSeq, Deserialize, Serialize, Serializer};
use serde_bytes::Bytes;
use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::iter::FromIterator;
use std::ops::Deref;
use std::ops::DerefMut;

pub mod flat_map;
pub mod hasher;
pub mod proto;
pub(crate) mod tree_hash;

pub use flat_map::FlatMap;
pub use tree_hash::*;

/// Represents a path (a collection of [`Label`]) in a hash tree.
///
/// Initialisation options include:
///
/// - If you have a `Vec<Label>` use `Path::new`.
///
/// - If you have a single [`Label`], use `Path::from(Label)`.
///
/// - If you have an iterator that contains [`Label`] or `&Label` use
///   `Path::from_iter(iterator)`.
///
// Implemented as a new type to allow implementation of traits like
// `fmt::Display`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
pub struct Path(Vec<Label>);

impl Deref for Path {
    type Target = Vec<Label>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Path {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl fmt::Display for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "/{}",
            self.iter()
                .map(|label| label.to_string())
                .collect::<Vec<String>>()
                .join("/")
        )
    }
}

impl FromIterator<Label> for Path {
    fn from_iter<T: IntoIterator<Item = Label>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl<'a> FromIterator<&'a Label> for Path {
    fn from_iter<T: IntoIterator<Item = &'a Label>>(iter: T) -> Self {
        Self(iter.into_iter().cloned().collect())
    }
}

impl From<Vec<Label>> for Path {
    fn from(path: Vec<Label>) -> Self {
        Self(path)
    }
}

impl From<Label> for Path {
    fn from(label: Label) -> Self {
        Self(vec![label])
    }
}

impl Path {
    pub fn new(path: Vec<Label>) -> Self {
        Self(path)
    }
}

/// A blob used as a label in the tree.
///
/// Most labels are expected to be printable ASCII strings, but some
/// are just short sequences of arbitrary bytes (e.g., CanisterIds).
///
/// Note that
/// - `Label`s are compared by comparing their byte representation.
///   Therefore, `Label`s casted from other representations must not
///   necessarily retain their original ordering, e.g., if `Label`s are
///   obtained via `From<String>`.
/// - `Label`s that hold a reference to an object are compared with
///   other labels by comparing the bytes of the underlying representation,
///   i.e., as if the `Label` would hold the bytes and not the reference.
#[derive(Clone, Serialize, Deserialize)]
#[serde(from = "&serde_bytes::Bytes")]
#[serde(into = "serde_bytes::ByteBuf")]
pub struct Label(LabelRepr);

/// Vec<u8> is typically 3 machine words long (pointer + size + capacity) which
/// is 24 bytes on amd64.  It's a good practice to keep enum variants of
/// approximately the same size. We want to optimize for labels of at most 32
/// bytes (as we will have many labels that are SHA256 hashes).
const SMALL_LABEL_SIZE: usize = 32;

/// This type hides the implementation of [`Label`].
#[derive(Clone)]
enum LabelRepr {
    /// A label small enough to fit into this representation "by value". The
    /// first byte of the array indicates the number of bytes that should be
    /// used as label value, so we can fit up to SMALL_LABEL_SIZE bytes.
    Value([u8; SMALL_LABEL_SIZE + 1]),
    /// Label of size above SMALL_LABEL_SIZE.
    Ref(Vec<u8>),
}

impl Default for Label {
    fn default() -> Self {
        // The default value is only used as a placeholder
        // It's not so important what the actual value is
        Self(LabelRepr::Value([0; SMALL_LABEL_SIZE + 1]))
    }
}

impl PartialEq for Label {
    fn eq(&self, rhs: &Self) -> bool {
        self.as_bytes() == rhs.as_bytes()
    }
}

impl Eq for Label {}

impl Ord for Label {
    fn cmp(&self, rhs: &Self) -> std::cmp::Ordering {
        self.as_bytes().cmp(rhs.as_bytes())
    }
}

impl PartialOrd for Label {
    fn partial_cmp(&self, rhs: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(rhs))
    }
}

impl Label {
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        match &self.0 {
            LabelRepr::Value(bytes) => {
                debug_assert!(bytes[0] as usize <= SMALL_LABEL_SIZE);
                &bytes[1..=bytes[0] as usize]
            }
            LabelRepr::Ref(v) => &v[..],
        }
    }

    #[inline]
    pub fn into_vec(self) -> Vec<u8> {
        match self {
            Label(LabelRepr::Ref(v)) => v,
            l => l.as_bytes().to_vec(),
        }
    }
}

impl fmt::Debug for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn is_printable_ascii(byte: u8) -> bool {
            (32..127).contains(&byte)
        }
        let bytes = self.as_bytes();
        if bytes.iter().all(|b| is_printable_ascii(*b)) {
            write!(
                f,
                "{}",
                std::str::from_utf8(bytes).expect("Conversion of ASCII to UTF8 should never fail")
            )
        } else {
            write!(f, "0x")?;
            bytes.iter().try_for_each(|b| write!(f, "{:02X}", b))
        }
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<Label> for String {
    fn from(val: Label) -> Self {
        val.to_string()
    }
}

impl From<Label> for serde_bytes::ByteBuf {
    fn from(val: Label) -> Self {
        Self::from(val.into_vec())
    }
}

impl<T> From<T> for Label
where
    T: std::convert::AsRef<[u8]>,
{
    fn from(bytes: T) -> Label {
        let slice = bytes.as_ref();
        let n = slice.len();
        if n <= SMALL_LABEL_SIZE {
            let mut buf = [0u8; SMALL_LABEL_SIZE + 1];
            buf[0] = n as u8;
            buf[1..=n].copy_from_slice(slice);
            debug_assert!(buf[0] as usize <= SMALL_LABEL_SIZE);
            Self(LabelRepr::Value(buf))
        } else {
            Self(LabelRepr::Ref(slice.to_vec()))
        }
    }
}
/// The computed hash of the data in a `Leaf`; or of a [`LabeledTree`].
#[derive(PartialEq, Eq, Clone)]
pub struct Digest(pub [u8; Sha256::DIGEST_LEN]);
ic_crypto_internal_types::derive_serde!(Digest, Sha256::DIGEST_LEN);

impl Digest {
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    #[inline]
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x")?;
        self.0.iter().try_for_each(|b| write!(f, "{:02X}", b))
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<[u8; Sha256::DIGEST_LEN]> for Digest {
    fn from(bytes: [u8; Sha256::DIGEST_LEN]) -> Self {
        Digest(bytes)
    }
}

impl TryFrom<Vec<u8>> for Digest {
    type Error = Vec<u8>;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let a: Box<[u8; Sha256::DIGEST_LEN]> = bytes.into_boxed_slice().try_into()?;
        Ok(Digest(*a))
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// A sorted, labeled rose tree whose leaves contain values of type `T`.
#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub enum LabeledTree<T> {
    /// A leaf node. Only `Leaf` nodes contain values.
    Leaf(T),
    /// Internal node with an arbitrary number of sorted, labeled children.
    SubTree(FlatMap<Label, LabeledTree<T>>),
}

impl<T> Default for LabeledTree<T> {
    fn default() -> Self {
        Self::SubTree(FlatMap::new())
    }
}

impl<T> Drop for LabeledTree<T> {
    fn drop(&mut self) {
        #[inline]
        fn take_if_subtree<T>(t: &mut LabeledTree<T>, to_drop: &mut Vec<LabeledTree<T>>) {
            match t {
                LabeledTree::Leaf(_) => {}
                LabeledTree::SubTree(children) => {
                    for (_, child) in std::mem::take(children) {
                        if matches!(child, LabeledTree::SubTree(_)) {
                            to_drop.push(child);
                        }
                    }
                }
            }
        }

        //  allocate a vector of a small constant size to not have many reallocations
        //  for small trees
        let mut to_drop = Vec::with_capacity(100);
        take_if_subtree(self, &mut to_drop);
        while let Some(ref mut t) = to_drop.pop() {
            take_if_subtree(t, &mut to_drop);
        }
    }
}

/// Descends into the subtree of `t` following the given `path`.
/// Returns the reference to the corresponding subtree.
pub fn lookup_path<'a>(
    t: &'a LabeledTree<Vec<u8>>,
    path: &[&[u8]],
) -> Option<&'a LabeledTree<Vec<u8>>> {
    let mut tref = t;
    for l in path.iter() {
        match tref {
            LabeledTree::Leaf(_) => return None,
            LabeledTree::SubTree(children) => {
                tref = children.get(&Label::from(l))?;
            }
        }
    }
    Some(tref)
}

/// A *binary* Merkle tree representation of a [`LabeledTree`].
///
/// A [`LabeledTree::Leaf`] is converted to a [`HashTree::Leaf`]. The value
/// contained in the former is hashed and the result is then stored as a
/// [`Digest`].
///
/// A [`LabeledTree::SubTree`] is converted into a binary tree of zero or more
/// binary [`HashTree::Fork`]s terminating in labeled, single-child
/// [`HashTree::Node`]s, with the left child always being a complete binary tree
/// (e.g. a [`LabeledTree::SubTree`] with 5 children maps to a
/// [`HashTree::Fork`] with a complete left subtree of 4 [`HashTree::Node`]
/// leaves and a right subtree consisting of a single [`HashTree::Node`]).
///
///
/// That is, a [`LabeledTree`] with labels `l_0` to `l_4`
/// ```text
///             (------------SubTree------------)
///             l_0 /  l_1 |  l_2 |  l_3 |  l_4 \
/// ```
///
/// is transformed to the following [`HashTree`]
///
/// ```text
///               (-----------Fork-----------)
///               /                          \
///            (--------Fork--------)       Node
///           /                     \     l_4 |
///         (--Fork--)          (--Fork--)
///        /          \        /          \
///    Node          Node   Node         Node
///  l_0 |         l_1 |  l_2 |        l_3 |
/// ```
///
/// The digest in a [`HashTree::Fork`] is computed over its children's digests.
/// The digest in a [`HashTree::Node`]s is computed over its label's digest and
/// the child's digest.
///
/// A [`HashTree`] can be obtained by feeding a [`LabeledTree`] to an
/// implementation of the [`HashTreeBuilder`] trait. The hash values contained
/// in the [`HashTree`] are not recomputed by altering the [`HashTree`].
#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub enum HashTree {
    /// An unlabeled leaf that is either the root or the child of a `Node`.
    Leaf { digest: Digest },
    /// The equivalent of a `LabeledTree` branch.
    Node {
        digest: Digest,
        label: Label,
        hash_tree: Box<HashTree>,
    },
    /// Unlabeled binary fork, used to represent a [`LabeledTree::SubTree`] with
    /// more than one child as a binary tree.
    Fork {
        digest: Digest,
        left_tree: Box<HashTree>,
        right_tree: Box<HashTree>,
    },
}

impl HashTree {
    /// Returns the digest of the tree, i.e. the digest of the tree's root node.
    /// Does not `panic!`.
    pub fn digest(&self) -> &Digest {
        match &self {
            HashTree::Leaf { digest } => digest,
            HashTree::Node { digest, .. } => digest,
            HashTree::Fork { digest, .. } => digest,
        }
    }
}

/// A self-sufficient proof of membership for some data in a [`HashTree`].
///
/// Whereas [`Witness`] requires the data-to-be-proved to be provided
/// externally, a [`MixedHashTree`] is sufficient to generate the root hash that
/// can be directly compared against the root hash of the [`HashTree`].
///
/// On a low level, the difference to [`Witness`] is twofold.
/// 1) A [`MixedHashTree::Leaf`] directly holds leaf values instead of plugging
///    them in to [`Witness::Known`] from external data.
/// 2) [`MixedHashTree::Empty`] marks empty subtrees with a constant hash.
///
/// A [`MixedHashTree`] contains the data requested by the call to
/// `read_certified_state` and digests for pruned parts of the hash tree.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum MixedHashTree {
    /// Empty subtree, which has a specific hash with a different domain separator.
    Empty,
    /// Corresponds to [`Witness::Fork`].
    Fork(Box<(MixedHashTree, MixedHashTree)>),
    /// Corresponds to [`Witness::Node`].
    Labeled(Label, Box<MixedHashTree>),
    /// Corresponds to [`LabeledTree::Leaf`] or, compared with the variants of
    /// [`Witness`], to a [`LabeledTree::Leaf`] plugged into [`Witness::Known`].
    Leaf(Vec<u8>),
    /// Corresponds to [`Witness::Pruned`].
    Pruned(Digest),
}

/// The result of a path lookup in a hash tree.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LookupStatus<'a> {
    /// The label exists in the tree.
    Found(&'a MixedHashTree),
    /// The tree contains a proof that the label does not exist.
    Absent,
    /// There is no way to tell whether the label is in the tree.
    Unknown,
}

impl LookupStatus<'_> {
    /// Returns true if the status is Found.
    pub fn is_found(&self) -> bool {
        matches!(self, Self::Found(_))
    }

    /// Returns true if the status is Absent.
    pub fn is_absent(&self) -> bool {
        self == &Self::Absent
    }

    /// Returns true if the status is Unknown.
    pub fn is_unknown(&self) -> bool {
        self == &Self::Unknown
    }
}

/// The result of [MixedHashTree::search_label] call.
enum SearchStatus<'a> {
    /// The label exists in the tree.
    Found(&'a MixedHashTree),
    /// The tree contains a proof that the label does not exist.
    Absent,
    /// There is no way to tell whether the label is in the tree.
    Unknown,
    /// The label is lexicographically less than all other labels in the tree.
    Lt,
    /// The label is lexicographically greater than all other labels in the tree.
    Gt,
}

impl MixedHashTree {
    /// Recomputes root hash of the full tree that this mixed tree was
    /// constructed from.
    pub fn digest(&self) -> Digest {
        #[derive(Debug)]
        enum StackItem<'a> {
            Expand(&'a MixedHashTree),
            Collect(&'a MixedHashTree),
        }

        impl<'a> StackItem<'a> {
            fn to_collect(&self) -> Self {
                match self {
                    Self::Expand(t) => Self::Collect(t),
                    Self::Collect(_) => panic!("expected Expand, got Collect"),
                }
            }
        }

        let mut stack: Vec<StackItem<'_>> = Vec::new();
        let mut digests: Vec<Digest> = Vec::new();

        stack.push(StackItem::Expand(self));

        while let Some(t) = stack.pop() {
            match t {
                StackItem::Expand(Self::Fork(lr)) => {
                    stack.push(t.to_collect());
                    stack.push(StackItem::Expand(&lr.1));
                    stack.push(StackItem::Expand(&lr.0));
                }
                StackItem::Expand(Self::Labeled(_, subtree)) => {
                    stack.push(t.to_collect());
                    stack.push(StackItem::Expand(subtree));
                }
                StackItem::Collect(Self::Fork(_)) => {
                    let right = digests.pop().expect("bug: missing right subtree digest");
                    let left = digests.pop().expect("bug: missing left subtree digest");
                    digests.push(tree_hash::compute_fork_digest(&left, &right));
                }
                StackItem::Collect(Self::Labeled(label, _)) => {
                    let subtree_digest = digests.pop().expect("bug: missing subtree digest");
                    let labeled_digest = tree_hash::compute_node_digest(label, &subtree_digest);
                    digests.push(labeled_digest);
                }
                StackItem::Collect(Self::Leaf(buf)) => {
                    digests.push(tree_hash::compute_leaf_digest(&buf[..]))
                }
                StackItem::Collect(Self::Pruned(digest)) => digests.push(digest.clone()),
                StackItem::Collect(Self::Empty) => digests.push(tree_hash::empty_subtree_hash()),
                t /* Expand of Leaf, Pruned or Empty */ => stack.push(t.to_collect()),
            }
        }

        assert_eq!(
            digests.len(),
            1,
            "bug: reduced tree to not exactly one digest: {digests:?}"
        );
        assert!(stack.is_empty(), "bug: stack is not empty: {stack:?}");

        digests[0].clone()
    }

    /// Finds a label in a hash tree.
    fn search_label<'a>(&'a self, label: &[u8]) -> SearchStatus<'a> {
        use std::cmp::Ordering;

        match self {
            Self::Empty => SearchStatus::Absent,
            Self::Leaf(_) => SearchStatus::Absent,
            Self::Fork(fork) => match fork.0.search_label(label) {
                SearchStatus::Unknown => {
                    // The left tree is probably pruned, let's look at the right tree.
                    match fork.1.search_label(label) {
                        SearchStatus::Lt => {
                            // The label is less than all the nodes in the right
                            // tree and we don't know what's in the left tree.
                            SearchStatus::Unknown
                        }
                        other => other,
                    }
                }
                SearchStatus::Gt => {
                    // The label is greater than all the labels in the left
                    // subtree, let's search the right subtree.
                    match fork.1.search_label(label) {
                        SearchStatus::Lt => SearchStatus::Absent,
                        other => other,
                    }
                }
                other => other,
            },
            Self::Labeled(l, t) => match label.cmp(l.as_bytes()) {
                Ordering::Equal => SearchStatus::Found(t),
                Ordering::Less => SearchStatus::Lt,
                Ordering::Greater => SearchStatus::Gt,
            },
            Self::Pruned(_) => SearchStatus::Unknown,
        }
    }

    /// Finds a tree node identified by the path.  This algorithm gives results
    /// similar to the `lookup_path` function in the public spec:
    /// https://internetcomputer.org/docs/current/references/ic-interface-spec/#lookup
    /// but does not allocate memory on the heap.
    ///
    /// This function is also more general the `lookup_path` function in the
    /// spec because it returns a subtree, not a leaf value.
    pub fn lookup<'a, L: AsRef<[u8]>>(&'a self, path: &[L]) -> LookupStatus<'a> {
        let mut t = self;
        for entry in path {
            t = match t.search_label(entry.as_ref()) {
                SearchStatus::Found(t) => t,
                SearchStatus::Absent | SearchStatus::Lt | SearchStatus::Gt => {
                    return LookupStatus::Absent
                }
                SearchStatus::Unknown => return LookupStatus::Unknown,
            }
        }
        LookupStatus::Found(t)
    }
}

/// An error indicating that a hash tree doesn't correspond to a valid
/// [`LabeledTree`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidHashTreeError {
    /// The hash tree contains a non-root leaf that is not a direct child of a
    /// labeled node. For example:
    ///
    /// ```text
    /// * - fork -- leaf X
    ///          \
    ///           ` leaf Y
    /// ```
    UnlabeledLeaf,

    /// Labels in the hash tree are not sorted.
    ///
    /// ```text
    /// * - fork -- labeled "b" -- leaf X
    ///          \
    ///           ` labeled "a" -- leaf Y
    /// ```
    LabelsNotSorted(Label),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MixedHashTreeConversionError {
    /// The hash tree contains a non-root leaf that is not a direct child of a
    /// labeled node.
    UnlabeledLeaf,
    /// Labels in the hash tree are not sorted.
    LabelsNotSorted(Label),
    /// The top-level node is a pruned.
    Pruned,
    /// Too deep recursion due to a too large tree depth
    TooDeepRecursion,
}

/// The maximum recursion depth of [`serde_cbor`] deserialization is currently 128.
const MAX_HASH_TREE_DEPTH: u8 = 128;
// error handling does not work if `MAX_HASH_TREE_DEPTH == u8::MAX`, since we
// cannot reach the error bound of `u8::MAX + 1` with `u8`
#[allow(clippy::assertions_on_constants)]
const _: () = assert!(MAX_HASH_TREE_DEPTH < u8::MAX);

/// Extracts the data part from a mixed hash tree by removing all forks and
/// pruned nodes.
impl TryFrom<MixedHashTree> for LabeledTree<Vec<u8>> {
    type Error = MixedHashTreeConversionError;

    fn try_from(root: MixedHashTree) -> Result<Self, Self::Error> {
        type E = MixedHashTreeConversionError;

        fn collect_children(
            t: MixedHashTree,
            children: &mut FlatMap<Label, LabeledTree<Vec<u8>>>,
            depth: u8,
        ) -> Result<(), E> {
            if depth > MAX_HASH_TREE_DEPTH {
                return Err(E::TooDeepRecursion);
            }
            match t {
                MixedHashTree::Leaf(_) => Err(E::UnlabeledLeaf),
                MixedHashTree::Labeled(label, subtree) => {
                    match try_from_impl(*subtree, depth) {
                        Ok(labeled_subtree) => children
                            .try_append(label, labeled_subtree)
                            .map_err(|(label, _)| E::LabelsNotSorted(label)),
                        // Pruned nodes with labels are commonly used for absence proofs.
                        Err(E::Pruned) => Ok(()),
                        Err(e) => Err(e),
                    }
                }
                MixedHashTree::Fork(lr) => match (
                    collect_children(lr.0, children, depth + 1),
                    collect_children(lr.1, children, depth + 1),
                ) {
                    // We can tolerate one of the children being pruned, but not
                    // both. This allows us to collapse weird trees like the one below:
                    //
                    // * - labeled L - fork --- pruned X
                    //                      \
                    //                       `- pruned Y
                    (Ok(()), Ok(())) => Ok(()),
                    (Ok(()), Err(E::Pruned)) => Ok(()),
                    (Err(E::Pruned), Ok(())) => Ok(()),
                    (Err(E::Pruned), Err(e)) => Err(e),
                    (Err(e), Err(E::Pruned)) => Err(e),
                    (Ok(()), e) => e,
                    (e, Ok(())) => e,
                    (e, _) => e,
                },
                MixedHashTree::Pruned(_) => Err(E::Pruned),
                MixedHashTree::Empty => Ok(()),
            }
        }

        fn try_from_impl(root: MixedHashTree, depth: u8) -> Result<LabeledTree<Vec<u8>>, E> {
            Ok(match root {
                MixedHashTree::Leaf(data) => LabeledTree::Leaf(data),
                MixedHashTree::Labeled(_, _) | MixedHashTree::Fork(_) => {
                    let mut children = FlatMap::new();
                    collect_children(root, &mut children, depth + 1)?;

                    LabeledTree::SubTree(children)
                }

                MixedHashTree::Pruned(_) => return Err(E::Pruned),
                MixedHashTree::Empty => LabeledTree::SubTree(Default::default()),
            })
        }

        try_from_impl(root, 0)
    }
}

impl Serialize for MixedHashTree {
    // Serialize a `MixedHashTree` per the CDDL of the public spec.
    // See https://internetcomputer.org/docs/current/references/ic-interface-spec#certification-encoding
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
    where
        S: Serializer,
    {
        match self {
            MixedHashTree::Empty => {
                let mut seq = serializer.serialize_seq(Some(1))?;
                seq.serialize_element(&0u8)?;
                seq.end()
            }
            MixedHashTree::Fork(tree) => {
                let mut seq = serializer.serialize_seq(Some(3))?;
                seq.serialize_element(&1u8)?;
                seq.serialize_element(&tree.0)?;
                seq.serialize_element(&tree.1)?;
                seq.end()
            }
            MixedHashTree::Labeled(label, tree) => {
                let mut seq = serializer.serialize_seq(Some(3))?;
                seq.serialize_element(&2u8)?;
                seq.serialize_element(Bytes::new(label.as_bytes()))?;
                seq.serialize_element(&tree)?;
                seq.end()
            }
            MixedHashTree::Leaf(leaf_bytes) => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element(&3u8)?;
                seq.serialize_element(Bytes::new(leaf_bytes))?;
                seq.end()
            }
            MixedHashTree::Pruned(digest) => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element(&4u8)?;
                seq.serialize_element(Bytes::new(digest.as_bytes()))?;
                seq.end()
            }
        }
    }
}

impl<'de> serde::de::Deserialize<'de> for MixedHashTree {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<MixedHashTree, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        use serde::de::{self, IgnoredAny, SeqAccess, Visitor};

        struct SeqVisitor;

        impl<'de> Visitor<'de> for SeqVisitor {
            type Value = MixedHashTree;

            #[inline]
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str(
                    "MixedHashTree encoded as a sequence of the form \
                     hash-tree ::= [0] | [1 hash-tree hash-tree] | [2 bytes hash-tree] | [3 bytes] | [4 hash]",
                )
            }

            #[inline]
            fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let tag: u8 = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;

                match tag {
                    0 => {
                        if let Some(IgnoredAny) = seq.next_element()? {
                            return Err(de::Error::invalid_length(2, &self));
                        }

                        Ok(MixedHashTree::Empty)
                    }
                    1 => {
                        let left: MixedHashTree = seq
                            .next_element()?
                            .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                        let right: MixedHashTree = seq
                            .next_element()?
                            .ok_or_else(|| de::Error::invalid_length(2, &self))?;

                        if let Some(IgnoredAny) = seq.next_element()? {
                            return Err(de::Error::invalid_length(4, &self));
                        }

                        Ok(MixedHashTree::Fork(Box::new((left, right))))
                    }
                    2 => {
                        let label: Label = seq
                            .next_element()?
                            .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                        let subtree: MixedHashTree = seq
                            .next_element()?
                            .ok_or_else(|| de::Error::invalid_length(2, &self))?;

                        if let Some(IgnoredAny) = seq.next_element()? {
                            return Err(de::Error::invalid_length(4, &self));
                        }

                        Ok(MixedHashTree::Labeled(label, Box::new(subtree)))
                    }
                    3 => {
                        let bytes: serde_bytes::ByteBuf = seq
                            .next_element()?
                            .ok_or_else(|| de::Error::invalid_length(1, &self))?;

                        if let Some(IgnoredAny) = seq.next_element()? {
                            return Err(de::Error::invalid_length(3, &self));
                        }

                        Ok(MixedHashTree::Leaf(bytes.into_vec()))
                    }
                    4 => {
                        let digest_bytes: serde_bytes::ByteBuf = seq
                            .next_element()?
                            .ok_or_else(|| de::Error::invalid_length(1, &self))?;

                        if let Some(IgnoredAny) = seq.next_element()? {
                            return Err(de::Error::invalid_length(3, &self));
                        }

                        let digest = Digest::try_from(digest_bytes.into_vec()).map_err(|err| {
                            de::Error::invalid_length(err.len(), &"Expected digest blob")
                        })?;

                        Ok(MixedHashTree::Pruned(digest))
                    }
                    _ => Err(de::Error::custom(format!(
                        "unknown tag: {}, expected the tag to be one of {{0, 1, 2, 3, 4}}",
                        tag
                    ))),
                }
            }
        }

        deserializer.deserialize_seq(SeqVisitor)
    }
}

/// Errors occurring in `tree_hash` module.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum TreeHashError {
    InconsistentPartialTree {
        offending_path: Vec<Label>,
    },
    InvalidArgument {
        info: String,
    },
    NonMinimalWitness {
        offending_path: Vec<Label>,
    },
    /// Results from a too deep tree and/or witness passed to a recursive
    /// algorithm such as `prune_witness`, resulting in a total recursion
    /// depth > [`PRUNE_WITNESS_RECURSION_LIMIT`]
    TooDeepRecursion {
        offending_path: Vec<Label>,
    },
}

/// A subset of a [`HashTree`] that is used to verify whether some specific
/// partial data is consistent with the original data (for which the
/// [`HashTree`] was computed). Effectively [`Witness`] is a [`HashTree`] with
/// some missing leaves, which have to be provided externally, e.g., by the
/// caller, in order to produce the root hash, which can then be compared
/// against the root hash of the full [`HashTree`]. The leaves that need to be
/// externally provided in the [`Witness`] are marked as [`Witness::Known`].
/// Also, since not necessarily all leaves in the [`HashTree`] are relevant to
/// the partial data, the irrelevant data is provided in form of a hash of the
/// root of the irrelevant subtrees as [`Witness::Pruned`]. Also, a [`Witness`]
/// includes no digests for either the partial data it verifies or for the
/// [`HashTree`] root.
///
/// A witness can also be used to update a [`HashTree`] when part of the
/// original data is updated.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub enum Witness {
    /// Represents a [`HashTree::Fork`].
    Fork {
        left_tree: Box<Witness>,
        right_tree: Box<Witness>,
    },

    /// Represents a [`HashTree::Node`].
    Node {
        label: Label,
        sub_witness: Box<Witness>,
    },

    /// Represents a pruned subtree, i.e., the root hash of a path irrelevant to
    /// the path to [`Witness::Known`].
    Pruned { digest: Digest },

    /// A marker for data (leaf or a subtree) to be explicitly provided
    /// by the caller for verification or for re-computation of a digest.
    Known(),
}

fn write_witness(witness: &Witness, level: u8, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let indent = String::from_utf8(vec![b' '; (level.saturating_mul(8)) as usize])
        .expect("String was not valid utf8");
    match witness {
        Witness::Known() => writeln!(f, "{}** KNOWN **", indent),
        Witness::Pruned { digest } => writeln!(f, "{}\\__pruned:{:?}", indent, digest),
        Witness::Node { label, sub_witness } => {
            writeln!(f, "{}+-- node:{:?}", indent, label)?;
            write_witness(sub_witness, level.saturating_add(1), f)
        }
        Witness::Fork {
            left_tree,
            right_tree,
        } => {
            writeln!(f, "{}+-- fork:", indent)?;
            write_witness(left_tree, level.saturating_add(1), f)?;
            write_witness(right_tree, level.saturating_add(1), f)
        }
    }
}

impl fmt::Debug for Witness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_witness(self, 0, f)
    }
}

/// `WitnessGenerator` is a container for a `HashTree` that offers access
/// to the contained tree,  and also provides operations related to the tree,
/// like for example the computation of `Witness`-objects.
pub trait WitnessGenerator {
    /// Returns the tree contained in this box.
    ///
    /// Does not `panic!`.
    fn hash_tree(&self) -> &HashTree;

    /// Computes and returns a witness for the paths specified `partial_tree`.
    /// All paths in `partial_tree` must end either with a `Leaf`-node or with
    /// an empty `SubTree`-node which in the original tree is also empty.
    /// If 'partial_tree' is inconsistent with the `HashTree` of this object,
    /// an error is returned.
    ///
    /// Does not `panic!`.
    fn witness(
        &self,
        partial_tree: &LabeledTree<Vec<u8>>,
    ) -> Result<Witness, WitnessGenerationError<Witness>>;

    fn mixed_hash_tree(
        &self,
        partial_tree: &LabeledTree<Vec<u8>>,
    ) -> Result<MixedHashTree, WitnessGenerationError<MixedHashTree>>;
}

/// Error produced by generating a witness of type `W` from [`WitnessGenerator`].
#[derive(thiserror::Error, Debug, PartialEq, Clone)]
pub enum WitnessGenerationError<W: WitnessBuilder> {
    #[error("Generating a witness failed due to too deep recursion (depth={0})")]
    TooDeepRecursion(u8),
    #[error("Merging witnesses failed due to their inconsistency at:\nleft={0:?}\nright={1:?}")]
    MergingInconsistentWitnesses(W, W),
}

/// `HashTreeBuilder` enables an iterative construction of a [`LabeledTree`],
/// which can also be accessed in form of a [`HashTree`].
/// The constructed [`LabeledTree`] is a part of the state of the Builder,
/// and is built successively by adding leaves and subtrees.
/// During the construction, the builder maintains an auxiliary state
/// that describes the current position in the [`LabeledTree`] under
/// construction. The auxiliary state is a list of nodes that corresponds to the
/// path in the tree from the root to the current node being constructed.
/// An example code to build the following labeled tree with a sub-tree and
/// three leaves:
///
/// ```text
///             root
///             /  \
///            /    \
///      label_A    label_B
///         /         \
///        /           \
///     "node A"       /\
///                   /  \
///                  /    \
///             label_C   label_D
///                /        \
///               /          \
///           "node C"     "node D is longer"
/// ```
///
/// ```ignore
/// let builder = HashTreeBuilderImpl::new();
///
/// builder.start_subtree(); // start root
///
/// builder.new_edge("label_A");
/// builder.start_leaf();
/// builder.write_leaf("node A");
/// builder.finish_leaf();
///
/// builder.new_edge("label_B");
///
/// builder.start_subtree(); // start subtree (C, D)
///
/// builder.new_edge("label_C");
/// builder.start_leaf();
/// builder.write_leaf("node C");
/// builder.finish_leaf();
///
/// builder.new_edge("label_D");
/// builder.start_leaf();
/// builder.write_leaf("node D");
/// builder.write_leaf(" is longer");
/// builder.finish_leaf();
///
/// builder.finish_subtree(); // end subtree (C, D)
/// builder.finish_subtree(); // end root
/// ```
pub trait HashTreeBuilder {
    type WitnessGenerator;

    /// Starts a new leaf at the current position in the tree.
    /// Does not change the current position in the tree.
    ///
    /// # Panics
    /// `panics!` if the current position is not an `Undefined`-node,
    /// i.e. if this builder is not in the initial state,
    /// or if the previous call was not `new_edge()`.
    fn start_leaf(&mut self);

    /// Adds bytes to the content of the current leaf.
    /// Does not change the current position in the tree.
    ///
    /// # Panics
    /// `panics!` if the current position is not a `Leaf`-node,
    /// i.e. if the previous call was neither `start_leaf()`,
    /// nor `write_leaf()`.
    fn write_leaf<T: AsRef<[u8]>>(&mut self, bytes: T);

    /// Finishes the current leaf.  Changes the current position
    /// in the tree to the parent of the finished leaf (if any).
    ///
    /// # Panics
    /// `panics!` if the current position is not a `Leaf`-node,
    /// i.e. if the previous call was neither `start_leaf()`,
    /// nor `write_leaf()`.
    fn finish_leaf(&mut self);

    /// Starts a new subtree at the current position in the tree.
    /// Does not change the current position in the tree.
    ///
    /// # Panics
    /// `panics!` if the current position is not an `Undefined`-node,
    /// i.e. if this builder is not in the initial state,
    /// or if the previous call was not `new_edge()`.
    fn start_subtree(&mut self);

    /// Adds a new edge to the current subtree, and creates a new
    /// `Undefined`-node, to which the new edge leads.
    /// Changes the current position to the newly created node.
    ///
    /// # Panics
    /// * `panics!` if the current position is not a `SubTree`-node, i.e. if the
    ///   previous call was neither `start_subtree()`, nor one of
    ///   `finish_leaf()` or `finish_subtree()` that updated the current
    ///   position to a parent that is a `SubTree`-node.
    /// * `panics!` if the current `SubTree`-node contains already an edge with
    ///   the specified label.
    fn new_edge<T: Into<Label>>(&mut self, label: T);

    /// Finishes the current subtree.  Changes the current position
    /// in the tree to the parent of the finished subtree (if any).
    ///
    /// # Panics
    /// `panics!` if the current position is not a `SubTree`-node,
    /// i.e. if the previous call was neither `start_subtree()`,
    /// nor one of `finish_leaf()` or `finish_subtree()` that updated
    /// the current position to a parent that is a `SubTree`-node.
    fn finish_subtree(&mut self);

    /// Returns a `WitnessGenerator` for the constructed tree
    /// if the construction is complete, and `None` otherwise.
    ///
    /// Does not `panic!`.
    fn witness_generator(&self) -> Option<Self::WitnessGenerator>;
}
