#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]

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

#[cfg(test)]
pub(crate) mod arbitrary;
#[cfg(test)]
mod conversion_tests;
#[cfg(test)]
mod encoding_tests;
#[cfg(test)]
mod merge_tests;

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
/// `Path::from_iter(iterator)`.
// Implemented as a newtype to allow implementation of traits like
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
    /// Label of size SMALL_LABEL_SIZE or longer.
    Ref(Vec<u8>),
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
        self.as_bytes().partial_cmp(rhs.as_bytes())
    }
}

impl Label {
    pub fn as_bytes(&self) -> &[u8] {
        match &self.0 {
            LabelRepr::Value(bytes) => &bytes[1..=bytes[0] as usize],
            LabelRepr::Ref(v) => &v[..],
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

impl fmt::Debug for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn printable(byte: u8) -> bool {
            (32..127).contains(&byte)
        }
        let bytes = self.as_bytes();
        if bytes.iter().all(|b| printable(*b)) {
            write!(
                f,
                "{}",
                std::str::from_utf8(bytes).expect("Failed to convert to utf8")
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
        Self::from(val.to_vec())
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
            Self(LabelRepr::Value(buf))
        } else {
            Self(LabelRepr::Ref(slice.to_vec()))
        }
    }
}

/// The computed hash of the data in a `Leaf`; or of a [`LabeledTree`].
#[derive(PartialEq, Eq, Clone)]
pub struct Digest(pub [u8; 32]);
ic_crypto_internal_types::derive_serde!(Digest, 32);

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

impl From<[u8; 32]> for Digest {
    fn from(bytes: [u8; 32]) -> Self {
        Digest(bytes)
    }
}

impl TryFrom<Vec<u8>> for Digest {
    type Error = Vec<u8>;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let a: Box<[u8; 32]> = bytes.into_boxed_slice().try_into()?;
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

/// A binary tree representation of a [`LabeledTree`], with [`Digest`] leaves.
///
/// A `LabeledTree::SubTree` is converted into a binary tree of zero or more
/// `HashTree::Forks` terminating in labeled `HashTree::Nodes`, with the left
/// child always a complete binary tree (e.g. a `SubTree` with 5 children maps
/// to a `Fork` with a complete left subtree of 4 `Node` leaves and a right
/// subtree consisting of a single `Node`).
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
    /// Unlabeled binary fork, used to represent a `LabeledTree::SubTree` with
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

    /// Returns the left sub-tree of the tree, assuming the tree is
    /// `HashTree::Fork`. panic!s if the tree is not a fork.
    pub fn left_tree(&self) -> &HashTree {
        match &self {
            HashTree::Fork { left_tree, .. } => left_tree,
            _ => panic!("Not a fork: {:?}", self),
        }
    }

    /// Returns the right sub-tree of the tree, assuming the tree is
    /// `HashTree::Fork`. panic!s if the tree is not a fork.
    pub fn right_tree(&self) -> &HashTree {
        match &self {
            HashTree::Fork { right_tree, .. } => right_tree,
            _ => panic!("Not a fork: {:?}", self),
        }
    }

    /// Returns the contained `hash_tree` of the tree, assuming the tree is
    /// `HashTree::Node`. panic!s if the tree is not `HashTree::Node`.
    pub fn node_tree(&self) -> &HashTree {
        match &self {
            HashTree::Node { hash_tree, .. } => hash_tree,
            _ => panic!("Not a node: {:?}", self),
        }
    }

    /// Returns the label of the tree, assuming the tree is `HashTree::Node`.
    /// panic!s if the tree is not `HashTree::Node`.
    pub fn label(&self) -> &Label {
        match &self {
            HashTree::Node { label, .. } => label,
            _ => panic!("Not a node: {:?}", self),
        }
    }
}

/// A hash tree that contains the data requested by the call to
/// `read_certified_state` and digests for pruned parts of the hash tree.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum MixedHashTree {
    Empty,
    Fork(Box<(MixedHashTree, MixedHashTree)>),
    Labeled(Label, Box<MixedHashTree>),
    Leaf(Vec<u8>),
    Pruned(Digest),
}

impl MixedHashTree {
    /// Recomputes root hash of the full tree that this mixed tree was
    /// constructed from.
    pub fn digest(&self) -> Digest {
        match self {
            Self::Empty => tree_hash::empty_subtree_hash(),
            Self::Fork(lr) => tree_hash::compute_fork_digest(&lr.0.digest(), &lr.1.digest()),
            Self::Labeled(label, subtree) => {
                tree_hash::compute_node_digest(label, &subtree.digest())
            }
            Self::Leaf(buf) => tree_hash::compute_leaf_digest(&buf[..]),
            Self::Pruned(digest) => digest.clone(),
        }
    }

    /// Merges two trees into a tree that combines the data parts of both inputs
    /// and has the same root hash.
    ///
    /// Precondition: lhs.digest() == rhs.digest()
    ///
    /// Postconditions:
    ///
    /// ```text
    ///     merge(lhs, rhs).digest() == lhs.digest() == rhs.digest()
    ///
    ///     ∀ p  Ok(v) = lookup(lhs, p) ⇒ lookup(merge(lhs, rhs), p) == Ok(v)
    ///        ∧ Ok(v) = lookup(rhs, p) ⇒ lookup(merge(lhs, rhs), p) == Ok(v)
    /// ```
    ///
    /// # Panics
    ///
    /// This function panics if the precondition is not met.
    pub fn merge(lhs: Self, rhs: Self) -> Self {
        use MixedHashTree::*;

        match (lhs, rhs) {
            (Pruned(l), Pruned(r)) if l == r => Pruned(l),
            (Pruned(_), r) => r,
            (l, Pruned(_)) => l,
            (Empty, Empty) => Empty,
            (Fork(l), Fork(r)) => Fork(Box::new((Self::merge(l.0, r.0), Self::merge(l.1, r.1)))),
            (Labeled(label, l), Labeled(rlabel, r)) if label == rlabel => {
                Labeled(label, Box::new(Self::merge(*l, *r)))
            }
            (Leaf(l), Leaf(r)) if l == r => Leaf(l),
            (l, r) => panic!("inconsistent trees: {:#?}, {:#?}", l, r),
        }
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

/// Extracts the data part from a mixed hash tree by removing all forks and
/// pruned nodes.
impl TryFrom<MixedHashTree> for LabeledTree<Vec<u8>> {
    type Error = InvalidHashTreeError;

    fn try_from(root: MixedHashTree) -> Result<Self, InvalidHashTreeError> {
        fn collect_children(
            t: MixedHashTree,
            children: &mut FlatMap<Label, LabeledTree<Vec<u8>>>,
        ) -> Result<(), InvalidHashTreeError> {
            match t {
                MixedHashTree::Leaf(_) => Err(InvalidHashTreeError::UnlabeledLeaf),
                MixedHashTree::Labeled(label, subtree) => {
                    children
                        .try_append(label, (*subtree).try_into()?)
                        .map_err(|(label, _)| InvalidHashTreeError::LabelsNotSorted(label))?;
                    Ok(())
                }
                MixedHashTree::Fork(lr) => {
                    collect_children(lr.0, children)?;
                    collect_children(lr.1, children)
                }
                MixedHashTree::Pruned(_) | MixedHashTree::Empty => Ok(()),
            }
        }

        Ok(match root {
            MixedHashTree::Leaf(data) => LabeledTree::Leaf(data),
            MixedHashTree::Labeled(_, _) | MixedHashTree::Fork(_) => {
                let mut children = FlatMap::new();
                collect_children(root, &mut children)?;

                LabeledTree::SubTree(children)
            }
            MixedHashTree::Pruned(_) | MixedHashTree::Empty => {
                LabeledTree::SubTree(Default::default())
            }
        })
    }
}

impl Serialize for MixedHashTree {
    // Serialize a `MixedHashTree` per the CDDL of the public spec.
    // See https://sdk.dfinity.org/docs/interface-spec/index.html#_encoding_of_certificates
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
    fn deserialize<D>(deserializer: D) -> Result<MixedHashTree, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        use serde::de::{self, IgnoredAny, SeqAccess, Visitor};

        struct SeqVisitor;

        impl<'de> Visitor<'de> for SeqVisitor {
            type Value = MixedHashTree;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str(
                    "MixedHashTree encoded as a sequence of the form \
                     hash-tree ::= [0] | [1 hash-tree hash-tree] | [2 bytes hash-tree] | [3 bytes] | [4 hash]",
                )
            }

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
    InconsistentPartialTree { offending_path: Vec<Label> },
    InvalidArgument { info: String },
}

/// A subset of a [`HashTree`] that is sufficient to verify whether some
/// specific partial data is consistent with the original data (for which the
/// [`HashTree`] was computed). In particular a [`Witness`] includes no digests
/// for the partial data it verifies; nor for the [`HashTree`] root.
///
/// A witness can also be used to update a HashTree when part of the original
/// data is updated.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub enum Witness {
    // Represents a HashTree::Fork
    Fork {
        left_tree: Box<Witness>,
        right_tree: Box<Witness>,
    },
    // Represents a HashTree::Node
    Node {
        label: Label,
        sub_witness: Box<Witness>,
    },
    // Represents either a HashTree::Leaf or a pruned subtree of a HashTree
    Pruned {
        digest: Digest,
    },

    // A marker for data (leaf or a subtree) to be explicitly provided
    // by the caller for verification or for re-computation of a digest.
    Known(),
}

impl Witness {
    /// Merges two witnesses produced from the same tree.
    ///
    /// Precondition:
    ///
    /// ```text
    ///     ∃ t : Ok(h) = recompute_digest(lhs, t)
    ///         ∧ Ok(h) = recompute_digest(rhs, t)
    /// ```
    ///
    /// Postcondition:
    ///
    /// ```text
    ///     ∀ t : Ok(h) = recompute_digest(lhs, t)
    ///         ∧ Ok(h) = recompute_digest(rhs, t)
    ///         ⇒ recompute_digest(merge(lhs, rhs)) == Ok(h)
    /// ```
    ///
    /// # Panics
    ///
    /// This function panics if the precondition is not met.
    pub fn merge(lhs: Self, rhs: Self) -> Self {
        use Witness::*;

        match (lhs, rhs) {
            (Pruned { .. }, r) => r,
            (l, Pruned { .. }) => l,
            (Known(), Known()) => Known(),
            (
                Fork {
                    left_tree: ll,
                    right_tree: lr,
                },
                Fork {
                    left_tree: rl,
                    right_tree: rr,
                },
            ) => Fork {
                left_tree: Box::new(Self::merge(*ll, *rl)),
                right_tree: Box::new(Self::merge(*lr, *rr)),
            },
            (
                Node {
                    label,
                    sub_witness: lw,
                },
                Node {
                    sub_witness: rw, ..
                },
            ) => Node {
                label,
                sub_witness: Box::new(Self::merge(*lw, *rw)),
            },
            (l, r) => panic!("inconsistent witnesses: {:#?}, {:#?}", l, r),
        }
    }
}

fn write_witness(witness: &Witness, level: u8, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let indent =
        String::from_utf8(vec![b' '; (level * 8) as usize]).expect("String was not valid utf8");
    match witness {
        Witness::Known() => writeln!(f, "{}** KNOWN **", indent),
        Witness::Pruned { digest } => writeln!(f, "{}\\__pruned:{:?}", indent, digest),
        Witness::Node { label, sub_witness } => {
            writeln!(f, "{}+-- node:{:?}", indent, label)?;
            write_witness(sub_witness, level + 1, f)
        }
        Witness::Fork {
            left_tree,
            right_tree,
        } => {
            writeln!(f, "{}+-- fork:", indent)?;
            write_witness(left_tree, level + 1, f)?;
            write_witness(right_tree, level + 1, f)
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
    fn witness(&self, partial_tree: &LabeledTree<Vec<u8>>) -> Result<Witness, TreeHashError>;

    fn mixed_hash_tree(
        &self,
        partial_tree: &LabeledTree<Vec<u8>>,
    ) -> Result<MixedHashTree, TreeHashError>;
}

/// `HashTreeBuilder` enables an iterative construction of a [`LabeledTree`],
/// which can also be accessed in form of a [`HashTree`].
/// The constructed [`LabeledTree`] is a part of the state of the Builder,
/// and is build successively by adding leaves and subtrees.
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
