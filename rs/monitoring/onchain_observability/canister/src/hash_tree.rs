use sha2::Digest;
use std::borrow::Cow;

/// Sha256 Digest: 32 bytes
pub type Sha256Digest = [u8; 32];

#[derive(Clone, Hash, Ord, PartialOrd, Eq, PartialEq, serde::Deserialize)]
#[serde(from = "&serde_bytes::Bytes")]
#[serde(into = "&serde_bytes::ByteBuf")]
/// For labeled [HashTreeNode]
pub struct Label(Vec<u8>);

impl Label {
    /// Returns this label as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<Label> for serde_bytes::ByteBuf {
    fn from(label: Label) -> serde_bytes::ByteBuf {
        serde_bytes::ByteBuf::from(label.as_bytes().to_vec())
    }
}

impl<T> From<T> for Label
where
    T: AsRef<[u8]>,
{
    fn from(s: T) -> Self {
        Self(s.as_ref().to_owned())
    }
}

impl std::fmt::Display for Label {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use std::fmt::Write;

        // Try to print it as an UTF-8 string. If an error happens, print the bytes
        // as hexadecimal.
        match std::str::from_utf8(self.as_bytes()) {
            Ok(s) if s.chars().all(|c| c.is_ascii_graphic()) => {
                f.write_char('"')?;
                f.write_str(s)?;
                f.write_char('"')
            }
            _ => {
                write!(f, "0x")?;
                std::fmt::Debug::fmt(self, f)
            }
        }
    }
}

impl std::fmt::Debug for Label {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_bytes()
            .iter()
            .try_for_each(|b| write!(f, "{:02X}", b))
    }
}

impl serde::Serialize for Label {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            format!("{:?}", self).serialize(serializer)
        } else {
            serializer.serialize_bytes(self.0.as_ref())
        }
    }
}

/// A result of looking up for a certificate.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum LookupResult<'tree> {
    /// The value is guaranteed to be absent in the original state tree.
    Absent,

    /// This partial view does not include information about this path, and the original
    /// tree may or may note include this value.
    Unknown,

    /// The value was found at the referenced node.
    Found(&'tree [u8]),

    /// The path does not make sense for this certificate.
    Error,
}

/// A HashTree representing a full tree.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HashTree<'a> {
    root: HashTreeNode<'a>,
}

#[allow(dead_code)]
impl<'a> HashTree<'a> {
    /// Recomputes root hash of the full tree that this hash tree was constructed from.
    #[inline]
    pub fn digest(&self) -> Sha256Digest {
        self.root.digest()
    }

    /// Given a (verified) tree, the client can fetch the value at a given path, which is a
    /// sequence of labels (blobs).
    pub fn lookup_path<'p, P>(&self, path: P) -> LookupResult<'_>
    where
        P: IntoIterator<Item = &'p Label>,
    {
        self.root.lookup_path(&mut path.into_iter())
    }

    /// List all paths in the [HashTree]
    pub fn list_paths(&self) -> Vec<Vec<Label>> {
        self.root.list_paths(&vec![])
    }
}

impl<'a> AsRef<HashTreeNode<'a>> for HashTree<'a> {
    fn as_ref(&self) -> &HashTreeNode<'a> {
        &self.root
    }
}

impl<'a> From<HashTree<'a>> for HashTreeNode<'a> {
    fn from(tree: HashTree<'a>) -> HashTreeNode<'a> {
        tree.root
    }
}

impl serde::Serialize for HashTree<'_> {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> Result<<S as serde::Serializer>::Ok, <S as serde::Serializer>::Error>
    where
        S: serde::Serializer,
    {
        self.root.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for HashTree<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(HashTree {
            root: HashTreeNode::deserialize(deserializer)?,
        })
    }
}

/// Private type for label lookup result.
#[derive(Debug)]
enum LookupLabelResult<'node> {
    /// The label is not part of this node's tree.
    Absent,

    /// Same as absent, but some leaves were pruned and so it's impossible to know.
    Unknown,

    /// The label was not found, but could still be to the left.
    Less,

    /// The label was not found, but could still be to the right.
    Greater,

    /// The label was found. Contains a reference to the [HashTreeNode].
    Found(&'node HashTreeNode<'node>),
}

/// A Node in the HashTree.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum HashTreeNode<'a> {
    Empty(),
    Fork(Box<(HashTreeNode<'a>, HashTreeNode<'a>)>),
    Labeled(Cow<'a, Label>, Box<HashTreeNode<'a>>),
    Leaf(Cow<'a, [u8]>),
    Pruned(Sha256Digest),
}

impl std::fmt::Debug for HashTreeNode<'_> {
    // Shows a nicer view to debug than the default debugger.
    // Example:
    //
    // ```
    // HashTree {
    //     root: Fork(
    //         Fork(
    //             Label("a", Fork(
    //                 Pruned(1b4feff9bef8131788b0c9dc6dbad6e81e524249c879e9f10f71ce3749f5a638),
    //                 Label("y", Leaf("world")),
    //             )),
    //             Label("b", Pruned(7b32ac0c6ba8ce35ac82c255fc7906f7fc130dab2a090f80fe12f9c2cae83ba6)),
    //         ),
    //         Fork(
    //             Pruned(ec8324b8a1f1ac16bd2e806edba78006479c9877fed4eb464a25485465af601d),
    //             Label("d", Leaf("morning")),
    //         ),
    //     ),
    // }
    // ```
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fn readable_print(f: &mut std::fmt::Formatter<'_>, v: &[u8]) -> std::fmt::Result {
            // If it's UTF-8 and all the characters are graphic ASCII, then show as a string.
            // If it's short, show hex.
            // Otherwise, show length.
            match std::str::from_utf8(v) {
                Ok(s) if s.chars().all(|c| c.is_ascii_graphic()) => {
                    f.write_str("\"")?;
                    f.write_str(s)?;
                    f.write_str("\"")
                }
                _ if v.len() <= 32 => {
                    f.write_str("0x")?;
                    f.write_str(&hex::encode(v))
                }
                _ => {
                    write!(f, "{} bytes", v.len())
                }
            }
        }

        match self {
            HashTreeNode::Empty() => f.write_str("Empty"),
            HashTreeNode::Fork(nodes) => f
                .debug_tuple("Fork")
                .field(&nodes.0)
                .field(&nodes.1)
                .finish(),
            HashTreeNode::Leaf(v) => {
                f.write_str("Leaf(")?;
                readable_print(f, v)?;
                f.write_str(")")
            }
            HashTreeNode::Labeled(l, node) => {
                f.write_str("Label(")?;
                readable_print(f, l.as_bytes())?;
                f.write_str(", ")?;
                node.fmt(f)?;
                f.write_str(")")
            }
            HashTreeNode::Pruned(digest) => write!(f, "Pruned({})", hex::encode(digest.as_ref())),
        }
    }
}

impl<'a> HashTreeNode<'a> {
    /// Update a hasher with the domain separator (byte(|s|) . s).
    #[inline]
    fn domain_sep(&self, hasher: &mut sha2::Sha256) {
        let domain_sep = match self {
            HashTreeNode::Empty() => "ic-hashtree-empty",
            HashTreeNode::Fork(_) => "ic-hashtree-fork",
            HashTreeNode::Labeled(_, _) => "ic-hashtree-labeled",
            HashTreeNode::Leaf(_) => "ic-hashtree-leaf",
            HashTreeNode::Pruned(_) => return,
        };
        hasher.update([domain_sep.len() as u8]);
        hasher.update(domain_sep.as_bytes());
    }

    /// Calculate the digest of this node only.
    #[inline]
    pub fn digest(&self) -> Sha256Digest {
        let mut hasher = sha2::Sha256::new();
        self.domain_sep(&mut hasher);

        match self {
            HashTreeNode::Empty() => {}
            HashTreeNode::Fork(nodes) => {
                hasher.update(nodes.0.digest());
                hasher.update(nodes.1.digest());
            }
            HashTreeNode::Labeled(label, node) => {
                hasher.update(label.as_bytes());
                hasher.update(node.digest());
            }
            HashTreeNode::Leaf(bytes) => {
                hasher.update(bytes);
            }
            HashTreeNode::Pruned(digest) => {
                return *digest;
            }
        }

        hasher.finalize().into()
    }

    /// Lookup a single label, returning a reference to the labeled [HashTreeNode] node if found.
    ///
    /// This assumes a sorted hash tree, which is what the spec says the system should
    /// return. It will stop when it finds a label that's greater than the one being looked
    /// for.
    ///
    /// This function is implemented with flattening in mind, ie. flattening the forks
    /// is not necessary.
    fn lookup_label(&self, label: &Label) -> LookupLabelResult {
        match self {
            // If this node is a labeled node, check for the name.
            HashTreeNode::Labeled(l, node) => match label.cmp(l) {
                std::cmp::Ordering::Greater => LookupLabelResult::Greater,
                std::cmp::Ordering::Equal => LookupLabelResult::Found(node.as_ref()),
                // If this node has a smaller label than the one we're looking for, shortcut
                // out of this search (sorted tree), we looked too far.
                std::cmp::Ordering::Less => LookupLabelResult::Less,
            },
            HashTreeNode::Fork(nodes) => {
                let left_label = nodes.0.lookup_label(label);
                match left_label {
                    // On greater or unknown, look on the right side of the fork.
                    LookupLabelResult::Greater => {
                        let right_label = nodes.1.lookup_label(label);
                        match right_label {
                            LookupLabelResult::Less => LookupLabelResult::Absent,
                            result => result,
                        }
                    }
                    LookupLabelResult::Unknown => {
                        let right_label = nodes.1.lookup_label(label);
                        match right_label {
                            LookupLabelResult::Less => LookupLabelResult::Unknown,
                            result => result,
                        }
                    }
                    result => result,
                }
            }
            HashTreeNode::Pruned(_) => LookupLabelResult::Unknown,
            // Any other type of node and we need to look for more forks.
            _ => LookupLabelResult::Absent,
        }
    }

    /// Lookup the path for the current node only. If the node does not contain the label,
    /// this will return [None], signifying that whatever process is recursively walking the
    /// tree should continue with siblings of this node (if possible). If it returns
    /// [Some] value, then it found an actual result and this may be propagated to the
    /// original process doing the lookup.
    ///
    /// This assumes a sorted hash tree, which is what the spec says the system should return.
    /// It will stop when it finds a label that's greater than the one being looked for.
    fn lookup_path(&self, path: &mut dyn Iterator<Item = &Label>) -> LookupResult<'_> {
        use HashTreeNode::*;
        use LookupLabelResult as LLR;
        use LookupResult::*;

        match (path.next().map(|segment| self.lookup_label(segment)), self) {
            (Some(LLR::Found(node)), _) => node.lookup_path(path),
            (None, Leaf(v)) => Found(v.as_ref()),

            (None, Empty()) => Absent,
            (None, Pruned(_)) => Unknown,
            (None, Labeled(_, _) | Fork(_)) => Error,

            (Some(LLR::Unknown), _) => Unknown,
            (Some(LLR::Absent | LLR::Greater | LLR::Less), _) => Absent,
        }
    }

    fn list_paths(&self, path: &Vec<Label>) -> Vec<Vec<Label>> {
        match self {
            HashTreeNode::Empty() => vec![],
            HashTreeNode::Fork(nodes) => {
                [nodes.0.list_paths(path), nodes.1.list_paths(path)].concat()
            }
            HashTreeNode::Leaf(_) => vec![path.clone()],
            HashTreeNode::Labeled(l, node) => {
                let mut path = path.clone();
                path.push(l.clone().into_owned());
                node.list_paths(&path)
            }
            HashTreeNode::Pruned(_) => vec![],
        }
    }
}

impl serde::Serialize for HashTreeNode<'_> {
    // Serialize a `MixedHashTree` per the CDDL of the public spec.
    // See https://docs.dfinity.systems/public/certificates.cddl
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> Result<<S as serde::Serializer>::Ok, <S as serde::Serializer>::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeSeq;
        use serde_bytes::Bytes;

        match self {
            HashTreeNode::Empty() => {
                let mut seq = serializer.serialize_seq(Some(1))?;
                seq.serialize_element(&0u8)?;
                seq.end()
            }
            HashTreeNode::Fork(tree) => {
                let mut seq = serializer.serialize_seq(Some(3))?;
                seq.serialize_element(&1u8)?;
                seq.serialize_element(&tree.0)?;
                seq.serialize_element(&tree.1)?;
                seq.end()
            }
            HashTreeNode::Labeled(label, tree) => {
                let mut seq = serializer.serialize_seq(Some(3))?;
                seq.serialize_element(&2u8)?;
                seq.serialize_element(Bytes::new(label.as_bytes()))?;
                seq.serialize_element(&tree)?;
                seq.end()
            }
            HashTreeNode::Leaf(leaf_bytes) => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element(&3u8)?;
                seq.serialize_element(Bytes::new(leaf_bytes))?;
                seq.end()
            }
            HashTreeNode::Pruned(digest) => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element(&4u8)?;
                seq.serialize_element(Bytes::new(digest))?;
                seq.end()
            }
        }
    }
}

impl<'de, 'tree: 'de> serde::Deserialize<'de> for HashTreeNode<'tree> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de;

        struct SeqVisitor;

        impl<'de> de::Visitor<'de> for SeqVisitor {
            type Value = HashTreeNode<'static>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str(
                    "HashTree encoded as a sequence of the form \
                     hash-tree ::= [0] | [1 hash-tree hash-tree] | [2 bytes hash-tree] | [3 bytes] | [4 hash]",
                )
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
            where
                V: de::SeqAccess<'de>,
            {
                let tag: u8 = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;

                match tag {
                    0 => {
                        if let Some(de::IgnoredAny) = seq.next_element()? {
                            return Err(de::Error::invalid_length(2, &self));
                        }

                        Ok(HashTreeNode::Empty())
                    }
                    1 => {
                        let left: HashTreeNode = seq
                            .next_element()?
                            .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                        let right: HashTreeNode = seq
                            .next_element()?
                            .ok_or_else(|| de::Error::invalid_length(2, &self))?;

                        if let Some(de::IgnoredAny) = seq.next_element()? {
                            return Err(de::Error::invalid_length(4, &self));
                        }

                        Ok(HashTreeNode::Fork(Box::new((left, right))))
                    }
                    2 => {
                        let label: Label = seq
                            .next_element()?
                            .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                        let subtree: HashTreeNode = seq
                            .next_element()?
                            .ok_or_else(|| de::Error::invalid_length(2, &self))?;

                        if let Some(de::IgnoredAny) = seq.next_element()? {
                            return Err(de::Error::invalid_length(4, &self));
                        }

                        Ok(HashTreeNode::Labeled(Cow::Owned(label), Box::new(subtree)))
                    }
                    3 => {
                        let bytes: serde_bytes::ByteBuf = seq
                            .next_element()?
                            .ok_or_else(|| de::Error::invalid_length(1, &self))?;

                        if let Some(de::IgnoredAny) = seq.next_element()? {
                            return Err(de::Error::invalid_length(3, &self));
                        }

                        Ok(HashTreeNode::Leaf(Cow::Owned(bytes.into_vec())))
                    }
                    4 => {
                        let digest_bytes: serde_bytes::ByteBuf = seq
                            .next_element()?
                            .ok_or_else(|| de::Error::invalid_length(1, &self))?;

                        if let Some(de::IgnoredAny) = seq.next_element()? {
                            return Err(de::Error::invalid_length(3, &self));
                        }

                        let digest = std::convert::TryFrom::try_from(digest_bytes.as_ref())
                            .map_err(|_| {
                                de::Error::invalid_length(
                                    digest_bytes.len(),
                                    &"Expected digest blob",
                                )
                            })?;

                        Ok(HashTreeNode::Pruned(digest))
                    }
                    _ => Err(de::Error::custom(format!(
                        "Unknown tag: {}, expected the tag to be one of {{0, 1, 2, 3, 4}}",
                        tag
                    ))),
                }
            }
        }

        deserializer.deserialize_seq(SeqVisitor)
    }
}
