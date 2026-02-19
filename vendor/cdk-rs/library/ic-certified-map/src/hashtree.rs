#[cfg(test)]
mod test;

use serde::de::{self, Deserialize, Deserializer, SeqAccess, Visitor};
use serde::{Serialize, Serializer, ser::SerializeSeq};
use serde_bytes::Bytes;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::fmt;

/// SHA-256 hash bytes.
pub type Hash = [u8; 32];

/// `HashTree` as defined in the [interfaces spec](https://internetcomputer.org/docs/current/references/ic-interface-spec#certificate).
#[derive(Debug, Clone, Default)]
pub enum HashTree<'a> {
    /// No child nodes; a proof of absence.
    #[default]
    Empty,
    /// Left and right child branches.
    Fork(Box<(HashTree<'a>, HashTree<'a>)>),
    /// A labeled child node.
    Labeled(&'a [u8], Box<HashTree<'a>>),
    /// A leaf node containing a value or hash.
    Leaf(Cow<'a, [u8]>),
    /// A branch that has been removed from this view of the tree, but is not necessarily absent.
    Pruned(Hash),
}

/// Shorthand for [`HashTree::Fork`].
pub fn fork<'a>(l: HashTree<'a>, r: HashTree<'a>) -> HashTree<'a> {
    HashTree::Fork(Box::new((l, r)))
}

/// Shorthand for [`HashTree::Labeled`].
pub fn labeled<'a>(l: &'a [u8], t: HashTree<'a>) -> HashTree<'a> {
    HashTree::Labeled(l, Box::new(t))
}

/// Identifiably hashes a fork in the branch. Used for hashing [`HashTree::Fork`].
pub fn fork_hash(l: &Hash, r: &Hash) -> Hash {
    let mut h = domain_sep("ic-hashtree-fork");
    h.update(&l[..]);
    h.update(&r[..]);
    h.finalize().into()
}

/// Identifiably hashes a leaf node's data. Used for hashing [`HashTree::Leaf`].
pub fn leaf_hash(data: &[u8]) -> Hash {
    let mut h = domain_sep("ic-hashtree-leaf");
    h.update(data);
    h.finalize().into()
}

/// Identifiably hashes a label for this branch. Used for hashing [`HashTree::Labeled`].
pub fn labeled_hash(label: &[u8], content_hash: &Hash) -> Hash {
    let mut h = domain_sep("ic-hashtree-labeled");
    h.update(label);
    h.update(&content_hash[..]);
    h.finalize().into()
}

impl HashTree<'_> {
    /// Produces the root hash of the tree.
    pub fn reconstruct(&self) -> Hash {
        match self {
            Self::Empty => domain_sep("ic-hashtree-empty").finalize().into(),
            Self::Fork(f) => fork_hash(&f.0.reconstruct(), &f.1.reconstruct()),
            Self::Labeled(l, t) => {
                let thash = t.reconstruct();
                labeled_hash(l, &thash)
            }
            Self::Leaf(data) => leaf_hash(data),
            Self::Pruned(h) => *h,
        }
    }
}

impl Serialize for HashTree<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
    where
        S: Serializer,
    {
        match self {
            HashTree::Empty => {
                let mut seq = serializer.serialize_seq(Some(1))?;
                seq.serialize_element(&0u8)?;
                seq.end()
            }
            HashTree::Fork(p) => {
                let mut seq = serializer.serialize_seq(Some(3))?;
                seq.serialize_element(&1u8)?;
                seq.serialize_element(&p.0)?;
                seq.serialize_element(&p.1)?;
                seq.end()
            }
            HashTree::Labeled(label, tree) => {
                let mut seq = serializer.serialize_seq(Some(3))?;
                seq.serialize_element(&2u8)?;
                seq.serialize_element(Bytes::new(label))?;
                seq.serialize_element(&tree)?;
                seq.end()
            }
            HashTree::Leaf(leaf_bytes) => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element(&3u8)?;
                seq.serialize_element(Bytes::new(leaf_bytes.as_ref()))?;
                seq.end()
            }
            HashTree::Pruned(digest) => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element(&4u8)?;
                seq.serialize_element(Bytes::new(&digest[..]))?;
                seq.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for HashTree<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct HashTreeVisitor;

        impl<'de> Visitor<'de> for HashTreeVisitor {
            type Value = HashTree<'de>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a valid sequence representing a HashTree")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let variant: u8 = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &"variant for the HashTree"))?;

                match variant {
                    0 => Ok(HashTree::Empty),
                    1 => {
                        let left: HashTree<'de> = seq.next_element()?.ok_or_else(|| {
                            de::Error::invalid_length(1, &"left child for the Fork")
                        })?;
                        let right: HashTree<'de> = seq.next_element()?.ok_or_else(|| {
                            de::Error::invalid_length(2, &"right child for the Fork")
                        })?;
                        Ok(HashTree::Fork(Box::new((left, right))))
                    }
                    2 => {
                        let label: &'de [u8] = seq.next_element()?.ok_or_else(|| {
                            de::Error::invalid_length(1, &"label for the Labeled")
                        })?;
                        let tree: HashTree<'de> = seq
                            .next_element()?
                            .ok_or_else(|| de::Error::invalid_length(2, &"tree for the Labeled"))?;
                        Ok(HashTree::Labeled(label, Box::new(tree)))
                    }
                    3 => {
                        let bytes: &'de [u8] = seq
                            .next_element()?
                            .ok_or_else(|| de::Error::invalid_length(1, &"bytes for the Leaf"))?;
                        Ok(HashTree::Leaf(Cow::Borrowed(bytes)))
                    }
                    4 => {
                        let digest: &'de [u8] = seq.next_element()?.ok_or_else(|| {
                            de::Error::invalid_length(1, &"digest for the Pruned")
                        })?;
                        let hash: Hash = digest.try_into().map_err(|_| {
                            de::Error::invalid_length(digest.len(), &"32 bytes for the Hash")
                        })?;
                        Ok(HashTree::Pruned(hash))
                    }
                    _ => Err(de::Error::unknown_variant(
                        &variant.to_string(),
                        &["0", "1", "2", "3", "4"],
                    )),
                }
            }
        }

        deserializer.deserialize_seq(HashTreeVisitor)
    }
}

fn domain_sep(s: &str) -> sha2::Sha256 {
    let buf: [u8; 1] = [s.len() as u8];
    let mut h = Sha256::new();
    h.update(&buf[..]);
    h.update(s.as_bytes());
    h
}
