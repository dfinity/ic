//! Protocol buffer equivalents to `LabeledTree<Vec<u8>>` and `Witness`, for
//! backwards- and forwards-compatible XNet wire format.

#[cfg(test)]
mod mixed_hash_tree_tests;
#[cfg(test)]
mod tests;

use crate::{Digest, FlatMap, Label, LabeledTree, MixedHashTree, Witness};
use ic_protobuf::messaging::xnet::v1 as pb;
use ic_protobuf::proxy::{try_from_option_field, ProxyDecodeError, ProxyDecodeError::*};
use std::convert::{TryFrom, TryInto};

type LabeledTreeOfBytes = LabeledTree<Vec<u8>>;

use pb::{labeled_tree, labeled_tree::NodeEnum};

/// Converts the contents of a `LabeledTree::SubTree`into the contents of a
/// `pb::labeled_tree::NodeEnum::SubTree`.
fn sub_tree_proto_from(map: FlatMap<Label, LabeledTreeOfBytes>) -> labeled_tree::SubTree {
    labeled_tree::SubTree {
        children: map
            .into_iter()
            .map(|(label, node)| labeled_tree::Child {
                label: label.to_vec(),
                node: Some(node.into()),
            })
            .collect(),
    }
}
impl From<LabeledTreeOfBytes> for pb::LabeledTree {
    fn from(tree: LabeledTreeOfBytes) -> Self {
        Self {
            node_enum: match tree {
                LabeledTree::Leaf(leaf) => Some(NodeEnum::Leaf(leaf)),
                LabeledTree::SubTree(map) => Some(NodeEnum::SubTree(sub_tree_proto_from(map))),
            },
        }
    }
}

/// Converts the contents of a `pb::labeled_tree::NodeEnum::SubTree` into the
/// contents of a `LabeledTree::SubTree` (or a `ProxyDecodeError` on failure).
fn sub_tree_map_from(
    subtree: labeled_tree::SubTree,
) -> Result<FlatMap<Label, LabeledTreeOfBytes>, ProxyDecodeError> {
    let kv: Vec<_> = subtree
        .children
        .into_iter()
        .map(|child| {
            Ok((
                Label::from(child.label),
                try_from_option_field(child.node, "LabeledTree::Subtree::value")?,
            ))
        })
        .collect::<Result<_, ProxyDecodeError>>()?;
    Ok(FlatMap::from_key_values(kv))
}
impl TryFrom<pb::LabeledTree> for LabeledTreeOfBytes {
    type Error = ProxyDecodeError;

    fn try_from(tree: pb::LabeledTree) -> Result<Self, Self::Error> {
        let tree: NodeEnum = try_from_option_field(tree.node_enum, "LabeledTree::node_enum")?;
        match tree {
            NodeEnum::Leaf(leaf) => Ok(LabeledTree::Leaf(leaf)),
            NodeEnum::SubTree(subtree) => Ok(LabeledTree::SubTree(sub_tree_map_from(subtree)?)),
        }
    }
}

use pb::{witness, witness::WitnessEnum};
impl From<Box<Witness>> for Box<pb::Witness> {
    fn from(value: Box<Witness>) -> Self {
        Box::new((*value).into())
    }
}
impl From<Witness> for pb::Witness {
    fn from(value: Witness) -> Self {
        let witness_enum: WitnessEnum = match value {
            Witness::Fork {
                left_tree,
                right_tree,
            } => WitnessEnum::Fork(Box::new(witness::Fork {
                left_tree: Some(left_tree.into()),
                right_tree: Some(right_tree.into()),
            })),

            Witness::Node { label, sub_witness } => WitnessEnum::Node(Box::new(witness::Node {
                label: label.to_vec(),
                sub_witness: Some(sub_witness.into()),
            })),

            Witness::Pruned { digest } => WitnessEnum::Pruned(witness::Pruned {
                digest: (Box::new(digest.0) as Box<[_]>).into_vec(),
            }),

            Witness::Known() => WitnessEnum::Known(witness::Known {}),
        };

        Self {
            witness_enum: Some(witness_enum),
        }
    }
}
impl TryFrom<Box<pb::Witness>> for Box<Witness> {
    type Error = ProxyDecodeError;

    fn try_from(value: Box<pb::Witness>) -> Result<Self, Self::Error> {
        Ok(Box::new((*value).try_into()?))
    }
}
impl TryFrom<pb::Witness> for Witness {
    type Error = ProxyDecodeError;

    fn try_from(witness: pb::Witness) -> Result<Self, Self::Error> {
        let witness = witness
            .witness_enum
            .ok_or(MissingField("Witness::witness_enum"))?;

        Ok(match witness {
            WitnessEnum::Fork(fork) => Witness::Fork {
                left_tree: try_from_option_field(fork.left_tree, "Witness::Fork::left_tree")?,
                right_tree: try_from_option_field(fork.right_tree, "Witness::Fork::right_tree")?,
            },

            WitnessEnum::Node(node) => Witness::Node {
                label: Label::from(node.label),
                sub_witness: try_from_option_field(node.sub_witness, "Witness::Node::sub_witness")?,
            },

            WitnessEnum::Pruned(pruned) => Witness::Pruned {
                digest: pruned.digest.try_into().map_err(|d: Vec<u8>| {
                    ProxyDecodeError::InvalidDigestLength {
                        expected: std::mem::size_of::<Digest>(),
                        actual: d.len(),
                    }
                })?,
            },

            WitnessEnum::Known(_) => Witness::Known(),
        })
    }
}

impl From<MixedHashTree> for pb::MixedHashTree {
    fn from(tree: MixedHashTree) -> Self {
        use pb::mixed_hash_tree::{Fork, Labeled, TreeEnum};
        use MixedHashTree as T;

        let tree_enum = match tree {
            T::Empty => TreeEnum::Empty(()),
            T::Fork(lr) => TreeEnum::Fork(Box::new(Fork {
                left_tree: Some(Box::new(lr.0.into())),
                right_tree: Some(Box::new(lr.1.into())),
            })),
            T::Labeled(label, subtree) => TreeEnum::Labeled(Box::new(Labeled {
                label: label.to_vec(),
                subtree: Some(Box::new(Self::from(*subtree))),
            })),
            T::Leaf(data) => TreeEnum::LeafData(data),
            T::Pruned(digest) => TreeEnum::PrunedDigest(digest.0.to_vec()),
        };

        Self {
            tree_enum: Some(tree_enum),
        }
    }
}

impl TryFrom<Box<pb::MixedHashTree>> for Box<MixedHashTree> {
    type Error = ProxyDecodeError;

    fn try_from(value: Box<pb::MixedHashTree>) -> Result<Self, Self::Error> {
        Ok(Box::new((*value).try_into()?))
    }
}

impl TryFrom<pb::MixedHashTree> for MixedHashTree {
    type Error = ProxyDecodeError;

    fn try_from(tree: pb::MixedHashTree) -> Result<Self, Self::Error> {
        use pb::mixed_hash_tree::TreeEnum;

        let tree_enum = tree
            .tree_enum
            .ok_or(MissingField("MixedHashTree::tree_enum"))?;

        Ok(match tree_enum {
            TreeEnum::Empty(()) => Self::Empty,
            TreeEnum::Fork(fork) => {
                let l: Box<MixedHashTree> =
                    try_from_option_field(fork.left_tree, "Fork::left_tree")?;
                let r: Box<MixedHashTree> =
                    try_from_option_field(fork.right_tree, "Fork::right_tree")?;

                Self::Fork(Box::new((*l, *r)))
            }
            TreeEnum::Labeled(labeled) => Self::Labeled(
                Label::from(labeled.label),
                try_from_option_field(labeled.subtree, "Labeled::subtree")?,
            ),
            TreeEnum::PrunedDigest(digest) => {
                let digest = Digest::try_from(digest).map_err(|vec| {
                    ProxyDecodeError::InvalidDigestLength {
                        expected: std::mem::size_of::<Digest>(),
                        actual: vec.len(),
                    }
                })?;
                Self::Pruned(digest)
            }
            TreeEnum::LeafData(leaf_data) => Self::Leaf(leaf_data),
        })
    }
}
