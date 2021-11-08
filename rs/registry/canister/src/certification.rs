//! This module contains utilities for constructing hash trees for
//! certification of updates of the registry.
//!
//! The structure of the tree constructed by the registry is as follows
//!
//! ```text
//! *
//! |
//! +-- current_version -- [ LEB128-encoded VERSION ]
//! |
//! `-- delta --+-- [ big-endian encoded 1u64    ] -- [ serialized protobuf ]
//!             |
//!             …
//!             |
//!             `-- [ big-endian encoded VERSION ] -- [ serialized protobuf ]
//! ```
//!
//! where lebels under "delta" form contiguous range [1,VERSION].

use ic_certified_map::{labeled, HashTree};
use ic_protobuf::messaging::xnet::v1 as pb;

use crate::registry::Version;

/// The maximum amount of bytes a 64-bit number can occupy when encoded in
/// LEB128.
const MAX_U64_ENCODING_BYTES: usize = 10;

pub fn current_version_tree(v: Version) -> HashTree<'static> {
    let mut buf = Vec::with_capacity(MAX_U64_ENCODING_BYTES);
    leb128::write::unsigned(&mut buf, v).unwrap();
    labeled(
        b"current_version",
        HashTree::Leaf(std::borrow::Cow::from(buf)),
    )
}

/// Encodes a hash tree into the protobuf representation expected by
/// the registry client.
pub fn hash_tree_to_proto(tree: HashTree<'_>) -> pb::MixedHashTree {
    use pb::mixed_hash_tree::{Fork, Labeled, TreeEnum};
    use HashTree::*;

    let tree_enum = match tree {
        Empty => TreeEnum::Empty(()),
        Fork(lr) => TreeEnum::Fork(Box::new(Fork {
            left_tree: Some(Box::new(hash_tree_to_proto(lr.0))),
            right_tree: Some(Box::new(hash_tree_to_proto(lr.1))),
        })),
        Labeled(label, subtree) => TreeEnum::Labeled(Box::new(Labeled {
            label: label.to_vec(),
            subtree: Some(Box::new(hash_tree_to_proto(*subtree))),
        })),
        Leaf(data) => TreeEnum::LeafData(data.into_owned()),
        Pruned(digest) => TreeEnum::PrunedDigest(digest.to_vec()),
    };

    pb::MixedHashTree {
        tree_enum: Some(tree_enum),
    }
}
