/// State tree root hash.
#[derive(serde::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CertificationContent {
    #[prost(bytes = "vec", tag = "2")]
    pub hash: ::prost::alloc::vec::Vec<u8>,
}
/// Certification of state tree root hash.
#[derive(serde::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Certification {
    #[prost(uint64, tag = "1")]
    pub height: u64,
    #[prost(message, optional, tag = "2")]
    pub content: ::core::option::Option<CertificationContent>,
    #[prost(message, optional, tag = "3")]
    pub signature: ::core::option::Option<super::super::super::types::v1::ThresholdSignature>,
}
/// Certification signed by a single replica
#[derive(serde::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CertificationShare {
    #[prost(uint64, tag = "1")]
    pub height: u64,
    #[prost(message, optional, tag = "2")]
    pub content: ::core::option::Option<CertificationContent>,
    #[prost(message, optional, tag = "3")]
    pub signature: ::core::option::Option<super::super::super::types::v1::ThresholdSignatureShare>,
}
/// XNet stream slice with certification and matching Merkle proof.
#[derive(serde::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CertifiedStreamSlice {
    /// Serialized part of the state tree containing the stream data.
    #[prost(bytes = "vec", tag = "1")]
    pub payload: ::prost::alloc::vec::Vec<u8>,
    /// Witness that can be used to recompute the root hash from the payload.
    #[prost(bytes = "vec", tag = "2")]
    pub merkle_proof: ::prost::alloc::vec::Vec<u8>,
    /// Certification of the root hash.
    #[prost(message, optional, tag = "3")]
    pub certification: ::core::option::Option<Certification>,
}
/// Tree with ordered, labeled edges.
#[derive(serde::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LabeledTree {
    #[prost(oneof = "labeled_tree::NodeEnum", tags = "1, 2")]
    pub node_enum: ::core::option::Option<labeled_tree::NodeEnum>,
}
/// Nested message and enum types in `LabeledTree`.
pub mod labeled_tree {
    /// Inner node with zero or more ordered, labeled children.
    #[derive(serde::Deserialize, serde::Serialize)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct SubTree {
        /// Defined as `repeated` instead of `map` in order to preserve ordering.
        #[prost(message, repeated, tag = "1")]
        pub children: ::prost::alloc::vec::Vec<Child>,
    }
    /// A `SubTree`'s labeled child.
    #[derive(serde::Deserialize, serde::Serialize)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Child {
        #[prost(bytes = "vec", tag = "1")]
        pub label: ::prost::alloc::vec::Vec<u8>,
        #[prost(message, optional, tag = "2")]
        pub node: ::core::option::Option<super::LabeledTree>,
    }
    #[derive(serde::Deserialize, serde::Serialize)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum NodeEnum {
        #[prost(bytes, tag = "1")]
        Leaf(::prost::alloc::vec::Vec<u8>),
        #[prost(message, tag = "2")]
        SubTree(SubTree),
    }
}
/// A tree containing both data and merkle proofs.
#[derive(serde::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MixedHashTree {
    #[prost(oneof = "mixed_hash_tree::TreeEnum", tags = "1, 2, 3, 4, 5")]
    pub tree_enum: ::core::option::Option<mixed_hash_tree::TreeEnum>,
}
/// Nested message and enum types in `MixedHashTree`.
pub mod mixed_hash_tree {
    #[derive(serde::Deserialize, serde::Serialize)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Fork {
        #[prost(message, optional, boxed, tag = "1")]
        pub left_tree: ::core::option::Option<::prost::alloc::boxed::Box<super::MixedHashTree>>,
        #[prost(message, optional, boxed, tag = "2")]
        pub right_tree: ::core::option::Option<::prost::alloc::boxed::Box<super::MixedHashTree>>,
    }
    #[derive(serde::Deserialize, serde::Serialize)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Labeled {
        #[prost(bytes = "vec", tag = "1")]
        pub label: ::prost::alloc::vec::Vec<u8>,
        #[prost(message, optional, boxed, tag = "2")]
        pub subtree: ::core::option::Option<::prost::alloc::boxed::Box<super::MixedHashTree>>,
    }
    #[derive(serde::Deserialize, serde::Serialize)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum TreeEnum {
        #[prost(message, tag = "1")]
        Empty(()),
        #[prost(message, tag = "2")]
        Fork(::prost::alloc::boxed::Box<Fork>),
        #[prost(message, tag = "3")]
        Labeled(::prost::alloc::boxed::Box<Labeled>),
        #[prost(bytes, tag = "4")]
        LeafData(::prost::alloc::vec::Vec<u8>),
        #[prost(bytes, tag = "5")]
        PrunedDigest(::prost::alloc::vec::Vec<u8>),
    }
}
/// Merkle proof - a subset of a `HashTree`.
#[derive(serde::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Witness {
    #[prost(oneof = "witness::WitnessEnum", tags = "1, 2, 3, 4")]
    pub witness_enum: ::core::option::Option<witness::WitnessEnum>,
}
/// Nested message and enum types in `Witness`.
pub mod witness {
    /// Binary fork.
    #[derive(serde::Deserialize, serde::Serialize)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Fork {
        #[prost(message, optional, boxed, tag = "1")]
        pub left_tree: ::core::option::Option<::prost::alloc::boxed::Box<super::Witness>>,
        #[prost(message, optional, boxed, tag = "2")]
        pub right_tree: ::core::option::Option<::prost::alloc::boxed::Box<super::Witness>>,
    }
    /// Labeled leaf or subtree.
    #[derive(serde::Deserialize, serde::Serialize)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Node {
        #[prost(bytes = "vec", tag = "3")]
        pub label: ::prost::alloc::vec::Vec<u8>,
        #[prost(message, optional, boxed, tag = "4")]
        pub sub_witness: ::core::option::Option<::prost::alloc::boxed::Box<super::Witness>>,
    }
    /// Pruned leaf or subtree.
    #[derive(serde::Deserialize, serde::Serialize)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Pruned {
        #[prost(bytes = "vec", tag = "5")]
        pub digest: ::prost::alloc::vec::Vec<u8>,
    }
    /// Marker for provided data (leaf or subtree).
    #[derive(serde::Deserialize, serde::Serialize)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Known {}
    #[derive(serde::Deserialize, serde::Serialize)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum WitnessEnum {
        #[prost(message, tag = "1")]
        Fork(::prost::alloc::boxed::Box<Fork>),
        #[prost(message, tag = "2")]
        Node(::prost::alloc::boxed::Box<Node>),
        #[prost(message, tag = "3")]
        Pruned(Pruned),
        #[prost(message, tag = "4")]
        Known(Known),
    }
}
