/// A tree containing both data and merkle proofs.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MixedHashTree {
    #[prost(oneof="mixed_hash_tree::TreeEnum", tags="1, 2, 3, 4, 5")]
    pub tree_enum: ::core::option::Option<mixed_hash_tree::TreeEnum>,
}
/// Nested message and enum types in `MixedHashTree`.
pub mod mixed_hash_tree {
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Fork {
        #[prost(message, optional, boxed, tag="1")]
        pub left_tree: ::core::option::Option<::prost::alloc::boxed::Box<super::MixedHashTree>>,
        #[prost(message, optional, boxed, tag="2")]
        pub right_tree: ::core::option::Option<::prost::alloc::boxed::Box<super::MixedHashTree>>,
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Labeled {
        #[prost(bytes="vec", tag="1")]
        pub label: ::prost::alloc::vec::Vec<u8>,
        #[prost(message, optional, boxed, tag="2")]
        pub subtree: ::core::option::Option<::prost::alloc::boxed::Box<super::MixedHashTree>>,
    }
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum TreeEnum {
        #[prost(message, tag="1")]
        Empty(()),
        #[prost(message, tag="2")]
        Fork(::prost::alloc::boxed::Box<Fork>),
        #[prost(message, tag="3")]
        Labeled(::prost::alloc::boxed::Box<Labeled>),
        #[prost(bytes, tag="4")]
        LeafData(::prost::alloc::vec::Vec<u8>),
        #[prost(bytes, tag="5")]
        PrunedDigest(::prost::alloc::vec::Vec<u8>),
    }
}
