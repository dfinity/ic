/// Represents a closed range of canister ids.
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterIdRange {
    #[prost(message, optional, tag="3")]
    pub start_canister_id: ::core::option::Option<super::super::super::types::v1::CanisterId>,
    #[prost(message, optional, tag="4")]
    pub end_canister_id: ::core::option::Option<super::super::super::types::v1::CanisterId>,
}
/// A list of closed ranges of canister Ids.
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterIdRanges {
    #[prost(message, repeated, tag="1")]
    pub ranges: ::prost::alloc::vec::Vec<CanisterIdRange>,
}
/// Maps a closed range of canister Ids to a subnet id.
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RoutingTable {
    /// Defined as `repeated` instead of `map` in order to preserve ordering.
    #[prost(message, repeated, tag="1")]
    pub entries: ::prost::alloc::vec::Vec<routing_table::Entry>,
}
/// Nested message and enum types in `RoutingTable`.
pub mod routing_table {
    #[derive(serde::Serialize, serde::Deserialize)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Entry {
        #[prost(message, optional, tag="1")]
        pub range: ::core::option::Option<super::CanisterIdRange>,
        #[prost(message, optional, tag="2")]
        pub subnet_id: ::core::option::Option<super::super::super::super::types::v1::SubnetId>,
    }
}
/// In-progress canister migrations.
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterMigrations {
    /// Defined as `repeated` instead of `map` in order to preserve ordering.
    #[prost(message, repeated, tag="1")]
    pub entries: ::prost::alloc::vec::Vec<canister_migrations::Entry>,
}
/// Nested message and enum types in `CanisterMigrations`.
pub mod canister_migrations {
    /// Describes an in-progress canister migration.
    ///
    /// The canisters in `range` are being sequentially migrated between the subnet
    /// IDs in the list (usually only two, i.e. `A -> B`; but not necessarily, e.g.
    /// `A -> B -> C` or even `A -> B -> A`).
    #[derive(serde::Serialize, serde::Deserialize)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Entry {
        /// Canister ID range being migrated.
        #[prost(message, optional, tag="1")]
        pub range: ::core::option::Option<super::CanisterIdRange>,
        /// Ordered list of subnet IDs tracing the path of the migration.
        #[prost(message, repeated, tag="2")]
        pub subnet_ids: ::prost::alloc::vec::Vec<super::super::super::super::types::v1::SubnetId>,
    }
}
