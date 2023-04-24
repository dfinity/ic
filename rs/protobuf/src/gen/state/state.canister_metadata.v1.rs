#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterChangeFromUser {
    #[prost(message, optional, tag = "1")]
    pub user_id: ::core::option::Option<super::super::super::types::v1::PrincipalId>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterChangeFromCanister {
    #[prost(message, optional, tag = "1")]
    pub canister_id: ::core::option::Option<super::super::super::types::v1::PrincipalId>,
    #[prost(uint64, optional, tag = "2")]
    pub canister_version: ::core::option::Option<u64>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterCreation {
    #[prost(message, repeated, tag = "1")]
    pub controllers: ::prost::alloc::vec::Vec<super::super::super::types::v1::PrincipalId>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterCodeUninstall {}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterCodeDeployment {
    #[prost(
        enumeration = "super::super::super::types::v1::CanisterInstallMode",
        tag = "1"
    )]
    pub mode: i32,
    #[prost(bytes = "vec", tag = "2")]
    pub module_hash: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterControllersChange {
    #[prost(message, repeated, tag = "1")]
    pub controllers: ::prost::alloc::vec::Vec<super::super::super::types::v1::PrincipalId>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterChange {
    #[prost(uint64, tag = "1")]
    pub timestamp_nanos: u64,
    #[prost(uint64, tag = "2")]
    pub canister_version: u64,
    #[prost(oneof = "canister_change::ChangeOrigin", tags = "3, 4")]
    pub change_origin: ::core::option::Option<canister_change::ChangeOrigin>,
    #[prost(oneof = "canister_change::ChangeDetails", tags = "5, 6, 7, 8")]
    pub change_details: ::core::option::Option<canister_change::ChangeDetails>,
}
/// Nested message and enum types in `CanisterChange`.
pub mod canister_change {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum ChangeOrigin {
        #[prost(message, tag = "3")]
        CanisterChangeFromUser(super::CanisterChangeFromUser),
        #[prost(message, tag = "4")]
        CanisterChangeFromCanister(super::CanisterChangeFromCanister),
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum ChangeDetails {
        #[prost(message, tag = "5")]
        CanisterCreation(super::CanisterCreation),
        #[prost(message, tag = "6")]
        CanisterCodeUninstall(super::CanisterCodeUninstall),
        #[prost(message, tag = "7")]
        CanisterCodeDeployment(super::CanisterCodeDeployment),
        #[prost(message, tag = "8")]
        CanisterControllersChange(super::CanisterControllersChange),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterHistory {
    #[prost(message, repeated, tag = "1")]
    pub changes: ::prost::alloc::vec::Vec<CanisterChange>,
    #[prost(uint64, tag = "2")]
    pub total_num_changes: u64,
}
/// / CanisterMetadata stores a collection of large but rarely mutated
/// / canister metadata. The collection is a singleton now,
/// / but we still define such a singleton collection to easily
/// / add more such pieces of metadata in the future.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterMetadata {
    #[prost(message, optional, tag = "1")]
    pub canister_history: ::core::option::Option<CanisterHistory>,
}
