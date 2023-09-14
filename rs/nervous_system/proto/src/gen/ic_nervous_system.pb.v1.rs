#[derive(
    Eq, candid::CandidType, candid::Deserialize, comparable::Comparable, serde::Serialize, Copy,
)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Duration {
    #[prost(uint64, optional, tag = "1")]
    pub seconds: ::core::option::Option<u64>,
}
#[derive(
    Eq, candid::CandidType, candid::Deserialize, comparable::Comparable, serde::Serialize, Copy,
)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GlobalTimeOfDay {
    #[prost(uint64, optional, tag = "1")]
    pub seconds_after_utc_midnight: ::core::option::Option<u64>,
}
#[derive(
    Eq, candid::CandidType, candid::Deserialize, comparable::Comparable, serde::Serialize, Copy,
)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Tokens {
    #[prost(uint64, optional, tag = "1")]
    pub e8s: ::core::option::Option<u64>,
}
#[derive(Eq, candid::CandidType, candid::Deserialize, comparable::Comparable, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Image {
    /// A data URI of a png. E.g.
    /// data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAAD0lEQVQIHQEEAPv/AAD/DwIRAQ8HgT3GAAAAAElFTkSuQmCC
    /// ^ 1 pixel containing the color #00FF0F.
    #[prost(string, optional, tag = "1")]
    pub base64_encoding: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(
    Eq, candid::CandidType, candid::Deserialize, comparable::Comparable, serde::Serialize, Copy,
)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Percentage {
    #[prost(uint64, optional, tag = "1")]
    pub basis_points: ::core::option::Option<u64>,
}
/// A Canister that will be transferred to an SNS.
#[derive(
    Eq,
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    serde::Serialize,
    Ord,
    PartialOrd,
    Copy,
)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Canister {
    /// The id of the canister.
    #[prost(message, optional, tag = "1")]
    pub id: ::core::option::Option<::ic_base_types::PrincipalId>,
}
/// Represents a set of countries. To be used in country-specific configurations,
/// e.g., to restrict the geography of an SNS swap.
#[derive(Eq, candid::CandidType, candid::Deserialize, comparable::Comparable, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Countries {
    /// ISO 3166-1 alpha-2 codes
    #[prost(string, repeated, tag = "1")]
    pub iso_codes: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
