// This file is @generated by prost-build.
#[derive(
    Eq,
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    serde::Serialize,
    Clone,
    Copy,
    PartialEq,
    ::prost::Message,
)]
pub struct Duration {
    #[prost(uint64, optional, tag = "1")]
    pub seconds: ::core::option::Option<u64>,
}
#[derive(
    Eq,
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    serde::Serialize,
    Clone,
    Copy,
    PartialEq,
    ::prost::Message,
)]
pub struct GlobalTimeOfDay {
    #[prost(uint64, optional, tag = "1")]
    pub seconds_after_utc_midnight: ::core::option::Option<u64>,
}
#[derive(
    Eq,
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    serde::Serialize,
    Clone,
    Copy,
    PartialEq,
    ::prost::Message,
)]
pub struct Tokens {
    #[prost(uint64, optional, tag = "1")]
    pub e8s: ::core::option::Option<u64>,
}
#[derive(
    Eq,
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    serde::Serialize,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct Image {
    /// A data URI of a png. E.g.
    /// data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAAD0lEQVQIHQEEAPv/AAD/DwIRAQ8HgT3GAAAAAElFTkSuQmCC
    /// ^ 1 pixel containing the color #00FF0F.
    #[prost(string, optional, tag = "1")]
    pub base64_encoding: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(
    Eq,
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    serde::Serialize,
    PartialOrd,
    Ord,
    Clone,
    Copy,
    PartialEq,
    ::prost::Message,
)]
pub struct Percentage {
    #[prost(uint64, optional, tag = "1")]
    pub basis_points: ::core::option::Option<u64>,
}
/// A list of principals.
/// Needed to allow prost to generate the equivalent of Optional<Vec<PrincipalId>>.
#[derive(
    Eq,
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    serde::Serialize,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct Principals {
    #[prost(message, repeated, tag = "1")]
    pub principals: ::prost::alloc::vec::Vec<::ic_base_types::PrincipalId>,
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
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct Canister {
    /// The id of the canister.
    #[prost(message, optional, tag = "1")]
    pub id: ::core::option::Option<::ic_base_types::PrincipalId>,
}
/// Represents a set of countries. To be used in country-specific configurations,
/// e.g., to restrict the geography of an SNS swap.
#[derive(
    Eq,
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    serde::Serialize,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct Countries {
    /// ISO 3166-1 alpha-2 codes
    #[prost(string, repeated, tag = "1")]
    pub iso_codes: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
/// Features:
///    1. Sign ('+' is optional).
///    2. Smallest positive value: 10^-28.
///    3. 96 bits of significand.
///    4. Decimal point character: '.' (dot/period).
#[derive(
    Eq,
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    serde::Serialize,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct Decimal {
    /// E.g. "3.14".
    #[prost(string, optional, tag = "1")]
    pub human_readable: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(
    Eq,
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    serde::Serialize,
    Clone,
    Copy,
    PartialEq,
    ::prost::Message,
)]
pub struct ResetTimersRequest {}
#[derive(
    Eq,
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    serde::Serialize,
    Clone,
    Copy,
    PartialEq,
    ::prost::Message,
)]
pub struct ResetTimersResponse {}
/// TODO\[NNS1-3420\] This type can be refined into different internal API types, depending on
/// TODO\[NNS1-3420\] the needs of a particular canister. The fields of this type represent
/// TODO\[NNS1-3420\] over-approximation of the fields that might be relevant for observing and
/// TODO\[NNS1-3420\] managing timers in nervous system-related canisters.
#[derive(
    Eq,
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    serde::Serialize,
    Clone,
    Copy,
    PartialEq,
    ::prost::Message,
)]
pub struct Timers {
    /// Indicates whether this canister (still) requires (timer-based) periodic tasks.
    ///
    /// May be ignored by canisters that never cancel their periodic tasks.
    #[prost(bool, optional, tag = "1")]
    pub requires_periodic_tasks: ::core::option::Option<bool>,
    #[prost(uint64, optional, tag = "2")]
    pub last_reset_timestamp_seconds: ::core::option::Option<u64>,
    #[prost(uint64, optional, tag = "3")]
    pub last_spawned_timestamp_seconds: ::core::option::Option<u64>,
}
#[derive(
    Eq,
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    serde::Serialize,
    Clone,
    Copy,
    PartialEq,
    ::prost::Message,
)]
pub struct GetTimersRequest {}
#[derive(
    Eq,
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    serde::Serialize,
    Clone,
    Copy,
    PartialEq,
    ::prost::Message,
)]
pub struct GetTimersResponse {
    #[prost(message, optional, tag = "1")]
    pub timers: ::core::option::Option<Timers>,
}