#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ArchivedMonthlyNodeProviderRewards {
    #[prost(oneof = "archived_monthly_node_provider_rewards::Version", tags = "1")]
    pub version: ::core::option::Option<archived_monthly_node_provider_rewards::Version>,
}
/// Nested message and enum types in `ArchivedMonthlyNodeProviderRewards`.
pub mod archived_monthly_node_provider_rewards {
    #[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct V1 {
        #[prost(message, optional, tag = "1")]
        pub rewards: ::core::option::Option<super::super::v1::MonthlyNodeProviderRewards>,
    }
    #[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Version {
        #[prost(message, tag = "1")]
        Version1(V1),
    }
}
