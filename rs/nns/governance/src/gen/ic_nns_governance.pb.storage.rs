/// The historical rewards that were provided to node providers, along with the contextual data
/// needed to calculate it.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ArchivedMonthlyNodeProviderRewards {
    /// The version of the rewards data.  These versions are added to accommodate changes to the
    /// rewards data structure over time.
    #[prost(oneof = "archived_monthly_node_provider_rewards::Version", tags = "1")]
    pub version: ::core::option::Option<archived_monthly_node_provider_rewards::Version>,
}
/// Nested message and enum types in `ArchivedMonthlyNodeProviderRewards`.
pub mod archived_monthly_node_provider_rewards {
    /// The first version of the stored rewards.
    #[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct V1 {
        #[prost(message, optional, tag = "1")]
        pub rewards: ::core::option::Option<super::super::v1::MonthlyNodeProviderRewards>,
    }
    /// The version of the rewards data.  These versions are added to accommodate changes to the
    /// rewards data structure over time.
    #[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Version {
        #[prost(message, tag = "1")]
        Version1(V1),
    }
}
