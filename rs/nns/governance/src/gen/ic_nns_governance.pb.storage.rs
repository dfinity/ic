#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct VersionedMonthlyNodeProviderRewards {
    #[prost(
        enumeration = "versioned_monthly_node_provider_rewards::MonthlyNodeProviderRewardsVersion",
        tag = "1"
    )]
    pub version: i32,
}
/// Nested message and enum types in `VersionedMonthlyNodeProviderRewards`.
pub mod versioned_monthly_node_provider_rewards {
    #[derive(
        candid::CandidType,
        candid::Deserialize,
        serde::Serialize,
        comparable::Comparable,
        Clone,
        Copy,
        Debug,
        PartialEq,
        Eq,
        Hash,
        PartialOrd,
        Ord,
        ::prost::Enumeration,
    )]
    #[repr(i32)]
    pub enum MonthlyNodeProviderRewardsVersion {
        Unspecified = 0,
        V1 = 1,
    }
    impl MonthlyNodeProviderRewardsVersion {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                MonthlyNodeProviderRewardsVersion::Unspecified => {
                    "MONTHLY_NODE_PROVIDER_REWARDS_VERSION_UNSPECIFIED"
                }
                MonthlyNodeProviderRewardsVersion::V1 => "MONTHLY_NODE_PROVIDER_REWARDS_VERSION_V1",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "MONTHLY_NODE_PROVIDER_REWARDS_VERSION_UNSPECIFIED" => Some(Self::Unspecified),
                "MONTHLY_NODE_PROVIDER_REWARDS_VERSION_V1" => Some(Self::V1),
                _ => None,
            }
        }
    }
}
