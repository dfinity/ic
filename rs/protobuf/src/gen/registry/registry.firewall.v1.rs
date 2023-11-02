/// Firewall configuration - Deprecated
#[derive(candid::CandidType, serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FirewallConfig {
    /// The firewall configuration content
    #[prost(string, tag = "1")]
    pub firewall_config: ::prost::alloc::string::String,
    /// List of allowed IPv4 prefixes
    #[prost(string, repeated, tag = "2")]
    pub ipv4_prefixes: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// List of allowed IPv6 prefixes
    #[prost(string, repeated, tag = "3")]
    pub ipv6_prefixes: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
#[derive(candid::CandidType, serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FirewallRule {
    #[prost(string, repeated, tag = "1")]
    pub ipv4_prefixes: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(string, repeated, tag = "2")]
    pub ipv6_prefixes: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(uint32, repeated, tag = "3")]
    pub ports: ::prost::alloc::vec::Vec<u32>,
    #[prost(enumeration = "FirewallAction", tag = "4")]
    pub action: i32,
    #[prost(string, tag = "5")]
    pub comment: ::prost::alloc::string::String,
    #[prost(string, optional, tag = "6")]
    pub user: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(enumeration = "FirewallRuleDirection", optional, tag = "7")]
    pub direction: ::core::option::Option<i32>,
}
#[derive(candid::CandidType, serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FirewallRuleSet {
    #[prost(message, repeated, tag = "1")]
    pub entries: ::prost::alloc::vec::Vec<FirewallRule>,
}
/// Available actions for firewall rules
#[derive(
    candid::CandidType,
    serde::Serialize,
    serde::Deserialize,
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
pub enum FirewallAction {
    Unspecified = 0,
    /// Allow traffic
    Allow = 1,
    /// Deny (drop) traffic
    Deny = 2,
    /// Reject traffic (send ICMP error back)
    Reject = 3,
}
impl FirewallAction {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            FirewallAction::Unspecified => "FIREWALL_ACTION_UNSPECIFIED",
            FirewallAction::Allow => "FIREWALL_ACTION_ALLOW",
            FirewallAction::Deny => "FIREWALL_ACTION_DENY",
            FirewallAction::Reject => "FIREWALL_ACTION_REJECT",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "FIREWALL_ACTION_UNSPECIFIED" => Some(Self::Unspecified),
            "FIREWALL_ACTION_ALLOW" => Some(Self::Allow),
            "FIREWALL_ACTION_DENY" => Some(Self::Deny),
            "FIREWALL_ACTION_REJECT" => Some(Self::Reject),
            _ => None,
        }
    }
}
#[derive(
    candid::CandidType,
    serde::Serialize,
    serde::Deserialize,
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
pub enum FirewallRuleDirection {
    Unspecified = 0,
    Inbound = 1,
    Outbound = 2,
}
impl FirewallRuleDirection {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            FirewallRuleDirection::Unspecified => "FIREWALL_RULE_DIRECTION_UNSPECIFIED",
            FirewallRuleDirection::Inbound => "FIREWALL_RULE_DIRECTION_INBOUND",
            FirewallRuleDirection::Outbound => "FIREWALL_RULE_DIRECTION_OUTBOUND",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "FIREWALL_RULE_DIRECTION_UNSPECIFIED" => Some(Self::Unspecified),
            "FIREWALL_RULE_DIRECTION_INBOUND" => Some(Self::Inbound),
            "FIREWALL_RULE_DIRECTION_OUTBOUND" => Some(Self::Outbound),
            _ => None,
        }
    }
}
