use crate::pb::v1::nervous_system_function::GenericNervousSystemFunction;
use crate::pb::v1::NervousSystemFunction;

/// Functions are categorized into topics.
/// (As a reminder, a function is either a built-in proposal type, or a generic function that has been added via an
/// AddGenericNervousSystemFunction proposal)
#[derive(
    Debug,
    candid::CandidType,
    candid::Deserialize,
    Ord,
    PartialOrd,
    Eq,
    Clone,
    PartialEq,
    Hash,
    Copy,
)]
pub enum Topic {
    NonCriticalProposals,
    DaoCommunitySettings,
    SnsFrameworkManagement,
    DappCanisterManagement,
    ApplicationBusinessLogic,
    Governance,
    TreasuryAssetManagement,
    CriticalDappOperations,
}

mod topic_ids {
    pub const NON_CRITICAL_PROPOSALS: u64 = 0;
    pub const DAO_COMMUNITY_SETTINGS: u64 = 1;
    pub const SNS_FRAMEWORK_MANAGEMENT: u64 = 2;
    pub const DAPP_CANISTER_MANAGEMENT: u64 = 3;
    pub const APPLICATION_BUSINESS_LOGIC: u64 = 4;
    pub const GOVERNANCE: u64 = 5;
    pub const TREASURY_ASSET_MANAGEMENT: u64 = 6;
    pub const CRITICAL_DAPP_OPERATIONS: u64 = 7;
}

impl From<Topic> for u64 {
    fn from(topic: Topic) -> Self {
        match topic {
            Topic::NonCriticalProposals => topic_ids::NON_CRITICAL_PROPOSALS,
            Topic::DaoCommunitySettings => topic_ids::DAO_COMMUNITY_SETTINGS,
            Topic::SnsFrameworkManagement => topic_ids::SNS_FRAMEWORK_MANAGEMENT,
            Topic::DappCanisterManagement => topic_ids::DAPP_CANISTER_MANAGEMENT,
            Topic::ApplicationBusinessLogic => topic_ids::APPLICATION_BUSINESS_LOGIC,
            Topic::Governance => topic_ids::GOVERNANCE,
            Topic::TreasuryAssetManagement => topic_ids::TREASURY_ASSET_MANAGEMENT,
            Topic::CriticalDappOperations => topic_ids::CRITICAL_DAPP_OPERATIONS,
        }
    }
}

impl TryFrom<u64> for Topic {
    type Error = ();

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            topic_ids::NON_CRITICAL_PROPOSALS => Ok(Topic::NonCriticalProposals),
            topic_ids::DAO_COMMUNITY_SETTINGS => Ok(Topic::DaoCommunitySettings),
            topic_ids::SNS_FRAMEWORK_MANAGEMENT => Ok(Topic::SnsFrameworkManagement),
            topic_ids::DAPP_CANISTER_MANAGEMENT => Ok(Topic::DappCanisterManagement),
            topic_ids::APPLICATION_BUSINESS_LOGIC => Ok(Topic::ApplicationBusinessLogic),
            topic_ids::GOVERNANCE => Ok(Topic::Governance),
            topic_ids::TREASURY_ASSET_MANAGEMENT => Ok(Topic::TreasuryAssetManagement),
            topic_ids::CRITICAL_DAPP_OPERATIONS => Ok(Topic::CriticalDappOperations),
            _ => Err(()),
        }
    }
}

/// Each topic has some information associated with it. This information is for the benefit of the user but has
/// no effect on the behavior of the SNS.
#[derive(Debug, candid::CandidType, candid::Deserialize, Clone, PartialEq)]
pub struct TopicInfo<C> {
    pub topic: Topic,
    pub name: String,
    pub description: String,
    pub content: C,
    pub nested_topics: Vec<TopicInfo<C>>,
    pub critical: bool,
}

#[derive(Debug, candid::CandidType, candid::Deserialize, Clone, PartialEq)]
pub struct BuiltInFunctions {
    pub built_in_functions: Vec<u64>,
}

#[derive(Debug, candid::CandidType, candid::Deserialize, Clone, PartialEq)]
pub struct BuiltInAndGenericFunctions {
    pub built_in_functions: Vec<NervousSystemFunction>,
    pub generic_functions: Vec<NervousSystemFunction>,
}

#[derive(Debug, candid::CandidType, candid::Deserialize, Clone, PartialEq)]
pub struct ListTopicsRequest {}

#[derive(Debug, candid::CandidType, candid::Deserialize, Clone, PartialEq)]
pub struct ListTopicsResponse {
    pub topics: Option<Vec<TopicInfo<BuiltInAndGenericFunctions>>>,
}
