use serde::Serialize;

use crate::pb::v1::{ExtensionOperationSpec, NervousSystemFunction};

/// Registered extension operation specification with canister ID
#[derive(Debug, candid::CandidType, candid::Deserialize, Clone, PartialEq, Serialize)]
pub struct RegisteredExtensionOperationSpec {
    pub canister_id: Option<ic_base_types::PrincipalId>,
    pub spec: Option<ExtensionOperationSpec>,
}

/// Functions are categorized into topics.
/// (As a reminder, a function is either a built-in proposal type, or a generic function that has been added via an
/// AddGenericNervousSystemFunction proposal)
#[derive(
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
pub enum Topic {
    DaoCommunitySettings = 1, // Start at 1 to match the proto type
    SnsFrameworkManagement,
    DappCanisterManagement,
    ApplicationBusinessLogic,
    Governance,
    TreasuryAssetManagement,
    CriticalDappOperations,
}

/// Each topic has some information associated with it. This information is for the benefit of the user but has
/// no effect on the behavior of the SNS.
#[derive(Debug, candid::CandidType, candid::Deserialize, Clone, PartialEq, Serialize)]
pub struct TopicInfo {
    pub topic: Option<Topic>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub native_functions: Option<Vec<NervousSystemFunction>>,
    pub custom_functions: Option<Vec<NervousSystemFunction>>,
    pub extension_operations: Option<Vec<RegisteredExtensionOperationSpec>>,
    pub is_critical: Option<bool>,
}

#[derive(Debug, candid::CandidType, candid::Deserialize, Clone, PartialEq)]
pub struct ListTopicsRequest {}

#[derive(Debug, candid::CandidType, candid::Deserialize, Clone, PartialEq, Serialize)]
pub struct ListTopicsResponse {
    pub topics: Option<Vec<TopicInfo>>,
    pub uncategorized_functions: Option<Vec<NervousSystemFunction>>,
}
