use crate::logs::ERROR;
use crate::pb::v1::{self as pb, NervousSystemFunction};
use crate::types::native_action_ids::{self, SET_CUSTOM_TOPICS_FOR_CUSTOM_PROPOSALS_ACTION};
use crate::{governance::Governance, pb::v1::nervous_system_function::FunctionType};
use ic_canister_log::log;
use ic_sns_governance_api::pb::v1::topics::Topic;
use itertools::Itertools;
use std::collections::{BTreeMap, HashMap};

/// Each topic has some information associated with it. This information is for the benefit of the user but has
/// no effect on the behavior of the SNS.
#[derive(Debug, candid::CandidType, candid::Deserialize, Clone, PartialEq)]
pub struct TopicInfo<C> {
    pub topic: Topic,
    pub name: String,
    pub description: String,
    pub functions: C,
    pub is_critical: bool,
}

#[derive(Debug, candid::CandidType, candid::Deserialize, Clone, PartialEq)]
pub struct NativeFunctions {
    pub native_functions: Vec<u64>,
}

#[derive(Debug, candid::CandidType, candid::Deserialize, Clone, PartialEq)]
pub struct NervousSystemFunctions {
    pub native_functions: Vec<NervousSystemFunction>,
    pub custom_functions: Vec<NervousSystemFunction>,
}

#[derive(Debug, candid::CandidType, candid::Deserialize, Clone, PartialEq)]
pub struct ListTopicsRequest {}

#[derive(Debug, candid::CandidType, candid::Deserialize, Clone, PartialEq)]
pub struct ListTopicsResponse {
    pub topics: Vec<TopicInfo<NervousSystemFunctions>>,

    /// Functions that are not categorized into any topic.
    pub uncategorized_functions: Vec<NervousSystemFunction>,
}

/// Returns an exhaustive list of topic descriptions, each corresponding to a topic.
/// Topics may be nested within other topics, and each topic may have a list of built-in functions that are categorized within that topic.
pub fn topic_descriptions() -> Vec<TopicInfo<NativeFunctions>> {
    use crate::types::native_action_ids::{
        ADD_GENERIC_NERVOUS_SYSTEM_FUNCTION, ADVANCE_SNS_TARGET_VERSION, DEREGISTER_DAPP_CANISTERS,
        MANAGE_DAPP_CANISTER_SETTINGS, MANAGE_LEDGER_PARAMETERS, MANAGE_NERVOUS_SYSTEM_PARAMETERS,
        MANAGE_SNS_METADATA, MINT_SNS_TOKENS, MOTION, REGISTER_DAPP_CANISTERS,
        REMOVE_GENERIC_NERVOUS_SYSTEM_FUNCTION, TRANSFER_SNS_TREASURY_FUNDS,
        UPGRADE_SNS_CONTROLLED_CANISTER, UPGRADE_SNS_TO_NEXT_VERSION,
    };

    vec![
        TopicInfo::<NativeFunctions> {
            topic: Topic::DaoCommunitySettings,
            name: "DAO community settings".to_string(),
            description: "Proposals to set the direction of the DAO by tokenomics & branding, such as the name and description, token name etc".to_string(),
            functions: NativeFunctions {
                native_functions: vec![
                    MANAGE_NERVOUS_SYSTEM_PARAMETERS,
                    MANAGE_LEDGER_PARAMETERS,
                    MANAGE_SNS_METADATA,
                ],
            },
            is_critical: false,
        },
        TopicInfo::<NativeFunctions> {
            topic: Topic::SnsFrameworkManagement,
            name: "SNS framework management".to_string(),
            description: "Proposals to upgrade and manage the SNS DAO framework.".to_string(),
            functions: NativeFunctions {
                native_functions: vec![
                    UPGRADE_SNS_TO_NEXT_VERSION,
                    ADVANCE_SNS_TARGET_VERSION,
                    SET_CUSTOM_TOPICS_FOR_CUSTOM_PROPOSALS_ACTION,
                ],
            },
            is_critical: false,
        },
        TopicInfo::<NativeFunctions> {
            topic: Topic::DappCanisterManagement,
            name: "Dapp canister management".to_string(),
            description: "Proposals to upgrade the registered dapp canisters and dapp upgrades via built-in or custom logic and updates to frontend assets.".to_string(),
            functions: NativeFunctions {
                native_functions: vec![
                    UPGRADE_SNS_CONTROLLED_CANISTER,
                    REGISTER_DAPP_CANISTERS,
                    MANAGE_DAPP_CANISTER_SETTINGS,
                ],
            },
            is_critical: false,
        },
        TopicInfo::<NativeFunctions> {
            topic: Topic::ApplicationBusinessLogic,
            name: "Application Business Logic".to_string(),
            description: "Proposals that are custom to what the governed dapp requires.".to_string(),
            functions: NativeFunctions {
                native_functions: vec![],
            },
            is_critical: false,
        },
        TopicInfo::<NativeFunctions> {
            topic: Topic::Governance,
            name: "Governance".to_string(),
            description: "Proposals that represent community polls or other forms of community opinion but don’t have any immediate effect in terms of code changes.".to_string(),
            functions: NativeFunctions {
                native_functions: vec![MOTION],
            },
            is_critical: false,
        },
        TopicInfo::<NativeFunctions> {
            topic: Topic::TreasuryAssetManagement,
            name: "Treasury & asset management".to_string(),
            description: "Proposals to move and manage assets that are DAO-owned, including tokens in the treasury, tokens in liquidity pools, or DAO-owned neurons.".to_string(),
            functions: NativeFunctions {
                native_functions: vec![
                    TRANSFER_SNS_TREASURY_FUNDS,
                    MINT_SNS_TOKENS,
                ],
            },
            is_critical: true,
        },
        TopicInfo::<NativeFunctions> {
            topic: Topic::CriticalDappOperations,
            name: "Critical Dapp Operations".to_string(),
            description: "Proposals to execute critical operations on dapps, such as adding or removing dapps from the SNS, or executing custom logic on dapps.".to_string(),
            functions: NativeFunctions {
                native_functions: vec![
                    DEREGISTER_DAPP_CANISTERS,
                    ADD_GENERIC_NERVOUS_SYSTEM_FUNCTION,
                    REMOVE_GENERIC_NERVOUS_SYSTEM_FUNCTION,
                ],
            },
            is_critical: true,
        },
    ]
}

impl Governance {
    pub fn list_topics(&self) -> ListTopicsResponse {
        let mut uncategorized_functions = vec![];

        let topic_id_to_functions: HashMap<u64, NervousSystemFunction> =
            native_action_ids::nervous_system_functions()
                .into_iter()
                .map(|function| (function.id, function))
                .collect();
        let custom_functions = self
            .proto
            .id_to_nervous_system_functions
            .values()
            .cloned()
            .filter_map(|function| {
                match function.function_type.clone() {
                    Some(FunctionType::GenericNervousSystemFunction(ref generic_function)) => {
                        let topic = generic_function
                            .topic
                            .and_then(|t| crate::pb::v1::Topic::try_from(t).ok())
                            .and_then(|t| Topic::try_from(t).ok());
                        match topic {
                            Some(topic) => Some((topic, function)),
                            None => {
                                uncategorized_functions.push(function);
                                None
                            }
                        }
                    }
                    // This case is impossible
                    _ => None,
                }
            })
            .into_group_map();

        let topics: Vec<TopicInfo<NativeFunctions>> = topic_descriptions();

        let topics = topics
            .into_iter()
            .map(|topic| TopicInfo {
                topic: topic.topic,
                name: topic.name,
                description: topic.description,
                functions: NervousSystemFunctions {
                    native_functions: topic
                        .functions
                        .native_functions
                        .into_iter()
                        .map(|id| topic_id_to_functions[&id].clone())
                        .collect(),
                    custom_functions: custom_functions
                        .get(&topic.topic)
                        .cloned()
                        .unwrap_or_default()
                        .clone(),
                },
                is_critical: topic.is_critical,
            })
            .collect();

        ListTopicsResponse {
            topics,
            uncategorized_functions,
        }
    }
}

impl pb::Governance {
    /// For each custom function ID, returns a pair (`function_name`, `topic`).
    pub fn custom_functions_to_topics(&self) -> BTreeMap<u64, (String, Option<pb::Topic>)> {
        self.id_to_nervous_system_functions
            .iter()
            .filter_map(|(function_id, function)| {
                let Some(FunctionType::GenericNervousSystemFunction(generic)) =
                    &function.function_type
                else {
                    // Skip native proposals.
                    return None;
                };

                let function_name = function.name.clone();

                let Some(topic) = generic.topic else {
                    // Topic not yet set for this custom function.
                    return Some((*function_id, (function_name, None)));
                };

                let specific_topic = match pb::Topic::try_from(topic) {
                    Err(err) => {
                        log!(
                            ERROR,
                            "Custom proposal ID {function_id}: Cannot interpret \
                                {topic} as Topic: {err}",
                        );

                        // This should never happen; if it somehow does, treat this
                        // case as a custom function for which the topic is unknown.
                        None
                    }
                    Ok(pb::Topic::Unspecified) => {
                        log!(
                            ERROR,
                            "Custom proposal ID {function_id}: topic Unspecified."
                        );

                        // This should never happen, but if it somehow does, treat this
                        // case as a custom function for which the topic is unknown.
                        None
                    }
                    Ok(topic) => Some(topic),
                };

                Some((*function_id, (function_name, specific_topic)))
            })
            .collect()
    }

    pub fn get_topic_for_action(
        &self,
        action: &pb::proposal::Action,
    ) -> Result<Option<pb::Topic>, String> {
        if let Some(topic) = pb::Topic::get_topic_for_native_action(action) {
            return Ok(Some(topic));
        };

        let action_code = u64::from(action);

        let Some(function) = self.id_to_nervous_system_functions.get(&action_code) else {
            return Err(format!("Invalid action with ID {action_code}."));
        };

        let custom_proposal_topic_id = match &function.function_type {
            Some(FunctionType::GenericNervousSystemFunction(generic)) => generic.topic,
            Some(FunctionType::NativeNervousSystemFunction(_)) => {
                return Err(format!(
                    "Internal: native function with ID {action_code} does not have a topic."
                ));
            }
            None => {
                return Err(format!(
                    "Function type not set for action with ID {action_code}."
                ));
            }
        };

        let Some(custom_proposal_topic_id) = custom_proposal_topic_id else {
            return Ok(None);
        };

        let Ok(topic) = pb::Topic::try_from(custom_proposal_topic_id) else {
            return Err(format!("Invalid topic ID {custom_proposal_topic_id}."));
        };

        Ok(Some(topic))
    }
}

impl pb::Topic {
    pub fn is_critical(&self) -> bool {
        topic_descriptions()
            .iter()
            .any(|topic| Self::from(topic.topic) == *self && topic.is_critical)
    }

    pub fn get_topic_for_native_action(action: &pb::proposal::Action) -> Option<Self> {
        let action_code = u64::from(action);

        topic_descriptions()
            .into_iter()
            .find_map(|topic_info: TopicInfo<NativeFunctions>| {
                topic_info
                    .functions
                    .native_functions
                    .into_iter()
                    .find(|native_function| action_code == *native_function)
                    .map(|_| Self::from(topic_info.topic))
            })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        pb::v1::{nervous_system_function, ExecuteGenericNervousSystemFunction},
        types::native_action_ids::nervous_system_functions,
    };
    use maplit::btreemap;
    use std::collections::BTreeSet;

    #[test]
    fn test_all_native_proposals_have_topics_except_execute_nervous_system_function() {
        let native_functions = nervous_system_functions()
            .into_iter()
            .filter_map(|nervous_system_function| {
                if nervous_system_function.needs_topic() {
                    Some((nervous_system_function.id, nervous_system_function.name))
                } else {
                    None
                }
            })
            .collect::<BTreeSet<_>>();

        let mut native_functions_with_topic = topic_descriptions()
            .into_iter()
            .flat_map(|topic_info: TopicInfo<NativeFunctions>| {
                topic_info.functions.native_functions
            })
            .collect::<BTreeSet<_>>();

        for (native_function_id, native_function_name) in native_functions {
            let function_id_found = native_functions_with_topic.remove(&native_function_id);
            assert!(
                function_id_found,
                "Topic not defined for native proposal '{}' with ID {}.",
                native_function_name, native_function_id,
            )
        }

        assert_eq!(
            native_functions_with_topic,
            BTreeSet::new(),
            "Some native proposal topics were defined for non-native proposals: {:?}",
            native_functions_with_topic,
        )
    }

    #[test]
    fn test_all_topics() {
        let custom_proposal_without_function_type = NervousSystemFunction {
            id: 1004,
            name: "Custom proposal for tests".to_string(),
            description: None,
            function_type: None,
        };

        let custom_proposal_without_topic = NervousSystemFunction {
            id: 1003,
            name: "Custom proposal for tests".to_string(),
            description: None,
            function_type: Some(
                nervous_system_function::FunctionType::GenericNervousSystemFunction(
                    nervous_system_function::GenericNervousSystemFunction {
                        topic: None,
                        ..Default::default()
                    },
                ),
            ),
        };

        let custom_proposal_with_invalid_topic = NervousSystemFunction {
            id: 1002,
            name: "Custom proposal for tests".to_string(),
            description: None,
            function_type: Some(
                nervous_system_function::FunctionType::GenericNervousSystemFunction(
                    nervous_system_function::GenericNervousSystemFunction {
                        topic: Some(i32::MAX),
                        ..Default::default()
                    },
                ),
            ),
        };

        let custom_proposal_with_valid_topic = NervousSystemFunction {
            id: 1001,
            name: "Custom proposal for tests".to_string(),
            description: None,
            function_type: Some(
                nervous_system_function::FunctionType::GenericNervousSystemFunction(
                    nervous_system_function::GenericNervousSystemFunction {
                        topic: Some(pb::Topic::CriticalDappOperations as i32),
                        ..Default::default()
                    },
                ),
            ),
        };

        let governance_proto = pb::Governance {
            id_to_nervous_system_functions: btreemap! {
                1001 => custom_proposal_with_valid_topic,
                1002 => custom_proposal_with_invalid_topic,
                1003 => custom_proposal_without_topic,
                1004 => custom_proposal_without_function_type,
            },
            ..Default::default()
        };

        let mut test_cases = vec![
            // DaoCommunitySettings
            (
                pb::proposal::Action::ManageNervousSystemParameters(Default::default()),
                Ok(Some(pb::Topic::DaoCommunitySettings)),
            ),
            (
                pb::proposal::Action::ManageLedgerParameters(Default::default()),
                Ok(Some(pb::Topic::DaoCommunitySettings)),
            ),
            (
                pb::proposal::Action::ManageSnsMetadata(Default::default()),
                Ok(Some(pb::Topic::DaoCommunitySettings)),
            ),
            // SnsFrameworkManagement
            (
                pb::proposal::Action::UpgradeSnsToNextVersion(Default::default()),
                Ok(Some(pb::Topic::SnsFrameworkManagement)),
            ),
            (
                pb::proposal::Action::AdvanceSnsTargetVersion(Default::default()),
                Ok(Some(pb::Topic::SnsFrameworkManagement)),
            ),
            (
                pb::proposal::Action::SetTopicsForCustomProposals(Default::default()),
                Ok(Some(pb::Topic::SnsFrameworkManagement)),
            ),
            // DappCanisterManagement
            (
                pb::proposal::Action::UpgradeSnsControlledCanister(Default::default()),
                Ok(Some(pb::Topic::DappCanisterManagement)),
            ),
            (
                pb::proposal::Action::RegisterDappCanisters(Default::default()),
                Ok(Some(pb::Topic::DappCanisterManagement)),
            ),
            (
                pb::proposal::Action::ManageDappCanisterSettings(Default::default()),
                Ok(Some(pb::Topic::DappCanisterManagement)),
            ),
            // ApplicationBusinessLogic - skipped, since this topic is for custom proposals.

            // Governance
            (
                pb::proposal::Action::Motion(Default::default()),
                Ok(Some(pb::Topic::Governance)),
            ),
            // TreasuryAssetManagement
            (
                pb::proposal::Action::TransferSnsTreasuryFunds(Default::default()),
                Ok(Some(pb::Topic::TreasuryAssetManagement)),
            ),
            (
                pb::proposal::Action::MintSnsTokens(Default::default()),
                Ok(Some(pb::Topic::TreasuryAssetManagement)),
            ),
            // CriticalDappOperations
            (
                pb::proposal::Action::DeregisterDappCanisters(Default::default()),
                Ok(Some(pb::Topic::CriticalDappOperations)),
            ),
            (
                pb::proposal::Action::AddGenericNervousSystemFunction(Default::default()),
                Ok(Some(pb::Topic::CriticalDappOperations)),
            ),
            (
                pb::proposal::Action::RemoveGenericNervousSystemFunction(Default::default()),
                Ok(Some(pb::Topic::CriticalDappOperations)),
            ),
        ];

        // Smoke test
        assert_eq!(
            test_cases.len(),
            nervous_system_functions().len() - 1,
            "Missing some test cases for native proposals."
        );

        // Special case: Undefined function.
        test_cases.push((
            pb::proposal::Action::Unspecified(Default::default()),
            Err("Invalid action with ID 0.".to_string()),
        ));

        // Add test cases for custom proposals.
        test_cases.push((
            pb::proposal::Action::ExecuteGenericNervousSystemFunction(
                ExecuteGenericNervousSystemFunction {
                    function_id: 1001,
                    ..Default::default()
                },
            ),
            Ok(Some(pb::Topic::CriticalDappOperations)),
        ));
        test_cases.push((
            pb::proposal::Action::ExecuteGenericNervousSystemFunction(
                ExecuteGenericNervousSystemFunction {
                    function_id: 1002,
                    ..Default::default()
                },
            ),
            Err(format!("Invalid topic ID {}.", i32::MAX)),
        ));
        test_cases.push((
            pb::proposal::Action::ExecuteGenericNervousSystemFunction(
                ExecuteGenericNervousSystemFunction {
                    function_id: 1003,
                    ..Default::default()
                },
            ),
            Ok(None),
        ));
        test_cases.push((
            pb::proposal::Action::ExecuteGenericNervousSystemFunction(
                ExecuteGenericNervousSystemFunction {
                    function_id: 1004,
                    ..Default::default()
                },
            ),
            Err("Function type not set for action with ID 1004.".to_string()),
        ));

        // Run code under test.
        for (action, expected) in test_cases.into_iter() {
            let observed = governance_proto.get_topic_for_action(&action);
            assert_eq!(observed, expected);
        }
    }
}
