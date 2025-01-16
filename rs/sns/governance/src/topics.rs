use crate::types::native_action_ids;
use crate::{governance::Governance, pb::v1::nervous_system_function::FunctionType};
use ic_sns_governance_api::pb::v1 as api;
use ic_sns_governance_api::topics::{
    BuiltInAndGenericFunctions, BuiltInFunctions, Topic, TopicInfo,
};
use itertools::Itertools;
use std::collections::HashMap;

/// Returns an exhaustive list of topic descriptions, each corresponding to a topic.
/// Topics may be nested within other topics, and each topic may have a list of built-in functions that are categorized within that topic.
pub fn topic_descriptions() -> Vec<TopicInfo<BuiltInFunctions>> {
    use crate::types::native_action_ids::{
        ADD_GENERIC_NERVOUS_SYSTEM_FUNCTION, ADVANCE_SNS_TARGET_VERSION, DEREGISTER_DAPP_CANISTERS,
        MANAGE_DAPP_CANISTER_SETTINGS, MANAGE_LEDGER_PARAMETERS, MANAGE_NERVOUS_SYSTEM_PARAMETERS,
        MANAGE_SNS_METADATA, MINT_SNS_TOKENS, MOTION, REGISTER_DAPP_CANISTERS,
        REMOVE_GENERIC_NERVOUS_SYSTEM_FUNCTION, TRANSFER_SNS_TREASURY_FUNDS,
        UPGRADE_SNS_CONTROLLED_CANISTER, UPGRADE_SNS_TO_NEXT_VERSION,
    };

    vec![
        TopicInfo::<BuiltInFunctions> {
            topic: Topic::NonCriticalProposals,
            name: "Non-critical proposals".to_string(),
            description: "All proposals that are not considered \"critical\".".to_string(),
            content: BuiltInFunctions {
                built_in_functions: vec![],
            },
            nested_topics: vec![
                TopicInfo::<BuiltInFunctions> {
                    topic: Topic::DaoCommunitySettings,
                    name: "DAO community settings".to_string(),
                    description: "Proposals to set the direction of the DAO by tokenomics & branding, such as the name and description, token name etc".to_string(),
                    content: BuiltInFunctions {
                        built_in_functions: vec![
                            MANAGE_NERVOUS_SYSTEM_PARAMETERS,
                            MANAGE_LEDGER_PARAMETERS,
                            MANAGE_SNS_METADATA,
                        ],
                    },
                    nested_topics: vec![],
                    critical: false,
                },
                TopicInfo::<BuiltInFunctions> {
                    topic: Topic::SnsFrameworkManagement,
                    name: "SNS framework management".to_string(),
                    description: "Proposals to upgrade and manage the SNS DAO framework.".to_string(),
                    content: BuiltInFunctions {
                        built_in_functions: vec![
                            UPGRADE_SNS_TO_NEXT_VERSION,
                            ADVANCE_SNS_TARGET_VERSION,
                        ],
                    },
                    nested_topics: vec![],
                    critical: false,
                },
                TopicInfo::<BuiltInFunctions> {
                    topic: Topic::DappCanisterManagement,
                    name: "Dapp canister management".to_string(),
                    description: "Proposals to upgrade the registered dapp canisters and dapp upgrades via built-in or custom logic and updates to frontend assets.".to_string(),
                    content: BuiltInFunctions {
                        built_in_functions: vec![
                            UPGRADE_SNS_CONTROLLED_CANISTER,
                            REGISTER_DAPP_CANISTERS,
                            MANAGE_DAPP_CANISTER_SETTINGS,
                        ],
                    },
                    nested_topics: vec![],
                    critical: false,
                },
                TopicInfo::<BuiltInFunctions> {
                    topic: Topic::ApplicationBusinessLogic,
                    name: "Application Business Logic".to_string(),
                    description: "Proposals that are custom to what the governed dapp requires.".to_string(),
                    content: BuiltInFunctions {
                        built_in_functions: vec![],
                    },
                    nested_topics: vec![],
                    critical: false,
                },
                TopicInfo::<BuiltInFunctions> {
                    topic: Topic::Governance,
                    name: "Governance".to_string(),
                    description: "Proposals that represent community polls or other forms of community opinion but don’t have any immediate effect in terms of code changes.".to_string(),
                    content: BuiltInFunctions {
                        built_in_functions: vec![MOTION],
                    },
                    nested_topics: vec![],
                    critical: false,
                }
            ],
            critical: false,
        },
        TopicInfo::<BuiltInFunctions> {
            topic: Topic::TreasuryAssetManagement,
            name: "Treasury & asset management".to_string(),
            description: "Proposals to move and manage assets that are DAO-owned, including tokens in the treasury, tokens in liquidity pools, or DAO-owned neurons.".to_string(),
            content: BuiltInFunctions {
                built_in_functions: vec![
                    TRANSFER_SNS_TREASURY_FUNDS,
                    MINT_SNS_TOKENS,
                ],
            },
            nested_topics: vec![],
            critical: true,
        },
        TopicInfo::<BuiltInFunctions> {
            topic: Topic::CriticalDappOperations,
            name: "Critical Dapp Operations".to_string(),
            description: "Proposals to execute critical operations on dapps, such as adding or removing dapps from the SNS, or executing custom logic on dapps.".to_string(),
            content: BuiltInFunctions {
                built_in_functions: vec![
                    DEREGISTER_DAPP_CANISTERS,
                    ADD_GENERIC_NERVOUS_SYSTEM_FUNCTION,
                    REMOVE_GENERIC_NERVOUS_SYSTEM_FUNCTION,
                ],
            },
            nested_topics: vec![],
            critical: true,
        },
    ]
}

impl Governance {
    pub fn list_topics(&self) -> Vec<TopicInfo<BuiltInAndGenericFunctions>> {
        let topic_id_to_function: HashMap<u64, api::NervousSystemFunction> =
            native_action_ids::built_in_functions()
                .into_iter()
                .map(|function| (function.id, api::NervousSystemFunction::from(function)))
                .collect();
        let generic_functions = self
            .proto
            .id_to_nervous_system_functions
            .values()
            .cloned()
            .filter_map(|function| {
                match &function.function_type {
                    Some(FunctionType::GenericNervousSystemFunction(ref generic_function)) => {
                        let topic = generic_function
                            .topic
                            .map(|t| {
                                Topic::try_from(t).unwrap() // todo: handle this better
                            })
                            .unwrap_or(Topic::NonCriticalProposals);
                        let function = api::NervousSystemFunction::from(function);
                        Some((topic, function))
                    }
                    // This case is impossible
                    _ => None,
                }
            })
            .into_group_map();

        fn add_generic_functions(
            topic: TopicInfo<BuiltInFunctions>,
            functions: &HashMap<Topic, Vec<api::NervousSystemFunction>>,
            topic_id_to_function: &HashMap<u64, api::NervousSystemFunction>,
        ) -> TopicInfo<BuiltInAndGenericFunctions> {
            TopicInfo {
                topic: topic.topic,
                name: topic.name,
                description: topic.description,
                content: BuiltInAndGenericFunctions {
                    built_in_functions: topic
                        .content
                        .built_in_functions
                        .into_iter()
                        .map(|id| topic_id_to_function[&id].clone())
                        .collect(),
                    generic_functions: functions
                        .get(&topic.topic)
                        .cloned()
                        .unwrap_or_default()
                        .clone(),
                },
                nested_topics: topic
                    .nested_topics
                    .into_iter()
                    .map(|t| add_generic_functions(t, functions, topic_id_to_function))
                    .collect(),
                critical: topic.critical,
            }
        }

        let topics: Vec<TopicInfo<BuiltInFunctions>> = topic_descriptions();

        topics
            .into_iter()
            .map(|t| add_generic_functions(t, &generic_functions, &topic_id_to_function))
            .collect()
    }
}
