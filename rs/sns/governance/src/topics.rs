#[derive(candid::CandidType, candid::Deserialize, Clone, PartialEq)]
struct Topic<C> {
    name: String,
    description: String,
    content: C,
    nested_topics: Vec<Topic<C>>,
    critical: bool,
}

#[derive(candid::CandidType, candid::Deserialize, Clone, PartialEq)]
struct TopicContent {
    built_in_proposals: Vec<u64>,
}

#[derive(candid::CandidType, candid::Deserialize, Clone, PartialEq)]
struct TopicContentWithGenericProposals {
    built_in_proposals: Vec<u64>,
    generic_proposals: Vec<u64>,
}

pub(crate) fn topics() -> Vec<Topic<TopicContent>> {
    use crate::types::native_action_ids::{
        ADD_GENERIC_NERVOUS_SYSTEM_FUNCTION, ADVANCE_SNS_TARGET_VERSION, DEREGISTER_DAPP_CANISTERS,
        MANAGE_DAPP_CANISTER_SETTINGS, MANAGE_LEDGER_PARAMETERS, MANAGE_NERVOUS_SYSTEM_PARAMETERS,
        MANAGE_SNS_METADATA, MINT_SNS_TOKENS, MOTION, REGISTER_DAPP_CANISTERS,
        REMOVE_GENERIC_NERVOUS_SYSTEM_FUNCTION, TRANSFER_SNS_TREASURY_FUNDS,
        UPGRADE_SNS_CONTROLLED_CANISTER, UPGRADE_SNS_TO_NEXT_VERSION,
    };

    vec![
        Topic::<TopicContent> {
            name: "Non-critical proposals".to_string(),
            description: "All proposals that are not considered \"critical\".".to_string(),
            content: TopicContent {
                built_in_proposals: vec![],
            },
            nested_topics: vec![
                Topic::<TopicContent> {
                    name: "DAO community settings".to_string(),
                    description: "Proposals to set the direction of the DAO by tokenomics & branding, such as the name and description, token name etc".to_string(),
                    content: TopicContent {
                        built_in_proposals: vec![
                            MANAGE_NERVOUS_SYSTEM_PARAMETERS,
                            MANAGE_LEDGER_PARAMETERS,
                            MANAGE_SNS_METADATA,
                        ],
                    },
                    nested_topics: vec![],
                    critical: false,
                },
                Topic::<TopicContent> {
                    name: "SNS framework management".to_string(),
                    description: "Proposals to upgrade and manage the SNS DAO framework.".to_string(),
                    content: TopicContent {
                        built_in_proposals: vec![
                            UPGRADE_SNS_TO_NEXT_VERSION,
                            ADVANCE_SNS_TARGET_VERSION,
                        ],
                    },
                    nested_topics: vec![],
                    critical: false,
                },
                Topic::<TopicContent> {
                    name: "Dapp canister management".to_string(),
                    description: "Proposals to upgrade the registered dapp canisters and dapp upgrades via built-in or custom logic and updates to frontend assets.".to_string(),
                    content: TopicContent {
                        built_in_proposals: vec![
                            UPGRADE_SNS_CONTROLLED_CANISTER,
                            REGISTER_DAPP_CANISTERS,
                            MANAGE_DAPP_CANISTER_SETTINGS,
                        ],
                    },
                    nested_topics: vec![],
                    critical: false,
                },
                Topic::<TopicContent> {
                    name: "Application Business Logic".to_string(),
                    description: "Proposals that are custom to what the governed dapp requires.".to_string(),
                    content: TopicContent {
                        built_in_proposals: vec![],
                    },
                    nested_topics: vec![],
                    critical: false,
                },
                Topic::<TopicContent> {
                    name: "Governance".to_string(),
                    description: "Proposals that represent community polls or other forms of community opinion but don’t have any immediate effect in terms of code changes.".to_string(),
                    content: TopicContent {
                        built_in_proposals: vec![MOTION],
                    },
                    nested_topics: vec![],
                    critical: false,
                }
            ],
            critical: false,
        },
        Topic::<TopicContent> {
            name: "Treasury & asset management".to_string(),
            description: "Proposals to move and manage assets that are DAO-owned, including tokens in the treasury, tokens in liquidity pools, or DAO-owned neurons.".to_string(),
            content: TopicContent {
                built_in_proposals: vec![
                    TRANSFER_SNS_TREASURY_FUNDS,
                    MINT_SNS_TOKENS,
                ],
            },
            nested_topics: vec![],
            critical: true,
        },
        Topic::<TopicContent> {
            name: "Critical Dapp Operations".to_string(),
            description: "Proposals to execute critical operations on dapps, such as adding or removing dapps from the SNS, or executing custom logic on dapps.".to_string(),
            content: TopicContent {
                built_in_proposals: vec![
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
