use crate::{
    extensions,
    extensions::{ExtensionOperationSpec, get_extension_operation_spec_from_cache},
    governance::Governance,
    logs::ERROR,
    pb::v1::{self as pb, NervousSystemFunction, nervous_system_function::FunctionType},
    storage::list_registered_extensions_from_cache,
    types::native_action_ids::{self, SET_TOPICS_FOR_CUSTOM_PROPOSALS_ACTION},
};
use ic_base_types::CanisterId;
use ic_canister_log::log;
use ic_sns_governance_api::pb::v1::topics::Topic;
use ic_sns_governance_proposal_criticality::ProposalCriticality;
use itertools::Itertools;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt,
};

#[derive(Debug, candid::CandidType, candid::Deserialize, Clone, PartialEq)]
pub struct RegisteredExtensionOperationSpec {
    pub canister_id: CanisterId,
    pub spec: ExtensionOperationSpec,
}

/// Each topic has some information associated with it. This information is for the benefit of the user but has
/// no effect on the behavior of the SNS.
#[derive(Debug, candid::CandidType, candid::Deserialize, Clone, PartialEq)]
pub struct TopicInfo<C> {
    pub topic: Topic,
    pub name: String,
    pub description: String,
    pub functions: C,
    pub extension_operations: Vec<RegisteredExtensionOperationSpec>,
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
/// Each topic may have a list of built-in functions that are categorized within that topic.
pub fn topic_descriptions() -> [TopicInfo<NativeFunctions>; 7] {
    use crate::types::native_action_ids::{
        ADD_GENERIC_NERVOUS_SYSTEM_FUNCTION, ADVANCE_SNS_TARGET_VERSION, DEREGISTER_DAPP_CANISTERS,
        MANAGE_DAPP_CANISTER_SETTINGS, MANAGE_LEDGER_PARAMETERS, MANAGE_NERVOUS_SYSTEM_PARAMETERS,
        MANAGE_SNS_METADATA, MINT_SNS_TOKENS, MOTION, REGISTER_DAPP_CANISTERS, REGISTER_EXTENSION,
        REMOVE_GENERIC_NERVOUS_SYSTEM_FUNCTION, TRANSFER_SNS_TREASURY_FUNDS, UPGRADE_EXTENSION,
        UPGRADE_SNS_CONTROLLED_CANISTER, UPGRADE_SNS_TO_NEXT_VERSION,
    };

    [
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
            extension_operations: vec![],
            is_critical: true,
        },
        TopicInfo::<NativeFunctions> {
            topic: Topic::SnsFrameworkManagement,
            name: "SNS framework management".to_string(),
            description: "Proposals to upgrade and manage the SNS DAO framework.".to_string(),
            functions: NativeFunctions {
                native_functions: vec![
                    UPGRADE_SNS_TO_NEXT_VERSION,
                    ADVANCE_SNS_TARGET_VERSION,
                ],
            },
            extension_operations: vec![],
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
            extension_operations: vec![],
            is_critical: false,
        },
        TopicInfo::<NativeFunctions> {
            topic: Topic::ApplicationBusinessLogic,
            name: "Application Business Logic".to_string(),
            description: "Proposals that are custom to what the governed dapp requires.".to_string(),
            functions: NativeFunctions {
                native_functions: vec![],
            },
            extension_operations: vec![],
            is_critical: false,
        },
        TopicInfo::<NativeFunctions> {
            topic: Topic::Governance,
            name: "Governance".to_string(),
            description: "Proposals that represent community polls or other forms of community opinion but don't have any immediate effect in terms of code changes.".to_string(),
            functions: NativeFunctions {
                native_functions: vec![MOTION],
            },
            extension_operations: vec![],
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
            extension_operations: vec![],
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
                    SET_TOPICS_FOR_CUSTOM_PROPOSALS_ACTION,
                    REGISTER_EXTENSION,
                    UPGRADE_EXTENSION,
                ],
            },
            extension_operations: vec![],
            is_critical: true,
        },
    ]
}

impl Governance {
    // TODO(NNS1-4036): List all registered extensions in their topic, which would require a cache
    // We would need to iterate through registered extensions to find all the different
    // operations that they support?  And Add something to TopicInfo for this.
    pub fn list_topics(&self) -> ListTopicsResponse {
        let mut uncategorized_functions = vec![];

        let function_id_to_functions: HashMap<u64, NervousSystemFunction> =
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

        let registered_extensions = list_registered_extensions_from_cache();
        let all_registered_operations: BTreeMap<Topic, Vec<RegisteredExtensionOperationSpec>> =
            registered_extensions
                .into_iter()
                .flat_map(|(canister_id, extension_spec)| {
                    let operations = extension_spec.all_operations();
                    operations.into_values().map(move |operation| {
                        let topic = Topic::try_from(operation.topic).expect("Topic is unknown");
                        let registered_spec = RegisteredExtensionOperationSpec {
                            canister_id,
                            spec: operation,
                        };

                        (topic, registered_spec)
                    })
                })
                .into_group_map()
                .into_iter()
                .collect();

        let topics = topic_descriptions()
            .map(|topic| TopicInfo {
                topic: topic.topic,
                name: topic.name,
                description: topic.description,
                functions: NervousSystemFunctions {
                    native_functions: topic
                        .functions
                        .native_functions
                        .into_iter()
                        .map(|id| function_id_to_functions[&id].clone())
                        .collect(),
                    custom_functions: custom_functions
                        .get(&topic.topic)
                        .cloned()
                        .unwrap_or_default()
                        .clone(),
                },
                extension_operations: all_registered_operations
                    .get(&topic.topic)
                    .cloned()
                    .unwrap_or_default(),
                is_critical: topic.is_critical,
            })
            .to_vec();

        ListTopicsResponse {
            topics,
            uncategorized_functions,
        }
    }

    pub fn get_topic_and_criticality_for_action(
        &self,
        action: &pb::proposal::Action,
    ) -> Result<(Option<pb::Topic>, ProposalCriticality), String> {
        if let Some(topic) = pb::Topic::get_topic_for_native_action(action) {
            return Ok((Some(topic), topic.proposal_criticality()));
        };

        // While these are "native actions", they should return an error if the name of the function
        // does not map to a known operation spec.
        if let pb::proposal::Action::ExecuteExtensionOperation(execute_extension_operation) = action
        {
            // NOTE: This will not work if the proposal has not been validated already, since that
            // also serves to populate the cache.  If the cache is unpopulated, then the action
            // will not be found.
            let spec = get_extension_operation_spec_from_cache(execute_extension_operation)?;
            let topic = spec.topic;
            let criticality = topic.proposal_criticality();
            return Ok((Some(topic), criticality));
        }

        let action_code = u64::from(action);

        let Some(function) = self.proto.id_to_nervous_system_functions.get(&action_code) else {
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
            // Fall back to default proposal criticality (if a topic isn't defined).
            return Ok((None, ProposalCriticality::default()));
        };

        let Ok(topic) = pb::Topic::try_from(custom_proposal_topic_id) else {
            return Err(format!("Invalid topic ID {custom_proposal_topic_id}."));
        };

        Ok((Some(topic), topic.proposal_criticality()))
    }
}

impl pb::Governance {
    fn custom_functions_to_topics_impl(
        id_to_nervous_system_functions: &BTreeMap<u64, NervousSystemFunction>,
    ) -> BTreeMap<u64, (String, Option<pb::Topic>)> {
        id_to_nervous_system_functions
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

    pub fn get_custom_functions_for_topic(
        id_to_nervous_system_functions: &BTreeMap<u64, NervousSystemFunction>,
        topic: pb::Topic,
    ) -> BTreeSet<u64> {
        Self::custom_functions_to_topics_impl(id_to_nervous_system_functions)
            .iter()
            .filter_map(|(function_id, (_, this_topic))| {
                let Some(this_topic) = this_topic else {
                    return None;
                };

                if *this_topic == topic {
                    Some(*function_id)
                } else {
                    None
                }
            })
            .collect()
    }

    /// For each custom function ID, returns a pair (`function_name`, `topic`).
    pub fn custom_functions_to_topics(&self) -> BTreeMap<u64, (String, Option<pb::Topic>)> {
        Self::custom_functions_to_topics_impl(&self.id_to_nervous_system_functions)
    }
}

impl pb::Topic {
    pub fn is_critical(&self) -> bool {
        // Handled explicitly to avoid any doubts.
        //
        // We used to fall back to non-critical proposal criticality for backward compatibility,
        // since when custom proposals were introduced, they were not categorized into topics
        // and were all considered non-critical. Since the SNS now enforces that all newly submitted
        // proposals are have topics, their criticality is guaranteed to be explicitly defined
        // (by the topic). Note that for native proposals, the criticality needs to be defined
        // via the topic assigned statically in `Governance::topic_descriptions`. We take
        // some measures to enforce that all native functions have topics. If this assumption
        // is still somehow violated, we now err on the side of caution.
        if *self == Self::Unspecified {
            return true;
        }

        topic_descriptions()
            .iter()
            .any(|topic| *self == Self::from(topic.topic) && topic.is_critical)
    }

    pub fn is_non_critical(&self) -> bool {
        !self.is_critical()
    }

    pub fn proposal_criticality(&self) -> ProposalCriticality {
        if self.is_critical() {
            ProposalCriticality::Critical
        } else {
            ProposalCriticality::Normal
        }
    }

    pub fn native_functions(&self) -> BTreeSet<u64> {
        topic_descriptions()
            .iter()
            .flat_map(|topic_info| {
                let this_topic = Self::from(topic_info.topic);

                if this_topic != *self {
                    return vec![];
                }

                topic_info.functions.native_functions.clone()
            })
            .collect()
    }

    pub fn get_topic_for_native_action(action: &pb::proposal::Action) -> Option<Self> {
        // Check if the topic comes from the extension spec.
        if let pb::proposal::Action::RegisterExtension(pb::RegisterExtension {
            chunked_canister_wasm:
                Some(pb::ChunkedCanisterWasm {
                    wasm_module_hash, ..
                }),
            ..
        }) = action
            && let Ok(extension_spec) = extensions::validate_extension_wasm(wasm_module_hash)
        {
            return Some(extension_spec.topic);
        }

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

impl fmt::Display for pb::Topic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let topic_str = match self {
            Self::Unspecified => "Unspecified",
            Self::DaoCommunitySettings => "DaoCommunitySettings",
            Self::SnsFrameworkManagement => "SnsFrameworkManagement",
            Self::DappCanisterManagement => "DappCanisterManagement",
            Self::ApplicationBusinessLogic => "ApplicationBusinessLogic",
            Self::Governance => "Governance",
            Self::TreasuryAssetManagement => "TreasuryAssetManagement",
            Self::CriticalDappOperations => "CriticalDappOperations",
        };
        write!(f, "{topic_str}")
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::types::native_action_ids::nervous_system_functions;
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
                "Topic not defined for native proposal '{native_function_name}' with ID {native_function_id}.",
            )
        }

        assert_eq!(
            native_functions_with_topic,
            BTreeSet::new(),
            "Some native proposal topics were defined for non-native proposals: {native_functions_with_topic:?}",
        )
    }
}
