use crate::{governance::EXECUTE_NNS_FUNCTION_PAYLOAD_LISTING_BYTES_MAX, pb::v1 as pb};

use candid::{Int, Nat};
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_governance_api as api;
use std::collections::{BTreeSet, HashMap};

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct ProposalDisplayOptions {
    omit_large_fields_requested: bool,
    show_self_describing_action: bool,
    show_action: bool,
    multi_query: bool,
}

impl ProposalDisplayOptions {
    pub fn for_list_proposals(
        omit_large_fields_requested: bool,
        return_self_describing_action: bool,
    ) -> Self {
        Self {
            omit_large_fields_requested,
            show_self_describing_action: return_self_describing_action,
            show_action: !return_self_describing_action,
            multi_query: true,
        }
    }

    pub fn for_get_pending_proposals(return_self_describing_action: bool) -> Self {
        Self {
            omit_large_fields_requested: false,
            show_self_describing_action: return_self_describing_action,
            show_action: !return_self_describing_action,
            multi_query: true,
        }
    }

    pub fn for_get_proposal_info() -> Self {
        Self {
            omit_large_fields_requested: false,
            show_self_describing_action: true,
            show_action: true,
            multi_query: false,
        }
    }

    pub fn show_self_describing_action(&self) -> bool {
        self.show_self_describing_action
    }

    pub fn show_action(&self) -> bool {
        self.show_action
    }

    pub fn omit_large_execute_nns_function_payload(&self) -> bool {
        self.multi_query
    }

    pub fn omit_create_service_nervous_system_large_fields(&self) -> bool {
        self.omit_large_fields_requested && self.multi_query
    }
}

fn convert_execute_nns_function(
    item: &pb::ExecuteNnsFunction,
    omit_large_fields: bool,
) -> api::ExecuteNnsFunction {
    let pb::ExecuteNnsFunction {
        nns_function,
        payload,
    } = item;

    let nns_function = *nns_function;
    let payload =
        if omit_large_fields && payload.len() > EXECUTE_NNS_FUNCTION_PAYLOAD_LISTING_BYTES_MAX {
            vec![]
        } else {
            payload.clone()
        };

    api::ExecuteNnsFunction {
        nns_function,
        payload,
    }
}

fn convert_install_code(item: &pb::InstallCode) -> api::InstallCode {
    let pb::InstallCode {
        canister_id,
        install_mode,
        wasm_module: _,
        arg: _,
        skip_stopping_before_installing,
        wasm_module_hash,
        arg_hash,
    } = item;

    let canister_id = *canister_id;
    let install_mode = *install_mode;
    let skip_stopping_before_installing = *skip_stopping_before_installing;
    let wasm_module_hash = wasm_module_hash.clone();
    let arg_hash = arg_hash.clone();

    api::InstallCode {
        canister_id,
        install_mode,
        skip_stopping_before_installing,
        wasm_module_hash,
        arg_hash,
    }
}

fn convert_ledger_parameters(
    item: &pb::create_service_nervous_system::LedgerParameters,
    omit_large_fields: bool,
) -> api::create_service_nervous_system::LedgerParameters {
    let pb::create_service_nervous_system::LedgerParameters {
        transaction_fee,
        token_name,
        token_symbol,
        token_logo,
    } = item;

    let transaction_fee = *transaction_fee;
    let token_name = token_name.clone();
    let token_symbol = token_symbol.clone();

    let token_logo = if omit_large_fields {
        None
    } else {
        token_logo.clone()
    };

    api::create_service_nervous_system::LedgerParameters {
        transaction_fee,
        token_name,
        token_symbol,
        token_logo,
    }
}

fn convert_create_service_nervous_system(
    item: &pb::CreateServiceNervousSystem,
    omit_large_fields: bool,
) -> api::CreateServiceNervousSystem {
    let pb::CreateServiceNervousSystem {
        name,
        description,
        url,
        logo,
        fallback_controller_principal_ids,
        dapp_canisters,
        initial_token_distribution,
        swap_parameters,
        ledger_parameters,
        governance_parameters,
    } = item;

    let name = name.clone();
    let description = description.clone();
    let url = url.clone();
    let fallback_controller_principal_ids = fallback_controller_principal_ids.clone();
    let dapp_canisters = dapp_canisters.clone();
    let initial_token_distribution = initial_token_distribution.clone().map(|x| x.into());
    let swap_parameters = swap_parameters.clone().map(|x| x.into());
    let governance_parameters = governance_parameters.clone().map(|x| x.into());

    let logo = if omit_large_fields {
        None
    } else {
        logo.clone()
    };
    let ledger_parameters = ledger_parameters
        .as_ref()
        .map(|ledger_parameters| convert_ledger_parameters(ledger_parameters, omit_large_fields));

    api::CreateServiceNervousSystem {
        name,
        description,
        url,
        logo,
        fallback_controller_principal_ids,
        dapp_canisters,
        initial_token_distribution,
        swap_parameters,
        ledger_parameters,
        governance_parameters,
    }
}

fn convert_action(
    item: &pb::proposal::Action,
    display_options: ProposalDisplayOptions,
) -> api::proposal::Action {
    match item {
        // Trivial conversions
        pb::proposal::Action::ManageNeuron(v) => {
            api::proposal::Action::ManageNeuron(Box::new(v.as_ref().clone().into()))
        }
        pb::proposal::Action::ManageNetworkEconomics(v) => {
            api::proposal::Action::ManageNetworkEconomics(v.clone().into())
        }
        pb::proposal::Action::Motion(v) => api::proposal::Action::Motion(v.clone().into()),
        pb::proposal::Action::ApproveGenesisKyc(v) => {
            api::proposal::Action::ApproveGenesisKyc(v.clone().into())
        }
        pb::proposal::Action::AddOrRemoveNodeProvider(v) => {
            api::proposal::Action::AddOrRemoveNodeProvider(v.clone().into())
        }
        pb::proposal::Action::RewardNodeProvider(v) => {
            api::proposal::Action::RewardNodeProvider(v.clone().into())
        }
        pb::proposal::Action::SetDefaultFollowees(v) => {
            api::proposal::Action::SetDefaultFollowees(v.clone().into())
        }
        pb::proposal::Action::RewardNodeProviders(v) => {
            api::proposal::Action::RewardNodeProviders(v.clone().into())
        }
        pb::proposal::Action::RegisterKnownNeuron(v) => {
            api::proposal::Action::RegisterKnownNeuron(v.clone().into())
        }
        pb::proposal::Action::DeregisterKnownNeuron(v) => {
            api::proposal::Action::DeregisterKnownNeuron((*v).into())
        }
        pb::proposal::Action::SetSnsTokenSwapOpenTimeWindow(v) => {
            api::proposal::Action::SetSnsTokenSwapOpenTimeWindow(v.clone().into())
        }
        pb::proposal::Action::OpenSnsTokenSwap(v) => {
            api::proposal::Action::OpenSnsTokenSwap(v.clone().into())
        }
        pb::proposal::Action::StopOrStartCanister(v) => {
            api::proposal::Action::StopOrStartCanister(v.clone().into())
        }
        pb::proposal::Action::UpdateCanisterSettings(v) => {
            api::proposal::Action::UpdateCanisterSettings(v.clone().into())
        }
        pb::proposal::Action::FulfillSubnetRentalRequest(v) => {
            api::proposal::Action::FulfillSubnetRentalRequest(v.clone().into())
        }
        pb::proposal::Action::BlessAlternativeGuestOsVersion(v) => {
            api::proposal::Action::BlessAlternativeGuestOsVersion(v.clone().into())
        }
        pb::proposal::Action::TakeCanisterSnapshot(v) => {
            api::proposal::Action::TakeCanisterSnapshot(v.clone().into())
        }
        pb::proposal::Action::LoadCanisterSnapshot(v) => {
            api::proposal::Action::LoadCanisterSnapshot(v.clone().into())
        }

        // The action types with potentially large fields need to be converted in a way that avoids
        // cloning the action first.
        pb::proposal::Action::InstallCode(v) => {
            api::proposal::Action::InstallCode(convert_install_code(v))
        }
        pb::proposal::Action::ExecuteNnsFunction(v) => {
            api::proposal::Action::ExecuteNnsFunction(convert_execute_nns_function(
                v,
                display_options.omit_large_execute_nns_function_payload(),
            ))
        }
        pb::proposal::Action::CreateServiceNervousSystem(v) => {
            api::proposal::Action::CreateServiceNervousSystem(
                convert_create_service_nervous_system(
                    v,
                    display_options.omit_create_service_nervous_system_large_fields(),
                ),
            )
        }
    }
}

fn convert_self_describing_action(
    item: &pb::SelfDescribingProposalAction,
    omit_create_service_nervous_system_logos: bool,
) -> api::SelfDescribingProposalAction {
    let pb::SelfDescribingProposalAction {
        type_name,
        type_description,
        value,
    } = item;

    let type_name = Some(type_name.clone());
    let type_description = Some(type_description.clone());

    let paths_to_omit = if omit_create_service_nervous_system_logos {
        vec![
            RecordPath {
                fields_names: vec!["logo"],
            },
            RecordPath {
                fields_names: vec!["ledger_parameters", "token_logo"],
            },
        ]
    } else {
        vec![]
    };
    let value = value
        .as_ref()
        .map(|value| convert_self_describing_value(value, paths_to_omit));

    api::SelfDescribingProposalAction {
        type_name,
        type_description,
        value,
    }
}

/// For example, suppose we have
///
/// ```
/// struct Plane {
///     wing: Wing,
///     landing_gear: LandingGear,
/// }
///
/// struct LandingGear {
///    wheel: Wheel,
/// }
///
/// struct Wheel {
///     tire: Tire,
/// }
///
/// let plane: Plane = ...;
/// ```
///
/// To reach the `Tire` from `plane`, we can use the path
/// `vec!["landing_gear", "wheel", "tire"]`, because `plane.landing_gear.wheel.tire`
/// evaluates to the `Tire`.
#[derive(Clone)]
struct RecordPath {
    // Must have at least one element.
    fields_names: Vec<&'static str>,
}

enum OmitAction {
    DoNothing,
    OmitCurrent,
    OmitDescendant(RecordPath),
}

impl RecordPath {
    fn matches(&self, field_name: &str) -> OmitAction {
        let Some((&first, rest)) = self.fields_names.split_first() else {
            // This should never happen, but we handle it anyway.
            return OmitAction::DoNothing;
        };
        if first != field_name {
            return OmitAction::DoNothing;
        }
        if rest.is_empty() {
            return OmitAction::OmitCurrent;
        }
        OmitAction::OmitDescendant(RecordPath {
            fields_names: rest.to_vec(),
        })
    }
}

fn convert_self_describing_field(
    field_name: &str,
    paths_to_omit: Vec<RecordPath>,
    original_value: &pb::SelfDescribingValue,
) -> api::SelfDescribingValue {
    let match_results = paths_to_omit
        .iter()
        .map(|path| path.matches(field_name))
        .collect::<Vec<_>>();
    if match_results
        .iter()
        .any(|result| matches!(result, OmitAction::OmitCurrent))
    {
        return api::SelfDescribingValue::Null;
    }
    let descendant_paths_to_omit = match_results
        .into_iter()
        .filter_map(|result| match result {
            OmitAction::OmitDescendant(path) => Some(path),
            _ => None,
        })
        .collect::<Vec<_>>();
    convert_self_describing_value(original_value, descendant_paths_to_omit)
}

fn convert_self_describing_value(
    item: &pb::SelfDescribingValue,
    paths_to_omit: Vec<RecordPath>,
) -> api::SelfDescribingValue {
    let pb::SelfDescribingValue { value } = item;

    let Some(value) = value else {
        // This should be unreacheable, because we always construct a SelfDescribingValue with a value.
        // Ideally the type should be non-optional, but prost always generates an optional field for
        // messages.
        return api::SelfDescribingValue::Map(HashMap::new());
    };

    match value {
        pb::self_describing_value::Value::Blob(v) => api::SelfDescribingValue::Blob(v.clone()),
        pb::self_describing_value::Value::Text(v) => api::SelfDescribingValue::Text(v.clone()),
        pb::self_describing_value::Value::Nat(v) => {
            let nat = Nat::decode(&mut v.as_slice()).unwrap();
            api::SelfDescribingValue::Nat(nat)
        }
        pb::self_describing_value::Value::Int(v) => {
            let int = Int::decode(&mut v.as_slice()).unwrap();
            api::SelfDescribingValue::Int(int)
        }
        pb::self_describing_value::Value::Null(_) => api::SelfDescribingValue::Null,
        pb::self_describing_value::Value::Bool(v) => api::SelfDescribingValue::Bool(*v),
        pb::self_describing_value::Value::Array(v) => api::SelfDescribingValue::Array(
            v.values
                .iter()
                .map(|value| convert_self_describing_value(value, vec![]))
                .collect(),
        ),

        // This is where `paths_to_omit` takes effect - the resursion (calling
        // `convert_self_describing_value` happens indirectly through
        // `convert_self_describing_field`, which calls `convert_self_describing_value` if the field
        // should not be omitted.
        pb::self_describing_value::Value::Map(v) => api::SelfDescribingValue::Map(
            v.values
                .iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        convert_self_describing_field(k, paths_to_omit.clone(), v),
                    )
                })
                .collect(),
        ),
    }
}

// To avoid cloning large values in production, this is only available in tests. Since multiple
// tests need to convert SelfDescribingValue to `api::SelfDescribingValue`, we define it here rather
// than in each test.
#[cfg(test)]
impl From<pb::SelfDescribingValue> for api::SelfDescribingValue {
    fn from(value: pb::SelfDescribingValue) -> Self {
        convert_self_describing_value(&value, vec![])
    }
}

pub(crate) fn convert_proposal(
    item: &pb::Proposal,
    display_options: ProposalDisplayOptions,
) -> api::Proposal {
    let pb::Proposal {
        title,
        summary,
        url,
        action,
        self_describing_action,
    } = item;

    // Convert (relatively) small fields
    let title = title.clone();
    let summary = summary.clone();
    let url = url.clone();

    let action = if display_options.show_action() {
        action.as_ref().map(|x| convert_action(x, display_options))
    } else {
        None
    };
    let is_create_service_nervous_system_proposal = action.as_ref().is_some_and(|action| {
        matches!(action, api::proposal::Action::CreateServiceNervousSystem(_))
    });
    let self_describing_action = if display_options.show_self_describing_action() {
        self_describing_action
            .as_ref()
            .map(|self_describing_action| {
                convert_self_describing_action(
                    self_describing_action,
                    is_create_service_nervous_system_proposal
                        && display_options.omit_create_service_nervous_system_large_fields(),
                )
            })
    } else {
        None
    };

    api::Proposal {
        title,
        summary,
        url,
        action,
        self_describing_action,
    }
}

fn convert_ballots(
    all_ballots: &HashMap<u64, pb::Ballot>,
    caller_neurons: &BTreeSet<NeuronId>,
) -> HashMap<u64, api::Ballot> {
    let mut ballots = HashMap::new();
    for neuron_id in caller_neurons.iter() {
        if let Some(v) = all_ballots.get(&neuron_id.id) {
            ballots.insert(neuron_id.id, (*v).into());
        }
    }
    ballots
}

pub(crate) fn proposal_data_to_info(
    data: &pb::ProposalData,
    display_options: ProposalDisplayOptions,
    caller_neurons: &BTreeSet<NeuronId>,
    now_seconds: u64,
    voting_period_seconds: impl Fn(pb::Topic) -> u64,
) -> api::ProposalInfo {
    // Calculate derived fields
    let status = data.status() as i32;
    let reward_status = data.reward_status(now_seconds, voting_period_seconds(data.topic())) as i32;
    let deadline_timestamp_seconds =
        Some(data.get_deadline_timestamp_seconds(voting_period_seconds(data.topic())));

    // Trivially convert fields
    let id = data.id;
    let proposer = data.proposer;
    let topic = data.topic() as i32;
    let reject_cost_e8s = data.reject_cost_e8s;
    let proposal_timestamp_seconds = data.proposal_timestamp_seconds;
    let latest_tally = data.latest_tally.map(|x| x.into());
    let decided_timestamp_seconds = data.decided_timestamp_seconds;
    let executed_timestamp_seconds = data.executed_timestamp_seconds;
    let failed_timestamp_seconds = data.failed_timestamp_seconds;
    let failure_reason = data.failure_reason.clone().map(|x| x.into());
    let reward_event_round = data.reward_event_round;
    let derived_proposal_information = data.derived_proposal_information.clone().map(|x| x.into());
    let total_potential_voting_power = data.total_potential_voting_power;

    let proposal = data
        .proposal
        .as_ref()
        .map(|x| convert_proposal(x, display_options));

    // Convert ballots which are potentially large.
    let ballots = convert_ballots(&data.ballots, caller_neurons);

    api::ProposalInfo {
        id,
        proposer,
        reject_cost_e8s,
        proposal,
        proposal_timestamp_seconds,
        ballots,
        latest_tally,
        decided_timestamp_seconds,
        executed_timestamp_seconds,
        failed_timestamp_seconds,
        failure_reason,
        reward_event_round,
        topic,
        status,
        reward_status,
        deadline_timestamp_seconds,
        derived_proposal_information,
        total_potential_voting_power,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::pb::v1::{
        CreateServiceNervousSystem, SelfDescribingProposalAction,
        create_service_nervous_system::LedgerParameters,
    };

    use ic_base_types::PrincipalId;
    use ic_crypto_sha2::Sha256;
    use ic_nervous_system_proto::pb::v1::Image;
    use maplit::hashmap;

    #[test]
    fn test_self_describing_value_conversions() {
        let nat_value = Nat::from(12345_u64);
        let int_value = Int::from(-9876_i64);

        let mut nat_bytes = Vec::new();
        nat_value.encode(&mut nat_bytes).unwrap();

        let mut int_bytes = Vec::new();
        int_value.encode(&mut int_bytes).unwrap();

        let value_pb = pb::SelfDescribingValue {
            value: Some(pb::self_describing_value::Value::Map(
                pb::SelfDescribingValueMap {
                    values: hashmap! {
                        "text_field".to_string() => pb::SelfDescribingValue {
                            value: Some(pb::self_describing_value::Value::Text("some text".to_string())),
                        },
                        "blob_field".to_string() => pb::SelfDescribingValue {
                            value: Some(pb::self_describing_value::Value::Blob(vec![1, 2, 3, 4, 5])),
                        },
                        "nat_field".to_string() => pb::SelfDescribingValue {
                            value: Some(pb::self_describing_value::Value::Nat(nat_bytes.clone())),
                        },
                        "int_field".to_string() => pb::SelfDescribingValue {
                            value: Some(pb::self_describing_value::Value::Int(int_bytes.clone())),
                        },
                        "array_field".to_string() => pb::SelfDescribingValue {
                            value: Some(pb::self_describing_value::Value::Array(pb::SelfDescribingValueArray {
                                values: vec![
                                    pb::SelfDescribingValue {
                                        value: Some(pb::self_describing_value::Value::Text("first".to_string())),
                                    },
                                    pb::SelfDescribingValue {
                                        value: Some(pb::self_describing_value::Value::Text("second".to_string())),
                                    },
                                    pb::SelfDescribingValue {
                                        value: Some(pb::self_describing_value::Value::Blob(vec![10, 20, 30])),
                                    },
                                ],
                            })),
                        },
                        "nested_map_field".to_string() => pb::SelfDescribingValue {
                            value: Some(pb::self_describing_value::Value::Map(pb::SelfDescribingValueMap {
                                values: hashmap! {
                                    "nested_text".to_string() => pb::SelfDescribingValue {
                                        value: Some(pb::self_describing_value::Value::Text("nested value".to_string())),
                                    },
                                    "nested_blob".to_string() => pb::SelfDescribingValue {
                                        value: Some(pb::self_describing_value::Value::Blob(vec![255, 254, 253])),
                                    },
                                    "nested_nat".to_string() => pb::SelfDescribingValue {
                                        value: Some(pb::self_describing_value::Value::Nat(nat_bytes.clone())),
                                    },
                                },
                            })),
                        },
                        "empty_array_field".to_string() => pb::SelfDescribingValue {
                            value: Some(pb::self_describing_value::Value::Array(pb::SelfDescribingValueArray {
                                values: vec![],
                            })),
                        },
                        "empty_map_field".to_string() => pb::SelfDescribingValue {
                            value: Some(pb::self_describing_value::Value::Map(pb::SelfDescribingValueMap {
                                values: hashmap! {},
                            })),
                        },
                        "array_of_maps_field".to_string() => pb::SelfDescribingValue {
                            value: Some(pb::self_describing_value::Value::Array(pb::SelfDescribingValueArray {
                                values: vec![
                                    pb::SelfDescribingValue {
                                        value: Some(pb::self_describing_value::Value::Map(pb::SelfDescribingValueMap {
                                            values: hashmap! {
                                                "key1".to_string() => pb::SelfDescribingValue {
                                                    value: Some(pb::self_describing_value::Value::Text("value1".to_string())),
                                                },
                                            },
                                        })),
                                    },
                                    pb::SelfDescribingValue {
                                        value: Some(pb::self_describing_value::Value::Map(pb::SelfDescribingValueMap {
                                            values: hashmap! {
                                                "key2".to_string() => pb::SelfDescribingValue {
                                                    value: Some(pb::self_describing_value::Value::Text("value2".to_string())),
                                                },
                                            },
                                        })),
                                    },
                                ],
                            })),
                        },
                    },
                },
            )),
        };

        let value_api = api::SelfDescribingValue::from(value_pb);

        assert_eq!(
            value_api,
            api::SelfDescribingValue::Map(hashmap! {
                "text_field".to_string() => api::SelfDescribingValue::Text("some text".to_string()),
                "blob_field".to_string() => api::SelfDescribingValue::Blob(vec![1, 2, 3, 4, 5]),
                "nat_field".to_string() => api::SelfDescribingValue::Nat(nat_value.clone()),
                "int_field".to_string() => api::SelfDescribingValue::Int(int_value.clone()),
                "array_field".to_string() => api::SelfDescribingValue::Array(vec![
                    api::SelfDescribingValue::Text("first".to_string()),
                    api::SelfDescribingValue::Text("second".to_string()),
                    api::SelfDescribingValue::Blob(vec![10, 20, 30]),
                ]),
                "nested_map_field".to_string() => api::SelfDescribingValue::Map(hashmap! {
                    "nested_text".to_string() => api::SelfDescribingValue::Text("nested value".to_string()),
                    "nested_blob".to_string() => api::SelfDescribingValue::Blob(vec![255, 254, 253]),
                    "nested_nat".to_string() => api::SelfDescribingValue::Nat(nat_value.clone()),
                }),
                "empty_array_field".to_string() => api::SelfDescribingValue::Array(vec![]),
                "empty_map_field".to_string() => api::SelfDescribingValue::Map(hashmap! {}),
                "array_of_maps_field".to_string() => api::SelfDescribingValue::Array(vec![
                    api::SelfDescribingValue::Map(hashmap! {
                        "key1".to_string() => api::SelfDescribingValue::Text("value1".to_string()),
                    }),
                    api::SelfDescribingValue::Map(hashmap! {
                        "key2".to_string() => api::SelfDescribingValue::Text("value2".to_string()),
                    }),
                ]),
            })
        );
    }

    #[test]
    fn test_self_describing_value_omit_logos() {
        let create_service_nervous_system = CreateServiceNervousSystem {
            name: Some("some name".to_string()),
            logo: Some(Image {
                base64_encoding: Some("base64 encoding of a logo".to_string()),
            }),
            ledger_parameters: Some(LedgerParameters {
                token_name: Some("some token name".to_string()),
                token_logo: Some(Image {
                    base64_encoding: Some("base64 encoding of a token logo".to_string()),
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let self_describing_action = SelfDescribingProposalAction {
            type_name: "Create Service Nervous System (SNS)".to_string(),
            type_description: "Create a new Service Nervous System (SNS).".to_string(),
            value: Some(pb::SelfDescribingValue::from(create_service_nervous_system)),
        };

        // Sanity check that the self-describing value does have logos when we don't omit them.
        let self_describing_value_with_logos =
            convert_self_describing_action(&self_describing_action, false)
                .value
                .unwrap();
        let map = match self_describing_value_with_logos {
            api::SelfDescribingValue::Map(map) => map,
            _ => panic!("Expected a map"),
        };
        assert_eq!(
            map.get("name").unwrap(),
            &api::SelfDescribingValue::Text("some name".to_string())
        );
        assert_eq!(
            map.get("logo").unwrap(),
            &api::SelfDescribingValue::Map(hashmap! {
                "base64_encoding".to_string() => api::SelfDescribingValue::Text("base64 encoding of a logo".to_string()),
            })
        );
        let ledger_parameters = map.get("ledger_parameters").unwrap();
        let ledger_parameters_map = match ledger_parameters {
            api::SelfDescribingValue::Map(map) => map,
            _ => panic!("Expected a map"),
        };
        assert_eq!(
            ledger_parameters_map.get("token_name").unwrap(),
            &api::SelfDescribingValue::Text("some token name".to_string())
        );
        assert_eq!(
            ledger_parameters_map.get("token_logo").unwrap(),
            &api::SelfDescribingValue::Map(hashmap! {
                "base64_encoding".to_string() => api::SelfDescribingValue::Text("base64 encoding of a token logo".to_string()),
            })
        );

        // Now check that the self-describing value does not have logos when we omit them, while the other fields are still present.
        let self_describing_value_without_logos =
            convert_self_describing_action(&self_describing_action, true)
                .value
                .unwrap();
        let map = match self_describing_value_without_logos {
            api::SelfDescribingValue::Map(map) => map,
            _ => panic!("Expected a map"),
        };
        assert_eq!(
            map.get("name").unwrap(),
            &api::SelfDescribingValue::Text("some name".to_string())
        );
        assert_eq!(map.get("logo"), Some(&api::SelfDescribingValue::Null));
        let ledger_parameters = map.get("ledger_parameters").unwrap();
        let ledger_parameters_map = match ledger_parameters {
            api::SelfDescribingValue::Map(map) => map,
            _ => panic!("Expected a map"),
        };
        assert_eq!(
            ledger_parameters_map.get("token_name").unwrap(),
            &api::SelfDescribingValue::Text("some token name".to_string())
        );
        assert_eq!(
            ledger_parameters_map.get("token_logo"),
            Some(&api::SelfDescribingValue::Null)
        );
    }

    #[test]
    fn install_code_request_to_internal() {
        let test_cases = vec![
            (
                api::InstallCodeRequest {
                    canister_id: Some(PrincipalId::new_user_test_id(1)),
                    install_mode: Some(pb::install_code::CanisterInstallMode::Install as i32),
                    skip_stopping_before_installing: None,
                    wasm_module: Some(vec![1, 2, 3]),
                    arg: Some(vec![]),
                },
                pb::InstallCode {
                    canister_id: Some(PrincipalId::new_user_test_id(1)),
                    install_mode: Some(api::install_code::CanisterInstallMode::Install as i32),
                    skip_stopping_before_installing: None,
                    wasm_module: Some(vec![1, 2, 3]),
                    arg: Some(vec![]),
                    wasm_module_hash: Some(Sha256::hash(&[1, 2, 3]).to_vec()),
                    arg_hash: Some(vec![]),
                },
            ),
            (
                api::InstallCodeRequest {
                    canister_id: Some(PrincipalId::new_user_test_id(1)),
                    install_mode: Some(pb::install_code::CanisterInstallMode::Upgrade as i32),
                    skip_stopping_before_installing: Some(true),
                    wasm_module: Some(vec![1, 2, 3]),
                    arg: Some(vec![4, 5, 6]),
                },
                pb::InstallCode {
                    canister_id: Some(PrincipalId::new_user_test_id(1)),
                    install_mode: Some(api::install_code::CanisterInstallMode::Upgrade as i32),
                    skip_stopping_before_installing: Some(true),
                    wasm_module: Some(vec![1, 2, 3]),
                    arg: Some(vec![4, 5, 6]),
                    wasm_module_hash: Some(Sha256::hash(&[1, 2, 3]).to_vec()),
                    arg_hash: Some(Sha256::hash(&[4, 5, 6]).to_vec()),
                },
            ),
        ];

        for (request, internal) in test_cases {
            assert_eq!(pb::InstallCode::from(request), internal);
        }
    }
}
