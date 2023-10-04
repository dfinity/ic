use super::*;
use crate::{
    pb::v1::{
        governance::{Migration, Migrations},
        proposal::Action,
        settle_community_fund_participation, ExecuteNnsFunction, GovernanceError, Neuron,
        OpenSnsTokenSwap, Proposal, ProposalData, ProposalStatus, SettleCommunityFundParticipation,
        Tally,
    },
    storage::STABLE_NEURON_STORE,
};
use async_trait::async_trait;
use candid::{Decode, Encode};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_base_types::{CanisterId, PrincipalId};
use ic_nervous_system_common::{assert_is_err, assert_is_ok, E8};
use ic_nervous_system_proto::pb::v1::GlobalTimeOfDay;
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_constants::SNS_WASM_CANISTER_ID;
use ic_sns_init::pb::v1::{self as sns_init_pb, SnsInitPayload};
use ic_sns_swap::pb::{
    v1 as sns_swap_pb,
    v1::{NeuronBasketConstructionParameters, Swap},
};
use ic_sns_wasm::pb::v1::{DeployedSns, ListDeployedSnsesRequest, ListDeployedSnsesResponse};
use lazy_static::lazy_static;
use maplit::btreemap;
use std::{
    collections::VecDeque,
    convert::TryFrom,
    string::ToString,
    sync::{Arc, Mutex},
};

mod stake_maturity;

#[test]
fn test_time_warp() {
    let w = TimeWarp { delta_s: 0_i64 };
    assert_eq!(w.apply(100_u64), 100);

    let w = TimeWarp { delta_s: 42_i64 };
    assert_eq!(w.apply(100_u64), 142);

    let w = TimeWarp { delta_s: -42_i64 };
    assert_eq!(w.apply(100_u64), 58);
}

const PARAMS: sns_swap_pb::Params = sns_swap_pb::Params {
    max_icp_e8s: 1000 * E8,
    min_icp_e8s: 10 * E8,
    min_participant_icp_e8s: 5 * E8,
    max_participant_icp_e8s: 1000 * E8,
    min_participants: 2,
    sns_token_e8s: 1000 * E8,
    swap_due_timestamp_seconds: 2524629600, // midnight, Jan 1, 2050
    neuron_basket_construction_parameters: Some(NeuronBasketConstructionParameters {
        count: 3,
        dissolve_delay_interval_seconds: 7890000, // 3 months
    }),
    sale_delay_seconds: None,
};

type CanisterMethodCallResult = Result<Vec<u8>, (Option<i32>, String)>;

lazy_static! {
    static ref PRINCIPAL_ID_1: PrincipalId = PrincipalId::new_user_test_id(1);
    static ref PRINCIPAL_ID_2: PrincipalId = PrincipalId::new_user_test_id(2);
    static ref TARGET_SWAP_CANISTER_ID: CanisterId = CanisterId::from_u64(435106);
    static ref OPEN_SNS_TOKEN_SWAP: OpenSnsTokenSwap = OpenSnsTokenSwap {
        target_swap_canister_id: Some((*TARGET_SWAP_CANISTER_ID).into()),
        params: Some(PARAMS.clone()),
        community_fund_investment_e8s: Some(500),
    };
    static ref SWAP_INIT: sns_swap_pb::Init = sns_swap_pb::Init {
        transaction_fee_e8s: Some(12_345),
        neuron_minimum_stake_e8s: Some(123_456_789),
        ..Default::default() // Not realistic, but good enough for tests.
    };

    static ref EXPECTED_LIST_DEPLOYED_SNSES: (ExpectedCallCanisterMethodCallArguments<'static>, CanisterMethodCallResult) =
        (
            ExpectedCallCanisterMethodCallArguments {
                target: SNS_WASM_CANISTER_ID,
                method_name: "list_deployed_snses",
                request: Encode!(&ListDeployedSnsesRequest {}).unwrap(),
            },
            Ok(Encode!(&ListDeployedSnsesResponse {
                instances: vec![DeployedSns {
                    swap_canister_id: Some((*TARGET_SWAP_CANISTER_ID).into()),
                    ..Default::default()
                },]
            })
               .unwrap()),
        );
}

struct StubIcpLedger {}
#[async_trait]
impl IcpLedger for StubIcpLedger {
    async fn transfer_funds(
        &self,
        _amount_e8s: u64,
        _fee_e8s: u64,
        _from_subaccount: Option<Subaccount>,
        _to: AccountIdentifier,
        _memo: u64,
    ) -> Result<u64, NervousSystemError> {
        unimplemented!()
    }

    async fn total_supply(&self) -> Result<Tokens, NervousSystemError> {
        unimplemented!()
    }

    async fn account_balance(
        &self,
        _account: AccountIdentifier,
    ) -> Result<Tokens, NervousSystemError> {
        unimplemented!()
    }

    fn canister_id(&self) -> CanisterId {
        unimplemented!()
    }
}

struct StubCMC {}
#[async_trait]
impl CMC for StubCMC {
    async fn neuron_maturity_modulation(&mut self) -> Result<i32, String> {
        unimplemented!()
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
struct ExpectedCallCanisterMethodCallArguments<'a> {
    target: CanisterId,
    method_name: &'a str,
    request: Vec<u8>,
}

#[allow(clippy::type_complexity)]
struct MockEnvironment<'a> {
    expected_call_canister_method_calls: Arc<
        Mutex<
            VecDeque<(
                ExpectedCallCanisterMethodCallArguments<'a>,
                Result<Vec<u8>, (Option<i32>, String)>,
            )>,
        >,
    >,
    now: Arc<Mutex<u64>>,
}

impl Default for MockEnvironment<'_> {
    fn default() -> Self {
        Self {
            expected_call_canister_method_calls: Arc::new(Mutex::new(VecDeque::from([
                EXPECTED_LIST_DEPLOYED_SNSES.clone(),
                (
                    ExpectedCallCanisterMethodCallArguments {
                        target: *TARGET_SWAP_CANISTER_ID,
                        method_name: "get_state",
                        request: Encode!(&sns_swap_pb::GetStateRequest {}).unwrap(),
                    },
                    Ok(Encode!(&sns_swap_pb::GetStateResponse {
                        swap: Some(Swap {
                            init: Some(SWAP_INIT.clone()),
                            ..Default::default() // Not realistic, but good enough for test.
                        }),
                        derived: None, // Not realistic, but good enough for test.
                    })
                    .unwrap()),
                ),
            ]))),
            now: Arc::new(Mutex::new(0)),
        }
    }
}

#[async_trait]
impl Environment for MockEnvironment<'_> {
    fn now(&self) -> u64 {
        *self.now.lock().unwrap()
    }

    fn random_u64(&mut self) -> u64 {
        unimplemented!();
    }

    fn random_byte_array(&mut self) -> [u8; 32] {
        unimplemented!();
    }

    fn execute_nns_function(
        &self,
        _proposal_id: u64,
        _update: &ExecuteNnsFunction,
    ) -> Result<(), GovernanceError> {
        unimplemented!();
    }

    fn heap_growth_potential(&self) -> HeapGrowthPotential {
        unimplemented!();
    }

    async fn call_canister_method(
        &mut self,
        target: CanisterId,
        method_name: &str,
        request: Vec<u8>,
    ) -> Result<Vec<u8>, (Option<i32>, String)> {
        let (expected_arguments, result) = self
            .expected_call_canister_method_calls
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| {
                panic!(
                    "Unexpected canister method call:\n\
                     method_name = {}\n\
                     target = {}\n\
                     request.len() = {}",
                    method_name,
                    target,
                    request.len(),
                )
            });

        let decode_request_bytes = |bytes| {
            match method_name {
                "get_state" => {
                    match Decode!(bytes, sns_swap_pb::GetStateRequest) {
                        Ok(ok) => format!("{:#?}", ok),
                        Err(err) => format!(
                            "Unable to decode request bytes as GetStateRequest because of {:?}: {}",
                            err, default_request_bytes_format(bytes),
                        ),
                    }
                }

                "list_deployed_snses" => {
                    match Decode!(bytes, ListDeployedSnsesRequest) {
                        Ok(ok) => format!("{:#?}", ok),
                        Err(err) => format!(
                            "Unable to decode request bytes as ListDeployedSnsesRequest because of {:?}: {}",
                            err, default_request_bytes_format(bytes),
                        ),
                    }
                }

                _ => default_request_bytes_format(bytes)
            }
        };
        fn default_request_bytes_format(bytes: &[u8]) -> String {
            let truncated = if bytes.len() > 16 {
                let head = &bytes[..8];
                let tail = &bytes[(bytes.len() - 8)..];
                format!("head = {:?}, tail = {:?}", head, tail)
            } else {
                format!("content = {:?}", bytes)
            };

            format!("<len = {}, {}>", bytes.len(), truncated)
        }

        // Compare incoming arguments vs. expected.
        assert_eq!(
            method_name, expected_arguments.method_name,
            "{:#?}",
            expected_arguments
        );
        assert_eq!(
            target, expected_arguments.target,
            "{:#?}",
            expected_arguments
        );
        assert!(
            // Because these are Vec<u8>, assert_eq would generate feedback
            // that's very hard to decipher, so we skip that by using
            // assert! plus the == operator instead.
            request == expected_arguments.request,
            "{}\nvs.\n{}",
            decode_request_bytes(&request),
            decode_request_bytes(&expected_arguments.request),
        );

        result
    }
}

#[tokio::test]
async fn validate_open_sns_token_swap_ok() {
    let result =
        validate_open_sns_token_swap(&OPEN_SNS_TOKEN_SWAP, &mut MockEnvironment::default()).await;
    assert!(result.is_ok(), "{:#?}", result);
}

#[tokio::test]
async fn validate_open_sns_token_swap_missing_target_swap_canister_id() {
    assert_is_err!(
        validate_open_sns_token_swap(
            &OpenSnsTokenSwap {
                target_swap_canister_id: None,
                ..OPEN_SNS_TOKEN_SWAP.clone()
            },
            &mut MockEnvironment::default(),
        )
        .await
    );
}

#[tokio::test]
async fn validate_open_sns_token_swap_params_no_params() {
    assert_is_err!(
        validate_open_sns_token_swap(
            &OpenSnsTokenSwap {
                params: None,
                ..OPEN_SNS_TOKEN_SWAP.clone()
            },
            &mut MockEnvironment::default(),
        )
        .await
    );
}

#[tokio::test]
async fn validate_open_sns_token_swap_sns_wasm_list_deployed_snses_fail() {
    assert_is_err!(
        validate_open_sns_token_swap(
            &OPEN_SNS_TOKEN_SWAP,
            &mut MockEnvironment {
                expected_call_canister_method_calls: Arc::new(Mutex::new(VecDeque::from([(
                    ExpectedCallCanisterMethodCallArguments {
                        target: SNS_WASM_CANISTER_ID,
                        method_name: "list_deployed_snses",
                        request: Encode!(&ListDeployedSnsesRequest {}).unwrap(),
                    },
                    Err((None, "derp".to_string())),
                ),]),)),
                now: Arc::new(Mutex::new(0))
            },
        )
        .await
    );
}

#[tokio::test]
async fn validate_open_sns_token_swap_unknown_swap() {
    assert_is_err!(
        validate_open_sns_token_swap(
            &OPEN_SNS_TOKEN_SWAP,
            &mut MockEnvironment {
                expected_call_canister_method_calls: Arc::new(Mutex::new(VecDeque::from([(
                    ExpectedCallCanisterMethodCallArguments {
                        target: SNS_WASM_CANISTER_ID,
                        method_name: "list_deployed_snses",
                        request: Encode!(&ListDeployedSnsesRequest {}).unwrap(),
                    },
                    Ok(Encode!(&ListDeployedSnsesResponse { instances: vec![] }).unwrap()),
                )]))),
                now: Arc::new(Mutex::new(0))
            },
        )
        .await
    );
}

#[tokio::test]
async fn validate_open_sns_token_swap_swap_get_state_fail() {
    assert_is_err!(
        validate_open_sns_token_swap(
            &OPEN_SNS_TOKEN_SWAP,
            &mut MockEnvironment {
                expected_call_canister_method_calls: Arc::new(Mutex::new(VecDeque::from([
                    EXPECTED_LIST_DEPLOYED_SNSES.clone(),
                    (
                        ExpectedCallCanisterMethodCallArguments {
                            target: *TARGET_SWAP_CANISTER_ID,
                            method_name: "get_state",
                            request: Encode!(&sns_swap_pb::GetStateRequest {}).unwrap(),
                        },
                        Err((None, "derp".to_string())),
                    )
                ]),)),
                now: Arc::new(Mutex::new(0))
            },
        )
        .await
    );
}

#[tokio::test]
async fn validate_open_sns_token_swap_params_max_icp_e8s_too_small() {
    assert_is_err!(
        validate_open_sns_token_swap(
            &OpenSnsTokenSwap {
                params: Some(sns_swap_pb::Params {
                    max_icp_e8s: 1, // Too small.
                    ..PARAMS.clone()
                }),
                ..OPEN_SNS_TOKEN_SWAP.clone()
            },
            &mut MockEnvironment::default(),
        )
        .await
    );
}

#[tokio::test]
async fn validate_open_sns_token_swap_params_basket_count_too_small() {
    assert_is_err!(
        validate_open_sns_token_swap(
            &OpenSnsTokenSwap {
                params: Some(sns_swap_pb::Params {
                    neuron_basket_construction_parameters: Some(
                        NeuronBasketConstructionParameters {
                            count: 0,                                 // Too small
                            dissolve_delay_interval_seconds: 7890000, // 3 months
                        },
                    ),
                    ..PARAMS.clone()
                }),
                ..OPEN_SNS_TOKEN_SWAP.clone()
            },
            &mut MockEnvironment::default(),
        )
        .await
    );
}

#[tokio::test]
async fn validate_open_sns_token_swap_params_zero_dissolve_delay() {
    assert_is_err!(
        validate_open_sns_token_swap(
            &OpenSnsTokenSwap {
                params: Some(sns_swap_pb::Params {
                    neuron_basket_construction_parameters: Some(
                        NeuronBasketConstructionParameters {
                            count: 12,
                            dissolve_delay_interval_seconds: 0, // Too small
                        },
                    ),
                    ..PARAMS.clone()
                }),
                ..OPEN_SNS_TOKEN_SWAP.clone()
            },
            &mut MockEnvironment::default(),
        )
        .await
    );
}

#[tokio::test]
async fn validate_open_sns_token_swap_params_practically_forever_dissolve_delay() {
    assert_is_err!(
        validate_open_sns_token_swap(
            &OpenSnsTokenSwap {
                params: Some(sns_swap_pb::Params {
                    neuron_basket_construction_parameters: Some(
                        NeuronBasketConstructionParameters {
                            count: 2,
                            dissolve_delay_interval_seconds: u64::MAX, // Will result in overflow
                        },
                    ),
                    ..PARAMS.clone()
                }),
                ..OPEN_SNS_TOKEN_SWAP.clone()
            },
            &mut MockEnvironment::default(),
        )
        .await
    );
}

#[tokio::test]
async fn validate_open_sns_token_swap_community_fund_investment_e8s() {
    assert_is_err!(
        validate_open_sns_token_swap(
            &OpenSnsTokenSwap {
                community_fund_investment_e8s: Some(1001 * E8), // Exceeds max_icp_e8s.
                ..OPEN_SNS_TOKEN_SWAP.clone()
            },
            &mut MockEnvironment::default(),
        )
        .await
    );
}

lazy_static! {
    static ref NEURON_STORE: NeuronStore = craft_neuron_store(&[
        // (maturity, controller, joined cf at)

        // CF neurons.
        (100 * E8, *PRINCIPAL_ID_1, Some(1)),
        (200 * E8, *PRINCIPAL_ID_2, Some(1)),
        (300 * E8, *PRINCIPAL_ID_1, Some(1)),

        // non-CF neurons.
        (400 * E8, *PRINCIPAL_ID_1, None),
        (500 * E8, *PRINCIPAL_ID_2, None),
    ]);

    static ref ORIGINAL_TOTAL_COMMUNITY_FUND_MATURITY_E8S_EQUIVALENT: u64 = {
        let result = total_community_fund_maturity_e8s_equivalent(&NEURON_STORE);
        assert_eq!(result, 600 * E8);
        result
    };
}

fn craft_neuron_store(
    values: &[(
        /* maturity: */ u64,
        /* controller: */ PrincipalId,
        /* joined cf at: */ Option<u64>,
    )],
) -> NeuronStore {
    NeuronStore::new(
        values
            .iter()
            .enumerate()
            .map(|(i, arg)| {
                let i = i as u64;
                let (maturity_e8s_equivalent, controller, joined_community_fund_timestamp_seconds) =
                    *arg;

                let id = i + 1;
                let neuron = Neuron {
                    id: Some(NeuronId { id }),
                    controller: Some(controller),
                    maturity_e8s_equivalent,
                    joined_community_fund_timestamp_seconds,
                    ..Default::default()
                };

                (id, neuron)
            })
            .collect(),
        None,
        Migration::default(),
    )
}

fn assert_clean_refund(
    neuron_store: &mut NeuronStore,
    cf_participants: &Vec<sns_swap_pb::CfParticipant>,
    expected_neuron_store: &NeuronStore,
) {
    let original_id_to_neuron = neuron_store.clone_neurons();
    let mut original_neuron_store =
        NeuronStore::new(original_id_to_neuron, None, Migration::default());

    let is_neuron_inactive = |_neuron: &Neuron| false; // This keeps all Neurons in heap, and none in stable memory.
    let failed_refunds =
        refund_community_fund_maturity(neuron_store, cf_participants, is_neuron_inactive);
    assert!(failed_refunds.is_empty(), "{:#?}", failed_refunds);

    // Assert that neurons have been restored to the way they were originally.
    assert_eq!(neuron_store, expected_neuron_store);

    // Assert that inserting extraneous elements into cf_participants does
    // not change the result, but it does result in failed refunds.
    let mut extra_cf_participants = cf_participants.clone();
    let mut expected_failed_refunds = vec![];
    if !extra_cf_participants.is_empty() {
        let cf_neuron = sns_swap_pb::CfNeuron {
            nns_neuron_id: 688477,
            amount_icp_e8s: 592,
        };
        extra_cf_participants
            .get_mut(0)
            .unwrap()
            .cf_neurons
            .push(cf_neuron.clone());
        expected_failed_refunds.push(sns_swap_pb::CfParticipant {
            hotkey_principal: extra_cf_participants
                .get(0)
                .unwrap()
                .hotkey_principal
                .clone(),
            cf_neurons: vec![cf_neuron],
        });
    }

    let cf_participant = sns_swap_pb::CfParticipant {
        hotkey_principal: PrincipalId::new_user_test_id(301590).to_string(),
        cf_neurons: vec![
            sns_swap_pb::CfNeuron {
                nns_neuron_id: 875889,
                amount_icp_e8s: 591,
            },
            sns_swap_pb::CfNeuron {
                nns_neuron_id: 734429,
                amount_icp_e8s: 917,
            },
        ],
    };
    extra_cf_participants.push(cf_participant.clone());
    expected_failed_refunds.push(cf_participant);

    let is_neuron_inactive = |_neuron: &Neuron| false; // This keeps all Neurons in heap, and none in stable memory.
    assert_eq!(
        refund_community_fund_maturity(
            &mut original_neuron_store,
            &extra_cf_participants,
            is_neuron_inactive
        ),
        expected_failed_refunds,
    );
    assert_eq!(original_neuron_store, *expected_neuron_store);
}

#[test]
fn draw_funds_from_the_community_fund_all_cf_neurons_have_zero_maturity() {
    let mut neuron_store = craft_neuron_store(&[
        // (maturity, controller, joined cf at)

        // CF neurons.
        (0, *PRINCIPAL_ID_1, Some(1)),
        (0, *PRINCIPAL_ID_2, Some(1)),
        (0, *PRINCIPAL_ID_1, Some(1)),
        // non-CF neurons.
        (400, *PRINCIPAL_ID_1, None),
        (500, *PRINCIPAL_ID_2, None),
    ]);
    let original_neuron_store = neuron_store.clone();

    let is_neuron_inactive = |_neuron: &Neuron| false; // This keeps all Neurons in heap, and none in stable memory.
    let observed_cf_neurons = draw_funds_from_the_community_fund(
        &mut neuron_store,
        *ORIGINAL_TOTAL_COMMUNITY_FUND_MATURITY_E8S_EQUIVALENT,
        /* withdrawal_amount_e8s = */ 60,
        &PARAMS,
        is_neuron_inactive,
    );

    // Inspect results.
    assert_eq!(observed_cf_neurons, vec![]);
    assert_eq!(neuron_store, original_neuron_store);
    assert_clean_refund(
        &mut neuron_store,
        &observed_cf_neurons,
        &original_neuron_store,
    );
}

#[test]
fn draw_funds_from_the_community_fund_zero_withdrawal_amount() {
    let mut neuron_store = craft_neuron_store(&[
        // (maturity, controller, joined cf at)

        // CF neurons.
        (0, *PRINCIPAL_ID_1, Some(1)),
        (10, *PRINCIPAL_ID_2, Some(1)),
        (50, *PRINCIPAL_ID_1, Some(1)),
        // non-CF neurons.
        (400, *PRINCIPAL_ID_1, None),
        (500, *PRINCIPAL_ID_2, None),
    ]);
    let original_neuron_store = neuron_store.clone();

    let is_neuron_inactive = |_neuron: &Neuron| false; // This keeps all Neurons in heap, and none in stable memory.
    let observed_cf_neurons = draw_funds_from_the_community_fund(
        &mut neuron_store,
        *ORIGINAL_TOTAL_COMMUNITY_FUND_MATURITY_E8S_EQUIVALENT,
        /* withdrawal_amount_e8s = */ 0,
        &PARAMS,
        is_neuron_inactive,
    );

    // Inspect results.
    assert_eq!(observed_cf_neurons, vec![]);
    assert_eq!(neuron_store, original_neuron_store);
    assert_clean_refund(
        &mut neuron_store,
        &observed_cf_neurons,
        &original_neuron_store,
    );
}

#[test]
fn draw_funds_from_the_community_fund_typical() {
    let mut neuron_store = NEURON_STORE.clone();
    let is_neuron_inactive = |_neuron: &Neuron| false; // This keeps all Neurons in heap, and none in stable memory.
    let observed_cf_neurons = draw_funds_from_the_community_fund(
        &mut neuron_store,
        *ORIGINAL_TOTAL_COMMUNITY_FUND_MATURITY_E8S_EQUIVALENT,
        /* withdrawal_amount_e8s = */ 60 * E8,
        &PARAMS,
        is_neuron_inactive,
    );

    // Inspect results.

    let mut expected_cf_neurons = vec![
        sns_swap_pb::CfParticipant {
            hotkey_principal: PRINCIPAL_ID_1.to_string(),
            cf_neurons: vec![
                sns_swap_pb::CfNeuron {
                    nns_neuron_id: 1,
                    amount_icp_e8s: 10 * E8,
                },
                sns_swap_pb::CfNeuron {
                    nns_neuron_id: 3,
                    amount_icp_e8s: 30 * E8,
                },
            ],
        },
        sns_swap_pb::CfParticipant {
            hotkey_principal: PRINCIPAL_ID_2.to_string(),
            cf_neurons: vec![sns_swap_pb::CfNeuron {
                nns_neuron_id: 2,
                amount_icp_e8s: 20 * E8,
            }],
        },
    ];
    expected_cf_neurons.sort_by(|n1, n2| n1.hotkey_principal.cmp(&n2.hotkey_principal));
    assert_eq!(observed_cf_neurons, expected_cf_neurons);

    assert_eq!(
        neuron_store,
        craft_neuron_store(&[
            // CF neurons less 10% of their maturity.
            (90 * E8, *PRINCIPAL_ID_1, Some(1)),
            (180 * E8, *PRINCIPAL_ID_2, Some(1)),
            (270 * E8, *PRINCIPAL_ID_1, Some(1)),
            // non-CF neurons remain untouched.
            (400 * E8, *PRINCIPAL_ID_1, None),
            (500 * E8, *PRINCIPAL_ID_2, None),
        ]),
    );

    assert_clean_refund(&mut neuron_store, &observed_cf_neurons, &NEURON_STORE);
}

#[test]
fn draw_funds_from_the_community_fund_cf_shrank_during_voting_period() {
    let mut neuron_store = NEURON_STORE.clone();

    let is_neuron_inactive = |_neuron: &Neuron| false; // This keeps all Neurons in heap, and none in stable memory.
    let observed_cf_neurons = draw_funds_from_the_community_fund(
        &mut neuron_store,
        2 * *ORIGINAL_TOTAL_COMMUNITY_FUND_MATURITY_E8S_EQUIVALENT,
        /* withdrawal_amount_e8s = */ 60 * E8,
        &PARAMS,
        is_neuron_inactive,
    );

    // Inspect results.

    let mut expected_cf_neurons = vec![
        sns_swap_pb::CfParticipant {
            hotkey_principal: PRINCIPAL_ID_1.to_string(),
            cf_neurons: vec![
                sns_swap_pb::CfNeuron {
                    nns_neuron_id: 1,
                    amount_icp_e8s: 5 * E8,
                },
                sns_swap_pb::CfNeuron {
                    nns_neuron_id: 3,
                    amount_icp_e8s: 15 * E8,
                },
            ],
        },
        sns_swap_pb::CfParticipant {
            hotkey_principal: PRINCIPAL_ID_2.to_string(),
            cf_neurons: vec![sns_swap_pb::CfNeuron {
                nns_neuron_id: 2,
                amount_icp_e8s: 10 * E8,
            }],
        },
    ];
    expected_cf_neurons.sort_by(|n1, n2| n1.hotkey_principal.cmp(&n2.hotkey_principal));
    assert_eq!(observed_cf_neurons, expected_cf_neurons);

    assert_eq!(
        neuron_store,
        craft_neuron_store(&[
            // CF neurons less 10% of their maturity.
            (95 * E8, *PRINCIPAL_ID_1, Some(1)),
            (190 * E8, *PRINCIPAL_ID_2, Some(1)),
            (285 * E8, *PRINCIPAL_ID_1, Some(1)),
            // non-CF neurons remain untouched.
            (400 * E8, *PRINCIPAL_ID_1, None),
            (500 * E8, *PRINCIPAL_ID_2, None),
        ]),
    );

    assert_clean_refund(&mut neuron_store, &observed_cf_neurons, &NEURON_STORE);
}

#[test]
fn draw_funds_from_the_community_fund_cf_grew_during_voting_period() {
    let mut neuron_store = NEURON_STORE.clone();

    let is_neuron_inactive = |_neuron: &Neuron| false; // This keeps all Neurons in heap, and none in stable memory.
    let observed_cf_neurons = draw_funds_from_the_community_fund(
        &mut neuron_store,
        *ORIGINAL_TOTAL_COMMUNITY_FUND_MATURITY_E8S_EQUIVALENT / 2,
        /* withdrawal_amount_e8s = */ 60 * E8,
        &PARAMS,
        is_neuron_inactive,
    );

    // Inspect results. Same as typical (copy n' pasted).

    let mut expected_cf_neurons = vec![
        sns_swap_pb::CfParticipant {
            hotkey_principal: PRINCIPAL_ID_1.to_string(),
            cf_neurons: vec![
                sns_swap_pb::CfNeuron {
                    nns_neuron_id: 1,
                    amount_icp_e8s: 10 * E8,
                },
                sns_swap_pb::CfNeuron {
                    nns_neuron_id: 3,
                    amount_icp_e8s: 30 * E8,
                },
            ],
        },
        sns_swap_pb::CfParticipant {
            hotkey_principal: PRINCIPAL_ID_2.to_string(),
            cf_neurons: vec![sns_swap_pb::CfNeuron {
                nns_neuron_id: 2,
                amount_icp_e8s: 20 * E8,
            }],
        },
    ];
    expected_cf_neurons.sort_by(|n1, n2| n1.hotkey_principal.cmp(&n2.hotkey_principal));
    assert_eq!(observed_cf_neurons, expected_cf_neurons);

    assert_eq!(
        neuron_store,
        craft_neuron_store(&[
            // CF neurons less 10% of their maturity.
            (90 * E8, *PRINCIPAL_ID_1, Some(1)),
            (180 * E8, *PRINCIPAL_ID_2, Some(1)),
            (270 * E8, *PRINCIPAL_ID_1, Some(1)),
            // non-CF neurons remain untouched.
            (400 * E8, *PRINCIPAL_ID_1, None),
            (500 * E8, *PRINCIPAL_ID_2, None),
        ]),
    );

    assert_clean_refund(&mut neuron_store, &observed_cf_neurons, &NEURON_STORE);
}

#[test]
fn draw_funds_from_the_community_fund_trivial() {
    let mut neuron_store = NeuronStore::new(btreemap! {}, None, Migration::default());
    let original_total_community_fund_maturity_e8s_equivalent = 0;

    let is_neuron_inactive = |_neuron: &Neuron| false; // This keeps all Neurons in heap, and none in stable memory.
    let observed_cf_neurons = draw_funds_from_the_community_fund(
        &mut neuron_store,
        original_total_community_fund_maturity_e8s_equivalent,
        /* withdrawal_amount_e8s = */ 60,
        &PARAMS,
        is_neuron_inactive,
    );

    // Inspect results.
    assert_eq!(observed_cf_neurons, vec![]);
    assert_eq!(
        neuron_store,
        NeuronStore::new(btreemap! {}, None, Migration::default())
    );

    assert_clean_refund(
        &mut neuron_store,
        &observed_cf_neurons,
        &NeuronStore::new(btreemap! {}, None, Migration::default()),
    );
}

#[test]
fn draw_funds_from_the_community_fund_cf_not_large_enough() {
    let mut neuron_store = NEURON_STORE.clone();

    let is_neuron_inactive = |_neuron: &Neuron| false; // This keeps all Neurons in heap, and none in stable memory.
    let observed_cf_neurons = draw_funds_from_the_community_fund(
        &mut neuron_store,
        *ORIGINAL_TOTAL_COMMUNITY_FUND_MATURITY_E8S_EQUIVALENT,
        /* withdrawal_amount_e8s = */ 1000 * E8,
        &PARAMS,
        is_neuron_inactive,
    );

    // Inspect results.

    let mut expected_cf_neurons = vec![
        sns_swap_pb::CfParticipant {
            hotkey_principal: PRINCIPAL_ID_1.to_string(),
            cf_neurons: vec![
                sns_swap_pb::CfNeuron {
                    nns_neuron_id: 1,
                    amount_icp_e8s: 100 * E8,
                },
                sns_swap_pb::CfNeuron {
                    nns_neuron_id: 3,
                    amount_icp_e8s: 300 * E8,
                },
            ],
        },
        sns_swap_pb::CfParticipant {
            hotkey_principal: PRINCIPAL_ID_2.to_string(),
            cf_neurons: vec![sns_swap_pb::CfNeuron {
                nns_neuron_id: 2,
                amount_icp_e8s: 200 * E8,
            }],
        },
    ];
    expected_cf_neurons.sort_by(|n1, n2| n1.hotkey_principal.cmp(&n2.hotkey_principal));
    assert_eq!(observed_cf_neurons, expected_cf_neurons);

    assert_eq!(
        neuron_store,
        craft_neuron_store(&[
            // CF neurons have been completely depleted.
            (0, *PRINCIPAL_ID_1, Some(1)),
            (0, *PRINCIPAL_ID_2, Some(1)),
            (0, *PRINCIPAL_ID_1, Some(1)),
            // non-CF neurons remain untouched.
            (400 * E8, *PRINCIPAL_ID_1, None),
            (500 * E8, *PRINCIPAL_ID_2, None),
        ]),
    );

    assert_clean_refund(&mut neuron_store, &observed_cf_neurons, &NEURON_STORE);
}

#[test]
fn draw_funds_from_the_community_fund_exclude_small_cf_neuron_and_cap_large() {
    let params = sns_swap_pb::Params {
        min_participant_icp_e8s: 150 * E8,
        max_participant_icp_e8s: 225 * E8,
        ..PARAMS.clone()
    };
    let mut neuron_store = NEURON_STORE.clone();

    let is_neuron_inactive = |_neuron: &Neuron| false; // This keeps all Neurons in heap, and none in stable memory.
    let observed_cf_neurons = draw_funds_from_the_community_fund(
        &mut neuron_store,
        *ORIGINAL_TOTAL_COMMUNITY_FUND_MATURITY_E8S_EQUIVALENT,
        /* withdrawal_amount_e8s = */ 600 * E8,
        &params,
        is_neuron_inactive,
    );

    // Inspect results.

    let mut expected_cf_neurons = vec![
        sns_swap_pb::CfParticipant {
            hotkey_principal: PRINCIPAL_ID_1.to_string(),
            cf_neurons: vec![sns_swap_pb::CfNeuron {
                nns_neuron_id: 3,
                amount_icp_e8s: 225 * E8,
            }],
        },
        sns_swap_pb::CfParticipant {
            hotkey_principal: PRINCIPAL_ID_2.to_string(),
            cf_neurons: vec![sns_swap_pb::CfNeuron {
                nns_neuron_id: 2,
                amount_icp_e8s: 200 * E8,
            }],
        },
    ];
    expected_cf_neurons.sort_by(|n1, n2| n1.hotkey_principal.cmp(&n2.hotkey_principal));
    assert_eq!(observed_cf_neurons, expected_cf_neurons);

    assert_eq!(
        neuron_store,
        craft_neuron_store(&[
            // CF neurons.
            (100 * E8, *PRINCIPAL_ID_1, Some(1)), // Does not participate, because too small.
            (0, *PRINCIPAL_ID_2, Some(1)),        // Fully participates.
            (75 * E8, *PRINCIPAL_ID_1, Some(1)),  // Participates up to the allowed participant max.
            // non-CF neurons remain untouched.
            (400 * E8, *PRINCIPAL_ID_1, None),
            (500 * E8, *PRINCIPAL_ID_2, None),
        ]),
    );

    assert_clean_refund(&mut neuron_store, &observed_cf_neurons, &NEURON_STORE);
}

#[test]
fn protect_not_concluded_open_sns_token_swap_proposal_from_gc() {
    let now_seconds = 1661731390;
    let voting_period_seconds = ONE_DAY_SECONDS;
    let mut subject = ProposalData {
        decided_timestamp_seconds: 1, // has been decided
        reward_event_round: 1,        // has been rewarded
        proposal: Some(Proposal::default()),
        executed_timestamp_seconds: 1,
        latest_tally: Some(Tally {
            yes: 1,
            no: 0,
            total: 1,
            timestamp_seconds: now_seconds,
        }),
        ..Default::default()
    };
    assert_eq!(subject.status(), ProposalStatus::Executed);
    assert!(subject.can_be_purged(now_seconds, voting_period_seconds));

    // Modify subject slightly to make it no longer ineligible for purge.
    subject.proposal.as_mut().unwrap().action =
        Some(Action::OpenSnsTokenSwap(OpenSnsTokenSwap::default()));
    assert!(!subject.can_be_purged(now_seconds, voting_period_seconds));

    let rejected_proposal_data = ProposalData {
        latest_tally: Some(Tally {
            yes: 0,
            no: 1,
            total: 1,
            timestamp_seconds: now_seconds,
        }),
        ..subject.clone()
    };
    assert_eq!(rejected_proposal_data.status(), ProposalStatus::Rejected);
    assert!(rejected_proposal_data.can_be_purged(now_seconds, voting_period_seconds));

    // Modify again to make it purge-able.
    subject.sns_token_swap_lifecycle = Some(Lifecycle::Aborted as i32);
    assert!(subject.can_be_purged(now_seconds, voting_period_seconds));
}

#[test]
fn sum_cf_participants_e8s_nonempty() {
    assert_eq!(
        sum_cf_participants_e8s(&[
            sns_swap_pb::CfParticipant {
                hotkey_principal: PRINCIPAL_ID_1.to_string(),
                cf_neurons: vec![
                    sns_swap_pb::CfNeuron {
                        nns_neuron_id: 1,
                        amount_icp_e8s: 100,
                    },
                    sns_swap_pb::CfNeuron {
                        nns_neuron_id: 3,
                        amount_icp_e8s: 300,
                    },
                ],
            },
            sns_swap_pb::CfParticipant {
                hotkey_principal: PRINCIPAL_ID_2.to_string(),
                cf_neurons: vec![sns_swap_pb::CfNeuron {
                    nns_neuron_id: 2,
                    amount_icp_e8s: 200,
                }],
            },
        ]),
        600,
    );
}

// TODO[NNS1-2632]: Remove this test once `settle_community_fund_participation` is deprecated.
mod settle_community_fund_participation_tests {
    use settle_community_fund_participation::{Aborted, Committed, Result};

    use super::*;

    lazy_static! {
        static ref COMMITTED: SettleCommunityFundParticipation = SettleCommunityFundParticipation {
            open_sns_token_swap_proposal_id: Some(7),
            result: Some(Result::Committed(Committed {
                sns_governance_canister_id: Some(PrincipalId::new_user_test_id(672891)),
                total_direct_contribution_icp_e8s: None,
                total_neurons_fund_contribution_icp_e8s: None,
            })),
        };
        static ref ABORTED: SettleCommunityFundParticipation = SettleCommunityFundParticipation {
            open_sns_token_swap_proposal_id: Some(42),
            result: Some(Result::Aborted(Aborted {})),
        };
    }

    #[test]
    fn ok() {
        assert_is_ok!(validate_settle_community_fund_participation(&COMMITTED));
        assert_is_ok!(validate_settle_community_fund_participation(&ABORTED));
    }

    #[test]
    fn no_proposal_id() {
        assert_is_err!(validate_settle_community_fund_participation(
            &SettleCommunityFundParticipation {
                open_sns_token_swap_proposal_id: None,
                ..COMMITTED.clone()
            }
        ));
    }

    #[test]
    fn no_result() {
        assert_is_err!(validate_settle_community_fund_participation(
            &SettleCommunityFundParticipation {
                result: None,
                ..COMMITTED.clone()
            }
        ));
    }

    #[test]
    fn no_sns_governance_canister_id() {
        assert_is_err!(validate_settle_community_fund_participation(
            &SettleCommunityFundParticipation {
                open_sns_token_swap_proposal_id: Some(7),
                result: Some(Result::Committed(Committed {
                    sns_governance_canister_id: None,
                    total_direct_contribution_icp_e8s: None,
                    total_neurons_fund_contribution_icp_e8s: None,
                })),
            }
        ));
    }
} // end mod settle_community_fund_participation_tests

mod settle_neurons_fund_participation_request_tests {
    use settle_neurons_fund_participation_request::{Aborted, Committed, Result};
    use SettleNeuronsFundParticipationRequest;

    use super::*;

    lazy_static! {
        static ref COMMITTED: SettleNeuronsFundParticipationRequest =
            SettleNeuronsFundParticipationRequest {
                nns_proposal_id: Some(7),
                result: Some(Result::Committed(Committed {
                    sns_governance_canister_id: Some(PrincipalId::new_user_test_id(672891)),
                    total_direct_participation_icp_e8s: Some(100_000 * E8),
                    total_neurons_fund_participation_icp_e8s: Some(50_000 * E8),
                }))
            };
        static ref ABORTED: SettleNeuronsFundParticipationRequest =
            SettleNeuronsFundParticipationRequest {
                nns_proposal_id: Some(42),
                result: Some(Result::Aborted(Aborted {}))
            };
    }

    #[test]
    fn ok() {
        assert_is_ok!(ValidatedSettleNeuronsFundParticipationRequest::try_from(
            COMMITTED.clone()
        ));
        assert_is_ok!(ValidatedSettleNeuronsFundParticipationRequest::try_from(
            ABORTED.clone()
        ));
    }

    #[test]
    fn no_proposal_id() {
        assert_is_err!(ValidatedSettleNeuronsFundParticipationRequest::try_from(
            SettleNeuronsFundParticipationRequest {
                nns_proposal_id: None,
                ..COMMITTED.clone()
            }
        ));
    }

    #[test]
    fn no_result() {
        assert_is_err!(ValidatedSettleNeuronsFundParticipationRequest::try_from(
            SettleNeuronsFundParticipationRequest {
                result: None,
                ..COMMITTED.clone()
            }
        ));
    }

    #[test]
    fn no_sns_governance_canister_id() {
        assert_is_err!(ValidatedSettleNeuronsFundParticipationRequest::try_from(
            SettleNeuronsFundParticipationRequest {
                nns_proposal_id: Some(7),
                result: Some(Result::Committed(Committed {
                    sns_governance_canister_id: None,
                    total_direct_participation_icp_e8s: Some(100_000 * E8),
                    total_neurons_fund_participation_icp_e8s: Some(50_000 * E8),
                })),
            }
        ));
    }

    #[test]
    fn no_total_direct_participation_icp_e8s() {
        assert_is_err!(ValidatedSettleNeuronsFundParticipationRequest::try_from(
            SettleNeuronsFundParticipationRequest {
                nns_proposal_id: Some(7),
                result: Some(Result::Committed(Committed {
                    sns_governance_canister_id: Some(PrincipalId::new_user_test_id(672891)),
                    total_direct_participation_icp_e8s: None,
                    total_neurons_fund_participation_icp_e8s: Some(50_000 * E8),
                })),
            }
        ));
    }

    #[test]
    fn no_total_neurons_fund_participation_icp_e8s() {
        assert_is_err!(ValidatedSettleNeuronsFundParticipationRequest::try_from(
            SettleNeuronsFundParticipationRequest {
                nns_proposal_id: Some(7),
                result: Some(Result::Committed(Committed {
                    sns_governance_canister_id: Some(PrincipalId::new_user_test_id(672891)),
                    total_direct_participation_icp_e8s: Some(100_000 * E8),
                    total_neurons_fund_participation_icp_e8s: None,
                })),
            }
        ));
    }
} // end mod settle_neurons_fund_participation_request_tests

mod convert_from_create_service_nervous_system_to_sns_init_payload_tests {
    use ic_nervous_system_proto::pb::v1 as pb;
    use ic_sns_init::pb::v1::sns_init_payload;
    use test_data::{CREATE_SERVICE_NERVOUS_SYSTEM, IMAGE_1, IMAGE_2};

    use super::*;

    // Alias types from crate::pb::v1::...
    //
    // This is done within another mod to differentiate against types that have
    // similar names as types found in ic_sns_init.
    mod src {
        pub use crate::pb::v1::create_service_nervous_system::initial_token_distribution::SwapDistribution;
    }

    fn unwrap_duration_seconds(original: &Option<pb::Duration>) -> Option<u64> {
        Some(original.as_ref().unwrap().seconds.unwrap())
    }

    fn unwrap_tokens_e8s(original: &Option<pb::Tokens>) -> Option<u64> {
        Some(original.as_ref().unwrap().e8s.unwrap())
    }

    fn unwrap_percentage_basis_points(original: &Option<pb::Percentage>) -> Option<u64> {
        Some(original.as_ref().unwrap().basis_points.unwrap())
    }

    #[test]
    fn test_convert_from_valid() {
        // Step 1: Prepare the world. (In this case, trivial.)

        // Step 2: Call the code under test.
        let converted = SnsInitPayload::try_from(CREATE_SERVICE_NERVOUS_SYSTEM.clone()).unwrap();

        // Step 3: Inspect the result.

        let original_ledger_parameters: &_ = CREATE_SERVICE_NERVOUS_SYSTEM
            .ledger_parameters
            .as_ref()
            .unwrap();
        let original_governance_parameters: &_ = CREATE_SERVICE_NERVOUS_SYSTEM
            .governance_parameters
            .as_ref()
            .unwrap();

        let original_voting_reward_parameters: &_ = original_governance_parameters
            .voting_reward_parameters
            .as_ref()
            .unwrap();

        let original_swap_parameters: &_ = CREATE_SERVICE_NERVOUS_SYSTEM
            .swap_parameters
            .as_ref()
            .unwrap();

        assert_eq!(
            SnsInitPayload {
                // We'll look at this separately.
                initial_token_distribution: None,
                swap_start_timestamp_seconds: None,
                swap_due_timestamp_seconds: None,
                neurons_fund_participants: None,
                nns_proposal_id: None,
                neuron_basket_construction_parameters: None,
                ..converted
            },
            SnsInitPayload {
                transaction_fee_e8s: unwrap_tokens_e8s(&original_ledger_parameters.transaction_fee),
                token_name: Some(original_ledger_parameters.clone().token_name.unwrap()),
                token_symbol: Some(original_ledger_parameters.clone().token_symbol.unwrap()),
                token_logo: Some(IMAGE_2.to_string()),

                proposal_reject_cost_e8s: unwrap_tokens_e8s(
                    &original_governance_parameters.proposal_rejection_fee
                ),

                neuron_minimum_stake_e8s: unwrap_tokens_e8s(
                    &original_governance_parameters.neuron_minimum_stake
                ),

                fallback_controller_principal_ids: CREATE_SERVICE_NERVOUS_SYSTEM
                    .fallback_controller_principal_ids
                    .iter()
                    .map(|id| id.to_string())
                    .collect(),

                logo: Some(IMAGE_1.to_string(),),
                url: Some("https://best.app".to_string(),),
                name: Some("Hello, world!".to_string(),),
                description: Some("Best app that you ever did saw.".to_string(),),

                neuron_minimum_dissolve_delay_to_vote_seconds: unwrap_duration_seconds(
                    &original_governance_parameters.neuron_minimum_dissolve_delay_to_vote
                ),

                initial_reward_rate_basis_points: unwrap_percentage_basis_points(
                    &original_voting_reward_parameters.initial_reward_rate
                ),
                final_reward_rate_basis_points: unwrap_percentage_basis_points(
                    &original_voting_reward_parameters.final_reward_rate
                ),
                reward_rate_transition_duration_seconds: unwrap_duration_seconds(
                    &original_voting_reward_parameters.reward_rate_transition_duration
                ),

                max_dissolve_delay_seconds: unwrap_duration_seconds(
                    &original_governance_parameters.neuron_maximum_dissolve_delay
                ),

                max_neuron_age_seconds_for_age_bonus: unwrap_duration_seconds(
                    &original_governance_parameters.neuron_maximum_age_for_age_bonus
                ),

                max_dissolve_delay_bonus_percentage: unwrap_percentage_basis_points(
                    &original_governance_parameters.neuron_maximum_dissolve_delay_bonus
                )
                .map(|basis_points| basis_points / 100),

                max_age_bonus_percentage: unwrap_percentage_basis_points(
                    &original_governance_parameters.neuron_maximum_age_bonus
                )
                .map(|basis_points| basis_points / 100),

                initial_voting_period_seconds: unwrap_duration_seconds(
                    &original_governance_parameters.proposal_initial_voting_period
                ),
                wait_for_quiet_deadline_increase_seconds: unwrap_duration_seconds(
                    &original_governance_parameters.proposal_wait_for_quiet_deadline_increase
                ),
                dapp_canisters: Some(sns_init_pb::DappCanisters {
                    canisters: vec![pb::Canister {
                        id: Some(CanisterId::from_u64(1000).get()),
                    }],
                }),
                min_participants: original_swap_parameters.minimum_participants,
                min_icp_e8s: unwrap_tokens_e8s(&original_swap_parameters.minimum_icp),
                max_icp_e8s: unwrap_tokens_e8s(&original_swap_parameters.maximum_icp),
                min_participant_icp_e8s: unwrap_tokens_e8s(
                    &original_swap_parameters.minimum_participant_icp
                ),
                max_participant_icp_e8s: unwrap_tokens_e8s(
                    &original_swap_parameters.maximum_participant_icp
                ),

                confirmation_text: original_swap_parameters.confirmation_text.clone(),
                restricted_countries: original_swap_parameters.restricted_countries.clone(),

                // We'll examine these later
                initial_token_distribution: None,
                neuron_basket_construction_parameters: None,
                neurons_fund_participants: None,
                swap_start_timestamp_seconds: None,
                swap_due_timestamp_seconds: None,
                nns_proposal_id: None,
                neurons_fund_participation_constraints: None,
            },
        );

        let original_initial_token_distribution: &_ = CREATE_SERVICE_NERVOUS_SYSTEM
            .initial_token_distribution
            .as_ref()
            .unwrap();
        let original_developer_distribution: &_ = original_initial_token_distribution
            .developer_distribution
            .as_ref()
            .unwrap();
        assert_eq!(
            original_developer_distribution.developer_neurons.len(),
            1,
            "{:#?}",
            original_developer_distribution.developer_neurons,
        );
        let original_neuron_distribution: &_ = original_developer_distribution
            .developer_neurons
            .get(0)
            .unwrap();

        let src::SwapDistribution { total: swap_total } = original_initial_token_distribution
            .swap_distribution
            .as_ref()
            .unwrap();
        let swap_total_e8s = unwrap_tokens_e8s(swap_total).unwrap();
        assert_eq!(swap_total_e8s, 1_840_880_000);

        assert_eq!(
            converted.initial_token_distribution.unwrap(),
            sns_init_payload::InitialTokenDistribution::FractionalDeveloperVotingPower(
                sns_init_pb::FractionalDeveloperVotingPower {
                    developer_distribution: Some(sns_init_pb::DeveloperDistribution {
                        developer_neurons: vec![sns_init_pb::NeuronDistribution {
                            controller: Some(original_neuron_distribution.controller.unwrap()),

                            stake_e8s: unwrap_tokens_e8s(&original_neuron_distribution.stake)
                                .unwrap(),

                            memo: original_neuron_distribution.memo.unwrap(),

                            dissolve_delay_seconds: unwrap_duration_seconds(
                                &original_neuron_distribution.dissolve_delay
                            )
                            .unwrap(),

                            vesting_period_seconds: unwrap_duration_seconds(
                                &original_neuron_distribution.vesting_period
                            ),
                        },],
                    },),
                    treasury_distribution: Some(sns_init_pb::TreasuryDistribution {
                        total_e8s: unwrap_tokens_e8s(
                            &original_initial_token_distribution
                                .treasury_distribution
                                .as_ref()
                                .unwrap()
                                .total
                        )
                        .unwrap(),
                    },),
                    swap_distribution: Some(sns_init_pb::SwapDistribution {
                        // These are intentionally the same.
                        total_e8s: swap_total_e8s,
                        initial_swap_amount_e8s: swap_total_e8s,
                    },),
                    airdrop_distribution: Some(sns_init_pb::AirdropDistribution {
                        airdrop_neurons: vec![],
                    },),
                },
            ),
        );

        let original_neuron_basket_construction_parameters = CREATE_SERVICE_NERVOUS_SYSTEM
            .swap_parameters
            .as_ref()
            .unwrap()
            .neuron_basket_construction_parameters
            .as_ref()
            .unwrap();

        assert_eq!(
            converted.neuron_basket_construction_parameters.unwrap(),
            NeuronBasketConstructionParameters {
                count: original_neuron_basket_construction_parameters
                    .count
                    .unwrap(),
                dissolve_delay_interval_seconds: unwrap_duration_seconds(
                    &original_neuron_basket_construction_parameters.dissolve_delay_interval
                )
                .unwrap(),
            }
        );

        assert_eq!(converted.nns_proposal_id, None);
        assert_eq!(converted.neurons_fund_participants, None);
        assert_eq!(converted.swap_start_timestamp_seconds, None);
        assert_eq!(converted.swap_due_timestamp_seconds, None);
    }

    #[test]
    fn test_convert_from_invalid() {
        // Step 1: Prepare the world: construct input.
        let mut original = CREATE_SERVICE_NERVOUS_SYSTEM.clone();
        let governance_parameters = original.governance_parameters.as_mut().unwrap();

        // Corrupt the data. The problem with this is that wait for quiet extension
        // amount cannot be more than half the initial voting period.
        governance_parameters.proposal_wait_for_quiet_deadline_increase = governance_parameters
            .proposal_initial_voting_period
            .as_ref()
            .map(|duration| {
                let seconds = Some(duration.seconds.unwrap() / 2 + 1);
                pb::Duration { seconds }
            });

        // Step 2: Call the code under test.
        let converted = SnsInitPayload::try_from(original);

        // Step 3: Inspect the result: Err must contain "wait for quiet".
        match converted {
            Ok(ok) => panic!("Invalid data was not rejected. Result: {:#?}", ok),
            Err(err) => assert!(err.contains("wait_for_quiet"), "{}", err),
        }
    }
}

mod convert_from_executed_create_service_nervous_system_proposal_to_sns_init_payload_tests {
    use ic_nervous_system_proto::pb::v1 as pb;
    use ic_sns_init::pb::v1::{sns_init_payload, NeuronsFundParticipants};
    use ic_sns_swap::pb::v1::{CfNeuron, CfParticipant};
    use test_data::{CREATE_SERVICE_NERVOUS_SYSTEM, IMAGE_1, IMAGE_2};

    use super::*;

    // Alias types from crate::pb::v1::...
    //
    // This is done within another mod to differentiate against types that have
    // similar names as types found in ic_sns_init.
    mod src {
        pub use crate::pb::v1::create_service_nervous_system::initial_token_distribution::SwapDistribution;
    }

    fn unwrap_duration_seconds(original: &Option<pb::Duration>) -> Option<u64> {
        Some(original.as_ref().unwrap().seconds.unwrap())
    }

    fn unwrap_tokens_e8s(original: &Option<pb::Tokens>) -> Option<u64> {
        Some(original.as_ref().unwrap().e8s.unwrap())
    }

    fn unwrap_percentage_basis_points(original: &Option<pb::Percentage>) -> Option<u64> {
        Some(original.as_ref().unwrap().basis_points.unwrap())
    }

    #[test]
    fn test_convert_from_valid() {
        // Step 1: Prepare the world. (In this case, trivial.)
        let current_timestamp_seconds = 13_245;
        let proposal_id = 1000;
        let neurons_fund_participants = vec![
            CfParticipant {
                hotkey_principal: PrincipalId::new_user_test_id(1).to_string(),
                cf_neurons: vec![CfNeuron {
                    nns_neuron_id: 1,
                    amount_icp_e8s: 10 * E8,
                }],
            },
            CfParticipant {
                hotkey_principal: PrincipalId::new_user_test_id(2).to_string(),
                cf_neurons: vec![
                    CfNeuron {
                        nns_neuron_id: 2,
                        amount_icp_e8s: 11 * E8,
                    },
                    CfNeuron {
                        nns_neuron_id: 3,
                        amount_icp_e8s: 12 * E8,
                    },
                ],
            },
        ];

        let executed_create_service_nervous_system_proposal =
            ExecutedCreateServiceNervousSystemProposal {
                current_timestamp_seconds,
                create_service_nervous_system: CREATE_SERVICE_NERVOUS_SYSTEM.clone(),
                proposal_id,
                neurons_fund_participants: neurons_fund_participants.clone(),
                random_swap_start_time: GlobalTimeOfDay {
                    seconds_after_utc_midnight: Some(0),
                },
                neurons_fund_participation_constraints: None, // TODO[NNS1-2558]
            };

        // Step 2: Call the code under test.
        let converted =
            SnsInitPayload::try_from(executed_create_service_nervous_system_proposal).unwrap();

        // Step 3: Inspect the result.

        let original_ledger_parameters: &_ = CREATE_SERVICE_NERVOUS_SYSTEM
            .ledger_parameters
            .as_ref()
            .unwrap();
        let original_governance_parameters: &_ = CREATE_SERVICE_NERVOUS_SYSTEM
            .governance_parameters
            .as_ref()
            .unwrap();

        let original_voting_reward_parameters: &_ = original_governance_parameters
            .voting_reward_parameters
            .as_ref()
            .unwrap();

        let original_swap_parameters: &_ = CREATE_SERVICE_NERVOUS_SYSTEM
            .swap_parameters
            .as_ref()
            .unwrap();

        assert_eq!(
            SnsInitPayload {
                // We'll look at this separately.
                initial_token_distribution: None,
                neuron_basket_construction_parameters: None,
                swap_start_timestamp_seconds: None,
                swap_due_timestamp_seconds: None,
                ..converted
            },
            SnsInitPayload {
                transaction_fee_e8s: unwrap_tokens_e8s(&original_ledger_parameters.transaction_fee),
                token_name: Some(original_ledger_parameters.clone().token_name.unwrap()),
                token_symbol: Some(original_ledger_parameters.clone().token_symbol.unwrap()),
                token_logo: Some(IMAGE_2.to_string()),

                proposal_reject_cost_e8s: unwrap_tokens_e8s(
                    &original_governance_parameters.proposal_rejection_fee
                ),

                neuron_minimum_stake_e8s: unwrap_tokens_e8s(
                    &original_governance_parameters.neuron_minimum_stake
                ),

                fallback_controller_principal_ids: CREATE_SERVICE_NERVOUS_SYSTEM
                    .fallback_controller_principal_ids
                    .iter()
                    .map(|id| id.to_string())
                    .collect(),

                logo: Some(IMAGE_1.to_string(),),
                url: Some("https://best.app".to_string(),),
                name: Some("Hello, world!".to_string(),),
                description: Some("Best app that you ever did saw.".to_string(),),

                neuron_minimum_dissolve_delay_to_vote_seconds: unwrap_duration_seconds(
                    &original_governance_parameters.neuron_minimum_dissolve_delay_to_vote
                ),

                initial_reward_rate_basis_points: unwrap_percentage_basis_points(
                    &original_voting_reward_parameters.initial_reward_rate
                ),
                final_reward_rate_basis_points: unwrap_percentage_basis_points(
                    &original_voting_reward_parameters.final_reward_rate
                ),
                reward_rate_transition_duration_seconds: unwrap_duration_seconds(
                    &original_voting_reward_parameters.reward_rate_transition_duration
                ),

                max_dissolve_delay_seconds: unwrap_duration_seconds(
                    &original_governance_parameters.neuron_maximum_dissolve_delay
                ),

                max_neuron_age_seconds_for_age_bonus: unwrap_duration_seconds(
                    &original_governance_parameters.neuron_maximum_age_for_age_bonus
                ),

                max_dissolve_delay_bonus_percentage: unwrap_percentage_basis_points(
                    &original_governance_parameters.neuron_maximum_dissolve_delay_bonus
                )
                .map(|basis_points| basis_points / 100),

                max_age_bonus_percentage: unwrap_percentage_basis_points(
                    &original_governance_parameters.neuron_maximum_age_bonus
                )
                .map(|basis_points| basis_points / 100),

                initial_voting_period_seconds: unwrap_duration_seconds(
                    &original_governance_parameters.proposal_initial_voting_period
                ),
                wait_for_quiet_deadline_increase_seconds: unwrap_duration_seconds(
                    &original_governance_parameters.proposal_wait_for_quiet_deadline_increase
                ),
                dapp_canisters: Some(sns_init_pb::DappCanisters {
                    canisters: vec![pb::Canister {
                        id: Some(CanisterId::from_u64(1000).get()),
                    }],
                }),
                min_participants: original_swap_parameters.minimum_participants,
                min_icp_e8s: unwrap_tokens_e8s(&original_swap_parameters.minimum_icp),
                max_icp_e8s: unwrap_tokens_e8s(&original_swap_parameters.maximum_icp),
                min_participant_icp_e8s: unwrap_tokens_e8s(
                    &original_swap_parameters.minimum_participant_icp
                ),
                max_participant_icp_e8s: unwrap_tokens_e8s(
                    &original_swap_parameters.maximum_participant_icp
                ),

                confirmation_text: original_swap_parameters.confirmation_text.clone(),
                restricted_countries: original_swap_parameters.restricted_countries.clone(),
                nns_proposal_id: Some(proposal_id),
                neurons_fund_participants: Some(NeuronsFundParticipants {
                    participants: neurons_fund_participants,
                }),
                // TODO[NNS1-2558]: Test this field.
                neurons_fund_participation_constraints: None,

                // We'll examine these later
                initial_token_distribution: None,
                neuron_basket_construction_parameters: None,
                swap_start_timestamp_seconds: None,
                swap_due_timestamp_seconds: None,
            },
        );

        let original_initial_token_distribution: &_ = CREATE_SERVICE_NERVOUS_SYSTEM
            .initial_token_distribution
            .as_ref()
            .unwrap();
        let original_developer_distribution: &_ = original_initial_token_distribution
            .developer_distribution
            .as_ref()
            .unwrap();
        assert_eq!(
            original_developer_distribution.developer_neurons.len(),
            1,
            "{:#?}",
            original_developer_distribution.developer_neurons,
        );
        let original_neuron_distribution: &_ = original_developer_distribution
            .developer_neurons
            .get(0)
            .unwrap();

        let src::SwapDistribution { total: swap_total } = original_initial_token_distribution
            .swap_distribution
            .as_ref()
            .unwrap();
        let swap_total_e8s = unwrap_tokens_e8s(swap_total).unwrap();
        assert_eq!(swap_total_e8s, 1_840_880_000);

        assert_eq!(
            converted.initial_token_distribution.unwrap(),
            sns_init_payload::InitialTokenDistribution::FractionalDeveloperVotingPower(
                sns_init_pb::FractionalDeveloperVotingPower {
                    developer_distribution: Some(sns_init_pb::DeveloperDistribution {
                        developer_neurons: vec![sns_init_pb::NeuronDistribution {
                            controller: Some(original_neuron_distribution.controller.unwrap()),

                            stake_e8s: unwrap_tokens_e8s(&original_neuron_distribution.stake)
                                .unwrap(),

                            memo: original_neuron_distribution.memo.unwrap(),

                            dissolve_delay_seconds: unwrap_duration_seconds(
                                &original_neuron_distribution.dissolve_delay
                            )
                            .unwrap(),

                            vesting_period_seconds: unwrap_duration_seconds(
                                &original_neuron_distribution.vesting_period
                            ),
                        },],
                    },),
                    treasury_distribution: Some(sns_init_pb::TreasuryDistribution {
                        total_e8s: unwrap_tokens_e8s(
                            &original_initial_token_distribution
                                .treasury_distribution
                                .as_ref()
                                .unwrap()
                                .total
                        )
                        .unwrap(),
                    },),
                    swap_distribution: Some(sns_init_pb::SwapDistribution {
                        // These are intentionally the same.
                        total_e8s: swap_total_e8s,
                        initial_swap_amount_e8s: swap_total_e8s,
                    },),
                    airdrop_distribution: Some(sns_init_pb::AirdropDistribution {
                        airdrop_neurons: vec![],
                    },),
                },
            ),
        );

        let original_neuron_basket_construction_parameters = CREATE_SERVICE_NERVOUS_SYSTEM
            .swap_parameters
            .as_ref()
            .unwrap()
            .neuron_basket_construction_parameters
            .as_ref()
            .unwrap();

        assert_eq!(
            converted.neuron_basket_construction_parameters.unwrap(),
            NeuronBasketConstructionParameters {
                count: original_neuron_basket_construction_parameters
                    .count
                    .unwrap(),
                dissolve_delay_interval_seconds: unwrap_duration_seconds(
                    &original_neuron_basket_construction_parameters.dissolve_delay_interval
                )
                .unwrap(),
            }
        );

        let (expected_swap_start_timestamp_seconds, expected_swap_due_timestamp_seconds) =
            CreateServiceNervousSystem::swap_start_and_due_timestamps(
                original_swap_parameters.start_time.unwrap(),
                original_swap_parameters.duration.unwrap(),
                current_timestamp_seconds,
            )
            .unwrap();

        assert_eq!(
            converted.swap_start_timestamp_seconds,
            Some(expected_swap_start_timestamp_seconds)
        );
        assert_eq!(
            converted.swap_due_timestamp_seconds,
            Some(expected_swap_due_timestamp_seconds)
        );
    }
}

mod metrics_tests {
    use std::sync::{Arc, Mutex};

    use maplit::btreemap;

    use crate::{
        encode_metrics,
        governance::{
            tests::{MockEnvironment, StubCMC, StubIcpLedger},
            Governance,
        },
        pb::v1::{proposal, Governance as GovernanceProto, Motion, Proposal, ProposalData, Tally},
    };

    #[test]
    fn test_metrics_total_voting_power() {
        let proposal_1 = ProposalData {
            proposal: Some(Proposal {
                title: Some("Foo Foo Bar".to_string()),
                action: Some(proposal::Action::Motion(Motion {
                    motion_text: "Text for this motion".to_string(),
                })),
                ..Proposal::default()
            }),
            latest_tally: Some(Tally {
                timestamp_seconds: 0,
                yes: 0,
                no: 0,
                total: 555,
            }),
            ..ProposalData::default()
        };

        let proposal_2 = ProposalData {
            proposal: Some(Proposal {
                title: Some("Foo Foo Bar".to_string()),
                action: Some(proposal::Action::ManageNeuron(Box::default())),

                ..Proposal::default()
            }),
            latest_tally: Some(Tally {
                timestamp_seconds: 0,
                yes: 0,
                no: 0,
                total: 1,
            }),
            ..ProposalData::default()
        };

        let governance = Governance::new(
            GovernanceProto {
                proposals: btreemap! {
                    1 =>  proposal_1,
                    2 => proposal_2
                },
                ..GovernanceProto::default()
            },
            Box::new(MockEnvironment {
                expected_call_canister_method_calls: Arc::new(Mutex::new(Default::default())),
                now: Arc::new(Mutex::new(0)),
            }),
            Box::new(StubIcpLedger {}),
            Box::new(StubCMC {}),
        );

        let mut writer = ic_metrics_encoder::MetricsEncoder::new(vec![], 1000);

        encode_metrics(&governance, &mut writer).unwrap();

        let body = writer.into_inner();
        let s = String::from_utf8_lossy(&body);

        // We assert that it is '555' instead of '1', so that we know the correct
        // proposal action is filtered out.
        assert!(s.contains("governance_voting_power_total 555 1000"));
    }
}

mod neuron_archiving_tests {
    use crate::{
        governance::{
            tests::{MockEnvironment, StubCMC, StubIcpLedger},
            Governance,
        },
        pb::v1::{
            governance::NeuronInFlightCommand, manage_neuron::NeuronIdOrSubaccount, proposal,
            Governance as GovernanceProto, ManageNeuron, Motion, Neuron, Proposal, ProposalData,
        },
    };
    use ic_nns_common::pb::v1::NeuronId;
    use maplit::{btreemap, hashmap};
    use proptest::proptest;
    use std::sync::{Arc, Mutex};

    fn empty_neuron_id_1() -> Neuron {
        Neuron {
            id: Some(NeuronId { id: 1 }),
            account: vec![],
            cached_neuron_stake_e8s: 0,
            neuron_fees_e8s: 0,
            staked_maturity_e8s_equivalent: None,
            ..Default::default()
        }
    }

    #[test]
    fn test_neuron_is_inactive_involved_with_proposals() {
        let inactive_neuron = empty_neuron_id_1();

        let neuron_2_is_proposer = ProposalData {
            proposer: Some(NeuronId { id: 2 }),
            proposal: Some(Proposal {
                title: Some("Foo Foo Bar".to_string()),
                action: Some(proposal::Action::Motion(Motion {
                    motion_text: "Text for this motion".to_string(),
                })),
                ..Proposal::default()
            }),
            ..ProposalData::default()
        };

        let neuron_3_is_managed_neuron = ProposalData {
            proposal: Some(Proposal {
                title: Some("Woo hoo".to_string()),
                action: Some(proposal::Action::ManageNeuron(Box::new(ManageNeuron {
                    id: None,
                    neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId {
                        id: 3,
                    })),
                    command: None,
                }))),
                ..Proposal::default()
            }),
            ..ProposalData::default()
        };

        let subaccount_123_is_managed_neuron = ProposalData {
            proposal: Some(Proposal {
                title: Some("Woo hoo".to_string()),
                action: Some(proposal::Action::ManageNeuron(Box::new(ManageNeuron {
                    id: None,
                    neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::Subaccount(vec![1, 2, 3])),
                    command: None,
                }))),
                ..Proposal::default()
            }),
            ..ProposalData::default()
        };

        let governance = Governance::new(
            GovernanceProto {
                proposals: btreemap! {
                    1 => neuron_2_is_proposer,
                    2 => neuron_3_is_managed_neuron,
                    3 => subaccount_123_is_managed_neuron
                },
                ..GovernanceProto::default()
            },
            Box::new(MockEnvironment {
                expected_call_canister_method_calls: Arc::new(Mutex::new(Default::default())),
                now: Arc::new(Mutex::new(0)),
            }),
            Box::new(StubIcpLedger {}),
            Box::new(StubCMC {}),
        );

        assert!(inactive_neuron.is_inactive(
            &governance.heap_data.proposals,
            &governance.heap_data.in_flight_commands,
        ));

        let neuron_is_proposer = Neuron {
            id: Some(NeuronId { id: 2 }),
            ..inactive_neuron.clone()
        };

        assert!(!neuron_is_proposer.is_inactive(
            &governance.heap_data.proposals,
            &governance.heap_data.in_flight_commands,
        ));

        let managed_by_proposal_neuron = Neuron {
            id: Some(NeuronId { id: 3 }),
            ..inactive_neuron.clone()
        };

        assert!(!managed_by_proposal_neuron.is_inactive(
            &governance.heap_data.proposals,
            &governance.heap_data.in_flight_commands,
        ));

        let subaccount_is_managed_neuron_in_proposal = Neuron {
            account: vec![1, 2, 3],
            ..inactive_neuron
        };

        assert!(!subaccount_is_managed_neuron_in_proposal.is_inactive(
            &governance.heap_data.proposals,
            &governance.heap_data.in_flight_commands,
        ));
    }

    #[test]
    fn test_neuron_is_inactive_neuron_locks() {
        let inactive_neuron = empty_neuron_id_1();

        let governance = Governance::new(
            GovernanceProto {
                proposals: btreemap! {},
                in_flight_commands: hashmap! {
                    4 => NeuronInFlightCommand { timestamp: 123, command: None}
                },
                ..GovernanceProto::default()
            },
            Box::new(MockEnvironment {
                expected_call_canister_method_calls: Arc::new(Mutex::new(Default::default())),
                now: Arc::new(Mutex::new(0)),
            }),
            Box::new(StubIcpLedger {}),
            Box::new(StubCMC {}),
        );

        assert!(inactive_neuron.is_inactive(
            &governance.heap_data.proposals,
            &governance.heap_data.in_flight_commands,
        ));

        let has_neuron_lock = Neuron {
            id: Some(NeuronId { id: 4 }),
            ..inactive_neuron
        };

        assert!(!has_neuron_lock.is_inactive(
            &governance.heap_data.proposals,
            &governance.heap_data.in_flight_commands,
        ));
    }

    proptest! {
    #[test]
    fn test_neuron_is_inactive_stake_and_maturity(stake in 0u64..10_000,
                                              staked_maturity in 0u64..10_000,
                                              fees in 0u64..10_000,
                                              maturity in 0u64..10_000) {
        let inactive_neuron = empty_neuron_id_1();

        let governance = Governance::new(
            GovernanceProto::default(),
            Box::new(MockEnvironment {
                expected_call_canister_method_calls: Arc::new(Mutex::new(Default::default())),
                now: Arc::new(Mutex::new(0)),
            }),
            Box::new(StubIcpLedger {}),
            Box::new(StubCMC {}),
        );


        let neuron = Neuron {
            cached_neuron_stake_e8s: stake,
            staked_maturity_e8s_equivalent: Some(staked_maturity),
            neuron_fees_e8s: fees,
            maturity_e8s_equivalent: maturity,
            ..inactive_neuron
        };

        assert_eq!(
            neuron.is_inactive(
                &governance.heap_data.proposals,
                &governance.heap_data.in_flight_commands,
            ),
            neuron.stake_e8s() == 0 && neuron.maturity_e8s_equivalent == 0,
            "{:#?}",
            neuron,
        );
    }} // end proptest
}

#[test]
fn test_should_copy_next_batch_of_inactive_neurons_to_stable_memory_blank() {
    let governance = Governance::new(
        GovernanceProto::default(),
        Box::new(MockEnvironment {
            expected_call_canister_method_calls: Arc::new(Mutex::new(Default::default())),
            now: Arc::new(Mutex::new(0)),
        }),
        Box::new(StubIcpLedger {}),
        Box::new(StubCMC {}),
    );

    assert!(governance.should_copy_next_batch_of_inactive_neurons_to_stable_memory());
}

#[test]
fn test_should_copy_next_batch_of_inactive_neurons_to_stable_memory_migration_exists() {
    let status_to_should_copy_next_batch = [
        (None, true),
        (Some(MigrationStatus::Unspecified as i32), true),
        (Some(MigrationStatus::InProgress as i32), true),
        (Some(MigrationStatus::Succeeded as i32), false),
        (Some(MigrationStatus::Failed as i32), false),
    ];

    for (status, should_copy_next_batch) in status_to_should_copy_next_batch {
        let governance = GovernanceProto {
            migrations: Some(Migrations {
                copy_inactive_neurons_to_stable_memory_migration: Some(Migration {
                    status,
                    failure_reason: None,
                    progress: None,
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        let governance = Governance::new(
            governance,
            Box::new(MockEnvironment {
                expected_call_canister_method_calls: Arc::new(Mutex::new(Default::default())),
                now: Arc::new(Mutex::new(0)),
            }),
            Box::new(StubIcpLedger {}),
            Box::new(StubCMC {}),
        );

        assert_eq!(
            governance.should_copy_next_batch_of_inactive_neurons_to_stable_memory(),
            should_copy_next_batch,
            "{:?}",
            status,
        );
    }
}

lazy_static! {
    static ref ORIGINAL_HEAP_NEURONS: BTreeMap<u64, Neuron> = {
        fn new_neuron(id: u64, maturity_e8s_equivalent: u64) -> Neuron {
            Neuron {
                id: Some(NeuronId { id }),
                maturity_e8s_equivalent,
                ..Default::default()
            }
        }

        btreemap! {
            1 => new_neuron(1, 0),
            3 => new_neuron(3, 0),
            4 => new_neuron(4, 0),
            5 => new_neuron(5, 1_000), // active/do not archive
            7 => new_neuron(7, 0),
            12 => new_neuron(12, 0),
            13 => new_neuron(13, 0),
        }
    };
}

/// A helper for the next handful or so of tests. This takes care of preparing
/// the world and running the code under test. The expected result depends on
/// the argument, and verifying it is a job that is left to the caller.
#[must_use]
fn copy_next_batch_of_inactive_neurons_to_stable_memory_from_last_neuron_id(
    last_neuron_id: NeuronId,
) -> Migrations {
    // Step 1: Prepare the world.
    let governance_proto = GovernanceProto {
        migrations: Some(Migrations {
            copy_inactive_neurons_to_stable_memory_migration: Some(Migration {
                status: Some(MigrationStatus::InProgress as i32),
                failure_reason: None,
                progress: Some(migration::Progress::LastNeuronId(
                    // The only thing that isn't fixed.
                    last_neuron_id,
                )),
            }),
            ..Default::default()
        }),
        neurons: ORIGINAL_HEAP_NEURONS.clone(),
        ..Default::default()
    };
    let mut governance = Governance::new(
        governance_proto,
        Box::new(MockEnvironment {
            expected_call_canister_method_calls: Arc::new(Mutex::new(Default::default())),
            now: Arc::new(Mutex::new(0)),
        }),
        Box::new(StubIcpLedger {}),
        Box::new(StubCMC {}),
    );

    // Step 2: Run the code under test.
    governance.copy_next_batch_of_inactive_neurons_to_stable_memory();

    // Return new status for verification by caller.
    governance.heap_data.migrations.clone().unwrap()
}

fn assert_copied_neurons(expected_neuron_ids: &[NeuronId]) {
    STABLE_NEURON_STORE.with(|stable_neuron_store| {
        let stable_neuron_store = stable_neuron_store.borrow();
        for id in 0..20 {
            let neuron_id = NeuronId { id };
            let read_result = stable_neuron_store.read(neuron_id);

            if expected_neuron_ids.contains(&neuron_id) {
                assert_eq!(
                    read_result,
                    Ok(ORIGINAL_HEAP_NEURONS.get(&id).unwrap().clone())
                );
                continue;
            }

            match &read_result {
                Err(err) => {
                    let GovernanceError {
                        error_type,
                        error_message,
                    } = &err;

                    assert_eq!(
                        ErrorType::from_i32(*error_type),
                        Some(ErrorType::NotFound),
                        "{:#?}",
                        err
                    );

                    let error_message = error_message.to_lowercase();
                    assert!(error_message.contains("unable"), "{:#?}", err);
                    assert!(error_message.contains(&format!("{}", id)), "{:#?}", err);
                }
                _ => panic!("{:?}", read_result),
            }
        }
    });
}

/// This tests, and subsequent ones like it, make use of the fact that BATCH_LEN = 3 when being
/// built as a test.
#[test]
fn test_copy_next_batch_of_inactive_neurons_to_stable_memory_from_neuron_id_from_neuron_id_0() {
    // Step 0: Verify pre-condition(s)
    assert_eq!(COPY_INACTIVE_NEURONS_TO_STABLE_MEMORY_BATCH_LEN, 3);

    // Steps 1 and 2: Prepare the world and run the code under test.
    let migrations =
        copy_next_batch_of_inactive_neurons_to_stable_memory_from_last_neuron_id(NeuronId {
            id: 0,
        });

    // Step 3: Verify results.
    assert_eq!(
        migrations,
        Migrations {
            copy_inactive_neurons_to_stable_memory_migration: Some(Migration {
                status: Some(MigrationStatus::InProgress as i32),
                failure_reason: None,
                progress: Some(migration::Progress::LastNeuronId(NeuronId { id: 4 })),
            }),
            ..Default::default()
        },
    );

    assert_copied_neurons(&[NeuronId { id: 1 }, NeuronId { id: 3 }, NeuronId { id: 4 }]);
}

#[test]
fn test_copy_next_batch_of_inactive_neurons_to_stable_memory_from_neuron_id_from_neuron_id_1() {
    // Steps 1 and 2: Prepare the world and run the code under test.
    let migrations =
        copy_next_batch_of_inactive_neurons_to_stable_memory_from_last_neuron_id(NeuronId {
            id: 1,
        });

    // Step 3: Verify results.
    assert_eq!(
        migrations,
        Migrations {
            copy_inactive_neurons_to_stable_memory_migration: Some(Migration {
                status: Some(MigrationStatus::InProgress as i32),
                failure_reason: None,
                progress: Some(migration::Progress::LastNeuronId(NeuronId { id: 5 })),
            }),
            ..Default::default()
        },
    );

    assert_copied_neurons(&[
        NeuronId { id: 3 },
        NeuronId { id: 4 },
        // 5 is scanned, but not copied, because it is active.
    ]);
}

#[test]
fn test_copy_next_batch_of_inactive_neurons_to_stable_memory_from_neuron_id_from_neuron_id_2() {
    // Steps 1 and 2: Prepare the world and run the code under test.
    let migrations =
        copy_next_batch_of_inactive_neurons_to_stable_memory_from_last_neuron_id(NeuronId {
            id: 2,
        });

    // Step 3: Verify results.
    assert_eq!(
        migrations,
        Migrations {
            copy_inactive_neurons_to_stable_memory_migration: Some(Migration {
                status: Some(MigrationStatus::InProgress as i32),
                failure_reason: None,
                progress: Some(migration::Progress::LastNeuronId(NeuronId { id: 5 })),
            }),
            ..Default::default()
        },
    );

    assert_copied_neurons(&[
        NeuronId { id: 3 },
        NeuronId { id: 4 },
        // 5 is scanned, but not copied, because it is active.
    ]);
}

#[test]
fn test_copy_next_batch_of_inactive_neurons_to_stable_memory_from_neuron_id_from_neuron_id_3() {
    // Steps 1 and 2: Prepare the world and run the code under test.
    let migrations =
        copy_next_batch_of_inactive_neurons_to_stable_memory_from_last_neuron_id(NeuronId {
            id: 3,
        });

    // Step 3: Verify results.
    assert_eq!(
        migrations,
        Migrations {
            copy_inactive_neurons_to_stable_memory_migration: Some(Migration {
                status: Some(MigrationStatus::InProgress as i32),
                failure_reason: None,
                progress: Some(migration::Progress::LastNeuronId(NeuronId { id: 7 })),
            }),
            ..Default::default()
        },
    );

    assert_copied_neurons(&[
        NeuronId { id: 4 },
        // 5 is scanned, but not copied, because it is active.
        NeuronId { id: 7 },
    ]);
}

#[test]
fn test_copy_next_batch_of_inactive_neurons_to_stable_memory_from_neuron_id_from_neuron_id_4() {
    // Steps 1 and 2: Prepare the world and run the code under test.
    let migrations =
        copy_next_batch_of_inactive_neurons_to_stable_memory_from_last_neuron_id(NeuronId {
            id: 4,
        });

    // Step 3: Verify results.
    assert_eq!(
        migrations,
        Migrations {
            copy_inactive_neurons_to_stable_memory_migration: Some(Migration {
                status: Some(MigrationStatus::InProgress as i32),
                failure_reason: None,
                progress: Some(migration::Progress::LastNeuronId(NeuronId { id: 12 })),
            }),
            ..Default::default()
        },
    );

    assert_copied_neurons(&[
        // 5 is scanned, but not copied, because it is active.
        NeuronId { id: 7 },
        NeuronId { id: 12 },
    ]);
}

/// Stop scanning 5.
#[test]
fn test_copy_next_batch_of_inactive_neurons_to_stable_memory_from_neuron_id_from_neuron_id_5() {
    // Steps 1 and 2: Prepare the world and run the code under test.
    let migrations =
        copy_next_batch_of_inactive_neurons_to_stable_memory_from_last_neuron_id(NeuronId {
            id: 5,
        });

    // Step 3: Verify results.
    assert_eq!(
        migrations,
        Migrations {
            copy_inactive_neurons_to_stable_memory_migration: Some(Migration {
                status: Some(MigrationStatus::InProgress as i32),
                failure_reason: None,
                progress: Some(migration::Progress::LastNeuronId(NeuronId { id: 13 })),
            }),
            ..Default::default()
        },
    );

    assert_copied_neurons(&[NeuronId { id: 7 }, NeuronId { id: 12 }, NeuronId { id: 13 }]);
}

/// This is the last time we'll see 7, and the last time that we have a "full" batch (i.e. scan
/// range len = batch len).
#[test]
fn test_copy_next_batch_of_inactive_neurons_to_stable_memory_from_neuron_id_from_neuron_id_6() {
    // Steps 1 and 2: Prepare the world and run the code under test.
    let migrations =
        copy_next_batch_of_inactive_neurons_to_stable_memory_from_last_neuron_id(NeuronId {
            id: 6,
        });

    // Step 3: Verify results.
    assert_eq!(
        migrations,
        Migrations {
            copy_inactive_neurons_to_stable_memory_migration: Some(Migration {
                // We are on the verge of success, but the code under test is not able to detect
                // this. That would be detected during the next call. That scenario is tested a few
                // tests later.
                status: Some(MigrationStatus::InProgress as i32),
                failure_reason: None,
                progress: Some(migration::Progress::LastNeuronId(NeuronId { id: 13 })),
            }),
            ..Default::default()
        },
    );

    assert_copied_neurons(&[NeuronId { id: 7 }, NeuronId { id: 12 }, NeuronId { id: 13 }]);
}

/// No longer scanning 7. This is the first time that the scan range len (2) is smaller than the
/// batch len (3). Now, completion is detected.
#[test]
fn test_copy_next_batch_of_inactive_neurons_to_stable_memory_from_neuron_id_from_neuron_id_7() {
    // Steps 1 and 2: Prepare the world and run the code under test.
    let migrations =
        copy_next_batch_of_inactive_neurons_to_stable_memory_from_last_neuron_id(NeuronId {
            id: 7,
        });

    // Step 3: Verify results.
    assert_eq!(
        migrations,
        Migrations {
            copy_inactive_neurons_to_stable_memory_migration: Some(Migration {
                // New! This is the first test where we end with not InProgress. Not really sure how
                // to force Failed.
                status: Some(MigrationStatus::Succeeded as i32),
                failure_reason: None,
                progress: None,
            }),
            ..Default::default()
        },
    );

    assert_copied_neurons(&[NeuronId { id: 12 }, NeuronId { id: 13 }]);
}

/// One past an edge case. The result here is the same as that of the previous test.
#[test]
fn test_copy_next_batch_of_inactive_neurons_to_stable_memory_from_neuron_id_from_neuron_id_8() {
    // Steps 1 and 2: Prepare the world and run the code under test.
    let migrations =
        copy_next_batch_of_inactive_neurons_to_stable_memory_from_last_neuron_id(NeuronId {
            id: 8,
        });

    // Step 3: Verify results.
    assert_eq!(
        migrations,
        Migrations {
            copy_inactive_neurons_to_stable_memory_migration: Some(Migration {
                status: Some(MigrationStatus::Succeeded as i32),
                failure_reason: None,
                progress: None,
            }),
            ..Default::default()
        },
    );

    assert_copied_neurons(&[NeuronId { id: 12 }, NeuronId { id: 13 }]);
}

/// Same result as the previous test case. This is because 8 and 11 are not much different from one
/// another. What they have in common is that they are both between known NeuronIds.
#[test]
fn test_copy_next_batch_of_inactive_neurons_to_stable_memory_from_neuron_id_from_neuron_id_11() {
    // Steps 1 and 2: Prepare the world and run the code under test.
    let migrations =
        copy_next_batch_of_inactive_neurons_to_stable_memory_from_last_neuron_id(NeuronId {
            id: 11,
        });

    // Step 3: Verify results.
    assert_eq!(
        migrations,
        Migrations {
            copy_inactive_neurons_to_stable_memory_migration: Some(Migration {
                status: Some(MigrationStatus::Succeeded as i32),
                failure_reason: None,
                progress: None,
            }),
            ..Default::default()
        },
    );

    assert_copied_neurons(&[NeuronId { id: 12 }, NeuronId { id: 13 }]);
}

/// Not yet at an edge, but close. Therefore, the len of the scan range is "much smaller", but
/// is still nevertheless nonempty.
#[test]
fn test_copy_next_batch_of_inactive_neurons_to_stable_memory_from_neuron_id_from_neuron_id_12() {
    // Steps 1 and 2: Prepare the world and run the code under test.
    let migrations =
        copy_next_batch_of_inactive_neurons_to_stable_memory_from_last_neuron_id(NeuronId {
            id: 12,
        });

    // Step 3: Verify results.
    assert_eq!(
        migrations,
        Migrations {
            copy_inactive_neurons_to_stable_memory_migration: Some(Migration {
                status: Some(MigrationStatus::Succeeded as i32),
                failure_reason: None,
                progress: None,
            }),
            ..Default::default()
        },
    );

    assert_copied_neurons(&[NeuronId { id: 13 }]);
}

/// An edge case. Here, no there are no neurons left to scan, but just barely.
#[test]
fn test_copy_next_batch_of_inactive_neurons_to_stable_memory_from_neuron_id_from_neuron_id_13() {
    // Steps 1 and 2: Prepare the world and run the code under test.
    let migrations =
        copy_next_batch_of_inactive_neurons_to_stable_memory_from_last_neuron_id(NeuronId {
            id: 13,
        });

    // Step 3: Verify results.
    assert_eq!(
        migrations,
        Migrations {
            copy_inactive_neurons_to_stable_memory_migration: Some(Migration {
                status: Some(MigrationStatus::Succeeded as i32),
                failure_reason: None,
                progress: None,
            }),
            ..Default::default()
        },
    );

    assert_copied_neurons(&[]);
}

/// We have gone over the edge now. This gets the same result as the previous test.
#[test]
fn test_copy_next_batch_of_inactive_neurons_to_stable_memory_from_neuron_id_from_neuron_id_14() {
    // Steps 1 and 2: Prepare the world and run the code under test.
    let migrations =
        copy_next_batch_of_inactive_neurons_to_stable_memory_from_last_neuron_id(NeuronId {
            id: 14,
        });

    // Step 3: Verify results.
    assert_eq!(
        migrations,
        Migrations {
            copy_inactive_neurons_to_stable_memory_migration: Some(Migration {
                status: Some(MigrationStatus::Succeeded as i32),
                failure_reason: None,
                progress: None,
            }),
            ..Default::default()
        },
    );

    assert_copied_neurons(&[]);
}

mod cast_vote_and_cascade_follow {
    use crate::{
        governance::{Governance, MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS},
        neuron_store::NeuronStore,
        pb::v1::{
            governance::Migration,
            neuron::{DissolveState, Followees},
            Ballot, Neuron, Topic, Vote,
        },
    };
    use ic_nns_common::pb::v1::{NeuronId, ProposalId};
    use maplit::hashmap;
    use std::collections::{BTreeMap, HashMap};

    const E8S: u64 = 100_000_000;

    fn make_ballot(voting_power: u64, vote: Vote) -> Ballot {
        Ballot {
            voting_power,
            vote: vote as i32,
        }
    }

    fn make_test_neuron_with_followees(
        id: u64,
        topic: Topic,
        followees: Vec<u64>,
        aging_since_timestamp_seconds: u64,
    ) -> Neuron {
        Neuron {
            id: Some(NeuronId { id }),
            followees: hashmap! {
                topic as i32 => Followees {
                    followees: followees.into_iter().map(|id| NeuronId { id }).collect()
                }
            },
            cached_neuron_stake_e8s: E8S, // clippy doesn't like 1 * E8S
            dissolve_state: Some(DissolveState::DissolveDelaySeconds(
                MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS,
            )),
            aging_since_timestamp_seconds,
            ..Default::default()
        }
    }

    #[test]
    fn test_cast_vote_and_cascade_works() {
        let now = 1000;
        let topic = Topic::NetworkCanisterManagement;

        let make_neuron = |id: u64, followees: Vec<u64>| {
            make_test_neuron_with_followees(id, topic, followees, now)
        };

        let add_neuron_with_ballot = |neuron_map: &mut BTreeMap<u64, Neuron>,
                                      ballots: &mut HashMap<u64, Ballot>,
                                      id: u64,
                                      followees: Vec<u64>,
                                      vote: Vote| {
            let neuron = make_neuron(id, followees);
            let voting_power = neuron.voting_power(now);
            neuron_map.insert(id, neuron);
            ballots.insert(id, make_ballot(voting_power, vote));
        };

        let add_neuron_without_ballot =
            |neuron_map: &mut BTreeMap<u64, Neuron>, id: u64, followees: Vec<u64>| {
                let neuron = make_neuron(id, followees);
                neuron_map.insert(id, neuron);
            };

        let mut heap_neurons = BTreeMap::new();
        let mut ballots = HashMap::new();
        for id in 1..=5 {
            // Each neuron follows all neurons with a lower id
            let followees = (1..id).collect();

            add_neuron_with_ballot(
                &mut heap_neurons,
                &mut ballots,
                id,
                followees,
                Vote::Unspecified,
            );
        }
        // Add another neuron that follows both a neuron with a ballot and without a ballot
        add_neuron_with_ballot(
            &mut heap_neurons,
            &mut ballots,
            6,
            vec![1, 7],
            Vote::Unspecified,
        );

        // Add a neuron without a ballot for neuron 6 to follow.
        add_neuron_without_ballot(&mut heap_neurons, 7, vec![1]);

        let mut neuron_store = NeuronStore::new(heap_neurons, None, Migration::default());

        Governance::cast_vote_and_cascade_follow(
            &ProposalId { id: 1 },
            &mut ballots,
            &NeuronId { id: 1 },
            Vote::Yes,
            topic,
            |_| false,
            &mut neuron_store,
        );

        assert_eq!(
            ballots,
            hashmap! {
                1 => make_ballot(neuron_store.with_neuron(&NeuronId {id: 1}, |n| n.voting_power(now)).unwrap(), Vote::Yes),
                2 => make_ballot(neuron_store.with_neuron(&NeuronId {id: 2}, |n| n.voting_power(now)).unwrap(), Vote::Yes),
                3 => make_ballot(neuron_store.with_neuron(&NeuronId {id: 3}, |n| n.voting_power(now)).unwrap(), Vote::Yes),
                4 => make_ballot(neuron_store.with_neuron(&NeuronId {id: 4}, |n| n.voting_power(now)).unwrap(), Vote::Yes),
                5 => make_ballot(neuron_store.with_neuron(&NeuronId {id: 5}, |n| n.voting_power(now)).unwrap(), Vote::Yes),
                6 => make_ballot(neuron_store.with_neuron(&NeuronId {id: 6}, |n| n.voting_power(now)).unwrap(), Vote::Unspecified),
            }
        );
    }
}
