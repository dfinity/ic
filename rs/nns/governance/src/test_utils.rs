// This allow(dead_code) is necessary because some parts of this file
// are not used in canbench-rs, but are used elsewhere.  Otherwise we get annoying clippy warnings.
#![allow(dead_code)]
use crate::{
    governance::{Environment, HeapGrowthPotential, RngError},
    pb::v1::{ExecuteNnsFunction, GovernanceError, OpenSnsTokenSwap},
};
use async_trait::async_trait;
use candid::{Decode, Encode};
use ic_base_types::{CanisterId, PrincipalId};
use ic_ledger_core::Tokens;
use ic_nervous_system_common::{cmc::CMC, ledger::IcpLedger, NervousSystemError, E8};
use ic_nns_constants::SNS_WASM_CANISTER_ID;
use ic_sns_swap::pb::{
    v1 as sns_swap_pb,
    v1::{NeuronBasketConstructionParameters, Params, Swap},
};
use ic_sns_wasm::pb::v1::{DeployedSns, ListDeployedSnsesRequest, ListDeployedSnsesResponse};
use icp_ledger::{AccountIdentifier, Subaccount};
use lazy_static::lazy_static;
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

pub const TEST_SWAP_PARAMS: Params = Params {
    max_icp_e8s: 1000 * E8,
    min_icp_e8s: 10 * E8,
    max_direct_participation_icp_e8s: Some(1000 * E8),
    min_direct_participation_icp_e8s: Some(10 * E8),
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

lazy_static! {
    pub static ref PRINCIPAL_ID_1: PrincipalId = PrincipalId::new_user_test_id(1);
    pub static ref PRINCIPAL_ID_2: PrincipalId = PrincipalId::new_user_test_id(2);
    pub static ref PRINCIPAL_ID_3: PrincipalId = PrincipalId::new_user_test_id(3);
    pub static ref TARGET_SWAP_CANISTER_ID: CanisterId = CanisterId::from_u64(435106);
    pub static ref OPEN_SNS_TOKEN_SWAP: OpenSnsTokenSwap = OpenSnsTokenSwap {
        target_swap_canister_id: Some((*TARGET_SWAP_CANISTER_ID).into()),
        params: Some(TEST_SWAP_PARAMS),
        community_fund_investment_e8s: Some(500),
    };
    pub static ref SWAP_INIT: sns_swap_pb::Init = sns_swap_pb::Init {
        transaction_fee_e8s: Some(12_345),
        neuron_minimum_stake_e8s: Some(123_456_789),
        ..Default::default() // Not realistic, but good enough for tests.
    };

    pub static ref EXPECTED_LIST_DEPLOYED_SNSES: (ExpectedCallCanisterMethodCallArguments, CanisterMethodCallResult) =
        (
            ExpectedCallCanisterMethodCallArguments::new(
                SNS_WASM_CANISTER_ID,
                "list_deployed_snses",
                Encode!(&ListDeployedSnsesRequest {}).unwrap(),
            ),
            Ok(Encode!(&ListDeployedSnsesResponse {
                instances: vec![DeployedSns {
                    swap_canister_id: Some((*TARGET_SWAP_CANISTER_ID).into()),
                    ..Default::default()
                },]
            })
               .unwrap()),
        );
}

type CanisterMethodCallResult = Result<Vec<u8>, (Option<i32>, String)>;

pub(crate) struct StubIcpLedger {}
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

pub(crate) struct StubCMC {}
#[async_trait]
impl CMC for StubCMC {
    async fn neuron_maturity_modulation(&mut self) -> Result<i32, String> {
        unimplemented!()
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct ExpectedCallCanisterMethodCallArguments {
    target: CanisterId,
    method_name: String,
    request: Vec<u8>,
}

impl ExpectedCallCanisterMethodCallArguments {
    pub fn new(
        target: CanisterId,
        method_name: &str,
        request: Vec<u8>,
    ) -> ExpectedCallCanisterMethodCallArguments {
        ExpectedCallCanisterMethodCallArguments {
            target,
            method_name: method_name.to_string(),
            request,
        }
    }
}

#[allow(clippy::type_complexity)]
pub(crate) struct MockEnvironment {
    expected_call_canister_method_calls: Arc<
        Mutex<
            VecDeque<(
                ExpectedCallCanisterMethodCallArguments,
                Result<Vec<u8>, (Option<i32>, String)>,
            )>,
        >,
    >,
    now: Arc<Mutex<u64>>,
}

// Here because clippy complains about the type alias being too complex.
type ExpectedCallsWithResults = Vec<(
    ExpectedCallCanisterMethodCallArguments,
    Result<Vec<u8>, (Option<i32>, String)>,
)>;

impl MockEnvironment {
    pub fn new(expected_call_responses: ExpectedCallsWithResults, now: u64) -> MockEnvironment {
        MockEnvironment {
            expected_call_canister_method_calls: Arc::new(Mutex::new(VecDeque::from(
                expected_call_responses,
            ))),
            now: Arc::new(Mutex::new(now)),
        }
    }
}

impl Default for MockEnvironment {
    fn default() -> Self {
        Self {
            expected_call_canister_method_calls: Arc::new(Mutex::new(VecDeque::from([
                EXPECTED_LIST_DEPLOYED_SNSES.clone(),
                (
                    ExpectedCallCanisterMethodCallArguments::new(
                        *TARGET_SWAP_CANISTER_ID,
                        "get_state",
                        Encode!(&sns_swap_pb::GetStateRequest {}).unwrap(),
                    ),
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
impl Environment for MockEnvironment {
    fn now(&self) -> u64 {
        *self.now.lock().unwrap()
    }

    fn random_u64(&mut self) -> Result<u64, RngError> {
        unimplemented!();
    }

    fn random_byte_array(&mut self) -> Result<[u8; 32], RngError> {
        unimplemented!();
    }

    fn seed_rng(&mut self, _seed: [u8; 32]) {}

    fn get_rng_seed(&self) -> Option<[u8; 32]> {
        Some([0; 32])
    }

    fn execute_nns_function(
        &self,
        _proposal_id: u64,
        _update: &ExecuteNnsFunction,
    ) -> Result<(), GovernanceError> {
        unimplemented!();
    }

    fn heap_growth_potential(&self) -> HeapGrowthPotential {
        HeapGrowthPotential::NoIssue
    }

    async fn call_canister_method(
        &self,
        target: CanisterId,
        method_name: &str,
        request: Vec<u8>,
    ) -> Result<Vec<u8>, (Option<i32>, String)> {
        if [SNS_WASM_CANISTER_ID].contains(&target) {
            // TODO: replace with a vec of all NNS canister IDs
            assert!(request.len() < 1000 * 1000 * 10, "request too large");
        } else {
            assert!(request.len() < 1000 * 1000 * 2, "request too large");
        }

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
