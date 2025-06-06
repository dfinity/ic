//! Here are tests where we verify the behavior of the governance canister when
//! the heap cannot grow very much.
use assert_matches::assert_matches;
use async_trait::async_trait;
use futures::future::FutureExt;
use ic_base_types::{CanisterId, PrincipalId};
use ic_crypto_sha2::Sha256;
use ic_nervous_system_canisters::cmc::CMC;
use ic_nervous_system_canisters::ledger::IcpLedger;
use ic_nervous_system_common::NervousSystemError;
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance::canister_state::CanisterRandomnessGenerator;
use ic_nns_governance::{
    governance::{
        Environment, Governance, HeapGrowthPotential, HEAP_SIZE_SOFT_LIMIT_IN_WASM32_PAGES,
    },
    pb::v1::{
        governance_error::ErrorType,
        install_code::CanisterInstallMode,
        manage_neuron::{
            claim_or_refresh::{By, MemoAndController},
            ClaimOrRefresh, Command,
        },
        proposal, ExecuteNnsFunction, GovernanceError, InstallCode, ManageNeuron, Motion, Proposal,
    },
};
use ic_nns_governance_api::{
    self as api, manage_neuron_response::Command as CommandResponse, ManageNeuronResponse,
};
use icp_ledger::{AccountIdentifier, Subaccount, Tokens};
use icrc_ledger_types::icrc3::blocks::{GetBlocksRequest, GetBlocksResult};
use maplit::btreemap;
use std::convert::TryFrom;
use std::sync::Arc;

struct DegradedEnv {}
#[async_trait]
impl Environment for DegradedEnv {
    fn now(&self) -> u64 {
        111000222
    }

    fn execute_nns_function(&self, _: u64, _: &ExecuteNnsFunction) -> Result<(), GovernanceError> {
        unimplemented!()
    }

    fn heap_growth_potential(&self) -> HeapGrowthPotential {
        HeapGrowthPotential::LimitedAvailability
    }

    async fn call_canister_method(
        &self,
        _target: CanisterId,
        _method_name: &str,
        _request: Vec<u8>,
    ) -> Result<Vec<u8>, (Option<i32>, String)> {
        unimplemented!();
    }
}

#[async_trait]
impl IcpLedger for DegradedEnv {
    async fn transfer_funds(
        &self,
        _: u64,
        _: u64,
        _: Option<Subaccount>,
        _: AccountIdentifier,
        _: u64,
    ) -> Result<u64, NervousSystemError> {
        unimplemented!()
    }

    async fn total_supply(&self) -> Result<Tokens, NervousSystemError> {
        unimplemented!()
    }

    async fn account_balance(&self, _: AccountIdentifier) -> Result<Tokens, NervousSystemError> {
        unimplemented!()
    }

    fn canister_id(&self) -> CanisterId {
        unimplemented!()
    }

    async fn icrc3_get_blocks(
        &self,
        _args: Vec<GetBlocksRequest>,
    ) -> Result<GetBlocksResult, NervousSystemError> {
        unimplemented!()
    }
}

#[async_trait]
impl CMC for DegradedEnv {
    async fn neuron_maturity_modulation(&self) -> Result<i32, String> {
        unimplemented!()
    }
}

/// Constructs a test principal id from an integer.
/// Convenience functions to make creating neurons more concise.
fn principal(i: u64) -> PrincipalId {
    PrincipalId::try_from(format!("SID{}", i).as_bytes().to_vec()).unwrap()
}

/// Constructs a fixture with 2 neurons of different stakes and no
/// following. Neuron 2 has a greater stake.
fn fixture_two_neurons_second_is_bigger() -> api::Governance {
    api::Governance {
        economics: Some(api::NetworkEconomics::default()),
        neurons: btreemap! {
            1 => api::Neuron {
                id: Some(NeuronId {id: 1}),
                controller: Some(principal(1)),
                cached_neuron_stake_e8s: 23,
                account: b"a__4___8__12__16__20__24__28__32".to_vec(),
                // One year
                dissolve_state: Some(api::neuron::DissolveState::DissolveDelaySeconds(31557600)),
                ..Default::default()
            },
            2 => api::Neuron {
                id: Some(NeuronId {id: 2}),
                controller: Some(principal(2)),
                cached_neuron_stake_e8s: 5100,
                account:  b"b__4___8__12__16__20__24__28__32".to_vec(),
                // One year
                dissolve_state: Some(api::neuron::DissolveState::DissolveDelaySeconds(31557600)),
                ..Default::default()
             },
        },
        ..Default::default()
    }
}

fn degraded_governance() -> Governance {
    Governance::new(
        fixture_two_neurons_second_is_bigger(),
        Arc::new(DegradedEnv {}),
        Arc::new(DegradedEnv {}),
        Arc::new(DegradedEnv {}),
        Box::new(CanisterRandomnessGenerator::new()),
    )
}

#[test]
fn test_heap_soft_limit_is_3_and_half_gigibyte() {
    let page_size_byte: usize = 64 * 1024;
    assert_eq!(
        HEAP_SIZE_SOFT_LIMIT_IN_WASM32_PAGES * page_size_byte,
        1024 * 1024 * 1024 * 35 / 10
    )
}

#[tokio::test]
async fn test_cannot_submit_motion_in_degraded_mode() {
    let mut gov = degraded_governance();

    // Now let's send a proposal
    assert_matches!(gov.make_proposal(
        &NeuronId { id: 1 },
        // Must match neuron 1's serialized_id.
        &principal(1),
        &Proposal {
            title: Some("A Reasonable Title".to_string()),
            summary: "proposal 1".to_string(),
            action: Some(proposal::Action::Motion(Motion {
                motion_text: "Rabbits are cute".to_string(),
            })),
            ..Default::default()
        },
    ).await,
    Err(e) if e.error_type == ErrorType::ResourceExhausted as i32);
}

#[tokio::test]
async fn test_can_submit_nns_canister_upgrade_in_degraded_mode() {
    let mut gov = degraded_governance();

    // Now let's send a proposal
    assert_matches!(
        gov.make_proposal(
            &NeuronId { id: 1 },
            // Must match neuron 1's serialized_id.
            &principal(1),
            &Proposal {
                title: Some("A Reasonable Title".to_string()),
                summary: "proposal 1".to_string(),
                action: Some(proposal::Action::InstallCode(InstallCode {
                    canister_id: Some(GOVERNANCE_CANISTER_ID.get()),
                    wasm_module: Some(vec![1, 2, 3]),
                    install_mode: Some(CanisterInstallMode::Upgrade as i32),
                    arg: Some(vec![4, 5, 6]),
                    skip_stopping_before_installing: None,
                    wasm_module_hash: Some(Sha256::hash(&[1, 2, 3]).to_vec()),
                    arg_hash: Some(Sha256::hash(&[4, 5, 6]).to_vec()),
                })),
                ..Default::default()
            },
        )
        .await,
        Ok(_)
    );
}

#[test]
fn test_cannot_create_neuron_in_degraded_mode() {
    let mut gov = degraded_governance();

    assert_matches!(gov.manage_neuron(&principal(57), &ManageNeuron {
        id: None,
        command: Some(Command::ClaimOrRefresh(ClaimOrRefresh {
            by: Some(By::MemoAndController(MemoAndController {
                memo: 145,
                controller: None,
            })),
        })),
        neuron_id_or_subaccount: None,
    })
    .now_or_never()
    .unwrap(),
     ManageNeuronResponse {
     command: Some(CommandResponse::Error(e))
     }  if e.error_type == ErrorType::ResourceExhausted as i32
    );
}
