//! Here are tests where we verify the behavior of the governance canister when
//! the heap cannot grow very much.
use assert_matches::assert_matches;
use async_trait::async_trait;
use futures::future::FutureExt;
use ic_base_types::PrincipalId;
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_governance::{
    governance::{Environment, Governance, Ledger},
    pb::v1::{
        claim_or_refresh_neuron_from_account_response::Result as ClaimOrRefreshResult,
        governance_error::ErrorType, neuron, proposal, ClaimOrRefreshNeuronFromAccount,
        ExecuteNnsFunction, Governance as GovernanceProto, GovernanceError, Motion,
        NetworkEconomics, Neuron, NnsFunction, Proposal,
    },
};
use ledger_canister::{AccountIdentifier, ICPTs};
use maplit::hashmap;
use std::convert::TryFrom;

use ic_nns_governance::governance::{HeapGrowthPotential, HEAP_SIZE_SOFT_LIMIT_IN_WASM32_PAGES};
use ic_nns_governance::pb::v1::ClaimOrRefreshNeuronFromAccountResponse;
use ledger_canister::Subaccount;

struct DegradedEnv {}
impl Environment for DegradedEnv {
    fn now(&self) -> u64 {
        111000222
    }

    fn random_u64(&mut self) -> u64 {
        4 // https://xkcd.com/221
    }

    fn random_byte_array(&mut self) -> [u8; 32] {
        unimplemented!()
    }

    fn execute_nns_function(&self, _: u64, _: &ExecuteNnsFunction) -> Result<(), GovernanceError> {
        unimplemented!()
    }

    fn heap_growth_potential(&self) -> HeapGrowthPotential {
        HeapGrowthPotential::LimitedAvailability
    }
}

#[async_trait]
impl Ledger for DegradedEnv {
    async fn transfer_funds(
        &self,
        _: u64,
        _: u64,
        _: Option<Subaccount>,
        _: AccountIdentifier,
        _: u64,
    ) -> Result<u64, GovernanceError> {
        unimplemented!()
    }

    async fn total_supply(&self) -> Result<ICPTs, GovernanceError> {
        unimplemented!()
    }

    async fn account_balance(&self, _: AccountIdentifier) -> Result<ICPTs, GovernanceError> {
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
fn fixture_two_neurons_second_is_bigger() -> GovernanceProto {
    GovernanceProto {
        economics: Some(NetworkEconomics::default()),
        neurons: hashmap! {
            1 => Neuron {
                id: Some(NeuronId {id: 1}),
                controller: Some(principal(1)),
                cached_neuron_stake_e8s: 23,
                account: b"a__4___8__12__16__20__24__28__32".to_vec(),
                // One year
                dissolve_state: Some(neuron::DissolveState::DissolveDelaySeconds(31557600)),
                ..Default::default()
            },
            2 => Neuron {
                id: Some(NeuronId {id: 1}),
                controller: Some(principal(2)),
                cached_neuron_stake_e8s: 51,
                account:  b"b__4___8__12__16__20__24__28__32".to_vec(),
                // One year
                dissolve_state: Some(neuron::DissolveState::DissolveDelaySeconds(31557600)),
                ..Default::default()
             },
        },
        ..Default::default()
    }
}

fn degraded_governance() -> Governance {
    Governance::new(
        fixture_two_neurons_second_is_bigger(),
        Box::new(DegradedEnv {}),
        Box::new(DegradedEnv {}),
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

#[test]
fn test_cannot_submit_motion_in_degraded_mode() {
    let mut gov = degraded_governance();

    // Now let's send a proposal
    assert_matches!(gov.make_proposal(
        &NeuronId { id: 1 },
        // Must match neuron 1's serialized_id.
        &principal(1),
        &Proposal {
            summary: "proposal 1".to_string(),
            action: Some(proposal::Action::Motion(Motion {
                motion_text: "Rabbits are cute".to_string(),
            })),
            ..Default::default()
        },
    ),
    Err(e) if e.error_type == ErrorType::ResourceExhausted as i32
    );
}

#[test]
fn test_can_submit_nns_canister_upgrade_in_degraded_mode() {
    let mut gov = degraded_governance();

    // Now let's send a proposal
    assert_matches!(
        gov.make_proposal(
            &NeuronId { id: 1 },
            // Must match neuron 1's serialized_id.
            &principal(1),
            &Proposal {
                summary: "proposal 1".to_string(),
                action: Some(proposal::Action::ExecuteNnsFunction(ExecuteNnsFunction {
                    nns_function: NnsFunction::NnsCanisterUpgrade as i32,
                    payload: Vec::new(),
                })),
                ..Default::default()
            },
        ),
        Ok(_)
    );
}

#[test]
fn test_cannot_create_neuron_in_degraded_mode() {
    let mut gov = degraded_governance();

    assert_matches!(gov.claim_or_refresh_neuron_from_account(
        &principal(57),
        &ClaimOrRefreshNeuronFromAccount {
            controller: None,
            memo: 145,
        },
    )
    .now_or_never()
    .unwrap(),
     ClaimOrRefreshNeuronFromAccountResponse{
     result: Some(ClaimOrRefreshResult::Error(e))
     }   if e.error_type == ErrorType::ResourceExhausted as i32
    );
}
