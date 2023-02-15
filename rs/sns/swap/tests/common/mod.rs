use crate::common::doubles::{LedgerExpect, MockLedger};
use crate::NNS_GOVERNANCE_CANISTER_ID;
use candid::Principal;
use ic_base_types::PrincipalId;
use ic_nervous_system_common::ledger::compute_neuron_staking_subaccount_bytes;
use ic_nervous_system_common::E8;
use ic_nervous_system_common_test_keys::TEST_USER1_PRINCIPAL;
use ic_sns_governance::{
    pb::v1::{
        claim_swap_neurons_request::NeuronParameters,
        claim_swap_neurons_response::{ClaimSwapNeuronsResult, ClaimedSwapNeurons, SwapNeuron},
        ClaimSwapNeuronsResponse, ClaimedSwapNeuronStatus, NeuronId,
    },
    types::ONE_MONTH_SECONDS,
};
use ic_sns_swap::pb::v1::{CfNeuron, CfParticipant};
use ic_sns_swap::{
    memory,
    pb::v1::{
        set_mode_call_result::SetModeResult,
        settle_community_fund_participation_result,
        sns_neuron_recipe::{ClaimedStatus, Investor},
        sns_neuron_recipe::{Investor::Direct, NeuronAttributes},
        CanisterCallError, DirectInvestment, ListDirectParticipantsRequest, Participant,
        RestoreDappControllersResponse, SetDappControllersCallResult, SetDappControllersResponse,
        SetModeCallResult, SettleCommunityFundParticipationResult, SnsNeuronRecipe, Swap,
        TransferableAmount,
    },
    swap::CLAIM_SWAP_NEURONS_MESSAGE_SIZE_LIMIT_BYTES,
};
use std::{
    mem,
    str::FromStr,
    sync::{Arc, Mutex},
};

pub mod doubles;

/// Intermediate structure that helps calculate an investor's SNS NeuronId
pub enum TestInvestor {
    /// The CommunityFund Investor with the memo used to calculate it's SNS NeuronId
    CommunityFund(u64),
    /// The Individual Investor with the PrincipalId used to calculate its SNS NeuronId
    Direct(PrincipalId),
}

/// Given a vector of NeuronRecipes, return all related NeuronRecipes for
/// the given buyer_principal
pub fn select_direct_investment_neurons<'a>(
    ns: &'a Vec<SnsNeuronRecipe>,
    buyer_principal: &str,
) -> Vec<&'a SnsNeuronRecipe> {
    let mut neurons = vec![];
    for n in ns {
        match &n.investor {
            Some(Direct(DirectInvestment {
                buyer_principal: buyer,
            })) => {
                if buyer == buyer_principal {
                    neurons.push(n);
                }
            }
            _ => continue,
        }
    }
    if neurons.is_empty() {
        panic!("Cannot find principal {}", buyer_principal);
    }

    neurons
}

pub fn verify_participant_balances(
    swap: &Swap,
    buyer_principal: &PrincipalId,
    icp_balance_e8s: u64,
    sns_balance_e8s: u64,
) {
    let buyer = swap.buyers.get(&buyer_principal.to_string()).unwrap();
    assert_eq!(icp_balance_e8s, buyer.amount_icp_e8s());
    let total_neuron_recipe_sns_e8s_for_principal: u64 =
        select_direct_investment_neurons(&swap.neuron_recipes, &buyer_principal.to_string())
            .iter()
            .map(|neuron_recipe| neuron_recipe.sns.as_ref().unwrap().amount_e8s)
            .sum();
    assert_eq!(total_neuron_recipe_sns_e8s_for_principal, sns_balance_e8s);
}

pub fn i2principal_id_string(i: u64) -> String {
    Principal::from(PrincipalId::new_user_test_id(i)).to_text()
}

pub fn create_single_neuron_recipe(amount_e8s: u64, buyer_principal: String) -> SnsNeuronRecipe {
    SnsNeuronRecipe {
        sns: Some(TransferableAmount {
            amount_e8s,
            transfer_start_timestamp_seconds: 0,
            transfer_success_timestamp_seconds: 0,
        }),
        neuron_attributes: Some(NeuronAttributes {
            memo: 0,
            dissolve_delay_seconds: 0,
            followees: vec![],
        }),
        investor: Some(Direct(DirectInvestment { buyer_principal })),
        claimed_status: Some(ClaimedStatus::Pending as i32),
    }
}

pub fn mock_stub(mut expect: Vec<LedgerExpect>) -> MockLedger {
    expect.reverse();
    let e = Arc::new(Mutex::new(expect));
    MockLedger { expect: e }
}

pub fn extract_canister_call_error(
    restore_dapp_controller_response: &RestoreDappControllersResponse,
) -> &CanisterCallError {
    use ic_sns_swap::pb::v1::restore_dapp_controllers_response::Possibility;

    match restore_dapp_controller_response.possibility.as_ref() {
        Some(Possibility::Ok(_)) | None => panic!(
            "Extracting CanisterCallError failed. Possibility was {:?}",
            restore_dapp_controller_response.possibility,
        ),
        Some(Possibility::Err(canister_call_error)) => canister_call_error,
    }
}

pub fn extract_set_dapp_controller_response(
    restore_dapp_controller_response: &RestoreDappControllersResponse,
) -> &SetDappControllersResponse {
    use ic_sns_swap::pb::v1::restore_dapp_controllers_response::Possibility;

    match restore_dapp_controller_response.possibility.as_ref() {
        Some(Possibility::Err(_)) | None => panic!(
            "Extracting SetDappControllersResponse failed. Possibility was {:?}",
            restore_dapp_controller_response.possibility,
        ),
        Some(Possibility::Ok(response)) => response,
    }
}

/// Helper method for constructing a successful response in tests
pub fn successful_settle_community_fund_participation_result(
) -> SettleCommunityFundParticipationResult {
    use ic_sns_swap::pb::v1::settle_community_fund_participation_result::Possibility;

    SettleCommunityFundParticipationResult {
        possibility: Some(Possibility::Ok(
            settle_community_fund_participation_result::Response {
                governance_error: None,
            },
        )),
    }
}

/// Helper method for constructing a successful response in tests
pub fn successful_set_dapp_controllers_call_result() -> SetDappControllersCallResult {
    use ic_sns_swap::pb::v1::set_dapp_controllers_call_result::Possibility;

    SetDappControllersCallResult {
        possibility: Some(Possibility::Ok(SetDappControllersResponse {
            failed_updates: vec![],
        })),
    }
}

/// Helper method for constructing a successful response in tests
pub fn successful_set_mode_call_result() -> SetModeCallResult {
    use ic_sns_swap::pb::v1::set_mode_call_result::Possibility;

    SetModeCallResult {
        possibility: Some(Possibility::Ok(SetModeResult {})),
    }
}

/// Helper method for constructing a successful response in tests
pub fn compute_single_successful_claim_swap_neurons_response(
    neuron_recipes: &[SnsNeuronRecipe],
) -> ClaimSwapNeuronsResponse {
    let swap_neurons = neuron_recipes
        .iter()
        .map(|recipe| {
            let controller = match recipe.investor.as_ref().unwrap() {
                Direct(direct) => PrincipalId::from_str(&direct.buyer_principal).unwrap(),
                Investor::CommunityFund(_) => NNS_GOVERNANCE_CANISTER_ID.get(),
            };

            NeuronId::from(compute_neuron_staking_subaccount_bytes(
                controller,
                recipe.neuron_attributes.as_ref().unwrap().memo,
            ))
        })
        .map(|nid| SwapNeuron {
            id: Some(nid),
            status: ClaimedSwapNeuronStatus::Success as i32,
        })
        .collect();

    ClaimSwapNeuronsResponse {
        claim_swap_neurons_result: Some(ClaimSwapNeuronsResult::Ok(ClaimedSwapNeurons {
            swap_neurons,
        })),
    }
}

/// Helper method for constructing a successful response in tests
pub fn compute_multiple_successful_claim_swap_neurons_response(
    neuron_recipes: &[SnsNeuronRecipe],
) -> Vec<ClaimSwapNeuronsResponse> {
    let neuron_parameters_size = mem::size_of::<NeuronParameters>();
    let current_batch_limit =
        CLAIM_SWAP_NEURONS_MESSAGE_SIZE_LIMIT_BYTES.saturating_div(neuron_parameters_size);

    let swap_neurons: Vec<SwapNeuron> = neuron_recipes
        .iter()
        .map(|recipe| {
            let controller = match recipe.investor.as_ref().unwrap() {
                Direct(direct) => PrincipalId::from_str(&direct.buyer_principal).unwrap(),
                Investor::CommunityFund(_) => NNS_GOVERNANCE_CANISTER_ID.get(),
            };

            NeuronId::from(compute_neuron_staking_subaccount_bytes(
                controller,
                recipe.neuron_attributes.as_ref().unwrap().memo,
            ))
        })
        .map(|nid| SwapNeuron {
            id: Some(nid),
            status: ClaimedSwapNeuronStatus::Success as i32,
        })
        .collect();

    swap_neurons
        .chunks(current_batch_limit)
        .map(|chunk| ClaimSwapNeuronsResponse {
            claim_swap_neurons_result: Some(ClaimSwapNeuronsResult::Ok(ClaimedSwapNeurons {
                swap_neurons: chunk.to_vec(),
            })),
        })
        .collect()
}

/// Helper method to create `count` SnsNeuronRecipes. To prevent collisions,
/// iterate over count and use the value as the memo.
pub fn create_generic_sns_neuron_recipes(count: u64) -> Vec<SnsNeuronRecipe> {
    (0..count)
        .map(|memo| SnsNeuronRecipe {
            sns: Some(TransferableAmount {
                amount_e8s: E8,
                ..Default::default()
            }),
            neuron_attributes: Some(NeuronAttributes {
                memo,
                dissolve_delay_seconds: ONE_MONTH_SECONDS,
                followees: vec![],
            }),
            investor: Some(Direct(DirectInvestment {
                buyer_principal: (*TEST_USER1_PRINCIPAL).to_string(),
            })),
            claimed_status: Some(ClaimedStatus::Pending as i32),
        })
        .collect()
}

pub fn create_generic_cf_participants(count: u64) -> Vec<CfParticipant> {
    (0..count)
        .map(|i| CfParticipant {
            hotkey_principal: i2principal_id_string(i),
            cf_neurons: vec![CfNeuron {
                nns_neuron_id: i,
                amount_icp_e8s: E8,
            }],
        })
        .collect()
}

pub fn paginate_participants(swap: &Swap, limit: usize) -> Vec<Participant> {
    let mut participants = vec![];
    let mut offset = 0;

    loop {
        let list_direct_participants_response =
            swap.list_direct_participants(ListDirectParticipantsRequest {
                limit: Some(limit as u32),
                offset: Some(offset),
            });

        let len = list_direct_participants_response.participants.len();
        assert!(len <= limit);

        participants.extend(list_direct_participants_response.participants);
        offset += len as u32;

        if len < limit {
            return participants;
        }
    }
}

pub fn get_snapshot_of_buyers_index_list() -> Vec<PrincipalId> {
    memory::BUYERS_LIST_INDEX.with(|m| m.borrow().iter().collect())
}
