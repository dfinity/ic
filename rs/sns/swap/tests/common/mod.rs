use crate::{
    NNS_GOVERNANCE_CANISTER_ID, SWAP_CANISTER_ID,
    common::doubles::{LedgerExpect, MockLedger},
    now_fn,
};
use candid::Principal;
use ic_base_types::PrincipalId;
use ic_ledger_core::Tokens;
use ic_nervous_system_common::{
    DEFAULT_TRANSFER_FEE, E8, ONE_MONTH_SECONDS, ledger::compute_neuron_staking_subaccount_bytes,
};
use ic_nervous_system_common_test_keys::TEST_USER1_PRINCIPAL;
use ic_sns_governance::pb::v1::{
    ClaimSwapNeuronsResponse, ClaimedSwapNeuronStatus, NeuronId,
    claim_swap_neurons_response::{ClaimSwapNeuronsResult, ClaimedSwapNeurons, SwapNeuron},
};
use ic_sns_swap::{
    memory,
    pb::v1::{
        CfNeuron, CfParticipant, DirectInvestment, ErrorRefundIcpRequest, ErrorRefundIcpResponse,
        ListDirectParticipantsRequest, Participant, SetDappControllersCallResult,
        SetDappControllersResponse, SetModeCallResult, SnsNeuronRecipe, Swap, SweepResult,
        TransferableAmount, error_refund_icp_response,
        set_mode_call_result::SetModeResult,
        sns_neuron_recipe::{ClaimedStatus, Investor, Investor::Direct, NeuronAttributes},
    },
    swap::{
        CLAIM_SWAP_NEURONS_BATCH_SIZE, NEURON_BASKET_MEMO_RANGE_START, principal_to_subaccount,
    },
};
use icrc_ledger_types::icrc1::account::Account;
use std::{
    str::FromStr,
    sync::{Arc, Mutex},
};

pub mod doubles;

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
        panic!("Cannot find principal {buyer_principal}");
    }

    neurons
}

pub fn verify_direct_participant_icp_balances(
    swap: &Swap,
    buyer_principal: &PrincipalId,
    icp_balance_e8s: u64,
) {
    let buyer = swap.buyers.get(&buyer_principal.to_string()).unwrap();
    assert_eq!(icp_balance_e8s, buyer.amount_icp_e8s());
}

pub fn verify_direct_participant_sns_balances(
    swap: &Swap,
    buyer_principal: &PrincipalId,
    sns_balance_e8s: u64,
) {
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

pub fn create_successful_swap_neuron_basket_for_one_direct_participant(
    controller: PrincipalId,
    basket_count: u64,
) -> Vec<SwapNeuron> {
    (0..basket_count)
        .map(|i| SwapNeuron {
            id: Some(NeuronId {
                id: compute_neuron_staking_subaccount_bytes(
                    controller,
                    NEURON_BASKET_MEMO_RANGE_START + i,
                )
                .into(),
            }),
            status: ClaimedSwapNeuronStatus::Success as i32,
        })
        .collect()
}

pub fn create_successful_swap_neuron_basket_for_neurons_fund(
    nns_governance_principal_id: PrincipalId,
    num_neurons_fund_participants: usize,
    basket_count: u64,
) -> Vec<SwapNeuron> {
    (0..num_neurons_fund_participants)
        .flat_map(|j| {
            (0..basket_count).map(move |i| SwapNeuron {
                id: Some(NeuronId {
                    id: compute_neuron_staking_subaccount_bytes(
                        nns_governance_principal_id,
                        NEURON_BASKET_MEMO_RANGE_START + (j as u64) * basket_count + i,
                    )
                    .into(),
                }),
                status: ClaimedSwapNeuronStatus::Success as i32,
            })
        })
        .collect()
}

pub fn mock_stub(mut expect: Vec<LedgerExpect>) -> MockLedger {
    expect.reverse();
    let e = Arc::new(Mutex::new(expect));
    MockLedger { expect: e }
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
        .chunks(CLAIM_SWAP_NEURONS_BATCH_SIZE)
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
    (1..count + 1)
        .map(|i| {
            let i = i * 3;
            #[allow(deprecated)] // TODO(NNS1-3198): remove once hotkey_principal is removed
            CfParticipant {
                controller: Some(PrincipalId::new_user_test_id(i)),
                hotkey_principal: ic_nervous_system_common::obsolete_string_field(
                    "hotkey_principal",
                    Some("controller"),
                ),
                cf_neurons: vec![
                    CfNeuron::try_new(
                        i,
                        E8,
                        vec![
                            PrincipalId::new_user_test_id(i + 1),
                            PrincipalId::new_user_test_id(i + 2),
                        ],
                    )
                    .unwrap(),
                ],
            }
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
    memory::BUYERS_LIST_INDEX.with(|m| {
        m.borrow()
            .iter()
            .map(|principal| principal.into())
            .collect()
    })
}

pub async fn buy_token(swap: &mut Swap, user: &PrincipalId, amount: &u64, ledger: &MockLedger) {
    assert!(
        swap.refresh_buyer_token_e8s(*user, None, SWAP_CANISTER_ID, ledger)
            .await
            .is_ok()
    );
    assert_eq!(
        swap.buyers
            .get(&user.clone().to_string())
            .unwrap()
            .amount_icp_e8s(),
        amount.clone()
    );
}

pub async fn try_error_refund_ok(
    swap: &mut Swap,
    user: &PrincipalId,
    ledger: &MockLedger,
) -> error_refund_icp_response::Ok {
    match swap
        .error_refund_icp(
            SWAP_CANISTER_ID,
            &ErrorRefundIcpRequest {
                source_principal_id: Some(*user),
            },
            ledger,
        )
        .await
    {
        ErrorRefundIcpResponse {
            result: Some(error_refund_icp_response::Result::Ok(ok)),
        } => ok,
        _ => panic!("Expected error refund not to fail!"),
    }
}

pub fn get_sns_balance(user: &PrincipalId, swap: &mut Swap) -> u64 {
    swap.buyers.get(&user.to_string()).unwrap().amount_icp_e8s()
}

pub async fn try_error_refund_err(
    swap: &mut Swap,
    user: &PrincipalId,
    ledger: &MockLedger,
) -> error_refund_icp_response::Err {
    match swap
        .error_refund_icp(
            SWAP_CANISTER_ID,
            &ErrorRefundIcpRequest {
                source_principal_id: Some(*user),
            },
            ledger,
        )
        .await
    {
        ErrorRefundIcpResponse {
            result: Some(error_refund_icp_response::Result::Err(error)),
        } => error,
        _ => panic!("Expected error refund to fail!"),
    }
}

pub fn get_transfer_and_account_balance_mock_ledger(
    amount: &u64,
    from_subaccount: &PrincipalId,
    to: &PrincipalId,
    error: bool,
) -> Vec<LedgerExpect> {
    vec![
        LedgerExpect::AccountBalance(
            Account {
                owner: SWAP_CANISTER_ID.into(),
                subaccount: Some(principal_to_subaccount(from_subaccount)),
            },
            Ok(Tokens::from_e8s(*amount)),
        ),
        LedgerExpect::TransferFunds(
            *amount - DEFAULT_TRANSFER_FEE.get_e8s(),
            DEFAULT_TRANSFER_FEE.get_e8s(),
            Some(principal_to_subaccount(from_subaccount)),
            Account {
                owner: (*to).into(),
                subaccount: None,
            },
            0,
            match error {
                false => Ok(100),
                true => Err(101),
            },
        ),
    ]
}

pub fn get_transfer_mock_ledger(
    amount: &u64,
    from_subaccount: &PrincipalId,
    to: &PrincipalId,
    error: bool,
) -> Vec<LedgerExpect> {
    vec![LedgerExpect::TransferFunds(
        *amount - DEFAULT_TRANSFER_FEE.get_e8s(),
        DEFAULT_TRANSFER_FEE.get_e8s(),
        Some(principal_to_subaccount(from_subaccount)),
        Account {
            owner: (*to).into(),
            subaccount: None,
        },
        0,
        match error {
            false => Ok(100),
            true => Err(101),
        },
    )]
}

pub fn get_account_balance_mock_ledger(amount: &u64, user: &PrincipalId) -> Vec<LedgerExpect> {
    vec![LedgerExpect::AccountBalance(
        Account {
            owner: SWAP_CANISTER_ID.into(),
            subaccount: Some(principal_to_subaccount(user)),
        },
        Ok(Tokens::from_e8s(*amount)),
    )]
}

pub async fn sweep(swap: &mut Swap, ledger: &MockLedger) -> SweepResult {
    swap.sweep_icp(now_fn, ledger).await
}
