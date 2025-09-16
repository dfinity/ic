use candid::types::number::Nat;
use dfn_candid::candid_one;
use ic_base_types::PrincipalId;
use ic_canister_client_sender::Sender;
use ic_crypto_sha2::Sha256;
use ic_ledger_core::{Tokens, tokens::TOKEN_SUBDIVIDABLE_BY};
use ic_nervous_system_common::DEFAULT_TRANSFER_FEE;
use ic_nervous_system_common_test_keys::TEST_USER1_KEYPAIR;
use ic_sns_governance::pb::v1::manage_neuron_response::Command as CommandResponse;
use icrc_ledger_types::icrc1::{
    account::Account,
    transfer::{Memo, TransferArg},
};

use ic_sns_governance::pb::v1::{
    Account as AccountProto, ManageNeuron, ManageNeuronResponse, NervousSystemParameters,
    NeuronPermissionList, NeuronPermissionType,
    manage_neuron::{
        ClaimOrRefresh, Command, Disburse,
        claim_or_refresh::{By, MemoAndController},
    },
};
use ic_sns_test_utils::{
    icrc1,
    itest_helpers::{SnsCanisters, SnsTestsInitPayloadBuilder, local_test_on_sns_subnet},
};

// This tests the whole neuron lifecycle in integration with the ledger. Namely
// tests that the neuron can be staked from a ledger account. That the neuron
// can be claimed and ultimately disbursed to the same account.
#[test]
fn test_stake_and_disburse_neuron_with_notification() {
    local_test_on_sns_subnet(|runtime| {
        async move {
            // Initialize the ledger with an account for a user.
            let user = Sender::from_keypair(&TEST_USER1_KEYPAIR);
            let alloc = Tokens::from_tokens(1000).unwrap();

            let system_params = NervousSystemParameters {
                neuron_claimer_permissions: Some(NeuronPermissionList {
                    permissions: NeuronPermissionType::all(),
                }),
                ..NervousSystemParameters::with_default_values()
            };

            let sns_init_payload = SnsTestsInitPayloadBuilder::new()
                .with_ledger_account(user.get_principal_id().0.into(), alloc)
                .with_nervous_system_parameters(system_params)
                .build();

            let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

            let user_balance = icrc1::balance_of(
                &sns_canisters.ledger,
                Account {
                    owner: user.get_principal_id().0,
                    subaccount: None,
                },
            )
            .await
            .map(Tokens::from_e8s)?;
            assert_eq!(alloc, user_balance);

            // Stake a neuron by transferring to a subaccount of the neurons
            // canister and claiming the neuron on the governance canister..
            let nonce = 12345u64;
            let to_subaccount = {
                let mut state = Sha256::new();
                state.write(&[0x0c]);
                state.write(b"neuron-stake");
                state.write(user.get_principal_id().as_slice());
                state.write(&nonce.to_be_bytes());
                state.finish()
            };

            // Stake the neuron.
            let stake = 100 * TOKEN_SUBDIVIDABLE_BY;
            let _block_height = icrc1::transfer(
                &sns_canisters.ledger,
                &user,
                TransferArg {
                    amount: Nat::from(stake),
                    fee: Some(Nat::from(DEFAULT_TRANSFER_FEE.get_e8s())),
                    from_subaccount: None,
                    to: Account {
                        owner: PrincipalId::from(sns_canisters.governance.canister_id()).0,
                        subaccount: Some(to_subaccount),
                    },
                    created_at_time: None,
                    memo: Some(Memo::from(nonce)),
                },
            )
            .await
            .expect("Couldn't send funds.");

            // Claim the neuron on the governance canister.
            let manage_neuron_response: ManageNeuronResponse = sns_canisters
                .governance
                .update_from_sender(
                    "manage_neuron",
                    candid_one,
                    ManageNeuron {
                        subaccount: to_subaccount.to_vec(),
                        command: Some(Command::ClaimOrRefresh(ClaimOrRefresh {
                            by: Some(By::MemoAndController(MemoAndController {
                                memo: nonce,
                                controller: None,
                            })),
                        })),
                    },
                    &user,
                )
                .await
                .expect("Error calling the manage_neuron api.");

            let neuron_id = match manage_neuron_response.command.unwrap() {
                CommandResponse::Error(error) => panic!("Unexpected error: {error}"),
                CommandResponse::ClaimOrRefresh(claim_or_refresh_response) => {
                    claim_or_refresh_response.refreshed_neuron_id.unwrap()
                }
                _ => panic!("Unexpected command response."),
            };

            // The balance now should have been deducted the stake.
            let user_balance = icrc1::balance_of(
                &sns_canisters.ledger,
                Account {
                    owner: user.get_principal_id().0,
                    subaccount: None,
                },
            )
            .await
            .map(Tokens::from_e8s)?;
            // The balance should now be: initial allocation - stake - fee
            assert_eq!(
                Tokens::from_e8s(user_balance.get_e8s() + stake + DEFAULT_TRANSFER_FEE.get_e8s()),
                alloc
            );

            let subaccount = neuron_id
                .subaccount()
                .expect("Error creating the subaccount");

            // Disburse the neuron.
            let result: ManageNeuronResponse = sns_canisters
                .governance
                .update_from_sender(
                    "manage_neuron",
                    candid_one,
                    ManageNeuron {
                        subaccount: subaccount.to_vec(),
                        command: Some(Command::Disburse(Disburse {
                            amount: None,
                            to_account: Some(AccountProto {
                                owner: Some(user.get_principal_id()),
                                subaccount: None,
                            }),
                        })),
                    },
                    &user,
                )
                .await
                .expect("Error calling the manage_neuron api.");
            result.expect("Error disbursing the neuron.");

            // Check the balance again.
            //
            // Use an "update" instead of a query to make sure that the transfer
            // was executed first.
            let user_balance: Tokens = icrc1::balance_of(
                &sns_canisters.ledger,
                Account {
                    owner: user.get_principal_id().0,
                    subaccount: None,
                },
            )
            .await
            .map(Tokens::from_e8s)?;

            // The balance should now be: initial allocation - fee * 2 (one fee for the
            // stake and one for the disburse).
            assert_eq!(
                Tokens::from_e8s(user_balance.get_e8s() + 2 * DEFAULT_TRANSFER_FEE.get_e8s()),
                alloc
            );

            Ok(())
        }
    });
}
