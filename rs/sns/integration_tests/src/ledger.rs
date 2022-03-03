use dfn_candid::candid_one;
use dfn_protobuf::protobuf;
use ic_base_types::PrincipalId;
use ic_canister_client::Sender;
use ic_crypto_sha::Sha256;
use ic_nns_constants::ids::TEST_USER1_KEYPAIR;
use ic_sns_governance::pb::v1::manage_neuron_response::Command as CommandResponse;

use ic_sns_governance::pb::v1::manage_neuron::claim_or_refresh::{By, MemoAndController};
use ic_sns_governance::pb::v1::manage_neuron::{ClaimOrRefresh, Command, Disburse};
use ic_sns_governance::pb::v1::{
    ManageNeuron, ManageNeuronResponse, NervousSystemParameters, NeuronPermissionList,
    NeuronPermissionType,
};
use ic_sns_test_utils::itest_helpers::{
    local_test_on_sns_subnet, SnsCanisters, SnsInitPayloadsBuilder,
};
use ic_sns_test_utils::TEST_GOVERNANCE_CANISTER_ID;
use ledger_canister::{
    AccountBalanceArgs, AccountIdentifier, Memo, SendArgs, Subaccount, Tokens, DEFAULT_TRANSFER_FEE,
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

            let sns_init_payload = SnsInitPayloadsBuilder::new()
                .with_ledger_account(user.get_principal_id().into(), alloc)
                .with_nervous_system_parameters(system_params)
                .build();

            let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

            let user_balance: Tokens = sns_canisters
                .ledger
                .query_(
                    "account_balance_pb",
                    protobuf,
                    AccountBalanceArgs {
                        account: user.get_principal_id().into(),
                    },
                )
                .await?;
            assert_eq!(alloc, user_balance);

            // Stake a neuron by transferring to a subaccount of the neurons
            // canister and claiming the neuron on the governance canister..
            let nonce = 12345u64;
            let to_subaccount = Subaccount({
                let mut state = Sha256::new();
                state.write(&[0x0c]);
                state.write(b"neuron-stake");
                state.write(user.get_principal_id().as_slice());
                state.write(&nonce.to_be_bytes());
                state.finish()
            });

            // Stake the neuron.
            let stake = Tokens::from_tokens(100).unwrap();
            let _block_height: u64 = sns_canisters
                .ledger
                .update_from_sender(
                    "send_pb",
                    protobuf,
                    SendArgs {
                        memo: Memo(nonce),
                        amount: stake,
                        fee: DEFAULT_TRANSFER_FEE,
                        from_subaccount: None,
                        to: AccountIdentifier::new(
                            PrincipalId::from(TEST_GOVERNANCE_CANISTER_ID),
                            Some(to_subaccount),
                        ),
                        created_at_time: None,
                    },
                    &user,
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
                CommandResponse::Error(error) => panic!("Unexpected error: {}", error),
                CommandResponse::ClaimOrRefresh(claim_or_refresh_response) => {
                    claim_or_refresh_response.refreshed_neuron_id.unwrap()
                }
                _ => panic!("Unexpected command response."),
            };

            // The balance now should have been deducted the stake.
            let user_balance: Tokens = sns_canisters
                .ledger
                .query_(
                    "account_balance_pb",
                    protobuf,
                    AccountBalanceArgs {
                        account: user.get_principal_id().into(),
                    },
                )
                .await?;
            // The balance should now be: initial allocation - stake - fee
            assert_eq!(
                Tokens::from_e8s(
                    user_balance.get_e8s() + stake.get_e8s() + DEFAULT_TRANSFER_FEE.get_e8s()
                ),
                alloc
            );

            let subaccount = match neuron_id.subaccount() {
                Ok(s) => s,
                Err(e) => panic!("Error creating the subaccount, {}", e),
            };

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
                            to_account: Some(
                                AccountIdentifier::new(user.get_principal_id(), None).into(),
                            ),
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
            let user_balance: Tokens = sns_canisters
                .ledger
                .update_from_sender(
                    "account_balance_pb",
                    protobuf,
                    AccountBalanceArgs {
                        account: user.get_principal_id().into(),
                    },
                    &user,
                )
                .await?;

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
