use canister_test::Canister;
use dfn_candid::candid_one;
use dfn_protobuf::protobuf;
use ic_canister_client::Sender;
use ic_crypto_sha::Sha256;
use ic_nervous_system_common_test_keys::{
    TEST_USER1_KEYPAIR, TEST_USER2_KEYPAIR, TEST_USER3_KEYPAIR, TEST_USER4_KEYPAIR,
};
use ic_sns_governance::pb::v1::governance_error::ErrorType;
use ic_sns_governance::pb::v1::manage_neuron::{
    claim_or_refresh::{By, MemoAndController},
    configure::Operation,
    AddNeuronPermissions, ClaimOrRefresh, Configure, IncreaseDissolveDelay,
};
use ic_sns_governance::pb::v1::manage_neuron::{
    Command, DisburseMaturity, RemoveNeuronPermissions,
};
use ic_sns_governance::pb::v1::manage_neuron_response::Command as CommandResponse;
use ic_sns_governance::pb::v1::proposal::Action;
use ic_sns_governance::pb::v1::{
    Empty, ListNeurons, ListNeuronsResponse, ManageNeuron, ManageNeuronResponse, Motion,
    NervousSystemParameters, Neuron, NeuronId, NeuronPermission, NeuronPermissionList,
    NeuronPermissionType, Proposal,
};
use ic_sns_governance::types::ONE_YEAR_SECONDS;
use ic_sns_test_utils::itest_helpers::{
    local_test_on_sns_subnet, SnsCanisters, SnsInitPayloadsBuilder, UserInfo, NONCE,
};
use ic_types::PrincipalId;
use ledger_canister::{AccountIdentifier, Tokens, TOKEN_SUBDIVIDABLE_BY};
use ledger_canister::{Memo, SendArgs, Subaccount, DEFAULT_TRANSFER_FEE};
use std::collections::HashSet;
use std::iter::FromIterator;

// This tests the determinism of list_neurons, now that the subaccount is used for
// the unique identifier of the Neuron.
#[test]
fn test_list_neurons_determinism() {
    local_test_on_sns_subnet(|runtime| async move {
        let users = vec![
            Sender::from_keypair(&TEST_USER1_KEYPAIR),
            Sender::from_keypair(&TEST_USER2_KEYPAIR),
            Sender::from_keypair(&TEST_USER3_KEYPAIR),
            Sender::from_keypair(&TEST_USER4_KEYPAIR),
        ];

        let account_identifiers = users
            .iter()
            .map(|user| AccountIdentifier::from(user.get_principal_id()))
            .collect();

        let alloc = Tokens::from_tokens(1000).unwrap();
        let sns_init_payload = SnsInitPayloadsBuilder::new()
            .with_ledger_accounts(account_identifiers, alloc)
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        for user in &users {
            sns_canisters.stake_and_claim_neuron(user, None).await;
        }

        let list_neuron_response: ListNeuronsResponse = sns_canisters
            .governance
            .query_from_sender(
                "list_neurons",
                candid_one,
                ListNeurons {
                    limit: 100,
                    start_page_at: None,
                    of_principal: None,
                },
                &users[0],
            )
            .await
            .expect("Error calling the list_neurons api");

        let expected = list_neuron_response.neurons;
        let actual = paginate_neurons(&sns_canisters.governance, &users[0], 1_usize).await;

        assert_eq!(expected, actual);

        Ok(())
    });
}

#[test]
fn test_list_neurons_of_principal() {
    local_test_on_sns_subnet(|runtime| async move {
        let user1 = Sender::from_keypair(&TEST_USER1_KEYPAIR);
        let user2 = Sender::from_keypair(&TEST_USER2_KEYPAIR);
        let user3 = Sender::from_keypair(&TEST_USER3_KEYPAIR);

        let account_identifier1 = AccountIdentifier::from(user1.get_principal_id());
        let account_identifier2 = AccountIdentifier::from(user2.get_principal_id());

        let sys_params = NervousSystemParameters {
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            ..NervousSystemParameters::with_default_values()
        };

        let alloc = Tokens::from_tokens(1000).unwrap();

        let sns_init_payload = SnsInitPayloadsBuilder::new()
            .with_ledger_account(account_identifier1, alloc)
            .with_ledger_account(account_identifier2, alloc)
            .with_nervous_system_parameters(sys_params)
            .build();
        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        sns_canisters.stake_and_claim_neuron(&user1, None).await;
        sns_canisters.stake_and_claim_neuron(&user2, None).await;

        let all_neurons: Vec<Neuron> = sns_canisters.list_neurons_(&user1, 100, None).await;

        assert_eq!(all_neurons.len(), 2);

        let neurons_of_principal: Vec<Neuron> = sns_canisters
            .list_neurons_(&user1, 100, Some(user1.get_principal_id()))
            .await;

        assert_eq!(neurons_of_principal.len(), 1);

        let neurons_of_principal: Vec<Neuron> = sns_canisters
            .list_neurons_(&user1, 100, Some(user3.get_principal_id()))
            .await;

        assert_eq!(neurons_of_principal.len(), 0);

        Ok(())
    });
}

#[test]
fn test_claim_neuron_with_default_permissions() {
    local_test_on_sns_subnet(|runtime| async move {
        let user = Sender::from_keypair(&TEST_USER1_KEYPAIR);
        let alloc = Tokens::from_tokens(1000).unwrap();

        let sns_init_payload = SnsInitPayloadsBuilder::new()
            .with_ledger_account(user.get_principal_id().into(), alloc)
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        let neuron_id = sns_canisters.stake_and_claim_neuron(&user, None).await;
        let neuron = sns_canisters.get_neuron(&neuron_id).await;

        let expected = vec![NeuronPermission::new(
            &user.get_principal_id(),
            NervousSystemParameters::with_default_values()
                .neuron_claimer_permissions
                .unwrap()
                .permissions,
        )];

        assert_eq!(neuron.permissions, expected);
        Ok(())
    });
}

#[test]
fn test_claim_neuron() {
    local_test_on_sns_subnet(|runtime| async move {
        // Set up an SNS with a ledger account for a single user
        let user = Sender::from_keypair(&TEST_USER1_KEYPAIR);
        let alloc = Tokens::from_tokens(1000).unwrap();

        let sys_params = NervousSystemParameters {
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsInitPayloadsBuilder::new()
            .with_ledger_account(user.get_principal_id().into(), alloc)
            .with_nervous_system_parameters(sys_params.clone())
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        // Calculate the user's subaccount (used in the staking transfer).
        let subaccount = Subaccount({
            let mut state = Sha256::new();
            state.write(&[0x0c]);
            state.write(b"neuron-stake");
            state.write(user.get_principal_id().as_slice());
            state.write(&NONCE.to_be_bytes());
            state.finish()
        });

        // Try claiming the Neuron (via memo and controller) before making the staking
        // transfer (funding the neuron). This should fail.
        let manage_neuron_command = ManageNeuron {
            subaccount: subaccount.to_vec(),
            command: Some(Command::ClaimOrRefresh(ClaimOrRefresh {
                by: Some(By::MemoAndController(MemoAndController {
                    memo: NONCE,
                    controller: None,
                })),
            })),
        };

        let response: ManageNeuronResponse = sns_canisters
            .governance
            .update_from_sender(
                "manage_neuron",
                candid_one,
                manage_neuron_command.clone(),
                &user,
            )
            .await
            .expect("Error calling the manage_neuron api.");

        // assert that the error_type is InsufficientFunds.
        let error = match response.command.unwrap() {
            CommandResponse::Error(error) => error,
            CommandResponse::ClaimOrRefresh(_) => {
                panic!(
                    "User should not have been able to claim the neuron due to insufficient funds"
                )
            }
            _ => panic!("Unexpected command response when claiming neuron"),
        };
        assert_eq!(error.error_type, ErrorType::InsufficientFunds as i32);

        // Now stake 1 governance token using the calculated subaccount
        sns_canisters
            .stake_neuron_account(&user, &subaccount, 1)
            .await;

        // Retry the same ClaimOrRefresh request. Now that the staking transfer
        // has been made, it should succeed this time (unlike the previous attempt),
        // and it should result in a new neuron.
        let response: ManageNeuronResponse = sns_canisters
            .governance
            .update_from_sender(
                "manage_neuron",
                candid_one,
                manage_neuron_command.clone(),
                &user,
            )
            .await
            .expect("Error calling the manage_neuron api.");

        let claim_or_refresh_response = match response.command.unwrap() {
            CommandResponse::ClaimOrRefresh(response) => response,
            _ => panic!("Unexpected command response when claiming neuron."),
        };

        let neuron_id = claim_or_refresh_response.refreshed_neuron_id.unwrap();
        let neuron = sns_canisters.get_neuron(&neuron_id).await;
        // The neuron's cached_neuron_stake_e8s should equal the 1 token (e8s) that was staked.
        assert_eq!(neuron.cached_neuron_stake_e8s, TOKEN_SUBDIVIDABLE_BY);

        Ok(())
    });
}

#[test]
fn test_claim_neuron_fails_when_max_number_of_neurons_is_reached() {
    local_test_on_sns_subnet(|runtime| async move {
        // Set up an SNS with a ledger account for two users
        let user1 = UserInfo::new(Sender::from_keypair(&TEST_USER1_KEYPAIR));
        let user2 = UserInfo::new(Sender::from_keypair(&TEST_USER2_KEYPAIR));
        let alloc = Tokens::from_tokens(1000).unwrap();

        let sys_params = NervousSystemParameters {
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            max_number_of_neurons: Some(1),
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsInitPayloadsBuilder::new()
            .with_ledger_account(user1.sender.get_principal_id().into(), alloc)
            .with_ledger_account(user2.sender.get_principal_id().into(), alloc)
            .with_nervous_system_parameters(sys_params.clone())
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        // Successfully STAKE and CLAIM user1's neuron, reaching the configured maximum number of
        // neurons allowed in the system
        sns_canisters
            .stake_and_claim_neuron(&user1.sender, Some(ONE_YEAR_SECONDS as u32))
            .await;

        // Only STAKE for user2.
        sns_canisters
            .stake_neuron_account(&user2.sender, &user2.subaccount, 1)
            .await;

        let manage_neuron_command = ManageNeuron {
            subaccount: user2.subaccount.to_vec(),
            command: Some(Command::ClaimOrRefresh(ClaimOrRefresh {
                by: Some(By::MemoAndController(MemoAndController {
                    memo: NONCE,
                    controller: None,
                })),
            })),
        };

        // Try claiming the Neuron for user2 (via memo and controller). This should fail due to
        // the max_number_of_neurons being reached.
        let response: ManageNeuronResponse = sns_canisters
            .governance
            .update_from_sender(
                "manage_neuron",
                candid_one,
                manage_neuron_command.clone(),
                &user2.sender,
            )
            .await
            .expect("Error calling the manage_neuron api.");

        // assert that the error_type is PreconditionFailed.
        let error = match response.command.unwrap() {
            CommandResponse::Error(error) => error,
            CommandResponse::ClaimOrRefresh(_) => {
                panic!("User should not have been able to claim a neuron due to reaching max_number_of_neurons")
            }
            _ => panic!("Unexpected command response when claiming neuron."),
        };
        assert_eq!(error.error_type, ErrorType::PreconditionFailed as i32);

        // Update the NervousSystemParameters (with user1) to increase max_number_of_neurons by 1
        let update_to_nervous_system_params = NervousSystemParameters {
            max_number_of_neurons: Some(sys_params.max_number_of_neurons.unwrap() + 1),
            ..Default::default()
        };
        sns_canisters
            .manage_nervous_system_parameters(
                &user1.sender,
                &user1.subaccount,
                update_to_nervous_system_params,
            )
            .await
            .expect("Expected updating NervousSystemParameters to succeed");

        // Try to claim the neuron (via memo and controller). Now that the max_number_of_neurons
        // has increased, this should result in a new neuron.
        let response: ManageNeuronResponse = sns_canisters
            .governance
            .update_from_sender(
                "manage_neuron",
                candid_one,
                manage_neuron_command.clone(),
                &user2.sender,
            )
            .await
            .expect("Error calling the manage_neuron api.");

        let claim_or_refresh_response = match response.command.unwrap() {
            CommandResponse::ClaimOrRefresh(response) => response,
            _ => panic!("Unexpected command response when claiming neuron."),
        };

        let neuron_id = claim_or_refresh_response.refreshed_neuron_id.unwrap();
        let neuron = sns_canisters.get_neuron(&neuron_id).await;
        // The neuron's cached_neuron_stake_e8s should equal the 1 token (e8s) that was staked.
        assert_eq!(neuron.cached_neuron_stake_e8s, TOKEN_SUBDIVIDABLE_BY);

        Ok(())
    });
}

#[test]
fn test_refresh_neuron() {
    local_test_on_sns_subnet(|runtime| async move {
        // Set up an SNS with a ledger account for a single user
        let user = UserInfo::new(Sender::from_keypair(&TEST_USER1_KEYPAIR));
        let alloc = Tokens::from_tokens(1000).unwrap();

        let params = NervousSystemParameters {
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsInitPayloadsBuilder::new()
            .with_ledger_account(user.sender.get_principal_id().into(), alloc)
            .with_nervous_system_parameters(params.clone())
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        // STAKE and CLAIM 1 token for the user to measure the neuron's pre-refresh stake
        sns_canisters
            .stake_and_claim_neuron_with_tokens(&user.sender, Some(ONE_YEAR_SECONDS as u32), 1)
            .await;

        let neuron = sns_canisters.get_neuron(&user.neuron_id).await;

        let cached_neuron_stake_e8s_before_refresh = neuron.cached_neuron_stake_e8s;

        // STAKE another token to subaccount of the already existing neuron. The ledger account
        // should then be greater than the neuron's cached stake.
        sns_canisters
            .stake_neuron_account(&user.sender, &user.subaccount, 1)
            .await;

        // Refresh the neuron via memo and controller by using the By::MemoAndController method
        let response: ManageNeuronResponse = sns_canisters
            .governance
            .update_from_sender(
                "manage_neuron",
                candid_one,
                ManageNeuron {
                    subaccount: user.subaccount.to_vec(),
                    command: Some(Command::ClaimOrRefresh(ClaimOrRefresh {
                        by: Some(By::MemoAndController(MemoAndController {
                            memo: NONCE,
                            controller: Some(user.sender.get_principal_id()),
                        })),
                    })),
                },
                &user.sender,
            )
            .await
            .expect("Error calling the manage_neuron api.");

        let claim_or_refresh_response = match response.command.unwrap() {
            CommandResponse::ClaimOrRefresh(response) => response,
            _ => panic!("Unexpected command response when claiming neuron."),
        };

        let neuron_id = claim_or_refresh_response.refreshed_neuron_id.unwrap();
        let neuron = sns_canisters.get_neuron(&neuron_id).await;
        // Make sure the previously recorded cached state has increased by
        // 1 token (unit is e8s hence TOKEN_SUBDIVIDABLE_BY)
        assert_eq!(
            cached_neuron_stake_e8s_before_refresh + TOKEN_SUBDIVIDABLE_BY,
            neuron.cached_neuron_stake_e8s
        );

        // STAKE another token to subaccount of the already existing neuron. The ledger account
        // should then be greater than the neuron's cached stake.
        sns_canisters
            .stake_neuron_account(&user.sender, &user.subaccount, 1)
            .await;

        // Refresh the neuron via NeuronId by using the By::NeuronId method
        let response: ManageNeuronResponse = sns_canisters
            .governance
            .update_from_sender(
                "manage_neuron",
                candid_one,
                ManageNeuron {
                    subaccount: user.subaccount.to_vec(),
                    command: Some(Command::ClaimOrRefresh(ClaimOrRefresh {
                        by: Some(By::NeuronId(Empty {})),
                    })),
                },
                &user.sender,
            )
            .await
            .expect("Error calling the manage_neuron api.");

        let claim_or_refresh_response = match response.command.unwrap() {
            CommandResponse::ClaimOrRefresh(response) => response,
            _ => panic!("Unexpected command response when claiming neuron."),
        };

        let neuron_id = claim_or_refresh_response.refreshed_neuron_id.unwrap();
        let neuron = sns_canisters.get_neuron(&neuron_id).await;
        // Make sure the previously recorded cached state has increased by
        // 2 tokens (unit is e8s hence TOKEN_SUBDIVIDABLE_BY)
        assert_eq!(
            cached_neuron_stake_e8s_before_refresh + (2 * TOKEN_SUBDIVIDABLE_BY),
            neuron.cached_neuron_stake_e8s
        );

        Ok(())
    });
}

#[test]
fn test_neuron_action_is_not_authorized() {
    local_test_on_sns_subnet(|runtime| async move {
        let neuron_owner = Sender::from_keypair(&TEST_USER1_KEYPAIR);
        let unauthorized_caller = Sender::from_keypair(&TEST_USER2_KEYPAIR);

        let neuron_owner_account_identifier =
            AccountIdentifier::from(neuron_owner.get_principal_id());
        let alloc = Tokens::from_tokens(1000).unwrap();

        let system_params = NervousSystemParameters {
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsInitPayloadsBuilder::new()
            .with_ledger_account(neuron_owner_account_identifier, alloc)
            .with_nervous_system_parameters(system_params)
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        // Stake and claim a neuron capable of making a proposal
        let neuron_owner_nid = sns_canisters
            .stake_and_claim_neuron(&neuron_owner, Some(ONE_YEAR_SECONDS as u32))
            .await;

        // Get that neuron's subaccount
        let neuron_owner_subaccount = neuron_owner_nid
            .subaccount()
            .expect("Error creating the subaccount");

        let proposal_payload = Proposal {
            title: "Motion to delete this SNS".into(),
            action: Some(Action::Motion(Motion {
                motion_text: "I'm a bad actor and this should not be tolerated".into(),
            })),
            ..Default::default()
        };

        let manage_neuron_response: ManageNeuronResponse = sns_canisters
            .governance
            .update_from_sender(
                "manage_neuron",
                candid_one,
                ManageNeuron {
                    subaccount: neuron_owner_subaccount.to_vec(),
                    command: Some(Command::MakeProposal(proposal_payload)),
                },
                &unauthorized_caller,
            )
            .await
            .expect("Error calling manage_neuron");

        match manage_neuron_response.command.unwrap() {
            CommandResponse::Error(e) => assert_eq!(e.error_type, ErrorType::NotAuthorized as i32),
            response => panic!("Unexpected response, {:?}", response),
        }

        Ok(())
    });
}

// TODO NNS1-925 - Re-enable tests when "Generic Voting Rewards" allow for maturity.
#[test]
#[ignore]
fn test_disburse_maturity() {
    local_test_on_sns_subnet(|runtime| async move {
        let user = Sender::from_keypair(&TEST_USER1_KEYPAIR);
        let account_identifier = AccountIdentifier::from(user.get_principal_id());
        let alloc = Tokens::from_tokens(1000).unwrap();

        let sys_params = NervousSystemParameters {
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsInitPayloadsBuilder::new()
            .with_ledger_account(account_identifier, alloc)
            .with_nervous_system_parameters(sys_params.clone())
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        // Stake and claim a neuron capable of making a proposal
        let neuron_id = sns_canisters
            .stake_and_claim_neuron(&user, Some(ONE_YEAR_SECONDS as u32))
            .await;

        let subaccount = neuron_id
            .subaccount()
            .expect("Error creating the subaccount");

        // Earn some maturity to test disburse_maturity
        sns_canisters
            .earn_maturity(&neuron_id, &user)
            .await
            .expect("Error when earning maturity");

        let neuron = sns_canisters.get_neuron(&neuron_id).await;
        let earned_maturity_e8s = neuron.maturity_e8s_equivalent;
        assert!(earned_maturity_e8s > 0);

        let balance_before_disbursal = sns_canisters.get_user_account_balance(&user).await;

        // Disburse all of the neuron's rewards aka maturity.
        let manage_neuron_response: ManageNeuronResponse = sns_canisters
            .governance
            .update_from_sender(
                "manage_neuron",
                candid_one,
                ManageNeuron {
                    subaccount: subaccount.to_vec(),
                    command: Some(Command::DisburseMaturity(DisburseMaturity {
                        percentage_to_disburse: 100,
                        to_account: None,
                    })),
                },
                &user,
            )
            .await
            .expect("Error calling the manage_neuron API.");

        let response = match manage_neuron_response.command.unwrap() {
            CommandResponse::DisburseMaturity(response) => response,
            response => panic!("Unexpected response from manage_neuron: {:?}", response),
        };
        assert!(response.transfer_block_height > 0);
        assert_eq!(response.amount_disbursed_e8s, earned_maturity_e8s);

        let neuron = sns_canisters.get_neuron(&neuron_id).await;
        assert_eq!(neuron.maturity_e8s_equivalent, 0);

        let balance_after_disbursal = sns_canisters.get_user_account_balance(&user).await;
        let expected_balance =
            (balance_before_disbursal + Tokens::from_e8s(response.amount_disbursed_e8s)).unwrap();
        assert_eq!(expected_balance, balance_after_disbursal);

        Ok(())
    });
}

// TODO NNS1-925 - Re-enable tests when "Generic Voting Rewards" allow for maturity.
#[test]
#[ignore]
fn test_disburse_maturity_to_different_account() {
    local_test_on_sns_subnet(|runtime| async move {
        let maturity_owner = Sender::from_keypair(&TEST_USER1_KEYPAIR);
        let maturity_owner_account_identifier =
            AccountIdentifier::from(maturity_owner.get_principal_id());
        let maturity_receiver = Sender::from_keypair(&TEST_USER2_KEYPAIR);

        let alloc = Tokens::from_tokens(1000).unwrap();

        let sys_params = NervousSystemParameters {
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsInitPayloadsBuilder::new()
            .with_ledger_account(maturity_owner_account_identifier, alloc)
            .with_nervous_system_parameters(sys_params.clone())
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        // Stake and claim a neuron capable of making a proposal
        let neuron_id = sns_canisters
            .stake_and_claim_neuron(&maturity_owner, Some(ONE_YEAR_SECONDS as u32))
            .await;

        let subaccount = neuron_id
            .subaccount()
            .expect("Error creating the subaccount");

        // Earn some maturity to test disburse_maturity
        sns_canisters
            .earn_maturity(&neuron_id, &maturity_owner)
            .await
            .expect("Error when earning maturity");

        let neuron = sns_canisters.get_neuron(&neuron_id).await;
        let earned_maturity_e8s = neuron.maturity_e8s_equivalent;
        assert!(earned_maturity_e8s > 0);

        let balance_before_disbursal = sns_canisters
            .get_user_account_balance(&maturity_receiver)
            .await;

        // Disburse half of maturity rewarded to neuron owned by user1. Funds are to be sent to user2's account.
        let manage_neuron_response: ManageNeuronResponse = sns_canisters
            .governance
            .update_from_sender(
                "manage_neuron",
                candid_one,
                ManageNeuron {
                    subaccount: subaccount.to_vec(),
                    command: Some(Command::DisburseMaturity(DisburseMaturity {
                        percentage_to_disburse: 50,
                        to_account: Some(
                            AccountIdentifier::new(maturity_receiver.get_principal_id(), None)
                                .into(),
                        ),
                    })),
                },
                &maturity_owner,
            )
            .await
            .expect("Error calling the manage_neuron API.");

        let response = match manage_neuron_response.command.unwrap() {
            CommandResponse::DisburseMaturity(response) => response,
            response => panic!("Unexpected response from manage_neuron: {:?}", response),
        };
        assert!(response.transfer_block_height > 0);
        // Disbursed 50% of the maturity
        assert_eq!(response.amount_disbursed_e8s, earned_maturity_e8s / 2);

        let neuron = sns_canisters.get_neuron(&neuron_id).await;
        let balance_after_disbursal = sns_canisters
            .get_user_account_balance(&maturity_receiver)
            .await;
        let expected_balance =
            (balance_before_disbursal + Tokens::from_e8s(response.amount_disbursed_e8s)).unwrap();
        // Neuron should now have 50% of what it has earned
        assert_eq!(neuron.maturity_e8s_equivalent, earned_maturity_e8s / 2);
        assert_eq!(expected_balance, balance_after_disbursal);

        Ok(())
    });
}

#[test]
fn test_disbursing_maturity_with_no_maturity_fails() {
    local_test_on_sns_subnet(|runtime| async move {
        let user = Sender::from_keypair(&TEST_USER1_KEYPAIR);
        let account_identifier = AccountIdentifier::from(user.get_principal_id());
        let alloc = Tokens::from_tokens(1000).unwrap();

        let sys_params = NervousSystemParameters {
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsInitPayloadsBuilder::new()
            .with_ledger_account(account_identifier, alloc)
            .with_nervous_system_parameters(sys_params.clone())
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        // Stake and claim a neuron capable of making a proposal
        let neuron_id = sns_canisters
            .stake_and_claim_neuron(&user, Some(ONE_YEAR_SECONDS as u32))
            .await;

        let subaccount = neuron_id
            .subaccount()
            .expect("Error creating the subaccount");

        let neuron = sns_canisters.get_neuron(&neuron_id).await;

        // No maturity should have been gained as no voting rewards have been distributed
        assert_eq!(neuron.maturity_e8s_equivalent, 0);

        // Disburse all of the neuron's rewards aka maturity.
        let manage_neuron_response: ManageNeuronResponse = sns_canisters
            .governance
            .update_from_sender(
                "manage_neuron",
                candid_one,
                ManageNeuron {
                    subaccount: subaccount.to_vec(),
                    command: Some(Command::DisburseMaturity(DisburseMaturity {
                        percentage_to_disburse: 100,
                        to_account: None,
                    })),
                },
                &user,
            )
            .await
            .expect("Error calling the manage_neuron API.");

        let response = match manage_neuron_response.command.unwrap() {
            CommandResponse::Error(error) => error,
            CommandResponse::DisburseMaturity(response) => panic!(
                "Neuron should not have been able to disburse maturity: {:?}",
                response
            ),
            response => panic!("Unexpected response from manage_neuron: {:?}", response),
        };

        assert_eq!(response.error_type, ErrorType::PreconditionFailed as i32);

        Ok(())
    });
}

async fn paginate_neurons(
    governance_canister: &Canister<'_>,
    user: &Sender,
    limit: usize,
) -> Vec<Neuron> {
    let mut all_neurons = vec![];
    let mut last_neuron_id: Option<NeuronId> = None;

    loop {
        let list_neuron_response: ListNeuronsResponse = governance_canister
            .query_from_sender(
                "list_neurons",
                candid_one,
                ListNeurons {
                    limit: limit as u32,
                    start_page_at: last_neuron_id.clone(),
                    of_principal: None,
                },
                user,
            )
            .await
            .expect("Error calling the list_neurons api");

        let len = list_neuron_response.neurons.len();
        let is_last = len < limit;
        assert!(len <= limit);

        if !list_neuron_response.neurons.is_empty() {
            last_neuron_id = Some(
                list_neuron_response.neurons[list_neuron_response.neurons.len() - 1]
                    .id
                    .as_ref()
                    .unwrap()
                    .clone(),
            );
            all_neurons.extend(list_neuron_response.neurons);
        }

        if is_last {
            return all_neurons;
        }
    }
}

#[test]
fn test_one_user_cannot_claim_other_users_neuron() {
    local_test_on_sns_subnet(|runtime| async move {
        let user1 = Sender::from_keypair(&TEST_USER1_KEYPAIR);
        let user2 = Sender::from_keypair(&TEST_USER2_KEYPAIR);
        let account_identifier1 = AccountIdentifier::from(user1.get_principal_id());
        let alloc = Tokens::from_tokens(1000).unwrap();
        let params = NervousSystemParameters {
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsInitPayloadsBuilder::new()
            .with_ledger_account(account_identifier1, alloc)
            .with_nervous_system_parameters(params)
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        let nonce = 12345u64;
        let to_subaccount = Subaccount({
            let mut state = Sha256::new();
            state.write(&[0x0c]);
            state.write(b"neuron-stake");
            state.write(user1.get_principal_id().as_slice());
            state.write(&nonce.to_be_bytes());
            state.finish()
        });

        // user1 makes a staking transfer
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
                        PrincipalId::from(sns_canisters.governance.canister_id()),
                        Some(to_subaccount),
                    ),
                    created_at_time: None,
                },
                &user1,
            )
            .await
            .expect("Couldn't send funds.");

        // user2 claims the neuron that user1 staked
        let claim_response: ManageNeuronResponse = sns_canisters
            .governance
            .update_from_sender(
                "manage_neuron",
                candid_one,
                ManageNeuron {
                    subaccount: to_subaccount.to_vec(),
                    command: Some(Command::ClaimOrRefresh(ClaimOrRefresh {
                        by: Some(By::MemoAndController(MemoAndController {
                            memo: nonce,
                            controller: Some(user1.get_principal_id()),
                        })),
                    })),
                },
                &user2,
            )
            .await
            .expect("Error calling the manage_neuron api.");

        let neuron_id = match claim_response.command.unwrap() {
            CommandResponse::ClaimOrRefresh(response) => response.refreshed_neuron_id.unwrap(),
            CommandResponse::Error(error) => panic!(
                "Unexpected error when claiming neuron for user {}: {}",
                user1.get_principal_id(),
                error
            ),
            _ => panic!(
                "Unexpected command response when claiming neuron for user {}.",
                user1.get_principal_id()
            ),
        };

        let neuron = sns_canisters.get_neuron(&neuron_id).await;

        let expected_permissions = vec![NeuronPermission::new(
            &user1.get_principal_id(),
            NeuronPermissionType::all(),
        )];

        assert_eq!(neuron.permissions, expected_permissions);

        // user2 should not be able to increase dissolve delay
        let dissolve_delay: u32 = 10_000;
        let increase_response: ManageNeuronResponse = sns_canisters
            .governance
            .update_from_sender(
                "manage_neuron",
                candid_one,
                ManageNeuron {
                    subaccount: to_subaccount.to_vec(),
                    command: Some(Command::Configure(Configure {
                        operation: Some(Operation::IncreaseDissolveDelay(IncreaseDissolveDelay {
                            additional_dissolve_delay_seconds: dissolve_delay,
                        })),
                    })),
                },
                &user2,
            )
            .await
            .expect("Error calling the manage_neuron api.");

        match increase_response.command.unwrap() {
            CommandResponse::Configure(_) => {
                panic!("user2 should not be able to increase dissolve delay of user1's neuron",)
            }
            CommandResponse::Error(error) => {
                assert_eq!(error.error_type, ErrorType::NotAuthorized as i32)
            }
            _ => panic!(
                "Unexpected command response when increasing dissolve delay for user {}.",
                user1.get_principal_id()
            ),
        };

        Ok(())
    });
}

#[test]
fn test_neuron_add_all_permissions_to_self() {
    local_test_on_sns_subnet(|runtime| async move {
        let user = Sender::from_keypair(&TEST_USER1_KEYPAIR);
        let account_identifier = AccountIdentifier::from(user.get_principal_id());
        let alloc = Tokens::from_tokens(1000).unwrap();

        let system_params = NervousSystemParameters {
            // Just grant ManagePrincipals to the claimer
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: vec![NeuronPermissionType::ManagePrincipals as i32],
            }),
            // Be able to grant all permissions
            neuron_grantable_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsInitPayloadsBuilder::new()
            .with_ledger_account(account_identifier, alloc)
            .with_nervous_system_parameters(system_params)
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        let neuron_id = sns_canisters.stake_and_claim_neuron(&user, None).await;
        let neuron = sns_canisters.get_neuron(&neuron_id).await;
        let subaccount = neuron.subaccount().expect("Error creating the subaccount");

        // Assert that the default claimer permissions are as expected before adding more
        assert_eq!(neuron.permissions.len(), 1);
        assert_eq!(
            neuron.permissions[0].principal.unwrap(),
            user.get_principal_id()
        );
        assert_eq!(neuron.permissions[0].permission_type.len(), 1);
        assert_eq!(
            neuron.permissions[0].permission_type[0],
            NeuronPermissionType::ManagePrincipals as i32
        );

        // Grant the claimer all permissions
        sns_canisters
            .add_neuron_permissions(
                &user,
                &subaccount,
                Some(user.get_principal_id()),
                NeuronPermissionType::all(),
            )
            .await;

        let neuron = sns_canisters.get_neuron(&neuron_id).await;
        assert_eq!(neuron.permissions.len(), 1);

        let mut neuron_permission =
            get_neuron_permission_from_neuron(&neuron, &user.get_principal_id());
        // There is no guarantee to order so sort is required for comparison
        neuron_permission.permission_type.sort_unstable();
        assert_eq!(
            neuron_permission.permission_type,
            NeuronPermissionType::all()
        );

        Ok(())
    });
}

#[test]
fn test_neuron_add_multiple_permissions_and_principals() {
    local_test_on_sns_subnet(|runtime| async move {
        let user = Sender::from_keypair(&TEST_USER1_KEYPAIR);
        let additional_user = Sender::from_keypair(&TEST_USER2_KEYPAIR);
        let account_identifier = AccountIdentifier::from(user.get_principal_id());
        let alloc = Tokens::from_tokens(1000).unwrap();

        let system_params = NervousSystemParameters {
            // Just grant ManagePrincipals to the claimer
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: vec![NeuronPermissionType::ManagePrincipals as i32],
            }),
            // Be able to grant all permissions
            neuron_grantable_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsInitPayloadsBuilder::new()
            .with_ledger_account(account_identifier, alloc)
            .with_nervous_system_parameters(system_params)
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        let neuron_id = sns_canisters.stake_and_claim_neuron(&user, None).await;
        let neuron = sns_canisters.get_neuron(&neuron_id).await;
        let subaccount = neuron.subaccount().expect("Error creating the subaccount");

        assert_eq!(neuron.permissions.len(), 1);

        sns_canisters
            .add_neuron_permissions(
                &user,
                &subaccount,
                Some(additional_user.get_principal_id()),
                vec![NeuronPermissionType::Vote as i32],
            )
            .await;

        // Assert that a new PrincipalId was added and has the intended Permission
        let neuron = sns_canisters.get_neuron(&neuron_id).await;
        assert_eq!(neuron.permissions.len(), 2);
        let neuron_permission =
            get_neuron_permission_from_neuron(&neuron, &additional_user.get_principal_id());
        assert_eq!(
            neuron_permission.permission_type,
            vec![NeuronPermissionType::Vote as i32]
        );

        sns_canisters
            .add_neuron_permissions(
                &user,
                &subaccount,
                Some(additional_user.get_principal_id()),
                vec![
                    // Intentionally testing that these are deduplicated
                    NeuronPermissionType::MergeMaturity as i32,
                    NeuronPermissionType::MergeMaturity as i32,
                ],
            )
            .await;

        // Assert that no new PrincipalId was added and the correct permissions have been updated
        let neuron = sns_canisters.get_neuron(&neuron_id).await;
        assert_eq!(neuron.permissions.len(), 2);
        let mut neuron_permission =
            get_neuron_permission_from_neuron(&neuron, &additional_user.get_principal_id());

        // .sort() emits () and needs to be called outside of the assert!
        let mut expected = vec![
            NeuronPermissionType::Vote as i32,
            NeuronPermissionType::MergeMaturity as i32,
        ];
        expected.sort_unstable();
        neuron_permission.permission_type.sort_unstable();

        assert_eq!(neuron_permission.permission_type, expected);

        Ok(())
    });
}

#[test]
fn test_neuron_add_non_grantable_permission_fails() {
    local_test_on_sns_subnet(|runtime| async move {
        let user = Sender::from_keypair(&TEST_USER1_KEYPAIR);
        let account_identifier = AccountIdentifier::from(user.get_principal_id());
        let alloc = Tokens::from_tokens(1000).unwrap();

        let system_params = NervousSystemParameters {
            // Just grant ManagePrincipals to the claimer
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: vec![NeuronPermissionType::ManagePrincipals as i32],
            }),
            // Be able to grant no permissions
            neuron_grantable_permissions: Some(NeuronPermissionList {
                permissions: vec![],
            }),
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsInitPayloadsBuilder::new()
            .with_ledger_account(account_identifier, alloc)
            .with_nervous_system_parameters(system_params)
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        let neuron_id = sns_canisters.stake_and_claim_neuron(&user, None).await;
        let neuron = sns_canisters.get_neuron(&neuron_id).await;
        let subaccount = neuron.subaccount().expect("Error creating the subaccount");

        let add_neuron_permission = AddNeuronPermissions {
            principal_id: Some(user.get_principal_id()),
            permissions_to_add: Some(NeuronPermissionList {
                permissions: vec![NeuronPermissionType::Vote as i32],
            }),
        };

        let manage_neuron_response: ManageNeuronResponse = sns_canisters
            .governance
            .update_from_sender(
                "manage_neuron",
                candid_one,
                ManageNeuron {
                    subaccount: subaccount.to_vec(),
                    command: Some(Command::AddNeuronPermissions(add_neuron_permission)),
                },
                &user,
            )
            .await
            .expect("Error calling manage_neuron");

        let error = match manage_neuron_response.command.unwrap() {
            CommandResponse::RemoveNeuronPermission(_) => {
                panic!("RemoveNeuronPermissions should have errored")
            }
            CommandResponse::Error(error) => error,
            response => panic!("Unexpected response from manage_neuron: {:?}", response),
        };

        assert_eq!(error.error_type, ErrorType::ErrorAccessControlList as i32);

        Ok(())
    });
}

#[test]
fn test_exceeding_max_principals_for_neuron_fails() {
    local_test_on_sns_subnet(|runtime| async move {
        let user = Sender::from_keypair(&TEST_USER1_KEYPAIR);
        let additional_user = Sender::from_keypair(&TEST_USER2_KEYPAIR);
        let account_identifier = AccountIdentifier::from(user.get_principal_id());
        let alloc = Tokens::from_tokens(1000).unwrap();

        let system_params = NervousSystemParameters {
            // Just grant ManagePrincipals to the claimer
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: vec![NeuronPermissionType::ManagePrincipals as i32],
            }),
            // Be able to grant all permissions
            neuron_grantable_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            max_number_of_principals_per_neuron: Some(1_u64),
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsInitPayloadsBuilder::new()
            .with_ledger_account(account_identifier, alloc)
            .with_nervous_system_parameters(system_params)
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        let neuron_id = sns_canisters.stake_and_claim_neuron(&user, None).await;
        let neuron = sns_canisters.get_neuron(&neuron_id).await;
        let subaccount = neuron.subaccount().expect("Error creating the subaccount");

        let add_neuron_permission = AddNeuronPermissions {
            principal_id: Some(additional_user.get_principal_id()),
            permissions_to_add: Some(NeuronPermissionList {
                permissions: vec![NeuronPermissionType::Vote as i32],
            }),
        };

        let manage_neuron_response: ManageNeuronResponse = sns_canisters
            .governance
            .update_from_sender(
                "manage_neuron",
                candid_one,
                ManageNeuron {
                    subaccount: subaccount.to_vec(),
                    command: Some(Command::AddNeuronPermissions(add_neuron_permission)),
                },
                &user,
            )
            .await
            .expect("Error calling manage_neuron");

        let error = match manage_neuron_response.command.unwrap() {
            CommandResponse::RemoveNeuronPermission(_) => {
                panic!("RemoveNeuronPermissions should have errored")
            }
            CommandResponse::Error(error) => error,
            response => panic!("Unexpected response from manage_neuron: {:?}", response),
        };

        assert_eq!(error.error_type, ErrorType::PreconditionFailed as i32);

        Ok(())
    });
}

#[test]
fn test_add_neuron_permission_missing_principal_id_fails() {
    local_test_on_sns_subnet(|runtime| async move {
        let user = Sender::from_keypair(&TEST_USER1_KEYPAIR);
        let account_identifier = AccountIdentifier::from(user.get_principal_id());
        let alloc = Tokens::from_tokens(1000).unwrap();

        let system_params = NervousSystemParameters {
            // Just grant ManagePrincipals to the claimer
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: vec![NeuronPermissionType::ManagePrincipals as i32],
            }),
            neuron_grantable_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsInitPayloadsBuilder::new()
            .with_ledger_account(account_identifier, alloc)
            .with_nervous_system_parameters(system_params)
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        let neuron_id = sns_canisters.stake_and_claim_neuron(&user, None).await;
        let neuron = sns_canisters.get_neuron(&neuron_id).await;
        let subaccount = neuron.subaccount().expect("Error creating the subaccount");
        // The neuron should have a single NeuronPermission after claiming
        assert_eq!(neuron.permissions.len(), 1);

        // Adding a new permission without specifying a PrincipalId should fail
        let add_neuron_permissions = AddNeuronPermissions {
            principal_id: None,
            permissions_to_add: Some(NeuronPermissionList {
                permissions: vec![NeuronPermissionType::Vote as i32],
            }),
        };

        let manage_neuron_response: ManageNeuronResponse = sns_canisters
            .governance
            .update_from_sender(
                "manage_neuron",
                candid_one,
                ManageNeuron {
                    subaccount: subaccount.to_vec(),
                    command: Some(Command::AddNeuronPermissions(add_neuron_permissions)),
                },
                &user,
            )
            .await
            .expect("Error calling manage_neuron");

        let error = match manage_neuron_response.command.unwrap() {
            CommandResponse::AddNeuronPermission(_) => {
                panic!("AddNeuronPermission should have errored")
            }
            CommandResponse::Error(error) => error,
            response => panic!("Unexpected response from manage_neuron: {:?}", response),
        };

        assert_eq!(error.error_type, ErrorType::InvalidCommand as i32);

        Ok(())
    });
}

#[test]
fn test_neuron_remove_all_permissions_of_self() {
    local_test_on_sns_subnet(|runtime| async move {
        let user = Sender::from_keypair(&TEST_USER1_KEYPAIR);
        let account_identifier = AccountIdentifier::from(user.get_principal_id());
        let alloc = Tokens::from_tokens(1000).unwrap();

        let system_params = NervousSystemParameters {
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsInitPayloadsBuilder::new()
            .with_ledger_account(account_identifier, alloc)
            .with_nervous_system_parameters(system_params)
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        let neuron_id = sns_canisters.stake_and_claim_neuron(&user, None).await;
        let neuron = sns_canisters.get_neuron(&neuron_id).await;
        let subaccount = neuron.subaccount().expect("Error creating the subaccount");

        // Assert that the Claimer has been granted all permissions
        assert_eq!(neuron.permissions.len(), 1);
        let mut neuron_permission =
            get_neuron_permission_from_neuron(&neuron, &user.get_principal_id());
        // .sort() emits () and needs to be called outside of the assert!
        neuron_permission.permission_type.sort_unstable();
        assert_eq!(
            neuron_permission.permission_type,
            NeuronPermissionType::all(),
        );

        sns_canisters
            .remove_neuron_permissions(
                &user,
                &subaccount,
                &user.get_principal_id(),
                NeuronPermissionType::all(),
            )
            .await;

        let neuron = sns_canisters.get_neuron(&neuron_id).await;
        assert_eq!(neuron.permissions.len(), 0);

        Ok(())
    });
}

#[test]
fn test_neuron_remove_some_permissions() {
    local_test_on_sns_subnet(|runtime| async move {
        let user = Sender::from_keypair(&TEST_USER1_KEYPAIR);
        let account_identifier = AccountIdentifier::from(user.get_principal_id());
        let alloc = Tokens::from_tokens(1000).unwrap();

        let system_params = NervousSystemParameters {
            // Just grant ManagePrincipals to the claimer
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsInitPayloadsBuilder::new()
            .with_ledger_account(account_identifier, alloc)
            .with_nervous_system_parameters(system_params)
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        let neuron_id = sns_canisters.stake_and_claim_neuron(&user, None).await;
        let neuron = sns_canisters.get_neuron(&neuron_id).await;
        let subaccount = neuron.subaccount().expect("Error creating the subaccount");

        // Assert that the Claimer has been granted all permissions
        assert_eq!(neuron.permissions.len(), 1);
        let mut neuron_permission =
            get_neuron_permission_from_neuron(&neuron, &user.get_principal_id());
        // .sort() emits () and needs to be called outside of the assert!
        neuron_permission.permission_type.sort_unstable();
        assert_eq!(
            neuron_permission.permission_type,
            NeuronPermissionType::all(),
        );

        sns_canisters
            .remove_neuron_permissions(
                &user,
                &subaccount,
                &user.get_principal_id(),
                vec![
                    NeuronPermissionType::Vote as i32,
                    NeuronPermissionType::MergeMaturity as i32,
                ],
            )
            .await;

        let neuron = sns_canisters.get_neuron(&neuron_id).await;
        assert_eq!(neuron.permissions.len(), 1);

        let neuron_permission =
            get_neuron_permission_from_neuron(&neuron, &user.get_principal_id());
        let permissions = neuron_permission.permission_type;
        assert_eq!(permissions.len(), NeuronPermissionType::all().len() - 2);

        let permission_set: HashSet<i32> = HashSet::from_iter(permissions);
        assert!(!permission_set.contains(&(NeuronPermissionType::Vote as i32)));
        assert!(!permission_set.contains(&(NeuronPermissionType::MergeMaturity as i32)));

        Ok(())
    });
}

#[test]
fn test_neuron_remove_permissions_of_wrong_principal() {
    local_test_on_sns_subnet(|runtime| async move {
        let user = Sender::from_keypair(&TEST_USER1_KEYPAIR);
        let additional_user = Sender::from_keypair(&TEST_USER2_KEYPAIR);
        let account_identifier = AccountIdentifier::from(user.get_principal_id());
        let alloc = Tokens::from_tokens(1000).unwrap();

        let system_params = NervousSystemParameters {
            // Just grant ManagePrincipals to the claimer
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsInitPayloadsBuilder::new()
            .with_ledger_account(account_identifier, alloc)
            .with_nervous_system_parameters(system_params)
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        let neuron_id = sns_canisters.stake_and_claim_neuron(&user, None).await;
        let neuron = sns_canisters.get_neuron(&neuron_id).await;
        let subaccount = neuron.subaccount().expect("Error creating the subaccount");

        assert_eq!(neuron.permissions.len(), 1);
        assert_eq!(
            neuron.permissions[0].principal.unwrap(),
            user.get_principal_id()
        );

        // Remove permissions on a user that does not have any permissions
        let remove_neuron_permissions = RemoveNeuronPermissions {
            principal_id: Some(additional_user.get_principal_id()),
            permissions_to_remove: Some(NeuronPermissionList {
                permissions: vec![NeuronPermissionType::Vote as i32],
            }),
        };

        let manage_neuron_response: ManageNeuronResponse = sns_canisters
            .governance
            .update_from_sender(
                "manage_neuron",
                candid_one,
                ManageNeuron {
                    subaccount: subaccount.to_vec(),
                    command: Some(Command::RemoveNeuronPermissions(remove_neuron_permissions)),
                },
                &user,
            )
            .await
            .expect("Error calling manage_neuron");

        let error = match manage_neuron_response.command.unwrap() {
            CommandResponse::RemoveNeuronPermission(_) => {
                panic!("RemoveNeuronPermissions should have errored")
            }
            CommandResponse::Error(error) => error,
            response => panic!("Unexpected response from manage_neuron: {:?}", response),
        };

        assert_eq!(error.error_type, ErrorType::ErrorAccessControlList as i32);

        Ok(())
    });
}

#[test]
fn test_neuron_remove_permissions_of_different_principal() {
    local_test_on_sns_subnet(|runtime| async move {
        let user = Sender::from_keypair(&TEST_USER1_KEYPAIR);
        let additional_user = Sender::from_keypair(&TEST_USER2_KEYPAIR);
        let account_identifier = AccountIdentifier::from(user.get_principal_id());
        let alloc = Tokens::from_tokens(1000).unwrap();

        let system_params = NervousSystemParameters {
            // Just grant ManagePrincipals to the claimer
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: vec![NeuronPermissionType::ManagePrincipals as i32],
            }),
            // Be able to grant all permissions
            neuron_grantable_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsInitPayloadsBuilder::new()
            .with_ledger_account(account_identifier, alloc)
            .with_nervous_system_parameters(system_params)
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        let neuron_id = sns_canisters.stake_and_claim_neuron(&user, None).await;
        let neuron = sns_canisters.get_neuron(&neuron_id).await;
        let subaccount = neuron.subaccount().expect("Error creating the subaccount");

        // Add all the permissions for the additional user to eventually be removed
        sns_canisters
            .add_neuron_permissions(
                &user,
                &subaccount,
                Some(additional_user.get_principal_id()),
                NeuronPermissionType::all(),
            )
            .await;

        // Assert that a new PrincipalId was added
        let neuron = sns_canisters.get_neuron(&neuron_id).await;
        assert_eq!(neuron.permissions.len(), 2);

        // Remove a single permission of a different PrincipalId
        sns_canisters
            .remove_neuron_permissions(
                &user,
                &subaccount,
                &additional_user.get_principal_id(),
                vec![NeuronPermissionType::MergeMaturity as i32],
            )
            .await;

        // Assert that no new PrincipalId was removed and the correct permissions have been removed
        let neuron = sns_canisters.get_neuron(&neuron_id).await;
        assert_eq!(neuron.permissions.len(), 2);
        let neuron_permission =
            get_neuron_permission_from_neuron(&neuron, &additional_user.get_principal_id());
        let permissions = neuron_permission.permission_type;
        assert_eq!(permissions.len(), NeuronPermissionType::all().len() - 1);

        let permission_set: HashSet<i32> = HashSet::from_iter(permissions);
        assert!(!permission_set.contains(&(NeuronPermissionType::MergeMaturity as i32)));

        // Remove the rest of the permissions a user has
        sns_canisters
            .remove_neuron_permissions(
                &user,
                &subaccount,
                &additional_user.get_principal_id(),
                Vec::from_iter(permission_set),
            )
            .await;

        // Assert the additional_user was removed from the neuron
        let neuron = sns_canisters.get_neuron(&neuron_id).await;
        assert_eq!(neuron.permissions.len(), 1);
        assert_ne!(
            neuron.permissions[0].principal.unwrap(),
            additional_user.get_principal_id()
        );

        Ok(())
    });
}

#[test]
fn test_remove_neuron_permission_missing_principal_id_fails() {
    local_test_on_sns_subnet(|runtime| async move {
        let user = Sender::from_keypair(&TEST_USER1_KEYPAIR);
        let account_identifier = AccountIdentifier::from(user.get_principal_id());
        let alloc = Tokens::from_tokens(1000).unwrap();

        let system_params = NervousSystemParameters {
            // Just grant ManagePrincipals to the claimer
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: vec![NeuronPermissionType::ManagePrincipals as i32],
            }),
            neuron_grantable_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsInitPayloadsBuilder::new()
            .with_ledger_account(account_identifier, alloc)
            .with_nervous_system_parameters(system_params)
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        let neuron_id = sns_canisters.stake_and_claim_neuron(&user, None).await;
        let neuron = sns_canisters.get_neuron(&neuron_id).await;
        let subaccount = neuron.subaccount().expect("Error creating the subaccount");

        let remove_neuron_permission = RemoveNeuronPermissions {
            principal_id: None,
            permissions_to_remove: Some(NeuronPermissionList {
                permissions: vec![NeuronPermissionType::Vote as i32],
            }),
        };

        let manage_neuron_response: ManageNeuronResponse = sns_canisters
            .governance
            .update_from_sender(
                "manage_neuron",
                candid_one,
                ManageNeuron {
                    subaccount: subaccount.to_vec(),
                    command: Some(Command::RemoveNeuronPermissions(remove_neuron_permission)),
                },
                &user,
            )
            .await
            .expect("Error calling manage_neuron");

        let error = match manage_neuron_response.command.unwrap() {
            CommandResponse::RemoveNeuronPermission(_) => {
                panic!("RemoveNeuronPermissions should have errored")
            }
            CommandResponse::Error(error) => error,
            response => panic!("Unexpected response from manage_neuron: {:?}", response),
        };

        assert_eq!(error.error_type, ErrorType::InvalidCommand as i32);

        Ok(())
    });
}

#[test]
fn test_remove_neuron_permission_when_neuron_missing_permission_type_fails() {
    local_test_on_sns_subnet(|runtime| async move {
        let user = Sender::from_keypair(&TEST_USER1_KEYPAIR);
        let account_identifier = AccountIdentifier::from(user.get_principal_id());
        let alloc = Tokens::from_tokens(1000).unwrap();

        let system_params = NervousSystemParameters {
            // Initialize a neuron with only two permissions, Vote and ManagePrincipals
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: vec![
                    NeuronPermissionType::ManagePrincipals as i32,
                    NeuronPermissionType::Vote as i32,
                ],
            }),
            neuron_grantable_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsInitPayloadsBuilder::new()
            .with_ledger_account(account_identifier, alloc)
            .with_nervous_system_parameters(system_params)
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        let neuron_id = sns_canisters.stake_and_claim_neuron(&user, None).await;
        let neuron = sns_canisters.get_neuron(&neuron_id).await;
        let subaccount = neuron.subaccount().expect("Error creating the subaccount");

        // Create a RemoveNeuronPermissions request that will remove a NeuronPermissionType that
        // The user does not have
        let remove_neuron_permission = RemoveNeuronPermissions {
            principal_id: user.get_principal_id().into(),
            permissions_to_remove: Some(NeuronPermissionList {
                permissions: vec![
                    NeuronPermissionType::Vote as i32,
                    NeuronPermissionType::MergeMaturity as i32,
                ],
            }),
        };

        let manage_neuron_response: ManageNeuronResponse = sns_canisters
            .governance
            .update_from_sender(
                "manage_neuron",
                candid_one,
                ManageNeuron {
                    subaccount: subaccount.to_vec(),
                    command: Some(Command::RemoveNeuronPermissions(remove_neuron_permission)),
                },
                &user,
            )
            .await
            .expect("Error calling manage_neuron");

        let error = match manage_neuron_response.command.unwrap() {
            CommandResponse::RemoveNeuronPermission(_) => {
                panic!("RemoveNeuronPermissions should have errored")
            }
            CommandResponse::Error(error) => error,
            response => panic!("Unexpected response from manage_neuron: {:?}", response),
        };

        assert_eq!(error.error_type, ErrorType::ErrorAccessControlList as i32);

        Ok(())
    });
}

// Returns a copy of the found NeuronPermission
fn get_neuron_permission_from_neuron(
    neuron: &Neuron,
    principal_id: &PrincipalId,
) -> NeuronPermission {
    neuron
        .permissions
        .iter()
        .find(|permission| permission.principal.unwrap() == *principal_id)
        .expect("PrincipalId not present in NeuronPermissions")
        .clone()
}
