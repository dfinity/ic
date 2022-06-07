use async_trait::async_trait;
use canister_test::Canister;
use dfn_candid::candid_one;
use dfn_protobuf::protobuf;
use ic_canister_client::Sender;
use ic_crypto_sha::Sha256;
use ic_nervous_system_common::{ledger::Ledger, NervousSystemError};
use ic_nervous_system_common_test_keys::{
    TEST_USER1_KEYPAIR, TEST_USER2_KEYPAIR, TEST_USER3_KEYPAIR, TEST_USER4_KEYPAIR,
};
use ic_sns_governance::{
    governance::Governance,
    neuron::NeuronState,
    pb::v1::{
        governance_error::ErrorType,
        manage_neuron::{
            claim_or_refresh::{By, MemoAndController},
            configure::Operation,
            AddNeuronPermissions, ClaimOrRefresh, Command, Configure, DisburseMaturity,
            IncreaseDissolveDelay, RemoveNeuronPermissions,
        },
        manage_neuron_response::Command as CommandResponse,
        proposal::Action,
        Ballot, Empty, Governance as GovernanceProto, ListNeurons, ListNeuronsResponse,
        ManageNeuron, ManageNeuronResponse, Motion, NervousSystemParameters, Neuron, NeuronId,
        NeuronPermission, NeuronPermissionList, NeuronPermissionType, Proposal, ProposalData,
        ProposalId, ProposalRewardStatus, RewardEvent, Vote, WaitForQuietState,
    },
    types::{test_helpers::NativeEnvironment, Environment, ONE_YEAR_SECONDS},
};
use ic_sns_test_utils::itest_helpers::{
    local_test_on_sns_subnet, SnsCanisters, SnsTestsInitPayloadBuilder, UserInfo, NONCE,
};
use ic_sns_test_utils::now_seconds;
use ic_types::PrincipalId;
use ledger_canister::{AccountIdentifier, Tokens, TOKEN_SUBDIVIDABLE_BY};
use ledger_canister::{Memo, SendArgs, Subaccount, DEFAULT_TRANSFER_FEE};
use maplit::btreemap;
use std::{collections::HashSet, convert::TryInto, iter::FromIterator};

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
        let sns_init_payload = SnsTestsInitPayloadBuilder::new()
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

        let sns_init_payload = SnsTestsInitPayloadBuilder::new()
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

        let sns_init_payload = SnsTestsInitPayloadBuilder::new()
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

        let sns_init_payload = SnsTestsInitPayloadBuilder::new()
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

        let sns_init_payload = SnsTestsInitPayloadBuilder::new()
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

        let sns_init_payload = SnsTestsInitPayloadBuilder::new()
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

        let sns_init_payload = SnsTestsInitPayloadBuilder::new()
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
#[allow(dead_code)]
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

        let sns_init_payload = SnsTestsInitPayloadBuilder::new()
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
#[allow(dead_code)]
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

        let sns_init_payload = SnsTestsInitPayloadBuilder::new()
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

        let sns_init_payload = SnsTestsInitPayloadBuilder::new()
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

#[tokio::test]
async fn zero_total_reward_shares() {
    // Step 1: Prepare the world.

    struct EmptyLedger {}
    #[async_trait]
    impl Ledger for EmptyLedger {
        async fn transfer_funds(
            &self,
            _amount_e8s: u64,
            _fee_e8s: u64,
            _from_subaccount: Option<Subaccount>,
            _to: AccountIdentifier,
            _memo: u64,
        ) -> Result<u64, NervousSystemError> {
            unimplemented!();
        }

        async fn total_supply(&self) -> Result<Tokens, NervousSystemError> {
            Ok(Tokens::from_e8s(0))
        }

        async fn account_balance(
            &self,
            _account: AccountIdentifier,
        ) -> Result<Tokens, NervousSystemError> {
            Ok(Tokens::from_e8s(0))
        }
    }

    let environment = NativeEnvironment::default();
    let now = environment.now();

    let genesis_timestamp_seconds = 1;

    // Step 1.1: Craft a neuron with a "net" stake (i.e. cached stake - fees) of 0.
    let neuron_id = NeuronId { id: vec![1, 2, 3] };
    // A number whose only significance is that it is not Protocol Buffers default (i.e. 0.0).
    let maturity_e8s_equivalent = 3;
    let depleted_neuron = Neuron {
        id: Some(neuron_id.clone()),
        cached_neuron_stake_e8s: 1_000_000_000,
        neuron_fees_e8s: 1_000_000_000,
        maturity_e8s_equivalent,
        ..Default::default()
    };
    let voting_power = depleted_neuron.voting_power(now, 60, 60);
    assert_eq!(voting_power, 0);

    // Step 1.2: Craft a ProposalData that is ReadyToSettle.
    let proposal_id = 99;
    let do_nothing_proposal = Proposal {
        action: Some(Action::Motion(Motion {
            motion_text: "For great justice.".to_string(),
        })),
        ..Default::default()
    };
    let ready_to_settle_proposal_data = ProposalData {
        id: Some(ProposalId { id: proposal_id }),
        proposal: Some(do_nothing_proposal),
        ballots: btreemap! {
            depleted_neuron.id.as_ref().unwrap().to_string() => Ballot {
                vote: Vote::Yes as i32,
                voting_power,
                cast_timestamp_seconds: now,
            },
        },
        wait_for_quiet_state: Some(WaitForQuietState::default()),
        ..Default::default()
    };
    assert_eq!(
        ready_to_settle_proposal_data.reward_status(now),
        ProposalRewardStatus::ReadyToSettle,
    );

    // Step 1.3: Craft a governance.
    let root_canister_id = [1; 29];
    let ledger_canister_id = [2; 29];
    let proto = GovernanceProto {
        // These won't be used, so we use garbage values.
        root_canister_id: Some(PrincipalId::new(29, root_canister_id)),
        ledger_canister_id: Some(PrincipalId::new(29, ledger_canister_id)),
        parameters: Some(NervousSystemParameters::with_default_values()),

        genesis_timestamp_seconds,

        proposals: btreemap! {
            ready_to_settle_proposal_data.id.unwrap().id => ready_to_settle_proposal_data,
        },
        neurons: btreemap! {
            depleted_neuron.id.as_ref().unwrap().to_string() => depleted_neuron,
        },

        // Last reward event was a "long time ago".
        // This should cause rewards to be distributed.
        latest_reward_event: Some(RewardEvent {
            periods_since_genesis: 1,
            actual_timestamp_seconds: 1,
            settled_proposals: vec![],
            distributed_e8s_equivalent: 0,
        }),

        ..Default::default()
    };
    let mut governance = Governance::new(
        proto.try_into().unwrap(),
        Box::new(environment),
        Box::new(EmptyLedger {}),
    );
    // Prevent gc.
    governance.latest_gc_timestamp_seconds = now;

    // Step 2: Run code under test.
    governance.run_periodic_tasks().await;

    // Step 3: Inspect results. The main thing is to make sure that we did not
    // divide by zero. If that happened, it would show up in a couple places:
    // neuron maturity, and latest_reward_event.

    // Step 3.1: Inspect the neuron.
    let neuron = governance
        .proto
        .neurons
        .get(&neuron_id.to_string())
        .unwrap();
    // We expect no change to the neuron's maturity.
    assert_eq!(
        neuron.maturity_e8s_equivalent, maturity_e8s_equivalent,
        "neuron: {:#?}",
        neuron,
    );

    // Step 3.2: Inspect the latest_reward_event.
    let reward_event = governance.proto.latest_reward_event.as_ref().unwrap();
    assert_eq!(
        reward_event
            .settled_proposals
            .iter()
            .map(|p| p.id)
            .collect::<Vec<_>>(),
        vec![proposal_id],
        "{:#?}",
        reward_event,
    );
    assert_eq!(
        reward_event.distributed_e8s_equivalent, 0,
        "{:#?}",
        reward_event,
    );
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

        let sns_init_payload = SnsTestsInitPayloadBuilder::new()
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

        let sns_init_payload = SnsTestsInitPayloadBuilder::new()
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

        let sns_init_payload = SnsTestsInitPayloadBuilder::new()
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

        let sns_init_payload = SnsTestsInitPayloadBuilder::new()
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

        let sns_init_payload = SnsTestsInitPayloadBuilder::new()
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

        let sns_init_payload = SnsTestsInitPayloadBuilder::new()
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

        let sns_init_payload = SnsTestsInitPayloadBuilder::new()
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

        let sns_init_payload = SnsTestsInitPayloadBuilder::new()
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

        let sns_init_payload = SnsTestsInitPayloadBuilder::new()
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

        let sns_init_payload = SnsTestsInitPayloadBuilder::new()
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

        let sns_init_payload = SnsTestsInitPayloadBuilder::new()
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

        let sns_init_payload = SnsTestsInitPayloadBuilder::new()
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

/// Tests the happy path of `ManageNeuron::Disburse` and that a neuron can disburse its stake
/// to the neuron owner's account.
#[test]
fn test_disburse_neuron_to_self_succeeds() {
    local_test_on_sns_subnet(|runtime| async move {
        let user = UserInfo::new(Sender::from_keypair(&TEST_USER1_KEYPAIR));
        let alloc = Tokens::from_tokens(1000).unwrap();

        let params = NervousSystemParameters {
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsTestsInitPayloadBuilder::new()
            .with_ledger_account(user.sender.get_principal_id().into(), alloc)
            .with_nervous_system_parameters(params.clone())
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        // Stake and claim a neuron for the user. The dissolve delay is set to ONE_YEAR_SECONDS
        // and is in state `NotDissolving`
        sns_canisters
            .stake_and_claim_neuron(&user.sender, Some(ONE_YEAR_SECONDS as u32))
            .await;

        // Attempt to disburse a neuron when it is not dissolved
        let disburse_response = sns_canisters
            .disburse_neuron(&user.sender, &user.subaccount, None, None)
            .await;

        // This should fail with error_type as PreconditionFailed
        let error = match disburse_response.command.unwrap() {
            CommandResponse::Error(error) => error,
            CommandResponse::Disburse(_) => {
                panic!("Neuron is not dissolved, Disburse command should have failed.")
            }
            _ => panic!("Unexpected command response when disbursing the neuron"),
        };
        assert_eq!(error.error_type, ErrorType::PreconditionFailed as i32);

        // Start dissolving the neuron
        sns_canisters
            .start_dissolving(&user.sender, &user.subaccount)
            .await;

        // Check that the Neuron has entered the dissolving state
        let neuron = sns_canisters.get_neuron(&user.neuron_id).await;
        assert_eq!(
            neuron.aging_since_timestamp_seconds,
            u64::MAX,
            "Neuron age not set to the 'dissolving' default value"
        );
        let neuron_state = neuron.state(now_seconds(None));
        assert_eq!(neuron_state, NeuronState::Dissolving);

        // Advance time one year so the neuron is now in the "dissolved" state
        let delta_s = ONE_YEAR_SECONDS;
        sns_canisters
            .set_time_warp(delta_s as i64)
            .await
            .expect("Expected set_time_warp to succeed");

        let neuron = sns_canisters.get_neuron(&user.neuron_id).await;

        // Assert that the Neuron is now dissolved
        let neuron_state = neuron.state(now_seconds(Some(delta_s)));
        assert_eq!(neuron_state, NeuronState::Dissolved);

        // Record balances before disbursal
        let neuron_stake_before_disbursal = neuron.cached_neuron_stake_e8s;
        assert!(neuron_stake_before_disbursal > 0);
        let account_balance_before_disbursal =
            sns_canisters.get_user_account_balance(&user.sender).await;

        // Disburse the neuron to self and assert that it succeeds
        let disburse_response = sns_canisters
            .disburse_neuron(&user.sender, &user.subaccount, None, None)
            .await;

        let transfer_block_height = match disburse_response.command.unwrap() {
            CommandResponse::Disburse(response) => response.transfer_block_height,
            CommandResponse::Error(error) => {
                panic!("Unexpected error when disbursing the neuron: {}", error)
            }
            _ => panic!("Unexpected command response when disbursing the neuron"),
        };
        assert!(transfer_block_height > 0);

        // Assert that the neuron's stake is now zero
        let neuron = sns_canisters.get_neuron(&user.neuron_id).await;
        assert_eq!(neuron.cached_neuron_stake_e8s, 0);

        // Calculate how much balance should have been disbursed
        let expected_disbursal_amount =
            Tokens::from_e8s(neuron_stake_before_disbursal - params.transaction_fee_e8s.unwrap());
        let expected_account_balance_after_disbursal =
            (account_balance_before_disbursal + expected_disbursal_amount).unwrap();

        // Assert that the Neuron owner's account balance has increased the expected amount
        let account_balance_after_disbursal =
            sns_canisters.get_user_account_balance(&user.sender).await;
        assert_eq!(
            account_balance_after_disbursal,
            expected_account_balance_after_disbursal
        );

        Ok(())
    });
}

/// Tests the the `ManageNeuron::Disburse` command supports disbursing to ledger accounts
/// other than the owner of a neuron.
#[test]
fn test_disburse_neuron_to_different_account_succeeds() {
    local_test_on_sns_subnet(|runtime| async move {
        let neuron_owner = UserInfo::new(Sender::from_keypair(&TEST_USER1_KEYPAIR));
        let funds_receiver = UserInfo::new(Sender::from_keypair(&TEST_USER2_KEYPAIR));
        let alloc = Tokens::from_tokens(1000).unwrap();

        let params = NervousSystemParameters {
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsTestsInitPayloadBuilder::new()
            .with_ledger_account(neuron_owner.sender.get_principal_id().into(), alloc)
            .with_nervous_system_parameters(params.clone())
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        // Stake and claim a neuron for the user. No dissolve delay is specified so the
        // neuron is in the dissolved state and can be disbursed.
        sns_canisters
            .stake_and_claim_neuron(&neuron_owner.sender, None)
            .await;

        let neuron = sns_canisters.get_neuron(&neuron_owner.neuron_id).await;

        // Assert that the Neuron is dissolved
        let neuron_state = neuron.state(now_seconds(None));
        assert_eq!(neuron_state, NeuronState::Dissolved);

        // Record balances before disbursal
        let neuron_stake_before_disbursal = neuron.cached_neuron_stake_e8s;
        let amount_to_disburse = neuron_stake_before_disbursal / 2;
        assert!(neuron_stake_before_disbursal > 0);
        let account_balance_before_disbursal_of_neuron_owner = sns_canisters
            .get_user_account_balance(&neuron_owner.sender)
            .await;
        let account_balance_before_disbursal_of_funds_receiver = sns_canisters
            .get_user_account_balance(&funds_receiver.sender)
            .await;

        // Disburse half the stake to the 'funds_receiver' user's ledger account, and assert it succeeds
        let disburse_response = sns_canisters
            .disburse_neuron(
                &neuron_owner.sender,
                &neuron_owner.subaccount,
                Some(amount_to_disburse),
                Some(funds_receiver.sender.get_principal_id().into()),
            )
            .await;
        let transfer_block_height = match disburse_response.command.unwrap() {
            CommandResponse::Disburse(response) => response.transfer_block_height,
            CommandResponse::Error(error) => {
                panic!("Unexpected error when disbursing the neuron: {}", error)
            }
            _ => panic!("Unexpected command response when disbursing the neuron"),
        };
        assert!(transfer_block_height > 0);

        // Assert that the neurons stake has been reduced by half (transaction fees are deducted
        // from the amount that is being transferred)
        let neuron = sns_canisters.get_neuron(&neuron_owner.neuron_id).await;
        let neuron_stake_after_disbursal = neuron.cached_neuron_stake_e8s;
        assert_eq!(neuron_stake_after_disbursal, amount_to_disburse);

        // Assert that the balance of the neuron owner should not have changed
        let account_balance_after_disbursal_of_neuron_owner = sns_canisters
            .get_user_account_balance(&neuron_owner.sender)
            .await;
        assert_eq!(
            account_balance_before_disbursal_of_neuron_owner,
            account_balance_after_disbursal_of_neuron_owner
        );

        // Calculate how much balance should have been disbursed. The transaction fee is subtracted
        // from the disbursed amount
        let expected_disbursal_amount =
            Tokens::from_e8s(amount_to_disburse - params.transaction_fee_e8s.unwrap());
        let expected_account_balance_after_disbursal_of_funds_receiver =
            (account_balance_before_disbursal_of_funds_receiver + expected_disbursal_amount)
                .unwrap();

        // Assert that the funds receiver account balance has increased the expected amount
        let account_balance_after_disbursal_of_funds_receiver = sns_canisters
            .get_user_account_balance(&funds_receiver.sender)
            .await;
        assert_eq!(
            account_balance_after_disbursal_of_funds_receiver,
            expected_account_balance_after_disbursal_of_funds_receiver
        );

        Ok(())
    });
}

/// Tests that `ManageNeuron::Disburse` will burn fees associated with rejected proposals.
#[test]
fn test_disburse_neuron_burns_neuron_fees() {
    local_test_on_sns_subnet(|runtime| async move {
        let user = UserInfo::new(Sender::from_keypair(&TEST_USER1_KEYPAIR));
        // Create another user to vote no on Proposals from parent, so parent accumulates neuron_fees
        let voter = UserInfo::new(Sender::from_keypair(&TEST_USER2_KEYPAIR));
        let alloc = Tokens::from_tokens(1000).unwrap();

        let params = NervousSystemParameters {
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsTestsInitPayloadBuilder::new()
            .with_ledger_account(user.sender.get_principal_id().into(), alloc)
            .with_ledger_account(voter.sender.get_principal_id().into(), alloc)
            .with_nervous_system_parameters(params.clone())
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        // Stake and claim a neuron for the user. The dissolve delay is set to ONE_YEAR_SECONDS
        // and is in state `NotDissolving`
        sns_canisters
            .stake_and_claim_neuron(&user.sender, Some(ONE_YEAR_SECONDS as u32))
            .await;

        // Stake and claim a neuron for the voter with a majority of voting power
        sns_canisters
            .stake_and_claim_neuron(&voter.sender, Some((20 * ONE_YEAR_SECONDS) as u32))
            .await;

        // Create a proposal and have the user submit it
        let proposal = Proposal {
            action: Some(Action::Motion(Motion {
                motion_text: String::from(""),
            })),
            ..Default::default()
        };

        let proposal_id = sns_canisters
            .make_proposal(&user.sender, &user.subaccount, proposal)
            .await
            .expect("Expected make_proposal to succeed");

        // Have the voter vote no on the proposal so the user neuron accumulates
        // neuron fees
        sns_canisters
            .vote(&voter.sender, &voter.subaccount, proposal_id, false)
            .await;

        // Start dissolving the neuron
        sns_canisters
            .start_dissolving(&user.sender, &user.subaccount)
            .await;

        // Advance time one year so the neuron is now in the "dissolved" state
        let delta_s = ONE_YEAR_SECONDS;
        sns_canisters
            .set_time_warp(delta_s as i64)
            .await
            .expect("Expected set_time_warp to succeed");

        let neuron = sns_canisters.get_neuron(&user.neuron_id).await;

        // Assert that the Neuron is now dissolved
        let neuron_state = neuron.state(now_seconds(Some(delta_s)));
        assert_eq!(neuron_state, NeuronState::Dissolved);

        // Record balances before disbursal
        let neuron_stake_before_disbursal = neuron.cached_neuron_stake_e8s;
        assert!(neuron_stake_before_disbursal > 0);
        let neuron_fees_before_disbursal = neuron.neuron_fees_e8s;
        assert_eq!(
            neuron_fees_before_disbursal,
            params.reject_cost_e8s.unwrap()
        );
        let account_balance_before_disbursal =
            sns_canisters.get_user_account_balance(&user.sender).await;

        // Disburse the neuron to the neuron owner and assert that it succeeds
        let disburse_response = sns_canisters
            .disburse_neuron(&user.sender, &user.subaccount, None, None)
            .await;

        let transfer_block_height = match disburse_response.command.unwrap() {
            CommandResponse::Disburse(response) => response.transfer_block_height,
            CommandResponse::Error(error) => {
                panic!("Unexpected error when disbursing the neuron: {}", error)
            }
            _ => panic!("Unexpected command response when disbursing the neuron"),
        };
        assert!(transfer_block_height > 0);

        let neuron = sns_canisters.get_neuron(&user.neuron_id).await;
        // Assert that the neuron's stake is now zero, i.e. the stake has been disbursed
        assert_eq!(neuron.cached_neuron_stake_e8s, 0);
        // Assert that the neuron's fees are now zero, i.e. the fees have been burned
        assert_eq!(neuron.neuron_fees_e8s, 0);

        // Calculate how much balance should have been disbursed. The neuron fees and ledger
        // transactions fees should be deducted from the stake.
        let expected_disbursal_amount = Tokens::from_e8s(
            neuron_stake_before_disbursal
                - neuron_fees_before_disbursal
                - params.transaction_fee_e8s.unwrap(),
        );
        let expected_account_balance_after_disbursal =
            (account_balance_before_disbursal + expected_disbursal_amount).unwrap();

        // Assert that the Neuron owner's account balance has increased the expected amount
        let account_balance_after_disbursal =
            sns_canisters.get_user_account_balance(&user.sender).await;
        assert_eq!(
            account_balance_after_disbursal,
            expected_account_balance_after_disbursal
        );

        Ok(())
    });
}

/// Tests the flow of `ManageNeuron::Split`, and that when a child neuron is split from a parent
/// neuron the correct neuron state is inherited.
#[test]
fn test_split_neuron_succeeds() {
    local_test_on_sns_subnet(|runtime| async move {
        let parent = UserInfo::new(Sender::from_keypair(&TEST_USER1_KEYPAIR));
        let alloc = Tokens::from_tokens(1000).unwrap();

        let params = NervousSystemParameters {
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsTestsInitPayloadBuilder::new()
            .with_ledger_account(parent.sender.get_principal_id().into(), alloc)
            .with_nervous_system_parameters(params.clone())
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        // Stake and claim a neuron for the parent
        sns_canisters
            .stake_and_claim_neuron(&parent.sender, None)
            .await;

        let parent_neuron = sns_canisters.get_neuron(&parent.neuron_id).await;
        let parent_neuron_stake_before_split = parent_neuron.cached_neuron_stake_e8s;
        let amount_to_split = parent_neuron_stake_before_split / 2;

        // Split the parent neuron and have the child neuron inherit half of the parent's
        // stake
        let split_response = sns_canisters
            .split_neuron(
                &parent.sender,
                &parent.subaccount,
                amount_to_split,
                0, // memo
            )
            .await;

        // Assert that the Split command succeeded
        let child_neuron_id = match split_response.command.unwrap() {
            CommandResponse::Split(response) => response
                .created_neuron_id
                .expect("Expected a NeuronId to be returned after splitting"),
            CommandResponse::Error(error) => {
                panic!("Unexpected error when splitting the neuron: {}", error)
            }
            _ => panic!("Unexpected command response when splitting the neuron"),
        };

        let parent_neuron = sns_canisters.get_neuron(&parent.neuron_id).await;
        let child_neuron = sns_canisters.get_neuron(&child_neuron_id).await;

        // Assert that the stake's of the two neurons have been adjusted correctly. The transaction
        // fee is deducted from the amount inherited by the child.
        let expected_parent_neuron_stake_after_split = amount_to_split;
        let expected_child_neuron_stake_after_split =
            amount_to_split - params.transaction_fee_e8s.unwrap();
        assert_eq!(
            expected_parent_neuron_stake_after_split,
            parent_neuron.cached_neuron_stake_e8s
        );
        assert_eq!(
            expected_child_neuron_stake_after_split,
            child_neuron.cached_neuron_stake_e8s
        );

        assert_eq!(parent_neuron.permissions, child_neuron.permissions);
        assert_eq!(
            parent_neuron.aging_since_timestamp_seconds,
            child_neuron.aging_since_timestamp_seconds
        );
        assert_eq!(parent_neuron.followees, child_neuron.followees);
        assert_eq!(parent_neuron.dissolve_state, child_neuron.dissolve_state);
        assert_eq!(child_neuron.maturity_e8s_equivalent, 0);
        assert_eq!(child_neuron.neuron_fees_e8s, 0);
        assert!(child_neuron.created_timestamp_seconds > 0);

        Ok(())
    });
}

/// Tests that when a Neuron is split using `ManageNeuron::Split`, fields such as neuron_fees_e8s
/// are not inherited.
#[test]
fn test_split_neuron_inheritance() {
    local_test_on_sns_subnet(|runtime| async move {
        let parent = UserInfo::new(Sender::from_keypair(&TEST_USER1_KEYPAIR));
        // Create another user to vote no on Proposals from parent, so parent accumulates neuron_fees
        let voter = UserInfo::new(Sender::from_keypair(&TEST_USER2_KEYPAIR));
        let alloc = Tokens::from_tokens(1000).unwrap();

        let params = NervousSystemParameters {
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsTestsInitPayloadBuilder::new()
            .with_ledger_account(parent.sender.get_principal_id().into(), alloc)
            .with_ledger_account(voter.sender.get_principal_id().into(), alloc)
            .with_nervous_system_parameters(params.clone())
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        // Stake and claim a neuron for the parent
        sns_canisters
            .stake_and_claim_neuron(&parent.sender, Some(ONE_YEAR_SECONDS as u32))
            .await;

        // Stake and claim a neuron for the voter with a majority of voting power
        sns_canisters
            .stake_and_claim_neuron(&voter.sender, Some((20 * ONE_YEAR_SECONDS) as u32))
            .await;

        // Create a proposal and have the parent submit it
        let proposal = Proposal {
            action: Some(Action::Motion(Motion {
                motion_text: String::from(""),
            })),
            ..Default::default()
        };

        let proposal_id = sns_canisters
            .make_proposal(&parent.sender, &parent.subaccount, proposal)
            .await
            .expect("Expected make_proposal to succeed");

        // Have the voter vote no on the proposal so the parent neuron accumulates
        // neuron fees
        sns_canisters
            .vote(&voter.sender, &voter.subaccount, proposal_id, false)
            .await;

        // Assert that the fees are present before the split
        let parent_neuron = sns_canisters.get_neuron(&parent.neuron_id).await;
        assert_eq!(
            parent_neuron.neuron_fees_e8s,
            params.reject_cost_e8s.unwrap()
        );

        // Split the parent neuron and have the child neuron inherit half of the parent's
        // stake
        let split_response = sns_canisters
            .split_neuron(
                &parent.sender,
                &parent.subaccount,
                parent_neuron.cached_neuron_stake_e8s / 2,
                0, // memo
            )
            .await;

        // Assert that the Split command succeeded
        let child_neuron_id = match split_response.command.unwrap() {
            CommandResponse::Split(response) => response
                .created_neuron_id
                .expect("Expected a NeuronId to be returned after splitting"),
            CommandResponse::Error(error) => {
                panic!("Unexpected error when splitting the neuron: {}", error)
            }
            _ => panic!("Unexpected command response when splitting the neuron"),
        };

        let parent_neuron = sns_canisters.get_neuron(&parent.neuron_id).await;
        let child_neuron = sns_canisters.get_neuron(&child_neuron_id).await;

        // The parent should retain the fees, the child should not
        assert_eq!(
            parent_neuron.neuron_fees_e8s,
            params.reject_cost_e8s.unwrap()
        );
        assert_eq!(child_neuron.neuron_fees_e8s, 0);

        Ok(())
    });
}

/// Tests that when a Neuron is split using `ManageNeuron::Split`, the child neuron will be split
/// with enough stake to meet the minimum stake requirements
#[test]
fn test_split_neuron_child_amount_is_above_min_stake() {
    local_test_on_sns_subnet(|runtime| async move {
        let parent = UserInfo::new(Sender::from_keypair(&TEST_USER1_KEYPAIR));
        let alloc = Tokens::from_tokens(1000).unwrap();

        let params = NervousSystemParameters {
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsTestsInitPayloadBuilder::new()
            .with_ledger_account(parent.sender.get_principal_id().into(), alloc)
            .with_nervous_system_parameters(params.clone())
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        // Stake and claim a neuron for the parent
        sns_canisters
            .stake_and_claim_neuron(&parent.sender, None)
            .await;

        // Initially, set the split amount to below the current minimum_stake
        let mut split_amount_e8s = params.neuron_minimum_stake_e8s.unwrap() - 1;

        let error = sns_canisters
            .split_neuron_with_failure(
                &parent.sender,
                &parent.subaccount,
                split_amount_e8s,
                0, // memo
            )
            .await;
        assert_eq!(error.error_type, ErrorType::InsufficientFunds as i32);

        // Setting the split amount to the current minimum_stake should also fail as the transaction fee
        // is deducted from the amount that is inherited
        split_amount_e8s = params.neuron_minimum_stake_e8s.unwrap();

        let error = sns_canisters
            .split_neuron_with_failure(
                &parent.sender,
                &parent.subaccount,
                split_amount_e8s,
                0, // memo
            )
            .await;
        assert_eq!(error.error_type, ErrorType::InsufficientFunds as i32);

        // Setting the split amount to the current minimum_stake plus the transaction_fee should
        // result in a successful split as the child neuron will now have the needed minimum stake
        split_amount_e8s =
            params.neuron_minimum_stake_e8s.unwrap() + params.transaction_fee_e8s.unwrap();

        let split_response = sns_canisters
            .split_neuron(
                &parent.sender,
                &parent.subaccount,
                split_amount_e8s,
                0, // memo
            )
            .await;
        let child_neuron_id = match split_response.command.unwrap() {
            CommandResponse::Split(response) => response
                .created_neuron_id
                .expect("Expected a NeuronId to be returned after splitting"),
            CommandResponse::Error(error) => {
                panic!("Unexpected error when splitting the neuron: {}", error)
            }
            _ => panic!("Unexpected command response when splitting the neuron"),
        };

        // The child should now be created and have stake equal to the minimum stake
        let child_neuron = sns_canisters.get_neuron(&child_neuron_id).await;
        assert_eq!(
            params.neuron_minimum_stake_e8s.unwrap(),
            child_neuron.cached_neuron_stake_e8s
        );

        Ok(())
    });
}

/// Tests that when a Neuron is split using `ManageNeuron::Split`, after the split the parent
/// neuron's stake will be above the minimum stake
#[test]
fn test_split_neuron_parent_amount_is_above_min_stake() {
    local_test_on_sns_subnet(|runtime| async move {
        let parent = UserInfo::new(Sender::from_keypair(&TEST_USER1_KEYPAIR));
        let alloc = Tokens::from_tokens(1000).unwrap();

        let params = NervousSystemParameters {
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsTestsInitPayloadBuilder::new()
            .with_ledger_account(parent.sender.get_principal_id().into(), alloc)
            .with_nervous_system_parameters(params.clone())
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        // Stake and claim a neuron for the parent
        sns_canisters
            .stake_and_claim_neuron(&parent.sender, None)
            .await;

        let parent_neuron = sns_canisters.get_neuron(&parent.neuron_id).await;

        // Initially, set the split amount to an amount that will leave the parent neuron's stake just
        // below the minimum_stake
        let mut split_amount_e8s =
            parent_neuron.cached_neuron_stake_e8s - params.neuron_minimum_stake_e8s.unwrap() + 1;

        let error = sns_canisters
            .split_neuron_with_failure(
                &parent.sender,
                &parent.subaccount,
                split_amount_e8s,
                0, // memo
            )
            .await;
        assert_eq!(error.error_type, ErrorType::InsufficientFunds as i32);

        // Setting the split amount to the current minimum_stake plus the transaction_fee should
        // result in a successful split as the parent neuron will now have the needed minimum stake
        split_amount_e8s =
            parent_neuron.cached_neuron_stake_e8s - params.neuron_minimum_stake_e8s.unwrap();

        let split_response = sns_canisters
            .split_neuron(
                &parent.sender,
                &parent.subaccount,
                split_amount_e8s,
                0, // memo
            )
            .await;
        let child_neuron_id = match split_response.command.unwrap() {
            CommandResponse::Split(response) => response
                .created_neuron_id
                .expect("Expected a NeuronId to be returned after splitting"),
            CommandResponse::Error(error) => {
                panic!("Unexpected error when splitting the neuron: {}", error)
            }
            _ => panic!("Unexpected command response when splitting the neuron"),
        };

        // The child neuron should now exist, and the parent neuron should have exactly the
        // minimum_stake
        let parent_neuron = sns_canisters.get_neuron(&parent.neuron_id).await;
        let child_neuron = sns_canisters.get_neuron(&child_neuron_id).await;
        assert_eq!(
            params.neuron_minimum_stake_e8s.unwrap(),
            parent_neuron.cached_neuron_stake_e8s
        );

        let expected_stake_of_child_neuron = split_amount_e8s - params.transaction_fee_e8s.unwrap();
        assert_eq!(
            child_neuron.cached_neuron_stake_e8s,
            expected_stake_of_child_neuron
        );

        Ok(())
    });
}
