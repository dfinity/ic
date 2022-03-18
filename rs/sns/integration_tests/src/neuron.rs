use canister_test::Canister;
use dfn_candid::candid_one;
use dfn_protobuf::protobuf;
use ic_canister_client::Sender;
use ic_crypto_sha::Sha256;
use ic_nns_test_keys::{
    TEST_USER1_KEYPAIR, TEST_USER2_KEYPAIR, TEST_USER3_KEYPAIR, TEST_USER4_KEYPAIR,
};
use ic_sns_governance::pb::v1::governance_error::ErrorType;
use ic_sns_governance::pb::v1::manage_neuron::{
    claim_or_refresh::{By, MemoAndController},
    configure::Operation,
    ClaimOrRefresh, Configure, IncreaseDissolveDelay,
};
use ic_sns_governance::pb::v1::manage_neuron::{Command, DisburseMaturity};
use ic_sns_governance::pb::v1::manage_neuron_response::Command as CommandResponse;
use ic_sns_governance::pb::v1::proposal::Action;
use ic_sns_governance::pb::v1::{
    ListNeurons, ListNeuronsResponse, ManageNeuron, ManageNeuronResponse, Motion,
    NervousSystemParameters, Neuron, NeuronId, NeuronPermission, NeuronPermissionList,
    NeuronPermissionType, Proposal,
};
use ic_sns_governance::types::ONE_YEAR_SECONDS;
use ic_sns_test_utils::itest_helpers::{
    local_test_on_sns_subnet, SnsCanisters, SnsInitPayloadsBuilder,
};
use ic_types::PrincipalId;
use ledger_canister::{AccountIdentifier, Tokens};
use ledger_canister::{Memo, SendArgs, Subaccount, DEFAULT_TRANSFER_FEE};

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
        let account_identifier = AccountIdentifier::from(user.get_principal_id());
        let alloc = Tokens::from_tokens(1000).unwrap();

        let sns_init_payload = SnsInitPayloadsBuilder::new()
            .with_ledger_account(account_identifier, alloc)
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        let nid = sns_canisters.stake_and_claim_neuron(&user, None).await;
        let neuron = sns_canisters.get_neuron(&nid).await;

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

#[test]
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

#[test]
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
