use crate::fixtures::{neuron_id, GovernanceCanisterFixtureBuilder, NeuronBuilder, TargetLedger};
use ic_base_types::PrincipalId;
use ic_nervous_system_common::E8;
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_OWNER_PRINCIPAL, TEST_NEURON_2_OWNER_PRINCIPAL,
};
use ic_sns_governance::neuron::NeuronState;
use ic_sns_governance::pb::v1::Neuron;
use ic_sns_governance::{
    pb::v1::{
        governance_error::ErrorType,
        manage_neuron,
        manage_neuron::claim_or_refresh,
        manage_neuron::{
            configure::Operation, AddNeuronPermissions, ClaimOrRefresh, Configure, Disburse,
            DisburseMaturity, Follow, IncreaseDissolveDelay, MergeMaturity, RegisterVote,
            RemoveNeuronPermissions, Split, StakeMaturity,
        },
        manage_neuron_response::{
            Command as CommandResponse, DisburseMaturityResponse, MergeMaturityResponse,
            StakeMaturityResponse,
        },
        proposal::Action,
        Account, Empty, GovernanceError, ManageNeuronResponse, Motion, NeuronPermission,
        NeuronPermissionList, NeuronPermissionType, Proposal, ProposalId,
    },
    types::ONE_MONTH_SECONDS,
};

pub mod fixtures;

/// Tests the happy path of `ManageNeuron::Disburse` and that a neuron can disburse its stake
/// to the neuron owner's account.
#[tokio::test]
async fn test_disburse_succeeds() {
    let user_principal = PrincipalId::new_user_test_id(1000);
    let neuron_id = neuron_id(user_principal, /*memo*/ 0);

    // Set up the test environment with a single dissolved neuron
    let mut canister_fixture = GovernanceCanisterFixtureBuilder::new()
        .add_neuron(NeuronBuilder::new(
            neuron_id.clone(),
            E8,
            NeuronPermission::all(&user_principal),
        ))
        .create();

    // Get the Neuron and assert it's stake greater than zero
    let neuron = canister_fixture.get_neuron(&neuron_id);
    let neuron_stake_before_disbursal = neuron.cached_neuron_stake_e8s;
    assert!(neuron_stake_before_disbursal > 0);

    // Record SNS ledger balances before disbursal
    let destination_account = ic_icrc1::Account {
        owner: user_principal,
        subaccount: None,
    };
    let account_balance_before_disbursal =
        canister_fixture.get_account_balance(&destination_account, TargetLedger::Sns);

    // Disburse the neuron to self and assert that it succeeds
    let manage_neuron_response = canister_fixture.manage_neuron(
        &neuron_id,
        manage_neuron::Command::Disburse(Disburse {
            amount: None, // Translates to all stake
            to_account: Some(Account {
                owner: Some(user_principal),
                subaccount: None,
            }),
        }),
        &user_principal,
    );
    match manage_neuron_response.command.unwrap() {
        CommandResponse::Disburse(response) => println!("Successfully disbursed: {:?}", response),
        CommandResponse::Error(error) => {
            panic!("Unexpected error when disbursing the neuron: {}", error)
        }
        _ => panic!("Unexpected command response when disbursing the neuron"),
    };

    // Assert that the neuron's stake is now zero
    let neuron = canister_fixture.get_neuron(&neuron_id);
    assert_eq!(neuron.cached_neuron_stake_e8s, 0);

    // Get the transaction_fee_e8s of the SNS This is used to calculate expected balances
    let transaction_fee_e8s = canister_fixture
        .get_nervous_system_parameters()
        .transaction_fee_e8s
        .unwrap();

    // Calculate how much balance should have been disbursed
    let expected_disbursal_amount = neuron_stake_before_disbursal - transaction_fee_e8s;
    let expected_account_balance_after_disbursal =
        account_balance_before_disbursal + expected_disbursal_amount;

    // Assert that the Neuron owner's account balance has increased the expected amount
    let account_balance_after_disbursal =
        canister_fixture.get_account_balance(&destination_account, TargetLedger::Sns);

    assert_eq!(
        account_balance_after_disbursal,
        expected_account_balance_after_disbursal
    );
}

/// Tests that `ManageNeuron::Disburse` fails if the Neuron is not in a fully dissolved state.
#[tokio::test]
async fn test_disburse_fails_when_state_is_not_dissolving() {
    let user_principal = PrincipalId::new_user_test_id(0);
    let neuron_id = neuron_id(user_principal, /*memo*/ 0);

    // Set up the canister fixture with a single neuron
    let mut canister_fixture = GovernanceCanisterFixtureBuilder::new()
        .add_neuron(NeuronBuilder::new(
            neuron_id.clone(),
            E8,
            NeuronPermission::all(&user_principal),
        ))
        .create();

    // Increase the neuron's dissolve delay to test if disbursing a non-dissolved neuron is blocked
    canister_fixture.manage_neuron(
        &neuron_id,
        manage_neuron::Command::Configure(Configure {
            operation: Some(Operation::IncreaseDissolveDelay(IncreaseDissolveDelay {
                additional_dissolve_delay_seconds: (6 * ONE_MONTH_SECONDS) as u32,
            })),
        }),
        &user_principal,
    );

    // Assert that the neuron state is NotDissolving
    let neuron = canister_fixture.get_neuron(&neuron_id);
    let neuron_state = neuron.state(canister_fixture.now());
    assert_eq!(neuron_state, NeuronState::NotDissolving);

    // Attempt to disburse a neuron when it is NotDissolving
    let manage_neuron_response = canister_fixture.manage_neuron(
        &neuron_id,
        manage_neuron::Command::Disburse(Disburse {
            amount: None, // Translates to all stake
            to_account: Some(Account {
                owner: Some(user_principal),
                subaccount: None,
            }),
        }),
        &user_principal,
    );

    // This should fail with error_type as PreconditionFailed
    let error = match manage_neuron_response.command.unwrap() {
        CommandResponse::Error(error) => error,
        CommandResponse::Disburse(_) => {
            panic!("Neuron is not dissolved, Disburse command should have failed.")
        }
        _ => panic!("Unexpected command response when disbursing the neuron"),
    };
    assert_eq!(error.error_type, ErrorType::PreconditionFailed as i32);
}

/// Assert that manage_neuron operations on vesting neurons succeed and fail as expected.
///
/// This test sets up a GovernanceCanisterFixture, then sets up an exhaustive pair of manage_neuron
/// requests and expected responses, and then calls manage_neuron for each request/response pair
/// and asserts that the actual reponse is equal to the expected response.
#[test]
fn test_vesting_neuron_manage_neuron_operations() {
    use manage_neuron::Command;

    let user_principal1 = PrincipalId::new_user_test_id(1000);
    let neuron_id1 = neuron_id(user_principal1, /*memo*/ 0);

    let user_principal2 = PrincipalId::new_user_test_id(1002);
    let neuron_id2 = neuron_id(user_principal2, /*memo*/ 0);

    let neuron_grantable_permissions = NeuronPermissionList {
        permissions: NeuronPermissionType::all(),
    };

    // Set up the test environment with a single dissolved neuron
    let mut gov = GovernanceCanisterFixtureBuilder::new()
        .set_start_time(140)
        .add_neuron(
            NeuronBuilder::new(
                neuron_id1.clone(),
                E8,
                NeuronPermission::all(&user_principal1),
            )
            .set_dissolve_delay(15778801)
            .set_vesting_period(10000)
            .set_maturity(1000000)
            .add_neuron_permission(NeuronPermission {
                principal: Some(user_principal1),
                permission_type: vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
            }),
        )
        .add_neuron(
            NeuronBuilder::new(
                neuron_id2.clone(),
                E8,
                NeuronPermission::all(&user_principal2),
            )
            .set_vesting_period(10000)
            .set_dissolve_delay(15778801),
        )
        .with_neuron_grantable_permissions(neuron_grantable_permissions)
        .create();

    let err = |op: &str| -> ManageNeuronResponse {
        ManageNeuronResponse::error(GovernanceError::new_with_message(
            ErrorType::PreconditionFailed,
            format!("Neuron {} is vesting and cannot call {}", neuron_id1, op),
        ))
    };

    let proposal = Proposal {
        action: Some(Action::Motion(Motion::default())),
        ..Default::default()
    };

    let claim_or_refresh = ClaimOrRefresh {
        by: Some(claim_or_refresh::By::NeuronId(Empty {})),
    };

    let disburse_maturity = DisburseMaturity {
        percentage_to_disburse: 10,
        to_account: None,
    };

    let disburse_maturity_response = DisburseMaturityResponse {
        transfer_block_height: 1,
        amount_disbursed_e8s: 100000,
    };

    let merge_maturity = MergeMaturity {
        percentage_to_merge: 10,
    };

    let merge_maturity_response = MergeMaturityResponse {
        merged_maturity_e8s: 90000,
        new_stake_e8s: 100090000,
    };

    let stake_maturity = StakeMaturity {
        percentage_to_stake: Some(10),
    };

    let stake_maturity_response = StakeMaturityResponse {
        maturity_e8s: 729000,
        staked_maturity_e8s: 81000,
    };

    let add_neuron_permissions = AddNeuronPermissions {
        principal_id: Some(user_principal2),
        permissions_to_add: Some(NeuronPermissionList {
            permissions: vec![1],
        }),
    };

    let remove_neuron_permissions = RemoveNeuronPermissions {
        principal_id: Some(user_principal2),
        permissions_to_remove: Some(NeuronPermissionList {
            permissions: vec![1],
        }),
    };

    let register_vote = RegisterVote {
        proposal: Some(ProposalId::from(1)),
        vote: 1,
    };

    let requests_and_expected_responses = vec![
        (
            Command::increase_dissolve_delay(10),
            err("IncreaseDissolveDelay"),
        ),
        (Command::start_dissolving(), err("StartDissolving")),
        (Command::stop_dissolving(), err("StopDissolving")),
        (
            Command::set_dissolve_timestamp(12),
            err("SetDissolveTimestamp"),
        ),
        (
            Command::change_auto_stake_maturity(true),
            ManageNeuronResponse::configure_response(),
        ),
        (Command::Disburse(Disburse::default()), err("Disburse")),
        (Command::Split(Split::default()), err("Split")),
        (
            Command::Follow(Follow::default()),
            ManageNeuronResponse::follow_response(),
        ),
        (
            Command::MakeProposal(proposal),
            ManageNeuronResponse::make_proposal_response(ProposalId::from(1)),
        ),
        (
            Command::ClaimOrRefresh(claim_or_refresh),
            ManageNeuronResponse::claim_or_refresh_neuron_response(neuron_id1.clone()),
        ),
        (
            Command::DisburseMaturity(disburse_maturity),
            ManageNeuronResponse::disburse_maturity_response(disburse_maturity_response),
        ),
        (
            Command::MergeMaturity(merge_maturity),
            ManageNeuronResponse::merge_maturity_response(merge_maturity_response),
        ),
        (
            Command::StakeMaturity(stake_maturity),
            ManageNeuronResponse::stake_maturity_response(stake_maturity_response),
        ),
        (
            Command::AddNeuronPermissions(add_neuron_permissions),
            ManageNeuronResponse::add_neuron_permissions_response(),
        ),
        (
            Command::RemoveNeuronPermissions(remove_neuron_permissions),
            ManageNeuronResponse::remove_neuron_permissions_response(),
        ),
    ];

    for (command, expected_response) in requests_and_expected_responses {
        let actual_response = gov.manage_neuron(&neuron_id1, command, &user_principal1);
        assert_eq!(expected_response, actual_response);
    }

    // RegisterVote needs to be tested with different neuron (neuron1 submitted the proposal)
    let command = Command::RegisterVote(register_vote);
    let expected_response = ManageNeuronResponse::register_vote_response();
    let actual_response = gov.manage_neuron(&neuron_id2, command, &user_principal2);
    assert_eq!(expected_response, actual_response);
}

#[test]
fn test_adding_permissions_when_we_have_manage_principals() {
    let caller = *TEST_NEURON_1_OWNER_PRINCIPAL;
    let target = *TEST_NEURON_2_OWNER_PRINCIPAL;
    let permissions_to_add = NeuronPermissionList::all();
    let (mut governance, neuron) = {
        let permissions: &[(PrincipalId, NeuronPermissionList)] =
            &[(caller, vec![NeuronPermissionType::ManagePrincipals].into())];
        let user_principal = PrincipalId::new_user_test_id(0);
        let neuron_id = neuron_id(user_principal, 0);

        let governance_fixture = GovernanceCanisterFixtureBuilder::new()
            .with_neuron_grantable_permissions(NeuronPermissionList::all())
            .add_neuron_with_permissions(permissions, neuron_id.clone())
            .create();

        (governance_fixture, neuron_id)
    };

    // Attempt to add permissions to `target` - should succeed since `caller`
    // has `ManagePrincipals`.
    governance
        .add_neuron_permissions(&neuron, target, permissions_to_add.clone(), caller)
        .unwrap();

    // Check that `target` now has those permissions.
    governance.assert_principal_has_permissions_for_neuron(&neuron, target, permissions_to_add);
}

#[test]
fn test_removing_permissions_when_we_have_manage_principals() {
    let caller = *TEST_NEURON_1_OWNER_PRINCIPAL;
    let target = *TEST_NEURON_2_OWNER_PRINCIPAL;
    let permissions_to_remove = NeuronPermissionList::all();
    let (mut governance, neuron) = {
        let permissions: &[(PrincipalId, NeuronPermissionList)] = &[
            (caller, vec![NeuronPermissionType::ManagePrincipals].into()),
            (target, permissions_to_remove.clone()),
        ];
        let user_principal = PrincipalId::new_user_test_id(0);
        let neuron_id = neuron_id(user_principal, 0);

        let governance_fixture = GovernanceCanisterFixtureBuilder::new()
            .with_neuron_grantable_permissions(NeuronPermissionList::all())
            .add_neuron_with_permissions(permissions, neuron_id.clone())
            .create();

        (governance_fixture, neuron_id)
    };

    // Attempt to remove permissions from `target` - should succeed since `caller`
    // has `ManagePrincipals`.
    governance
        .remove_neuron_permissions(&neuron, target, permissions_to_remove, caller)
        .unwrap();

    // Check that `target` now has no permissions.
    governance.assert_principal_has_permissions_for_neuron(
        &neuron,
        target,
        NeuronPermissionList::empty(),
    );
}

#[test]
fn test_manage_voting_permission_allows_adding_permissions_related_to_voting() {
    let caller = *TEST_NEURON_1_OWNER_PRINCIPAL;
    let target = *TEST_NEURON_2_OWNER_PRINCIPAL;
    let permissions_to_add: NeuronPermissionList =
        Neuron::PERMISSIONS_RELATED_TO_VOTING.to_vec().into();
    let (mut governance, neuron) = {
        let permissions: &[(PrincipalId, NeuronPermissionList)] = &[(
            caller,
            vec![NeuronPermissionType::ManageVotingPermission].into(),
        )];
        let user_principal = PrincipalId::new_user_test_id(0);
        let neuron_id = neuron_id(user_principal, 0);

        let governance_fixture = GovernanceCanisterFixtureBuilder::new()
            .with_neuron_grantable_permissions(NeuronPermissionList::all())
            .add_neuron_with_permissions(permissions, neuron_id.clone())
            .create();

        (governance_fixture, neuron_id)
    };

    // Attempt to add voting-related permissions to `target` - should succeed
    // since `caller` has ManageVotingPermission.
    governance
        .add_neuron_permissions(&neuron, target, permissions_to_add.clone(), caller)
        .unwrap();

    // Check that `target` now has those permissions.
    governance.assert_principal_has_permissions_for_neuron(&neuron, target, permissions_to_add);
}

#[test]
fn test_manage_voting_permission_allows_removing_permissions_related_to_voting() {
    let caller = *TEST_NEURON_1_OWNER_PRINCIPAL;
    let target = *TEST_NEURON_2_OWNER_PRINCIPAL;
    let permissions_to_remove: NeuronPermissionList =
        Neuron::PERMISSIONS_RELATED_TO_VOTING.to_vec().into();

    let (mut governance, neuron) = {
        let permissions: &[(PrincipalId, NeuronPermissionList)] = &[
            (
                caller,
                vec![NeuronPermissionType::ManageVotingPermission].into(),
            ),
            (target, permissions_to_remove.clone()),
        ];
        let user_principal = PrincipalId::new_user_test_id(0);
        let neuron_id = neuron_id(user_principal, 0);

        let governance_fixture = GovernanceCanisterFixtureBuilder::new()
            .with_neuron_grantable_permissions(NeuronPermissionList::all())
            .add_neuron_with_permissions(permissions, neuron_id.clone())
            .create();

        (governance_fixture, neuron_id)
    };

    // Attempt to remove voting-related permissions from `target` - should
    // succeed since `caller` has ManageVotingPermission.
    governance
        .remove_neuron_permissions(&neuron, target, permissions_to_remove, caller)
        .unwrap();

    // Check that `target` no longer has those permissions.
    governance.assert_principal_has_permissions_for_neuron(
        &neuron,
        target,
        NeuronPermissionList::empty(),
    );
}

#[test]
fn test_manage_voting_permission_doesnt_allow_adding_permissions_unrelated_to_voting() {
    let caller = *TEST_NEURON_1_OWNER_PRINCIPAL;
    let target = *TEST_NEURON_2_OWNER_PRINCIPAL;

    // We want to try adding the permissions individually
    // to make sure they all fail, so we get all the
    // permissions not related to voting and loop over them.
    let permissions_not_related_to_voting =
        Vec::<NeuronPermissionType>::try_from(NeuronPermissionList {
            permissions: NeuronPermissionType::all(),
        })
        .unwrap()
        .into_iter()
        .filter(|permission| !Neuron::PERMISSIONS_RELATED_TO_VOTING.contains(permission));
    for permission_not_related_to_voting in permissions_not_related_to_voting {
        let (mut governance, neuron) = {
            let permissions: &[(PrincipalId, NeuronPermissionList)] = &[(
                caller,
                vec![NeuronPermissionType::ManageVotingPermission].into(),
            )];
            let user_principal = PrincipalId::new_user_test_id(0);
            let neuron_id = neuron_id(user_principal, 0);

            let governance_fixture = GovernanceCanisterFixtureBuilder::new()
                .with_neuron_grantable_permissions(NeuronPermissionList::all())
                .add_neuron_with_permissions(permissions, neuron_id.clone())
                .create();

            (governance_fixture, neuron_id)
        };

        // Attempt to add voting-unrelated permission to `target` - should fail
        // since `caller` doesn't have `ManagePrincipals`.
        governance
            .add_neuron_permissions(
                &neuron,
                target,
                vec![permission_not_related_to_voting].into(),
                caller,
            )
            .unwrap_err();

        // Check that `target` didn't get any permissions
        governance.assert_principal_has_permissions_for_neuron(
            &neuron,
            target,
            NeuronPermissionList::empty(),
        );
    }
}

#[test]
fn test_manage_voting_permission_doesnt_allow_removing_permissions_unrelated_to_voting() {
    let caller = *TEST_NEURON_1_OWNER_PRINCIPAL;
    let target = *TEST_NEURON_2_OWNER_PRINCIPAL;

    // We want to try removing the permissions individually
    // to make sure they all fail, so we get all the
    // permissions not related to voting and loop over them.
    let permissions_not_related_to_voting =
        Vec::<NeuronPermissionType>::try_from(NeuronPermissionList {
            permissions: NeuronPermissionType::all(),
        })
        .unwrap()
        .into_iter()
        .filter(|permission| !Neuron::PERMISSIONS_RELATED_TO_VOTING.contains(permission));
    for permission_not_related_to_voting in permissions_not_related_to_voting {
        let (mut governance, neuron) = {
            let permissions: &[(PrincipalId, NeuronPermissionList)] = &[
                (
                    caller,
                    vec![NeuronPermissionType::ManageVotingPermission].into(),
                ),
                (target, vec![permission_not_related_to_voting].into()),
            ];
            let user_principal = PrincipalId::new_user_test_id(0);
            let neuron_id = neuron_id(user_principal, 0);

            let governance_fixture = GovernanceCanisterFixtureBuilder::new()
                .with_neuron_grantable_permissions(NeuronPermissionList::all())
                .add_neuron_with_permissions(permissions, neuron_id.clone())
                .create();

            (governance_fixture, neuron_id)
        };

        // Attempt to remove our voting-unrelated permission to `target` - should fail
        // since `caller` doesn't have `ManagePrincipals`.
        governance
            .remove_neuron_permissions(
                &neuron,
                target,
                vec![permission_not_related_to_voting].into(),
                caller,
            )
            .unwrap_err();

        // Check that `target` still has the permissions
        governance.assert_principal_has_permissions_for_neuron(
            &neuron,
            target,
            vec![permission_not_related_to_voting].into(),
        );
    }
}

#[test]
fn test_manage_voting_permission_allows_adding_voting_permissions_to_self() {
    let caller = *TEST_NEURON_1_OWNER_PRINCIPAL;
    let permissions_to_add: NeuronPermissionList =
        Neuron::PERMISSIONS_RELATED_TO_VOTING.to_vec().into();

    let (mut governance, neuron) = {
        let permissions: &[(PrincipalId, NeuronPermissionList)] = &[(
            caller,
            vec![NeuronPermissionType::ManageVotingPermission].into(),
        )];
        let user_principal = PrincipalId::new_user_test_id(0);
        let neuron_id = neuron_id(user_principal, 0);

        let governance_fixture = GovernanceCanisterFixtureBuilder::new()
            .with_neuron_grantable_permissions(NeuronPermissionList::all())
            .add_neuron_with_permissions(permissions, neuron_id.clone())
            .create();

        (governance_fixture, neuron_id)
    };

    // Attempt to add voting-related permissions to `caller` - should succeed
    // since `caller` has ManageVotingPermission.
    governance
        .add_neuron_permissions(&neuron, caller, permissions_to_add.clone(), caller)
        .unwrap();

    // Check that `caller` now has those permissions.
    governance.assert_principal_has_permissions_for_neuron(&neuron, caller, permissions_to_add);
}

#[test]
fn test_manage_voting_permission_allows_removing_voting_permissions_from_self() {
    let caller = *TEST_NEURON_1_OWNER_PRINCIPAL;
    let permissions_to_remove = Neuron::PERMISSIONS_RELATED_TO_VOTING.to_vec().into();

    let (mut governance, neuron) = {
        let permissions: &[(PrincipalId, NeuronPermissionList)] = &[(
            caller,
            Neuron::PERMISSIONS_RELATED_TO_VOTING.to_vec().into(),
        )];
        let user_principal = PrincipalId::new_user_test_id(0);
        let neuron_id = neuron_id(user_principal, 0);

        let governance_fixture = GovernanceCanisterFixtureBuilder::new()
            .with_neuron_grantable_permissions(NeuronPermissionList::all())
            .add_neuron_with_permissions(permissions, neuron_id.clone())
            .create();

        (governance_fixture, neuron_id)
    };

    // Attempt to remove voting-related permissions from `caller` - should
    // succeed since `caller` has ManageVotingPermission.
    governance
        .remove_neuron_permissions(&neuron, caller, permissions_to_remove, caller)
        .unwrap();

    // Check that `caller` no longer has those permissions.
    governance.assert_principal_has_permissions_for_neuron(
        &neuron,
        caller,
        NeuronPermissionList::empty(),
    );
}

#[test]
fn test_manage_principals_allows_adding_voting_permissions_to_self() {
    let caller = *TEST_NEURON_1_OWNER_PRINCIPAL;
    let permissions_to_add = NeuronPermissionList::all();

    let (mut governance, neuron) = {
        let permissions: &[(PrincipalId, NeuronPermissionList)] =
            &[(caller, vec![NeuronPermissionType::ManagePrincipals].into())];
        let user_principal = PrincipalId::new_user_test_id(0);
        let neuron_id = neuron_id(user_principal, 0);

        let governance_fixture = GovernanceCanisterFixtureBuilder::new()
            .with_neuron_grantable_permissions(NeuronPermissionList::all())
            .add_neuron_with_permissions(permissions, neuron_id.clone())
            .create();

        (governance_fixture, neuron_id)
    };

    // Attempt to add voting-related permissions to `caller` - should succeed
    // since `caller` has ManageVotingPermission.
    governance
        .add_neuron_permissions(&neuron, caller, permissions_to_add.clone(), caller)
        .unwrap();

    // Check that `caller` now has those permissions.
    governance.assert_principal_has_permissions_for_neuron(&neuron, caller, permissions_to_add);
}

#[test]
fn test_manage_principals_allows_removing_voting_permissions_from_self() {
    let caller = *TEST_NEURON_1_OWNER_PRINCIPAL;
    let permissions_to_remove = NeuronPermissionList::all();

    let (mut governance, neuron) = {
        let permissions: &[(PrincipalId, NeuronPermissionList)] =
            &[(caller, permissions_to_remove.clone())];
        let user_principal = PrincipalId::new_user_test_id(0);
        let neuron_id = neuron_id(user_principal, 0);

        let governance_fixture = GovernanceCanisterFixtureBuilder::new()
            .with_neuron_grantable_permissions(NeuronPermissionList::all())
            .add_neuron_with_permissions(permissions, neuron_id.clone())
            .create();

        (governance_fixture, neuron_id)
    };

    // Attempt to remove voting-related permissions from `caller` - should
    // succeed since `caller` has ManageVotingPermission.
    governance
        .remove_neuron_permissions(&neuron, caller, permissions_to_remove, caller)
        .unwrap();

    // Check that `caller` no longer has those permissions.
    governance.assert_principal_has_permissions_for_neuron(
        &neuron,
        caller,
        NeuronPermissionList::empty(),
    );
}

#[test]
fn test_normally_unable_to_add_permissions_to_self() {
    let caller = *TEST_NEURON_1_OWNER_PRINCIPAL;
    let permissions_to_add: NeuronPermissionList =
        Neuron::PERMISSIONS_RELATED_TO_VOTING.to_vec().into();

    let (mut governance, neuron) = {
        let permissions: &[(PrincipalId, NeuronPermissionList)] =
            &[(caller, vec![NeuronPermissionType::Vote].into())];
        let user_principal = PrincipalId::new_user_test_id(0);
        let neuron_id = neuron_id(user_principal, 0);

        let governance_fixture = GovernanceCanisterFixtureBuilder::new()
            .with_neuron_grantable_permissions(NeuronPermissionList::all())
            .add_neuron_with_permissions(permissions, neuron_id.clone())
            .create();

        (governance_fixture, neuron_id)
    };

    // Attempt to add voting-related permissions to `caller` - should
    // fail since `caller` doesn't have ManageVotingPermission or
    // ManagePrincipals.
    governance
        .add_neuron_permissions(&neuron, caller, permissions_to_add, caller)
        .unwrap_err();

    // Check that `caller` didn't get the permissions
    governance.assert_principal_has_permissions_for_neuron(
        &neuron,
        caller,
        vec![NeuronPermissionType::Vote].into(),
    );
}

#[test]
fn test_normally_unable_to_remove_permissions_from_self() {
    let caller = *TEST_NEURON_1_OWNER_PRINCIPAL;
    let permissions_to_remove: NeuronPermissionList = vec![NeuronPermissionType::Vote].into();

    let (mut governance, neuron) = {
        let permissions: &[(PrincipalId, NeuronPermissionList)] =
            &[(caller, vec![NeuronPermissionType::Vote].into())];
        let user_principal = PrincipalId::new_user_test_id(0);
        let neuron_id = neuron_id(user_principal, 0);

        let governance_fixture = GovernanceCanisterFixtureBuilder::new()
            .with_neuron_grantable_permissions(NeuronPermissionList::all())
            .add_neuron_with_permissions(permissions, neuron_id.clone())
            .create();

        (governance_fixture, neuron_id)
    };

    // Attempt to add voting-related permissions to `caller` - should
    // fail since `caller` doesn't have ManageVotingPermission or
    // ManagePrincipals.
    governance
        .remove_neuron_permissions(&neuron, caller, permissions_to_remove, caller)
        .unwrap_err();

    // Check that `caller` still has the permission
    governance.assert_principal_has_permissions_for_neuron(
        &neuron,
        caller,
        vec![NeuronPermissionType::Vote].into(),
    );
}

#[test]
fn test_normally_unable_to_add_permissions_to_others() {
    let caller = *TEST_NEURON_1_OWNER_PRINCIPAL;
    let target = *TEST_NEURON_2_OWNER_PRINCIPAL;
    let permissions_to_add: NeuronPermissionList = vec![NeuronPermissionType::Vote].into();

    let (mut governance, neuron) = {
        let permissions: &[(PrincipalId, NeuronPermissionList)] =
            &[(caller, vec![NeuronPermissionType::Vote].into())];
        let user_principal = PrincipalId::new_user_test_id(0);
        let neuron_id = neuron_id(user_principal, 0);

        let governance_fixture = GovernanceCanisterFixtureBuilder::new()
            .with_neuron_grantable_permissions(NeuronPermissionList::all())
            .add_neuron_with_permissions(permissions, neuron_id.clone())
            .create();

        (governance_fixture, neuron_id)
    };

    // Attempt to add voting-related permissions to `target` - should
    // fail since `caller` doesn't have ManageVotingPermission or
    // ManagePrincipals.
    governance
        .remove_neuron_permissions(&neuron, target, permissions_to_add, caller)
        .unwrap_err();

    // Check that `target` didn't get the new permissions.
    governance.assert_principal_has_permissions_for_neuron(
        &neuron,
        target,
        NeuronPermissionList::empty(),
    );
}

#[test]
fn test_normally_unable_to_remove_permissions_to_others() {
    let caller = *TEST_NEURON_1_OWNER_PRINCIPAL;
    let target = *TEST_NEURON_2_OWNER_PRINCIPAL;
    let permissions_to_remove: NeuronPermissionList = vec![NeuronPermissionType::Vote].into();

    let (mut governance, neuron) = {
        let permissions: &[(PrincipalId, NeuronPermissionList)] = &[
            (caller, vec![NeuronPermissionType::Vote].into()),
            (target, vec![NeuronPermissionType::Vote].into()),
        ];
        let user_principal = PrincipalId::new_user_test_id(0);
        let neuron_id = neuron_id(user_principal, 0);

        let governance_fixture = GovernanceCanisterFixtureBuilder::new()
            .with_neuron_grantable_permissions(NeuronPermissionList::all())
            .add_neuron_with_permissions(permissions, neuron_id.clone())
            .create();

        (governance_fixture, neuron_id)
    };

    // Attempt to remove voting-related permissions from `target` - should
    // fail since `caller` doesn't have ManageVotingPermission or
    // ManagePrincipals.
    governance
        .remove_neuron_permissions(&neuron, target, permissions_to_remove.clone(), caller)
        .unwrap_err();

    governance.assert_principal_has_permissions_for_neuron(&neuron, target, permissions_to_remove);
}

#[test]
fn test_adding_invalid_permissions_fails() {
    let caller = *TEST_NEURON_1_OWNER_PRINCIPAL;
    let target = *TEST_NEURON_2_OWNER_PRINCIPAL;
    let permissions_to_add: NeuronPermissionList = NeuronPermissionList {
        permissions: vec![10_000], // 10_000 is not going to be a valid permission
    };

    let (mut governance, neuron) = {
        let permissions: &[(PrincipalId, NeuronPermissionList)] =
            &[(caller, vec![NeuronPermissionType::ManagePrincipals].into())];
        let user_principal = PrincipalId::new_user_test_id(0);
        let neuron_id = neuron_id(user_principal, 0);

        let governance_fixture = GovernanceCanisterFixtureBuilder::new()
            .with_neuron_grantable_permissions(NeuronPermissionList::all())
            .add_neuron_with_permissions(permissions, neuron_id.clone())
            .create();

        (governance_fixture, neuron_id)
    };

    // Attempt to remove voting-related permissions from `target` - should
    // fail since `caller` doesn't have ManageVotingPermission or
    // ManagePrincipals.
    governance
        .add_neuron_permissions(&neuron, target, permissions_to_add, caller)
        .unwrap_err();

    governance.assert_principal_has_permissions_for_neuron(
        &neuron,
        target,
        NeuronPermissionList::empty(),
    );
}
