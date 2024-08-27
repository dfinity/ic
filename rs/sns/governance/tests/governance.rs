use crate::fixtures::{
    environment_fixture::CanisterCallRequest, neuron_id, GovernanceCanisterFixture,
    GovernanceCanisterFixtureBuilder, NeuronBuilder, TargetLedger,
};
use assert_matches::assert_matches;
use ic_base_types::{CanisterId, PrincipalId};
use ic_nervous_system_common::{E8, ONE_DAY_SECONDS, ONE_MONTH_SECONDS};
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_OWNER_PRINCIPAL, TEST_NEURON_2_OWNER_PRINCIPAL,
};
use ic_nervous_system_proto::pb::v1::{Percentage, Principals};
use ic_sns_governance::{
    governance::MATURITY_DISBURSEMENT_DELAY_SECONDS,
    neuron::NeuronState,
    pb::{
        sns_root_types::{
            set_dapp_controllers_response::FailedUpdate, RegisterDappCanistersResponse,
            SetDappControllersResponse,
        },
        v1::{
            claim_swap_neurons_request::{
                neuron_recipe::{self, Participant},
                NeuronRecipe, NeuronRecipes,
            },
            claim_swap_neurons_response::{ClaimSwapNeuronsResult, ClaimedSwapNeurons, SwapNeuron},
            governance_error::ErrorType,
            manage_neuron::{
                self, claim_or_refresh, configure::Operation, AddNeuronPermissions, ClaimOrRefresh,
                Configure, Disburse, DisburseMaturity, Follow, IncreaseDissolveDelay,
                MergeMaturity, RegisterVote, RemoveNeuronPermissions, Split, StakeMaturity,
            },
            manage_neuron_response::{
                Command as CommandResponse, DisburseMaturityResponse, MergeMaturityResponse,
                RegisterVoteResponse, StakeMaturityResponse,
            },
            neuron::{self, DissolveState, Followees},
            proposal::Action,
            Account as AccountProto, AddMaturityRequest, Ballot, ClaimSwapNeuronsError,
            ClaimSwapNeuronsRequest, ClaimSwapNeuronsResponse, ClaimedSwapNeuronStatus,
            DeregisterDappCanisters, Empty, GovernanceError, ManageNeuronResponse,
            MintTokensRequest, MintTokensResponse, Motion, NervousSystemParameters, Neuron,
            NeuronId, NeuronIds, NeuronPermission, NeuronPermissionList, NeuronPermissionType,
            Proposal, ProposalData, ProposalId, RegisterDappCanisters, Vote, WaitForQuietState,
        },
    },
    types::native_action_ids,
};
use maplit::btreemap;
use pretty_assertions::assert_eq;
use std::collections::{BTreeMap, HashSet};
use strum::IntoEnumIterator;

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
    let destination_account = icrc_ledger_types::icrc1::account::Account {
        owner: user_principal.0,
        subaccount: None,
    };
    let account_balance_before_disbursal =
        canister_fixture.get_account_balance(&destination_account, TargetLedger::Sns);

    // Disburse the neuron to self and assert that it succeeds
    let manage_neuron_response = canister_fixture.manage_neuron(
        &neuron_id,
        manage_neuron::Command::Disburse(Disburse {
            amount: None, // Translates to all stake
            to_account: Some(AccountProto {
                owner: Some(user_principal),
                subaccount: None,
            }),
        }),
        user_principal,
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
        user_principal,
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
            to_account: Some(AccountProto {
                owner: Some(user_principal),
                subaccount: None,
            }),
        }),
        user_principal,
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

struct DisburseMaturityTestEnvironment {
    pub gov_fixture: GovernanceCanisterFixture,
    pub neuron_id: NeuronId,
    pub controller: PrincipalId,
}

fn setup_test_environment_with_one_neuron_with_maturity(
    earned_maturity_e8s: u64,
    additional_accounts: Vec<PrincipalId>,
) -> DisburseMaturityTestEnvironment {
    let controller = PrincipalId::new_user_test_id(1000);
    let neuron_id = neuron_id(controller, /*memo*/ 0);

    // To enable minting, this account has to be added to SNS ledger, with sufficient funds.
    let governance_canister_id = CanisterId::from_u64(0);

    // Set up the test environment with a single neuron with maturity
    let mut gov_fixture_builder = GovernanceCanisterFixtureBuilder::new()
        .add_neuron(
            NeuronBuilder::new(neuron_id.clone(), E8, NeuronPermission::all(&controller))
                .set_maturity(earned_maturity_e8s),
        )
        .add_account_for(
            governance_canister_id.get(),
            1_000_000_000,
            TargetLedger::Sns,
        );
    for account in additional_accounts {
        gov_fixture_builder = gov_fixture_builder.add_account_for(account, 0, TargetLedger::Sns);
    }
    DisburseMaturityTestEnvironment {
        gov_fixture: gov_fixture_builder.create(),
        neuron_id,
        controller,
    }
}

#[test]
fn test_disburse_maturity_succeeds_to_self() {
    let earned_maturity_e8s = 12345678;
    let mut env = setup_test_environment_with_one_neuron_with_maturity(earned_maturity_e8s, vec![]);

    // Record SNS ledger balance before disbursal.
    let destination_account = icrc_ledger_types::icrc1::account::Account {
        owner: env.controller.0,
        subaccount: None,
    };
    let account_balance_before_disbursal = env
        .gov_fixture
        .get_account_balance(&destination_account, TargetLedger::Sns);

    // Disburse maturity to self.
    let command_response = env
        .gov_fixture
        .manage_neuron(
            &env.neuron_id,
            manage_neuron::Command::DisburseMaturity(DisburseMaturity {
                percentage_to_disburse: 100,
                to_account: None,
            }),
            env.controller,
        )
        .command
        .expect("missing response from manage_neuron operation");
    let response = match command_response {
        CommandResponse::DisburseMaturity(response) => response,
        _ => panic!(
            "Wrong response to DisburseMaturity: {:#?}",
            command_response
        ),
    };
    assert_eq!(response.amount_disbursed_e8s, earned_maturity_e8s);

    // Check the response and the disbursing maturity in progress.
    let neuron = env.gov_fixture.get_neuron(&env.neuron_id);
    assert_eq!(neuron.maturity_e8s_equivalent, 0);
    assert_eq!(neuron.disburse_maturity_in_progress.len(), 1);
    let in_progress = &neuron.disburse_maturity_in_progress[0];
    assert_eq!(
        in_progress.finalize_disbursement_timestamp_seconds,
        Some(env.gov_fixture.now() + MATURITY_DISBURSEMENT_DELAY_SECONDS)
    );
    let target_account_proto = in_progress
        .account_to_disburse_to
        .as_ref()
        .expect("Missing account_to_disburse_to")
        .clone();
    assert_eq!(in_progress.amount_e8s, earned_maturity_e8s);
    let self_account_proto = AccountProto {
        owner: Some(env.controller),
        subaccount: None,
    };
    assert_eq!(target_account_proto, self_account_proto);
    let now = env.gov_fixture.now() as i64;
    let ts = in_progress.timestamp_of_disbursement_seconds as i64;
    let d_age = now - ts;
    assert!(
        d_age >= 0,
        "Disbursement timestamp {} is in the future (now = {})",
        ts,
        now
    );
    assert!(
        d_age < 10,
        "Disbursement timestamp {} is too old (now = {})",
        ts,
        now
    );

    // Check the disbursal is not transferred yet.
    let account_balance = env
        .gov_fixture
        .get_account_balance(&destination_account, TargetLedger::Sns);
    assert_eq!(account_balance_before_disbursal, account_balance);

    // Advance time by a few days, but without triggering disbursal finalization.
    env.gov_fixture.advance_time_by(6 * ONE_DAY_SECONDS);
    env.gov_fixture.heartbeat();
    let neuron = env.gov_fixture.get_neuron(&env.neuron_id);
    assert_eq!(neuron.disburse_maturity_in_progress.len(), 1);

    // Advance more, to hit 7-day period, and to trigger disbursal finalization.
    env.gov_fixture.advance_time_by(ONE_DAY_SECONDS + 10);
    env.gov_fixture.heartbeat();
    let neuron = env.gov_fixture.get_neuron(&env.neuron_id);
    assert_eq!(neuron.disburse_maturity_in_progress.len(), 0);

    // Check that the target's account balance has increased the expected amount.
    // There are no transaction fees, as the disbursal is a minting transfer.
    let expected_account_balance_after_disbursal =
        account_balance_before_disbursal + earned_maturity_e8s;
    let account_balance = env
        .gov_fixture
        .get_account_balance(&destination_account, TargetLedger::Sns);
    assert_eq!(account_balance, expected_account_balance_after_disbursal);
}

#[test]
fn test_disburse_maturity_succeeds_to_other() {
    let earned_maturity_e8s = 12345678;
    let receiver = PrincipalId::new_user_test_id(111);
    let destination_account = icrc_ledger_types::icrc1::account::Account {
        owner: receiver.0,
        subaccount: None,
    };
    let destination_account_proto = AccountProto::from(destination_account);
    let mut env =
        setup_test_environment_with_one_neuron_with_maturity(earned_maturity_e8s, vec![receiver]);
    assert_ne!(env.controller, receiver);

    let controller_account = icrc_ledger_types::icrc1::account::Account {
        owner: env.controller.0,
        subaccount: None,
    };

    // Record SNS ledger balance before disbursal.
    let receiver_balance_before_disbursal = env
        .gov_fixture
        .get_account_balance(&destination_account, TargetLedger::Sns);
    let controller_balance_before_disbursal = env
        .gov_fixture
        .get_account_balance(&controller_account, TargetLedger::Sns);

    // Disburse maturity to other.
    let command_response = env
        .gov_fixture
        .manage_neuron(
            &env.neuron_id,
            manage_neuron::Command::DisburseMaturity(DisburseMaturity {
                percentage_to_disburse: 100,
                to_account: Some(destination_account_proto.clone()),
            }),
            env.controller,
        )
        .command
        .expect("missing response from manage_neuron operation");
    let response = match command_response {
        CommandResponse::DisburseMaturity(response) => response,
        _ => panic!("Wrong response to DisburseMaturity"),
    };
    assert_eq!(response.amount_disbursed_e8s, earned_maturity_e8s);

    // Check the response and the disbursing maturity in progress.
    let neuron = env.gov_fixture.get_neuron(&env.neuron_id);
    assert_eq!(neuron.maturity_e8s_equivalent, 0);
    assert_eq!(neuron.disburse_maturity_in_progress.len(), 1);
    let in_progress = &neuron.disburse_maturity_in_progress[0];
    assert_eq!(
        in_progress.finalize_disbursement_timestamp_seconds,
        Some(env.gov_fixture.now() + MATURITY_DISBURSEMENT_DELAY_SECONDS)
    );
    let target_account_proto = in_progress
        .account_to_disburse_to
        .as_ref()
        .expect("Missing account_to_disburse_to")
        .clone();
    assert_eq!(in_progress.amount_e8s, earned_maturity_e8s);
    assert_eq!(target_account_proto, destination_account_proto);
    let now = env.gov_fixture.now() as i64;
    let ts = in_progress.timestamp_of_disbursement_seconds as i64;
    let d_age = now - ts;
    assert!(
        d_age >= 0,
        "Disbursement timestamp {} is in the future (now = {})",
        ts,
        now
    );
    assert!(
        d_age < 10,
        "Disbursement timestamp {} is too old (now = {})",
        ts,
        now
    );

    // Check the disbursal is not transferred yet.
    let account_balance = env
        .gov_fixture
        .get_account_balance(&destination_account, TargetLedger::Sns);
    assert_eq!(receiver_balance_before_disbursal, account_balance);

    // Advance time by a few days, but without triggering disbursal finalization.
    env.gov_fixture.advance_time_by(6 * ONE_DAY_SECONDS);
    env.gov_fixture.heartbeat();
    let neuron = env.gov_fixture.get_neuron(&env.neuron_id);
    assert_eq!(neuron.disburse_maturity_in_progress.len(), 1);

    // Advance more, to hit 7-day period, and to trigger disbursal finalization.
    env.gov_fixture.advance_time_by(ONE_DAY_SECONDS + 10);
    env.gov_fixture.heartbeat();
    let neuron = env.gov_fixture.get_neuron(&env.neuron_id);
    assert_eq!(neuron.disburse_maturity_in_progress.len(), 0);

    // Check that the target's account balance has increased the expected amount.
    // There are no transaction fees, as the disbursal is a minting transfer.
    let expected_receiver_balance_after_disbursal =
        receiver_balance_before_disbursal + earned_maturity_e8s;
    let receiver_balance_after_disbursal = env
        .gov_fixture
        .get_account_balance(&destination_account, TargetLedger::Sns);
    assert_eq!(
        receiver_balance_after_disbursal,
        expected_receiver_balance_after_disbursal
    );

    // Check that controller's balance remains unchanged.
    let controller_balance_after_disbursal = env
        .gov_fixture
        .get_account_balance(&controller_account, TargetLedger::Sns);
    assert_eq!(
        controller_balance_before_disbursal,
        controller_balance_after_disbursal
    );
}

#[test]
fn test_disburse_maturity_succeeds_with_multiple_operations() {
    let earned_maturity_e8s = 1000000;
    let receiver = PrincipalId::new_user_test_id(111);
    let mut env =
        setup_test_environment_with_one_neuron_with_maturity(earned_maturity_e8s, vec![receiver]);
    assert_ne!(env.controller, receiver);

    // Disburse maturity repeatedly.
    let mut remaining_maturity_e8s = earned_maturity_e8s;
    let percentage_and_destination = [(50, receiver), (50, env.controller), (100, receiver)];
    for (i, (percentage, destination)) in percentage_and_destination.iter().enumerate() {
        let destination_account = icrc_ledger_types::icrc1::account::Account {
            owner: destination.0,
            subaccount: None,
        };
        let destination_account_proto = AccountProto::from(destination_account);
        let command_response = env
            .gov_fixture
            .manage_neuron(
                &env.neuron_id,
                manage_neuron::Command::DisburseMaturity(DisburseMaturity {
                    percentage_to_disburse: *percentage,
                    to_account: Some(destination_account_proto.clone()),
                }),
                env.controller,
            )
            .command
            .expect("missing response from manage_neuron operation");
        let response = match command_response {
            CommandResponse::DisburseMaturity(response) => response,
            _ => panic!("Wrong response to DisburseMaturity"),
        };
        let expected_amount_disbursed_e8s = remaining_maturity_e8s * (*percentage as u64) / 100;
        remaining_maturity_e8s -= expected_amount_disbursed_e8s;
        assert_eq!(response.amount_disbursed_e8s, expected_amount_disbursed_e8s);

        // Check the response and the disbursing maturity in progress.
        let neuron = env.gov_fixture.get_neuron(&env.neuron_id);
        assert_eq!(neuron.maturity_e8s_equivalent, remaining_maturity_e8s);
        assert_eq!(neuron.disburse_maturity_in_progress.len(), i + 1);
        let in_progress = &neuron.disburse_maturity_in_progress[i];
        let target_account_proto = in_progress
            .account_to_disburse_to
            .as_ref()
            .expect("Missing account_to_disburse_to")
            .clone();
        assert_eq!(
            in_progress.amount_e8s, expected_amount_disbursed_e8s,
            "pos: {}",
            i
        );
        assert_eq!(target_account_proto, destination_account_proto);
    }

    // Advance time, to trigger disbursal finalization.
    env.gov_fixture.advance_time_by(7 * ONE_DAY_SECONDS + 10);
    let mut remaining_maturity_e8s = earned_maturity_e8s;
    for (i, (percentage, destination)) in percentage_and_destination.iter().enumerate() {
        let destination_account = icrc_ledger_types::icrc1::account::Account {
            owner: destination.0,
            subaccount: None,
        };
        let balance_before_disbursal = env
            .gov_fixture
            .get_account_balance(&destination_account, TargetLedger::Sns);
        // Each call to heartbeat() "consumes" one entry of disburse_maturity_in_progress.
        env.gov_fixture.heartbeat();
        let neuron = env.gov_fixture.get_neuron(&env.neuron_id);
        assert_eq!(
            neuron.disburse_maturity_in_progress.len(),
            percentage_and_destination.len() - i - 1
        );

        let expected_amount_disbursed_e8s = remaining_maturity_e8s * (*percentage as u64) / 100;
        remaining_maturity_e8s -= expected_amount_disbursed_e8s;
        // Check that the target's account balance has increased the expected amount.
        // There are no transaction fees, as the disbursal is a minting transfer.
        let expected_balance_after_disbursal =
            balance_before_disbursal + expected_amount_disbursed_e8s;
        let account_balance_after_disbursal = env
            .gov_fixture
            .get_account_balance(&destination_account, TargetLedger::Sns);
        assert_eq!(
            account_balance_after_disbursal,
            expected_balance_after_disbursal
        );
    }
}

#[test]
fn test_disburse_maturity_fails_if_maturity_too_low() {
    let earned_maturity_e8s = 123;
    let mut env = setup_test_environment_with_one_neuron_with_maturity(earned_maturity_e8s, vec![]);

    // Disburse maturity.
    let command_response = env
        .gov_fixture
        .manage_neuron(
            &env.neuron_id,
            manage_neuron::Command::DisburseMaturity(DisburseMaturity {
                percentage_to_disburse: 100,
                to_account: None,
            }),
            env.controller,
        )
        .command
        .expect("missing response from manage_neuron operation");
    assert_matches!(
        command_response,
        CommandResponse::Error(GovernanceError{error_type: code, error_message: msg})
            if code == ErrorType::PreconditionFailed as i32 && msg.to_lowercase().contains("can't disburse an amount less than"));
}

#[test]
fn test_disburse_maturity_fails_if_not_authorized() {
    let earned_maturity_e8s = 1234567;
    let mut env = setup_test_environment_with_one_neuron_with_maturity(earned_maturity_e8s, vec![]);
    let unauthorized_caller = PrincipalId::new_user_test_id(111);
    // Disburse maturity.
    let command_response = env
        .gov_fixture
        .manage_neuron(
            &env.neuron_id,
            manage_neuron::Command::DisburseMaturity(DisburseMaturity {
                percentage_to_disburse: 100,
                to_account: None,
            }),
            unauthorized_caller,
        )
        .command
        .expect("missing response from manage_neuron operation");
    assert_matches!(
        command_response,
        CommandResponse::Error(GovernanceError{error_type: code, error_message: _msg})
            if code == ErrorType::NotAuthorized as i32);
}

#[test]
fn test_disburse_maturity_fails_on_non_existing_neuron() {
    let earned_maturity_e8s = 12345767;
    let mut env = setup_test_environment_with_one_neuron_with_maturity(earned_maturity_e8s, vec![]);
    let wrong_neuron_id = neuron_id(PrincipalId::new_user_test_id(111), 0);

    // Disburse maturity.
    let command_response = env
        .gov_fixture
        .manage_neuron(
            &wrong_neuron_id,
            manage_neuron::Command::DisburseMaturity(DisburseMaturity {
                percentage_to_disburse: 100,
                to_account: None,
            }),
            env.controller,
        )
        .command
        .expect("missing response from manage_neuron operation");
    assert_matches!(
        command_response,
        CommandResponse::Error(GovernanceError{error_type: code, error_message: msg})
            if code == ErrorType::NotFound as i32 && msg.to_lowercase().contains("neuron not found"));
}

#[test]
fn test_disburse_maturity_fails_if_invalid_percentage_to_disburse() {
    let earned_maturity_e8s = 12345767;
    let mut env = setup_test_environment_with_one_neuron_with_maturity(earned_maturity_e8s, vec![]);

    // Disburse maturity.
    for percentage in &[0, 101, 120] {
        let command_response = env
            .gov_fixture
            .manage_neuron(
                &env.neuron_id,
                manage_neuron::Command::DisburseMaturity(DisburseMaturity {
                    percentage_to_disburse: *percentage,
                    to_account: None,
                }),
                env.controller,
            )
            .command
            .expect("missing response from manage_neuron operation");
        assert_matches!(
        command_response,
        CommandResponse::Error(GovernanceError{error_type: code, error_message: msg})
            if code == ErrorType::PreconditionFailed as i32 && msg.to_lowercase().contains("percentage of maturity"),
            "Didn't reject invalid percentage_to_disburse value {}", percentage);
    }
}

/// Assert that manage_neuron operations on vesting neurons succeed and fail as expected.
///
/// This test sets up a GovernanceCanisterFixture, then sets up an exhaustive pair of manage_neuron
/// requests and expected responses, and then calls manage_neuron for each request/response pair
/// and asserts that the actual response is equal to the expected response.
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
        amount_disbursed_e8s: 100000,
        amount_deducted_e8s: Some(100000),
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
        let actual_response = gov.manage_neuron(&neuron_id1, command, user_principal1);
        assert_eq!(expected_response, actual_response);
    }

    // RegisterVote needs to be tested with different neuron (neuron1 submitted the proposal)
    let command = Command::RegisterVote(register_vote);
    let expected_response = ManageNeuronResponse::register_vote_response();
    let actual_response = gov.manage_neuron(&neuron_id2, command, user_principal2);
    assert_eq!(expected_response, actual_response);
}

#[test]
fn test_refresh_neuron() {
    use manage_neuron::Command;

    let claim_or_refresh = ClaimOrRefresh {
        by: Some(claim_or_refresh::By::NeuronId(Empty {})),
    };

    let user_principal1 = PrincipalId::new_user_test_id(1000);
    let neuron_id1 = neuron_id(user_principal1, /*memo*/ 0);

    let user_principal2 = PrincipalId::new_user_test_id(1002);
    let neuron_id2 = neuron_id(user_principal2, /*memo*/ 0);

    // Set up the test environment with a single dissolved neuron
    let mut gov = GovernanceCanisterFixtureBuilder::new()
        // Add a neuron that will be configured the way a neuron originating from an NNS Neurons' Fund participation
        // in a decentralization swap will be
        .add_neuron(
            NeuronBuilder::new(
                neuron_id1.clone(),
                E8,
                NeuronPermission::all(&PrincipalId::from(ic_nns_constants::GOVERNANCE_CANISTER_ID)),
            )
            .add_neuron_permission(NeuronPermission {
                principal: Some(user_principal1),
                permission_type: vec![NeuronPermissionType::Vote as i32],
            }),
        )
        // Add a regular neuron for comparison's sake
        .add_neuron(NeuronBuilder::new(
            neuron_id2.clone(),
            E8,
            NeuronPermission::all(&user_principal2),
        ))
        .create();

    {
        let actual_response = gov.manage_neuron(
            &neuron_id1,
            Command::ClaimOrRefresh(claim_or_refresh.clone()),
            user_principal1,
        );
        assert_eq!(
            ManageNeuronResponse {
                command: Some(CommandResponse::Error(GovernanceError {
                    error_type: ErrorType::PreconditionFailed as i32,
                    error_message: "Cannot refresh an SNS Neuron controlled by the Neurons' Fund"
                        .to_string()
                }))
            },
            actual_response
        );
    }
    {
        let actual_response = gov.manage_neuron(
            &neuron_id2,
            Command::ClaimOrRefresh(claim_or_refresh),
            user_principal2,
        );
        assert_eq!(
            ManageNeuronResponse::claim_or_refresh_neuron_response(neuron_id2.clone()),
            actual_response
        );
    }
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

/// Test that the list_nervous_system_functions API always contains entries for
/// native nervous system functions (i.e. functions that correspond to Proposal::Action(_))
#[test]
fn test_list_nervous_system_function_contain_all_proposal_actions() {
    let canister_fixture = GovernanceCanisterFixtureBuilder::new().create();

    let nervous_system_functions = canister_fixture
        .governance
        .list_nervous_system_functions()
        .functions;

    let function_ids = nervous_system_functions
        .iter()
        .map(|function| function.id)
        .collect::<HashSet<u64>>();

    let missing_actions: Vec<Action> = Action::iter()
        .filter(|action| !function_ids.contains(&(u64::from(action))))
        .collect();

    assert!(
        missing_actions.is_empty(),
        "Governance::list_nervous_system_functions is missing \
         native proposal actions in response {:?}",
        missing_actions
    );
}

#[test]
fn test_validate_and_execute_register_dapp_proposal() {
    // Set up the test environment with a single neuron
    let (mut canister_fixture, user_principal, neuron_id) =
        GovernanceCanisterFixtureBuilder::new().create_with_test_neuron();

    let proposal = RegisterDappCanisters {
        canister_ids: vec![CanisterId::from_u64(10000).get()],
    };

    // There will be only one call to SNS root. Mock a successful response
    canister_fixture
        .environment_fixture
        .push_mocked_canister_reply(RegisterDappCanistersResponse {});

    // Make the proposal. Since there is only one neuron, it expected to immediately pass and
    // execute.
    let (_proposal_id, proposal_data) = canister_fixture
        .make_default_proposal(&neuron_id, proposal, user_principal)
        .unwrap();

    // Proposal should not have failed execution
    assert_eq!(proposal_data.failed_timestamp_seconds, 0);
    assert!(proposal_data.executed_timestamp_seconds > 0);

    let observed_register_canister_request = match canister_fixture
        .environment_fixture
        .pop_observed_canister_call()
    {
        CanisterCallRequest::RegisterDappCanisters(request) => request,
        unexpected_observed_canister_call => {
            panic!("Unexpected observed_canister_call: {unexpected_observed_canister_call:?}")
        }
    };

    // Assert that the observed request includes the canister_ids passed in the proposal
    assert_eq!(
        observed_register_canister_request.canister_ids,
        vec![CanisterId::from_u64(10000).get()]
    );
}

#[test]
fn test_register_dapp_canister_proposal_root_failure() {
    // Set up the test environment with a single neuron
    let (mut canister_fixture, user_principal, neuron_id) =
        GovernanceCanisterFixtureBuilder::new().create_with_test_neuron();

    let proposal = RegisterDappCanisters {
        canister_ids: vec![CanisterId::from_u64(10000).get()],
    };

    // There will be only one call to SNS root. Mock a failed response from root (currently this
    // is a panic)
    canister_fixture
        .environment_fixture
        .push_mocked_canister_panic("SNS ROOT PANICKED");

    // Make the proposal. Since there is only one neuron, it expected to immediately pass and
    // execute. The execution will fail, but that is observed in the ProposalData.
    let (_proposal_id, proposal_data) = canister_fixture
        .make_default_proposal(&neuron_id, proposal, user_principal)
        .unwrap();

    // Proposal should have failed execution
    assert!(proposal_data.failed_timestamp_seconds > 0);
    assert_eq!(proposal_data.executed_timestamp_seconds, 0);
    assert!(proposal_data
        .failure_reason
        .unwrap()
        .error_message
        .contains("Canister method call failed"));

    let observed_register_canister_request = match canister_fixture
        .environment_fixture
        .pop_observed_canister_call()
    {
        CanisterCallRequest::RegisterDappCanisters(request) => request,
        unexpected_observed_canister_call => {
            panic!("Unexpected observed_canister_call: {unexpected_observed_canister_call:?}")
        }
    };

    // Assert that the observed request includes the canister_ids passed in the proposal
    assert_eq!(
        observed_register_canister_request.canister_ids,
        vec![CanisterId::from_u64(10000).get()]
    );
}

#[test]
fn test_validate_and_execute_deregister_dapp_proposal() {
    // Set up the test environment with a single neuron
    let (mut canister_fixture, user_principal, neuron_id) =
        GovernanceCanisterFixtureBuilder::new().create_with_test_neuron();

    let test_canister_id = CanisterId::from_u64(10000).get();

    let proposal = DeregisterDappCanisters {
        canister_ids: vec![test_canister_id],
        new_controllers: vec![user_principal],
    };

    // There will be only one call to SNS root. Mock a successful response
    canister_fixture
        .environment_fixture
        .push_mocked_canister_reply(SetDappControllersResponse {
            failed_updates: vec![],
        });

    // Make the proposal. Since there is only one neuron, it expected to immediately pass and
    // execute.
    let (_proposal_id, proposal_data) = canister_fixture
        .make_default_proposal(&neuron_id, proposal, user_principal)
        .unwrap();

    // Proposal should not have failed execution
    assert_eq!(proposal_data.failed_timestamp_seconds, 0);
    assert!(proposal_data.executed_timestamp_seconds > 0);

    let observed_register_canister_request = match canister_fixture
        .environment_fixture
        .pop_observed_canister_call()
    {
        CanisterCallRequest::SetDappControllers(request) => request,
        unexpected_observed_canister_call => {
            panic!("Unexpected observed_canister_call: {unexpected_observed_canister_call:?}")
        }
    };

    // Assert that the observed request includes the canister_ids passed in the proposal
    assert_eq!(
        observed_register_canister_request
            .canister_ids
            .unwrap()
            .canister_ids,
        vec![CanisterId::from_u64(10000).get()]
    );
}

#[test]
fn test_validate_and_execute_deregister_dapp_proposal_failure() {
    // Set up the test environment with a single neuron
    let (mut canister_fixture, user_principal, neuron_id) =
        GovernanceCanisterFixtureBuilder::new().create_with_test_neuron();

    let test_canister_id = CanisterId::from_u64(10000).get();

    let proposal = DeregisterDappCanisters {
        canister_ids: vec![test_canister_id],
        new_controllers: vec![user_principal],
    };

    // There will be only one call to SNS root. Mock a panic response
    canister_fixture
        .environment_fixture
        .push_mocked_canister_panic("SNS ROOT PANICKED");

    // Make the proposal. Since there is only one neuron, it expected to immediately pass and
    // execute.
    let (_proposal_id, proposal_data) = canister_fixture
        .make_default_proposal(&neuron_id, proposal, user_principal)
        .unwrap();

    // Proposal should have failed execution
    assert!(proposal_data.failed_timestamp_seconds > 0);
    assert_eq!(proposal_data.executed_timestamp_seconds, 0);

    let observed_register_canister_request = match canister_fixture
        .environment_fixture
        .pop_observed_canister_call()
    {
        CanisterCallRequest::SetDappControllers(request) => request,
        unexpected_observed_canister_call => {
            panic!("Unexpected observed_canister_call: {unexpected_observed_canister_call:?}")
        }
    };

    // Assert that the observed request includes the canister_ids passed in the proposal
    assert_eq!(
        observed_register_canister_request
            .canister_ids
            .unwrap()
            .canister_ids,
        vec![CanisterId::from_u64(10000).get()]
    );
}

#[test]
fn test_validate_and_execute_deregister_dapp_proposal_fails_when_cant_set_all_controllers() {
    // Set up the test environment with a single neuron
    let (mut canister_fixture, user_principal, neuron_id) =
        GovernanceCanisterFixtureBuilder::new().create_with_test_neuron();

    let test_canister_id = CanisterId::from_u64(10000).get();

    let proposal = DeregisterDappCanisters {
        canister_ids: vec![test_canister_id],
        new_controllers: vec![user_principal],
    };

    // There will be only one call to SNS root. Mock a panic response
    canister_fixture
        .environment_fixture
        .push_mocked_canister_reply(SetDappControllersResponse {
            failed_updates: vec![FailedUpdate {
                dapp_canister_id: Some(test_canister_id),
                err: None,
            }],
        });

    // Make the proposal. Since there is only one neuron, it expected to immediately pass and
    // execute.
    let (_proposal_id, proposal_data) = canister_fixture
        .make_default_proposal(&neuron_id, proposal, user_principal)
        .unwrap();

    // Proposal should have failed execution
    assert!(proposal_data.failed_timestamp_seconds > 0);
    assert_eq!(proposal_data.executed_timestamp_seconds, 0);

    let observed_register_canister_request = match canister_fixture
        .environment_fixture
        .pop_observed_canister_call()
    {
        CanisterCallRequest::SetDappControllers(request) => request,
        unexpected_observed_canister_call => {
            panic!("Unexpected observed_canister_call: {unexpected_observed_canister_call:?}")
        }
    };

    // Assert that the observed request includes the canister_ids passed in the proposal
    assert_eq!(
        observed_register_canister_request
            .canister_ids
            .unwrap()
            .canister_ids,
        vec![CanisterId::from_u64(10000).get()]
    );
}

#[test]
fn test_validate_and_execute_register_dapp_proposal_fails_when_no_canisters_passed() {
    // Set up the test environment with a single neuron
    let (mut canister_fixture, user_principal, neuron_id) =
        GovernanceCanisterFixtureBuilder::new().create_with_test_neuron();

    let proposal = RegisterDappCanisters {
        canister_ids: vec![],
    };

    // There will be only one call to SNS root. Mock a successful response
    canister_fixture
        .environment_fixture
        .push_mocked_canister_reply(RegisterDappCanistersResponse {});

    // Make the proposal. Since there is only one neuron, it expected to immediately pass and
    // execute.
    let GovernanceError {
        error_type: _,
        error_message,
    } = canister_fixture
        .make_default_proposal(&neuron_id, proposal, user_principal)
        .unwrap_err();

    // Proposal should not have failed execution
    assert!(error_message.contains("must specify at least one canister id"));
}

#[test]
fn test_claim_swap_neurons_rejects_unauthorized_access() {
    // Set up the test environment with the default sale canister id
    let mut canister_fixture = GovernanceCanisterFixtureBuilder::new().create();

    // Build the request, but leave it empty as it is not relevant to the test
    #[allow(deprecated)] // TODO: remove once neuron_parameters is removed
    let request = ClaimSwapNeuronsRequest {
        neuron_parameters: vec![],
        neuron_recipes: None,
    };

    // Generate a principal id that should not be authorized to call claim_swap_neurons
    let unauthorized_principal = PrincipalId::new_user_test_id(1000);

    // Call the method with the unauthorized principal and assert the response is correct
    let response = canister_fixture
        .governance
        .claim_swap_neurons(request.clone(), unauthorized_principal);

    assert_eq!(
        response,
        ClaimSwapNeuronsResponse {
            claim_swap_neurons_result: Some(ClaimSwapNeuronsResult::Err(
                ClaimSwapNeuronsError::Unauthorized as i32
            )),
        }
    );

    // Get the configured sale canister id created by the test environment
    let authorized_sale_principal = canister_fixture.get_sale_canister_id();

    // Call the method with the authorized principal and assert the response is correct
    let response = canister_fixture
        .governance
        .claim_swap_neurons(request, authorized_sale_principal);

    assert_eq!(
        response,
        ClaimSwapNeuronsResponse {
            claim_swap_neurons_result: Some(ClaimSwapNeuronsResult::Ok(ClaimedSwapNeurons {
                swap_neurons: vec![],
            })),
        }
    );
}

#[test]
fn test_claim_swap_neurons_reports_invalid_neuron_parameters() {
    // Set up the test environment with default sale canister id
    let mut canister_fixture = GovernanceCanisterFixtureBuilder::new().create();

    // Create a neuron id so the test can identify the correct item in the response
    let test_neuron_id = NeuronId::new_test_neuron_id(1);

    // Create a request with an invalid NeuronParameter
    #[allow(deprecated)] // TODO: remove once neuron_parameters is removed
    let request = ClaimSwapNeuronsRequest {
        neuron_parameters: vec![],
        neuron_recipes: Some(NeuronRecipes::from(vec![NeuronRecipe {
            neuron_id: Some(test_neuron_id.clone()),
            ..Default::default() // The rest of the fields are unset and will fail validation
        }])),
    };

    // Call the method
    let authorized_sale_principal = canister_fixture.get_sale_canister_id();
    let response = canister_fixture
        .governance
        .claim_swap_neurons(request, authorized_sale_principal);

    // Assert that the invalid neuron parameter results in a SwapNeuron with an invalid status
    assert_eq!(
        response,
        ClaimSwapNeuronsResponse {
            claim_swap_neurons_result: Some(ClaimSwapNeuronsResult::Ok(ClaimedSwapNeurons {
                swap_neurons: vec![SwapNeuron {
                    id: Some(test_neuron_id),
                    status: ClaimedSwapNeuronStatus::Invalid as i32,
                }],
            })),
        }
    );
}

#[test]
fn test_claim_swap_neurons_reports_already_existing_neurons() {
    // Create a valid neuron that will be inserted into the test environment
    let user_principal = PrincipalId::new_user_test_id(1000);
    let neuron_id = neuron_id(user_principal, /*memo*/ 0);

    // Set up the test environment with a single neuron
    let mut canister_fixture = GovernanceCanisterFixtureBuilder::new()
        .add_neuron(NeuronBuilder::new(
            neuron_id.clone(),
            E8,
            NeuronPermission::all(&user_principal),
        ))
        .create();

    // Create a request with a neuron id that should collide with the neuron already inserted into
    // Governance
    #[allow(deprecated)] // TODO: remove once neuron_parameters is removed
    let request = ClaimSwapNeuronsRequest {
        neuron_parameters: vec![],
        neuron_recipes: Some(NeuronRecipes::from(vec![NeuronRecipe {
            neuron_id: Some(neuron_id.clone()),
            controller: Some(user_principal),
            participant: Some(Participant::Direct(neuron_recipe::Direct {})),
            stake_e8s: Some(E8),
            dissolve_delay_seconds: Some(0),
            followees: Some(NeuronIds::from(vec![])),
        }])),
    };

    let authorized_sale_principal = canister_fixture.get_sale_canister_id();
    let response = canister_fixture
        .governance
        .claim_swap_neurons(request, authorized_sale_principal);

    assert_eq!(
        response,
        ClaimSwapNeuronsResponse {
            claim_swap_neurons_result: Some(ClaimSwapNeuronsResult::Ok(ClaimedSwapNeurons {
                swap_neurons: vec![SwapNeuron {
                    id: Some(neuron_id),
                    status: ClaimedSwapNeuronStatus::AlreadyExists as i32,
                }],
            })),
        }
    );
}

#[test]
fn test_claim_swap_neurons_reports_failure_if_neuron_cannot_be_added() {
    // Set up the test environment with default sale canister id.
    let mut canister_fixture = GovernanceCanisterFixtureBuilder::new().create();

    // To cause a failure, set the nervous_system_parameters::max_number_of_neurons to 0
    canister_fixture
        .governance
        .proto
        .parameters
        .as_mut()
        .unwrap()
        .max_number_of_neurons = Some(1);

    // Create a neuron id so the test can identify the correct item in the response
    let test_neuron_id_success = NeuronId::new_test_neuron_id(1);
    let test_neuron_id_failure = NeuronId::new_test_neuron_id(2);

    // Create a request with a NeuronParameter should succeed
    #[allow(deprecated)] // TODO: remove once neuron_parameters is removed
    let request = ClaimSwapNeuronsRequest {
        neuron_parameters: vec![],
        neuron_recipes: Some(NeuronRecipes::from(vec![
            NeuronRecipe {
                neuron_id: Some(test_neuron_id_success.clone()),
                controller: Some(PrincipalId::new_user_test_id(1000)),
                participant: Some(Participant::Direct(neuron_recipe::Direct {})),
                stake_e8s: Some(E8),
                dissolve_delay_seconds: Some(0),
                followees: Some(NeuronIds::from(vec![])),
            },
            NeuronRecipe {
                neuron_id: Some(test_neuron_id_failure.clone()),
                controller: Some(PrincipalId::new_user_test_id(1000)),
                participant: Some(Participant::Direct(neuron_recipe::Direct {})),
                stake_e8s: Some(E8),
                dissolve_delay_seconds: Some(0),
                followees: Some(NeuronIds::from(vec![])),
            },
        ])),
    };

    // Call the method
    let authorized_sale_principal = canister_fixture.get_sale_canister_id();
    let response = canister_fixture
        .governance
        .claim_swap_neurons(request, authorized_sale_principal);

    // Assert that the invalid neuron parameter results in a SwapNeuron with an invalid status
    assert_eq!(
        response,
        ClaimSwapNeuronsResponse {
            claim_swap_neurons_result: Some(ClaimSwapNeuronsResult::Ok(ClaimedSwapNeurons {
                swap_neurons: vec![
                    SwapNeuron {
                        id: Some(test_neuron_id_success),
                        status: ClaimedSwapNeuronStatus::Success as i32,
                    },
                    SwapNeuron {
                        id: Some(test_neuron_id_failure),
                        status: ClaimedSwapNeuronStatus::MemoryExhausted as i32
                    }
                ],
            })),
        }
    );
}

#[test]
fn test_claim_swap_neurons_succeeds() {
    // Set up the test environment with default sale canister id.
    let mut canister_fixture = GovernanceCanisterFixtureBuilder::new().create();

    let direct_participant_neuron_recipe = NeuronRecipe {
        neuron_id: Some(NeuronId::new_test_neuron_id(1)),
        controller: Some(PrincipalId::new_user_test_id(1000)),
        participant: Some(Participant::Direct(neuron_recipe::Direct {})),
        stake_e8s: Some(E8),
        dissolve_delay_seconds: Some(0),
        followees: Some(NeuronIds::from(vec![NeuronId::new_test_neuron_id(10)])),
    };

    let nf_participant_nns_neuron_id = 2;
    let nf_participant_nns_neuron_controller = PrincipalId::new_user_test_id(1002);
    let nf_participant_neuron_recipe = NeuronRecipe {
        neuron_id: Some(NeuronId::new_test_neuron_id(2)),
        controller: Some(PrincipalId::new_user_test_id(1001)),
        participant: Some(Participant::NeuronsFund(neuron_recipe::NeuronsFund {
            nns_neuron_controller: Some(nf_participant_nns_neuron_controller),
            nns_neuron_id: Some(nf_participant_nns_neuron_id),
            nns_neuron_hotkeys: Some(Principals::from(vec![PrincipalId::new_user_test_id(1003)])),
        })),
        stake_e8s: Some(2 * E8),
        dissolve_delay_seconds: Some(ONE_MONTH_SECONDS),
        followees: Some(NeuronIds::from(vec![NeuronId::new_test_neuron_id(20)])),
    };

    #[allow(deprecated)] // TODO: remove once neuron_parameters is removed
    let request = ClaimSwapNeuronsRequest {
        neuron_parameters: vec![],
        neuron_recipes: Some(NeuronRecipes::from(vec![
            direct_participant_neuron_recipe.clone(),
            nf_participant_neuron_recipe.clone(),
        ])),
    };

    // Call the method
    let authorized_sale_principal = canister_fixture.get_sale_canister_id();
    let response = canister_fixture
        .governance
        .claim_swap_neurons(request, authorized_sale_principal);

    // Parse the result from the response
    let swap_neurons = match response.claim_swap_neurons_result.unwrap() {
        ClaimSwapNeuronsResult::Ok(result) => result.swap_neurons,
        ClaimSwapNeuronsResult::Err(err) => panic!(
            "Unexpected response from claim_swap_neurons. Was expected Ok(result). Err {}",
            err
        ),
    };

    // Assert that each NeuronParameter has a response and that it has the correct status
    let direct_participant_swap_neuron = swap_neurons
        .iter()
        .find(|s| s.id == direct_participant_neuron_recipe.neuron_id)
        .unwrap();
    assert_eq!(
        direct_participant_swap_neuron.status,
        ClaimedSwapNeuronStatus::Success as i32
    );

    let cf_participant_swap_neuron = swap_neurons
        .iter()
        .find(|s| s.id == nf_participant_neuron_recipe.neuron_id)
        .unwrap();
    assert_eq!(
        cf_participant_swap_neuron.status,
        ClaimedSwapNeuronStatus::Success as i32
    );

    // Asserts on Direct Participant
    let direct_participant_neuron =
        canister_fixture.get_neuron(direct_participant_neuron_recipe.neuron_id.as_ref().unwrap());
    assert_eq!(
        direct_participant_neuron.id,
        direct_participant_neuron_recipe.neuron_id
    );
    assert_eq!(
        direct_participant_neuron.cached_neuron_stake_e8s,
        direct_participant_neuron_recipe.stake_e8s()
    );
    assert_eq!(
        direct_participant_neuron.dissolve_state,
        Some(DissolveState::DissolveDelaySeconds(
            direct_participant_neuron_recipe.dissolve_delay_seconds()
        ))
    );
    assert_eq!(direct_participant_neuron.source_nns_neuron_id, None);
    assert_eq!(direct_participant_neuron.maturity_e8s_equivalent, 0);
    assert_eq!(direct_participant_neuron.neuron_fees_e8s, 0);
    assert_eq!(direct_participant_neuron.auto_stake_maturity, None);
    for followees in direct_participant_neuron.followees.values() {
        assert_eq!(
            Some(NeuronIds::from(followees.followees.clone())),
            direct_participant_neuron_recipe.followees
        );
    }

    // Asserts on CF Participant
    let cf_participant_neuron =
        canister_fixture.get_neuron(nf_participant_neuron_recipe.neuron_id.as_ref().unwrap());
    assert_eq!(
        cf_participant_neuron.id,
        nf_participant_neuron_recipe.neuron_id
    );
    assert_eq!(
        cf_participant_neuron.cached_neuron_stake_e8s,
        nf_participant_neuron_recipe.stake_e8s()
    );
    assert_eq!(
        cf_participant_neuron.dissolve_state,
        Some(DissolveState::DissolveDelaySeconds(
            nf_participant_neuron_recipe.dissolve_delay_seconds()
        ))
    );
    assert_eq!(
        cf_participant_neuron.source_nns_neuron_id,
        Some(nf_participant_nns_neuron_id)
    );
    assert_eq!(cf_participant_neuron.maturity_e8s_equivalent, 0);
    assert_eq!(cf_participant_neuron.neuron_fees_e8s, 0);
    assert_eq!(cf_participant_neuron.auto_stake_maturity, Some(true));
    for followees in cf_participant_neuron.followees.values() {
        assert_eq!(
            Some(NeuronIds::from(followees.followees.clone())),
            nf_participant_neuron_recipe.followees
        );
    }
}

// If the proposal ID doesn't map to any proposal, we should not be able to vote on that ID.
#[test]
fn test_register_vote_fails_if_proposal_not_found() {
    // Set up the test environment with a single neuron
    let proposal_deadline = 10;
    let (mut canister_fixture, user_principal, neuron_id) = GovernanceCanisterFixtureBuilder::new()
        .set_start_time(proposal_deadline - 1)
        .create_with_test_neuron();

    // Don't insert a proposal (because that's what we're testing)
    let proposal_id = ProposalId::from(1);

    // Register a vote
    let error = canister_fixture
        .vote(&neuron_id, proposal_id, Vote::Yes, user_principal)
        .unwrap_err();

    // Inspect results
    assert!(
        error.to_string().contains("Can't find proposal."),
        "{error:?}"
    );
}

// If the ProposalData's ballots field doesn't contain the neuron, the neuron
// should not be able to vote. This happens when the neuron was created after
// the proposal was created.
#[test]
fn test_register_vote_fails_if_neuron_not_present_in_proposal() {
    // Set up the test environment with a single neuron
    let proposal_deadline = 10;
    let (mut canister_fixture, user_principal, neuron_id) = GovernanceCanisterFixtureBuilder::new()
        .set_start_time(proposal_deadline - 1)
        .create_with_test_neuron();

    // Insert a proposal
    let proposal_id = ProposalId::from(1);
    let proposal = ProposalData {
        id: Some(proposal_id),
        wait_for_quiet_state: Some(WaitForQuietState {
            current_deadline_timestamp_seconds: proposal_deadline,
        }),
        proposal: Some(Proposal {
            action: Some(Action::Motion(Motion::new("Test"))),
            ..Proposal::default()
        }),
        // The `ballots` will be initialized to an empty map.
        // Only neurons with an entry in `ballots` should be able to vote.
        ..ProposalData::default()
    };

    canister_fixture.directly_insert_proposal_data(proposal);

    // Register a vote
    let error = canister_fixture
        .vote(&neuron_id, proposal_id, Vote::Yes, user_principal)
        .unwrap_err();

    // Inspect results
    assert!(error.to_string().contains("not eligible"), "{error:?}");
    let proposal = canister_fixture.get_proposal_or_panic(proposal_id);
    assert_eq!(proposal.ballots, BTreeMap::new());
}

// If the neuron has already voted, it should not be able to vote again.
#[test]
fn test_register_vote_fails_if_neuron_already_voted() {
    // Set up the test environment with a single neuron
    let proposal_deadline = 10;
    let (mut canister_fixture, user_principal, neuron_id) = GovernanceCanisterFixtureBuilder::new()
        .set_start_time(proposal_deadline - 1)
        .create_with_test_neuron();

    // Insert a proposal
    let proposal_id = ProposalId::from(1);
    let proposal = ProposalData {
        id: Some(proposal_id),
        wait_for_quiet_state: Some(WaitForQuietState {
            current_deadline_timestamp_seconds: proposal_deadline,
        }),
        proposal: Some(Proposal {
            action: Some(Action::Motion(Motion::new("Test"))),
            ..Proposal::default()
        }),
        ballots: btreemap! {
            neuron_id.to_string() => Ballot {
                vote: Vote::No as i32, // Here, the neuron already voted `no`,
                                       // so it should not be able to vote again.
                ..Ballot::default()
            }
        },
        ..ProposalData::default()
    };

    canister_fixture.directly_insert_proposal_data(proposal);

    // Register a vote
    let error = canister_fixture
        .vote(&neuron_id, proposal_id, Vote::Yes, user_principal)
        .unwrap_err();

    // Inspect results
    assert!(error.to_string().contains("already voted"), "{error:?}");
    let proposal = canister_fixture.get_proposal_or_panic(proposal_id);
    assert_eq!(
        proposal.ballots,
        btreemap! {
            neuron_id.clone().to_string() => Ballot {
                vote: Vote::No as i32,
                ..Ballot::default()
            }
        }
    );
}

// If the deadline has passed, the neuron should not be able to vote.
#[test]
fn test_register_vote_fails_if_past_deadline() {
    // Set up the test environment with a single neuron
    let proposal_deadline = 10;
    let (mut canister_fixture, user_principal, neuron_id) = GovernanceCanisterFixtureBuilder::new()
        // Set the start time to be after the proposal deadline, so attempts to
        // vote on the proposal should fail.
        .set_start_time(proposal_deadline + 1)
        .create_with_test_neuron();

    let proposal_id = ProposalId::from(1);
    let proposal = ProposalData {
        id: Some(proposal_id),
        wait_for_quiet_state: Some(WaitForQuietState {
            current_deadline_timestamp_seconds: proposal_deadline,
        }),
        proposal: Some(Proposal {
            action: Some(Action::Motion(Motion::new("Test"))),
            ..Proposal::default()
        }),
        ballots: btreemap! {
            neuron_id.to_string() => Ballot {
                vote: Vote::Unspecified as i32,
                ..Ballot::default()
            }
        },
        ..ProposalData::default()
    };

    // Register a vote
    canister_fixture.directly_insert_proposal_data(proposal);
    let error = canister_fixture
        .vote(&neuron_id, proposal_id, Vote::Yes, user_principal)
        .unwrap_err();

    // Inspect results
    assert!(error.to_string().contains("deadline"), "{error:?}");
    let proposal = canister_fixture.get_proposal_or_panic(proposal_id);
    assert_eq!(
        proposal.ballots,
        btreemap! {
            neuron_id.clone().to_string() => Ballot {
                vote: Vote::Unspecified as i32,
                ..Ballot::default()
            }
        }
    );
}

// If the deadline has passed, the neuron should not be able to vote.
// This applies even if wait_for_quiet_state is None.
#[test]
fn test_register_vote_fails_if_past_deadline_no_wait_for_quiet() {
    // Set up the test environment with a single neuron
    let proposal_deadline = 10;
    let (mut canister_fixture, user_principal, neuron_id) = GovernanceCanisterFixtureBuilder::new()
        // Set the start time to be after the proposal deadline, so attempts to
        // vote on the proposal should fail.
        .set_start_time(proposal_deadline + 1)
        .create_with_test_neuron();

    let proposal_id = ProposalId::from(1);
    let proposal = ProposalData {
        id: Some(proposal_id),
        proposal: Some(Proposal {
            action: Some(Action::Motion(Motion::new("Test"))),
            ..Proposal::default()
        }),
        ballots: btreemap! {
            neuron_id.to_string() => Ballot {
                vote: Vote::Unspecified as i32,
                ..Ballot::default()
            }
        },
        // Setting initial_voting_period_seconds instead of wait_for_quiet_state
        initial_voting_period_seconds: proposal_deadline,
        ..ProposalData::default()
    };

    // Register a vote
    canister_fixture.directly_insert_proposal_data(proposal);
    let error = canister_fixture
        .vote(&neuron_id, proposal_id, Vote::Yes, user_principal)
        .unwrap_err();

    // Inspect results
    assert!(error.to_string().contains("deadline"), "{error:?}");
    let proposal = canister_fixture.get_proposal_or_panic(proposal_id);
    assert_eq!(
        proposal.ballots,
        btreemap! {
            neuron_id.clone().to_string() => Ballot {
                vote: Vote::Unspecified as i32,
                ..Ballot::default()
            }
        }
    );
}

#[test]
fn test_register_vote_happy() {
    // Set up the test environment with a single neuron
    let proposal_deadline = 10;
    let (mut canister_fixture, user_principal, neuron_id) = GovernanceCanisterFixtureBuilder::new()
        .set_start_time(proposal_deadline - 1)
        .create_with_test_neuron();

    // Insert a proposal
    let proposal_id = ProposalId::from(1);
    let proposal = ProposalData {
        id: Some(proposal_id),
        wait_for_quiet_state: Some(WaitForQuietState {
            current_deadline_timestamp_seconds: proposal_deadline,
        }),
        proposal: Some(Proposal {
            action: Some(Action::Motion(Motion::new("Test"))),
            ..Proposal::default()
        }),
        ballots: btreemap! {
            neuron_id.to_string() => Ballot {
                vote: Vote::Unspecified as i32,
                ..Ballot::default()
            }
        },
        ..ProposalData::default()
    };

    canister_fixture.directly_insert_proposal_data(proposal);

    // Register a vote
    let RegisterVoteResponse {} = canister_fixture
        .vote(&neuron_id, proposal_id, Vote::Yes, user_principal)
        .unwrap();

    // Inspect results
    let proposal = canister_fixture.get_proposal_or_panic(proposal_id);
    assert_eq!(
        proposal.ballots,
        btreemap! {
            neuron_id.clone().to_string() => Ballot {
                vote: Vote::Yes as i32,
                cast_timestamp_seconds: proposal_deadline - 1,
                ..Ballot::default()
            }
        }
    );
}

/// Test that a neuron can follow itself on a specific Action and effectively
/// override the "catch-all" follow relationship defined by Action::Unspecified
#[test]
fn test_neurons_can_follow_themselves() {
    // Create the various neurons needed for this test
    let followee_principal_id = PrincipalId::new_user_test_id(1000);
    let followee_neuron_id = neuron_id(followee_principal_id, /*memo*/ 0);

    let follower_principal_id = PrincipalId::new_user_test_id(1001);
    let follower_neuron_id = neuron_id(follower_principal_id, /*memo*/ 0);

    let proposer_principal_id = PrincipalId::new_user_test_id(1002);
    let proposer_neuron_id = neuron_id(proposer_principal_id, /*memo*/ 0);

    // Set up the test environment with neurons that can vote
    let mut canister_fixture = GovernanceCanisterFixtureBuilder::new()
        .add_neuron(
            NeuronBuilder::new(
                followee_neuron_id.clone(),
                E8,
                NeuronPermission::all(&followee_principal_id),
            )
            .set_dissolve_delay(15778801),
        )
        .add_neuron(
            NeuronBuilder::new(
                follower_neuron_id.clone(),
                E8,
                NeuronPermission::all(&follower_principal_id),
            )
            .set_dissolve_delay(15778801),
        )
        .add_neuron(
            NeuronBuilder::new(
                proposer_neuron_id.clone(),
                E8,
                NeuronPermission::all(&proposer_principal_id),
            )
            .set_dissolve_delay(15778801),
        )
        .create();

    // Set up the following relationships

    // The follower neuron will follow the followee neuron for all actions
    assert!(canister_fixture
        .follow(
            &follower_neuron_id,
            native_action_ids::UNSPECIFIED,
            vec![followee_neuron_id.clone()],
            follower_principal_id
        )
        .is_ok());

    // The follower neuron will follow themselves on a single Action, effectively overriding
    // the catch all follow.
    assert!(canister_fixture
        .follow(
            &follower_neuron_id,
            native_action_ids::MOTION,
            vec![follower_neuron_id.clone()],
            follower_principal_id,
        )
        .is_ok());

    // Assert that the following has been setup correctly and no errors were thrown.
    let follower_neuron = canister_fixture.get_neuron(&follower_neuron_id);
    assert_eq!(
        follower_neuron.followees,
        btreemap! {
            native_action_ids::UNSPECIFIED => neuron::Followees {
                followees: vec![followee_neuron_id.clone()]
            },
            native_action_ids::MOTION => neuron::Followees {
                followees: vec![follower_neuron_id.clone()]
            }
        }
    );

    // Submit a motion proposal
    let (proposal_id, _) = canister_fixture
        .make_default_proposal(
            &proposer_neuron_id,
            Motion {
                motion_text: "Test self following".to_string(),
            },
            proposer_principal_id,
        )
        .unwrap();

    // Vote with the followee neuron, this should not result in the follower neuron voting
    assert!(canister_fixture
        .vote(
            &followee_neuron_id,
            proposal_id,
            Vote::Yes,
            followee_principal_id
        )
        .is_ok());

    let proposal_data = canister_fixture.get_proposal_or_panic(proposal_id);
    let follower_ballot = proposal_data
        .ballots
        .get(&follower_neuron_id.to_string())
        .expect("Expected the follower neuron to have a ballot");
    assert_eq!(follower_ballot.vote, Vote::Unspecified as i32);

    // Vote with the follower neuron, this should result in casting a vote
    assert!(canister_fixture
        .vote(
            &follower_neuron_id,
            proposal_id,
            Vote::No,
            follower_principal_id
        )
        .is_ok());
    let proposal_data = canister_fixture.get_proposal_or_panic(proposal_id);
    let follower_ballot = proposal_data
        .ballots
        .get(&follower_neuron_id.to_string())
        .expect("Expected the follower neuron to have a ballot");
    assert_eq!(follower_ballot.vote, Vote::No as i32);

    // Submit a covered by the "catch-all" follow
    let (proposal_id, _) = canister_fixture
        .make_default_proposal(
            &proposer_neuron_id,
            RegisterDappCanisters {
                canister_ids: vec![PrincipalId::new_user_test_id(1)],
            },
            proposer_principal_id,
        )
        .unwrap();

    // Vote with the followee neuron. This should result in the follower neuron casting a vote
    assert!(canister_fixture
        .vote(
            &followee_neuron_id,
            proposal_id,
            Vote::No,
            followee_principal_id
        )
        .is_ok());

    let proposal_data = canister_fixture.get_proposal_or_panic(proposal_id);
    let follower_ballot = proposal_data
        .ballots
        .get(&follower_neuron_id.to_string())
        .expect("Expected the follower neuron to have a ballot");
    assert_eq!(follower_ballot.vote, Vote::No as i32);

    // An error should occur if the follower neuron now tries to vote as their vote has
    // already been cast
    assert!(canister_fixture
        .vote(
            &follower_neuron_id,
            proposal_id,
            Vote::No,
            follower_principal_id
        )
        .is_err());
}

// Same as the previous test, but wait_for_quiet_state is None.
#[test]
fn test_register_vote_happy_no_wait_for_quiet() {
    // Set up the test environment with a single neuron
    let proposal_deadline = 10;
    let (mut canister_fixture, user_principal, neuron_id) = GovernanceCanisterFixtureBuilder::new()
        .set_start_time(proposal_deadline - 1)
        .create_with_test_neuron();

    // Insert a proposal
    let proposal_id = ProposalId::from(1);
    let proposal = ProposalData {
        id: Some(proposal_id),
        proposal: Some(Proposal {
            action: Some(Action::Motion(Motion::new("Test"))),
            ..Proposal::default()
        }),
        ballots: btreemap! {
            neuron_id.to_string() => Ballot {
                vote: Vote::Unspecified as i32,
                ..Ballot::default()
            }
        },
        // Setting initial_voting_period_seconds instead of wait_for_quiet_state
        initial_voting_period_seconds: proposal_deadline,
        ..ProposalData::default()
    };

    canister_fixture.directly_insert_proposal_data(proposal);

    // Register a vote
    let RegisterVoteResponse {} = canister_fixture
        .vote(&neuron_id, proposal_id, Vote::Yes, user_principal)
        .unwrap();

    // Inspect results
    let proposal = canister_fixture.get_proposal_or_panic(proposal_id);
    assert_eq!(
        proposal.ballots,
        btreemap! {
            neuron_id.clone().to_string() => Ballot {
                vote: Vote::Yes as i32,
                cast_timestamp_seconds: proposal_deadline - 1,
                ..Ballot::default()
            }
        }
    );
}

/// Tests that if a Neuron's has an empty Followees vector for an Action, the fallback is
/// to vote with the followees in the Unspecified Action
#[test]
fn test_empty_followees_are_filtered() {
    // Create the various neurons needed for this test
    let followee_principal_id = PrincipalId::new_user_test_id(1000);
    let followee_neuron_id = neuron_id(followee_principal_id, /*memo*/ 0);

    let follower_principal_id = PrincipalId::new_user_test_id(1001);
    let follower_neuron_id = neuron_id(follower_principal_id, /*memo*/ 0);

    let proposer_principal_id = PrincipalId::new_user_test_id(1002);
    let proposer_neuron_id = neuron_id(proposer_principal_id, /*memo*/ 0);

    // Set up the test environment with neurons that can vote
    let mut canister_fixture = GovernanceCanisterFixtureBuilder::new()
        .add_neuron(
            NeuronBuilder::new(
                follower_neuron_id.clone(),
                E8,
                NeuronPermission::all(&follower_principal_id),
            )
            .add_followees(
                native_action_ids::UNSPECIFIED,
                Followees {
                    followees: vec![followee_neuron_id.clone()],
                },
            )
            .add_followees(native_action_ids::MOTION, Followees { followees: vec![] })
            .set_dissolve_delay(15778801),
        )
        .add_neuron(
            NeuronBuilder::new(
                followee_neuron_id.clone(),
                E8,
                NeuronPermission::all(&followee_principal_id),
            )
            .set_dissolve_delay(15778801),
        )
        .add_neuron(
            NeuronBuilder::new(
                proposer_neuron_id.clone(),
                E8,
                NeuronPermission::all(&proposer_principal_id),
            )
            .set_dissolve_delay(15778801),
        )
        .create();

    // Submit a motion proposal
    let (proposal_id, _) = canister_fixture
        .make_default_proposal(
            &proposer_neuron_id,
            Motion {
                motion_text: "Test self following".to_string(),
            },
            proposer_principal_id,
        )
        .unwrap();

    // Vote with the followee neuron, this should result in the follower neuron voting even though
    // it has an empty followees vector on this Action
    assert!(canister_fixture
        .vote(
            &followee_neuron_id,
            proposal_id,
            Vote::Yes,
            followee_principal_id
        )
        .is_ok());

    let proposal_data = canister_fixture.get_proposal_or_panic(proposal_id);
    let follower_ballot = proposal_data
        .ballots
        .get(&follower_neuron_id.to_string())
        .expect("Expected the follower neuron to have a ballot");
    // This assert fails before NNS1-2148
    assert_eq!(follower_ballot.vote, Vote::Yes as i32);
}

/// Tests that `ManageNeuron::DisburseMaturity` disburses the correct given different maturity
/// modulation values
#[tokio::test]
async fn test_disburse_maturity_with_modulation_succeeds() {
    assert_disburse_maturity_with_modulation_disburses_correctly(E8, 200, 102_000_000).await;
    assert_disburse_maturity_with_modulation_disburses_correctly(E8, 0, 100_000_000).await;
    assert_disburse_maturity_with_modulation_disburses_correctly(E8, -300, 97_000_000).await;
}

/// Assert that the expected disbursement happens given an initial amount of maturity (of a neuron)
/// and a maturity modulation value.
async fn assert_disburse_maturity_with_modulation_disburses_correctly(
    initial_maturity_e8s: u64,
    maturity_modulation_basis_points: i32,
    expected_amount_disbursed_e8s: u64,
) {
    let user_principal = PrincipalId::new_user_test_id(1000);
    let neuron_id = neuron_id(user_principal, /*memo*/ 0);

    // Set up the test environment with a single dissolved neuron
    let mut canister_fixture = GovernanceCanisterFixtureBuilder::new()
        .add_neuron(
            NeuronBuilder::new(
                neuron_id.clone(),
                E8,
                NeuronPermission::all(&user_principal),
            )
            .set_maturity(initial_maturity_e8s),
        )
        .set_maturity_modulation(maturity_modulation_basis_points)
        .create();

    // This is supposed to cause Governance to poll CMC for the maturity modulation.
    canister_fixture.heartbeat();

    // Get the Neuron and assert its maturity is set as expected
    let neuron = canister_fixture.get_neuron(&neuron_id);
    let neuron_maturity_before_disbursal = neuron.maturity_e8s_equivalent;
    assert_eq!(neuron_maturity_before_disbursal, E8);

    let destination_account = icrc_ledger_types::icrc1::account::Account {
        owner: user_principal.into(),
        subaccount: None,
    };

    let account_balance_before_disbursal =
        canister_fixture.get_account_balance(&destination_account, TargetLedger::Sns);
    assert_eq!(account_balance_before_disbursal, 0);

    // Disburse the neuron to self and assert that it succeeds
    let manage_neuron_response = canister_fixture.manage_neuron(
        &neuron_id,
        manage_neuron::Command::DisburseMaturity(DisburseMaturity {
            percentage_to_disburse: 100,
            to_account: Some(AccountProto {
                owner: Some(user_principal),
                subaccount: None,
            }),
        }),
        user_principal,
    );
    let disburse_maturity_response = match manage_neuron_response.command.unwrap() {
        CommandResponse::DisburseMaturity(response) => response,
        CommandResponse::Error(error) => {
            panic!("Unexpected error when disbursing maturity: {}", error)
        }
        _ => panic!("Unexpected command response when disbursing maturity"),
    };

    let DisburseMaturityResponse {
        amount_disbursed_e8s,
        amount_deducted_e8s,
    } = disburse_maturity_response;
    assert_eq!(amount_deducted_e8s.unwrap(), amount_disbursed_e8s);
    assert_eq!(amount_deducted_e8s.unwrap(), initial_maturity_e8s);

    // Assert that the neuron's maturity is now zero
    let neuron = canister_fixture.get_neuron(&neuron_id);
    assert_eq!(neuron.maturity_e8s_equivalent, 0);

    canister_fixture.advance_time_by(7 * ONE_DAY_SECONDS + 1);
    canister_fixture.heartbeat();

    // Assert that the Neuron owner's account balance has increased the expected amount
    let account_balance_after_disbursal =
        canister_fixture.get_account_balance(&destination_account, TargetLedger::Sns);

    assert_eq!(
        account_balance_after_disbursal,
        expected_amount_disbursed_e8s
    );
}

/// Tests that `ManageNeuron::DisburseMaturity` applies maturity modulation at the
/// end of the time window.
#[tokio::test]
async fn test_disburse_maturity_applied_modulation_at_end_of_window() {
    let initial_maturity_modulation_basis_points = 100;
    let time_of_disbursement_maturity_modulation_basis_points = 200;
    let initial_maturity_e8s = E8;

    let user_principal = PrincipalId::new_user_test_id(1000);
    let neuron_id = neuron_id(user_principal, /*memo*/ 0);

    // Set up the test environment with a single dissolved neuron
    let mut canister_fixture = GovernanceCanisterFixtureBuilder::new()
        .add_neuron(
            NeuronBuilder::new(
                neuron_id.clone(),
                E8,
                NeuronPermission::all(&user_principal),
            )
            .set_maturity(initial_maturity_e8s),
        )
        // Set an initial maturity modulation that will be different then the final maturity modulation
        .set_maturity_modulation(initial_maturity_modulation_basis_points)
        .create();

    // This is supposed to cause Governance to poll CMC for the maturity modulation.
    canister_fixture.heartbeat();

    let current_basis_points = canister_fixture
        .get_maturity_modulation()
        .maturity_modulation
        .unwrap()
        .current_basis_points
        .unwrap();

    assert_eq!(
        current_basis_points,
        initial_maturity_modulation_basis_points
    );

    // Get the Neuron and assert its maturity is set as expected
    let neuron = canister_fixture.get_neuron(&neuron_id);
    let neuron_maturity_before_disbursal = neuron.maturity_e8s_equivalent;
    assert_eq!(neuron_maturity_before_disbursal, E8);

    let destination_account = icrc_ledger_types::icrc1::account::Account {
        owner: user_principal.into(),
        subaccount: None,
    };

    let account_balance_before_disbursal =
        canister_fixture.get_account_balance(&destination_account, TargetLedger::Sns);
    assert_eq!(account_balance_before_disbursal, 0);

    // Disburse the neuron to self and assert that it succeeds
    let manage_neuron_response = canister_fixture.manage_neuron(
        &neuron_id,
        manage_neuron::Command::DisburseMaturity(DisburseMaturity {
            percentage_to_disburse: 100,
            to_account: Some(AccountProto {
                owner: Some(user_principal),
                subaccount: None,
            }),
        }),
        user_principal,
    );

    let disburse_maturity_response = match manage_neuron_response.command.unwrap() {
        CommandResponse::DisburseMaturity(response) => response,
        CommandResponse::Error(error) => {
            panic!("Unexpected error when disbursing maturity: {}", error)
        }
        _ => panic!("Unexpected command response when disbursing maturity"),
    };

    let DisburseMaturityResponse {
        amount_disbursed_e8s,
        amount_deducted_e8s,
    } = disburse_maturity_response;
    assert_eq!(amount_disbursed_e8s, amount_deducted_e8s.unwrap());
    assert_eq!(amount_deducted_e8s.unwrap(), initial_maturity_e8s);

    // Assert that the neuron's maturity is now zero
    let neuron = canister_fixture.get_neuron(&neuron_id);
    assert_eq!(neuron.maturity_e8s_equivalent, 0);

    // Update the maturity_modulation that the CMC will serve before the disbursement
    *canister_fixture
        .cmc_fixture
        .maturity_modulation
        .try_lock()
        .unwrap() = time_of_disbursement_maturity_modulation_basis_points;

    // Advancing time and triggering a heartbeat should force a query of the new modulation
    canister_fixture.advance_time_by(2 * ONE_DAY_SECONDS);
    canister_fixture.heartbeat();
    let current_basis_points = canister_fixture
        .get_maturity_modulation()
        .maturity_modulation
        .unwrap()
        .current_basis_points
        .unwrap();

    assert_eq!(
        current_basis_points,
        time_of_disbursement_maturity_modulation_basis_points
    );
    // Assert that the Neuron owner's account balance has not changed
    let account_balance_before_disbursal =
        canister_fixture.get_account_balance(&destination_account, TargetLedger::Sns);

    assert_eq!(account_balance_before_disbursal, 0);

    // Advancing time and triggering a heartbeat should trigger the final disbursal
    canister_fixture.advance_time_by(5 * ONE_DAY_SECONDS + 1);
    canister_fixture.heartbeat();

    // Assert that the Neuron owner's account balance has increased the expected amount
    let account_balance_after_disbursal =
        canister_fixture.get_account_balance(&destination_account, TargetLedger::Sns);

    assert_eq!(account_balance_after_disbursal, 102_000_000);
}

#[test]
fn test_add_maturity() {
    let (mut canister_fixture, _user_principal, neuron_id) =
        GovernanceCanisterFixtureBuilder::new().create_with_test_neuron();

    const MATURITY_TO_ADD: u64 = 100_000;

    let neuron_original = canister_fixture.get_neuron(&neuron_id);
    let add_maturity_result = canister_fixture
        .governance
        .add_maturity(AddMaturityRequest {
            id: Some(neuron_id.clone()),
            amount_e8s: Some(MATURITY_TO_ADD),
        });
    let neuron_new = canister_fixture.get_neuron(&neuron_id);

    assert_eq!(
        neuron_original.maturity_e8s_equivalent + MATURITY_TO_ADD,
        neuron_new.maturity_e8s_equivalent
    );
    assert_eq!(
        add_maturity_result.new_maturity_e8s,
        Some(neuron_new.maturity_e8s_equivalent)
    );
}

#[tokio::test]
async fn test_mint_tokens() {
    let mut canister_fixture = GovernanceCanisterFixtureBuilder::new().create();
    let user_principal = PrincipalId::new_user_test_id(1000);
    const E8S_TO_MINT: u64 = 100_000;

    let account = AccountProto {
        owner: Some(user_principal),
        subaccount: None,
    };

    let balance_original = canister_fixture
        .get_account_balance(&(account.clone().try_into().unwrap()), TargetLedger::Sns);
    let MintTokensResponse {} = canister_fixture
        .governance
        .mint_tokens(MintTokensRequest {
            recipient: Some(account.clone()),
            amount_e8s: Some(E8S_TO_MINT),
        })
        .await;
    let balance_new = canister_fixture
        .get_account_balance(&(account.clone().try_into().unwrap()), TargetLedger::Sns);

    assert_eq!(balance_original + E8S_TO_MINT, balance_new);
}

#[tokio::test]
async fn test_process_proposals_tallies_votes_for_proposals_where_voting_is_possible() {
    let mut canister_fixture = GovernanceCanisterFixtureBuilder::new()
        .set_start_time(10)
        .create();

    canister_fixture.governance.proto.proposals.insert(
        10,
        ProposalData {
            decided_timestamp_seconds: 9, // proposal is decided
            action: 1,
            wait_for_quiet_state: Some(WaitForQuietState {
                current_deadline_timestamp_seconds: 20, // voting period is still open
            }),
            proposal: Some(Proposal {
                action: Some(Action::Motion(Motion {
                    motion_text: "Test".to_string(),
                })),
                ..Proposal::default()
            }),
            latest_tally: None,
            ..ProposalData::default()
        },
    );
    canister_fixture.governance.process_proposals();
    let proposal = canister_fixture
        .governance
        .proto
        .proposals
        .get(&10)
        .unwrap();

    assert!(proposal.latest_tally.is_some());
}

#[tokio::test]
async fn test_process_proposals_doesnt_tally_votes_for_proposals_where_voting_is_impossible() {
    let mut canister_fixture = GovernanceCanisterFixtureBuilder::new()
        .set_start_time(30)
        .create();

    canister_fixture.governance.proto.proposals.insert(
        10,
        ProposalData {
            decided_timestamp_seconds: 9, // proposal is decided
            action: 1,
            wait_for_quiet_state: Some(WaitForQuietState {
                current_deadline_timestamp_seconds: 20, // voting period is still open
            }),
            proposal: Some(Proposal {
                action: Some(Action::Motion(Motion {
                    motion_text: "Test".to_string(),
                })),
                ..Proposal::default()
            }),
            latest_tally: None,
            ..ProposalData::default()
        },
    );
    canister_fixture.governance.process_proposals();
    let proposal = canister_fixture
        .governance
        .proto
        .proposals
        .get(&10)
        .unwrap();

    assert_eq!(proposal.latest_tally, None);
}

#[test]
fn test_motion_has_normal_voting_thresholds() {
    let user_principal = PrincipalId::new_user_test_id(1000);
    let neuron_id_2 = neuron_id(user_principal, /*memo*/ 42);

    let (mut canister_fixture, user_principal, neuron_id) = GovernanceCanisterFixtureBuilder::new()
        .add_neuron(
            NeuronBuilder::new(
                neuron_id_2.clone(),
                E8 * 1000,
                NeuronPermission::new(&user_principal, vec![]),
            )
            .set_dissolve_delay(15778801),
        )
        // Create with a test neuron so that the proposal doesn't instantly pass
        .create_with_test_neuron();

    let proposal = Motion {
        motion_text: "Do stuff".to_string(),
    };

    // Create the proposal with neuron_id so it doesn't instantly pass
    let (_, proposal_data) = canister_fixture
        .make_default_proposal(&neuron_id, proposal, user_principal)
        .unwrap();

    assert_eq!(
        proposal_data.decided_timestamp_seconds, 0,
        "proposal should not have been decided yet. ballots: {:?}",
        proposal_data.ballots
    );
    assert_eq!(
        proposal_data.minimum_yes_proportion_of_exercised.unwrap(),
        NervousSystemParameters::DEFAULT_MINIMUM_YES_PROPORTION_OF_EXERCISED_VOTING_POWER
    );
    assert_eq!(
        proposal_data.minimum_yes_proportion_of_total.unwrap(),
        NervousSystemParameters::DEFAULT_MINIMUM_YES_PROPORTION_OF_TOTAL_VOTING_POWER
    );
}

#[test]
fn test_deregister_dapp_has_higher_voting_thresholds() {
    let user_principal = PrincipalId::new_user_test_id(1000);
    let neuron_id_2 = neuron_id(user_principal, /*memo*/ 42);

    let (mut canister_fixture, user_principal, neuron_id) = GovernanceCanisterFixtureBuilder::new()
        .add_neuron(
            NeuronBuilder::new(
                neuron_id_2.clone(),
                E8 * 1000,
                NeuronPermission::new(&user_principal, vec![]),
            )
            .set_dissolve_delay(15778801),
        )
        // Create with a test neuron so that the proposal doesn't instantly pass
        .create_with_test_neuron();

    let proposal = DeregisterDappCanisters {
        canister_ids: vec![user_principal],
        new_controllers: vec![user_principal],
    };

    // Create the proposal with neuron_id so it doesn't instantly pass
    let (_, proposal_data) = canister_fixture
        .make_default_proposal(&neuron_id, proposal, user_principal)
        .unwrap();

    assert_eq!(
        proposal_data.decided_timestamp_seconds, 0,
        "proposal should not have been decided yet. ballots: {:?}",
        proposal_data.ballots
    );
    assert!(
        proposal_data.minimum_yes_proportion_of_exercised.unwrap()
            > NervousSystemParameters::DEFAULT_MINIMUM_YES_PROPORTION_OF_EXERCISED_VOTING_POWER
    );
    assert_eq!(
        proposal_data.minimum_yes_proportion_of_exercised.unwrap(),
        Percentage::from_basis_points(6700)
    );
    assert!(
        proposal_data.minimum_yes_proportion_of_total.unwrap()
            > NervousSystemParameters::DEFAULT_MINIMUM_YES_PROPORTION_OF_TOTAL_VOTING_POWER
    );
    assert_eq!(
        proposal_data.minimum_yes_proportion_of_total.unwrap(),
        Percentage::from_basis_points(2000)
    );
}
