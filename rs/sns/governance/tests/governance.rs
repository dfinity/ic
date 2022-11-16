use crate::fixtures::{neuron_id, GovernanceCanisterFixtureBuilder, NeuronBuilder, TargetLedger};
use ic_base_types::PrincipalId;
use ic_nervous_system_common::E8;
use ic_sns_governance::neuron::NeuronState;
use ic_sns_governance::{
    pb::v1::{
        governance_error::ErrorType,
        manage_neuron,
        manage_neuron::{configure::Operation, Configure, Disburse, IncreaseDissolveDelay},
        manage_neuron_response::Command as CommandResponse,
        Account, NeuronPermission,
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

    // Assert tha the neuron state is NotDissolving
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
