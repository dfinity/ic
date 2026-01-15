use crate::{
    governance::{Governance, MockEnvironment, ONE_MONTH_SECONDS},
    pb::v1::{
        Governance as GovernanceProto, NeuronType,
        governance::{SeedAccounts, seed_accounts::SeedAccount},
    },
    seed_accounts::{AccountState, SEED_NEURON_DISTRIBUTION_COUNT},
};
use candid::Encode;
use ic_base_types::PrincipalId;
use ic_nervous_system_common::{E8, cmc::MockCMC, ledger::MockIcpLedger};
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_governance_api as api;
use icp_ledger::Subaccount;
use maplit::btreemap;
use std::time::{SystemTime, UNIX_EPOCH};

fn create_mock_environment(now_timestamp_seconds: Option<u64>) -> MockEnvironment {
    let mut environment = MockEnvironment::new();
    let now_timestamp_seconds = now_timestamp_seconds.unwrap_or(now_seconds());

    environment.expect_now().return_const(now_timestamp_seconds);
    environment
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn neuron(id: u64, controller: PrincipalId, cached_neuron_stake_e8s: u64) -> Neuron {
    NeuronBuilder::new_for_test(
        id,
        DissolveStateAndAge::DissolvingOrDissolved {
            when_dissolved_timestamp_seconds: 0,
        },
    )
    .with_controller(controller)
    .with_cached_neuron_stake_e8s(cached_neuron_stake_e8s)
    .build()
}

#[test]
fn test_can_tag_seed_neurons_handles_corrupted_state() {
    // Setup
    let mut governance = Governance::new(
        Default::default(),
        Arc::new(create_mock_environment(None)),
        Arc::<MockIcpLedger>::default(),
        Arc::<MockCMC>::default(),
        Box::new(MockRandomness::new()),
    );

    // Corrupt the state
    governance.heap_data.seed_accounts = None;

    // Execute / verify
    assert!(!governance.can_tag_seed_neurons());
}

#[test]
fn test_can_tag_seed_neurons_transitions() {
    fn start_seed_tagging(gov: &mut Governance) {
        gov.heap_data
            .seed_accounts
            .as_mut()
            .unwrap()
            .accounts
            .iter_mut()
            .find(|seed_account| {
                seed_account.tag_start_timestamp_seconds.is_none()
                    && seed_account.tag_end_timestamp_seconds.is_none()
            })
            .map(|seed_account| seed_account.tag_start_timestamp_seconds = Some(0))
            .unwrap()
    }

    fn finish_seed_tagging(gov: &mut Governance) {
        gov.heap_data
            .seed_accounts
            .as_mut()
            .unwrap()
            .accounts
            .iter_mut()
            .find(|seed_account| {
                seed_account.tag_start_timestamp_seconds.is_some()
                    && seed_account.tag_end_timestamp_seconds.is_none()
            })
            .map(|seed_account| seed_account.tag_end_timestamp_seconds = Some(0))
            .unwrap()
    }

    fn fail_seed_tagging(gov: &mut Governance) {
        gov.heap_data
            .seed_accounts
            .as_mut()
            .unwrap()
            .accounts
            .iter_mut()
            .find(|seed_account| {
                seed_account.tag_start_timestamp_seconds.is_some()
                    && seed_account.tag_end_timestamp_seconds.is_none()
            })
            .map(|seed_account| seed_account.tag_start_timestamp_seconds = None)
            .unwrap()
    }

    // Setup
    let mut governance = Governance::new(
        Default::default(),
        Arc::new(create_mock_environment(None)),
        Arc::<MockIcpLedger>::default(),
        Arc::<MockCMC>::default(),
        Box::new(MockRandomness::new()),
    );

    // Execute / verify

    // Assert that on a fresh install, the tagging can start
    assert!(governance.can_tag_seed_neurons());

    // Once a seed tagging starts, it returns false
    start_seed_tagging(&mut governance);
    assert!(!governance.can_tag_seed_neurons());

    // Once a seed tagging finishes, it returns true again
    finish_seed_tagging(&mut governance);
    assert!(governance.can_tag_seed_neurons());

    // If a seed tag fails, it should return true
    start_seed_tagging(&mut governance);
    assert!(!governance.can_tag_seed_neurons());
    fail_seed_tagging(&mut governance);
    assert!(governance.can_tag_seed_neurons());
}

#[test]
fn test_can_tag_seed_neurons_exits_early_if_data_is_processed() {
    // Setup
    let mut governance = Governance::new(
        Default::default(),
        Arc::new(create_mock_environment(None)),
        Arc::<MockIcpLedger>::default(),
        Arc::<MockCMC>::default(),
        Box::new(MockRandomness::new()),
    );

    // Execute / Verify

    // With an unprocessed list, can_tag_seed_neurons should return true
    assert!(governance.can_tag_seed_neurons());

    // Simulate the last SeedAccount being processed. To save iterating the list every
    // heartbeat, this function should return false early
    if let Some(seed_account) = governance
        .heap_data
        .seed_accounts
        .as_mut()
        .unwrap()
        .accounts
        .last_mut()
    {
        seed_account.tag_start_timestamp_seconds = Some(0);
        seed_account.tag_end_timestamp_seconds = Some(0);
    };

    assert!(!governance.can_tag_seed_neurons());
}

#[tokio::test]
async fn test_tag_seed_neurons_happy() {
    // Setup

    let seed_neuron_controller = PrincipalId::new_user_test_id(1);
    let non_seed_neuron_controller = PrincipalId::new_user_test_id(2);
    let account_id = String::from("AccountId1");
    let now_timestamp_seconds = now_seconds();

    // Create the mock environment that will return mocked data from the Genesis token canister
    let mut environment = create_mock_environment(Some(now_timestamp_seconds));
    environment
        .expect_call_canister_method()
        .return_const(Ok(Encode!(&Ok::<AccountState, String>(AccountState {
            neuron_ids: vec![NeuronId { id: 1 }],
            authenticated_principal_id: Some(seed_neuron_controller),
            icpts: 10,
            ..Default::default()
        }))
        .unwrap()));

    let mut governance = Governance::new(
        api::Governance {
            genesis_timestamp_seconds: now_timestamp_seconds - ONE_MONTH_SECONDS,
            ..Default::default()
        },
        Arc::new(environment),
        Arc::<MockIcpLedger>::default(),
        Arc::<MockCMC>::default(),
        Box::new(MockRandomness::new()),
    );

    governance
        .add_neuron(1, neuron(1, seed_neuron_controller, 10 * E8), false)
        .unwrap();
    governance
        .add_neuron(2, neuron(2, seed_neuron_controller, E8), false)
        .unwrap();
    governance
        .add_neuron(3, neuron(3, non_seed_neuron_controller, E8), false)
        .unwrap();

    let expected_seed_account = SeedAccount {
        account_id: account_id.clone(),
        neuron_type: NeuronType::Seed as i32,
        ..Default::default()
    };
    governance.heap_data.seed_accounts = Some(SeedAccounts {
        accounts: vec![expected_seed_account.clone()],
    });

    // Execute

    assert!(governance.can_tag_seed_neurons());
    governance.tag_seed_neurons().await;

    // Verify
    assert_eq!(
        governance.heap_data.seed_accounts,
        Some(SeedAccounts {
            accounts: vec![SeedAccount {
                // Verify the fields that should not have changed
                account_id: expected_seed_account.account_id,
                neuron_type: expected_seed_account.neuron_type,

                // Verify the fields that should have changed
                tag_start_timestamp_seconds: Some(now_timestamp_seconds),
                tag_end_timestamp_seconds: Some(now_timestamp_seconds),
                error_count: 0,
            }],
        }),
    );

    assert_eq!(
        governance
            .get_full_neuron(&NeuronId { id: 1 }, &seed_neuron_controller)
            .unwrap()
            .neuron_type,
        Some(NeuronType::Seed as i32),
    );

    assert_eq!(
        governance
            .get_full_neuron(&NeuronId { id: 2 }, &seed_neuron_controller)
            .unwrap()
            .neuron_type,
        None,
    );

    assert_eq!(
        governance
            .get_full_neuron(&NeuronId { id: 3 }, &non_seed_neuron_controller)
            .unwrap()
            .neuron_type,
        None,
    );
}

#[tokio::test]
async fn test_tag_neuron_sad() {
    // Setup

    let seed_neuron_controller = PrincipalId::new_user_test_id(1);
    let non_seed_neuron_controller = PrincipalId::new_user_test_id(2);
    let account_id = String::from("AccountId1");
    let now_timestamp_seconds = now_seconds();

    // Create the mock environment that will return the mocked error from the replica
    let mut environment = create_mock_environment(Some(now_timestamp_seconds));
    environment
        .expect_call_canister_method()
        .return_const(Err((Some(1), "Error from the replica".to_string())));

    let mut governance = Governance::new(
        api::Governance {
            genesis_timestamp_seconds: now_timestamp_seconds - ONE_MONTH_SECONDS,
            ..Default::default()
        },
        Arc::new(environment),
        Arc::<MockIcpLedger>::default(),
        Arc::<MockCMC>::default(),
        Box::new(MockRandomness::new()),
    );

    governance
        .add_neuron(1, neuron(1, seed_neuron_controller, 10 * E8), false)
        .unwrap();
    governance
        .add_neuron(2, neuron(2, seed_neuron_controller, E8), false)
        .unwrap();
    governance
        .add_neuron(3, neuron(3, non_seed_neuron_controller, E8), false)
        .unwrap();

    let expected_seed_account = SeedAccount {
        account_id: account_id.clone(),
        neuron_type: NeuronType::Seed as i32,
        ..Default::default()
    };
    governance.heap_data.seed_accounts = Some(SeedAccounts {
        accounts: vec![expected_seed_account.clone()],
    });

    // Execute

    assert!(governance.can_tag_seed_neurons());
    governance.tag_seed_neurons().await;

    // Verify
    assert_eq!(
        governance.heap_data.seed_accounts,
        Some(SeedAccounts {
            accounts: vec![SeedAccount {
                // Verify the fields that should not have changed
                account_id: expected_seed_account.account_id,
                neuron_type: expected_seed_account.neuron_type,

                // Verify the fields that should have changed
                tag_start_timestamp_seconds: None,
                tag_end_timestamp_seconds: None,
                error_count: 1,
            }],
        }),
    );

    assert_eq!(
        governance
            .get_full_neuron(&NeuronId { id: 1 }, &seed_neuron_controller)
            .unwrap()
            .neuron_type,
        None,
    );

    assert_eq!(
        governance
            .get_full_neuron(&NeuronId { id: 2 }, &seed_neuron_controller)
            .unwrap()
            .neuron_type,
        None,
    );

    assert_eq!(
        governance
            .get_full_neuron(&NeuronId { id: 3 }, &non_seed_neuron_controller)
            .unwrap()
            .neuron_type,
        None,
    );
}

#[tokio::test]
async fn test_tag_seed_neurons_handles_neuron_splits() {
    // Setup

    let split_seed_neuron_controller = PrincipalId::new_user_test_id(1);
    let now_timestamp_seconds = now_seconds();

    // Create the mock environment that will return mocked data from the Genesis token canister
    let mut environment = create_mock_environment(Some(now_timestamp_seconds));
    environment
        .expect_call_canister_method()
        .return_const(Ok(Encode!(&Ok::<AccountState, String>(AccountState {
            neuron_ids: vec![NeuronId { id: 1 }],
            authenticated_principal_id: Some(split_seed_neuron_controller),
            // Set the vested `icpts` higher than whats present in the neurons in Governance. This
            // indicates a split has occurred
            icpts: 20,
            ..Default::default()
        }))
        .unwrap()));

    let mut governance = Governance::new(
        api::Governance {
            // This indicates that no stake should have been vested and all
            // funds should be in the neurons
            genesis_timestamp_seconds: now_timestamp_seconds,
            ..Default::default()
        },
        Arc::new(environment),
        Arc::<MockIcpLedger>::default(),
        Arc::<MockCMC>::default(),
        Box::new(MockRandomness::new()),
    );

    governance
        .add_neuron(1, neuron(1, split_seed_neuron_controller, 10 * E8), false)
        .unwrap();
    governance
        .add_neuron(2, neuron(2, split_seed_neuron_controller, E8), false)
        .unwrap();

    // Execute

    assert!(governance.can_tag_seed_neurons());
    governance.tag_seed_neurons().await;

    // Verify

    // The Neuron in the GTC response should be tagged as seed.
    assert_eq!(
        governance
            .get_full_neuron(&NeuronId { id: 1 }, &split_seed_neuron_controller)
            .unwrap()
            .neuron_type,
        Some(NeuronType::Seed as i32),
    );

    // Since not all funds are available in the Neurons identified by the GTC, all other
    // neurons controlled by `split_seed_neuron_controller` should be tagged as well.
    assert_eq!(
        governance
            .get_full_neuron(&NeuronId { id: 2 }, &split_seed_neuron_controller)
            .unwrap()
            .neuron_type,
        Some(NeuronType::Seed as i32),
    );
}

#[tokio::test]
async fn test_tag_seed_neurons_doesnt_over_tag_seed_neurons() {
    // Setup

    let split_seed_neuron_controller = PrincipalId::new_user_test_id(1);
    // set an arbitrary genesis timestamp
    let genesis_timestamp_seconds = 1;
    // set the time of the current test to some time in the future
    let now_timestamp_seconds = genesis_timestamp_seconds + (24 * ONE_MONTH_SECONDS);

    // Create the mock environment that will return mocked data from the Genesis token canister
    let mut environment = create_mock_environment(Some(now_timestamp_seconds));
    environment
        .expect_call_canister_method()
        .return_const(Ok(Encode!(&Ok::<AccountState, String>(AccountState {
            neuron_ids: vec![NeuronId { id: 1 }],
            authenticated_principal_id: Some(split_seed_neuron_controller),
            // Set the vested `icpts` higher than whats present in the neurons in Governace under the
            // assumption that the neurons would have disbursed vested ICP
            icpts: 20,
            ..Default::default()
        }))
        .unwrap()));

    let mut governance = Governance::new(
        api::Governance {
            genesis_timestamp_seconds,
            ..Default::default()
        },
        Arc::new(environment),
        Arc::<MockIcpLedger>::default(),
        Arc::<MockCMC>::default(),
        Box::new(MockRandomness::new()),
    );
    governance
        .add_neuron(1, neuron(1, split_seed_neuron_controller, 10 * E8), false)
        .unwrap();
    governance
        .add_neuron(2, neuron(2, split_seed_neuron_controller, E8), false)
        .unwrap();

    // Execute

    assert!(governance.can_tag_seed_neurons());
    governance.tag_seed_neurons().await;

    // Verify

    // The Neuron in the GTC response should be tagged as seed.
    assert_eq!(
        governance
            .get_full_neuron(&NeuronId { id: 1 }, &split_seed_neuron_controller)
            .unwrap()
            .neuron_type,
        Some(NeuronType::Seed as i32),
    );

    // Since the amount of ICP missing from the total stake is within expected values,
    // other neurons controlled by the principal should not be tagged.
    assert_eq!(
        governance
            .get_full_neuron(&NeuronId { id: 2 }, &split_seed_neuron_controller)
            .unwrap()
            .neuron_type,
        None,
    );
}

#[test]
fn test_calculate_genesis_account_expected_stake_e8s() {
    let neuron_distribution_icp_e8s = 3900000 * E8;
    let monthly_vested_icp_e8s =
        neuron_distribution_icp_e8s as f64 / SEED_NEURON_DISTRIBUTION_COUNT;
    // Set the genesis_timestamp_seconds to something easy to use in tests. 0 is not allowed
    let genesis_timestamp_seconds = 1;

    let governance = Governance::new(
        api::Governance {
            genesis_timestamp_seconds,
            ..Default::default()
        },
        Arc::new(create_mock_environment(None)),
        Arc::<MockIcpLedger>::default(),
        Arc::<MockCMC>::default(),
        Box::new(MockRandomness::new()),
    );

    // At genesis_timestamp_seconds, expected stake e8s should
    // be total - 1/49th of neuron_distribution_icp_e8s, since the 0th neuron has
    // dissolve delay equal to zero.
    let now_timestamp_seconds = genesis_timestamp_seconds;
    assert_eq!(
        neuron_distribution_icp_e8s - monthly_vested_icp_e8s as u64,
        governance.calculate_genesis_account_expected_stake_e8s(
            neuron_distribution_icp_e8s,
            now_timestamp_seconds
        )
    );

    // 1 second before genesis_timestamp_seconds + ONE_MONTH_SECONDS, expected stake e8s should
    // be total - 1/49th of neuron_distribution_icp_e8s, since the 0th neuron has
    // dissolve delay equal to zero.
    let now_timestamp_seconds = genesis_timestamp_seconds + ONE_MONTH_SECONDS - 1;
    assert_eq!(
        neuron_distribution_icp_e8s - monthly_vested_icp_e8s as u64,
        governance.calculate_genesis_account_expected_stake_e8s(
            neuron_distribution_icp_e8s,
            now_timestamp_seconds
        )
    );

    // At exactly genesis_timestamp_seconds + ONE_MONTH_SECONDS, expected e8s should
    // be total - 2/49th of neuron_distribution_icp_e8s, since the 0th neuron has
    // dissolve delay equal to zero and the second neuron just vested.
    let now_timestamp_seconds = genesis_timestamp_seconds + ONE_MONTH_SECONDS;
    assert_eq!(
        neuron_distribution_icp_e8s - 2 * (monthly_vested_icp_e8s as u64),
        governance.calculate_genesis_account_expected_stake_e8s(
            neuron_distribution_icp_e8s,
            now_timestamp_seconds
        )
    );

    // 1 second after genesis_timestamp_seconds + ONE_MONTH_SECONDS, expected e8s should
    // be total - 2/49th of neuron_distribution_icp_e8s, since the 0th neuron has
    // dissolve delay equal to zero and the second neuron just vested 1 second ago.
    let now_timestamp_seconds = genesis_timestamp_seconds + ONE_MONTH_SECONDS + 1;
    assert_eq!(
        neuron_distribution_icp_e8s - 2 * (monthly_vested_icp_e8s as u64),
        governance.calculate_genesis_account_expected_stake_e8s(
            neuron_distribution_icp_e8s,
            now_timestamp_seconds
        )
    );

    // Fast forward several months since genesis, there should be
    // total - (number of months + 1) / 49 of neuron_distribution_icp_e8s.
    let now_timestamp_seconds = genesis_timestamp_seconds + (20 * ONE_MONTH_SECONDS);
    assert_eq!(
        neuron_distribution_icp_e8s - (monthly_vested_icp_e8s * 21_f64) as u64,
        governance.calculate_genesis_account_expected_stake_e8s(
            neuron_distribution_icp_e8s,
            now_timestamp_seconds
        )
    );

    // Fast forward to more than 49 months since genesis. The amount should be 0 since all
    // funds have been distributed
    let now_timestamp_seconds = genesis_timestamp_seconds + (100 * ONE_MONTH_SECONDS);
    assert_eq!(
        0,
        governance.calculate_genesis_account_expected_stake_e8s(
            neuron_distribution_icp_e8s,
            now_timestamp_seconds
        )
    );
}
