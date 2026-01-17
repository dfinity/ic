use super::*;

use crate::{
    pb::v1::{NeuronState, Topic, governance_error::ErrorType},
    test_utils::{MockEnvironment, MockRandomness},
};

use ic_nervous_system_canisters::{cmc::MockCMC, ledger::MockIcpLedger};
use ic_nervous_system_common::ONE_YEAR_SECONDS;
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_governance_api::{
    Governance as GovernanceApi, NetworkEconomics, StakeNeuronRequest,
    manage_neuron::{SetFollowing, set_following::FolloweesForTopic},
};
use std::{cell::RefCell, sync::Arc};

static NOW_SECONDS: u64 = 1_234_567_890;
static CALLER: PrincipalId = PrincipalId::new_user_test_id(1);

thread_local! {
    static MOCK_ENVIRONMENT: Arc<MockEnvironment> = Arc::new(
        MockEnvironment::new(vec![], NOW_SECONDS));
    static TEST_GOVERNANCE: RefCell<Governance> = RefCell::new(Governance::new_uninitialized(
        MOCK_ENVIRONMENT.with(|env| env.clone()),
        Arc::new(MockIcpLedger::default()),
        Arc::new(MockCMC::default()),
        Box::new(MockRandomness::new()),
    ));
}

fn mock_ledger_for_success(amount_e8s: u64, fee_e8s: u64) -> MockIcpLedger {
    let mut mock_ledger = MockIcpLedger::new();
    mock_ledger
        .expect_icrc2_transfer_from()
        .withf(move |_from, to, actual_amount, actual_fee, _memo| {
            // Verify the target account is governance's
            to.owner == GOVERNANCE_CANISTER_ID.get().0
                && to.subaccount.is_some()
                && *actual_amount == amount_e8s
                && *actual_fee == fee_e8s
        })
        .times(1)
        .returning(|_, _, _, _, _| Ok(42));
    mock_ledger
}

fn mock_ledger_for_no_transfer() -> MockIcpLedger {
    let mut mock_ledger = MockIcpLedger::new();
    mock_ledger.expect_icrc2_transfer_from().never();
    mock_ledger
}

fn set_governance_for_test(mock_ledger: MockIcpLedger) {
    let governance = Governance::new(
        GovernanceApi {
            economics: Some(NetworkEconomics::with_default_values()),
            ..Default::default()
        },
        MOCK_ENVIRONMENT.with(|env| env.clone()),
        Arc::new(mock_ledger),
        Arc::new(MockCMC::default()),
        Box::new(MockRandomness::new()),
    );

    TEST_GOVERNANCE.set(governance);
}

#[tokio::test]
async fn test_stake_neuron_with_defaults() {
    let amount_e8s = 1_000_000_000;

    set_governance_for_test(mock_ledger_for_success(amount_e8s, 10_000));

    let request = StakeNeuronRequest {
        source_subaccount: None,
        amount_e8s: Some(amount_e8s),
        controller: None,
        followees: None,
        dissolve_delay_seconds: None,
        dissolving: None,
        auto_stake_maturity: None,
    };

    let result = Governance::stake_neuron(&TEST_GOVERNANCE, CALLER, request)
        .await
        .unwrap();

    let neuron_id = result.neuron_id.unwrap();

    TEST_GOVERNANCE.with_borrow(|governance| {
        let neuron = governance
            .neuron_store
            .with_neuron(&neuron_id, |n| n.clone())
            .unwrap();

        assert_eq!(neuron.controller(), CALLER);
        assert_eq!(neuron.cached_neuron_stake_e8s, amount_e8s);
        assert_eq!(
            neuron.dissolve_delay_seconds(NOW_SECONDS),
            INITIAL_NEURON_DISSOLVE_DELAY
        );
        assert_eq!(neuron.state(NOW_SECONDS), NeuronState::NotDissolving);
        // Verify auto_stake_maturity defaults to None (false)
        assert_eq!(neuron.auto_stake_maturity, None);
    });
}

#[tokio::test]
async fn test_stake_neuron_with_custom_values() {
    let amount_e8s = 1_000_000_000;
    let source_subaccount = Some(vec![1u8; 32]);
    let controller = PrincipalId::new_user_test_id(42);
    let dissolve_delay_seconds = ONE_YEAR_SECONDS * 2;

    set_governance_for_test(mock_ledger_for_success(amount_e8s, 10_000));

    let followees = SetFollowing {
        topic_following: Some(vec![
            FolloweesForTopic {
                topic: Some(Topic::Governance as i32),
                followees: Some(vec![NeuronId { id: 100 }, NeuronId { id: 101 }]),
            },
            FolloweesForTopic {
                topic: Some(Topic::NetworkEconomics as i32),
                followees: Some(vec![NeuronId { id: 200 }]),
            },
        ]),
    };

    let request = StakeNeuronRequest {
        source_subaccount,
        amount_e8s: Some(amount_e8s),
        controller: Some(controller),
        followees: Some(followees),
        dissolve_delay_seconds: Some(dissolve_delay_seconds),
        dissolving: Some(true),
        auto_stake_maturity: Some(true),
    };

    let result = Governance::stake_neuron(&TEST_GOVERNANCE, CALLER, request)
        .await
        .unwrap();

    let neuron_id = result.neuron_id.unwrap();

    TEST_GOVERNANCE.with_borrow(|governance| {
        let neuron = governance
            .neuron_store
            .with_neuron(&neuron_id, |n| n.clone())
            .unwrap();

        assert_eq!(neuron.controller(), controller);
        assert_eq!(neuron.cached_neuron_stake_e8s, amount_e8s);
        assert_eq!(
            neuron.dissolve_delay_seconds(NOW_SECONDS),
            dissolve_delay_seconds
        );
        // Verify the neuron is dissolving since dissolving: Some(true) was set
        assert_eq!(neuron.state(NOW_SECONDS), NeuronState::Dissolving);
        // Verify when_dissolved_timestamp_seconds is correctly calculated
        assert_eq!(
            neuron.dissolved_at_timestamp_seconds(),
            Some(NOW_SECONDS + dissolve_delay_seconds)
        );
        // Verify auto_stake_maturity is set since auto_stake_maturity: Some(true) was set
        assert_eq!(neuron.auto_stake_maturity, Some(true));
        assert_eq!(neuron.followees.len(), 2);
        assert_eq!(
            neuron
                .followees
                .get(&(Topic::Governance as i32))
                .unwrap()
                .followees,
            vec![NeuronId { id: 100 }, NeuronId { id: 101 }]
        );
        assert_eq!(
            neuron
                .followees
                .get(&(Topic::NetworkEconomics as i32))
                .unwrap()
                .followees,
            vec![NeuronId { id: 200 }]
        );
    });
}

#[tokio::test]
async fn test_stake_neuron_invalid_followees() {
    let amount_e8s = 1_000_000_000;

    set_governance_for_test(mock_ledger_for_no_transfer());

    // Create invalid followees with duplicate topics
    let followees = SetFollowing {
        topic_following: Some(vec![
            FolloweesForTopic {
                topic: Some(Topic::Governance as i32),
                followees: Some(vec![NeuronId { id: 100 }]),
            },
            FolloweesForTopic {
                topic: Some(Topic::Governance as i32),
                followees: Some(vec![NeuronId { id: 101 }]),
            },
        ]),
    };

    let request = StakeNeuronRequest {
        source_subaccount: None,
        amount_e8s: Some(amount_e8s),
        controller: None,
        followees: Some(followees),
        dissolve_delay_seconds: None,
        dissolving: None,
        auto_stake_maturity: None,
    };

    let result = Governance::stake_neuron(&TEST_GOVERNANCE, CALLER, request).await;

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert_eq!(error.error_type, ErrorType::InvalidCommand as i32);
}

#[tokio::test]
async fn test_stake_neuron_amount_below_minimum() {
    let amount_e8s = 100; // Below minimum stake

    set_governance_for_test(mock_ledger_for_no_transfer());

    let request = StakeNeuronRequest {
        source_subaccount: None,
        amount_e8s: Some(amount_e8s),
        controller: None,
        followees: None,
        dissolve_delay_seconds: None,
        dissolving: None,
        auto_stake_maturity: None,
    };

    let result = Governance::stake_neuron(&TEST_GOVERNANCE, CALLER, request).await;

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert_eq!(error.error_type, ErrorType::InsufficientFunds as i32);
}

#[tokio::test]
async fn test_stake_neuron_missing_amount() {
    set_governance_for_test(mock_ledger_for_no_transfer());

    let request = StakeNeuronRequest {
        source_subaccount: None,
        amount_e8s: None,
        controller: None,
        followees: None,
        dissolve_delay_seconds: None,
        dissolving: None,
        auto_stake_maturity: None,
    };

    let result = Governance::stake_neuron(&TEST_GOVERNANCE, CALLER, request).await;

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert_eq!(error.error_type, ErrorType::InvalidCommand as i32);
}

#[tokio::test]
async fn test_stake_neuron_invalid_source_subaccount() {
    let amount_e8s = 1_000_000_000;

    set_governance_for_test(mock_ledger_for_no_transfer());

    let request = StakeNeuronRequest {
        source_subaccount: Some(vec![1u8; 31]), // Invalid length (not 32 bytes)
        amount_e8s: Some(amount_e8s),
        controller: None,
        followees: None,
        dissolve_delay_seconds: None,
        dissolving: None,
        auto_stake_maturity: None,
    };

    let result = Governance::stake_neuron(&TEST_GOVERNANCE, CALLER, request).await;

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert_eq!(error.error_type, ErrorType::InvalidCommand as i32);
}
