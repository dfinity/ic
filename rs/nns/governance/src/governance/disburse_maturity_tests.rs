use super::*;

use crate::{
    governance::Environment,
    neuron::{DissolveStateAndAge, Neuron, NeuronBuilder},
    pb::v1::Subaccount,
    test_utils::{MockEnvironment, MockRandomness},
};

use futures::FutureExt;
use ic_nervous_system_canisters::{cmc::MockCMC, ledger::MockIcpLedger};
use ic_nervous_system_common::NervousSystemError;
use ic_nns_governance_api::Governance as GovernanceApi;
use icp_ledger::AccountIdentifier;
use mockall::Sequence;
use std::{collections::BTreeMap, sync::Arc};

static NOW_SECONDS: u64 = 1_234_567_890;
static CONTROLLER: PrincipalId = PrincipalId::new_user_test_id(1);
static DEFAULT_MATURITY_MODULATION_BASIS_POINTS: i32 = 100; // 1%

fn create_neuron_builder() -> NeuronBuilder {
    NeuronBuilder::new(
        NeuronId { id: 1 },
        icp_ledger::Subaccount([1u8; 32]),
        CONTROLLER,
        DissolveStateAndAge::DissolvingOrDissolved {
            when_dissolved_timestamp_seconds: NOW_SECONDS + ONE_DAY_SECONDS,
        },
        NOW_SECONDS,
    )
    .with_maturity_e8s_equivalent(100_000_000_000)
}

#[test]
fn test_initiate_maturity_disbursement_to_caller_successful() {
    let mut neuron_store = NeuronStore::new(BTreeMap::new());
    let neuron = create_neuron_builder().build();
    neuron_store.add_neuron(neuron).unwrap();

    assert_eq!(
        initiate_maturity_disbursement(
            &mut neuron_store,
            &CONTROLLER,
            &NeuronId { id: 1 },
            &DisburseMaturity {
                percentage_to_disburse: 50,
                to_account: None,
                to_account_identifier: None,
            },
            NOW_SECONDS,
        ),
        Ok(50_000_000_000)
    );
    let maturity_disbursements: Vec<_> = neuron_store
        .with_neuron(&NeuronId { id: 1 }, |neuron| {
            neuron.maturity_disbursements_in_progress().to_vec()
        })
        .unwrap();
    assert_eq!(maturity_disbursements.len(), 1);
    let maturity_disbursement = maturity_disbursements.first().unwrap();
    assert_eq!(
        *maturity_disbursement,
        MaturityDisbursement {
            amount_e8s: 50_000_000_000,
            destination: Some(Destination::AccountToDisburseTo(Account {
                owner: Some(CONTROLLER),
                subaccount: None,
            })),
            timestamp_of_disbursement_seconds: NOW_SECONDS,
            finalize_disbursement_timestamp_seconds: NOW_SECONDS + ONE_DAY_SECONDS * 7,
        }
    );
}

#[test]
fn test_initiate_maturity_disbursement_to_provided_account_successful() {
    let mut neuron_store = NeuronStore::new(BTreeMap::new());
    let neuron = create_neuron_builder().build();
    neuron_store.add_neuron(neuron).unwrap();

    assert_eq!(
        initiate_maturity_disbursement(
            &mut neuron_store,
            &CONTROLLER,
            &NeuronId { id: 1 },
            &DisburseMaturity {
                percentage_to_disburse: 50,
                to_account: Some(Account {
                    owner: Some(PrincipalId::new_user_test_id(2)),
                    subaccount: Some(Subaccount {
                        subaccount: vec![2u8; 32]
                    }),
                }),
                to_account_identifier: None,
            },
            NOW_SECONDS,
        ),
        Ok(50_000_000_000)
    );
    let maturity_disbursements: Vec<_> = neuron_store
        .with_neuron(&NeuronId { id: 1 }, |neuron| {
            neuron.maturity_disbursements_in_progress().to_vec()
        })
        .unwrap();
    assert_eq!(maturity_disbursements.len(), 1);
    let maturity_disbursement = maturity_disbursements.first().unwrap();
    assert_eq!(
        *maturity_disbursement,
        MaturityDisbursement {
            amount_e8s: 50_000_000_000,
            destination: Some(Destination::AccountToDisburseTo(Account {
                owner: Some(PrincipalId::new_user_test_id(2)),
                subaccount: Some(Subaccount {
                    subaccount: vec![2u8; 32]
                }),
            })),
            timestamp_of_disbursement_seconds: NOW_SECONDS,
            finalize_disbursement_timestamp_seconds: NOW_SECONDS + ONE_DAY_SECONDS * 7,
        }
    );
    // Since the correctness of the account identifier is outside the scope of governance, we simply
    // verify that the length is expected.
    assert_eq!(
        maturity_disbursement
            .destination
            .as_ref()
            .unwrap()
            .into_account_identifier_proto()
            .unwrap()
            .hash
            .len(),
        32,
    )
}

#[test]
fn test_initiate_maturity_disbursement_to_account_identifier_successful() {
    let mut neuron_store = NeuronStore::new(BTreeMap::new());
    let neuron = create_neuron_builder().build();
    neuron_store.add_neuron(neuron).unwrap();

    let account_identifier_proto: AccountIdentifierProto = AccountIdentifierProto {
        hash: [
            128, 112, 119, 233, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0,
        ]
        .to_vec(),
    };

    assert_eq!(
        initiate_maturity_disbursement(
            &mut neuron_store,
            &CONTROLLER,
            &NeuronId { id: 1 },
            &DisburseMaturity {
                percentage_to_disburse: 50,
                to_account: None,
                to_account_identifier: Some(account_identifier_proto.clone()),
            },
            NOW_SECONDS,
        ),
        Ok(50_000_000_000)
    );
    let maturity_disbursements: Vec<_> = neuron_store
        .with_neuron(&NeuronId { id: 1 }, |neuron| {
            neuron.maturity_disbursements_in_progress().to_vec()
        })
        .unwrap();
    assert_eq!(maturity_disbursements.len(), 1);
    let maturity_disbursement = maturity_disbursements.first().unwrap();
    assert_eq!(
        *maturity_disbursement,
        MaturityDisbursement {
            amount_e8s: 50_000_000_000,
            destination: Some(Destination::AccountIdentifierToDisburseTo(
                account_identifier_proto.clone()
            )),
            timestamp_of_disbursement_seconds: NOW_SECONDS,
            finalize_disbursement_timestamp_seconds: NOW_SECONDS + ONE_DAY_SECONDS * 7,
        }
    );
    assert_eq!(
        maturity_disbursement
            .destination
            .as_ref()
            .unwrap()
            .into_account_identifier_proto()
            .unwrap(),
        account_identifier_proto
    );
}

#[test]
fn test_initiate_maturity_disbursement_account_identifier_invalid() {
    let mut neuron_store = NeuronStore::new(BTreeMap::new());
    let neuron = create_neuron_builder().build();
    neuron_store.add_neuron(neuron).unwrap();

    assert_eq!(
        initiate_maturity_disbursement(
            &mut neuron_store,
            &CONTROLLER,
            &NeuronId { id: 1 },
            &DisburseMaturity {
                percentage_to_disburse: 50,
                to_account: None,
                to_account_identifier: Some(AccountIdentifierProto {
                    hash: vec![1u8; 1000],
                }),
            },
            NOW_SECONDS,
        ),
        Err(InitiateMaturityDisbursementError::InvalidDestination {
            reason: "Invalid account identifier".to_string()
        })
    );
}

#[test]
fn test_initiate_maturity_disbursement_both_account_and_account_identifier_invalid() {
    let mut neuron_store = NeuronStore::new(BTreeMap::new());
    let neuron = create_neuron_builder().build();
    neuron_store.add_neuron(neuron).unwrap();

    assert_eq!(
        initiate_maturity_disbursement(
            &mut neuron_store,
            &CONTROLLER,
            &NeuronId { id: 1 },
            &DisburseMaturity {
                percentage_to_disburse: 50,
                to_account: Some(Account {
                    owner: Some(PrincipalId::new_user_test_id(2)),
                    subaccount: Some(Subaccount {
                        subaccount: vec![2u8; 32]
                    }),
                }),
                to_account_identifier: Some(AccountIdentifierProto {
                    hash: vec![3u8; 32],
                }),
            },
            NOW_SECONDS,
        ),
        Err(InitiateMaturityDisbursementError::InvalidDestination {
            reason: "Cannot provide both to_account and to_account_identifier".to_string()
        })
    );
}

#[test]
fn test_initiate_maturity_disbursement_neuron_not_found() {
    let mut neuron_store = NeuronStore::new(BTreeMap::new());
    let neuron = create_neuron_builder().build();
    neuron_store.add_neuron(neuron).unwrap();

    assert_eq!(
        initiate_maturity_disbursement(
            &mut neuron_store,
            &CONTROLLER,
            &NeuronId { id: 2 },
            &DisburseMaturity {
                percentage_to_disburse: 50,
                to_account: None,
                to_account_identifier: None,
            },
            NOW_SECONDS,
        ),
        Err(InitiateMaturityDisbursementError::NeuronNotFound)
    );
}

#[test]
fn test_initiate_maturity_disbursement_invalid_percentage() {
    let mut neuron_store = NeuronStore::new(BTreeMap::new());
    let neuron = create_neuron_builder().build();
    neuron_store.add_neuron(neuron).unwrap();

    assert_eq!(
        initiate_maturity_disbursement(
            &mut neuron_store,
            &CONTROLLER,
            &NeuronId { id: 1 },
            &DisburseMaturity {
                percentage_to_disburse: 101,
                to_account: None,
                to_account_identifier: None,
            },
            NOW_SECONDS,
        ),
        Err(InitiateMaturityDisbursementError::InvalidPercentage)
    );
    assert_eq!(
        initiate_maturity_disbursement(
            &mut neuron_store,
            &CONTROLLER,
            &NeuronId { id: 1 },
            &DisburseMaturity {
                percentage_to_disburse: 0,
                to_account: None,
                to_account_identifier: None,
            },
            NOW_SECONDS,
        ),
        Err(InitiateMaturityDisbursementError::InvalidPercentage)
    );
}

#[test]
fn test_initiate_maturity_disbursement_neuron_invalid_destination() {
    let mut neuron_store = NeuronStore::new(BTreeMap::new());
    let neuron = create_neuron_builder().build();
    neuron_store.add_neuron(neuron).unwrap();

    assert_eq!(
        initiate_maturity_disbursement(
            &mut neuron_store,
            &CONTROLLER,
            &NeuronId { id: 1 },
            &DisburseMaturity {
                percentage_to_disburse: 50,
                to_account: Some(Account {
                    owner: None,
                    subaccount: None,
                }),
                to_account_identifier: None,
            },
            NOW_SECONDS,
        ),
        Err(InitiateMaturityDisbursementError::InvalidDestination {
            reason: "Owner is required".to_string()
        })
    );

    assert_eq!(
        initiate_maturity_disbursement(
            &mut neuron_store,
            &CONTROLLER,
            &NeuronId { id: 1 },
            &DisburseMaturity {
                percentage_to_disburse: 50,
                to_account: Some(Account {
                    owner: Some(PrincipalId::new_user_test_id(2)),
                    subaccount: Some(Subaccount {
                        subaccount: vec![1u8; 33],
                    }),
                }),
                to_account_identifier: None,
            },
            NOW_SECONDS,
        ),
        Err(InitiateMaturityDisbursementError::InvalidDestination {
            reason: "Subaccount must be 32 bytes".to_string()
        })
    );
}

#[test]
fn test_initiate_maturity_disbursement_neuron_spawning() {
    let mut neuron_store = NeuronStore::new(BTreeMap::new());
    let neuron = create_neuron_builder()
        .with_spawn_at_timestamp_seconds(NOW_SECONDS + ONE_DAY_SECONDS)
        .build();
    neuron_store.add_neuron(neuron).unwrap();

    assert_eq!(
        initiate_maturity_disbursement(
            &mut neuron_store,
            &CONTROLLER,
            &NeuronId { id: 1 },
            &DisburseMaturity {
                percentage_to_disburse: 50,
                to_account: None,
                to_account_identifier: None,
            },
            NOW_SECONDS,
        ),
        Err(InitiateMaturityDisbursementError::NeuronSpawning)
    );
}

#[test]
fn test_initiate_maturity_disbursement_not_controller() {
    let mut neuron_store = NeuronStore::new(BTreeMap::new());
    let neuron = create_neuron_builder().build();
    neuron_store.add_neuron(neuron).unwrap();

    assert_eq!(
        initiate_maturity_disbursement(
            &mut neuron_store,
            &PrincipalId::new_user_test_id(2),
            &NeuronId { id: 1 },
            &DisburseMaturity {
                percentage_to_disburse: 50,
                to_account: None,
                to_account_identifier: None,
            },
            NOW_SECONDS,
        ),
        Err(InitiateMaturityDisbursementError::CallerIsNotNeuronController)
    );
}

#[test]
fn test_initiate_maturity_disbursement_too_many_disbursements() {
    let mut neuron_store = NeuronStore::new(BTreeMap::new());
    let neuron = create_neuron_builder().build();
    neuron_store.add_neuron(neuron).unwrap();

    for _ in 0..10 {
        initiate_maturity_disbursement(
            &mut neuron_store,
            &CONTROLLER,
            &NeuronId { id: 1 },
            &DisburseMaturity {
                percentage_to_disburse: 1,
                to_account: None,
                to_account_identifier: None,
            },
            NOW_SECONDS,
        )
        .unwrap();
    }

    assert_eq!(
        initiate_maturity_disbursement(
            &mut neuron_store,
            &CONTROLLER,
            &NeuronId { id: 1 },
            &DisburseMaturity {
                percentage_to_disburse: 1,
                to_account: None,
                to_account_identifier: None,
            },
            NOW_SECONDS,
        ),
        Err(InitiateMaturityDisbursementError::TooManyDisbursements)
    );
}

#[test]
fn test_initiate_maturity_disbursement_disbursement_too_small() {
    let mut neuron_store = NeuronStore::new(BTreeMap::new());
    let neuron = create_neuron_builder()
        .with_maturity_e8s_equivalent(10_500_000_000)
        .build();
    neuron_store.add_neuron(neuron).unwrap();

    // 1% of 10_500_000_000 is 105_000_000, with -5% maturity modulation, the worst case
    // disbursement is 105_000_000 * 0.95 = 99_750_000 < 1e8.
    assert_eq!(
        initiate_maturity_disbursement(
            &mut neuron_store,
            &CONTROLLER,
            &NeuronId { id: 1 },
            &DisburseMaturity {
                percentage_to_disburse: 1,
                to_account: None,
                to_account_identifier: None,
            },
            NOW_SECONDS,
        ),
        Err(InitiateMaturityDisbursementError::DisbursementTooSmall {
            disbursement_maturity_e8s: 105_000_000,
            minimum_disbursement_e8s: 100_000_000,
            worst_case_maturity_modulation_basis_points: -500,
        })
    );
}

thread_local! {
    static MOCK_ENVIRONMENT: Arc<MockEnvironment> = Arc::new(
        MockEnvironment::new(Default::default(), NOW_SECONDS));
    static TEST_GOVERNANCE: RefCell<Governance> = RefCell::new(Governance::new_uninitialized(
        MOCK_ENVIRONMENT.with(|env| env.clone()),
        Arc::new(MockIcpLedger::default()),
        Arc::new(MockCMC::default()),
        Box::new(MockRandomness::new()),
    ));
}

fn advance_time(seconds: u64) {
    MOCK_ENVIRONMENT.with(|env| {
        let now = env.now();
        env.now_setter()(now + seconds);
    });
}

struct MintIcpExpectation {
    pub amount_e8s: u64,
    pub to_account: AccountIdentifier,
    pub should_succeed: bool,
}

fn mock_ledger(expectations: Vec<MintIcpExpectation>) -> MockIcpLedger {
    let mut mock_ledger = MockIcpLedger::new();

    if expectations.is_empty() {
        mock_ledger.expect_transfer_funds().never();
        return mock_ledger;
    }

    let mut seq = Sequence::new();
    for expectation in expectations {
        let MintIcpExpectation {
            amount_e8s,
            to_account,
            should_succeed,
        } = expectation;
        mock_ledger
            .expect_transfer_funds()
            .withf(
                move |actual_amount_e8s,
                      actual_fees_e8s,
                      actual_from_subaccount,
                      actual_to_account,
                      _memo| {
                    *actual_amount_e8s == amount_e8s
                        && *actual_fees_e8s == 0
                        && actual_from_subaccount.is_none()
                        && *actual_to_account == to_account
                },
            )
            .times(1)
            .in_sequence(&mut seq)
            .returning(move |_, _, _, _, _| {
                if should_succeed {
                    Ok(0)
                } else {
                    Err(NervousSystemError::new())
                }
            });
    }
    mock_ledger
}

fn set_governance_for_test(
    neurons: Vec<Neuron>,
    mock_ledger: MockIcpLedger,
    maturity_modulation: i32,
) {
    let mut governance = Governance::new(
        GovernanceApi {
            cached_daily_maturity_modulation_basis_points: Some(maturity_modulation),
            ..Default::default()
        },
        MOCK_ENVIRONMENT.with(|env| env.clone()),
        Arc::new(mock_ledger),
        Arc::new(MockCMC::default()),
        Box::new(MockRandomness::new()),
    );
    for neuron in neurons {
        governance.neuron_store.add_neuron(neuron).unwrap();
    }

    TEST_GOVERNANCE.set(governance);
}

#[tokio::test]
async fn test_finalize_maturity_disbursement_successful() {
    // Step 1: Set up the test environment
    set_governance_for_test(
        vec![create_neuron_builder().build()],
        mock_ledger(vec![MintIcpExpectation {
            amount_e8s: 1_010_000_000,
            to_account: AccountIdentifier::from(CONTROLLER),
            should_succeed: true,
        }]),
        DEFAULT_MATURITY_MODULATION_BASIS_POINTS,
    );

    // Step 2: Initiate the maturity disbursement
    assert_eq!(
        TEST_GOVERNANCE.with_borrow_mut(|governance| {
            initiate_maturity_disbursement(
                &mut governance.neuron_store,
                &CONTROLLER,
                &NeuronId { id: 1 },
                &DisburseMaturity {
                    percentage_to_disburse: 1,
                    to_account: None,
                    to_account_identifier: None,
                },
                NOW_SECONDS,
            )
        }),
        Ok(1_000_000_000)
    );

    // Step 3: Advance time to 1 second before the disbursement, and verify that the next
    // disbursement is 1 second away.
    let delay = TEST_GOVERNANCE.with_borrow(get_delay_until_next_finalization);
    assert_eq!(delay, Duration::from_secs(DISBURSEMENT_DELAY_SECONDS));
    advance_time(delay.as_secs() - 1);
    assert_eq!(
        finalize_maturity_disbursement(&TEST_GOVERNANCE)
            .now_or_never()
            .unwrap(),
        Duration::from_secs(1)
    );

    // Step 4: Advance time to the disbursement time, and verify that the next disbursement is 7
    // days away. There are no real changes, and it is apparent from the fact that only 1 ledger
    // transfer is allowed from the mock ledger.
    advance_time(1);
    assert_eq!(
        finalize_maturity_disbursement(&TEST_GOVERNANCE)
            .now_or_never()
            .unwrap(),
        Duration::from_secs(DISBURSEMENT_DELAY_SECONDS)
    );
}

#[tokio::test]
async fn test_finalize_maturity_disbursement_no_maturity_modulation() {
    // Step 1: Set up the test environment without maturity modulation.
    set_governance_for_test(
        vec![create_neuron_builder().build()],
        MockIcpLedger::default(),
        DEFAULT_MATURITY_MODULATION_BASIS_POINTS,
    );
    TEST_GOVERNANCE.with_borrow_mut(|governance| {
        governance
            .heap_data
            .cached_daily_maturity_modulation_basis_points = None;
    });

    // Step 2: Initiate the maturity disbursement and advance to disbursement time.
    assert_eq!(
        TEST_GOVERNANCE.with_borrow_mut(|governance| {
            initiate_maturity_disbursement(
                &mut governance.neuron_store,
                &CONTROLLER,
                &NeuronId { id: 1 },
                &DisburseMaturity {
                    percentage_to_disburse: 1,
                    to_account: None,
                    to_account_identifier: None,
                },
                NOW_SECONDS,
            )
        }),
        Ok(1_000_000_000)
    );
    advance_time(DISBURSEMENT_DELAY_SECONDS);

    // Step 4: Finalize the maturity disbursement and verify that it fails.
    let result = try_finalize_maturity_disbursement(&TEST_GOVERNANCE)
        .now_or_never()
        .unwrap();
    assert_eq!(
        result,
        Err(FinalizeMaturityDisbursementError::NoMaturityModulation)
    );
}

#[tokio::test]
async fn test_finalize_maturity_disbursement_ledger_failure() {
    // Step 1: Set up the test environment with a ledger which will fail the first minting attempt
    // but will succeed on the second.
    set_governance_for_test(
        vec![create_neuron_builder().build()],
        mock_ledger(vec![
            MintIcpExpectation {
                amount_e8s: 1_010_000_000,
                to_account: AccountIdentifier::from(CONTROLLER),
                should_succeed: false,
            },
            MintIcpExpectation {
                amount_e8s: 1_010_000_000,
                to_account: AccountIdentifier::from(CONTROLLER),
                should_succeed: true,
            },
        ]),
        DEFAULT_MATURITY_MODULATION_BASIS_POINTS,
    );

    // Step 2: Initiate the maturity disbursement and advance to disbursement time.
    assert_eq!(
        TEST_GOVERNANCE.with_borrow_mut(|governance| {
            initiate_maturity_disbursement(
                &mut governance.neuron_store,
                &CONTROLLER,
                &NeuronId { id: 1 },
                &DisburseMaturity {
                    percentage_to_disburse: 1,
                    to_account: None,
                    to_account_identifier: None,
                },
                NOW_SECONDS,
            )
        }),
        Ok(1_000_000_000)
    );
    advance_time(DISBURSEMENT_DELAY_SECONDS);

    // Step 3: Finalize the maturity disbursement and verify that it fails.
    let result = try_finalize_maturity_disbursement(&TEST_GOVERNANCE)
        .now_or_never()
        .unwrap();
    let Err(FinalizeMaturityDisbursementError::FailToMintIcp { neuron_id, reason }) = result else {
        panic!("Expected a FailToMintIcp error, but got: {result:?}");
    };
    assert_eq!(neuron_id, NeuronId { id: 1 });
    assert!(reason.contains("Failed to mint ICP"));

    // Step 4: Finalize the maturity disbursement again and verify that it succeeds.
    try_finalize_maturity_disbursement(&TEST_GOVERNANCE)
        .now_or_never()
        .unwrap()
        .unwrap();
}
