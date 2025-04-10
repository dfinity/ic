use super::*;

use crate::{
    neuron::{DissolveStateAndAge, NeuronBuilder},
    pb::v1::Subaccount,
};

use std::collections::BTreeMap;

static NOW_SECONDS: u64 = 1_234_567_890;
static CONTROLLER: PrincipalId = PrincipalId::new_user_test_id(1);

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
            account_to_disburse_to: Some(Account {
                owner: Some(CONTROLLER),
                subaccount: None,
            }),
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
            account_to_disburse_to: Some(Account {
                owner: Some(PrincipalId::new_user_test_id(2)),
                subaccount: Some(Subaccount {
                    subaccount: vec![2u8; 32]
                }),
            }),
            timestamp_of_disbursement_seconds: NOW_SECONDS,
            finalize_disbursement_timestamp_seconds: NOW_SECONDS + ONE_DAY_SECONDS * 7,
        }
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

    // 1% of 1_050_000 is 10_500, with -5% maturity modulation, the worst case
    // disbursement is 10_500 * 0.95 = 9_975 < 10_000.
    assert_eq!(
        initiate_maturity_disbursement(
            &mut neuron_store,
            &CONTROLLER,
            &NeuronId { id: 1 },
            &DisburseMaturity {
                percentage_to_disburse: 1,
                to_account: None,
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
