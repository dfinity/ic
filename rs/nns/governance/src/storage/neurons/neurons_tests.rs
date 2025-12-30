use super::*;

use crate::{
    neuron::{DissolveStateAndAge, NeuronBuilder},
    pb::v1::Vote,
};
use ic_base_types::PrincipalId;
use ic_nns_common::pb::v1::ProposalId;
use icp_ledger::Subaccount;
use lazy_static::lazy_static;
use pretty_assertions::assert_eq;

fn create_model_neuron(id: u64) -> Neuron {
    let controller = PrincipalId::new_user_test_id(id);
    let subaccount = Subaccount::from(&controller);
    NeuronBuilder::new(
        NeuronId { id },
        subaccount,
        controller,
        DissolveStateAndAge::NotDissolving {
            dissolve_delay_seconds: 10_000_000_000,
            aging_since_timestamp_seconds: 123_456_789,
        },
        123_456_789,
    )
    .with_hot_keys(vec![
        PrincipalId::new_user_test_id(100),
        PrincipalId::new_user_test_id(101),
    ])
    .with_followees(hashmap! {
        0 => Followees {
            followees: vec![
                NeuronId { id: 200 },
                NeuronId { id: 201 },
            ],
        },
        1 => Followees {
            followees: vec![
                // Not sorted and has duplicates, to make sure we preserve order and
                // multiplicity.
                NeuronId { id: 211 },
                NeuronId { id: 212 },
                NeuronId { id: 210 },
                NeuronId { id: 210 },
            ],
        },
    })
    .with_known_neuron_data(Some(KnownNeuronData {
        name: "Fabulous".to_string(),
        description: Some("Follow MeEe for max rewards!".to_string()),
        links: vec![],
        committed_topics: vec![],
    }))
    .with_recent_ballots(vec![
        BallotInfo {
            proposal_id: Some(ProposalId { id: 300 }),
            vote: Vote::Yes as i32,
        },
        BallotInfo {
            proposal_id: Some(ProposalId { id: 301 }),
            vote: Vote::No as i32,
        },
    ])
    .with_transfer(Some(NeuronStakeTransfer {
        transfer_timestamp: 123_456_789,
        from: Some(PrincipalId::new_user_test_id(400)),
        from_subaccount: vec![4, 0x01],
        to_subaccount: vec![4, 0x02],
        neuron_stake_e8s: 403,
        block_height: 404,
        memo: 405,
    }))
    .build()
}

fn new_red_herring_neuron(seed: u64) -> Neuron {
    // Here, we use create_model_neuron(), simply because this is a little bit more convenient, and
    // it doesn't particularly matter what the result looks like exactly. What matters is that it is
    // distinct.
    let mut result = create_model_neuron(seed);

    // To make the result distinct, we have to make some perturbations.
    result.neuron_fees_e8s = seed;

    // We must also make the auxiliary fields distinct.

    result.hot_keys.push(PrincipalId::new_user_test_id(seed));
    result.followees.insert(
        2,
        Followees {
            followees: vec![NeuronId { id: seed }],
        },
    );
    result.recent_ballots.push(BallotInfo {
        proposal_id: Some(ProposalId { id: seed }),
        vote: Vote::No as i32,
    });

    let mut new_known_neuron_data = result.known_neuron_data().unwrap().clone();
    new_known_neuron_data.name = format!("Red Herring {seed}");
    result.set_known_neuron_data(new_known_neuron_data);

    result.transfer.as_mut().unwrap().memo = seed;

    // Done!
    result
}

lazy_static! {
    // These are to make sure that modifying the main neuron in
    // StableNeuronStore does not spill over to these other neurons.
    static ref RED_HERRING_NEURONS: Vec<Neuron> = vec![
        // These are "adjacent" to MODEL_NEURON.
        new_red_herring_neuron(41),
        new_red_herring_neuron(43),

        // More random neurons.
        new_red_herring_neuron(958_288),
        new_red_herring_neuron(965_006),
        new_red_herring_neuron(488_725),
    ];
}

fn create_red_herring_neurons(store: &mut StableNeuronStore<VectorMemory>) {
    for red_herring_neuron in RED_HERRING_NEURONS.iter() {
        assert_eq!(
            store.create(red_herring_neuron.clone()),
            Ok(()),
            "{:#?}",
            red_herring_neuron,
        );
    }
}

fn assert_that_red_herring_neurons_are_untouched(store: &StableNeuronStore<VectorMemory>) {
    for red_herring_neuron in &*RED_HERRING_NEURONS {
        let id = red_herring_neuron.id();
        assert_eq!(
            store.read(id, NeuronSections::ALL),
            Ok(red_herring_neuron.clone())
        );
    }
}

/// Summary:
///
///   1. create
///   2. bad create
///   3. read to verify create
///   4. bad read
///
///   5. update
///   6. read to verify the update
///   7. bad update
///   8. read to verify bad update
///   9. update: This time, with None singletons.
///   10. read to verify
///
///   11. delete
///   12. bad delete: repeat
///   13. read to verify.
#[test]
fn test_store_simplest_nontrivial_case() {
    let mut store = new_heap_based();

    // 1. Create a Neuron.
    let neuron_1 = create_model_neuron(42);
    assert_eq!(store.create(neuron_1.clone()), Ok(()));

    create_red_herring_neurons(&mut store);
    assert_that_red_herring_neurons_are_untouched(&store);

    // 2. Bad create: use an existing NeuronId. This should result in an
    // InvalidCommand Err.
    let bad_create_result = store.create(create_model_neuron(42));
    match &bad_create_result {
        Err(err) => match err {
            NeuronStoreError::NeuronAlreadyExists(neuron_id) => {
                assert_eq!(*neuron_id, NeuronId { id: 42 });
            }
            _ => panic!(
                "create(evil_twin_neuron) resulted in an Err other than already exists: {err:?}"
            ),
        },

        _ => panic!("create(evil_twin_neuron) did not result in an Err: {bad_create_result:?}"),
    }

    // 3. Read back the first neuron (the second one should have no effect).
    assert_eq!(
        store.read(NeuronId { id: 42 }, NeuronSections::ALL),
        Ok(neuron_1.clone()),
    );

    // 4. Bad read: Unknown NeuronId. This should result in a NotFound Err.
    let bad_read_result = store.read(NeuronId { id: 0xDEAD_BEEF }, NeuronSections::NONE);
    match &bad_read_result {
        Err(err) => match err {
            NeuronStoreError::NeuronNotFound { neuron_id } => {
                assert_eq!(*neuron_id, NeuronId { id: 0xDEAD_BEEF });
            }
            _ => panic!("read returns error other than not found: {err:?}"),
        },

        _ => panic!("read(0xDEAD) did not result in an Err: {bad_read_result:?}"),
    }

    // 5. Update existing neuron.

    // Derive neuron_5 from neuron_1 by adding entries to collections (to make
    // sure the updating collections works).
    let neuron_5 = {
        let mut hot_keys = neuron_1.hot_keys.clone();
        hot_keys.push(PrincipalId::new_user_test_id(102));

        let mut followees = neuron_1.followees.clone();
        assert_eq!(
            followees.insert(
                7,
                Followees {
                    followees: vec![NeuronId { id: 220 }]
                }
            ),
            None,
        );

        let mut recent_ballots = neuron_1.recent_ballots.clone();
        recent_ballots.push(BallotInfo {
            proposal_id: Some(ProposalId { id: 303 }),
            vote: Vote::Yes as i32,
        });

        let mut known_neuron_data = neuron_1.known_neuron_data().unwrap().clone();
        known_neuron_data.name = "I changed my mind".to_string();

        let mut transfer = neuron_1.transfer.clone();
        transfer.as_mut().unwrap().memo = 405_405;

        let mut neuron = neuron_1.clone();
        neuron.cached_neuron_stake_e8s = 0xFEED; // After drink, we eat.

        neuron.hot_keys = hot_keys;
        neuron.followees = followees;
        neuron.recent_ballots = recent_ballots;

        neuron.set_known_neuron_data(known_neuron_data);
        neuron.transfer = transfer;

        neuron
    };
    assert_eq!(store.update(&neuron_1, neuron_5.clone()), Ok(()));
    assert_that_red_herring_neurons_are_untouched(&store);

    // 6. Read to verify update.
    assert_eq!(
        store.read(NeuronId { id: 42 }, NeuronSections::ALL),
        Ok(neuron_5.clone())
    );

    // 7. Bad update: Neuron not found (unknown ID).
    let non_existent_neuron = create_model_neuron(0xDEAD_BEEF);
    let update_result = store.update(&non_existent_neuron, non_existent_neuron.clone());
    match &update_result {
        // This is what we expected.
        Err(err) => match err {
            NeuronStoreError::NeuronNotFound { neuron_id } => {
                assert_eq!(*neuron_id, NeuronId { id: 0xDEAD_BEEF });
            }
            _ => panic!("update returns Err other than not found {err:?}"),
        },

        // Any other result is bad.
        _ => panic!("{update_result:#?}"),
    }
    assert_that_red_herring_neurons_are_untouched(&store);

    // 8. Read to verify bad update.
    let read_result = store.read(NeuronId { id: 0xDEAD_BEEF }, NeuronSections::NONE);
    match &read_result {
        // This is what we expected.
        Err(err) => {
            // Take a closer look at err.
            match err {
                NeuronStoreError::NeuronNotFound { neuron_id } => {
                    assert_eq!(*neuron_id, NeuronId { id: 0xDEAD_BEEF });
                }
                _ => panic!("read returns error other than not found: {err:?}"),
            }
        }

        _ => panic!("read did not return Err: {read_result:?}"),
    }

    // 9. Update again.
    let mut neuron_9 = neuron_5.clone();
    neuron_9.clear_known_neuron_data();
    neuron_9.transfer = None;
    assert_eq!(store.update(&neuron_5, neuron_9.clone()), Ok(()));
    assert_that_red_herring_neurons_are_untouched(&store);

    // 10. Read to verify second update.
    assert_eq!(
        store.read(NeuronId { id: 42 }, NeuronSections::ALL),
        Ok(neuron_9)
    );

    // 11. Delete.
    assert_eq!(store.delete(NeuronId { id: 42 }), Ok(()));
    assert_that_red_herring_neurons_are_untouched(&store);

    // 12. Bad delete: repeat.
    let delete_result = store.delete(NeuronId { id: 42 });
    match &delete_result {
        // This is what we expected.
        Err(err) => {
            // Take a closer look at err.
            match err {
                NeuronStoreError::NeuronNotFound { neuron_id } => {
                    assert_eq!(*neuron_id, NeuronId { id: 42 });
                }
                _ => panic!("read returns error other than not found: {err:?}"),
            }
        }

        _ => panic!("second delete did not return Err: {delete_result:?}"),
    }
    assert_that_red_herring_neurons_are_untouched(&store);

    // 13. Read to verify delete.
    let read_result = store.read(NeuronId { id: 42 }, NeuronSections::NONE);
    match &read_result {
        // This is what we expected.
        Err(err) => {
            // Take a closer look at err.
            match err {
                NeuronStoreError::NeuronNotFound { neuron_id } => {
                    assert_eq!(*neuron_id, NeuronId { id: 42 });
                }
                _ => panic!("read returns error other than not found: {err:?}"),
            }
        }

        _ => panic!("read did not return Err: {read_result:?}"),
    }
    assert_that_red_herring_neurons_are_untouched(&store);

    // Make sure delete is actually thorough. I.e. no dangling references.
    // Here, we access privates. Elsewhere, we do not do this. I suppose
    // StableNeuronStore could have a pub is_internally_consistent method.
    fn assert_no_zombie_references_in<Key, Value, Memory>(
        map_name: &str,
        map: &StableBTreeMap<Key, Value, Memory>,
        key_value_to_neuron_id: impl Fn(Key, Value) -> NeuronId,
        bad_neuron_id: NeuronId,
    ) where
        Key: Storable + Ord + Copy + std::fmt::Debug,
        Value: Storable + Clone + std::fmt::Debug,
        Memory: ic_stable_structures::Memory,
    {
        for (key, value) in map.iter() {
            assert_ne!(
                key_value_to_neuron_id(key, value.clone()),
                bad_neuron_id,
                "{map_name} {key:?}: {value:#?}"
            );
        }
    }

    // No zombies. This requires looking at privates. Normally, we try to avoid
    // this, but APIs normally assume internal consistency, but that is exactly
    // what we're trying to to verify here.
    let original_neuron_id = neuron_1.id();

    assert_no_zombie_references_in(
        "hot_keys",
        &store.hot_keys_map,
        |key, _| key.0,
        original_neuron_id,
    );
    assert_no_zombie_references_in(
        "recent_ballots",
        &store.recent_ballots_map,
        |key, _| key.0,
        original_neuron_id,
    );
    assert_no_zombie_references_in(
        "followees",
        &store.followees_map,
        |_, followee_id| followee_id,
        original_neuron_id,
    );

    assert_no_zombie_references_in(
        "known_neuron_data",
        &store.known_neuron_data_map,
        |key, _| key,
        original_neuron_id,
    );
    assert_no_zombie_references_in(
        "transfer",
        &store.transfer_map,
        |key, _| key,
        original_neuron_id,
    );
}

#[test]
fn test_partial_read() {
    let mut store = new_heap_based();
    let neuron = create_model_neuron(42);
    assert_eq!(store.create(neuron.clone()), Ok(()));

    let partial_read_test_helper = |sections: NeuronSections| {
        let neuron_read_result = store.read(NeuronId { id: 42 }, sections).unwrap();

        assert_eq!(neuron_read_result.controller(), neuron.controller());

        if sections.hot_keys {
            assert_eq!(neuron_read_result.hot_keys, neuron.hot_keys);
        } else {
            assert_eq!(neuron_read_result.hot_keys, vec![]);
        }

        if sections.followees {
            assert_eq!(neuron_read_result.followees, neuron.followees);
        } else {
            assert_eq!(neuron_read_result.followees, HashMap::new());
        }

        if sections.recent_ballots {
            assert_eq!(neuron_read_result.recent_ballots, neuron.recent_ballots);
        } else {
            assert_eq!(neuron_read_result.recent_ballots, vec![]);
        }

        if sections.known_neuron_data {
            assert_eq!(
                neuron_read_result.known_neuron_data(),
                neuron.known_neuron_data(),
            );
        } else {
            assert_eq!(neuron_read_result.known_neuron_data(), None);
        }

        if sections.transfer {
            assert_eq!(neuron_read_result.transfer, neuron.transfer);
        } else {
            assert_eq!(neuron_read_result.transfer, None);
        }
    };

    partial_read_test_helper(NeuronSections::NONE);
    partial_read_test_helper(NeuronSections::ALL);
    partial_read_test_helper(NeuronSections {
        hot_keys: true,
        ..NeuronSections::NONE
    });
    partial_read_test_helper(NeuronSections {
        followees: true,
        ..NeuronSections::NONE
    });
    partial_read_test_helper(NeuronSections {
        recent_ballots: true,
        ..NeuronSections::NONE
    });
    partial_read_test_helper(NeuronSections {
        known_neuron_data: true,
        ..NeuronSections::NONE
    });
    partial_read_test_helper(NeuronSections {
        transfer: true,
        ..NeuronSections::NONE
    });
}

#[test]
fn test_range_neurons_reconstitutes_fully() {
    let mut store = new_heap_based();
    let neurons = {
        let mut neurons = vec![];
        for i in 1..10 {
            let neuron = create_model_neuron(i);
            store.create(neuron.clone()).unwrap();
            neurons.push(neuron);
        }
        neurons
    };

    let result = store.range_neurons(..).collect::<Vec<_>>();

    assert_eq!(result, neurons);
}

#[test]
fn test_range_neurons_ranges_work_correctly() {
    // This test is here to ensure that the conversions that happen inside range_neurons are correct.
    let mut store = new_heap_based();
    let neurons = {
        let mut neurons = vec![];
        for i in 1..=10 {
            let neuron = create_model_neuron(i);
            store.create(neuron.clone()).unwrap();
            neurons.push(neuron);
        }
        neurons
    };

    let result = store
        .range_neurons(NeuronId::from_u64(2)..NeuronId::from_u64(9))
        .collect::<Vec<_>>();
    assert_eq!(result, neurons[1..8]);

    let result = store
        .range_neurons(NeuronId::from_u64(2)..=NeuronId::from_u64(3))
        .collect::<Vec<_>>();
    assert_eq!(result, neurons[1..3]);

    let result = store
        .range_neurons((
            std::ops::Bound::Excluded(NeuronId::from_u64(2)),
            std::ops::Bound::Included(NeuronId::from_u64(4)),
        ))
        .collect::<Vec<_>>();
    assert_eq!(result.len(), 2);
    assert_eq!(result, neurons[2..4]);
}

#[test]
fn test_range_neurons_not_all_neuron_sections() {
    let mut store = new_heap_based();
    let neurons = {
        let mut neurons = vec![];
        for i in 1..=10 {
            let neuron = create_model_neuron(i);
            store.create(neuron.clone()).unwrap();
            neurons.push(neuron);
        }
        neurons
    };

    type NeuronModifier = Box<dyn Fn(Neuron) -> Neuron>;
    let cases: Vec<(NeuronSections, NeuronModifier)> = vec![
        // Fetch 0 auxiliary.
        (
            NeuronSections::NONE,
            Box::new(|mut neuron: Neuron| {
                neuron.hot_keys.clear();
                neuron.recent_ballots.clear();
                neuron.followees.clear();
                neuron.clear_known_neuron_data();
                neuron.transfer = None;

                neuron
            }),
        ),
        // Fetch 1 auxiliary.
        (
            NeuronSections {
                hot_keys: true,
                ..NeuronSections::NONE
            },
            Box::new(|mut neuron: Neuron| {
                neuron.recent_ballots.clear();
                neuron.followees.clear();
                neuron.clear_known_neuron_data();
                neuron.transfer = None;

                neuron
            }),
        ),
        (
            NeuronSections {
                recent_ballots: true,
                ..NeuronSections::NONE
            },
            Box::new(|mut neuron: Neuron| {
                neuron.hot_keys.clear();
                neuron.followees.clear();
                neuron.clear_known_neuron_data();
                neuron.transfer = None;

                neuron
            }),
        ),
        (
            NeuronSections {
                followees: true,
                ..NeuronSections::NONE
            },
            Box::new(|mut neuron: Neuron| {
                neuron.hot_keys.clear();
                neuron.recent_ballots.clear();
                neuron.clear_known_neuron_data();
                neuron.transfer = None;

                neuron
            }),
        ),
        (
            NeuronSections {
                known_neuron_data: true,
                ..NeuronSections::NONE
            },
            Box::new(|mut neuron: Neuron| {
                neuron.hot_keys.clear();
                neuron.recent_ballots.clear();
                neuron.followees.clear();
                neuron.transfer = None;

                neuron
            }),
        ),
        (
            NeuronSections {
                transfer: true,
                ..NeuronSections::NONE
            },
            Box::new(|mut neuron: Neuron| {
                neuron.hot_keys.clear();
                neuron.recent_ballots.clear();
                neuron.followees.clear();
                neuron.clear_known_neuron_data();

                neuron
            }),
        ),
        // Fetch two auxiliary.
        (
            NeuronSections {
                hot_keys: true,
                transfer: true,
                ..NeuronSections::NONE
            },
            Box::new(|mut neuron: Neuron| {
                neuron.recent_ballots.clear();
                neuron.followees.clear();
                neuron.clear_known_neuron_data();

                neuron
            }),
        ),
    ];

    for (neuron_sections, clear) in cases {
        let neuron_2 = neurons[2].clone();
        let neuron_3 = neurons[3].clone();
        let expected_result = vec![clear(neuron_2), clear(neuron_3)];

        let result = store
            .range_neurons_sections(
                (
                    std::ops::Bound::Excluded(NeuronId::from_u64(2)),
                    std::ops::Bound::Included(NeuronId::from_u64(4)),
                ),
                neuron_sections,
            )
            .collect::<Vec<_>>();

        assert_eq!(result, expected_result, "{:#?}", neuron_sections);
    }
}

#[test]
fn test_register_recent_neuron_ballot_migration_full() {
    // Set up with 100 ballots, and ensure that the pointer is in the right place and the ballots are reversed
    let mut store = new_heap_based();
    let mut neuron = create_model_neuron(1);
    neuron.recent_ballots_next_entry_index = None;

    let recent_ballots = (0..100)
        .map(|i| BallotInfo {
            proposal_id: Some(ProposalId { id: i as u64 }),
            vote: Vote::Yes as i32,
        })
        .collect::<Vec<_>>();

    neuron.recent_ballots = recent_ballots.clone();

    store.create(neuron.clone()).unwrap();

    let retrieved_neuron = store.read(neuron.id(), NeuronSections::ALL).unwrap();
    assert_eq!(retrieved_neuron, neuron);

    store
        .register_recent_neuron_ballot(
            neuron.id(),
            Topic::NetworkEconomics,
            ProposalId { id: 100 },
            Vote::No,
        )
        .unwrap();

    let mut expected_updated_ballots = {
        let mut recent_ballots = recent_ballots.clone();
        recent_ballots.reverse();
        recent_ballots[0] = BallotInfo {
            proposal_id: Some(ProposalId { id: 100 }),
            vote: Vote::No as i32,
        };
        recent_ballots
    };

    let retrieved_neuron = store.read(neuron.id(), NeuronSections::ALL).unwrap();
    assert_eq!(retrieved_neuron.recent_ballots, expected_updated_ballots);
    assert_eq!(retrieved_neuron.recent_ballots_next_entry_index, Some(1));

    // Now, let's add another ballot and ensure that the pointer is updated correctly and ballots
    // are not reversed again
    store
        .register_recent_neuron_ballot(
            neuron.id(),
            Topic::NetworkEconomics,
            ProposalId { id: 101 },
            Vote::Yes,
        )
        .unwrap();
    expected_updated_ballots[1] = BallotInfo {
        proposal_id: Some(ProposalId { id: 101 }),
        vote: Vote::Yes as i32,
    };
    let retrieved_neuron = store.read(neuron.id(), NeuronSections::ALL).unwrap();
    assert_eq!(retrieved_neuron.recent_ballots, expected_updated_ballots);
    assert_eq!(retrieved_neuron.recent_ballots_next_entry_index, Some(2));
}

#[test]
fn test_register_recent_neuron_ballot_migration_notfull() {
    // Set up with 100 ballots, and ensure that the pointer is in the right place and the ballots are reversed
    let mut store = new_heap_based();
    let mut neuron = create_model_neuron(1);
    neuron.recent_ballots_next_entry_index = None;

    let recent_ballots = (0..20)
        .map(|i| BallotInfo {
            proposal_id: Some(ProposalId { id: i as u64 }),
            vote: Vote::Yes as i32,
        })
        .collect::<Vec<_>>();

    neuron.recent_ballots = recent_ballots.clone();

    store.create(neuron.clone()).unwrap();

    let retrieved_neuron = store.read(neuron.id(), NeuronSections::ALL).unwrap();
    assert_eq!(retrieved_neuron, neuron);

    store
        .register_recent_neuron_ballot(
            neuron.id(),
            Topic::NetworkEconomics,
            ProposalId { id: 100 },
            Vote::No,
        )
        .unwrap();

    let mut expected_updated_ballots = {
        let mut recent_ballots = recent_ballots.clone();
        recent_ballots.reverse();
        recent_ballots.push(BallotInfo {
            proposal_id: Some(ProposalId { id: 100 }),
            vote: Vote::No as i32,
        });
        recent_ballots
    };

    let retrieved_neuron = store.read(neuron.id(), NeuronSections::ALL).unwrap();
    assert_eq!(retrieved_neuron.recent_ballots, expected_updated_ballots);
    assert_eq!(retrieved_neuron.recent_ballots_next_entry_index, Some(21));

    // Now, let's add another ballot and ensure that the pointer is updated correctly and ballots
    // are not reversed again
    store
        .register_recent_neuron_ballot(
            neuron.id(),
            Topic::NetworkEconomics,
            ProposalId { id: 101 },
            Vote::Yes,
        )
        .unwrap();
    expected_updated_ballots.push(BallotInfo {
        proposal_id: Some(ProposalId { id: 101 }),
        vote: Vote::Yes as i32,
    });
    let retrieved_neuron = store.read(neuron.id(), NeuronSections::ALL).unwrap();
    assert_eq!(retrieved_neuron.recent_ballots, expected_updated_ballots);
    assert_eq!(retrieved_neuron.recent_ballots_next_entry_index, Some(22));
}
