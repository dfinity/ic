use super::*;

use crate::pb::v1::Vote;
use ic_nns_common::pb::v1::ProposalId;
use lazy_static::lazy_static;
use pretty_assertions::assert_eq;

// TODO(NNS1-2497): Add tests that fail if our BoundedStorage types grow. This
// way, people are very aware of how they might be eating into our headroom.

lazy_static! {
    static ref MODEL_NEURON: Neuron = Neuron {
        id: Some(NeuronId { id: 42 }),
        cached_neuron_stake_e8s: 0xCAFE, // Yummy.

        hot_keys: vec![
            PrincipalId::new_user_test_id(100),
            PrincipalId::new_user_test_id(101),
        ],

        followees: hashmap! {
            0 => Followees {
                followees: vec![
                    NeuronId { id: 200 },
                    NeuronId { id: 201 },
                ],
            },
            1 => Followees {
                followees: vec![
                    // Not sorted, to make sure we preserve order.
                    NeuronId { id: 211 },
                    NeuronId { id: 212 },
                    NeuronId { id: 210 },
                ],
            },
        },

        recent_ballots: vec![
            BallotInfo {
                proposal_id: Some(ProposalId { id: 300 }),
                vote: Vote::Yes as i32,
            },
            BallotInfo {
                proposal_id: Some(ProposalId { id: 301 }),
                vote: Vote::No as i32,
            },
        ],

        known_neuron_data: Some(KnownNeuronData {
            name: "Fabulous".to_string(),
            description: Some("Follow MeEe for max rewards!".to_string()),
        }),

        transfer: Some(NeuronStakeTransfer {
            transfer_timestamp: 123_456_789,
            from: Some(PrincipalId::new_user_test_id(400)),
            from_subaccount: vec![4, 0x01],
            to_subaccount: vec![4, 0x02],
            neuron_stake_e8s: 403,
            block_height: 404,
            memo: 405,
        }),

        ..Default::default()
    };
}

fn new_red_herring_neuron(seed: u64) -> Neuron {
    // Here, we use MODEL_NEURON, simply because this is a little bit more
    // convenient, and it doesn't particularly matter what the result looks like
    // exactly. What matters is that it is distinct.
    let mut result = MODEL_NEURON.clone();

    // To make the result distinct, we have to make some perturbations.
    result.id.as_mut().unwrap().id = seed;
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

    result.known_neuron_data.as_mut().unwrap().name = format!("Red Herring {}", seed,);

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
        let id = *red_herring_neuron.id.as_ref().unwrap();
        assert_eq!(store.read(id), Ok(red_herring_neuron.clone()));
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
    let neuron_1 = MODEL_NEURON.clone();
    assert_eq!(store.create(neuron_1.clone()), Ok(()));

    create_red_herring_neurons(&mut store);
    assert_that_red_herring_neurons_are_untouched(&store);

    // 2. Bad create: use an existing NeuronId. This should result in an
    // InvalidCommand Err.
    let bad_create_result = store.create(Neuron {
        id: Some(NeuronId { id: 42 }),
        cached_neuron_stake_e8s: 0xDEAD_BEEF,
        ..Default::default()
    });
    match &bad_create_result {
        Err(err) => {
            let GovernanceError {
                error_type,
                error_message,
            } = err;

            assert_eq!(
                ErrorType::from_i32(*error_type),
                Some(ErrorType::PreconditionFailed),
                "{:?}",
                err,
            );

            let error_message = error_message.to_lowercase();
            assert!(error_message.contains("already in use"), "{:?}", err);
            assert!(error_message.contains("42"), "{:?}", err);
        }

        _ => panic!(
            "create(evil_twin_neuron) did not result in an Err: {:?}",
            bad_create_result
        ),
    }

    // 3. Read back the first neuron (the second one should have no effect).
    assert_eq!(store.read(NeuronId { id: 42 }), Ok(neuron_1.clone()),);

    // 4. Bad read: Unknown NeuronId. This should result in a NotFound Err.
    let bad_read_result = store.read(NeuronId { id: 0xDEAD_BEEF });
    match &bad_read_result {
        Err(err) => {
            let GovernanceError {
                error_type,
                error_message,
            } = err;

            assert_eq!(
                ErrorType::from_i32(*error_type),
                Some(ErrorType::NotFound),
                "{:?}",
                err,
            );

            let error_message = error_message.to_lowercase();
            assert!(error_message.contains("unable to find"), "{:?}", err);
            assert!(error_message.contains("3735928559"), "{:?}", err); // 0xDEAD_BEEF
        }

        _ => panic!(
            "read(0xDEAD) did not result in an Err: {:?}",
            bad_read_result
        ),
    }

    // 5. Update existing neuron.

    // Derive neuron_5 from neuron_1 by adding entries to collections (to make
    // sure the updating collections works).
    let neuron_5 = {
        let mut hot_keys = neuron_1.hot_keys;
        hot_keys.push(PrincipalId::new_user_test_id(102));

        let mut followees = neuron_1.followees;
        assert_eq!(
            followees.insert(
                7,
                Followees {
                    followees: vec![NeuronId { id: 220 }]
                }
            ),
            None,
        );

        let mut recent_ballots = neuron_1.recent_ballots;
        recent_ballots.push(BallotInfo {
            proposal_id: Some(ProposalId { id: 303 }),
            vote: Vote::Yes as i32,
        });

        let mut known_neuron_data = neuron_1.known_neuron_data;
        known_neuron_data.as_mut().unwrap().name = "I changed my mind".to_string();

        let mut transfer = neuron_1.transfer;
        transfer.as_mut().unwrap().memo = 405_405;

        Neuron {
            cached_neuron_stake_e8s: 0xFEED, // After drink, we eat.

            hot_keys,
            followees,
            recent_ballots,

            known_neuron_data,
            transfer,

            ..neuron_1
        }
    };
    assert_eq!(store.update(neuron_5.clone()), Ok(()));
    assert_that_red_herring_neurons_are_untouched(&store);

    // 6. Read to verify update.
    assert_eq!(store.read(NeuronId { id: 42 }), Ok(neuron_5.clone()));

    // 7. Bad update: Neuron not found (unknown ID).
    let update_result = store.update(Neuron {
        id: Some(NeuronId { id: 0xDEAD_BEEF }),
        cached_neuron_stake_e8s: 0xBAD_F00D,
        ..Default::default()
    });
    match &update_result {
        // This is what we expected.
        Err(err) => {
            // Take a closer look at err.
            let GovernanceError {
                error_type,
                error_message,
            } = err;

            // Inspect type.
            let error_type = ErrorType::from_i32(*error_type);
            assert_eq!(error_type, Some(ErrorType::NotFound), "{:?}", err);

            // Next, turn to error_message.
            let error_message = error_message.to_lowercase();
            assert!(error_message.contains("update"), "{:?}", err);
            assert!(error_message.contains("existing"), "{:?}", err);
            assert!(error_message.contains("neuron"), "{:?}", err);
            assert!(error_message.contains("there was none"), "{:?}", err);

            assert!(error_message.contains("id"), "{:?}", err);
            assert!(error_message.contains("3735928559"), "{:?}", err); // 0xDEAD_BEEF

            assert!(
                error_message.contains("cached_neuron_stake_e8s"),
                "{:?}",
                err,
            );
            assert!(error_message.contains("195948557"), "{:?}", err); // 0xBAD_F00D
        }

        // Any other result is bad.
        _ => panic!("{:#?}", update_result),
    }
    assert_that_red_herring_neurons_are_untouched(&store);

    // 8. Read to verify bad update.
    let read_result = store.read(NeuronId { id: 0xDEAD_BEEF });
    match &read_result {
        // This is what we expected.
        Err(err) => {
            // Take a closer look at err.
            let GovernanceError {
                error_type,
                error_message,
            } = err;

            // Inspect type.
            let error_type = ErrorType::from_i32(*error_type);
            assert_eq!(error_type, Some(ErrorType::NotFound), "{:?}", err);

            // Next, turn to error_message.
            let error_message = error_message.to_lowercase();
            assert!(error_message.contains("unable to find"), "{:?}", err);
            assert!(error_message.contains("3735928559"), "{:?}", err); // 0xDEAD_BEEF
        }

        _ => panic!("read did not return Err: {:?}", read_result),
    }

    // 9. Update again.
    let neuron_9 = Neuron {
        known_neuron_data: None,
        transfer: None,
        ..neuron_5
    };
    assert_eq!(store.update(neuron_9.clone()), Ok(()));
    assert_that_red_herring_neurons_are_untouched(&store);

    // 10. Read to verify second update.
    assert_eq!(store.read(NeuronId { id: 42 }), Ok(neuron_9));

    // 11. Delete.
    assert_eq!(store.delete(NeuronId { id: 42 }), Ok(()));
    assert_that_red_herring_neurons_are_untouched(&store);

    // 12. Bad delete: repeat.
    let delete_result = store.delete(NeuronId { id: 42 });
    match &delete_result {
        // This is what we expected.
        Err(err) => {
            // Take a closer look at err.
            let GovernanceError {
                error_type,
                error_message,
            } = err;

            // Inspect type.
            let error_type = ErrorType::from_i32(*error_type);
            assert_eq!(error_type, Some(ErrorType::NotFound), "{:?}", err);

            // Next, turn to error_message.
            let error_message = error_message.to_lowercase();
            assert!(error_message.contains("not found"), "{:?}", err);
            assert!(error_message.contains("42"), "{:?}", err);
        }

        _ => panic!("second delete did not return Err: {:?}", delete_result),
    }
    assert_that_red_herring_neurons_are_untouched(&store);

    // 13. Read to verify delete.
    let read_result = store.read(NeuronId { id: 42 });
    match &read_result {
        // This is what we expected.
        Err(err) => {
            // Take a closer look at err.
            let GovernanceError {
                error_type,
                error_message,
            } = err;

            // Inspect type.
            let error_type = ErrorType::from_i32(*error_type);
            assert_eq!(error_type, Some(ErrorType::NotFound), "{:?}", err);

            // Next, turn to error_message.
            let error_message = error_message.to_lowercase();
            assert!(error_message.contains("unable to find"), "{:?}", err);
            assert!(error_message.contains("42"), "{:?}", err);
        }

        _ => panic!("read did not return Err: {:?}", read_result),
    }
    assert_that_red_herring_neurons_are_untouched(&store);

    // Make sure delete is actually thorough. I.e. no dangling references.
    // Here, we access privates. Elsewhere, we do not do this. I suppose
    // StableNeuronStore could have a pub is_internally_consistent method.
    fn assert_no_zombie_references_in<Key, Value, Memory>(
        map_name: &str,
        map: &StableBTreeMap<Key, Value, Memory>,
        key_to_neuron_id: impl Fn(Key) -> NeuronId,
        bad_neuron_id: NeuronId,
    ) where
        Key: BoundedStorable + Ord + Copy + std::fmt::Debug,
        Value: BoundedStorable + std::fmt::Debug,
        Memory: ic_stable_structures::Memory,
    {
        for (key, value) in map.iter() {
            assert_ne!(
                key_to_neuron_id(key),
                bad_neuron_id,
                "{} {:?}: {:#?}",
                map_name,
                key,
                value
            );
        }
    }

    // No zombies. This requires looking at privates. Normally, we try to avoid
    // this, but APIs normally assume internal consistency, but that is exactly
    // what we're trying to to verify here.
    let original_neuron_id = *MODEL_NEURON.id.as_ref().unwrap();

    assert_no_zombie_references_in(
        "hot_keys",
        &store.hot_keys_map,
        |key| NeuronId { id: key.0 },
        original_neuron_id,
    );
    assert_no_zombie_references_in(
        "recent_ballots",
        &store.recent_ballots_map,
        |key| NeuronId { id: key.0 },
        original_neuron_id,
    );
    assert_no_zombie_references_in(
        "followees",
        &store.followees_map,
        |key: FolloweesKey| NeuronId {
            id: key.followee_id,
        },
        original_neuron_id,
    );

    assert_no_zombie_references_in(
        "known_neuron_data",
        &store.known_neuron_data_map,
        |key| NeuronId { id: key },
        original_neuron_id,
    );
    assert_no_zombie_references_in(
        "transfer",
        &store.transfer_map,
        |key| NeuronId { id: key },
        original_neuron_id,
    );
}

/// Summary:
///
///   1. upsert (effectively, an insert)
///   2. read to verify
///   3. upsert same ID (effectively, an update)
///   4. read to verify
#[test]
fn test_store_upsert() {
    let mut store = new_heap_based();

    let neuron = MODEL_NEURON.clone();
    let neuron_id = neuron.id.unwrap();

    // 0. create red herrings
    create_red_herring_neurons(&mut store);

    // 1. upsert (entry not already present)
    assert_eq!(store.upsert(neuron.clone()), Ok(()));
    assert_that_red_herring_neurons_are_untouched(&store);

    // 2. read to verify
    assert_eq!(store.read(neuron_id), Ok(neuron.clone()));

    // Modify neuron.
    let updated_neuron = {
        let mut hot_keys = neuron.hot_keys;
        hot_keys.push(PrincipalId::new_user_test_id(999_000));

        let mut followees = neuron.followees;
        followees
            .entry(0)
            .or_default()
            .followees
            .push(NeuronId { id: 999_001 });

        let mut recent_ballots = neuron.recent_ballots;
        recent_ballots.insert(
            0,
            BallotInfo {
                proposal_id: Some(ProposalId { id: 999_002 }),
                vote: Vote::No as i32,
            },
        );

        let mut known_neuron_data = neuron.known_neuron_data;
        known_neuron_data.as_mut().unwrap().description = None;

        let mut transfer = neuron.transfer;
        let transfer = None;

        Neuron {
            cached_neuron_stake_e8s: 0xCAFE,

            hot_keys,
            followees,
            recent_ballots,

            known_neuron_data,
            transfer,

            ..neuron
        }
    };

    // 3. upsert (change an existing entry)
    assert_eq!(store.upsert(updated_neuron.clone()), Ok(()));
    assert_that_red_herring_neurons_are_untouched(&store);

    // 4. read to verify
    assert_eq!(store.read(neuron_id), Ok(updated_neuron));
}
