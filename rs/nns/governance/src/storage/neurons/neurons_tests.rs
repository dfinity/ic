use super::*;

use crate::{
    neuron::{DissolveStateAndAge, NeuronBuilder},
    pb::v1::{abridged_neuron::DissolveState, Vote},
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
        let id = red_herring_neuron.id();
        assert_eq!(
            store.read(id, NeuronSections::all()),
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
                "create(evil_twin_neuron) resulted in an Err other than already exists: {:?}",
                err
            ),
        },

        _ => panic!(
            "create(evil_twin_neuron) did not result in an Err: {:?}",
            bad_create_result
        ),
    }

    // 3. Read back the first neuron (the second one should have no effect).
    assert_eq!(
        store.read(NeuronId { id: 42 }, NeuronSections::all()),
        Ok(neuron_1.clone()),
    );

    // 4. Bad read: Unknown NeuronId. This should result in a NotFound Err.
    let bad_read_result = store.read(NeuronId { id: 0xDEAD_BEEF }, NeuronSections::default());
    match &bad_read_result {
        Err(err) => match err {
            NeuronStoreError::NeuronNotFound { neuron_id } => {
                assert_eq!(*neuron_id, NeuronId { id: 0xDEAD_BEEF });
            }
            _ => panic!("read returns error other than not found: {:?}", err),
        },

        _ => panic!(
            "read(0xDEAD) did not result in an Err: {:?}",
            bad_read_result
        ),
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

        let mut known_neuron_data = neuron_1.known_neuron_data.clone();
        known_neuron_data.as_mut().unwrap().name = "I changed my mind".to_string();

        let mut transfer = neuron_1.transfer.clone();
        transfer.as_mut().unwrap().memo = 405_405;

        let mut neuron = neuron_1.clone();
        neuron.cached_neuron_stake_e8s = 0xFEED; // After drink, we eat.

        neuron.hot_keys = hot_keys;
        neuron.followees = followees;
        neuron.recent_ballots = recent_ballots;

        neuron.known_neuron_data = known_neuron_data;
        neuron.transfer = transfer;

        neuron
    };
    assert_eq!(store.update(&neuron_1, neuron_5.clone()), Ok(()));
    assert_that_red_herring_neurons_are_untouched(&store);

    // 6. Read to verify update.
    assert_eq!(
        store.read(NeuronId { id: 42 }, NeuronSections::all()),
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
            _ => panic!("update returns Err other than not found {:?}", err),
        },

        // Any other result is bad.
        _ => panic!("{:#?}", update_result),
    }
    assert_that_red_herring_neurons_are_untouched(&store);

    // 8. Read to verify bad update.
    let read_result = store.read(NeuronId { id: 0xDEAD_BEEF }, NeuronSections::default());
    match &read_result {
        // This is what we expected.
        Err(err) => {
            // Take a closer look at err.
            match err {
                NeuronStoreError::NeuronNotFound { neuron_id } => {
                    assert_eq!(*neuron_id, NeuronId { id: 0xDEAD_BEEF });
                }
                _ => panic!("read returns error other than not found: {:?}", err),
            }
        }

        _ => panic!("read did not return Err: {:?}", read_result),
    }

    // 9. Update again.
    let mut neuron_9 = neuron_5.clone();
    neuron_9.known_neuron_data = None;
    neuron_9.transfer = None;
    assert_eq!(store.update(&neuron_5, neuron_9.clone()), Ok(()));
    assert_that_red_herring_neurons_are_untouched(&store);

    // 10. Read to verify second update.
    assert_eq!(
        store.read(NeuronId { id: 42 }, NeuronSections::all()),
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
                _ => panic!("read returns error other than not found: {:?}", err),
            }
        }

        _ => panic!("second delete did not return Err: {:?}", delete_result),
    }
    assert_that_red_herring_neurons_are_untouched(&store);

    // 13. Read to verify delete.
    let read_result = store.read(NeuronId { id: 42 }, NeuronSections::default());
    match &read_result {
        // This is what we expected.
        Err(err) => {
            // Take a closer look at err.
            match err {
                NeuronStoreError::NeuronNotFound { neuron_id } => {
                    assert_eq!(*neuron_id, NeuronId { id: 42 });
                }
                _ => panic!("read returns error other than not found: {:?}", err),
            }
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
                neuron_read_result.known_neuron_data,
                neuron.known_neuron_data,
            );
        } else {
            assert_eq!(neuron_read_result.known_neuron_data, None);
        }

        if sections.transfer {
            assert_eq!(neuron_read_result.transfer, neuron.transfer);
        } else {
            assert_eq!(neuron_read_result.transfer, None);
        }
    };

    partial_read_test_helper(NeuronSections::default());
    partial_read_test_helper(NeuronSections::all());
    partial_read_test_helper(NeuronSections {
        hot_keys: true,
        ..NeuronSections::default()
    });
    partial_read_test_helper(NeuronSections {
        followees: true,
        ..NeuronSections::default()
    });
    partial_read_test_helper(NeuronSections {
        recent_ballots: true,
        ..NeuronSections::default()
    });
    partial_read_test_helper(NeuronSections {
        known_neuron_data: true,
        ..NeuronSections::default()
    });
    partial_read_test_helper(NeuronSections {
        transfer: true,
        ..NeuronSections::default()
    });
}

#[test]
fn test_abridged_neuron_size() {
    // All VARINT encoded fields (e.g. int32, uint64, ..., as opposed to fixed32/fixed64) have
    // larger serialized size for larger numbers (10 bytes for u64::MAX as uint64, while 1 byte for
    // 0u64). Therefore, we make the numbers below as large as possible even though they aren't
    // realistic.
    let abridged_neuron = AbridgedNeuron {
        account: vec![u8::MAX; 32],
        controller: Some(PrincipalId::new(
            PrincipalId::MAX_LENGTH_IN_BYTES,
            [u8::MAX; PrincipalId::MAX_LENGTH_IN_BYTES],
        )),
        cached_neuron_stake_e8s: u64::MAX,
        neuron_fees_e8s: u64::MAX,
        created_timestamp_seconds: u64::MAX,
        aging_since_timestamp_seconds: u64::MAX,
        spawn_at_timestamp_seconds: Some(u64::MAX),
        kyc_verified: true,
        maturity_e8s_equivalent: u64::MAX,
        staked_maturity_e8s_equivalent: Some(u64::MAX),
        auto_stake_maturity: Some(true),
        not_for_profit: true,
        joined_community_fund_timestamp_seconds: Some(u64::MAX),
        neuron_type: Some(i32::MAX),
        dissolve_state: Some(DissolveState::WhenDissolvedTimestampSeconds(u64::MAX)),
        visibility: None,
    };

    assert!(abridged_neuron.encoded_len() as u32 <= AbridgedNeuron::BOUND.max_size());
    // This size can be updated. This assertion is created so that we are aware of the available
    // headroom.
    assert_eq!(abridged_neuron.encoded_len(), 184);
}
