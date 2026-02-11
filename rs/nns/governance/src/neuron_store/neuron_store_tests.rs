use super::*;
use crate::{
    neuron::{DissolveStateAndAge, NeuronBuilder},
    pb::v1::{BallotInfo, Followees, KnownNeuronData, MaturityDisbursement},
    storage::{with_stable_neuron_indexes, with_voting_history_store},
};
use ic_nervous_system_common::ONE_MONTH_SECONDS;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use maplit::{btreemap, btreeset, hashmap, hashset};
use pretty_assertions::assert_eq;

// Value is 6 months ahead of when this code was written. For realism, and to
// make sure this is "long" after we release periodic confirmation.
static CREATED_TIMESTAMP_SECONDS: u64 = 1730834058 + 6 * ONE_MONTH_SECONDS;

fn simple_neuron_builder(id: u64) -> NeuronBuilder {
    // Make sure different neurons have different accounts.
    let mut account = vec![0; 32];
    for (destination, data) in account.iter_mut().zip(id.to_le_bytes().iter().cycle()) {
        *destination = *data;
    }

    NeuronBuilder::new(
        NeuronId { id },
        Subaccount::try_from(account.as_slice()).unwrap(),
        PrincipalId::new_user_test_id(id),
        DissolveStateAndAge::NotDissolving {
            dissolve_delay_seconds: 1,
            aging_since_timestamp_seconds: 0,
        },
        CREATED_TIMESTAMP_SECONDS,
    )
}

#[test]
fn test_neuron_add_modify_remove() {
    // Step 1: prepare a neuron and an empty neuron store.
    let neuron = simple_neuron_builder(1)
        .with_cached_neuron_stake_e8s(1)
        .build();
    let neuron_id = neuron.id();
    let mut neuron_store = NeuronStore::new(BTreeMap::new());

    // Step 2: verify that the neuron store is empty and does not contain the neuron.
    assert_eq!(neuron_store.len(), 0);
    assert!(!neuron_store.contains(neuron_id));

    // Step 3: add the neuron into the neuron store.
    assert_eq!(neuron_store.add_neuron(neuron.clone()), Ok(neuron_id));

    // Step 4: verify that the neuron can be read and the neuron store isn't empty anymore.
    assert_eq!(neuron_store.len(), 1);
    assert!(neuron_store.contains(neuron_id));
    let neuron_read_result = neuron_store.with_neuron(&neuron.id(), |neuron| neuron.clone());
    assert_eq!(neuron_read_result, Ok(neuron.clone()));

    // Step 5: modify the neuron.
    assert_eq!(
        neuron_store.with_neuron_mut(&neuron_id, |neuron| neuron.cached_neuron_stake_e8s = 2),
        Ok(())
    );

    // Step 6: verify that the neuron can still be read and the modification took place.
    assert_eq!(neuron_store.len(), 1);
    assert!(neuron_store.contains(neuron_id));
    let neuron_read_result = neuron_store.with_neuron(&neuron.id(), |neuron| neuron.clone());
    let mut expected_neuron = neuron.clone();
    expected_neuron.cached_neuron_stake_e8s = 2;
    assert_eq!(neuron_read_result, Ok(expected_neuron));

    // Step 7: remove the neuron.
    neuron_store.remove_neuron(&neuron_id);

    // Step 8: verify the neuron store is empty again and the neuron cannot be read anymore.
    assert_eq!(neuron_store.len(), 0);
    assert!(!neuron_store.contains(neuron_id));
    let neuron_read_result = neuron_store.with_neuron(&neuron.id(), |neuron| neuron.clone());
    assert_eq!(
        neuron_read_result,
        Err(NeuronStoreError::not_found(neuron_id))
    );
}

#[test]
fn test_add_neuron_update_indexes() {
    // Step 1: prepare the neuron and neuron store.
    let mut neuron_store = NeuronStore::new(btreemap! {
        1 => simple_neuron_builder(1).build(),
    });

    // Step 2: adds a new neuron into neuron store.
    let neuron_2 = simple_neuron_builder(2).build();
    neuron_store.add_neuron(neuron_2.clone()).unwrap();

    // Step 3: verifies that the indexes can be looked up for the new neuron.
    let neuron_id_found_by_subaccount_index = with_stable_neuron_indexes(|indexes| {
        indexes
            .subaccount()
            .get_neuron_id_by_subaccount(&neuron_2.subaccount())
            .unwrap()
    });
    assert_eq!(neuron_id_found_by_subaccount_index, neuron_2.id());

    let expected_account_id =
        AccountIdentifier::new(GOVERNANCE_CANISTER_ID.get(), Some(neuron_2.subaccount()));
    let neuron_id_found_by_account_id_index = with_stable_neuron_indexes(|indexes| {
        indexes
            .account_id()
            .get_neuron_id_by_account_id(&expected_account_id)
            .unwrap()
    });
    assert_eq!(neuron_id_found_by_account_id_index, neuron_2.id());
}

#[test]
fn test_remove_neuron_update_indexes() {
    // Step 1: prepare the neuron and neuron store.
    let neuron = simple_neuron_builder(1).build();
    let mut neuron_store = NeuronStore::new(btreemap! {
        neuron.id().id => neuron.clone(),
    });

    // Step 2: removes the neuron from neuron store.
    neuron_store.remove_neuron(&neuron.id());

    // Step 3: verifies that the neuron has also been removed from the subaccount index.
    let neuron_id_found_by_subaccount_index = with_stable_neuron_indexes(|indexes| {
        indexes
            .subaccount()
            .get_neuron_id_by_subaccount(&neuron.subaccount())
    });
    assert_eq!(neuron_id_found_by_subaccount_index, None);

    let expected_account_id =
        AccountIdentifier::new(GOVERNANCE_CANISTER_ID.get(), Some(neuron.subaccount()));
    let neuron_id_found_by_account_id_index = with_stable_neuron_indexes(|indexes| {
        indexes
            .account_id()
            .get_neuron_id_by_account_id(&expected_account_id)
    });
    assert_eq!(neuron_id_found_by_account_id_index, None);
}

#[test]
fn test_modify_neuron_update_indexes() {
    // Step 1: prepare the neuron and neuron store.
    let neuron = simple_neuron_builder(1)
        .with_controller(PrincipalId::new_user_test_id(1))
        .build();
    let mut neuron_store = NeuronStore::new(btreemap! {
        neuron.id().id => neuron.clone(),
    });

    // Step 2: modifies the controller of the neuron.
    neuron_store
        .with_neuron_mut(&neuron.id(), |neuron| {
            neuron.set_controller(PrincipalId::new_user_test_id(2));
        })
        .unwrap();

    // Step 3: verifies that the neuron can be looked up by the neuron controller but not the old one.
    let neuron_ids_found_by_new_controller = with_stable_neuron_indexes(|indexes| {
        indexes
            .principal()
            .get_neuron_ids(PrincipalId::new_user_test_id(2))
    });
    assert_eq!(neuron_ids_found_by_new_controller, hashset! {neuron.id()});
    let neuron_ids_found_by_old_controller = with_stable_neuron_indexes(|indexes| {
        indexes
            .principal()
            .get_neuron_ids(PrincipalId::new_user_test_id(1))
    });
    assert_eq!(neuron_ids_found_by_old_controller, hashset! {});
}

#[test]
fn test_add_neurons() {
    // Step 1.1: create neuron store with no neurons.
    let mut neuron_store = NeuronStore::new(BTreeMap::new());

    // Step 1.1: set up 1 active neuron and 1 inactive neuron.
    let now = neuron_store.now();
    let active_neuron = active_neuron_builder(1, now).build();
    let inactive_neuron = inactive_neuron_builder(2).build();

    // Step 2: add both neurons into neuron store.
    neuron_store.add_neuron(active_neuron.clone()).unwrap();
    neuron_store.add_neuron(inactive_neuron.clone()).unwrap();

    // Step 3.1: verify that the active neuron is in the heap, not in the stable neuron store, and
    // can be read.
    assert!(is_neuron_in_stable(active_neuron.id()));
    let active_neuron_read_result =
        neuron_store.with_neuron(&active_neuron.id(), |neuron| neuron.clone());
    assert_eq!(active_neuron_read_result, Ok(active_neuron.clone()));

    // Step 3.2: verify that inactive neuron is in the stable neuron store, not in the heap, and can
    // be read.
    assert!(is_neuron_in_stable(inactive_neuron.id()));
    let inactive_neuron_read_result =
        neuron_store.with_neuron(&inactive_neuron.id(), |neuron| neuron.clone());
    assert_eq!(inactive_neuron_read_result, Ok(inactive_neuron.clone()));

    // Step 3.3: verify that the inactive neuron can also be read from neuron store.
    let inactive_neuron_in_neuron_store =
        neuron_store.with_neuron(&inactive_neuron.id(), |neuron| neuron.clone());
    assert_eq!(inactive_neuron_in_neuron_store, Ok(inactive_neuron.clone()));
}

#[test]
fn test_remove_inactive_neuron() {
    // Step 1.1: set up 1 active neuron and 1 inactive neuron.
    let inactive_neuron = inactive_neuron_builder(1).build();

    // Step 1.2: create neuron store with no neurons.
    let mut neuron_store = NeuronStore::new(BTreeMap::new());

    // Step 1.3: add the inactive neuron into neuron store and verifies it's in the stable neuron store.
    neuron_store.add_neuron(inactive_neuron.clone()).unwrap();
    assert!(is_neuron_in_stable(inactive_neuron.id()));
    let inactive_neuron_read_result =
        neuron_store.with_neuron(&inactive_neuron.id(), |neuron| neuron.clone());
    assert_eq!(inactive_neuron_read_result, Ok(inactive_neuron.clone()));

    // Step 2: remove the neuron from neuron store.
    neuron_store.remove_neuron(&inactive_neuron.id());

    // Step 3: verify that inactive neuron cannot be read from stable neuron store anymore.
    let inactive_neuron_read_result =
        neuron_store.with_neuron(&inactive_neuron.id(), |neuron| neuron.clone());
    match inactive_neuron_read_result {
        Ok(_) => panic!("Inactive neuron failed to be removed from stable neuron store"),
        Err(error) => match error {
            NeuronStoreError::NeuronNotFound { neuron_id } => {
                assert_eq!(neuron_id, inactive_neuron.id());
            }
            _ => panic!("read returns error other than not found: {error:?}"),
        },
    }
}

#[test]
fn test_neuron_store_new_then_restore() {
    // Step 1: create a NeuronStore for the first time with 10 neurons with following.
    let neurons: BTreeMap<_, _> = (0..10)
        .map(|i| {
            let neuron = simple_neuron_builder(i)
                .with_followees(hashmap! {
                    Topic::Governance as i32 => Followees {
                        followees: vec![NeuronId { id: 10 }],
                    }
                })
                .build();
            (i, neuron)
        })
        .collect();
    let neuron_store = NeuronStore::new(neurons.clone());

    // Step 2: verify the neurons and followee index are in the neuron store.
    for neuron in neurons.values() {
        assert_eq!(
            neuron_store
                .with_neuron(&neuron.id(), |neuron| neuron.clone())
                .unwrap(),
            neuron.clone()
        );
    }
    assert_eq!(
        neuron_store
            .get_followers_by_followee_and_topic(NeuronId { id: 10 }, Topic::Governance)
            .len(),
        10
    );

    // Step 3: take its state and restore from it.
    let restored_neuron_store = NeuronStore::new_restored();

    // Step 4: verify again the neurons and followee index are in the restored neuron store.
    for neuron in neurons.values() {
        assert_eq!(
            restored_neuron_store
                .with_neuron(&neuron.id(), |neuron| neuron.clone())
                .unwrap(),
            neuron.clone(),
        );
    }
    assert_eq!(
        restored_neuron_store
            .get_followers_by_followee_and_topic(NeuronId { id: 10 }, Topic::Governance)
            .len(),
        10
    );
}

// Below are tests related to how the neurons are stored, which look at the internals of the neuron
// store. They should probably be cleaned up after the inactive neuron migration since it's better
// to test through its public API.

fn active_neuron_builder(id: u64, now: u64) -> NeuronBuilder {
    simple_neuron_builder(id)
        .with_cached_neuron_stake_e8s(0)
        .with_dissolve_state_and_age(DissolveStateAndAge::DissolvingOrDissolved {
            when_dissolved_timestamp_seconds: now,
        })
}

fn inactive_neuron_builder(id: u64) -> NeuronBuilder {
    simple_neuron_builder(id)
        .with_cached_neuron_stake_e8s(0)
        .with_dissolve_state_and_age(DissolveStateAndAge::DissolvingOrDissolved {
            when_dissolved_timestamp_seconds: 1,
        })
}

fn is_neuron_in_stable(neuron_id: NeuronId) -> bool {
    with_stable_neuron_store(|stable_neuron_store| stable_neuron_store.contains(neuron_id))
}

#[test]
fn test_get_followers_by_followee_and_topic() {
    let neuron = simple_neuron_builder(1)
        .with_followees(hashmap! {
            Topic::Unspecified as i32 => Followees {
                followees: vec![NeuronId { id: 2 }, NeuronId { id: 3 }],
            }
        })
        .build();
    let neuron_store = NeuronStore::new(btreemap! {
        1 => neuron,
    });
    assert_eq!(
        neuron_store.get_followers_by_followee_and_topic(NeuronId { id: 2 }, Topic::Unspecified),
        vec![NeuronId { id: 1 }]
    );
    assert_eq!(
        neuron_store.get_followers_by_followee_and_topic(NeuronId { id: 2 }, Topic::Governance),
        vec![]
    );
}

#[test]
fn test_get_neuron_ids_readable_by_caller() {
    let neuron = simple_neuron_builder(1)
        .with_controller(PrincipalId::new_user_test_id(1))
        .with_hot_keys(vec![
            PrincipalId::new_user_test_id(2),
            PrincipalId::new_user_test_id(3),
        ])
        .build();
    let neuron_store = NeuronStore::new(btreemap! {
        1 => neuron,
    });
    for i in 1..=3 {
        assert_eq!(
            neuron_store.get_neuron_ids_readable_by_caller(PrincipalId::new_user_test_id(i)),
            btreeset! { NeuronId { id: 1 } }
        );
    }
    assert_eq!(
        neuron_store.get_neuron_ids_readable_by_caller(PrincipalId::new_user_test_id(4)),
        btreeset! {}
    );
}

/// Creates a MaturityDisbursement with the given finalize_disbursement_timestamp_seconds. Note that
/// other values are default and not realistic, but at the leve l of `NeuronStore`, we don't care
/// about them.
fn create_maturity_disbursement(
    finalize_disbursement_timestamp_seconds: u64,
) -> MaturityDisbursement {
    MaturityDisbursement {
        finalize_disbursement_timestamp_seconds,
        ..Default::default()
    }
}

#[test]
fn test_maturity_disbursement_index() {
    // Set up 2 neurons with no maturity disbursements.
    let mut neuron_store = NeuronStore::new(btreemap! {
        1 => simple_neuron_builder(1).build(),
        2 => simple_neuron_builder(2).build(),
    });

    // No neurons should be ready to finalize maturity disbursement, and the next maturity disbursement doesn't exist.
    assert_eq!(
        neuron_store.get_neuron_ids_ready_to_finalize_maturity_disbursement(0),
        btreeset! {}
    );
    assert_eq!(neuron_store.get_next_maturity_disbursement(), None);

    // Add 2 disbursements for neuron 1 (finalizing at t = 1 and t = 2), and add 1 disbursement for
    // neuron 2 finalizing at t = 2.
    neuron_store
        .with_neuron_mut(&NeuronId::from_u64(1), |neuron| {
            neuron.add_maturity_disbursement_in_progress(create_maturity_disbursement(1));
            neuron.add_maturity_disbursement_in_progress(create_maturity_disbursement(2));
        })
        .unwrap();
    neuron_store
        .with_neuron_mut(&NeuronId::from_u64(2), |neuron| {
            neuron.add_maturity_disbursement_in_progress(create_maturity_disbursement(2));
        })
        .unwrap();

    // At t = 0, no neurons are ready to finalize maturity disbursement, and the next maturity
    // disbursement is at t = 1.
    assert_eq!(
        neuron_store.get_neuron_ids_ready_to_finalize_maturity_disbursement(0),
        btreeset! {}
    );
    assert_eq!(
        neuron_store.get_next_maturity_disbursement(),
        Some((1, NeuronId::from_u64(1)))
    );

    // At t = 1, neuron 1 is ready to finalize maturity disbursement, and the next maturity.
    assert_eq!(
        neuron_store.get_neuron_ids_ready_to_finalize_maturity_disbursement(1),
        btreeset! {NeuronId::from_u64(1)}
    );
    // At t = 2, both neurons are ready to finalize maturity disbursement.
    assert_eq!(
        neuron_store.get_neuron_ids_ready_to_finalize_maturity_disbursement(2),
        btreeset! {NeuronId::from_u64(1), NeuronId::from_u64(2)}
    );

    // After removing the first disbursement for neuron 1, no neurons are ready to finalize
    // disbursement at t = 1, but both are still ready at t = 2. The next maturity
    // disbursement becomes t = 2.
    neuron_store
        .with_neuron_mut(&NeuronId::from_u64(1), |neuron| {
            neuron.pop_maturity_disbursement_in_progress().unwrap();
        })
        .unwrap();
    assert_eq!(
        neuron_store.get_neuron_ids_ready_to_finalize_maturity_disbursement(1),
        btreeset! {}
    );
    assert_eq!(
        neuron_store.get_neuron_ids_ready_to_finalize_maturity_disbursement(2),
        btreeset! {NeuronId::from_u64(1), NeuronId::from_u64(2)}
    );
    assert_eq!(
        neuron_store.get_next_maturity_disbursement(),
        Some((2, NeuronId::from_u64(1)))
    );

    // After removing the second disbursement for neuron 2, neuron 1 is the only one ready to
    // finalize disbursement at t = 2.
    neuron_store
        .with_neuron_mut(&NeuronId::from_u64(2), |neuron| {
            neuron.pop_maturity_disbursement_in_progress().unwrap();
        })
        .unwrap();
    assert_eq!(
        neuron_store.get_neuron_ids_ready_to_finalize_maturity_disbursement(2),
        btreeset! {NeuronId::from_u64(1)}
    );

    // After removing the last disbursement for neuron 1, no neurons are ready to finalize
    // disbursement at t = 2. The next maturity disbursement becomes None.
    neuron_store
        .with_neuron_mut(&NeuronId::from_u64(1), |neuron| {
            neuron.pop_maturity_disbursement_in_progress().unwrap();
        })
        .unwrap();
    assert_eq!(
        neuron_store.get_neuron_ids_ready_to_finalize_maturity_disbursement(2),
        btreeset! {}
    );
    assert_eq!(neuron_store.get_next_maturity_disbursement(), None);
}

#[test]
fn test_prune_some_following_standard_voting_power_refresh_requirements() {
    // Step 1: Prepare the world.

    let followees = hashmap! {
        Topic::Governance as i32 => Followees {
            followees: vec![NeuronId { id: 99 }],
        },
        Topic::NeuronManagement as i32 => Followees {
            followees: vec![NeuronId { id: 101 }],
        },
    };

    let mut fresh_neuron = simple_neuron_builder(1)
        .with_followees(followees.clone())
        .build();
    fresh_neuron.refresh_voting_power(CREATED_TIMESTAMP_SECONDS - 7 * ONE_MONTH_SECONDS + 1);

    // Similar to fresh_neuron, except voting power was refrshed a "long" time
    // ago.
    let mut stale_neuron = simple_neuron_builder(3)
        .with_followees(followees.clone())
        .build();
    stale_neuron.refresh_voting_power(CREATED_TIMESTAMP_SECONDS - 7 * ONE_MONTH_SECONDS - 1);

    let mut neuron_store = NeuronStore::new(btreemap! {
        fresh_neuron.id().id => fresh_neuron.clone(),
        stale_neuron.id().id => stale_neuron.clone(),
    });

    // Control the perception of time by neuron_store.
    #[derive(Debug, Clone)]
    struct DummyClock {}
    impl Clock for DummyClock {
        fn now(&self) -> u64 {
            CREATED_TIMESTAMP_SECONDS
        }

        fn set_time_warp(&mut self, _: TimeWarp) {
            unimplemented!();
        }
    }
    impl PracticalClock for DummyClock {}
    let clock = DummyClock {};
    neuron_store.clock = Box::new(clock);

    // Step 2: Call code under test.

    // Stop after the second neuron is processed.
    let mut neuron_count = 0;
    let carry_on = || {
        neuron_count += 1;
        neuron_count < 2
    };

    assert_eq!(
        prune_some_following(
            &VotingPowerEconomics::DEFAULT,
            &mut neuron_store,
            Bound::Unbounded,
            carry_on
        ),
        Bound::Excluded(stale_neuron.id()),
    );
    assert_eq!(neuron_count, 2);

    // Do the next batch (which is empty). What we want to see is that
    // prune_some_following "loops back around". More concretely, it should
    // return Bound::Unbounded.
    let mut call_count = 0;
    let carry_on = || {
        call_count += 1;
        true
    };
    assert_eq!(
        prune_some_following(
            &VotingPowerEconomics::DEFAULT,
            &mut neuron_store,
            Bound::Excluded(stale_neuron.id()),
            carry_on,
        ),
        Bound::Unbounded,
    );
    // Because after teh stale neuron, there are no more neurons. In that case
    // prune_some_following tells us to loop back around.
    assert_eq!(call_count, 0);

    // Step 3: Inspect results.

    // Assert that fresh neuron did not change.
    neuron_store
        .with_neuron(&fresh_neuron.id(), |fresh_neuron| {
            assert_eq!(fresh_neuron.followees, followees);
        })
        .unwrap();

    // Assert that the stale neuron did in fact change.
    neuron_store
        .with_neuron(&stale_neuron.id(), |stale_neuron| {
            assert_eq!(
                stale_neuron.followees,
                hashmap! {
                    // Governance got wiped out.

                    // NeuronManagement did not get touched.
                    Topic::NeuronManagement as i32 => Followees {
                        followees: vec![NeuronId { id: 101 }],
                    },
                },
            );
        })
        .unwrap();

    assert_eq!(neuron_store.len(), 2);
}

/// This shows that VotingPowerEconomics is used when pruning following, not the
/// old constant(s).
#[test]
fn test_prune_some_following_super_strict_voting_power_refresh() {
    // Step 1: Prepare the world. (This is exactly the same as the previous test.)

    let followees = hashmap! {
        Topic::Governance as i32 => Followees {
            followees: vec![NeuronId { id: 99 }],
        },
        Topic::NeuronManagement as i32 => Followees {
            followees: vec![NeuronId { id: 101 }],
        },
    };

    let mut fresh_neuron = simple_neuron_builder(1)
        .with_followees(followees.clone())
        .build();
    fresh_neuron.refresh_voting_power(CREATED_TIMESTAMP_SECONDS - 7 * ONE_MONTH_SECONDS + 1);

    // Similar to fresh_neuron, except voting power was refrshed a "long" time
    // ago.
    let mut stale_neuron = simple_neuron_builder(3)
        .with_followees(followees.clone())
        .build();
    stale_neuron.refresh_voting_power(CREATED_TIMESTAMP_SECONDS - 7 * ONE_MONTH_SECONDS - 1);

    let mut neuron_store = NeuronStore::new(btreemap! {
        fresh_neuron.id().id => fresh_neuron.clone(),
        stale_neuron.id().id => stale_neuron.clone(),
    });

    // Control the perception of time by neuron_store.
    #[derive(Debug, Clone)]
    struct DummyClock {}
    impl Clock for DummyClock {
        fn now(&self) -> u64 {
            CREATED_TIMESTAMP_SECONDS
        }

        fn set_time_warp(&mut self, _: TimeWarp) {
            unimplemented!();
        }
    }
    impl PracticalClock for DummyClock {}
    let clock = DummyClock {};
    neuron_store.clock = Box::new(clock);

    // Step 2: Call code under test. (This is where things start looking
    // different, compared to the previous test.)

    assert_eq!(
        prune_some_following(
            &VotingPowerEconomics {
                // These are much smaller than the normal values. As a result, all
                // neurons suddenly look stale. As a result, all following is
                // supposed to be cleared.
                start_reducing_voting_power_after_seconds: Some(42),
                clear_following_after_seconds: Some(58),
                neuron_minimum_dissolve_delay_to_vote_seconds: Some(42)
            },
            &mut neuron_store,
            Bound::Unbounded, // Start new cycle.
            || true,          // Do a full cycle.
        ),
        Bound::Unbounded,
    );

    // Step 3: Inspect results.

    // Assert that everyone's following got cleared, due to super strict
    // VotingPowerEconomics.
    for neuron_id in [fresh_neuron.id(), stale_neuron.id()] {
        neuron_store
            .with_neuron(&neuron_id, |observed_neuron| {
                assert_eq!(
                    observed_neuron.followees,
                    hashmap! {
                        // Governance got wiped out.

                        // NeuronManagement did not get touched.
                        Topic::NeuronManagement as i32 => Followees {
                            followees: vec![NeuronId { id: 101 }],
                        },
                    },
                );
            })
            .unwrap();
    }

    assert_eq!(neuron_store.len(), 2);
}

#[test]
fn test_get_non_empty_neuron_ids_readable_by_caller() {
    // Prepare the neurons.
    let controller = PrincipalId::new_user_test_id(1);
    let hot_key = PrincipalId::new_user_test_id(2);
    let neuron_builder = |i| {
        simple_neuron_builder(i)
            .with_controller(controller)
            .with_hot_keys(vec![hot_key])
    };
    let neuron_empty = neuron_builder(1).build();
    let neuron_empty_with_fees = neuron_builder(2)
        .with_cached_neuron_stake_e8s(1)
        .with_neuron_fees_e8s(1)
        .build();
    let neuron_with_stake = neuron_builder(3).with_cached_neuron_stake_e8s(1).build();
    let neuron_with_maturity = neuron_builder(4).with_maturity_e8s_equivalent(1).build();
    let neuron_with_staked_maturity = neuron_builder(5)
        .with_staked_maturity_e8s_equivalent(1)
        .build();
    let neuron_with_maturity_disbursement = neuron_builder(6)
        .with_maturity_disbursements_in_progress(vec![MaturityDisbursement {
            finalize_disbursement_timestamp_seconds: 1,
            ..Default::default()
        }])
        .build();
    let neuron_store = NeuronStore::new(btreemap! {
        1 => neuron_empty,
        2 => neuron_empty_with_fees,
        3 => neuron_with_stake,
        4 => neuron_with_maturity,
        5 => neuron_with_staked_maturity,
        6 => neuron_with_maturity_disbursement,
    });

    assert_eq!(
        neuron_store.get_non_empty_neuron_ids_readable_by_caller(controller),
        btreeset! { 3, 4, 5, 6 }
            .into_iter()
            .map(NeuronId::from_u64)
            .collect()
    );
    assert_eq!(
        neuron_store.get_non_empty_neuron_ids_readable_by_caller(hot_key),
        btreeset! { 3, 4, 5, 6 }
            .into_iter()
            .map(NeuronId::from_u64)
            .collect()
    );
    assert_eq!(
        neuron_store.get_non_empty_neuron_ids_readable_by_caller(PrincipalId::new_user_test_id(3)),
        btreeset! {}
    );
}

#[test]
fn test_unstake_maturity() {
    let mut neuron_store = NeuronStore::new(BTreeMap::new());
    let now_seconds = neuron_store.now();
    for id in 1..=5 {
        let neuron = simple_neuron_builder(id)
            .with_dissolve_state_and_age(DissolveStateAndAge::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds: now_seconds,
            })
            .with_staked_maturity_e8s_equivalent(1_000_000)
            .build();
        neuron_store.add_neuron(neuron).unwrap();
    }

    let neuron_has_staked_maturity = |neuron_store: &NeuronStore, id: u64| {
        neuron_store
            .with_neuron(&NeuronId { id }, |neuron| {
                neuron.staked_maturity_e8s_equivalent.is_some()
            })
            .unwrap()
    };

    // Initially all neurons have staked maturity.
    for id in 1..=5 {
        assert!(neuron_has_staked_maturity(&neuron_store, id));
    }

    // Unstake the maturity of the first 3 neurons.
    neuron_store.unstake_maturity_of_dissolved_neurons(now_seconds, 3);

    // Verify that the first 3 neurons have no staked maturity, while the rest do.
    for id in 1..=3 {
        assert!(!neuron_has_staked_maturity(&neuron_store, id));
    }
    for id in 4..=5 {
        assert!(neuron_has_staked_maturity(&neuron_store, id));
    }

    // Unstake the maturity of the remaining neurons.
    neuron_store.unstake_maturity_of_dissolved_neurons(now_seconds, 3);

    // Verify that all neurons have no staked maturity.
    for id in 1..=5 {
        assert!(!neuron_has_staked_maturity(&neuron_store, id));
    }
}

#[test]
fn test_get_full_neuron() {
    let principal_id = PrincipalId::new_user_test_id(42);
    let neuron_controlled = simple_neuron_builder(1)
        .with_controller(principal_id)
        .build();
    let neuron_readable_by_hot_key = simple_neuron_builder(2)
        .with_hot_keys(vec![principal_id])
        .build();
    let neuron_managed_1 = simple_neuron_builder(3)
        .with_followees(hashmap! {
            Topic::NeuronManagement as i32 => Followees {
                followees: vec![neuron_controlled.id()],
            }
        })
        .build();
    let neuron_managed_2 = simple_neuron_builder(4)
        .with_followees(hashmap! {
            Topic::NeuronManagement as i32 => Followees {
                followees: vec![neuron_readable_by_hot_key.id()],
            }
        })
        .build();
    // This neuron followes a neuron controlled by the principal on a different topic than
    // NeuronManagement, and therefore not considered being managed by the controlled neuron.
    let neuron_not_managed = simple_neuron_builder(5)
        .with_followees(hashmap! {
            Topic::Governance as i32 => Followees {
                followees: vec![neuron_controlled.id()],
            }
        })
        .build();
    let neuron_store = NeuronStore::new(btreemap! {
        neuron_controlled.id().id => neuron_controlled.clone(),
        neuron_readable_by_hot_key.id().id => neuron_readable_by_hot_key.clone(),
        neuron_managed_1.id().id => neuron_managed_1.clone(),
        neuron_managed_2.id().id => neuron_managed_2.clone(),
        neuron_not_managed.id().id => neuron_not_managed.clone(),
    });

    assert_eq!(
        neuron_store.get_full_neuron(neuron_controlled.id(), principal_id),
        Ok(neuron_controlled)
    );
    assert_eq!(
        neuron_store.get_full_neuron(neuron_readable_by_hot_key.id(), principal_id),
        Ok(neuron_readable_by_hot_key)
    );
    assert_eq!(
        neuron_store.get_full_neuron(neuron_managed_1.id(), principal_id),
        Ok(neuron_managed_1)
    );
    assert_eq!(
        neuron_store.get_full_neuron(neuron_managed_2.id(), principal_id),
        Ok(neuron_managed_2)
    );

    assert!(neuron_store.contains(neuron_not_managed.id()));

    assert_eq!(
        neuron_store.get_full_neuron(neuron_not_managed.id(), principal_id),
        Err(NeuronStoreError::NotAuthorizedToGetFullNeuron {
            neuron_id: neuron_not_managed.id(),
            principal_id,
        })
    );
}

#[test]
fn test_approve_genesis_kyc() {
    let principal_1 = PrincipalId::new_self_authenticating(b"SID1");
    let principal_2 = PrincipalId::new_self_authenticating(b"SID2");
    let principal_3 = PrincipalId::new_self_authenticating(b"SID3");
    let neuron_1 = simple_neuron_builder(1)
        .with_controller(principal_1)
        .with_kyc_verified(false)
        .build();
    let neuron_2 = simple_neuron_builder(2)
        .with_controller(principal_2)
        .with_kyc_verified(false)
        .build();
    let neuron_3 = simple_neuron_builder(3)
        .with_controller(principal_2)
        .with_kyc_verified(false)
        .build();
    let neuron_4 = simple_neuron_builder(4)
        .with_controller(principal_3)
        .with_kyc_verified(false)
        .build();
    let mut neuron_store = NeuronStore::new(btreemap! {
        neuron_1.id().id => neuron_1.clone(),
        neuron_2.id().id => neuron_2.clone(),
        neuron_3.id().id => neuron_3.clone(),
        neuron_4.id().id => neuron_4.clone(),
    });
    // Before calling `approve_genesis_kyc`, none of the neurons have KYC verified.
    assert!(
        !neuron_store
            .with_neuron(&neuron_1.id(), |n| n.kyc_verified)
            .unwrap()
    );
    assert!(
        !neuron_store
            .with_neuron(&neuron_2.id(), |n| n.kyc_verified)
            .unwrap()
    );
    assert!(
        !neuron_store
            .with_neuron(&neuron_3.id(), |n| n.kyc_verified)
            .unwrap()
    );
    assert!(
        !neuron_store
            .with_neuron(&neuron_4.id(), |n| n.kyc_verified)
            .unwrap()
    );

    // Approve KYC for neuron_1, neuron_2 and neuron_3.
    approve_genesis_kyc(&mut neuron_store, &[principal_1, principal_2]).unwrap();

    assert!(
        neuron_store
            .with_neuron(&neuron_1.id(), |n| n.kyc_verified)
            .unwrap()
    );
    assert!(
        neuron_store
            .with_neuron(&neuron_2.id(), |n| n.kyc_verified)
            .unwrap()
    );
    assert!(
        neuron_store
            .with_neuron(&neuron_3.id(), |n| n.kyc_verified)
            .unwrap()
    );
    assert!(
        !neuron_store
            .with_neuron(&neuron_4.id(), |n| n.kyc_verified)
            .unwrap()
    );
}

// Prepares `num_neurons_same_controller` neurons with the same controller and
// `num_neurons_diff_controllers` neurons with different controllers.
fn prepare_neurons_for_kyc(
    num_neurons_same_controller: u64,
    num_neurons_diff_controllers: u64,
) -> (Vec<Neuron>, Vec<PrincipalId>) {
    let mut neurons = Vec::new();
    let principal_id = PrincipalId::new_self_authenticating(b"SID");
    let mut principal_ids = hashset! { principal_id };
    for id in 1..=num_neurons_same_controller {
        let neuron = simple_neuron_builder(id)
            .with_controller(principal_id)
            .with_kyc_verified(false)
            .build();
        neurons.push(neuron);
    }
    for id in (num_neurons_same_controller + 1)
        ..=(num_neurons_same_controller + num_neurons_diff_controllers)
    {
        let neuron = simple_neuron_builder(id).with_kyc_verified(false).build();
        principal_ids.insert(neuron.controller());
        neurons.push(neuron);
    }
    (neurons, principal_ids.into_iter().collect())
}

#[test]
fn test_approve_genesis_kyc_cap_not_exceeded() {
    let mut neuron_store = NeuronStore::new(BTreeMap::new());
    // Set up 1000 neurons that should be KYC verified.
    let (neurons, principal_ids) = prepare_neurons_for_kyc(500, 500);
    for neuron in &neurons {
        neuron_store.add_neuron(neuron.clone()).unwrap();
    }
    // Set up a neuron that should not be KYC verified.
    let neuron_should_not_have_kyc_verified =
        simple_neuron_builder(1001).with_kyc_verified(false).build();
    neuron_store
        .add_neuron(neuron_should_not_have_kyc_verified.clone())
        .unwrap();

    // Approve KYC for 1000 neurons.
    approve_genesis_kyc(&mut neuron_store, &principal_ids).unwrap();

    // All 1000 neurons should have KYC verified.
    for neuron in &neurons {
        assert!(
            neuron_store
                .with_neuron(&neuron.id(), |n| n.kyc_verified)
                .unwrap()
        );
    }

    // The neuron with id 1001 should not have KYC verified.
    assert!(
        !neuron_store
            .with_neuron(&neuron_should_not_have_kyc_verified.id(), |n| n
                .kyc_verified)
            .unwrap()
    );
}

#[test]
fn test_approve_genesis_kyc_cap_exceeded() {
    let mut neuron_store = NeuronStore::new(BTreeMap::new());
    let (neurons, principal_ids) = prepare_neurons_for_kyc(500, 501);
    for neuron in &neurons {
        neuron_store.add_neuron(neuron.clone()).unwrap();
    }

    // Approve KYC for 1001 neurons.
    let result = approve_genesis_kyc(&mut neuron_store, &principal_ids);
    assert_eq!(
        result,
        Err(GovernanceError::new_with_message(
            ErrorType::PreconditionFailed,
            "ApproveGenesisKyc can only change the KYC status of up to 1000 neurons at a time",
        ),)
    );

    // None of the neurons should have KYC verified.
    for neuron in &neurons {
        assert!(
            !neuron_store
                .with_neuron(&neuron.id(), |n| n.kyc_verified)
                .unwrap()
        );
    }
}

#[test]
fn test_record_neuron_vote() {
    let mut neuron_store = NeuronStore::new(BTreeMap::new());
    let neuron = simple_neuron_builder(1)
        .with_known_neuron_data(Some(KnownNeuronData {
            name: "my known neuron".to_string(),
            description: Some("my known neuron description".to_string()),
            links: vec![],
            committed_topics: vec![],
        }))
        .build();
    let neuron_id = neuron_store.add_neuron(neuron).unwrap();

    neuron_store
        .record_neuron_vote(
            neuron_id,
            Topic::NetworkEconomics,
            ProposalId { id: 1 },
            Vote::Yes,
        )
        .unwrap();

    let recent_ballots = neuron_store
        .with_neuron(&neuron_id, |n| n.recent_ballots.clone())
        .unwrap();
    assert_eq!(
        recent_ballots,
        vec![BallotInfo {
            proposal_id: Some(ProposalId { id: 1 }),
            vote: Vote::Yes as i32,
        }]
    );

    let voting_history = with_voting_history_store(|voting_history| {
        voting_history.list_neuron_votes(neuron_id, None, Some(10))
    });
    assert_eq!(voting_history, vec![(ProposalId { id: 1 }, Vote::Yes)]);
}
