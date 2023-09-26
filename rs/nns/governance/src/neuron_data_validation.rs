#![allow(dead_code)] // TODO(NNS1-2413): remove after calling it in heartbeat.
use crate::neuron_store::{NeuronStore, NeuronStoreError};

use ic_nns_common::pb::v1::NeuronId;
use std::{collections::VecDeque, marker::PhantomData};

use crate::{pb::v1::Neuron, storage::STABLE_NEURON_STORE};

const MAX_VALIDATION_AGE_SECONDS: u64 = 60 * 60 * 24;

// TODO(NNS1-2413): add actual issues found by validation.
#[derive(Debug, PartialEq)]
enum ValidationIssue {
    Unspecified,
    InactiveNeuronCardinalityMismatch { heap: u64, stable: u64 },
    NeuronCopyValueNotMatch(NeuronId),
    NeuronStoreError(NeuronId, NeuronStoreError),
}

/// A validator for secondary neuron data, such as indexes. It can be called in heartbeat to perform
/// a small chunk of the validation, while keeping track of its progress.
pub struct NeuronDataValidator {
    state: State,
    issues: Issues,
}

// TODO(NNS-2413): add a method to read the status of the in-progress/previous validation result.
impl NeuronDataValidator {
    pub fn new(now: u64) -> Self {
        Self {
            state: State::Validating {
                in_progress: ValidationInProgress::new(now),
                previous_issues: None,
            },
            issues: Issues::new(now),
        }
    }

    /// Validates the indexes in a way that does not incur too much computation (to fit into one
    /// heartbeat). Returns whether some computation intensive work has been done (so that the
    /// heartbeat method have a chance to early return after calling this method).
    pub fn maybe_validate(&mut self, now: u64, neuron_store: &NeuronStore) -> bool {
        let should_restart = match &mut self.state {
            State::Validated() => {
                now > self.issues.updated_time_seconds + MAX_VALIDATION_AGE_SECONDS
            }
            State::Validating { .. } => false,
        };

        if should_restart {
            self.state = State::Validating {
                in_progress: ValidationInProgress::new(now),
                previous_issues: Some(std::mem::replace(&mut self.issues, Issues::new(now))),
            };
        }

        let validation_in_progress = match &mut self.state {
            State::Validating {
                in_progress,
                previous_issues: _,
            } => in_progress,
            State::Validated() => return false,
        };

        let issues = validation_in_progress.validate_next_chunk(neuron_store);
        self.issues.update(now, issues);

        if validation_in_progress.is_done() {
            self.state = State::Validated();
        }

        true
    }
}

/// Validation state.
enum State {
    // No validation is in progress. Storing the validation issues found the last time.
    Validated(),
    // Validation in progress. Also storing the validation issues found the previous time if it exists.
    Validating {
        in_progress: ValidationInProgress,
        previous_issues: Option<Issues>,
    },
}

/// Information related to a validation in progress.
struct ValidationInProgress {
    /// The timestamp when it started.
    started_time_seconds: u64,

    /// Validation tasks that can be performed in chunks.
    tasks: VecDeque<Box<dyn ValidationTask>>,
}

impl ValidationInProgress {
    fn new(now: u64) -> Self {
        let mut tasks: VecDeque<Box<dyn ValidationTask>> = VecDeque::new();
        tasks.push_back(Box::new(NeuronRangeValidationTask::<
            SubaccountIndexValidator,
        >::new(DEFAULT_RANGE_VALIDATION_CHUNK_SIZE)));
        tasks.push_back(Box::new(CardinalitiesValidationTask::<
            SubaccountIndexValidator,
        >::new()));

        tasks.push_back(Box::new(
            NeuronRangeValidationTask::<PrincipalIndexValidator>::new(
                DEFAULT_RANGE_VALIDATION_CHUNK_SIZE,
            ),
        ));
        tasks.push_back(Box::new(CardinalitiesValidationTask::<
            PrincipalIndexValidator,
        >::new()));

        tasks.push_back(Box::new(
            NeuronRangeValidationTask::<FollowingIndexValidator>::new(
                DEFAULT_RANGE_VALIDATION_CHUNK_SIZE,
            ),
        ));
        tasks.push_back(Box::new(CardinalitiesValidationTask::<
            FollowingIndexValidator,
        >::new()));

        tasks.push_back(Box::new(NeuronRangeValidationTask::<
            KnownNeuronIndexValidator,
        >::new(DEFAULT_RANGE_VALIDATION_CHUNK_SIZE)));
        tasks.push_back(Box::new(CardinalitiesValidationTask::<
            KnownNeuronIndexValidator,
        >::new()));

        tasks.push_back(Box::new(NeuronCopyValidator::new(
            DEFAULT_RANGE_VALIDATION_CHUNK_SIZE,
        )));

        Self {
            started_time_seconds: now,
            tasks,
        }
    }

    fn is_done(&self) -> bool {
        self.tasks.is_done()
    }

    fn validate_next_chunk(&mut self, neuron_store: &NeuronStore) -> Vec<ValidationIssue> {
        self.tasks.validate_next_chunk(neuron_store)
    }
}

/// Validation issues.
struct Issues {
    updated_time_seconds: u64,
    issues: Vec<ValidationIssue>,
}

impl Issues {
    fn new(now: u64) -> Self {
        Self {
            updated_time_seconds: now,
            issues: Vec::new(),
        }
    }

    fn update(&mut self, now: u64, mut issues: Vec<ValidationIssue>) {
        self.updated_time_seconds = now;
        self.issues.append(&mut issues);
    }
}

/// A validation task which can be composed of multiple tasks.
trait ValidationTask {
    /// Whether the task has been done. If composed of multiple tasks, whether every subtask is done.
    fn is_done(&self) -> bool;

    /// Performs the next chunk of validation.
    fn validate_next_chunk(&mut self, neuron_store: &NeuronStore) -> Vec<ValidationIssue>;
}

/// A list of tasks should also be a (composed) task.
impl ValidationTask for VecDeque<Box<dyn ValidationTask>> {
    fn is_done(&self) -> bool {
        self.is_empty()
    }

    fn validate_next_chunk(&mut self, neuron_store: &NeuronStore) -> Vec<ValidationIssue> {
        let next_task = match self.front_mut() {
            Some(next_task) => next_task,
            None => return vec![],
        };
        let result = next_task.validate_next_chunk(neuron_store);

        if next_task.is_done() {
            self.pop_front();
        }
        result
    }
}

trait CardinalityAndRangeValidator {
    // TODO(NNS1-2413): define BATCH_SIZE.

    /// Validates the cardinalities of primary data and index to be equal.
    fn validate_cardinalities(neuron_store: &NeuronStore) -> Vec<ValidationIssue>;

    /// Validates that the primary neuron data has corresponding entries in the index.
    fn validate_primary_neuron_has_corresponding_index_entries(
        neuron_id: NeuronId,
        neuron_store: &NeuronStore,
    ) -> Vec<ValidationIssue>;
}

struct CardinalitiesValidationTask<Validator: CardinalityAndRangeValidator> {
    is_done: bool,
    // PhantomData is needed so that CardinalitiesValidationTask can be associated with a Validator
    // type without containing such a member.
    _phantom: PhantomData<Validator>,
}

impl<Validator: CardinalityAndRangeValidator> CardinalitiesValidationTask<Validator> {
    fn new() -> Self {
        Self {
            is_done: false,
            _phantom: PhantomData,
        }
    }
}

impl<Validator: CardinalityAndRangeValidator> ValidationTask
    for CardinalitiesValidationTask<Validator>
{
    fn is_done(&self) -> bool {
        self.is_done
    }

    fn validate_next_chunk(&mut self, neuron_store: &NeuronStore) -> Vec<ValidationIssue> {
        self.is_done = true;
        Validator::validate_cardinalities(neuron_store)
    }
}

struct NeuronRangeValidationTask<Validator: CardinalityAndRangeValidator> {
    next_neuron_id: Option<NeuronId>,
    // PhantomData is needed so that NeuronRangeValidationTask can be associated with a Validator
    // type without containing such a member.
    _phantom: PhantomData<Validator>,
    chunk_size: usize,
}

// TODO this is a randomly selected value, to be empirically tuned.
const DEFAULT_RANGE_VALIDATION_CHUNK_SIZE: usize = 100;

impl<Validator: CardinalityAndRangeValidator> NeuronRangeValidationTask<Validator> {
    fn new(chunk_size: usize) -> Self {
        Self {
            // NeuronId cannot be 0.
            next_neuron_id: Some(NeuronId { id: 1 }),
            _phantom: PhantomData,
            chunk_size,
        }
    }
}

impl<Validator: CardinalityAndRangeValidator> ValidationTask
    for NeuronRangeValidationTask<Validator>
{
    fn is_done(&self) -> bool {
        self.next_neuron_id.is_none()
    }

    fn validate_next_chunk(&mut self, _neuron_store: &NeuronStore) -> Vec<ValidationIssue> {
        // TODO(NNS1-2413): implement the validation logic.
        self.next_neuron_id = None;
        vec![]
    }
}

struct SubaccountIndexValidator;

impl CardinalityAndRangeValidator for SubaccountIndexValidator {
    fn validate_cardinalities(_neuron_store: &NeuronStore) -> Vec<ValidationIssue> {
        // TODO(NNS1-2413): implement the validation logic.
        vec![]
    }

    fn validate_primary_neuron_has_corresponding_index_entries(
        _neuron_id: NeuronId,
        _neuron_store: &NeuronStore,
    ) -> Vec<ValidationIssue> {
        // TODO(NNS1-2413): implement the validation logic.
        vec![]
    }
}

struct PrincipalIndexValidator;

impl CardinalityAndRangeValidator for PrincipalIndexValidator {
    fn validate_cardinalities(_neuron_store: &NeuronStore) -> Vec<ValidationIssue> {
        // TODO(NNS1-2413): implement the validation logic.
        vec![]
    }

    fn validate_primary_neuron_has_corresponding_index_entries(
        _neuron_id: NeuronId,
        _neuron_store: &NeuronStore,
    ) -> Vec<ValidationIssue> {
        // TODO(NNS1-2413): implement the validation logic.
        vec![]
    }
}

struct FollowingIndexValidator;

impl CardinalityAndRangeValidator for FollowingIndexValidator {
    fn validate_cardinalities(_neuron_store: &NeuronStore) -> Vec<ValidationIssue> {
        // TODO(NNS1-2413): implement the validation logic.
        vec![]
    }

    fn validate_primary_neuron_has_corresponding_index_entries(
        _neuron_id: NeuronId,
        _neuron_store: &NeuronStore,
    ) -> Vec<ValidationIssue> {
        // TODO(NNS1-2413): implement the validation logic.
        vec![]
    }
}

struct KnownNeuronIndexValidator;

impl CardinalityAndRangeValidator for KnownNeuronIndexValidator {
    fn validate_cardinalities(_neuron_store: &NeuronStore) -> Vec<ValidationIssue> {
        // TODO(NNS1-2413): implement the validation logic.
        vec![]
    }

    fn validate_primary_neuron_has_corresponding_index_entries(
        _neuron_id: NeuronId,
        _neuron_store: &NeuronStore,
    ) -> Vec<ValidationIssue> {
        // TODO(NNS1-2413): implement the validation logic.
        vec![]
    }
}

/// A validator for all neuron copies for times when they exists in both stable storage
/// and heap.  
/// This validator will not be needed once neurons are only stored in one or the other.
struct NeuronCopyValidator {
    next_neuron_id: Option<NeuronId>,
    chunk_size: usize,
    validated_cardinalities: bool,
}

impl NeuronCopyValidator {
    fn new(chunk_size: usize) -> Self {
        Self {
            next_neuron_id: Some(NeuronId { id: 0 }),
            chunk_size,
            validated_cardinalities: false,
        }
    }

    /// Validate that the expected number of neurons are in stable storage.
    fn validate_cardinalities(neuron_store: &NeuronStore) -> Vec<ValidationIssue> {
        let stable_entry_count =
            STABLE_NEURON_STORE.with(|stable_neuron_store| stable_neuron_store.borrow().len());

        let matching_heap_entries = neuron_store
            .heap_neurons()
            .iter()
            // TODO NNS1-2350 add validation for actual inactive calculation...
            // this may require some refactoring to allow validation tasks to get other parameters?
            // Also, is it worth the complexity since this will be temporary validation?
            .filter(|(_id, neuron)| neuron.cached_neuron_stake_e8s == 0)
            .count();
        // because heap_neurons is a btreemap with u64 as key, it cannot have more than u64 entries
        if stable_entry_count != matching_heap_entries as u64 {
            return vec![ValidationIssue::InactiveNeuronCardinalityMismatch {
                heap: matching_heap_entries as u64,
                stable: stable_entry_count,
            }];
        }

        vec![]
    }

    /// Validate that the neuron in stable storage and heap match exactly.
    fn validate_neuron_matches_in_both_stores(
        stable_neuron: Neuron,
        neuron_store: &NeuronStore,
    ) -> Option<ValidationIssue> {
        let neuron_id = match stable_neuron.id.as_ref() {
            // Should be impossible, as stable_neuron should be coming straight from the store.
            None => return Some(ValidationIssue::Unspecified),
            Some(id) => id,
        };
        match neuron_store.with_neuron(neuron_id, |neuron| {
            if *neuron != stable_neuron {
                Some(ValidationIssue::NeuronCopyValueNotMatch(
                    stable_neuron.id.unwrap(),
                ))
            } else {
                None
            }
        }) {
            Ok(maybe_issue) => maybe_issue,
            Err(neuron_store_error) => Some(ValidationIssue::NeuronStoreError(
                stable_neuron.id.unwrap(),
                neuron_store_error,
            )),
        }
    }
}

impl ValidationTask for NeuronCopyValidator {
    fn is_done(&self) -> bool {
        self.next_neuron_id.is_none()
    }

    fn validate_next_chunk(&mut self, neuron_store: &NeuronStore) -> Vec<ValidationIssue> {
        if !self.validated_cardinalities {
            let issues = Self::validate_cardinalities(neuron_store);
            self.validated_cardinalities = true;
            return issues;
        }

        let next_neuron_id = match self.next_neuron_id.take() {
            Some(next_neuron_id) => next_neuron_id,
            None => return vec![],
        };

        STABLE_NEURON_STORE.with(|stable_neuron_store| {
            let stable_neuron_store = stable_neuron_store.borrow();

            stable_neuron_store
                .range_neurons(next_neuron_id..)
                .take(self.chunk_size)
                .flat_map(|neuron| {
                    // We set the next neuron to the one after this so that if we early return, we start
                    // in the right place.
                    self.next_neuron_id = Some(NeuronId {
                        id: neuron.id.unwrap().id + 1,
                    });
                    Self::validate_neuron_matches_in_both_stores(neuron, neuron_store)
                })
                .collect()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lazy_static::lazy_static;
    use std::{cell::RefCell, collections::BTreeMap};

    use ic_base_types::PrincipalId;
    use maplit::{btreemap, hashmap};

    use crate::pb::v1::{governance::Migration, neuron::Followees, KnownNeuronData, Neuron};

    thread_local! {
        static NEXT_TEST_NEURON_ID: RefCell<u64> = RefCell::new(1);
    }

    lazy_static! {
        // Use MODEL_NEURON for tests where the exact member values are not needed for understanding the
        // test.
        static ref MODEL_NEURON: Neuron = Neuron {
            id: Some(NeuronId { id: 1 }),
            account: vec![1u8; 32],
            controller: Some(PrincipalId::new_user_test_id(1)),
            hot_keys: vec![
                PrincipalId::new_user_test_id(2),
                PrincipalId::new_user_test_id(3),
            ],
            followees: hashmap! {
                1 => Followees{
                    followees: vec![
                        NeuronId { id: 2 },
                        NeuronId { id: 4 },
                        NeuronId { id: 3 },
                    ],
                },
            },
            known_neuron_data: Some(KnownNeuronData {
                name: "known neuron data".to_string(),
                description: None,
            }),

            ..Default::default()
        };
    }

    fn next_test_neuron() -> Neuron {
        let mut neuron = MODEL_NEURON.clone();
        neuron.id = Some(NeuronId {
            id: NEXT_TEST_NEURON_ID.with(|next_test_neuron_id| {
                let mut next_test_neuron_id = next_test_neuron_id.borrow_mut();
                let id = *next_test_neuron_id;
                *next_test_neuron_id += 1;
                id
            }),
        });
        neuron
            .account
            .splice(28..32, neuron.id.unwrap().id.to_le_bytes());
        neuron
    }

    #[test]
    fn test_finish_validation() {
        let neuron_store = NeuronStore::new(
            btreemap! {
                1 => Neuron {
                    id: Some(NeuronId { id: 1 }),
                    account: [1u8; 32].to_vec(),
                    controller: Some(PrincipalId::new_user_test_id(1)),
                    ..Default::default()
                },
            },
            Migration::default(),
        );
        let mut validation = NeuronDataValidator::new(0);

        // Each index use 2 rounds and we have 4 indexes.
        for i in 0..10 {
            assert!(validation.maybe_validate(i, &neuron_store));
        }

        // After 10 rounds it should not validate.
        assert!(!validation.maybe_validate(11, &neuron_store));

        // After 1 day it should validate again.
        assert!(validation.maybe_validate(86411, &neuron_store));
    }

    #[test]
    fn test_neuron_copy_validation_when_valid() {
        let idle_neurons = (0..8).map(|_| next_test_neuron()).collect::<Vec<_>>();

        let mut btree_map: BTreeMap<u64, Neuron> = idle_neurons
            .clone()
            .into_iter()
            .map(|neuron| (neuron.id.unwrap().id, neuron))
            .collect();

        let non_idle = Neuron {
            cached_neuron_stake_e8s: 1000,
            ..next_test_neuron()
        };
        btree_map.insert(non_idle.id.unwrap().id, non_idle);

        let neuron_store = NeuronStore::new(btree_map, Migration::default());

        STABLE_NEURON_STORE.with(|stable_neuron_store| {
            for neuron in idle_neurons {
                stable_neuron_store
                    .borrow_mut()
                    .create(neuron)
                    .expect("Couldn't create");
            }
        });

        let mut validator = NeuronCopyValidator::new(2);

        for _ in 0..5 {
            let defects = validator.validate_next_chunk(&neuron_store);
            assert_eq!(defects, vec![]);
            assert!(!validator.is_done());
        }
        let defects = validator.validate_next_chunk(&neuron_store);
        assert_eq!(defects, vec![]);
        assert!(validator.is_done());
    }

    #[test]
    fn test_neuron_copy_validation_when_bad_neurons() {
        let idle_neurons = (0..8).map(|_| next_test_neuron()).collect::<Vec<_>>();

        let mut btree_map: BTreeMap<u64, Neuron> = idle_neurons
            .clone()
            .into_iter()
            .map(|neuron| (neuron.id.unwrap().id, neuron))
            .collect();

        let non_idle = Neuron {
            cached_neuron_stake_e8s: 1000,
            ..next_test_neuron()
        };
        btree_map.insert(non_idle.id.unwrap().id, non_idle);

        // Create some defects (mismatches)
        btree_map.get_mut(&1).unwrap().cached_neuron_stake_e8s += 1;
        btree_map.get_mut(&2).unwrap().cached_neuron_stake_e8s += 1;
        btree_map.remove(&3);

        let neuron_store = NeuronStore::new(btree_map, Migration::default());

        STABLE_NEURON_STORE.with(|stable_neuron_store| {
            for neuron in idle_neurons {
                stable_neuron_store
                    .borrow_mut()
                    .create(neuron)
                    .expect("Couldn't create");
            }
        });

        let mut validator = NeuronCopyValidator::new(2);

        let defects = validator.validate_next_chunk(&neuron_store);
        assert_eq!(
            defects,
            vec![ValidationIssue::InactiveNeuronCardinalityMismatch { heap: 5, stable: 8 }]
        );

        // Our first 2 entries should be no bueno
        let defects = validator.validate_next_chunk(&neuron_store);
        assert_eq!(
            defects,
            vec![
                ValidationIssue::NeuronCopyValueNotMatch(NeuronId { id: 1 }),
                ValidationIssue::NeuronCopyValueNotMatch(NeuronId { id: 2 })
            ]
        );
        // Our 3rd entry is missing from heap entirely
        let defects = validator.validate_next_chunk(&neuron_store);
        assert_eq!(
            defects,
            vec![ValidationIssue::NeuronStoreError(
                NeuronId { id: 3 },
                NeuronStoreError::not_found(&NeuronId { id: 3 })
            ),]
        );

        // No further issues should be found
        for _ in 0..2 {
            let defects = validator.validate_next_chunk(&neuron_store);
            assert_eq!(defects, vec![]);
            assert!(!validator.is_done());
        }
        let defects = validator.validate_next_chunk(&neuron_store);
        assert_eq!(defects, vec![]);
        assert!(validator.is_done());
    }
}
