use crate::{
    neuron_store::{get_neuron_subaccount, NeuronStore, NeuronStoreError},
    pb::v1::{Neuron, Topic},
    storage::{Signed32, NEURON_INDEXES, STABLE_NEURON_STORE},
};

#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_base_types::PrincipalId;
use ic_nns_common::pb::v1::NeuronId;
use icp_ledger::Subaccount;
use std::{collections::VecDeque, marker::PhantomData};

const MAX_VALIDATION_AGE_SECONDS: u64 = 60 * 60 * 24;

#[derive(Debug, PartialEq)]
enum ValidationIssue {
    Unspecified,
    InactiveNeuronCardinalityMismatch {
        heap: u64,
        stable: u64,
    },
    NeuronCopyValueNotMatch(NeuronId),
    NeuronStoreError(NeuronId, NeuronStoreError),
    SubaccountIndexCardinalityMismatch {
        primary: u64,
        index: u64,
    },
    SubaccountMissingFromIndex {
        neuron_id: NeuronId,
        subaccount: Subaccount,
    },
    PrincipalIdMissingFromIndex {
        neuron_id: NeuronId,
        missing_principal_ids: Vec<PrincipalId>,
    },
    PrincipalIndexCardinalityMismatch {
        primary: u64,
        index: u64,
    },
    TopicFolloweePairsMissingFromIndex {
        neuron_id: NeuronId,
        missing_topic_followee_pairs: Vec<(Topic, NeuronId)>,
    },
    FollowingIndexCardinalityMismatch {
        primary: u64,
        index: u64,
    },
    KnownNeuronMissingFromIndex {
        neuron_id: NeuronId,
        known_neuron_name: String,
    },
    KnownNeuronIndexCardinalityMismatch {
        primary: u64,
        index: u64,
    },
}

/// A summary of neuron data validation.
pub struct NeuronDataValidationSummary {
    pub current_validation_started_time_seconds: Option<u64>,
    pub current_issues_summary: Option<IssuesSummary>,
    pub previous_issues_summary: Option<IssuesSummary>,
}

/// A summary of validation issues.
pub struct IssuesSummary {
    pub last_updated_time_seconds: u64,
    // TODO(NNS1-2482): add more fields when we expose the summary through canister query method.
}

/// A validator for secondary neuron data, such as indexes. It can be called in heartbeat to perform
/// a small chunk of the validation, while keeping track of its progress.
pub struct NeuronDataValidator {
    state: State,
}

impl NeuronDataValidator {
    pub fn new() -> Self {
        Self {
            state: State::NotStarted,
        }
    }

    /// Validates the indexes in a way that does not incur too much computation (to fit into one
    /// heartbeat). Returns whether some computation intensive work has been done (so that the
    /// heartbeat method have a chance to early return after calling this method).
    pub fn maybe_validate(&mut self, now: u64, neuron_store: &NeuronStore) -> bool {
        let (should_start, issues) = match &mut self.state {
            State::NotStarted => (true, None),
            State::Validated(issues) => {
                let validation_age_seconds = now.saturating_sub(issues.last_updated_time_seconds);
                if validation_age_seconds > MAX_VALIDATION_AGE_SECONDS {
                    (true, Some(std::mem::take(issues)))
                } else {
                    (false, None)
                }
            }
            State::Validating { .. } => (false, None),
        };

        if should_start {
            self.state = State::Validating {
                in_progress: ValidationInProgress::new(now),
                current_issues: Issues::new(now),
                previous_issues: issues,
            };
        }

        let (validation_in_progress, current_issues) = match &mut self.state {
            State::NotStarted => return false,
            State::Validating {
                in_progress,
                current_issues,
                previous_issues: _,
            } => (in_progress, current_issues),
            State::Validated(_) => return false,
        };

        let new_issues = validation_in_progress.validate_next_chunk(neuron_store);
        current_issues.update(now, new_issues);

        if validation_in_progress.is_done() {
            self.state = State::Validated(std::mem::take(current_issues));
        }

        true
    }

    // TODO(NNS1-2482): this method is just for testing before summary() is ready.
    #[cfg(test)]
    fn issues(&self) -> Vec<&ValidationIssue> {
        match &self.state {
            State::NotStarted => vec![],
            State::Validating { current_issues, .. } => current_issues.issues.iter().collect(),
            State::Validated(issues) => issues.issues.iter().collect(),
        }
    }

    pub fn summary(&self) -> NeuronDataValidationSummary {
        match &self.state {
            State::NotStarted => NeuronDataValidationSummary {
                current_issues_summary: None,
                previous_issues_summary: None,
                current_validation_started_time_seconds: None,
            },
            State::Validating {
                in_progress,
                current_issues,
                previous_issues,
            } => NeuronDataValidationSummary {
                current_issues_summary: Some(current_issues.summary()),
                previous_issues_summary: previous_issues.as_ref().map(|issues| issues.summary()),
                current_validation_started_time_seconds: Some(in_progress.started_time_seconds),
            },
            State::Validated(issues) => NeuronDataValidationSummary {
                current_issues_summary: Some(issues.summary()),
                previous_issues_summary: None,
                current_validation_started_time_seconds: None,
            },
        }
    }
}

/// Validation state.
enum State {
    // Validation has not started.
    NotStarted,
    // No validation is in progress. Storing the validation issues found the last time.
    Validated(Issues),
    // Validation in progress. Also storing the validation issues found the previous time if it exists.
    Validating {
        in_progress: ValidationInProgress,
        current_issues: Issues,
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
        >::new()));
        tasks.push_back(Box::new(CardinalitiesValidationTask::<
            SubaccountIndexValidator,
        >::new()));

        tasks.push_back(Box::new(
            NeuronRangeValidationTask::<PrincipalIndexValidator>::new(),
        ));
        tasks.push_back(Box::new(CardinalitiesValidationTask::<
            PrincipalIndexValidator,
        >::new()));

        tasks.push_back(Box::new(
            NeuronRangeValidationTask::<FollowingIndexValidator>::new(),
        ));
        tasks.push_back(Box::new(CardinalitiesValidationTask::<
            FollowingIndexValidator,
        >::new()));

        tasks.push_back(Box::new(NeuronRangeValidationTask::<
            KnownNeuronIndexValidator,
        >::new()));
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
#[derive(Debug, Default, PartialEq)]
struct Issues {
    last_updated_time_seconds: u64,
    // TODO(NNS1-2482): define a 'summary' of issues, so that the memory needed for 'issues' won't
    // be linear to the number of neurons.
    issues: Vec<ValidationIssue>,
}

impl Issues {
    fn new(now: u64) -> Self {
        Self {
            last_updated_time_seconds: now,
            issues: Vec::new(),
        }
    }

    fn update(&mut self, now: u64, mut issues: Vec<ValidationIssue>) {
        self.last_updated_time_seconds = now;
        self.issues.append(&mut issues);
    }

    fn summary(&self) -> IssuesSummary {
        IssuesSummary {
            last_updated_time_seconds: self.last_updated_time_seconds,
        }
    }
}

/// A validation task which can be composed of multiple tasks.
trait ValidationTask: Send + Sync {
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
    const NEURON_RANGE_CHUNK_SIZE: usize = DEFAULT_RANGE_VALIDATION_CHUNK_SIZE;

    /// Validates the cardinalities of primary data and index to be equal.
    fn validate_cardinalities(neuron_store: &NeuronStore) -> Option<ValidationIssue>;

    /// Validates that the primary neuron data has corresponding entries in the index.
    fn validate_primary_neuron_has_corresponding_index_entries(
        neuron_id: NeuronId,
        neuron_store: &NeuronStore,
    ) -> Option<ValidationIssue>;
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

impl<Validator: CardinalityAndRangeValidator + Send + Sync> ValidationTask
    for CardinalitiesValidationTask<Validator>
{
    fn is_done(&self) -> bool {
        self.is_done
    }

    fn validate_next_chunk(&mut self, neuron_store: &NeuronStore) -> Vec<ValidationIssue> {
        self.is_done = true;
        Validator::validate_cardinalities(neuron_store)
            .into_iter()
            .collect()
    }
}

struct NeuronRangeValidationTask<Validator: CardinalityAndRangeValidator> {
    next_neuron_id: Option<NeuronId>,
    // PhantomData is needed so that NeuronRangeValidationTask can be associated with a Validator
    // type without containing such a member.
    _phantom: PhantomData<Validator>,
}

// TODO this is a randomly selected value, to be empirically tuned.
const DEFAULT_RANGE_VALIDATION_CHUNK_SIZE: usize = 100;

impl<Validator: CardinalityAndRangeValidator> NeuronRangeValidationTask<Validator> {
    fn new() -> Self {
        Self {
            // NeuronId cannot be 0.
            next_neuron_id: Some(NeuronId { id: 1 }),
            _phantom: PhantomData,
        }
    }
}

impl<Validator: CardinalityAndRangeValidator + Send + Sync> ValidationTask
    for NeuronRangeValidationTask<Validator>
{
    fn is_done(&self) -> bool {
        self.next_neuron_id.is_none()
    }

    fn validate_next_chunk(&mut self, neuron_store: &NeuronStore) -> Vec<ValidationIssue> {
        let next_neuron_id = match self.next_neuron_id.take() {
            Some(next_neuron_id) => next_neuron_id,
            None => {
                println!("validate_next_chunk should not be called when is_done() is true");
                return vec![];
            }
        };
        neuron_store
            .heap_neurons()
            .range(next_neuron_id.id..)
            .take(Validator::NEURON_RANGE_CHUNK_SIZE)
            .flat_map(|(neuron_id, _)| {
                self.next_neuron_id = Some(NeuronId { id: neuron_id + 1 });
                Validator::validate_primary_neuron_has_corresponding_index_entries(
                    NeuronId { id: *neuron_id },
                    neuron_store,
                )
            })
            .collect()
    }
}

struct SubaccountIndexValidator;

impl CardinalityAndRangeValidator for SubaccountIndexValidator {
    fn validate_cardinalities(neuron_store: &NeuronStore) -> Option<ValidationIssue> {
        let cardinality_primary = neuron_store.heap_neurons().len() as u64;
        let cardinality_index =
            NEURON_INDEXES.with(|indexes| indexes.borrow().subaccount().num_entries()) as u64;
        if cardinality_primary != cardinality_index {
            Some(ValidationIssue::SubaccountIndexCardinalityMismatch {
                primary: cardinality_primary,
                index: cardinality_index,
            })
        } else {
            None
        }
    }

    fn validate_primary_neuron_has_corresponding_index_entries(
        neuron_id: NeuronId,
        neuron_store: &NeuronStore,
    ) -> Option<ValidationIssue> {
        let subaccount = get_neuron_subaccount(neuron_store, neuron_id);
        let subaccount = match subaccount {
            Ok(subaccount) => subaccount,
            Err(error) => return Some(ValidationIssue::NeuronStoreError(neuron_id, error)),
        };
        let subaccount_in_index = NEURON_INDEXES.with(|indexes| {
            indexes
                .borrow()
                .subaccount()
                .contains_entry(neuron_id, &subaccount)
        });
        if !subaccount_in_index {
            Some(ValidationIssue::SubaccountMissingFromIndex {
                neuron_id,
                subaccount,
            })
        } else {
            None
        }
    }
}

struct PrincipalIndexValidator;

impl CardinalityAndRangeValidator for PrincipalIndexValidator {
    fn validate_cardinalities(neuron_store: &NeuronStore) -> Option<ValidationIssue> {
        let cardinality_primary: u64 = neuron_store
            .heap_neurons()
            .values()
            .map(|neuron| neuron.principal_ids_with_special_permissions().len() as u64)
            .sum();
        let cardinality_index =
            NEURON_INDEXES.with(|indexes| indexes.borrow().principal().num_entries()) as u64;
        if cardinality_primary != cardinality_index {
            Some(ValidationIssue::PrincipalIndexCardinalityMismatch {
                primary: cardinality_primary,
                index: cardinality_index,
            })
        } else {
            None
        }
    }

    fn validate_primary_neuron_has_corresponding_index_entries(
        neuron_id: NeuronId,
        neuron_store: &NeuronStore,
    ) -> Option<ValidationIssue> {
        let principal_ids = neuron_store.with_neuron(&neuron_id, |neuron| {
            neuron.principal_ids_with_special_permissions()
        });
        let principal_ids = match principal_ids {
            Ok(principal_ids) => principal_ids,
            Err(error) => return Some(ValidationIssue::NeuronStoreError(neuron_id, error)),
        };
        let missing_principal_ids: Vec<_> = principal_ids
            .into_iter()
            .filter(|principal_id| {
                let pair_exists_in_index = NEURON_INDEXES.with(|indexes| {
                    indexes
                        .borrow()
                        .principal()
                        .contains_entry(&neuron_id.id, *principal_id)
                });
                !pair_exists_in_index
            })
            .collect();
        if !missing_principal_ids.is_empty() {
            Some(ValidationIssue::PrincipalIdMissingFromIndex {
                neuron_id,
                missing_principal_ids,
            })
        } else {
            None
        }
    }
}

struct FollowingIndexValidator;

impl CardinalityAndRangeValidator for FollowingIndexValidator {
    fn validate_cardinalities(neuron_store: &NeuronStore) -> Option<ValidationIssue> {
        let cardinality_primary: u64 = neuron_store
            .heap_neurons()
            .values()
            .map(|neuron| {
                neuron
                    .followees
                    .values()
                    .map(|followees_by_topic| followees_by_topic.followees.len() as u64)
                    .sum::<u64>()
            })
            .sum();
        let cardinality_index =
            NEURON_INDEXES.with(|indexes| indexes.borrow().following().num_entries()) as u64;
        if cardinality_primary != cardinality_index {
            Some(ValidationIssue::FollowingIndexCardinalityMismatch {
                primary: cardinality_primary,
                index: cardinality_index,
            })
        } else {
            None
        }
    }

    fn validate_primary_neuron_has_corresponding_index_entries(
        neuron_id: NeuronId,
        neuron_store: &NeuronStore,
    ) -> Option<ValidationIssue> {
        let topic_followee_pairs =
            neuron_store.with_neuron(&neuron_id, |neuron| neuron.topic_followee_pairs());
        let topic_followee_pairs = match topic_followee_pairs {
            Ok(topic_followee_pairs) => topic_followee_pairs,
            Err(error) => return Some(ValidationIssue::NeuronStoreError(neuron_id, error)),
        };
        let missing_topic_followee_pairs: Vec<_> = topic_followee_pairs
            .into_iter()
            .filter(|(topic, followee)| {
                let pair_exists_in_index = NEURON_INDEXES.with(|indexes| {
                    indexes.borrow().following().contains_entry(
                        Signed32::from(*topic as i32),
                        &followee.id,
                        &neuron_id.id,
                    )
                });
                !pair_exists_in_index
            })
            .collect();
        if !missing_topic_followee_pairs.is_empty() {
            Some(ValidationIssue::TopicFolloweePairsMissingFromIndex {
                neuron_id,
                missing_topic_followee_pairs,
            })
        } else {
            None
        }
    }
}

struct KnownNeuronIndexValidator;

impl CardinalityAndRangeValidator for KnownNeuronIndexValidator {
    fn validate_cardinalities(neuron_store: &NeuronStore) -> Option<ValidationIssue> {
        let cardinality_primary = neuron_store
            .heap_neurons()
            .values()
            .filter(|neuron| neuron.known_neuron_data.is_some())
            .count();
        let cardinality_index =
            NEURON_INDEXES.with(|indexes| indexes.borrow().known_neuron().num_entries());
        if cardinality_primary != cardinality_index {
            Some(ValidationIssue::KnownNeuronIndexCardinalityMismatch {
                primary: cardinality_primary as u64,
                index: cardinality_index as u64,
            })
        } else {
            None
        }
    }

    fn validate_primary_neuron_has_corresponding_index_entries(
        neuron_id: NeuronId,
        neuron_store: &NeuronStore,
    ) -> Option<ValidationIssue> {
        let known_neuron_name = neuron_store.with_neuron(&neuron_id, |neuron| {
            neuron
                .known_neuron_data
                .as_ref()
                .map(|known_neuron_data| known_neuron_data.name.clone())
        });
        let known_neuron_name = match known_neuron_name {
            // Most neurons aren't known neurons.
            Ok(None) => return None,
            Err(error) => return Some(ValidationIssue::NeuronStoreError(neuron_id, error)),
            Ok(Some(known_neuron_name)) => known_neuron_name,
        };
        let index_has_entry = NEURON_INDEXES.with(|indexes| {
            indexes
                .borrow()
                .known_neuron()
                .contains_entry(neuron_id, &known_neuron_name)
        });
        if !index_has_entry {
            Some(ValidationIssue::KnownNeuronMissingFromIndex {
                neuron_id,
                known_neuron_name,
            })
        } else {
            None
        }
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
    use maplit::hashmap;

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
        let id = NEXT_TEST_NEURON_ID.with(|next_test_neuron_id| {
            let mut next_test_neuron_id = next_test_neuron_id.borrow_mut();
            let id = *next_test_neuron_id;
            *next_test_neuron_id += 1;
            id
        });
        neuron.id = Some(NeuronId { id });
        neuron
            .account
            .splice(24..32, neuron.id.unwrap().id.to_le_bytes());
        neuron
            .known_neuron_data
            .as_mut()
            .unwrap()
            .name
            .push_str(&id.to_string());
        neuron
    }

    #[test]
    fn test_finish_validation() {
        let neuron_store = NeuronStore::new_for_test(vec![Neuron {
            id: Some(NeuronId { id: 1 }),
            account: [1u8; 32].to_vec(),
            controller: Some(PrincipalId::new_user_test_id(1)),
            ..Default::default()
        }]);
        let mut validation = NeuronDataValidator::new();

        // Each index use 3 rounds and invalid neuron validator takes 2 rounds.
        for i in 0..14 {
            assert!(validation.maybe_validate(i, &neuron_store));
        }

        // After 10 rounds it should not validate.
        assert!(!validation.maybe_validate(14, &neuron_store));

        // After 1 day it should validate again.
        assert!(validation.maybe_validate(86415, &neuron_store));
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

        let neuron_store = NeuronStore::new(btree_map, None, Migration::default());

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

        let neuron_store = NeuronStore::new(btree_map, None, Migration::default());

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

    #[test]
    fn test_validator_valid() {
        let neuron_store = NeuronStore::new_for_test(vec![Neuron {
            cached_neuron_stake_e8s: 1,
            ..next_test_neuron()
        }]);
        let mut validator = NeuronDataValidator::new();
        let mut now = 1;
        while validator.maybe_validate(now, &neuron_store) {
            now += 1;
        }
        // TODO(NNS1-2482) validate from a pub method that returns issues summary.
        // assert_eq!(validator.issues.issues, vec![]);
    }

    #[test]
    fn test_validator_invalid_issues() {
        // Cause as many issues as possible by having an inactive neuron (without adding it to
        // STABLE_NEURON_STORE, and remove the only neuron from indexes).
        let neuron = next_test_neuron();
        let neuron_store = NeuronStore::new_for_test(vec![neuron.clone()]);
        NEURON_INDEXES
            .with(|indexes| indexes.borrow_mut().remove_neuron(&neuron))
            .unwrap();

        let mut validator = NeuronDataValidator::new();
        let mut now = 1;
        while validator.maybe_validate(now, &neuron_store) {
            now += 1;
        }
        // TODO(NNS1-2482) validate from a pub method that returns issues summary.
        let issues = validator.issues();
        assert_eq!(issues.len(), 9);
        assert!(matches!(
            *issues[0],
            ValidationIssue::SubaccountMissingFromIndex { neuron_id, subaccount: _ }
            if neuron_id == neuron.id.unwrap()
        ));
        assert_eq!(
            *issues[1],
            ValidationIssue::SubaccountIndexCardinalityMismatch {
                primary: 1,
                index: 0
            }
        );
        assert!(matches!(
            *issues[2],
            ValidationIssue::PrincipalIdMissingFromIndex { .. }
        ));
        assert_eq!(
            *issues[3],
            ValidationIssue::PrincipalIndexCardinalityMismatch {
                primary: 3,
                index: 0
            }
        );
        assert!(matches!(
            *issues[4],
            ValidationIssue::TopicFolloweePairsMissingFromIndex { .. }
        ));
        assert_eq!(
            *issues[5],
            ValidationIssue::FollowingIndexCardinalityMismatch {
                primary: 3,
                index: 0
            }
        );
        assert!(matches!(
            *issues[6],
            ValidationIssue::KnownNeuronMissingFromIndex { .. }
        ));
        assert_eq!(
            *issues[7],
            ValidationIssue::KnownNeuronIndexCardinalityMismatch {
                primary: 1,
                index: 0
            }
        );
        assert_eq!(
            *issues[8],
            ValidationIssue::InactiveNeuronCardinalityMismatch { heap: 1, stable: 0 }
        );
    }
}
