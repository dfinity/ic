use crate::{
    neuron::Neuron,
    neuron_store::NeuronStore,
    pb::v1::Topic,
    storage::{with_stable_neuron_indexes, with_stable_neuron_store},
};

use candid::{CandidType, Deserialize};
use ic_base_types::PrincipalId;
use ic_cdk::println;
use ic_nns_common::pb::v1::NeuronId;
use icp_ledger::Subaccount;
use serde::Serialize;
use std::{
    collections::{HashMap, VecDeque},
    marker::PhantomData,
    mem::{discriminant, Discriminant},
};

const MAX_VALIDATION_AGE_SECONDS: u64 = 60 * 60 * 24;
const MAX_EXAMPLE_ISSUES_COUNT: usize = 10;
// On average, checking whether an entry exists in a StableBTreeMap takes ~130K instructions, and a
// neuron on average has ~40 entries (1 main neuron data + 11.3 followees + 1.2 hot key +
// 26.2 recent ballots). Using batch size = 10 keeps the overall instructions under 60M.
const INACTIVE_NEURON_VALIDATION_CHUNK_SIZE: usize = 10;

#[derive(Clone, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub enum ValidationIssue {
    ActiveNeuronInStableStorage(NeuronId),
    NeuronStoreError(String),
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
#[derive(PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct NeuronDataValidationSummary {
    pub current_validation_started_time_seconds: Option<u64>,
    pub current_issues_summary: Option<IssuesSummary>,
    pub previous_issues_summary: Option<IssuesSummary>,
}

/// A group of validation issues, where we keep track of the count of issues and truncate the
/// example issues to only 10.
#[derive(Clone, PartialEq, Debug, Default, CandidType, Deserialize, Serialize)]
pub struct IssueGroup {
    /// Count of issues for a specific type.
    pub issues_count: u64,
    /// Up to 10 example issues of this type.
    pub example_issues: Vec<ValidationIssue>,
}

/// A summary of validation issues.
#[derive(PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct IssuesSummary {
    pub last_updated_time_seconds: u64,
    pub issue_groups: Vec<IssueGroup>,
}

/// A validator for secondary neuron data, such as indexes. It can be called in heartbeat to perform
/// a small chunk of the validation, while keeping track of its progress.
pub(crate) enum NeuronDataValidator {
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

impl NeuronDataValidator {
    pub fn new() -> Self {
        Self::NotStarted
    }

    /// Validates the indexes in a way that does not incur too much computation (to fit into one
    /// heartbeat). Returns whether some computation intensive work has been done (so that the
    /// heartbeat method have a chance to early return after calling this method).
    pub fn maybe_validate(&mut self, now: u64, neuron_store: &NeuronStore) -> bool {
        let (should_start, issues) = match self {
            Self::NotStarted => (true, None),
            Self::Validated(issues) => {
                let validation_age_seconds = now.saturating_sub(issues.last_updated_time_seconds);
                if validation_age_seconds > MAX_VALIDATION_AGE_SECONDS {
                    (true, Some(std::mem::take(issues)))
                } else {
                    (false, None)
                }
            }
            Self::Validating { .. } => (false, None),
        };

        if should_start {
            *self = Self::Validating {
                in_progress: ValidationInProgress::new(now),
                current_issues: Issues::new(now),
                previous_issues: issues,
            };
        }

        let (validation_in_progress, current_issues) = match self {
            Self::NotStarted => return false,
            Self::Validating {
                in_progress,
                current_issues,
                previous_issues: _,
            } => (in_progress, current_issues),
            Self::Validated(_) => return false,
        };

        let new_issues = validation_in_progress.validate_next_chunk(neuron_store);
        current_issues.update(now, new_issues);

        if validation_in_progress.is_done() {
            *self = Self::Validated(std::mem::take(current_issues));
        }

        true
    }

    pub fn summary(&self) -> NeuronDataValidationSummary {
        match &self {
            Self::NotStarted => NeuronDataValidationSummary {
                current_issues_summary: None,
                previous_issues_summary: None,
                current_validation_started_time_seconds: None,
            },
            Self::Validating {
                in_progress,
                current_issues,
                previous_issues,
            } => NeuronDataValidationSummary {
                current_issues_summary: Some(current_issues.summary()),
                previous_issues_summary: previous_issues.as_ref().map(|issues| issues.summary()),
                current_validation_started_time_seconds: Some(in_progress.started_time_seconds),
            },
            Self::Validated(issues) => NeuronDataValidationSummary {
                current_issues_summary: Some(issues.summary()),
                previous_issues_summary: None,
                current_validation_started_time_seconds: None,
            },
        }
    }
}

impl Default for NeuronDataValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Information related to a validation in progress.
pub(crate) struct ValidationInProgress {
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

        tasks.push_back(Box::new(StableNeuronStoreValidator::new(
            INACTIVE_NEURON_VALIDATION_CHUNK_SIZE,
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

/// Validation issues stored on the heap while the validation is running. This is not meant to be
/// exposed through a query method (but IssuesSummary does).
#[derive(PartialEq, Debug, Default)]
pub(crate) struct Issues {
    last_updated_time_seconds: u64,
    issue_groups_map: HashMap<Discriminant<ValidationIssue>, IssueGroup>,
}

impl Issues {
    fn new(now: u64) -> Self {
        Self {
            last_updated_time_seconds: now,
            issue_groups_map: HashMap::new(),
        }
    }

    fn update(&mut self, now: u64, issues: Vec<ValidationIssue>) {
        self.last_updated_time_seconds = now;
        for issue in issues {
            let issue_group = self
                .issue_groups_map
                .entry(discriminant(&issue))
                .or_default();
            issue_group.issues_count += 1;
            if issue_group.example_issues.len() < MAX_EXAMPLE_ISSUES_COUNT {
                issue_group.example_issues.push(issue);
            }
        }
    }

    fn summary(&self) -> IssuesSummary {
        IssuesSummary {
            last_updated_time_seconds: self.last_updated_time_seconds,
            issue_groups: self.issue_groups_map.values().cloned().collect(),
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

/// A type of validator against a data set derived from neurons (primary data) where each item is
/// associated with one and only one neuron (while each neuron can be associated with potentially
/// multiple items). The overall methodology is that we can check 2 things: (1) the count
/// (cardinality) of the data set is equal to the item count, and (2) given a particular neuron, all
/// items that should be in the data set are indeed in the data set. If we have both (1)
/// count(primary) == count(derived) and (2) for each item in primary => the item is in secondary,
/// then we know the 2 sets are equal. Note that checking (2) is done in multiple heartbeats, during
/// which the 2 data sets can change. However, while updating the 2 data sets, it's much easier to
/// make sure that the neuron and associated items being updated are indeed consistent. The primary
/// goal of this validation is to make sure that the all items are consistent across 2 data sets
/// (particularly the ones not updated recently), since the secondary data is stored in stable
/// storage, and therefore past inconsistencies would be preserved indefinitely until found and
/// fixed.
trait CardinalityAndRangeValidator {
    const HEAP_NEURON_RANGE_CHUNK_SIZE: usize;

    /// Validates the cardinalities of primary data and index to be equal.
    fn validate_cardinalities(neuron_store: &NeuronStore) -> Option<ValidationIssue>;

    /// Validates that the primary neuron data has corresponding entries in the index.
    fn validate_primary_neuron_has_corresponding_index_entries(
        neuron: &Neuron,
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
    heap_next_neuron_id: Option<NeuronId>,
    stable_next_neuron_id: Option<NeuronId>,
    // PhantomData is needed so that NeuronRangeValidationTask can be associated with a Validator
    // type without containing such a member.
    _phantom: PhantomData<Validator>,
}

impl<Validator: CardinalityAndRangeValidator> NeuronRangeValidationTask<Validator> {
    fn new() -> Self {
        Self {
            // NeuronId cannot be 0.
            heap_next_neuron_id: Some(NeuronId { id: 1 }),
            stable_next_neuron_id: Some(NeuronId { id: 1 }),
            _phantom: PhantomData,
        }
    }
}

impl<Validator: CardinalityAndRangeValidator + Send + Sync> ValidationTask
    for NeuronRangeValidationTask<Validator>
{
    fn is_done(&self) -> bool {
        self.heap_next_neuron_id.is_none() && self.stable_next_neuron_id.is_none()
    }

    fn validate_next_chunk(&mut self, neuron_store: &NeuronStore) -> Vec<ValidationIssue> {
        if let Some(next_neuron_id) = self.heap_next_neuron_id.take() {
            neuron_store
                .heap_neurons()
                .range(next_neuron_id.id..)
                .take(Validator::HEAP_NEURON_RANGE_CHUNK_SIZE)
                .flat_map(|(neuron_id, neuron)| {
                    self.heap_next_neuron_id = (NeuronId { id: *neuron_id }).next();
                    Validator::validate_primary_neuron_has_corresponding_index_entries(neuron)
                })
                .collect()
        } else if let Some(next_neuron_id) = self.stable_next_neuron_id.take() {
            with_stable_neuron_store(|stable_neuron_store| {
                stable_neuron_store
                    .range_neurons(next_neuron_id..)
                    .take(INACTIVE_NEURON_VALIDATION_CHUNK_SIZE)
                    .flat_map(|neuron| {
                        let neuron_id_to_validate = neuron.id();
                        self.stable_next_neuron_id = neuron_id_to_validate.next();
                        Validator::validate_primary_neuron_has_corresponding_index_entries(&neuron)
                    })
                    .collect()
            })
        } else {
            println!("validate_next_chunk should not be called when is_done() is true");
            vec![]
        }
    }
}

struct SubaccountIndexValidator;

impl CardinalityAndRangeValidator for SubaccountIndexValidator {
    // On average, checking whether an entry exists in a StableBTreeMap takes ~130K instructions,
    // and there is exactly one entry for a neuron, so 400 neurons takes 52M instructions (aiming to
    // keep it under 60M).
    const HEAP_NEURON_RANGE_CHUNK_SIZE: usize = 400;

    fn validate_cardinalities(neuron_store: &NeuronStore) -> Option<ValidationIssue> {
        let cardinality_primary_heap = neuron_store.heap_neurons().len() as u64;
        let cardinality_primary_stable =
            with_stable_neuron_store(|stable_neuron_store| stable_neuron_store.len() as u64);
        let cardinality_primary = cardinality_primary_heap + cardinality_primary_stable;
        let cardinality_index =
            with_stable_neuron_indexes(|indexes| indexes.subaccount().num_entries()) as u64;
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
        neuron: &Neuron,
    ) -> Option<ValidationIssue> {
        let neuron_id = neuron.id();
        let subaccount = neuron.subaccount();
        let subaccount_in_index = with_stable_neuron_indexes(|indexes| {
            indexes.subaccount().contains_entry(neuron_id, &subaccount)
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
    // On average, checking whether an entry exists in a StableBTreeMap takes ~130K instructions,
    // and there is 1 controler + 1.2 hot keys (=2.2) on average, so 200 neurons takes 57.2M
    // instructions (aiming to keep it under 60M).
    const HEAP_NEURON_RANGE_CHUNK_SIZE: usize = 200;

    fn validate_cardinalities(neuron_store: &NeuronStore) -> Option<ValidationIssue> {
        let cardinality_primary_heap: u64 = neuron_store
            .heap_neurons()
            .values()
            .map(|neuron| neuron.principal_ids_with_special_permissions().len() as u64)
            .sum();
        let cardinality_primary_stable = with_stable_neuron_store(|stable_neuron_store|
                    // `stable_neuron_store.len()` is for the controllers.
                    stable_neuron_store.lens().hot_keys + stable_neuron_store.len() as u64);
        let cardinality_primary = cardinality_primary_heap + cardinality_primary_stable;
        let cardinality_index =
            with_stable_neuron_indexes(|indexes| indexes.principal().num_entries()) as u64;
        // Because hot keys can also be controllers, the primary data might have larger cardinality
        // than the index. Therefore we only report an issue when index size is larger than primary.
        if cardinality_primary < cardinality_index {
            Some(ValidationIssue::PrincipalIndexCardinalityMismatch {
                primary: cardinality_primary,
                index: cardinality_index,
            })
        } else {
            None
        }
    }

    fn validate_primary_neuron_has_corresponding_index_entries(
        neuron: &Neuron,
    ) -> Option<ValidationIssue> {
        let neuron_id = neuron.id();
        let missing_principal_ids: Vec<_> = neuron
            .principal_ids_with_special_permissions()
            .into_iter()
            .filter(|principal_id| {
                let pair_exists_in_index = with_stable_neuron_indexes(|indexes| {
                    indexes
                        .principal()
                        .contains_entry(&neuron_id, *principal_id)
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
    // On average, checking whether an entry exists in a StableBTreeMap takes ~130K instructions,
    // and there are ~11.3 followee entries on average, so 40 neurons takes 58.76M instructions
    // (aiming to keep it under 60M).
    const HEAP_NEURON_RANGE_CHUNK_SIZE: usize = 40;

    fn validate_cardinalities(neuron_store: &NeuronStore) -> Option<ValidationIssue> {
        let cardinality_primary_heap: u64 = neuron_store
            .heap_neurons()
            .values()
            .map(|neuron| neuron.topic_followee_pairs().len() as u64)
            .sum();
        let cardinality_primary_stable =
            with_stable_neuron_store(|stable_neuron_store| stable_neuron_store.lens().followees);
        let cardinality_primary = cardinality_primary_heap + cardinality_primary_stable;
        let cardinality_index =
            with_stable_neuron_indexes(|indexes| indexes.following().num_entries()) as u64;
        // Because followees can have duplicates, the primary data might have larger cardinality
        // than the index. Therefore we only report an issue when index size is larger than primary.
        if cardinality_primary < cardinality_index {
            Some(ValidationIssue::FollowingIndexCardinalityMismatch {
                primary: cardinality_primary,
                index: cardinality_index,
            })
        } else {
            None
        }
    }

    fn validate_primary_neuron_has_corresponding_index_entries(
        neuron: &Neuron,
    ) -> Option<ValidationIssue> {
        let neuron_id = neuron.id();
        let missing_topic_followee_pairs: Vec<_> = neuron
            .topic_followee_pairs()
            .into_iter()
            .filter(|(topic, followee)| {
                let pair_exists_in_index = with_stable_neuron_indexes(|indexes| {
                    indexes
                        .following()
                        .contains_entry(*topic, followee, &neuron_id)
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
    // As long as we have <460 known neurons, we will be able to keep the instructions <60M as each
    // entry lookup takes ~130K instructions.
    const HEAP_NEURON_RANGE_CHUNK_SIZE: usize = 300000;
    fn validate_cardinalities(neuron_store: &NeuronStore) -> Option<ValidationIssue> {
        let cardinality_primary_heap = neuron_store
            .heap_neurons()
            .values()
            .filter(|neuron| neuron.known_neuron_data.is_some())
            .count() as u64;
        let cardinality_primary_stable = with_stable_neuron_store(|stable_neuron_store| {
            stable_neuron_store.lens().known_neuron_data
        });
        let cardinality_primary = cardinality_primary_heap + cardinality_primary_stable;
        let cardinality_index =
            with_stable_neuron_indexes(|indexes| indexes.known_neuron().num_entries()) as u64;
        if cardinality_primary != cardinality_index {
            Some(ValidationIssue::KnownNeuronIndexCardinalityMismatch {
                primary: cardinality_primary,
                index: cardinality_index,
            })
        } else {
            None
        }
    }

    fn validate_primary_neuron_has_corresponding_index_entries(
        neuron: &Neuron,
    ) -> Option<ValidationIssue> {
        let neuron_id = neuron.id();
        let known_neuron_name = match &neuron.known_neuron_data {
            // Most neurons aren't known neurons.
            None => return None,
            Some(known_neuron_data) => &known_neuron_data.name,
        };
        let index_has_entry = with_stable_neuron_indexes(|indexes| {
            indexes
                .known_neuron()
                .contains_entry(neuron_id, known_neuron_name)
        });
        if !index_has_entry {
            Some(ValidationIssue::KnownNeuronMissingFromIndex {
                neuron_id,
                known_neuron_name: known_neuron_name.clone(),
            })
        } else {
            None
        }
    }
}

/// A validator to validate that all neurons in stable storage are inactive.
struct StableNeuronStoreValidator {
    next_neuron_id: Option<NeuronId>,
    chunk_size: usize,
}

impl StableNeuronStoreValidator {
    fn new(chunk_size: usize) -> Self {
        Self {
            next_neuron_id: Some(NeuronId { id: 0 }),
            chunk_size,
        }
    }
}

impl ValidationTask for StableNeuronStoreValidator {
    fn is_done(&self) -> bool {
        self.next_neuron_id.is_none()
    }

    fn validate_next_chunk(&mut self, neuron_store: &NeuronStore) -> Vec<ValidationIssue> {
        let next_neuron_id = match self.next_neuron_id.take() {
            Some(next_neuron_id) => next_neuron_id,
            None => return vec![],
        };

        let (invalid_neuron_ids, neuron_id_for_next_batch) = neuron_store
            .batch_validate_neurons_in_stable_store_are_inactive(next_neuron_id, self.chunk_size);

        self.next_neuron_id = neuron_id_for_next_batch;
        invalid_neuron_ids
            .into_iter()
            .map(ValidationIssue::ActiveNeuronInStableStorage)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, collections::BTreeMap};

    use ic_base_types::PrincipalId;
    use maplit::{btreemap, hashmap};

    use crate::{
        neuron::{DissolveStateAndAge, NeuronBuilder},
        pb::v1::{neuron::Followees, KnownNeuronData},
        storage::{with_stable_neuron_indexes_mut, with_stable_neuron_store_mut},
    };

    thread_local! {
        static NEXT_TEST_NEURON_ID: RefCell<u64> = const { RefCell::new(1) };
    }

    fn next_test_neuron() -> NeuronBuilder {
        let id = NEXT_TEST_NEURON_ID.with(|next_test_neuron_id| {
            let mut next_test_neuron_id = next_test_neuron_id.borrow_mut();
            let id = *next_test_neuron_id;
            *next_test_neuron_id += 1;
            id
        });
        let mut account = [1u8; 32].to_vec();
        account.splice(24..32, id.to_le_bytes());
        let subaccount = Subaccount::try_from(&account[..]).unwrap();
        let known_neuron_name = format!("known neuron data{}", id);

        NeuronBuilder::new(
            NeuronId { id },
            subaccount,
            PrincipalId::new_user_test_id(1),
            DissolveStateAndAge::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds: 1,
            },
            123_456_789,
        )
        .with_hot_keys(vec![
            PrincipalId::new_user_test_id(1),
            PrincipalId::new_user_test_id(2),
            PrincipalId::new_user_test_id(3),
        ])
        .with_followees(hashmap! {
            1 => Followees{
                followees: vec![
                    NeuronId { id: 2 },
                    NeuronId { id: 4 },
                    NeuronId { id: 3 },
                    NeuronId { id: 3 }, // We allow duplicates.
                ],
            },
        })
        .with_known_neuron_data(Some(KnownNeuronData {
            name: known_neuron_name,
            description: None,
        }))
    }

    #[test]
    fn test_finish_validation() {
        let neuron = NeuronBuilder::new(
            NeuronId { id: 1 },
            Subaccount::try_from([1u8; 32].as_ref()).unwrap(),
            PrincipalId::new_user_test_id(1),
            DissolveStateAndAge::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds: 1,
            },
            123_456_789,
        )
        .build();
        let neuron_store = NeuronStore::new(btreemap! {neuron.id().id => neuron});
        let mut validation = NeuronDataValidator::new();

        // At first it will validate at least one chunk.
        assert!(validation.maybe_validate(0, &neuron_store));

        // It will take much fewer than 100 rounds, but we pick 100 so that the test won't be
        // brittle.
        for i in 1..100 {
            validation.maybe_validate(i, &neuron_store);
        }

        // After 100 rounds it should not validate.
        assert!(!validation.maybe_validate(100, &neuron_store));

        // After 1 day it should validate again.
        assert!(validation.maybe_validate(86400 + 100, &neuron_store));
    }

    #[test]
    fn test_validator_valid() {
        // Both followees and principals (controller is a hot key) have duplicates since we do allow
        // it at this time.
        let neuron = NeuronBuilder::new(
            NeuronId { id: 1 },
            Subaccount::try_from([1u8; 32].as_ref()).unwrap(),
            PrincipalId::new_user_test_id(1),
            DissolveStateAndAge::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds: 1,
            },
            123_456_789,
        )
        .with_hot_keys(vec![
            PrincipalId::new_user_test_id(2),
            PrincipalId::new_user_test_id(3),
            PrincipalId::new_user_test_id(1),
        ])
        .with_followees(hashmap! {
            1 => Followees{
                followees: vec![
                    NeuronId { id: 2 },
                    NeuronId { id: 4 },
                    NeuronId { id: 3 },
                    NeuronId { id: 2 },
                ],
            },
        })
        .build();

        let neuron_store = NeuronStore::new(btreemap! {neuron.id().id => neuron});
        let mut validator = NeuronDataValidator::new();
        let mut now = 1;
        while validator.maybe_validate(now, &neuron_store) {
            now += 1;
        }
        let summary = validator.summary();
        assert_eq!(summary.current_issues_summary.unwrap().issue_groups, vec![]);
    }

    #[test]
    fn test_validator_invalid_issues_missing_indexes() {
        // Step 1: Cause all the issues related to neurons existing in main storage but does not
        // have corresponding entries in indexes.
        let active_neuron = next_test_neuron().with_cached_neuron_stake_e8s(1).build();
        let inactive_neuron = next_test_neuron()
            .with_cached_neuron_stake_e8s(0)
            .with_dissolve_state_and_age(DissolveStateAndAge::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds: 1,
            })
            .build();

        let mut neuron_store = NeuronStore::new(BTreeMap::new());
        neuron_store.add_neuron(active_neuron.clone()).unwrap();
        neuron_store.add_neuron(inactive_neuron.clone()).unwrap();
        // Remove the neurons from indexes to cause issues with indexes validation.
        with_stable_neuron_indexes_mut(|indexes| {
            indexes.remove_neuron(&active_neuron).unwrap();
            indexes.remove_neuron(&inactive_neuron).unwrap();
        });

        // Step 2: Validate and get validation summary.
        let mut validator = NeuronDataValidator::new();
        let mut now = 1;
        while validator.maybe_validate(now, &neuron_store) {
            now += 1;
        }
        let summary = validator.summary();

        // Step 3: Check validation summary for current issues. It has 4 issues related to primary
        // data missing from indexes, and 2 issues for cardinality mismatches for subaccount and
        // known neuron, since those are checked for exact matches.
        let issue_groups = summary.current_issues_summary.unwrap().issue_groups;
        assert_eq!(issue_groups.len(), 6);
        assert!(
            issue_groups
                .iter()
                .any(|issue_group| issue_group.issues_count == 1
                    && issue_group.example_issues[0]
                        == ValidationIssue::SubaccountIndexCardinalityMismatch {
                            primary: 2,
                            index: 0
                        }),
            "{:?}",
            issue_groups
        );
        assert!(
            issue_groups
                .iter()
                .any(|issue_group| issue_group.issues_count == 2
                    && matches!(
                        issue_group.example_issues[0],
                        ValidationIssue::SubaccountMissingFromIndex { .. }
                    )),
            "{:?}",
            issue_groups
        );
        assert!(
            issue_groups
                .iter()
                .any(|issue_group| issue_group.issues_count == 2
                    && matches!(
                        &issue_group.example_issues[0],
                        ValidationIssue::PrincipalIdMissingFromIndex { .. }
                    )),
            "{:?}",
            issue_groups
        );
        assert!(
            issue_groups
                .iter()
                .any(|issue_group| issue_group.issues_count == 2
                    && matches!(
                        issue_group.example_issues[0],
                        ValidationIssue::TopicFolloweePairsMissingFromIndex { .. }
                    )),
            "{:?}",
            issue_groups
        );
        assert!(
            issue_groups
                .iter()
                .any(|issue_group| issue_group.issues_count == 1
                    && issue_group.example_issues[0]
                        == ValidationIssue::KnownNeuronIndexCardinalityMismatch {
                            primary: 2,
                            index: 0
                        }),
            "{:?}",
            issue_groups
        );
        assert!(
            issue_groups
                .iter()
                .any(|issue_group| issue_group.issues_count == 2
                    && matches!(
                        issue_group.example_issues[0],
                        ValidationIssue::KnownNeuronMissingFromIndex { .. }
                    )),
            "{:?}",
            issue_groups
        );
    }

    #[test]
    fn test_validator_invalid_issues_wrong_cardinalities() {
        // Step 1: Cause all the issues related to cardinality mismatches because of neurons
        // existing in indexes but not primary storage.
        let active_neuron = next_test_neuron().with_cached_neuron_stake_e8s(1).build();
        let inactive_neuron = next_test_neuron()
            .with_cached_neuron_stake_e8s(0)
            .with_dissolve_state_and_age(DissolveStateAndAge::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds: 1,
            })
            .build();

        let neuron_store = NeuronStore::new(BTreeMap::new());
        // Add the neurons into indexes to cause issues with cardinality validations.
        with_stable_neuron_indexes_mut(|indexes| {
            indexes.add_neuron(&active_neuron).unwrap();
            indexes.add_neuron(&inactive_neuron).unwrap();
        });

        // Step 2: Validate and get validation summary.
        let mut validator = NeuronDataValidator::new();
        let mut now = 1;
        while validator.maybe_validate(now, &neuron_store) {
            now += 1;
        }
        let summary = validator.summary();

        // Step 3: Check validation summary for current issues. It has 4 issues related to primary
        // data missing from indexes, and 2 issues for cardinality mismatches for subaccount and
        // known neuron, since those are checked for exact matches.
        let issue_groups = summary.current_issues_summary.unwrap().issue_groups;
        assert_eq!(issue_groups.len(), 4);
        assert!(
            issue_groups
                .iter()
                .any(|issue_group| issue_group.issues_count == 1
                    && issue_group.example_issues[0]
                        == ValidationIssue::SubaccountIndexCardinalityMismatch {
                            primary: 0,
                            index: 2
                        }),
            "{:?}",
            issue_groups
        );
        assert!(
            issue_groups
                .iter()
                .any(|issue_group| issue_group.issues_count == 1
                    && issue_group.example_issues[0]
                        == ValidationIssue::PrincipalIndexCardinalityMismatch {
                            primary: 0,
                            index: 6
                        }),
            "{:?}",
            issue_groups
        );
        assert!(
            issue_groups
                .iter()
                .any(|issue_group| issue_group.issues_count == 1
                    && issue_group.example_issues[0]
                        == ValidationIssue::FollowingIndexCardinalityMismatch {
                            primary: 0,
                            index: 6
                        }),
            "{:?}",
            issue_groups
        );
        assert!(
            issue_groups
                .iter()
                .any(|issue_group| issue_group.issues_count == 1
                    && issue_group.example_issues[0]
                        == ValidationIssue::KnownNeuronIndexCardinalityMismatch {
                            primary: 0,
                            index: 2
                        }),
            "{:?}",
            issue_groups
        );
    }

    #[test]
    fn test_validator_invalid_issues_active_neuron_in_stable() {
        // Step 1: Cause an issue with active neuron in stable storage.
        // Step 1.1 First create it as an inactive neuron so it can be added to stable storage.
        let inactive_neuron = next_test_neuron()
            .with_cached_neuron_stake_e8s(0)
            .with_dissolve_state_and_age(DissolveStateAndAge::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds: 1,
            })
            .build();

        let mut active_neuron = inactive_neuron.clone();
        active_neuron.cached_neuron_stake_e8s = 1;

        let neuron_store =
            NeuronStore::new(btreemap! {inactive_neuron.id().id => inactive_neuron.clone()});
        // Make the neuron active while it's still in stable storage, to cause the issue with stable neuron store validation.
        with_stable_neuron_store_mut(|stable_neuron_store| {
            stable_neuron_store
                .update(&inactive_neuron, active_neuron)
                .unwrap()
        });

        // Step 2: Validate and get validation summary.
        let mut validator = NeuronDataValidator::new();
        let mut now = 1;
        while validator.maybe_validate(now, &neuron_store) {
            now += 1;
        }
        let summary = validator.summary();

        // Step 3: Check validation summary for current issues. It has 4 issues related to primary
        // data missing from indexes, and 2 issues for cardinality mismatches for subaccount and
        // known neuron, since those are checked for exact matches.
        let issue_groups = summary.current_issues_summary.unwrap().issue_groups;
        assert_eq!(issue_groups.len(), 1);
        assert!(
            issue_groups
                .iter()
                .any(|issue_group| issue_group.issues_count == 1
                    && issue_group.example_issues[0]
                        == ValidationIssue::ActiveNeuronInStableStorage(inactive_neuron.id())),
            "{:?}",
            issue_groups
        );

        // Step 4: check that previous issues is empty and no running validation.
        assert_eq!(summary.previous_issues_summary, None);
        assert_eq!(summary.current_validation_started_time_seconds, None);

        // Step 5: resume validation by advancing `now` that's passed in.
        now += MAX_VALIDATION_AGE_SECONDS + 1;
        assert!(validator.maybe_validate(now, &neuron_store));

        // Step 6: check that previous_issues now have values and there is a running validation.
        let summary = validator.summary();
        assert_eq!(
            summary.previous_issues_summary.unwrap().issue_groups.len(),
            1
        );
        assert_eq!(summary.current_validation_started_time_seconds, Some(now));
    }

    #[test]
    fn test_validator_truncate_same_type_of_issues() {
        // Create 11 issues of each type by adding 11 neurons and removing all of them from the
        // indexes.
        let neurons: BTreeMap<_, _> = (0..=10)
            .map(|_| {
                let neuron = next_test_neuron().build();
                (neuron.id().id, neuron)
            })
            .collect();
        let neuron_store = NeuronStore::new(neurons.clone());
        with_stable_neuron_indexes_mut(|indexes| {
            for neuron in neurons.values() {
                indexes.remove_neuron(neuron).unwrap()
            }
        });

        let mut validator = NeuronDataValidator::new();
        let mut now = 1;
        while validator.maybe_validate(now, &neuron_store) {
            now += 1;
        }

        let summary = validator.summary();
        let current_issue_groups = summary.current_issues_summary.unwrap().issue_groups;
        for issue_group in current_issue_groups {
            assert!(issue_group.example_issues.len() <= 10);
        }
    }
}
