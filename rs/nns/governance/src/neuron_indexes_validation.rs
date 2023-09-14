#![allow(dead_code)] // TODO(NNS1-2413): remove after calling it in heartbeat.
use crate::neuron_store::NeuronStore;

use ic_nns_common::pb::v1::NeuronId;
use std::{collections::VecDeque, marker::PhantomData};

#[cfg(target_arch = "wasm32")]
use dfn_core::println;

const MAX_VALIDATION_AGE_SECONDS: u64 = 60 * 60 * 24;

// TODO(NNS1-2413): add actual issues found by validation.
enum ValidationIssue {}

/// A validator for all neuron indexes. It can be called in heartbeat to perform a small chunk of
/// the validation, while keeping track of its progress.
pub struct NeuronIndexesValidator {
    state: State,
    issues: Issues,
}

// TODO(NNS-2413): add a method to read the status of the in-progress/previous validation result.
impl NeuronIndexesValidator {
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

        let issue = validation_in_progress.validate_next_chunk(neuron_store);
        self.issues.update(now, issue);

        if validation_in_progress.tasks.is_done() {
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

        Self {
            started_time_seconds: now,
            tasks,
        }
    }

    fn is_done(&self) -> bool {
        self.tasks.is_done()
    }

    fn validate_next_chunk(&mut self, neuron_store: &NeuronStore) -> Option<ValidationIssue> {
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

    fn update(&mut self, now: u64, issue: Option<ValidationIssue>) {
        self.updated_time_seconds = now;
        if let Some(issue) = issue {
            self.issues.push(issue);
        }
    }
}

/// A validation task which can be composed of multiple tasks.
trait ValidationTask {
    /// Whether the task has been done. If composed of multiple tasks, whether every subtask is done.
    fn is_done(&self) -> bool;

    /// Performs the next chunk of validation.
    fn validate_next_chunk(&mut self, neuron_store: &NeuronStore) -> Option<ValidationIssue>;
}

/// A list of tasks should also be a (composed) task.
impl ValidationTask for VecDeque<Box<dyn ValidationTask>> {
    fn is_done(&self) -> bool {
        self.is_empty()
    }

    fn validate_next_chunk(&mut self, neuron_store: &NeuronStore) -> Option<ValidationIssue> {
        let next_task = match self.front_mut() {
            Some(next_task) => next_task,
            None => return None,
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

impl<Validator: CardinalityAndRangeValidator> ValidationTask
    for CardinalitiesValidationTask<Validator>
{
    fn is_done(&self) -> bool {
        self.is_done
    }

    fn validate_next_chunk(&mut self, neuron_store: &NeuronStore) -> Option<ValidationIssue> {
        self.is_done = true;
        Validator::validate_cardinalities(neuron_store)
    }
}

struct NeuronRangeValidationTask<Validator: CardinalityAndRangeValidator> {
    next_neuron_id: Option<NeuronId>,
    // PhantomData is needed so that NeuronRangeValidationTask can be associated with a Validator
    // type without containing such a member.
    _phantom: PhantomData<Validator>,
}

impl<Validator: CardinalityAndRangeValidator> NeuronRangeValidationTask<Validator> {
    fn new() -> Self {
        Self {
            next_neuron_id: Some(NeuronId { id: 1 }),
            _phantom: PhantomData,
        }
    }
}

impl<Validator: CardinalityAndRangeValidator> ValidationTask
    for NeuronRangeValidationTask<Validator>
{
    fn is_done(&self) -> bool {
        self.next_neuron_id.is_none()
    }

    fn validate_next_chunk(&mut self, _neuron_store: &NeuronStore) -> Option<ValidationIssue> {
        // TODO(NNS1-2413): implement the validation logic.
        self.next_neuron_id = None;
        None
    }
}

struct SubaccountIndexValidator;

impl CardinalityAndRangeValidator for SubaccountIndexValidator {
    fn validate_cardinalities(_neuron_store: &NeuronStore) -> Option<ValidationIssue> {
        // TODO(NNS1-2413): implement the validation logic.
        None
    }

    fn validate_primary_neuron_has_corresponding_index_entries(
        _neuron_id: NeuronId,
        _neuron_store: &NeuronStore,
    ) -> Option<ValidationIssue> {
        // TODO(NNS1-2413): implement the validation logic.
        None
    }
}

struct PrincipalIndexValidator;

impl CardinalityAndRangeValidator for PrincipalIndexValidator {
    fn validate_cardinalities(_neuron_store: &NeuronStore) -> Option<ValidationIssue> {
        // TODO(NNS1-2413): implement the validation logic.
        None
    }

    fn validate_primary_neuron_has_corresponding_index_entries(
        _neuron_id: NeuronId,
        _neuron_store: &NeuronStore,
    ) -> Option<ValidationIssue> {
        // TODO(NNS1-2413): implement the validation logic.
        None
    }
}

struct FollowingIndexValidator;

impl CardinalityAndRangeValidator for FollowingIndexValidator {
    fn validate_cardinalities(_neuron_store: &NeuronStore) -> Option<ValidationIssue> {
        // TODO(NNS1-2413): implement the validation logic.
        None
    }

    fn validate_primary_neuron_has_corresponding_index_entries(
        _neuron_id: NeuronId,
        _neuron_store: &NeuronStore,
    ) -> Option<ValidationIssue> {
        // TODO(NNS1-2413): implement the validation logic.
        None
    }
}

struct KnownNeuronIndexValidator;

impl CardinalityAndRangeValidator for KnownNeuronIndexValidator {
    fn validate_cardinalities(_neuron_store: &NeuronStore) -> Option<ValidationIssue> {
        // TODO(NNS1-2413): implement the validation logic.
        None
    }

    fn validate_primary_neuron_has_corresponding_index_entries(
        _neuron_id: NeuronId,
        _neuron_store: &NeuronStore,
    ) -> Option<ValidationIssue> {
        // TODO(NNS1-2413): implement the validation logic.
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::pb::v1::Neuron;

    use ic_base_types::PrincipalId;
    use maplit::btreemap;

    #[test]
    fn test_finish_validation() {
        let neuron_store = NeuronStore::new(btreemap! {
            1 => Neuron {
                id: Some(NeuronId { id: 1 }),
                account: [1u8; 32].to_vec(),
                controller: Some(PrincipalId::new_user_test_id(1)),
                ..Default::default()
            },
        });
        let mut validation = NeuronIndexesValidator::new(0);

        // Each index use 2 rounds and we have 4 indexes.
        for i in 0..8 {
            assert!(validation.maybe_validate(i, &neuron_store));
        }

        // After 8 rounds it should not validate.
        assert!(!validation.maybe_validate(8, &neuron_store));

        // After 1 day it should validate again.
        assert!(validation.maybe_validate(86408, &neuron_store));
    }
}
