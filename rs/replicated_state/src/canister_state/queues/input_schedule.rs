#![allow(dead_code)]

use super::queue::CanisterQueue;
use super::CanisterQueues;
use crate::{InputQueueType, InputSource};
use ic_protobuf::proxy::ProxyDecodeError;
use ic_protobuf::state::queues::v1::canister_queues::NextInputQueue;
use ic_protobuf::types::v1 as pb_types;
use ic_types::CanisterId;
use std::collections::{BTreeSet, VecDeque};
use std::convert::TryFrom;

#[cfg(test)]
mod tests;

/// Round-robin schedule for canister inputs, across ingress, local senders and
/// remote senders; as well as within local senders and remote senders.
///
/// We define three buckets of queues ("sources"): messages from canisters on
/// the same subnet ("local senders"); ingress; and messages from canisters on
/// other subnets ("remote senders"). Each time an input is popped or skipped,
/// we rotate round-robin between the three sources. We also rotate round-robin
/// over the canisters in the local sender and remote serder buckets when we pop
/// or skip messages from those sources.
///
/// # Soft invariants
///
/// There are three possible outcomes of an inconsistent `InputSchedule`:
///
///  * An input queue is scheduled multiple times, leading to unfairness.
///  * An input queue is never scheduled, leading to starvation.
///  * Replica divergence, if a restarted replica loads an internally consistent
///    `InputSchedule`, while other replicas continue with a mismatch between
///    the two schedules on the one hand and `scheduled_senders` on the other.
///
/// All of the above occurrences would be detected from critical errors or other
/// alerting. They are also exceedingly unlikely to result in a crash loop,
/// unlike the use of `assert!()` to enforce hard invariants.
///
/// As a result, we rely on defensive programming and validation to check the
/// following soft invariants:
///
///  * All non-empty input queues are scheduled exactly once.
///  * A sender is enqueued in the local or remote input schedule iff present in
///    the `scheduled_senders` set.
///  * Local canisters (including ourselves) are scheduled in the local sender
///    schedule. Canisters that are not known to be local (including potentially
///    deleted local canisters) may be scheduled in either input schedule.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct InputSchedule {
    /// The input source (local senders, ingress or remote senders) at the front
    /// of the schedule.
    ///
    /// Used to implement round-robin rotation over input sources.
    next_input_source: InputSource,

    /// FIFO queue of local subnet sender canister IDs ensuring round-robin
    /// consumption of input messages. All local senders with non-empty queues
    /// are scheduled.
    ///
    /// We rely on `ReplicatedState::canister_states` to decide whether a canister
    /// is local or not. This test is subject to race conditions (e.g. if the sender
    /// has just been deleted), meaning that the separation into local and remote
    /// senders is best effort.
    local_sender_schedule: VecDeque<CanisterId>,

    /// FIFO queue of remote subnet sender canister IDs ensuring round-robin
    /// consumption of input messages. All remote senders with non-empty queues
    /// are scheduled.
    ///
    /// We rely on `ReplicatedState::canister_states` to decide whether a canister
    /// is local or not. This test is subject to race conditions (e.g. if the sender
    /// has just been deleted), meaning that the separation into local and remote
    /// senders is best effort.
    remote_sender_schedule: VecDeque<CanisterId>,

    /// Set of all senders enqueued in either `local_sender_schedule` or
    /// `remote_sender_schedule`, to ensure that a sender is enqueued at most once.
    ///
    /// We cannot rely on the input queue going from empty to non-empty as the only
    /// condition for whether to enqueue a sender, because the contents of the queue
    /// may have been dropped (expired or shed) while the sender was already
    /// enqueued.
    scheduled_senders: BTreeSet<CanisterId>,
}

impl InputSchedule {
    /// Returns the current input source, without advancing it (e.g. for `peek()`).
    pub(super) fn input_source(&self) -> InputSource {
        self.next_input_source
    }

    /// Returns the current input source and advances to the next one.
    pub(super) fn next_input_source(&mut self) -> InputSource {
        let input_source = self.next_input_source;
        // Switch to the next input source.
        self.next_input_source = match self.next_input_source {
            InputSource::LocalSubnet => InputSource::Ingress,
            InputSource::Ingress => InputSource::RemoteSubnet,
            InputSource::RemoteSubnet => InputSource::LocalSubnet,
        };
        input_source
    }

    /// Enqueues the sender at the back of the given schedule (local or remote), iff
    /// not already enqueued (in either schedule).
    pub(super) fn schedule(&mut self, sender: CanisterId, input_queue_type: InputQueueType) {
        if self.scheduled_senders.insert(sender) {
            match input_queue_type {
                InputQueueType::LocalSubnet => self.local_sender_schedule.push_back(sender),
                InputQueueType::RemoteSubnet => self.remote_sender_schedule.push_back(sender),
            }
        }
    }

    /// Reschedules the sender from the front to the back of the given schedule
    /// (local or remote).
    ///
    /// Panics if the sender is not at the front of the given schedule.
    pub(super) fn reschedule(&mut self, sender: CanisterId, input_queue_type: InputQueueType) {
        debug_assert!(self.scheduled_senders.contains(&sender));
        let sender_schedule = match input_queue_type {
            InputQueueType::LocalSubnet => &mut self.local_sender_schedule,
            InputQueueType::RemoteSubnet => &mut self.remote_sender_schedule,
        };

        let popped = sender_schedule.pop_front();
        debug_assert_eq!(Some(sender), popped);
        if let Some(popped) = popped {
            sender_schedule.push_back(popped);
        }
    }

    /// Returns a reference to the sender at the front of the given schedule (local
    /// or remote senders), if any.
    pub(super) fn peek(&self, input_queue_type: InputQueueType) -> Option<&CanisterId> {
        match input_queue_type {
            InputQueueType::LocalSubnet => self.local_sender_schedule.front(),
            InputQueueType::RemoteSubnet => self.remote_sender_schedule.front(),
        }
    }

    /// Removes and returns the sender at the front of the given schedule (local or
    /// remote senders), if any.
    pub(super) fn pop(&mut self, input_queue_type: InputQueueType) -> Option<CanisterId> {
        let sender = match input_queue_type {
            InputQueueType::LocalSubnet => self.local_sender_schedule.pop_front(),
            InputQueueType::RemoteSubnet => self.remote_sender_schedule.pop_front(),
        }?;
        assert!(self.scheduled_senders.remove(&sender));
        Some(sender)
    }

    /// Re-partitions `self.local_sender_schedule` and `self.remote_sender_schedule`
    /// based on the determination made by `input_queue_type_fn`.
    pub(super) fn split(&mut self, input_queue_type_fn: impl Fn(&CanisterId) -> InputQueueType) {
        let local_schedule = std::mem::take(&mut self.local_sender_schedule);
        let remote_schedule = std::mem::take(&mut self.remote_sender_schedule);

        for canister_id in local_schedule.into_iter().chain(remote_schedule) {
            match input_queue_type_fn(&canister_id) {
                InputQueueType::LocalSubnet => self.local_sender_schedule.push_back(canister_id),
                InputQueueType::RemoteSubnet => self.remote_sender_schedule.push_back(canister_id),
            }
        }
    }

    /// Validates `InputSchedule`'s invariants after checkpoint loading; or in debug
    /// builds.
    ///
    /// Checks that the canister IDs of all input queues that contain at least one
    /// message are found exactly once in either the local sender schedule or in the
    /// remote sender schedule.
    ///
    /// Time complexity: `O(n * log(n))`.
    pub(super) fn test_invariants<'a>(
        &self,
        input_queues: impl Iterator<Item = (&'a CanisterId, &'a CanisterQueue)>,
        input_queue_type_fn: &dyn Fn(&CanisterId) -> InputQueueType,
    ) -> Result<(), String> {
        let mut local_schedule: BTreeSet<_> = self.local_sender_schedule.iter().collect();
        let mut remote_schedule: BTreeSet<_> = self.remote_sender_schedule.iter().collect();

        if local_schedule.len() != self.local_sender_schedule.len()
            || remote_schedule.len() != self.remote_sender_schedule.len()
            || local_schedule.intersection(&remote_schedule).count() != 0
        {
            return Err(format!(
                "Duplicate entries in local and/or remote input schedules:\n  `local_sender_schedule`: {:?}\n  `remote_sender_schedule`: {:?}",
                self.local_sender_schedule, self.remote_sender_schedule,
            ));
        }

        if self.local_sender_schedule.len() + self.remote_sender_schedule.len()
            != self.scheduled_senders.len()
            || local_schedule
                .iter()
                .chain(remote_schedule.iter())
                .any(|canister_id| !self.scheduled_senders.contains(canister_id))
        {
            return Err(
                format!("Inconsistent input schedules:\n  `local_sender_schedule`: {:?}\n  `remote_sender_schedule`: {:?}\n  `scheduled_senders`: {:?}",
                self.local_sender_schedule, self.remote_sender_schedule, self.scheduled_senders)
            );
        }

        for (canister_id, input_queue) in input_queues {
            if input_queue.len() == 0 {
                continue;
            }

            match input_queue_type_fn(canister_id) {
                InputQueueType::LocalSubnet => {
                    if !local_schedule.remove(canister_id) {
                        return Err(format!(
                            "Local canister with non-empty input queue ({:?}) absent from `local_sender_schedule`",
                            canister_id
                        ));
                    }
                }
                InputQueueType::RemoteSubnet => {
                    if !remote_schedule.remove(canister_id) && !local_schedule.remove(canister_id) {
                        return Err(format!(
                            "Remote canister with non-empty input queue ({:?}) absent from `remote_sender_schedule`",
                            canister_id
                        ));
                    }
                }
            }
        }

        // Note that a currently empty input queue may have been enqueued into an input
        // schedule before all its messages expired or were shed.

        Ok(())
    }
}

impl From<&InputSchedule> for (i32, Vec<pb_types::CanisterId>, Vec<pb_types::CanisterId>) {
    fn from(item: &InputSchedule) -> Self {
        let next_input_source = NextInputQueue::from(&item.next_input_source).into();
        let local_sender_schedule = item
            .local_sender_schedule
            .iter()
            .map(|sender| pb_types::CanisterId::from(*sender))
            .collect();
        let remote_sender_schedule = item
            .remote_sender_schedule
            .iter()
            .map(|sender| pb_types::CanisterId::from(*sender))
            .collect();
        (
            next_input_source,
            local_sender_schedule,
            remote_sender_schedule,
        )
    }
}

impl TryFrom<(i32, Vec<pb_types::CanisterId>, Vec<pb_types::CanisterId>)> for InputSchedule {
    type Error = ProxyDecodeError;
    fn try_from(
        (next_input_source, local_sender_schedule, remote_sender_schedule): (
            i32,
            Vec<pb_types::CanisterId>,
            Vec<pb_types::CanisterId>,
        ),
    ) -> Result<Self, Self::Error> {
        let next_input_source =
            InputSource::from(NextInputQueue::try_from(next_input_source).unwrap_or_default());

        let local_sender_schedule = local_sender_schedule
            .into_iter()
            .map(CanisterId::try_from)
            .collect::<Result<VecDeque<_>, _>>()?;
        let remote_sender_schedule = remote_sender_schedule
            .into_iter()
            .map(CanisterId::try_from)
            .collect::<Result<VecDeque<_>, _>>()?;
        let scheduled_senders = local_sender_schedule
            .iter()
            .cloned()
            .chain(remote_sender_schedule.iter().cloned())
            .collect();

        Ok(InputSchedule {
            next_input_source,
            local_sender_schedule,
            remote_sender_schedule,
            scheduled_senders,
        })
    }
}

/// Encapsulates information about `CanisterQueues`,
/// used in detecting a loop when consuming the input messages.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CanisterQueuesLoopDetector {
    pub local_queue_skip_count: usize,
    pub remote_queue_skip_count: usize,
    pub ingress_queue_skip_count: usize,
}

impl CanisterQueuesLoopDetector {
    /// Detects a loop in `CanisterQueues`.
    pub fn detected_loop(&self, canister_queues: &CanisterQueues) -> bool {
        let skipped_all_remote =
            self.remote_queue_skip_count >= canister_queues.remote_subnet_input_schedule.len();

        let skipped_all_local =
            self.local_queue_skip_count >= canister_queues.local_subnet_input_schedule.len();

        let skipped_all_ingress =
            self.ingress_queue_skip_count >= canister_queues.ingress_queue.ingress_schedule_size();

        // An empty queue is skipped implicitly by `peek_input()` and `pop_input()`.
        // This means that no new messages can be consumed from an input source if
        // - either it is empty,
        // - or all its queues were explicitly skipped.
        // Note that `skipped_all_remote`, `skipped_all_local`, and `skipped_all_ingress`
        // are trivially true if the corresponding input source is empty because empty
        // queues are removed from the source.
        skipped_all_remote && skipped_all_local && skipped_all_ingress
    }
}

pub mod testing {
    use super::InputSchedule;
    use ic_types::CanisterId;
    use std::collections::VecDeque;

    /// Publicly exposes testing-only `InputSchedule` fields for use in unit tests.
    pub trait InputScheduleTesting {
        /// Publicly exposes the local sender input_schedule.
        fn local_sender_schedule(&self) -> &VecDeque<CanisterId>;

        /// Publicly exposes the remote subnet input_schedule.
        fn remote_sender_schedule(&self) -> &VecDeque<CanisterId>;
    }

    impl InputScheduleTesting for InputSchedule {
        fn local_sender_schedule(&self) -> &VecDeque<CanisterId> {
            &self.local_sender_schedule
        }

        fn remote_sender_schedule(&self) -> &VecDeque<CanisterId> {
            &self.remote_sender_schedule
        }
    }
}
