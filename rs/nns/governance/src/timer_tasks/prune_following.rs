use ic_nervous_system_long_message::is_message_over_threshold;
use ic_nervous_system_timer_task::RecurringSyncTask;
use ic_nns_common::pb::v1::NeuronId;
use std::{cell::RefCell, ops::Bound, thread::LocalKey, time::Duration};

use crate::governance::Governance;

const PRUNE_FOLLOWING_INTERVAL: Duration = Duration::from_secs(10);

// Once this amount of instructions is used by the
// Governance::prune_some_following, it stops, saves where it is, schedules more
// pruning later, and returns.
//
// Why this value seems to make sense:
//
// I think we can conservatively estimate that it takes 2e6 instructions to pull
// a neuron from stable memory. If we assume 200e3 neurons are in stable memory,
// then 400e9 instructions are needed to read all neurons in stable memory.
// 400e9 instructions / 50e6 instructions per batch = 8e3 batches. If we process
// 1 batch every 10 s (see PRUNE_FOLLOWING_INTERVAL), then it would take less
// than 23 hours to complete a full pass.
//
// This comes to 1.08 full passes per day. If each full pass uses 400e9
// instructions, then we use 432e9 instructions per day doing
// prune_some_following. If we assume 1 terainstruction costs 1 XDR,
// prune_some_following uses less than half an XDR per day.
const MAX_PRUNE_SOME_FOLLOWING_INSTRUCTIONS: u64 = 50_000_000;

pub(super) struct PruneFollowingTask {
    governance: &'static LocalKey<RefCell<Governance>>,
    begin: Bound<NeuronId>,
}

impl PruneFollowingTask {
    pub fn new(governance: &'static LocalKey<RefCell<Governance>>) -> Self {
        Self {
            governance,
            begin: Bound::Unbounded,
        }
    }
}

impl RecurringSyncTask for PruneFollowingTask {
    fn execute(self) -> (Option<Duration>, Self) {
        let new_begin = self.governance.with_borrow_mut(|governance| {
            let carry_on = || !is_message_over_threshold(MAX_PRUNE_SOME_FOLLOWING_INSTRUCTIONS);
            governance.prune_some_following(self.begin, carry_on)
        });

        (
            Some(PRUNE_FOLLOWING_INTERVAL),
            Self {
                governance: self.governance,
                begin: new_begin,
            },
        )
    }

    fn initial_delay(&self) -> Duration {
        Duration::from_secs(0)
    }

    const NAME: &'static str = "prune_following";
}
