use ic_base_types::NumBytes;
use ic_types::{Cycles, NumInstructions};
use serde::{Deserialize, Serialize};

// DEPRECATED: as this configuration has some fields that can be different on
// different subnets, use of this struct is now deprecated.
#[derive(Clone, Deserialize, Debug, PartialEq, Eq, Serialize)]
#[serde(default)]
pub struct Config {
    /// Number of canisters that the scheduler is allowed to schedule in
    /// parallel on the NNS subnet.
    pub nns_subnet_scheduler_cores: usize,

    /// Number of canisters that the scheduler is allowed to schedule in
    /// parallel on the non-NNS subnet.
    pub non_nns_subnet_scheduler_cores: usize,

    /// Maximum amount of instructions a single round can consume (on one
    /// thread).
    pub max_instructions_per_round: NumInstructions,
    /// Maximum amount of instructions a single message's execution can consume.
    /// This should be significantly smaller than `max_instructions_per_round`.
    pub max_instructions_per_message: NumInstructions,

    /// This specifies the upper limit on how much delta all the canisters
    /// together on the subnet can produce in between checkpoints. This is a
    /// soft limit in the sense, that we will continue to execute canisters as
    /// long the current delta size is below this limit and stop if the current
    /// size is above this limit. Hence, it is possible that the actual usage of
    /// the subnet goes above this limit.
    pub subnet_state_delta_change_capacity: NumBytes,

    /// Maximum amount of cycles a single round can consume (on one
    /// thread).
    pub round_cycles_max: Cycles,
    /// Maximum amount of cycles a single message's execution can
    /// consume. This has to be significantly smaller than `round_cycles_max`.
    pub exec_cycles: Cycles,

    /// Number of cores that the execution component is allowed to
    /// schedule canisters on. This is now deprecated and only exists to keep
    /// backwards compatibility with older `ic.json5`.
    pub scheduler_cores: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            scheduler_cores: 0,
            nns_subnet_scheduler_cores: 0,
            non_nns_subnet_scheduler_cores: 0,
            subnet_state_delta_change_capacity: NumBytes::from(0),
            max_instructions_per_round: NumInstructions::from(0),
            max_instructions_per_message: NumInstructions::from(0),
            round_cycles_max: Cycles::from(0),
            exec_cycles: Cycles::from(0),
        }
    }
}
