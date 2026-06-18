use crate::CanisterCyclesCostSchedule;
use serde::{Deserialize, Serialize};

/// Groups the subnet configuration parameters needed for cycle cost calculations.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CyclesAccountManagerSubnetConfig {
    pub subnet_size: usize,
    pub cost_schedule: CanisterCyclesCostSchedule,
}

impl CyclesAccountManagerSubnetConfig {
    pub fn new(subnet_size: usize, cost_schedule: CanisterCyclesCostSchedule) -> Self {
        Self {
            subnet_size,
            cost_schedule,
        }
    }
}
