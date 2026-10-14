use crate::CanisterCyclesCostSchedule;
use serde::{Deserialize, Serialize};

/// Groups the subnet configuration parameters needed for cycle cost calculations.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CyclesAccountManagerSubnetConfig {
    pub subnet_size: usize,
    pub cost_schedule: CanisterCyclesCostSchedule,
    /// Reference value of a subnet size that all fees are calculated for.
    /// Fees for a real subnet are calculated proportionally to this reference value.
    pub reference_subnet_size: usize,
}

impl CyclesAccountManagerSubnetConfig {
    pub fn new(
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
        reference_subnet_size: usize,
    ) -> Self {
        Self {
            subnet_size,
            cost_schedule,
            reference_subnet_size,
        }
    }
}
