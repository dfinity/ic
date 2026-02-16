use crate::{
    pb::v1::{CreateServiceNervousSystem, SelfDescribingValue},
    proposals::self_describing::LocallyDescribableProposalAction,
};

use ic_nervous_system_proto::pb::v1::{Duration, GlobalTimeOfDay};

impl CreateServiceNervousSystem {
    /// Computes timestamps for when the SNS token swap will start, and will be
    /// due, based on the start and end times.
    ///
    /// The swap will start on the first `start_time_of_day` that is more than
    /// 24h after the swap was approved.
    ///
    /// The end time is calculated by adding `duration` to the computed start time.
    ///
    /// if start_time_of_day is None, then randomly_pick_swap_start is used to
    /// pick a start time.
    pub fn swap_start_and_due_timestamps(
        start_time_of_day: GlobalTimeOfDay,
        duration: Duration,
        swap_approved_timestamp_seconds: u64,
    ) -> Result<(u64, u64), String> {
        ic_nns_governance_api::CreateServiceNervousSystem::swap_start_and_due_timestamps(
            start_time_of_day,
            duration,
            swap_approved_timestamp_seconds,
        )
    }
}

impl LocallyDescribableProposalAction for CreateServiceNervousSystem {
    const TYPE_NAME: &'static str = "Create Service Nervous System (SNS)";
    const TYPE_DESCRIPTION: &'static str = "Create a new Service Nervous System (SNS).";

    fn to_self_describing_value(&self) -> SelfDescribingValue {
        SelfDescribingValue::from(self.clone())
    }
}
