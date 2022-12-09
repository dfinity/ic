use std::collections::BTreeSet;

use crate::{job_types::JobType, TargetGroup};

pub trait ConfigGenerator: Send {
    fn generate_config(
        &self,
        job: JobType,
        target_group: BTreeSet<TargetGroup>,
    ) -> std::io::Result<()>;
}
