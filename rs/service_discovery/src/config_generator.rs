use std::collections::BTreeSet;

use crate::TargetGroup;

pub trait ConfigGenerator: Send {
    fn generate_config(
        &self,
        job: &str,
        target_group: BTreeSet<TargetGroup>,
    ) -> std::io::Result<()>;
}
