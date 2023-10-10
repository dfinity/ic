use std::collections::BTreeSet;

use crate::contracts::TargetDto;

pub mod log_vector_config_structure;
pub mod prometheus_config_structure;
pub mod vector_config_enriched;

pub trait ConfigBuilder {
    fn build(&self, target_groups: BTreeSet<TargetDto>) -> String;
}
