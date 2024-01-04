use std::collections::BTreeSet;

use crate::contracts::target::TargetDto;

pub mod exec_log_config_structure;
pub mod log_vector_config_structure;
pub mod prometheus_config_structure;
pub mod script_log_config_structure;
pub mod sns_canister_config_structure;
pub mod vector_config_enriched;

pub trait ConfigBuilder {
    fn build(&self, target_groups: BTreeSet<TargetDto>) -> String;
}
