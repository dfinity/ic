//! Prunes a replicated state, as part of a subnet split.

use ic_logger::replica_logger::no_op_logger;
use ic_metrics::MetricsRegistry;
use ic_registry_routing_table::CanisterIdRange;
use ic_state_manager::split::resolve_ranges_and_split;
use ic_types::{PrincipalId, Time};
use std::path::PathBuf;

/// Loads the latest checkpoint under the given root; splits off the state of
/// `subnet_id`, retaining or dropping the provided canister ID ranges (exactly
/// one of which must be non-empty); and writes back the split state as a new
/// checkpoint, under the same root.
pub fn do_split(
    root: PathBuf,
    subnet_id: PrincipalId,
    retain: Vec<CanisterIdRange>,
    drop: Vec<CanisterIdRange>,
    new_subnet_batch_time: Option<Time>,
) -> Result<(), String> {
    resolve_ranges_and_split(
        root,
        subnet_id,
        retain,
        drop,
        new_subnet_batch_time,
        &MetricsRegistry::new(),
        no_op_logger(),
    )
}
