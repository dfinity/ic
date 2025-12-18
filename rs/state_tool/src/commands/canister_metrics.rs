use std::io::Write;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use ic_logger::no_op_logger;
use ic_metrics::MetricsRegistry;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::CanisterMetrics;
use ic_replicated_state::canister_state::system_state::LoadMetrics;
use ic_replicated_state::page_map::TestPageAllocatorFileDescriptorImpl;
use ic_state_layout::CompleteCheckpointLayout;
use ic_state_manager::{CheckpointMetrics, checkpoint::load_checkpoint};
use ic_types::Height;

const HEIGHT_IS_IRRELEVANT_BECAUSE_ITS_UNUSED: Height = Height::new(0);

/// Loads the replicated state at the checkpoint and creates a csv file with all [`CanisterMetrics`]
/// for each canister in the state.
pub fn get(
    checkpoint_dir: PathBuf,
    subnet_type: SubnetType,
    output_path: &Path,
) -> Result<(), String> {
    let replicated_state = load_checkpoint(
        &CompleteCheckpointLayout::new_untracked(
            checkpoint_dir,
            HEIGHT_IS_IRRELEVANT_BECAUSE_ITS_UNUSED,
        )
        .map_err(|err| format!("Failed to create CheckpointLayout: {err:?}"))?,
        subnet_type,
        &CheckpointMetrics::new(&MetricsRegistry::new(), no_op_logger()),
        None,
        Arc::new(TestPageAllocatorFileDescriptorImpl::new()),
    )
    .map_err(|err| format!("Failed to load the checkpoint: {err:?}"))?;

    let mut output_file = std::fs::File::create(&output_path)
        .map_err(|err| format!("Failed to create the output file: {err}"))?;
    // Write the header.
    writeln!(
        output_file,
        "canister_id,instructions_executed,ingress_messages_executed,xnet_messages_executed,intranet_messages_executed,http_outcalls_executed,heartbeats_executed,global_timers_executed"
    )
    .map_err(|err| format!("Failed to write header: {err}"))?;

    // Write rows.
    for (canister_id, canister_state) in replicated_state.canister_states {
        let CanisterMetrics {
            instructions_executed,
            load_metrics:
                LoadMetrics {
                    ingress_messages_executed,
                    xnet_messages_executed,
                    intranet_messages_executed,
                    http_outcalls_executed,
                    heartbeats_executed,
                    global_timers_executed,
                },
            ..
        } = canister_state.system_state.canister_metrics;
        writeln!(
            output_file,
            "{canister_id},{instructions_executed},{ingress_messages_executed},{xnet_messages_executed},{intranet_messages_executed},{http_outcalls_executed},{heartbeats_executed},{global_timers_executed}"
        )
        .map_err(|err| format!("Failed to write row: {err}"))?;
    }

    Ok(())
}
