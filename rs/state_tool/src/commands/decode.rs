//! Displays a pretty-printed debug view of a state file.

use ic_protobuf::state::{
    canister_state_bits::v1 as pb_canister, ingress::v1 as pb_ingress, queues::v1 as pb_queues,
    system_metadata::v1 as pb_metadata,
};
use ic_replicated_state::CheckpointLoadingMetrics;
use ic_replicated_state::{
    canister_state::CanisterQueues, metadata_state::IngressHistoryState, SystemMetadata,
};
use ic_state_layout::{
    CanisterStateBits, ProtoFileWith, ReadOnly, CANISTER_FILE, INGRESS_HISTORY_FILE, QUEUES_FILE,
    SUBNET_QUEUES_FILE, SYSTEM_METADATA_FILE,
};
use ic_state_manager::CheckpointMetrics;
use std::convert::TryFrom;
use std::path::PathBuf;

/// Decodes the `.pbuf` state file located at `path`.
pub fn do_decode(path: PathBuf) -> Result<(), String> {
    let dummy_metrics_registry = ic_metrics::MetricsRegistry::new();
    let dummy_metrics = CheckpointMetrics::new(&dummy_metrics_registry, crate::commands::logger());
    let fname = path
        .file_name()
        .ok_or_else(|| format!("failed to get file name of path {}", path.display()))?
        .to_str()
        .ok_or_else(|| format!("failed to convert path {} to UTF-8 string", path.display()))?;
    match fname {
        SYSTEM_METADATA_FILE => {
            display_proto_with_error_metric::<pb_metadata::SystemMetadata, SystemMetadata>(
                path.clone(),
                &dummy_metrics as &dyn CheckpointLoadingMetrics,
            )
        }
        INGRESS_HISTORY_FILE => {
            display_proto::<pb_ingress::IngressHistoryState, IngressHistoryState>(path.clone())
        }
        QUEUES_FILE | SUBNET_QUEUES_FILE => {
            display_proto_with_error_metric::<pb_queues::CanisterQueues, CanisterQueues>(
                path.clone(),
                &dummy_metrics as &dyn CheckpointLoadingMetrics,
            )
        }
        CANISTER_FILE => {
            display_proto::<pb_canister::CanisterStateBits, CanisterStateBits>(path.clone())
        }
        _ => Err(format!("don't know how to decode {}", fname)),
    }
}

/// Pretty prints the `RustType` persisted at `path`, encoded as `ProtoType`.
/// This is for Rust types that require `CheckpointLoadingMetrics` for
/// deserialization.
fn display_proto_with_error_metric<'a, ProtoType, RustType>(
    path: PathBuf,
    metrics: &'a dyn CheckpointLoadingMetrics,
) -> Result<(), String>
where
    ProtoType: prost::Message + Default,
    RustType: TryFrom<(ProtoType, &'a dyn CheckpointLoadingMetrics)> + std::fmt::Debug,
    <RustType as TryFrom<(ProtoType, &'a dyn CheckpointLoadingMetrics)>>::Error: std::fmt::Display,
{
    let f: ProtoFileWith<ProtoType, ReadOnly> = path.into();
    let pb = f.deserialize().map_err(|e| format!("{:?}", e))?;
    let t = RustType::try_from((pb, metrics)).map_err(|e| {
        format!(
            "failed to decode rust type {} from protobuf {}: {}",
            std::any::type_name::<RustType>(),
            std::any::type_name::<ProtoType>(),
            e
        )
    })?;
    println!("{:#?}", t);
    Ok(())
}

/// Pretty prints the `RustType` persisted at `path`, encoded as `ProtoType`.
fn display_proto<ProtoType, RustType>(path: PathBuf) -> Result<(), String>
where
    ProtoType: prost::Message + Default,
    RustType: TryFrom<ProtoType> + std::fmt::Debug,
    <RustType as TryFrom<ProtoType>>::Error: std::fmt::Display,
{
    let f: ProtoFileWith<ProtoType, ReadOnly> = path.into();
    let pb = f.deserialize().map_err(|e| format!("{:?}", e))?;
    let t = RustType::try_from(pb).map_err(|e| {
        format!(
            "failed to decode rust type {} from protobuf {}: {}",
            std::any::type_name::<RustType>(),
            std::any::type_name::<ProtoType>(),
            e
        )
    })?;
    println!("{:#?}", t);
    Ok(())
}
