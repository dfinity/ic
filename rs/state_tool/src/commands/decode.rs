//! Displays a pretty-printed debug view of a state file.

use ic_protobuf::state::{
    canister_state_bits::v1 as pb_canister, ingress::v1 as pb_ingress, queues::v1 as pb_queues,
    system_metadata::v1 as pb_metadata,
};
use ic_replicated_state::{
    canister_state::CanisterQueues, metadata_state::IngressHistoryState, SystemMetadata,
};
use ic_state_layout::{
    CanisterStateBits, ProtoFileWith, ReadOnly, CANISTER_FILE, INGRESS_HISTORY_FILE, QUEUES_FILE,
    SUBNET_QUEUES_FILE, SYSTEM_METADATA_FILE,
};
use std::convert::TryFrom;
use std::path::PathBuf;

/// Decodes the `.pbuf` state file located at `path`.
pub fn do_decode(path: PathBuf) -> Result<(), String> {
    let fname = path
        .file_name()
        .ok_or_else(|| format!("failed to get file name of path {}", path.display()))?
        .to_str()
        .ok_or_else(|| format!("failed to convert path {} to UTF-8 string", path.display()))?;
    match fname {
        SYSTEM_METADATA_FILE => {
            display_proto::<pb_metadata::SystemMetadata, SystemMetadata>(path.clone())
        }
        INGRESS_HISTORY_FILE => {
            display_proto::<pb_ingress::IngressHistoryState, IngressHistoryState>(path.clone())
        }
        QUEUES_FILE | SUBNET_QUEUES_FILE => {
            display_proto::<pb_queues::CanisterQueues, CanisterQueues>(path.clone())
        }
        CANISTER_FILE => {
            display_proto::<pb_canister::CanisterStateBits, CanisterStateBits>(path.clone())
        }
        _ => Err(format!("don't know how to decode {}", fname)),
    }
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
