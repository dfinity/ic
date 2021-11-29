//! Displays a pretty-printed debug view of a state file.

use ic_protobuf::state::{
    canister_state_bits::v1 as pb_canister, queues::v1 as pb_queues,
    system_metadata::v1 as pb_metadata,
};
use ic_replicated_state::{canister_state::CanisterQueues, SystemMetadata};
use ic_state_layout::{CanisterStateBits, ProtoFileWith, ReadOnly};
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
        "system_metadata.pbuf" => {
            display_proto::<pb_metadata::SystemMetadata, SystemMetadata>(path.clone())
        }
        "queues.pbuf" => display_proto::<pb_queues::CanisterQueues, CanisterQueues>(path.clone()),
        "subnet_queues.pbuf" => {
            display_proto::<pb_queues::CanisterQueues, CanisterQueues>(path.clone())
        }
        "canister.pbuf" => {
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
