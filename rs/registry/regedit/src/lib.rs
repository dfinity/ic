pub mod args;
mod diff;
mod json;
mod normalization;
mod projection;
mod protobuf;
mod snapshot;
mod source;
mod tests;

use anyhow::Result;
use args::{universal_projection, Command, RegistrySpec, SourceSpec, VersionSpec};
use ic_base_types::RegistryVersion;
use ic_registry_local_store::{LocalStoreImpl, LocalStoreWriter};
use normalization::NormalizedSnapshot;
use serde_json::Value;
use snapshot::Snapshot;
use std::path::PathBuf;

fn registry_spec_to_snapshot(registry_spec: RegistrySpec) -> Result<Snapshot> {
    let cl = source::get_changelog(registry_spec.source)?;
    snapshot::changelog_to_snapshot(cl, registry_spec.version)
}

pub fn execute_command(cmd: Command) -> Result<Value> {
    let res = match cmd {
        Command::Snapshot {
            registry_spec,
            projection,
        } => {
            let snapshot = registry_spec_to_snapshot(registry_spec)?;
            let (normalized_snapshot, _) = normalization::normalize(snapshot.0);
            projection::project(normalized_snapshot.0, projection)
        }
        Command::ShowDiff {
            registry_spec,
            snapshot,
        } => {
            let base_snapshot = registry_spec_to_snapshot(registry_spec)?;
            let (_, inv_map) = normalization::normalize(base_snapshot.0.clone());
            let expanded_snapshot = normalization::expand(&inv_map, NormalizedSnapshot(snapshot));
            let diff = diff::make_diff(base_snapshot, expanded_snapshot)?;
            let (normalized_diff, _) = normalization::normalize(diff.0);
            normalized_diff.0
        }
        Command::ApplyUpdate {
            local_store_path,
            snapshot,
            amend,
        } => {
            let base_snapshot = registry_spec_to_snapshot(RegistrySpec {
                source: SourceSpec::LocalStore(local_store_path.clone()),
                version: VersionSpec::RelativeToLatest(0),
            })?;

            let (_, inv_map) = normalization::normalize(base_snapshot.0.clone());
            let expanded_snapshot = normalization::expand(&inv_map, NormalizedSnapshot(snapshot));
            let diff = diff::make_diff(base_snapshot, expanded_snapshot)?;
            let (v, changelog_entry) = diff::diff_to_changelog_entry(diff.clone())?;

            let local_store = LocalStoreImpl::new(&local_store_path);
            let v = if amend {
                v - RegistryVersion::from(1)
            } else {
                v
            };
            local_store.store(v, changelog_entry)?;
            diff.0
        }
    };
    Ok(res)
}

pub fn load_registry_local_store(local_store_path: PathBuf) -> Result<Value> {
    execute_command(args::Command::Snapshot {
        registry_spec: args::RegistrySpec {
            version: None.into(),
            source: SourceSpec::LocalStore(local_store_path),
        },
        projection: universal_projection(),
    })
}
