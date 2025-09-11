pub mod args;
mod diff;
mod json;
mod normalization;
mod projection;
mod protobuf;
mod snapshot;
mod source;
mod tests;

use anyhow::{Result, anyhow};
use args::{Command, RegistrySpec, SourceSpec, VersionSpec, universal_projection};
use ic_base_types::RegistryVersion;
use ic_registry_local_store::{
    KeyMutation, LocalStoreImpl, LocalStoreWriter, changelog_to_compact_delta,
};
use normalization::NormalizedSnapshot;
use serde_json::Value;
use snapshot::Snapshot;
use std::{fs::File, io::Write, path::PathBuf};

fn registry_spec_to_snapshot(registry_spec: RegistrySpec) -> Result<Snapshot> {
    let cl = source::get_changelog(registry_spec.source)?;
    snapshot::changelog_to_snapshot(cl, registry_spec.version)
}

/// Returns registry entries in delta pb encoded format with the latest version that appears in the pb.
fn registry_spec_to_delta_pb(
    source_spec: SourceSpec,
    start_version: RegistryVersion,
    stop_version: Option<RegistryVersion>,
) -> Result<(Vec<u8>, RegistryVersion)> {
    let (mut registry_changelogs, latest_registry_version) = source::get_changelog(source_spec)?;
    // Sort according to registry versions.
    registry_changelogs.sort_by(|a, b| a.version.cmp(&b.version));
    // Clip registry versions that are not within requested interval.
    registry_changelogs.retain(|a| {
        a.version >= start_version
            && a.version <= stop_version.unwrap_or_else(|| RegistryVersion::from(u64::MAX))
    });

    // Convert from [(RegistryVersion, Key, Value)] format
    // to (BaseRegistryVersion, [[(Key, Value)]]) where the vector indices
    // represent the registry version offset to BaseRegistryVersion
    let base_registry_version = registry_changelogs
        .first()
        .ok_or_else(|| anyhow!("registry changelog empty"))?
        .version;
    let local_store_changelog = registry_changelogs.into_iter().fold(vec![], |mut cl, r| {
        let v_delta = (r.version - start_version).get() + 1;
        if cl.len() < v_delta as usize {
            cl.push(Vec::new())
        }
        cl.last_mut().unwrap().push(KeyMutation {
            key: r.key.clone(),
            value: r.value.clone(),
        });
        cl
    });

    // let local_store_changelog: Changelog = key_mutations_at_versions.values().cloned().collect();

    let pb = changelog_to_compact_delta(base_registry_version, local_store_changelog)?;
    Ok((pb, stop_version.unwrap_or(latest_registry_version)))
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
        Command::CanisterToProto {
            start_version,
            latest_version,
            source_spec,
            path,
        } => {
            let (pb, latest_registry_version_in_pb) =
                registry_spec_to_delta_pb(source_spec, start_version, latest_version)?;

            let pb_path = if path.is_absolute() {
                path.display().to_string()
            } else {
                let current_dir = std::env::current_dir()?;
                current_dir.join(path.clone()).display().to_string()
            };

            let mut f = File::create(path)?;
            f.write_all(&pb)?;
            Value::String(format!(
                "Successfully written registry delta protbobuf for version range {start_version}-{latest_registry_version_in_pb} to: {pb_path}"
            ))
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
