use crate::{
    json, protobuf,
    snapshot::{Snapshot, SPECIAL_FIELD_PREFIX, VERSION_FIELD},
};
use anyhow::{anyhow, ensure, Result};
use ic_base_types::RegistryVersion;
use ic_registry_local_store::{ChangelogEntry, KeyMutation};
use serde_json::Value;
use std::collections::BTreeMap;
use thiserror::Error;

pub const DELETED_MARKER: &str = "(deleted)";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diff(pub Value);

pub fn make_diff(base_snapshot: Snapshot, new_snapshot: Snapshot) -> Result<Diff> {
    let base_version =
        snapshot_to_version(&base_snapshot.0).map_err(|e| e.context("base snapshot"))?;
    let new_version = snapshot_to_version(&new_snapshot.0).map_err(|e| e.context("new version"))?;
    // compare versions
    ensure!(
        base_version <= new_version,
        DiffErr::IncompatibleVersions {
            base_version,
            new_version
        }
    );

    let new_version = if base_version == new_version {
        new_version + 1
    } else {
        new_version
    };

    let base_value = base_snapshot
        .0
        .as_object()
        .ok_or_else(|| DiffErr::InvalidJsonValue("Base Snapshot is not an Object".into()))?;
    let new_value = new_snapshot
        .0
        .as_object()
        .ok_or_else(|| DiffErr::InvalidJsonValue("New Snapshot is not an Object.".into()))?;

    let mut res = BTreeMap::default();
    for (k, v_base) in base_value.iter() {
        if let Some(v) = new_value.get(k) {
            if v != v_base {
                res.insert(k.clone(), v.clone());
            }
        } else {
            let deleted_marker = json::assert_to_value(DELETED_MARKER);
            res.insert(k.clone(), deleted_marker);
        }
    }

    for (k, v) in new_value
        .iter()
        .filter(|(k, _)| !base_value.contains_key(*k))
    {
        res.insert(k.clone(), v.clone());
    }

    res.insert(
        VERSION_FIELD.to_string(),
        json::assert_to_value(new_version),
    );

    Ok(Diff(json::assert_to_value(&res)))
}

pub fn diff_to_changelog_entry(diff: Diff) -> Result<(RegistryVersion, ChangelogEntry)> {
    let v = RegistryVersion::from(snapshot_to_version(&diff.0)?);

    let mut changelog_entry = ChangelogEntry::default();
    let obj = diff
        .0
        .as_object()
        .ok_or_else(|| anyhow!(DiffErr::InvalidJsonValue("Expected an object.".into())))?;
    for (k, v) in obj
        .iter()
        .filter(|(k, _)| !k.starts_with(SPECIAL_FIELD_PREFIX))
    {
        let key = k.clone();
        let value = if !is_deleted_marker(v) {
            Some(protobuf::value_to_raw_data(k, v.clone()))
        } else {
            None
        };
        changelog_entry.push(KeyMutation { key, value });
    }

    Ok((v, changelog_entry))
}

pub fn snapshot_to_version(obj: &Value) -> Result<u64> {
    obj.as_object()
        .ok_or_else(|| anyhow!(DiffErr::InvalidJsonValue("Expected object.".into())))
        .and_then(|obj| {
            obj.get(VERSION_FIELD)
                .ok_or(DiffErr::VersionMissing)?
                .as_u64()
                .ok_or_else(|| anyhow!(DiffErr::InvalidJsonValue("Version is not a u64".into(),)))
        })
}

fn is_deleted_marker(value: &Value) -> bool {
    value.as_str().map(|s| s == DELETED_MARKER).unwrap_or(false)
}

#[derive(Clone, Debug, Error)]
pub enum DiffErr {
    #[error(
        "Versions are not compatible\
    (base_version: {base_version:}, snapshot_version: {new_version:}"
    )]
    IncompatibleVersions { base_version: u64, new_version: u64 },

    #[error("Invalid Snapshot object: '__version'-key is missing.")]
    VersionMissing,

    #[error("Invalid object structure: {0}")]
    InvalidJsonValue(String),
}
