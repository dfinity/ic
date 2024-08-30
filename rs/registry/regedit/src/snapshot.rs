use crate::{args::VersionSpec, json, protobuf::raw_data_to_value, source::Changelog};
use anyhow::{bail, Result};
use serde_json::Value;
use std::collections::BTreeMap;
use thiserror::Error;

pub const VERSION_FIELD: &str = "__version";
pub const SPECIAL_FIELD_PREFIX: &str = "__";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot(pub Value);

pub fn changelog_to_snapshot(changelog: Changelog, version: VersionSpec) -> Result<Snapshot> {
    let (mut changelog, v) = changelog;
    let bound = match version {
        VersionSpec::RelativeToLatest(r) => {
            if r > v.get() {
                bail!(SnapshotCreationError::RelativeVersionTooOld {
                    latest_version: v.get(),
                    relative_version: -(r as i64)
                });
            } else {
                v.get() - r
            }
        }
        VersionSpec::Absolute(v) => v.get(),
    };

    changelog.retain(|x| x.version.get() <= bound);
    changelog.sort_by_key(|x| x.version);

    let mut res = BTreeMap::default();
    let latest_version = changelog.last().map(|r| r.version.get()).unwrap_or(0);
    for entry in changelog {
        if let Some(v) = entry.value {
            res.insert(entry.key.to_string(), v);
        } else {
            res.remove(&entry.key);
        }
    }

    let mut res: BTreeMap<String, Value> = res
        .iter()
        .map(|(k, v)| (k.to_string(), raw_data_to_value(k, v)))
        .collect();
    res.insert(
        VERSION_FIELD.to_string(),
        json::assert_to_value(latest_version),
    );

    let json_val = json::assert_to_value(res);

    Ok(Snapshot(json_val))
}

#[derive(Debug, Error)]
pub enum SnapshotCreationError {
    #[error(
        "Specified relative version is too old. (Latest version:
    #{latest_version:}, relative version: {relative_version:})"
    )]
    RelativeVersionTooOld {
        latest_version: u64,
        relative_version: i64,
    },
}
