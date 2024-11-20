use crate::pb::v1::governance::CachedUpgradeSteps as CachedUpgradeStepsPb;
use crate::pb::v1::governance::Version;
use crate::pb::v1::governance::Versions;
use crate::sns_upgrade::SnsCanisterType;

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CachedUpgradeSteps {
    current_version: Version,
    subsequent_versions: Vec<Version>,

    response_timestamp_seconds: u64,
    pub requested_timestamp_seconds: u64,
}

impl From<CachedUpgradeSteps> for CachedUpgradeStepsPb {
    fn from(src: CachedUpgradeSteps) -> Self {
        let CachedUpgradeSteps {
            current_version,
            subsequent_versions,
            requested_timestamp_seconds,
            response_timestamp_seconds,
        } = src;

        let upgrade_steps = {
            let mut versions = vec![current_version];
            versions.extend(subsequent_versions);
            Some(Versions { versions })
        };

        Self {
            upgrade_steps,
            requested_timestamp_seconds: Some(requested_timestamp_seconds),
            response_timestamp_seconds: Some(response_timestamp_seconds),
        }
    }
}

impl TryFrom<&CachedUpgradeStepsPb> for CachedUpgradeSteps {
    type Error = String;

    fn try_from(src: &CachedUpgradeStepsPb) -> Result<Self, Self::Error> {
        let CachedUpgradeStepsPb {
            upgrade_steps: Some(upgrade_steps),
            // requested_timestamp_seconds is not guaranteed to be <= response_timestamp_seconds,
            // when requested_timestamp_seconds > response_timestamp_seconds it indicates a request
            // for upgrade steps is in-flight. Thus we don't validate the relationship between them.
            requested_timestamp_seconds,
            response_timestamp_seconds,
        } = src
        else {
            return Err("Cannot interpret CachedUpgradeSteps; \
                 please specify the required field upgrade_steps"
                .to_string());
        };

        let Some((current_version, subsequent_versions)) = upgrade_steps.versions.split_first()
        else {
            return Err(
                "Cannot interpret CachedUpgradeSteps: upgrade_steps must not be empty.".to_string(),
            );
        };

        let requested_timestamp_seconds = requested_timestamp_seconds.unwrap_or_default();

        let response_timestamp_seconds = response_timestamp_seconds.unwrap_or_default();

        Ok(Self {
            current_version: current_version.clone(),
            subsequent_versions: subsequent_versions.to_vec(),
            requested_timestamp_seconds,
            response_timestamp_seconds,
        })
    }
}

/// Formats the first 7 bytes of a hash as a hexadecimal string.
pub fn format_short_hash(hash: &[u8]) -> String {
    hash.iter()
        .take(7)
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}

/// Formats the 32 bytes of a hash as a hexadecimal string.
pub fn format_full_hash(hash: &[u8]) -> String {
    hash.iter()
        .take(32)
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}

/// Formats the version as a Markdown table row.
fn render_markdown_row(index: usize, version: &Version, canister_changes: &str) -> String {
    format!(
        "| {} | {} | {} | {} | {} | {} | {} | {} |",
        index,
        format_short_hash(&version.root_wasm_hash[..]),
        format_short_hash(&version.governance_wasm_hash[..]),
        format_short_hash(&version.swap_wasm_hash[..]),
        format_short_hash(&version.index_wasm_hash[..]),
        format_short_hash(&version.ledger_wasm_hash[..]),
        format_short_hash(&version.archive_wasm_hash[..]),
        canister_changes,
    )
}

pub fn render_two_versions_as_markdown_table(
    current_version: &Version,
    target_version: &Version,
) -> String {
    format!(
        "| Canister   | Current version's module hash    | New target version's module hash |\n\
         |------------|----------------------------------|----------------------------------|\n\
         | Root       | {} | {} |\n\
         | Governance | {} | {} |\n\
         | Swap       | {} | {} |\n\
         | Index      | {} | {} |\n\
         | Ledger     | {} | {} |\n\
         | Archive    | {} | {} |",
        format_full_hash(&current_version.root_wasm_hash[..]),
        format_full_hash(&target_version.root_wasm_hash[..]),
        format_full_hash(&current_version.governance_wasm_hash[..]),
        format_full_hash(&target_version.governance_wasm_hash[..]),
        format_full_hash(&current_version.swap_wasm_hash[..]),
        format_full_hash(&target_version.swap_wasm_hash[..]),
        format_full_hash(&current_version.index_wasm_hash[..]),
        format_full_hash(&target_version.index_wasm_hash[..]),
        format_full_hash(&current_version.ledger_wasm_hash[..]),
        format_full_hash(&target_version.ledger_wasm_hash[..]),
        format_full_hash(&current_version.archive_wasm_hash[..]),
        format_full_hash(&target_version.archive_wasm_hash[..]),
    )
}

fn render_sns_canister_type(sns_canister_type: SnsCanisterType) -> String {
    match sns_canister_type {
        SnsCanisterType::Unspecified => "Unspecified".to_string(),
        SnsCanisterType::Root => "Root".to_string(),
        SnsCanisterType::Governance => "Governance".to_string(),
        SnsCanisterType::Swap => "Swap".to_string(),
        SnsCanisterType::Index => "Index".to_string(),
        SnsCanisterType::Ledger => "Ledger".to_string(),
        SnsCanisterType::Archive => "Archive".to_string(),
    }
}

fn render_sns_canister_change(
    canister_changes: Vec<(SnsCanisterType, Vec<u8> /*wasm hash*/)>,
) -> String {
    canister_changes
        .into_iter()
        .map(|(sns_canister_type, wasm_hash)| {
            format!(
                "{} @ {}",
                render_sns_canister_type(sns_canister_type),
                format_full_hash(&wasm_hash[..])
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

impl std::fmt::Display for CachedUpgradeSteps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "| Step | Root  | Governance | Swap  | Index | Ledger | Archive | Changes |"
        )?;
        writeln!(
            f,
            "|------|-------|------------|-------|-------|--------|---------|---------|"
        )?;
        writeln!(
            f,
            "{}",
            render_markdown_row(0, &self.current_version, "Current version")
        )?;

        let mut previous_version = &self.current_version;
        for (index, version) in self.subsequent_versions.iter().enumerate() {
            let changes = previous_version.changes_against(version);
            let changes = render_sns_canister_change(changes);

            // Index 0 corresponds to `current_version`.
            let index = index.saturating_add(1);

            writeln!(
                f,
                "{}",
                render_markdown_row(index + 1, &self.current_version, &changes)
            )?;

            previous_version = version;
        }

        Ok(())
    }
}

impl CachedUpgradeSteps {
    pub fn last(&self) -> &Version {
        self.subsequent_versions
            .last()
            .unwrap_or(&self.current_version)
    }

    pub fn contains(&self, version: &Version) -> bool {
        &self.current_version == version || self.subsequent_versions.contains(version)
    }

    pub fn current(&self) -> &Version {
        &self.current_version
    }

    pub fn is_current(&self, version: &Version) -> bool {
        version == self.current()
    }

    /// Approximate time at which this cache was valid.
    pub fn approximate_time_of_validity_timestamp_seconds(&self) -> u64 {
        self.response_timestamp_seconds
    }

    pub fn validate_new_target_version(&self, new_target: &Version) -> Result<(), String> {
        if !self.contains(new_target) {
            return Err("new_target_version must be among the upgrade steps.".to_string());
        }
        if self.is_current(new_target) {
            return Err("new_target_version must differ from the current version.".to_string());
        }
        Ok(())
    }
}
