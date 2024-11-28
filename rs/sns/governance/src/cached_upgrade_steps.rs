use crate::governance::Governance;
use crate::governance::UPGRADE_STEPS_INTERVAL_REFRESH_BACKOFF_SECONDS;
use crate::logs::ERROR;
use crate::pb::v1::governance::CachedUpgradeSteps as CachedUpgradeStepsPb;
use crate::pb::v1::governance::Version;
use crate::pb::v1::governance::Versions;
use crate::pb::v1::upgrade_journal_entry;
use crate::pb::v1::Governance as GovernancePb;
use crate::sns_upgrade::ListUpgradeStep;
use crate::sns_upgrade::ListUpgradeStepsResponse;
use crate::sns_upgrade::SnsCanisterType;
use ic_canister_log::log;

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

        // Check for duplicate versions in the response
        {
            let mut seen = std::collections::HashSet::new();
            for version in &upgrade_steps.versions {
                if !seen.insert(version) {
                    return Err(
                        "CachedUpgradeSteps.upgrade_steps must not contain duplicate versions."
                            .to_string(),
                    );
                }
            }
        }

        let Some((current_version, subsequent_versions)) = upgrade_steps.versions.split_first()
        else {
            return Err("CachedUpgradeSteps.upgrade_steps must not be empty.".to_string());
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

/// Formats the first 3 bytes of a hash as a hexadecimal string. Corresponds to 6 ascii symbols.
pub fn format_short_hash(hash: &[u8]) -> String {
    hash.iter()
        .take(3)
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}

/// Formats the 32 bytes of a hash as a hexadecimal string. Corresponds to 64 ascii symbols.
pub fn format_full_hash(hash: &[u8]) -> String {
    hash.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}

pub fn render_two_versions_as_markdown_table(
    current_version: &Version,
    target_version: &Version,
) -> String {
    let long_line = "-".repeat(64);
    let current_column_label = format!("{:<64}", "Current version's module hash");
    let target_column_label = format!("{:<64}", "New target version's module hash");
    format!(
        "| Canister   | {current_column_label} | {target_column_label} |\n\
         |------------|-{long_line}-|-{long_line}-|\n\
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

impl std::fmt::Display for SnsCanisterType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            SnsCanisterType::Unspecified => "Unspecified",
            SnsCanisterType::Root => "Root",
            SnsCanisterType::Governance => "Governance",
            SnsCanisterType::Swap => "Swap",
            SnsCanisterType::Index => "Index",
            SnsCanisterType::Ledger => "Ledger",
            SnsCanisterType::Archive => "Archive",
        };
        write!(f, "{}", value)
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
                sns_canister_type,
                format_full_hash(&wasm_hash[..])
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// Formats the version as a Markdown table row.
fn render_markdown_row(index: usize, version: &Version, canister_changes: &str) -> String {
    format!(
        "| {:>4} | {} | {} | {} | {} | {} | {} | {} |",
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

impl std::fmt::Display for CachedUpgradeSteps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "| Step | Root | Governance | Swap | Index | Ledger | Archive | Changes |\n\
             |------|------|------------|------|-------|--------|---------|---------|"
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

            writeln!(f, "{}", render_markdown_row(index, version, &changes))?;

            previous_version = version;
        }

        Ok(())
    }
}

impl CachedUpgradeSteps {
    pub fn try_from_sns_w_response(
        sns_w_response: ListUpgradeStepsResponse,
        requested_timestamp_seconds: u64,
        response_timestamp_seconds: u64,
    ) -> Result<Self, String> {
        let response_str = format!("{:?}", sns_w_response);

        let ListUpgradeStepsResponse { steps } = sns_w_response;

        let versions: Vec<Version> = steps
            .into_iter()
            .map(|list_upgrade_step| match list_upgrade_step {
                ListUpgradeStep {
                    version: Some(version),
                } => Ok(version.into()),
                _ => Err(format!(
                    "SnsW.list_upgrade_steps response had invalid fields: {}",
                    response_str
                )),
            })
            .collect::<Result<_, _>>()?;

        let mut versions = versions.into_iter();

        let Some(current_version) = versions.next() else {
            return Err("ListUpgradeStepsResponse.steps must not be empty.".to_string());
        };

        Ok(Self {
            current_version,
            subsequent_versions: versions.collect(),
            requested_timestamp_seconds,
            response_timestamp_seconds,
        })
    }

    /// Creates an instance of `Self` capturing a situation with no pending upgrades.
    fn without_pending_upgrades(current_version: Version, now_timestamp_seconds: u64) -> Self {
        Self {
            current_version,
            subsequent_versions: vec![],
            // Since this function is used when get_or_reset_upgrade_steps resets the upgrade steps,
            // having zero here makes the cache refresh happen ASAP after the upgrade steps
            // are invalidated.
            requested_timestamp_seconds: 0,
            response_timestamp_seconds: now_timestamp_seconds,
        }
    }

    pub fn last(&self) -> &Version {
        self.subsequent_versions
            .last()
            .unwrap_or(&self.current_version)
    }

    pub fn contains(&self, version: &Version) -> bool {
        &self.current_version == version || self.subsequent_versions.contains(version)
    }

    pub fn contains_in_order(&self, left: &Version, right: &Version) -> Result<bool, String> {
        if !self.contains(left) {
            return Err(format!("{:?} does not contain {:?}", self, left));
        }
        if !self.contains(right) {
            return Err(format!("{:?} does not contain {:?}", self, right));
        }

        // Check if we have `current_version` -> ... -> `left` -> `right` -> ...
        let upgrade_steps_starting_from_left = self.clone().take_from(left)?;

        let contains_in_order = upgrade_steps_starting_from_left.contains(right);

        Ok(contains_in_order)
    }

    pub fn current(&self) -> &Version {
        &self.current_version
    }

    pub fn next(&self) -> Option<&Version> {
        self.subsequent_versions.first()
    }

    pub fn is_current(&self, version: &Version) -> bool {
        version == self.current()
    }

    /// Returns whether there are no pending upgrades.
    pub fn has_pending_upgrades(&self) -> bool {
        !self.subsequent_versions.is_empty()
    }

    /// Returns a new instance of `Self` starting with `version` in the `Ok` result
    /// or `Err` if `!self.contains(version)`.
    pub fn take_from(self, new_current_version: &Version) -> Result<Self, String> {
        if self.is_current(new_current_version) {
            return Ok(self);
        }

        let Self {
            current_version: _current_version,
            subsequent_versions,
            response_timestamp_seconds,
            requested_timestamp_seconds,
        } = self;

        let mut subsequent_versions = subsequent_versions.into_iter();
        while let Some(current_version) = subsequent_versions.next() {
            if new_current_version == &current_version {
                return Ok(Self {
                    current_version,
                    subsequent_versions: subsequent_versions.collect(),
                    response_timestamp_seconds,
                    requested_timestamp_seconds,
                });
            }
        }

        Err(format!(
            "Cannot take_from {} that is not one of the cached upgrade steps.",
            new_current_version
        ))
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

impl Governance {
    /// Invalidates the cached upgrade steps.
    pub(crate) fn invalidate_target_version(&mut self, reason: String) {
        self.push_to_upgrade_journal(upgrade_journal_entry::TargetVersionReset::new(
            self.proto.target_version.clone(),
            None,
            reason,
        ));
        self.proto.target_version = None;
    }

    /// Returns the upgrade steps that are guaranteed to start from `current_version`.
    ///
    /// - Initialized the cache if it has not been initialized yet.
    /// - Resets `cached_upgrade_steps` and `target_version` if an inconsistency is detected.
    pub(crate) fn get_or_reset_upgrade_steps(
        &mut self,
        current_version: &Version,
    ) -> CachedUpgradeSteps {
        let cached_upgrade_steps =
            if let Some(cached_upgrade_steps_pb) = &self.proto.cached_upgrade_steps {
                CachedUpgradeSteps::try_from(cached_upgrade_steps_pb)
            } else {
                // Make a new, valid `cached_upgrade_steps_pb` instance and initialize
                // the cache with it.
                let cached_upgrade_steps_pb =
                    CachedUpgradeStepsPb::from(CachedUpgradeSteps::without_pending_upgrades(
                        current_version.clone(),
                        self.env.now(),
                    ));
                let cached_upgrade_steps = CachedUpgradeSteps::try_from(&cached_upgrade_steps_pb);
                self.proto
                    .cached_upgrade_steps
                    .replace(cached_upgrade_steps_pb);
                cached_upgrade_steps
            };

        let error_message = match cached_upgrade_steps
            .and_then(|cached_upgrade_steps| cached_upgrade_steps.take_from(current_version))
        {
            Ok(upgrade_steps) => {
                // Happy case.
                return upgrade_steps;
            }
            Err(err) => err,
        };

        self.push_to_upgrade_journal(upgrade_journal_entry::UpgradeStepsReset::new(
            error_message.clone(),
            vec![current_version.clone()],
        ));

        let cached_upgrade_steps =
            CachedUpgradeSteps::without_pending_upgrades(current_version.clone(), self.env.now());

        self.proto
            .cached_upgrade_steps
            .replace(CachedUpgradeStepsPb::from(cached_upgrade_steps.clone()));

        if self.proto.target_version.is_some() {
            self.invalidate_target_version(error_message)
        }

        cached_upgrade_steps
    }

    pub fn try_temporarily_lock_refresh_cached_upgrade_steps(&mut self) -> Result<Version, String> {
        let deployed_version = self
            .proto
            .deployed_version
            .clone()
            .ok_or("Cannot lock refresh_cached_upgrade_steps: deployed_version not set.")?;

        let mut cached_upgrade_steps = self.get_or_reset_upgrade_steps(&deployed_version);

        // Lock the upgrade mechanism.
        cached_upgrade_steps.requested_timestamp_seconds = self.env.now();
        let cached_upgrade_steps = CachedUpgradeStepsPb::from(cached_upgrade_steps);
        self.proto.cached_upgrade_steps = Some(cached_upgrade_steps);

        Ok(deployed_version)
    }

    pub fn should_refresh_cached_upgrade_steps(&mut self) -> bool {
        let now = self.env.now();

        if let Some(ref cached_upgrade_steps) = self.proto.cached_upgrade_steps {
            let requested_timestamp_seconds = cached_upgrade_steps
                .requested_timestamp_seconds
                .unwrap_or(0);
            if now - requested_timestamp_seconds < UPGRADE_STEPS_INTERVAL_REFRESH_BACKOFF_SECONDS {
                return false;
            }
        }

        true
    }

    /// Refreshes the cached_upgrade_steps field
    pub async fn refresh_cached_upgrade_steps(&mut self, deployed_version: Version) {
        let sns_governance_canister_id = self.env.canister_id().get();

        let upgrade_steps = crate::sns_upgrade::get_upgrade_steps(
            &*self.env,
            deployed_version,
            sns_governance_canister_id,
        )
        .await;

        let upgrade_steps = match upgrade_steps {
            Ok(upgrade_steps) => upgrade_steps,
            Err(err) => {
                log!(ERROR, "Cannot refresh cached_upgrade_steps: {}", err);
                return;
            }
        };

        let new_cache = CachedUpgradeStepsPb::from(upgrade_steps);

        let identical_upgrade_steps = self
            .proto
            .cached_upgrade_steps
            .as_ref()
            .map(|cache| cache.upgrade_steps == new_cache.upgrade_steps)
            .unwrap_or_default();

        if !identical_upgrade_steps {
            self.push_to_upgrade_journal(upgrade_journal_entry::UpgradeStepsRefreshed::new(
                new_cache.clone().upgrade_steps.unwrap_or_default().versions,
            ));
        }

        self.proto.cached_upgrade_steps.replace(new_cache);
    }
}

impl GovernancePb {
    fn cached_upgrade_steps_or_err(&self) -> Result<CachedUpgradeSteps, String> {
        let Some(cached_upgrade_steps) = &self.cached_upgrade_steps else {
            return Err(
                "Internal error: GovernanceProto.cached_upgrade_steps must be specified."
                    .to_string(),
            );
        };

        let cached_upgrade_steps = CachedUpgradeSteps::try_from(cached_upgrade_steps)
            .map_err(|err| format!("Internal error: {}", err))?;

        Ok(cached_upgrade_steps)
    }

    pub(crate) fn validate_new_target_version<V>(
        &self,
        new_target: Option<V>,
    ) -> Result<
        (
            /* pending_upgrade_steps */ CachedUpgradeSteps,
            /* valid_target_version */ Version,
        ),
        String,
    >
    where
        Version: TryFrom<V>,
        <Version as TryFrom<V>>::Error: ToString,
    {
        let deployed_version = self.deployed_version_or_err()?;

        let cached_upgrade_steps = self.cached_upgrade_steps_or_err()?;

        let upgrade_steps = cached_upgrade_steps.take_from(&deployed_version);
        let upgrade_steps = match upgrade_steps {
            Ok(upgrade_steps) if upgrade_steps.has_pending_upgrades() => upgrade_steps,
            _ => {
                return Err(format!(
                    "Currently, the SNS does not have pending upgrades. \
                     You may need to wait for the upgrade steps to be refreshed. \
                     This shouldn't take more than {} seconds.",
                    UPGRADE_STEPS_INTERVAL_REFRESH_BACKOFF_SECONDS
                ));
            }
        };

        let new_target = if let Some(new_target) = new_target {
            let new_target = Version::try_from(new_target).map_err(|err| err.to_string())?;
            upgrade_steps.validate_new_target_version(&new_target)?;
            new_target
        } else {
            upgrade_steps.last().clone()
        };

        if let Some(current_target_version) = &self.target_version {
            let new_target_is_not_ahead_of_current_target =
                upgrade_steps.contains_in_order(&new_target, current_target_version)?;
            if new_target_is_not_ahead_of_current_target {
                return Err(format!(
                    "SNS target already set to {}.",
                    current_target_version
                ));
            }
        }

        Ok((upgrade_steps, new_target))
    }
}
