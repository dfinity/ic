use crate::pb::v1::governance::CachedUpgradeSteps as CachedUpgradeStepsPb;
use crate::pb::v1::governance::Version;
use crate::pb::v1::governance::Versions;

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

impl CachedUpgradeSteps {
    pub fn empty(current_version: Version, now_timestamp_seconds: u64) -> Self {
        Self {
            current_version,
            subsequent_versions: vec![],
            requested_timestamp_seconds: 0,
            response_timestamp_seconds: now_timestamp_seconds,
        }
    }

    pub fn new(
        current_version: Version,
        subsequent_versions: Vec<Version>,
        requested_timestamp_seconds: u64,
        response_timestamp_seconds: u64,
    ) -> Self {
        Self {
            current_version,
            subsequent_versions,
            requested_timestamp_seconds,
            response_timestamp_seconds,
        }
    }

    #[allow(unused)]
    pub fn last(&self) -> Version {
        let Some(last) = self.subsequent_versions.last() else {
            return self.current_version.clone();
        };
        last.clone()
    }

    #[allow(unused)]
    pub fn contains(&self, version: &Version) -> bool {
        &self.current_version == version || self.subsequent_versions.contains(version)
    }

    #[allow(unused)]
    pub fn is_current(&self, version: &Version) -> bool {
        version == &self.current_version
    }

    pub fn current(&self) -> Version {
        self.current_version.clone()
    }

    /// Approximate time at which this cache was valid.
    #[allow(unused)]
    pub fn approximate_time_of_validity_timestamp_seconds(&self) -> u64 {
        self.response_timestamp_seconds
    }

    // Clippy wants us to implement `Iterator for CachedUpgradeSteps`, but that would require adding
    // iterator-specific state to this type, which is an overkill for the purpose of having a simple
    // self-consuming method with an intuitive name.
    #[allow(unused)]
    #[allow(clippy::should_implement_trait)]
    pub fn into_iter(self) -> impl Iterator<Item = Version> {
        Iterator::chain(
            std::iter::once(self.current_version),
            self.subsequent_versions,
        )
    }

    #[allow(unused)]
    pub fn validate_new_target_version(&self, new_target: &Version) -> Result<(), String> {
        if !self.contains(new_target) {
            return Err("new_target_version must be among the upgrade steps.".to_string());
        }
        if self.is_current(new_target) {
            return Err("new_target_version must differ from the current version.".to_string());
        }
        Ok(())
    }

    /// Consume self, returning the previous SNS version and a new CachedUpgradeSteps instance
    /// containing *all but the current* SNS versions in the Ok result.
    ///
    /// Returns `Err` if the current version is the only one (i.e., there are no pending upgrades).
    pub fn consume(self) -> Result<(Version, CachedUpgradeSteps), String> {
        let Self {
            current_version: previous_version,
            subsequent_versions: previous_subsequent_versions,
            requested_timestamp_seconds,
            response_timestamp_seconds,
        } = self;

        let Some((current_version, subsequent_versions)) =
            previous_subsequent_versions.split_first()
        else {
            return Err(format!(
                "Cannot consume an upgrade step: only the current version {:?} is available.",
                previous_version
            ));
        };

        Ok((
            previous_version,
            Self {
                current_version: current_version.clone(),
                subsequent_versions: subsequent_versions.to_vec(),
                requested_timestamp_seconds,
                response_timestamp_seconds,
            },
        ))
    }

    pub fn is_equivalent_to(&self, other: &Self) -> bool {
        self.current_version == other.current_version
            && self.subsequent_versions == other.subsequent_versions
    }
}
