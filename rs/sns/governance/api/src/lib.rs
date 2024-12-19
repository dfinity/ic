pub mod neuron;
pub mod pb;
mod request_impls;

/// Formats the 32 bytes of a hash as a hexadecimal string. Corresponds to 64 ascii symbols.
pub fn format_full_hash(hash: &[u8]) -> String {
    hash.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}

impl pb::v1::upgrade_journal_entry::Event {
    /// Useful for specifying expected states of the SNS upgrade journal in a way that isn't
    /// overly fragile.
    pub fn redact_human_readable(self) -> Self {
        match self {
            Self::UpgradeOutcome(upgrade_outcome) => {
                Self::UpgradeOutcome(pb::v1::upgrade_journal_entry::UpgradeOutcome {
                    human_readable: None,
                    ..upgrade_outcome
                })
            }
            Self::UpgradeStepsReset(upgrade_steps_reset) => {
                Self::UpgradeStepsReset(pb::v1::upgrade_journal_entry::UpgradeStepsReset {
                    human_readable: None,
                    ..upgrade_steps_reset
                })
            }
            Self::TargetVersionReset(target_version_reset) => {
                Self::TargetVersionReset(pb::v1::upgrade_journal_entry::TargetVersionReset {
                    human_readable: None,
                    ..target_version_reset
                })
            }
            event => event,
        }
    }
}

impl std::fmt::Display for pb::v1::GovernanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.error_type(), self.error_message)
    }
}
