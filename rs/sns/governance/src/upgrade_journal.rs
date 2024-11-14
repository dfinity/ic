use crate::governance::Governance;
use crate::pb::v1::{
    governance::{Version, Versions},
    upgrade_journal_entry::{self, upgrade_outcome, upgrade_started},
    Empty, ProposalId, UpgradeJournal, UpgradeJournalEntry,
};

impl upgrade_journal_entry::UpgradeStepsRefreshed {
    /// Creates a new UpgradeStepsRefreshed event with the given versions
    pub fn new(versions: Vec<Version>) -> Self {
        Self {
            upgrade_steps: Some(Versions { versions }),
        }
    }
}

impl upgrade_journal_entry::TargetVersionSet {
    /// Creates a new TargetVersionSet event with old and new versions
    pub fn new(old_version: Option<Version>, new_version: Option<Version>) -> Self {
        Self {
            old_target_version: old_version,
            new_target_version: new_version,
        }
    }
}

impl upgrade_journal_entry::TargetVersionReset {
    /// Creates a new TargetVersionReset event with old and new versions
    pub fn new(old_version: Option<Version>, new_version: Option<Version>) -> Self {
        Self {
            old_target_version: old_version,
            new_target_version: new_version,
        }
    }
}

impl upgrade_journal_entry::UpgradeStarted {
    /// Creates a new UpgradeStarted event triggered by a proposal
    pub fn from_proposal(current: Version, expected: Version, proposal_id: ProposalId) -> Self {
        Self {
            current_version: Some(current),
            expected_version: Some(expected),
            reason: Some(upgrade_started::Reason::UpgradeSnsToNextVersionProposal(
                proposal_id,
            )),
        }
    }

    /// Creates a new UpgradeStarted event triggered by being behind target version
    pub fn from_behind_target(current: Version, expected: Version) -> Self {
        Self {
            current_version: Some(current),
            expected_version: Some(expected),
            reason: Some(upgrade_started::Reason::BehindTargetVersion(Empty {})),
        }
    }
}

impl upgrade_journal_entry::UpgradeOutcome {
    /// Creates a new successful upgrade outcome
    pub fn success(message: Option<String>) -> Self {
        Self {
            human_readable: message,
            status: Some(upgrade_outcome::Status::Success(Empty {})),
        }
    }

    /// Creates a new timeout upgrade outcome
    pub fn timeout(message: String) -> Self {
        Self {
            human_readable: Some(message),
            status: Some(upgrade_outcome::Status::Timeout(Empty {})),
        }
    }

    /// Creates a new invalid state upgrade outcome
    pub fn invalid_state(message: String, version: Option<Version>) -> Self {
        Self {
            human_readable: Some(message),
            status: Some(upgrade_outcome::Status::InvalidState(
                upgrade_outcome::InvalidState { version },
            )),
        }
    }

    /// Creates a new external failure upgrade outcome
    pub fn external_failure(message: Option<String>) -> Self {
        Self {
            human_readable: message,
            status: Some(upgrade_outcome::Status::ExternalFailure(Empty {})),
        }
    }
}

impl Governance {
    pub fn push_to_upgrade_journal<Event>(&mut self, event: Event)
    where
        upgrade_journal_entry::Event: From<Event>,
    {
        let event = upgrade_journal_entry::Event::from(event);
        let upgrade_journal_entry = UpgradeJournalEntry {
            event: Some(event),
            timestamp_seconds: Some(self.env.now()),
        };
        match self.proto.upgrade_journal {
            None => {
                self.proto.upgrade_journal = Some(UpgradeJournal {
                    entries: vec![upgrade_journal_entry],
                });
            }
            Some(ref mut journal) => {
                journal.entries.push(upgrade_journal_entry);
            }
        }
    }
}

impl From<upgrade_journal_entry::UpgradeStepsRefreshed> for upgrade_journal_entry::Event {
    fn from(event: upgrade_journal_entry::UpgradeStepsRefreshed) -> Self {
        upgrade_journal_entry::Event::UpgradeStepsRefreshed(event)
    }
}
impl From<upgrade_journal_entry::UpgradeStarted> for upgrade_journal_entry::Event {
    fn from(event: upgrade_journal_entry::UpgradeStarted) -> Self {
        upgrade_journal_entry::Event::UpgradeStarted(event)
    }
}
impl From<upgrade_journal_entry::UpgradeOutcome> for upgrade_journal_entry::Event {
    fn from(event: upgrade_journal_entry::UpgradeOutcome) -> Self {
        upgrade_journal_entry::Event::UpgradeOutcome(event)
    }
}
impl From<upgrade_journal_entry::TargetVersionSet> for upgrade_journal_entry::Event {
    fn from(event: upgrade_journal_entry::TargetVersionSet) -> Self {
        upgrade_journal_entry::Event::TargetVersionSet(event)
    }
}
impl From<upgrade_journal_entry::TargetVersionReset> for upgrade_journal_entry::Event {
    fn from(event: upgrade_journal_entry::TargetVersionReset) -> Self {
        upgrade_journal_entry::Event::TargetVersionReset(event)
    }
}
