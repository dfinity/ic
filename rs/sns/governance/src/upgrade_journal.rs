use crate::governance::{Governance, MAX_UPGRADE_JOURNAL_ENTRIES_PER_REQUEST};
use crate::pb::v1::{
    Empty, GetUpgradeJournalRequest, GetUpgradeJournalResponse, ProposalId, UpgradeJournal,
    UpgradeJournalEntry,
    governance::{Version, Versions},
    upgrade_journal_entry::{self, upgrade_outcome, upgrade_started},
};
use ic_sns_governance_api::serialize_journal_entries;

impl upgrade_journal_entry::UpgradeStepsRefreshed {
    /// Creates a new UpgradeStepsRefreshed event with the given versions
    pub fn new(versions: Vec<Version>) -> Self {
        Self {
            upgrade_steps: Some(Versions { versions }),
        }
    }
}

impl upgrade_journal_entry::UpgradeStepsReset {
    /// Creates a new UpgradeStepsReset event with the given versions and message
    pub fn new(human_readable: String, versions: Vec<Version>) -> Self {
        Self {
            human_readable: Some(human_readable),
            upgrade_steps: Some(Versions { versions }),
        }
    }
}

impl upgrade_journal_entry::TargetVersionSet {
    /// Creates a new TargetVersionSet event with old and new versions
    pub fn new(
        old_version: Option<Version>,
        new_version: Version,
        is_advanced_automatically: bool,
    ) -> Self {
        Self {
            old_target_version: old_version,
            new_target_version: Some(new_version),
            is_advanced_automatically: Some(is_advanced_automatically),
        }
    }
}

impl upgrade_journal_entry::TargetVersionReset {
    /// Creates a new TargetVersionReset event with old and new versions
    pub fn new(
        old_version: Option<Version>,
        new_version: Option<Version>,
        human_readable: String,
    ) -> Self {
        Self {
            old_target_version: old_version,
            new_target_version: new_version,
            human_readable: Some(human_readable),
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
    pub fn success(message: String) -> Self {
        Self {
            human_readable: Some(message),
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

    pub fn get_upgrade_journal(
        &self,
        request: GetUpgradeJournalRequest,
    ) -> GetUpgradeJournalResponse {
        let upgrade_journal = self.proto.upgrade_journal.as_ref().map(|journal| {
            let limit = request
                .limit
                .unwrap_or(MAX_UPGRADE_JOURNAL_ENTRIES_PER_REQUEST)
                .min(MAX_UPGRADE_JOURNAL_ENTRIES_PER_REQUEST) as usize;
            let offset = request
                .offset
                .map(|offset| offset as usize)
                .unwrap_or_else(|| journal.entries.len().saturating_sub(limit));
            let entries = journal
                .entries
                .iter()
                .skip(offset)
                .take(limit)
                .cloned()
                .collect();
            UpgradeJournal { entries }
        });
        let upgrade_journal_entry_count = self
            .proto
            .upgrade_journal
            .as_ref()
            .map(|journal| journal.entries.len() as u64);

        let upgrade_steps = self.proto.cached_upgrade_steps.clone();
        match upgrade_steps {
            Some(cached_upgrade_steps) => GetUpgradeJournalResponse {
                upgrade_steps: cached_upgrade_steps.upgrade_steps,
                response_timestamp_seconds: cached_upgrade_steps.response_timestamp_seconds,
                target_version: self.proto.target_version.clone(),
                deployed_version: self.proto.deployed_version.clone(),
                upgrade_journal,
                upgrade_journal_entry_count,
            },
            None => GetUpgradeJournalResponse {
                upgrade_steps: None,
                response_timestamp_seconds: None,
                target_version: None,
                deployed_version: self.proto.deployed_version.clone(),
                upgrade_journal,
                upgrade_journal_entry_count,
            },
        }
    }
}

impl From<upgrade_journal_entry::UpgradeStepsRefreshed> for upgrade_journal_entry::Event {
    fn from(event: upgrade_journal_entry::UpgradeStepsRefreshed) -> Self {
        upgrade_journal_entry::Event::UpgradeStepsRefreshed(event)
    }
}
impl From<upgrade_journal_entry::UpgradeStepsReset> for upgrade_journal_entry::Event {
    fn from(event: upgrade_journal_entry::UpgradeStepsReset) -> Self {
        upgrade_journal_entry::Event::UpgradeStepsReset(event)
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

pub fn serve_journal(journal: UpgradeJournal) -> ic_http_types::HttpResponse {
    use ic_http_types::HttpResponseBuilder;

    let journal = ic_sns_governance_api::pb::v1::UpgradeJournal::from(journal);

    match serialize_journal_entries(&journal) {
        Err(err) => {
            HttpResponseBuilder::server_error(format!("Failed to encode journal: {err}")).build()
        }
        Ok(body) => HttpResponseBuilder::ok()
            .header("Content-Type", "application/json")
            .with_body_and_content_length(body)
            .build(),
    }
}
