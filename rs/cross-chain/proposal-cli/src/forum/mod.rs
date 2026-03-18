#[cfg(test)]
mod tests;

use crate::canister::TargetCanister;
use crate::dashboard::responses::ProposalInfo;
use candid::Principal;
use core::fmt;
use maplit::btreeset;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Formatter;
use std::str::FromStr;
use std::time::Duration;
use url::Url;

type ProposalId = u64;

/// Kind of forum topic: application canister management vs protocol canister management.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ForumTopicKind {
    ApplicationCanisterManagement,
    ProtocolCanisterManagement,
}

/// Forum topic kind to use for each canister. Edit this match to use
/// `ProtocolCanisterManagement` for protocol canisters and `ApplicationCanisterManagement` for application canisters.
fn forum_topic_kind(canister: &TargetCanister) -> ForumTopicKind {
    match canister {
        TargetCanister::Bitcoin
        | TargetCanister::BtcWatchdog
        | TargetCanister::DogeWatchdog
        | TargetCanister::Dogecoin => ForumTopicKind::ProtocolCanisterManagement,
        TargetCanister::CyclesLedger
        | TargetCanister::CyclesIndex
        | TargetCanister::IcpArchive1
        | TargetCanister::IcpArchive2
        | TargetCanister::IcpArchive3
        | TargetCanister::IcpArchive4
        | TargetCanister::IcpIndex
        | TargetCanister::IcpLedger => ForumTopicKind::ProtocolCanisterManagement,
        TargetCanister::ExchangeRateCanister => ForumTopicKind::ProtocolCanisterManagement,
        TargetCanister::BtcChecker
        | TargetCanister::CkBtcArchive
        | TargetCanister::CkBtcIndex
        | TargetCanister::CkBtcLedger
        | TargetCanister::CkBtcMinter
        | TargetCanister::CkDogeIndex
        | TargetCanister::CkDogeLedger
        | TargetCanister::CkDogeMinter
        | TargetCanister::CkEthArchive
        | TargetCanister::CkEthIndex
        | TargetCanister::CkEthLedger
        | TargetCanister::CkEthMinter
        | TargetCanister::EvmRpc
        | TargetCanister::LedgerSuiteOrchestrator
        | TargetCanister::SolRpc => ForumTopicKind::ApplicationCanisterManagement,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ForumTopic {
    /// A new topic in the application canister management category for the given proposals.
    /// A single post may cover multiple proposals (e.g. a topic to cover a new ckBTC ledger suite,
    /// which involves 3 proposals: for the ledger, index and archive canisters).
    ApplicationCanisterManagement {
        proposals: BTreeMap<ProposalId, UpgradeProposalSummary>,
    },
    ProtocolCanisterManagement {
        proposals: BTreeMap<ProposalId, UpgradeProposalSummary>,
    },
}

impl ForumTopic {
    /// Build a forum topic for the given upgrade proposals. The topic kind (application vs
    /// protocol canister management) is determined by `forum_topic_kind` in this module.
    /// All canisters in the batch must map to the same topic kind.
    pub fn for_upgrade_proposals<I: IntoIterator<Item = ProposalInfo>>(
        proposals: I,
    ) -> Result<ForumTopic, String> {
        let mut summaries = BTreeMap::new();
        let mut proposal_kinds = BTreeMap::new();
        for proposal in proposals.into_iter() {
            let proposal_id = proposal.proposal_id;
            let summary = UpgradeProposalSummary::try_from(proposal)?;
            let kind = forum_topic_kind(&summary.canister);
            proposal_kinds
                .entry(kind)
                .and_modify(|p: &mut Vec<u64>| p.push(proposal_id))
                .or_insert_with(|| vec![proposal_id]);
            summaries.insert(proposal_id, summary);
        }
        assert!(
            !summaries.is_empty(),
            "BUG: no forum topic needed if there is no proposal"
        );
        assert_eq!(
            proposal_kinds.len(),
            1,
            "ERROR: cannot create single forum topic for proposals mixing application and protocol canister topics: {proposal_kinds:?}"
        );
        let kind = proposal_kinds.keys().next().unwrap();
        Ok(match kind {
            ForumTopicKind::ApplicationCanisterManagement => {
                ForumTopic::ApplicationCanisterManagement {
                    proposals: summaries,
                }
            }
            ForumTopicKind::ProtocolCanisterManagement => ForumTopic::ProtocolCanisterManagement {
                proposals: summaries,
            },
        })
    }
}

impl TryFrom<ProposalInfo> for UpgradeProposalSummary {
    type Error = String;

    fn try_from(proposal: ProposalInfo) -> Result<Self, Self::Error> {
        let canister_id = Principal::from_text(proposal.payload.canister_id)
            .map_err(|e| format!("Failed to parse canister ID: {e}"))?;
        let canister = TargetCanister::find_by_id(&canister_id)
            .ok_or_else(|| format!("ERROR: no known target canister for {canister_id}"))?;
        let install_mode = proposal.payload.install_mode_name.parse()?;
        Ok(Self {
            canister,
            install_mode,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpgradeProposalSummary {
    canister: TargetCanister,
    install_mode: CanisterInstallMode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd)]
enum CanisterInstallMode {
    Unspecified,
    Install,
    Reinstall,
    Upgrade,
}

impl FromStr for CanisterInstallMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "CANISTER_INSTALL_MODE_UNSPECIFIED" => Ok(Self::Unspecified),
            "CANISTER_INSTALL_MODE_INSTALL" => Ok(Self::Install),
            "CANISTER_INSTALL_MODE_REINSTALL" => Ok(Self::Reinstall),
            "CANISTER_INSTALL_MODE_UPGRADE" => Ok(Self::Upgrade),
            _ => Err(format!("Unknown install mode: {s}")),
        }
    }
}

impl fmt::Display for CanisterInstallMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            CanisterInstallMode::Unspecified => write!(f, "manage"),
            CanisterInstallMode::Install => write!(f, "install"),
            CanisterInstallMode::Reinstall => write!(f, "reinstall"),
            CanisterInstallMode::Upgrade => write!(f, "upgrade"),
        }
    }
}

impl ForumTopic {
    fn title(&self) -> String {
        match self {
            ForumTopic::ApplicationCanisterManagement { proposals }
            | ForumTopic::ProtocolCanisterManagement { proposals } => {
                let proposal_ids: Vec<_> = proposals.keys().collect();
                let canister_names: Vec<_> =
                    proposals.values().map(|c| c.canister.to_string()).collect();
                let summary_install_mode = {
                    let install_modes: BTreeSet<_> =
                        proposals.values().map(|s| s.install_mode).collect();
                    let aggregate_install_mode = if install_modes.len() != 1 {
                        &CanisterInstallMode::Unspecified
                    } else {
                        install_modes.first().unwrap()
                    };
                    aggregate_install_mode.to_string()
                };
                format!(
                    "{} {} to {} the {}",
                    pluralize("Proposal", proposals.len()),
                    display_sequence(proposal_ids.as_slice()),
                    summary_install_mode,
                    display_sequence(canister_names.as_slice()),
                )
            }
        }
    }

    fn body(&self) -> String {
        match self {
            ForumTopic::ApplicationCanisterManagement { proposals }
            | ForumTopic::ProtocolCanisterManagement { proposals } => {
                let mut res = Vec::new();
                res.push("Hi everyone :waving_hand:".to_string());
                res.push(String::new());
                res.push(format!(
                    "Please use this forum thread to discuss the following {}:",
                    pluralize("proposal", proposals.len())
                ));
                for (proposal_id, summary) in proposals {
                    res.push(format!(
                        "* Proposal [{}](https://dashboard.internetcomputer.org/proposal/{}): {} the {}",
                        proposal_id, proposal_id, summary.install_mode, summary.canister
                    ))
                }
                res.push(String::new());
                res.push(":information_source: All listed proposals should contain the necessary information to verify them.".to_string());
                res.join("\n")
            }
        }
    }

    fn category(&self) -> u64 {
        match &self {
            ForumTopic::ApplicationCanisterManagement { .. }
            | ForumTopic::ProtocolCanisterManagement { .. } => {
                // Category "NNS proposal discussions"
                // https://forum.dfinity.org/c/governance/nns-proposal-discussions/76
                76
            }
        }
    }

    fn tags(&self) -> BTreeSet<Tag> {
        match &self {
            ForumTopic::ApplicationCanisterManagement { .. } => {
                btreeset! {Tag::ApplicationCanisterMgmt}
            }
            ForumTopic::ProtocolCanisterManagement { .. } => btreeset! {Tag::ProtocolCanisterMgmt},
        }
    }
}

fn pluralize(word: &str, count: usize) -> String {
    if count < 2 {
        return word.to_string();
    }
    format!("{word}s")
}

fn display_sequence<T: fmt::Display>(seq: &[T]) -> String {
    let result = seq
        .iter()
        .map(|item| item.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    if seq.len() < 2 {
        return result;
    }
    format!("({result})")
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Tag {
    /// [Application canister management](https://forum.dfinity.org/tags/c/governance/nns-proposal-discussions/76/application-canister-mgmt) tag.
    ApplicationCanisterMgmt,
    /// [Protocol canister management](https://forum.dfinity.org/tags/c/governance/nns-proposal-discussions/76/protocol-canister-management) tag.
    ProtocolCanisterMgmt,
}

impl Tag {
    fn id(&self) -> &'static str {
        match self {
            Tag::ApplicationCanisterMgmt => "Application-canister-mgmt",
            Tag::ProtocolCanisterMgmt => "Protocol-canister-management",
        }
    }
}

/// Create a new topic (first forum post in a thread)
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CreateTopicRequest {
    title: String,
    raw: String,
    category: u64,
    tags: Vec<String>,
}

impl From<ForumTopic> for CreateTopicRequest {
    fn from(topic: ForumTopic) -> Self {
        Self {
            title: topic.title(),
            raw: topic.body(),
            category: topic.category(),
            tags: topic
                .tags()
                .into_iter()
                .map(|t| t.id().to_string())
                .collect(),
        }
    }
}

/// Response returned upon successful creation of a new topic.
#[derive(Clone, PartialEq, Eq, Deserialize)]
pub struct CreateTopicResponse {
    pub id: u64,
    pub topic_id: u64,
    pub topic_slug: String,
    pub post_url: String,
}

pub struct DiscourseClient {
    client: reqwest::Client,
    forum_url: Url,
    api_user: String,
    api_key: String,
}

impl DiscourseClient {
    pub fn new(url: Url, api_user: String, api_key: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("ERROR: Failed to create client");

        Self {
            client,
            forum_url: url,
            api_key,
            api_user,
        }
    }

    pub async fn create_topic<T: Into<CreateTopicRequest>>(
        &self,
        request: T,
    ) -> Result<CreateTopicResponse, String> {
        let request = request.into();
        self.post_request("posts.json?skip_validations=true", request)
            .await
    }

    async fn post_request<Request: Serialize, Response: DeserializeOwned>(
        &self,
        path: &str,
        request: Request,
    ) -> Result<Response, String> {
        let url = self.forum_url.join(path).map_err(|e| e.to_string())?;
        let response = self
            .client
            .post(url)
            .json(&request)
            .header("Api-Key", &self.api_key)
            .header("Api-Username", &self.api_user)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !response.status().is_success() {
            return Err(format!("HTTP error: {response:?}"));
        }
        response.json().await.map_err(|e| e.to_string())
    }
}
