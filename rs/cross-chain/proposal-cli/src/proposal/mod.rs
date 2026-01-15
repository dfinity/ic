use crate::TargetCanister;
use crate::candid::UpgradeArgs;
use crate::git::{CompressedWasmHash, GitCommitHash, ReleaseNotes};
use askama::Template;
use candid::Principal;
use std::io::Write;

#[derive(Template)]
#[template(path = "upgrade.md")]
pub struct UpgradeProposalTemplate {
    pub canister: TargetCanister,
    pub to: GitCommitHash,
    pub compressed_wasm_hash: CompressedWasmHash,
    pub canister_id: Principal,
    pub last_upgrade_proposal_id: Option<u64>,
    pub upgrade_args: UpgradeArgs,
    pub release_notes: ReleaseNotes,
    pub build_artifact_command: String,
}

impl UpgradeProposalTemplate {
    pub fn previous_upgrade_proposal_url(&self) -> String {
        self.last_upgrade_proposal_id
            .map(|id| format!("https://dashboard.internetcomputer.org/proposal/{id}"))
            .unwrap_or_else(|| "None".to_string())
    }
}

#[derive(Template)]
#[template(path = "install.md")]
pub struct InstallProposalTemplate {
    pub canister: TargetCanister,
    pub at: GitCommitHash,
    pub compressed_wasm_hash: CompressedWasmHash,
    pub canister_id: Principal,
    pub install_args: UpgradeArgs,
    pub build_artifact_command: String,
}

pub enum ProposalTemplate {
    Upgrade(UpgradeProposalTemplate),
    Install(InstallProposalTemplate),
}

impl ProposalTemplate {
    pub fn write_bin_args<W: Write>(&self, writer: &mut W) {
        let bin_args = match self {
            ProposalTemplate::Upgrade(template) => template.upgrade_args.upgrade_args_bin(),
            ProposalTemplate::Install(template) => template.install_args.upgrade_args_bin(),
        };
        writer
            .write_all(bin_args)
            .expect("failed to write binary args");
    }

    pub fn args_sha256_hex(&self) -> String {
        match self {
            ProposalTemplate::Upgrade(template) => template.upgrade_args.args_sha256_hex(),
            ProposalTemplate::Install(template) => template.install_args.args_sha256_hex(),
        }
    }

    pub fn render(&self) -> String {
        match self {
            ProposalTemplate::Upgrade(template) => template.render(),
            ProposalTemplate::Install(template) => template.render(),
        }
        .expect("failed to render proposal template")
    }

    pub fn canister_id(&self) -> &Principal {
        match self {
            ProposalTemplate::Upgrade(template) => &template.canister_id,
            ProposalTemplate::Install(template) => &template.canister_id,
        }
    }

    pub fn compressed_wasm_hash(&self) -> &CompressedWasmHash {
        match self {
            ProposalTemplate::Upgrade(template) => &template.compressed_wasm_hash,
            ProposalTemplate::Install(template) => &template.compressed_wasm_hash,
        }
    }

    pub fn target_canister(&self) -> &TargetCanister {
        match self {
            ProposalTemplate::Upgrade(template) => &template.canister,
            ProposalTemplate::Install(template) => &template.canister,
        }
    }
}

impl From<UpgradeProposalTemplate> for ProposalTemplate {
    fn from(template: UpgradeProposalTemplate) -> Self {
        ProposalTemplate::Upgrade(template)
    }
}

impl From<InstallProposalTemplate> for ProposalTemplate {
    fn from(template: InstallProposalTemplate) -> Self {
        ProposalTemplate::Install(template)
    }
}
