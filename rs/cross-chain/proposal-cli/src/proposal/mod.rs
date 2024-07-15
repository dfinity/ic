use crate::candid::UpgradeArgs;
use crate::git::{CompressedWasmHash, GitCommitHash, ReleaseNotes};
use crate::TargetCanister;
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
    pub upgrade_args: UpgradeArgs,
    pub release_notes: ReleaseNotes,
}

#[derive(Template)]
#[template(path = "install.md")]
pub struct InstallProposalTemplate {
    pub canister: TargetCanister,
    pub at: GitCommitHash,
    pub compressed_wasm_hash: CompressedWasmHash,
    pub canister_id: Principal,
    pub install_args: UpgradeArgs,
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

    pub fn write_hex_args<W: Write>(&self, writer: &mut W) {
        let hex_args = match self {
            ProposalTemplate::Upgrade(template) => template.upgrade_args.upgrade_args_hex(),
            ProposalTemplate::Install(template) => template.install_args.upgrade_args_hex(),
        };
        writer
            .write_all(hex_args.as_bytes())
            .expect("failed to write hex args");
    }

    pub fn render(&self) -> String {
        match self {
            ProposalTemplate::Upgrade(template) => template.render(),
            ProposalTemplate::Install(template) => template.render(),
        }
        .expect("failed to render proposal template")
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
