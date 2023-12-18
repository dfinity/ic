use crate::candid::UpgradeArgs;
use crate::git::{CompressedWasmHash, GitCommitHash, ReleaseNotes};
use crate::TargetCanister;
use askama::Template;
use candid::Principal;

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
