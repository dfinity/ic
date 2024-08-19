use crate::git::CompressedWasmHash;
use crate::proposal::ProposalTemplate;
use askama::Template;
use candid::Principal;
use clap::Args;
use std::path::PathBuf;

#[derive(Debug, Clone, Args)]
pub struct IcAdminArgs {
    /// Use an HSM to sign calls.
    #[clap(long)]
    use_hsm: bool,

    /// The slot related to the HSM key that shall be used.
    #[clap(
        long = "slot",
        help = "Only required if use-hsm is set. Ignored otherwise."
    )]
    hsm_slot: Option<String>,

    /// The id of the key on the HSM that shall be used.
    #[clap(
        long = "key-id",
        help = "Only required if use-hsm is set. Ignored otherwise."
    )]
    key_id: Option<String>,

    /// The PIN used to unlock the HSM.
    #[clap(
        long = "pin",
        help = "Only required if use-hsm is set. Ignored otherwise."
    )]
    pin: Option<String>,

    #[clap(long)]
    /// The id of the neuron on behalf of which the proposal will be submitted.
    proposer: Option<u64>,

    /// The title of the proposal.
    #[clap(long)]
    proposal_title: Option<String>,
}

impl IcAdminArgs {
    pub fn command_to_submit_proposal(
        self,
        proposal: &ProposalTemplate,
        generated_files: ProposalFiles,
    ) -> String {
        IcAdminTemplate {
            args: self,
            canister_id: *proposal.canister_id(),
            wasm_module_path: generated_files.wasm,
            wasm_module_sha256: proposal.compressed_wasm_hash().clone(),
            arg: generated_files.arg,
            summary_file: generated_files.summary,
        }
        .render()
        .expect("failed to render ic-admin template")
    }
}

pub struct ProposalFiles {
    pub wasm: PathBuf,
    pub arg: PathBuf,
    pub summary: PathBuf,
}

#[derive(Template)]
#[template(path = "submit_with_ic_admin.sh", escape = "none")]
pub struct IcAdminTemplate {
    pub args: IcAdminArgs,

    /// The ID of the canister to modify
    pub canister_id: Principal,

    /// The file system path to the new wasm module to ship.
    pub wasm_module_path: PathBuf,

    /// The sha256 of the new wasm module to ship.
    pub wasm_module_sha256: CompressedWasmHash,

    /// The path to a binary file containing the initialization or upgrade args of the
    /// canister.
    pub arg: PathBuf,

    /// A file containing a human-readable summary of the proposal content.
    pub summary_file: PathBuf,
}
