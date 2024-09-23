#[cfg(test)]
mod tests;

use crate::git::CompressedWasmHash;
use crate::proposal::ProposalTemplate;
use askama::Template;
use candid::Principal;
use clap::Args;
use std::path::{Path, PathBuf, StripPrefixError};

#[derive(Clone, Debug, Args)]
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
    proposer: u64,

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
        let mode = match proposal {
            ProposalTemplate::Upgrade(_) => "upgrade",
            ProposalTemplate::Install(_) => "install",
        }
        .to_string();
        IcAdminTemplate {
            args: self,
            mode,
            canister_id: *proposal.canister_id(),
            wasm_module_path: generated_files.wasm.to_string_lossy().to_string(),
            wasm_module_sha256: proposal.compressed_wasm_hash().clone(),
            arg: generated_files.arg.to_string_lossy().to_string(),
            arg_sha256: proposal.args_sha256_hex(),
            summary_file: generated_files.summary.to_string_lossy().to_string(),
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

impl ProposalFiles {
    pub fn strip_prefix(self, base: &Path) -> Result<Self, StripPrefixError> {
        Ok(Self {
            wasm: self.wasm.strip_prefix(base)?.to_path_buf(),
            arg: self.arg.strip_prefix(base)?.to_path_buf(),
            summary: self.summary.strip_prefix(base)?.to_path_buf(),
        })
    }
}

#[derive(Template)]
#[template(path = "submit_with_ic_admin.shx", escape = "none")]
// The template uses the extension ".shx" to avoid the automatic linting done by "shfmt" on all ".sh" files.
// This is necessary because the template contains not-yet-valid shell code that will only be valid after the template is rendered.
pub struct IcAdminTemplate {
    pub args: IcAdminArgs,

    /// The mode to use when updating the canister.
    // We could use CanisterInstallMode instead, but it lives in the `ic-management-canister-types` crate
    // which has a somewhat large number of dependencies for what we need here, which is
    // just a simple enum with 2 variants.
    mode: String,

    /// The ID of the canister to modify.
    pub canister_id: Principal,

    /// The file system path to the new wasm module to ship.
    pub wasm_module_path: String,

    /// The sha256 of the new wasm module to ship.
    pub wasm_module_sha256: CompressedWasmHash,

    /// The path to a binary file containing the initialization or upgrade args of the
    /// canister.
    pub arg: String,

    /// The sha256 of the arg binary file.
    pub arg_sha256: String,

    /// A file containing a human-readable summary of the proposal content.
    pub summary_file: String,
}
