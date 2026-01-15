use candid::{Decode, Encode};
use clap::Parser;
use ic_agent::{Agent, export::Principal};
use ic_identity_hsm::HardwareIdentity;
use ic_nns_common::pb::v1::{NeuronId, ProposalId};
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance_api::{
    MakeProposalRequest, ManageNeuronCommandRequest, ManageNeuronRequest, ManageNeuronResponse,
    Motion, ProposalActionRequest,
    manage_neuron::NeuronIdOrSubaccount,
    manage_neuron_response::{self, MakeProposalResponse},
};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Uses an HSM based identity (in dfx, named `hsm`) to submit a motion proposal.
///
/// The DFX_HSM_PIN environment variable must be set (to the PIN of your HSM, of
/// course). Here is a more secure way to do that:
///
/// ```
/// read -s DFX_HSM_PIN
/// export DFX_HSM_PIN
/// ```
///
/// The first command waits for you to enter your PIN, but when you type, you'll
/// see nothing (the -s is for secret, or something like that).
#[derive(Parser, Debug)]
struct Argv {
    /// ID of the neuron that will submit the motion proposal. (The hsm identity
    /// must be able to propose with this neuron, meaning it must be the
    /// controller, or a hotkey.)
    #[arg(long)]
    neuron_id: u64,

    /// This file has the following format:
    ///
    /// ${HEADER}
    /// --------------------------------------------------------------------------------
    /// ${SUMMARY}
    ///
    /// That is, it is split into two top level sections, separated by a line
    /// containing 80 dash characters.
    ///
    /// The ${HEADER} section is in YAML format. It has a couple of keys:
    ///
    ///   * title
    ///   * URL
    ///
    /// As you would expect, all these pieces specify the various bits of the
    /// motion proposal to be submitted.
    #[arg(long, verbatim_doc_comment)]
    proposal_file: String,

    #[arg(long, default_value = "https://ic0.app")]
    network_url: String,

    #[arg(long, default_value = "false")]
    verbose: bool,
}

/// See the Identity struct. This is relative to the home directory of the user
/// running this program.
const DFX_HSM_IDENTITY_PATH: &str = ".config/dfx/identity/hsm/identity.json";

/// See the comments for Argv above.
#[tokio::main]
async fn main() {
    let Argv {
        network_url,
        neuron_id,
        proposal_file,
        verbose,
    } = Argv::parse();

    let request = load_proposal(&proposal_file, neuron_id, verbose);

    let governance_canister_id = Principal::from(GOVERNANCE_CANISTER_ID);
    let response = new_ic_agent(&network_url)
        .await
        .update(&governance_canister_id, "manage_neuron")
        .with_arg(Encode!(&request).unwrap())
        .call_and_wait()
        .await
        .unwrap();

    handle_response(response);
}

/// Reports what happend as a result of attempting to make/submit a motion
/// proposal. In the happy case, the main thing this prints out is a URL to the
/// proposal that was just submitted/made.
fn handle_response(response: Vec<u8>) {
    // Unpack API.
    let ManageNeuronResponse { command } = Decode!(&response, ManageNeuronResponse).unwrap();
    let command = command.unwrap();
    let make_proposal_response = match command {
        manage_neuron_response::Command::MakeProposal(ok) => ok,
        _ => panic!("{command:#?}"),
    };
    let MakeProposalResponse {
        proposal_id,
        message,
    } = &make_proposal_response;

    // Prepare to present outcome by gathering the bits and pieces of the final report.
    let proposal_id = proposal_id
        .map(|proposal_id| {
            let ProposalId { id: proposal_id } = proposal_id;

            format!("{proposal_id}")
        })
        .unwrap_or_else(|| "???".to_string());

    println!("Succes! 🚀");
    println!("Proposal URL: https://dashboard.internetcomputer.org/proposals/{proposal_id}");
    if let Some(message) = message {
        println!("Message: {message}");
    }
}

/// Reads the file, which is formatted according to the --proposal-file file,
/// parses it, and constructs a proposal creation request that can be sent to
/// the NNS Governance canister via the manage_neuron canister method.
fn load_proposal(proposal_file_path: &str, neuron_id: u64, verbose: bool) -> ManageNeuronRequest {
    let proposal_file_content = std::fs::read_to_string(proposal_file_path).unwrap();

    let divider = "-".repeat(80) + "\n";
    let (header, summary) = proposal_file_content.split_once(&divider).unwrap();

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Header {
        title: String,
        url: String,
    }

    let Header { title, url } = serde_yaml::from_str::<Header>(header).unwrap();
    println!("Title: {title}");
    if verbose {
        println!("URL: {url}");
        println!("Summary:");
        println!("{summary}");
    }
    println!("Submitting... ⏳");

    // Robotic mechanical conversions that are nevertheless necessary.
    let title = Some(title);
    let summary = summary.to_string();

    ManageNeuronRequest {
        neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId { id: neuron_id })),
        command: Some(ManageNeuronCommandRequest::MakeProposal(Box::new(
            MakeProposalRequest {
                title,
                url,
                summary,
                action: Some(ProposalActionRequest::Motion(Motion {
                    motion_text: "See the proposal summary.".to_string(),
                })),
            },
        ))),
        id: None,
    }
}

/// An Agent is a device by which you can call canisters running in the ICP from
/// outside the ICP.
async fn new_ic_agent(network_url: &str) -> Agent {
    let agent = Agent::builder()
        .with_url(network_url)
        .with_identity(new_identity())
        .build()
        .unwrap();

    agent.fetch_root_key().await.unwrap();

    agent
}

/// Constructs a new "Identity" that an Agent (from ic_agent) can use to sign
/// requests that will be sent to canisters running in the ICP.
///
/// This identity is based on a plugged in HSM security devices, a small USB
/// dongle that is capable of signing things, when supplied with the right PIN.
///
/// The configuration for this lives in
/// ~/.config/dfx/identities/hsm/identity.json. That is, this uses the same
/// configuration as the dfx "hsm" identity.
fn new_identity() -> HardwareIdentity {
    // Read configuration file.
    let home = std::env::var("HOME").unwrap();
    let path = Path::new(&home).join(DFX_HSM_IDENTITY_PATH);
    let identity = std::fs::read_to_string(path).unwrap();

    // Parse configuration.

    /// This follows the format used by ~/.config/dfx/identity/*/identity.json files.
    #[derive(Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Identity {
        hsm: Hsm,

        /// Not used. Not sure how to use these. These need to be listed,
        /// because we use deny_unknown_fields to avoid being caught off guard.
        encryption: Option<String>,
        keyring_identity_suffix: Option<String>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Hsm {
        pkcs11_lib_path: String,

        // #[serde(deserialize_with = "hex::deserialize")]
        key_id: String,
    }

    let Identity {
        hsm: Hsm {
            pkcs11_lib_path,
            key_id,
        },
        encryption: _,
        keyring_identity_suffix: _,
    } = serde_json::from_str::<Identity>(&identity).unwrap();

    HardwareIdentity::new(
        pkcs11_lib_path,
        0, // slot
        &key_id,
        || {
            // Get pin from environment variable.
            std::env::var("DFX_HSM_PIN").map_err(|err| {
                format!(
                    "DFX_HSM_PIN environment variable is not set (or just \
                     not exported such that it is visible to this process): {err}",
                )
            })
        },
    )
    .unwrap()
}
