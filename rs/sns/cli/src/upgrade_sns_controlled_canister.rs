use anyhow::{bail, Context, Result};
use candid::{CandidType, Decode, Deserialize, Encode, Principal, TypeEnv};
use candid_parser::{check_prog, parse_idl_args, IDLArgs, IDLProg};
use clap::Parser;
use cycles_minting_canister::{CanisterSettingsArgs, SubnetSelection};
use ic_agent::{export::reqwest::Url, Agent};
use ic_base_types::{CanisterId, PrincipalId};
use ic_management_canister_types::{BoundedVec, CanisterInstallMode};
use ic_nervous_system_agent::{
    management_canister::{self, CHUNK_SIZE},
    nns, sns,
    sns::root::SnsCanisters,
};
use ic_sns_governance::pb::v1::{
    manage_neuron, manage_neuron_response, proposal::Action, ManageNeuronResponse, NeuronId,
    Proposal, UpgradeSnsControlledCanister,
};
use std::{collections::BTreeSet, fs::File, io::Read, path::PathBuf};

use crate::neuron_id_to_candid_subaccount::ParsedSnsNeuron;

const RAW_WASM_HEADER: [u8; 4] = [0, 0x61, 0x73, 0x6d];
const GZIPPED_WASM_HEADER: [u8; 3] = [0x1f, 0x8b, 0x08];

/// The arguments used to configure the upgrade_sns_controlled_canister command.
#[derive(Debug, Parser)]
pub struct UpgradeSnsControlledCanisterArgs {
    #[clap(long)]
    root_canister_id: CanisterId,

    #[clap(long)]
    sns_neuron_id: ParsedSnsNeuron,

    #[clap(long)]
    target_canister_id: CanisterId,

    #[clap(long)]
    wasm_path: PathBuf,

    #[clap(long)]
    candid_arg: Option<String>,

    #[clap(long)]
    proposal_url: Url,

    #[clap(long)]
    summary: String,
}

fn load_wasm(wasm_path: PathBuf) -> Result<Vec<u8>> {
    let mut file = File::open(&wasm_path).context("Cannot open file.")?;

    // Create a buffer to store the file's content
    let mut bytes = Vec::new();

    // Read the file's content into the buffer
    file.read_to_end(&mut bytes).context("Cannot read file.")?;

    // Smoke test: Is this a ICP Wasm?
    if bytes.len() < 4 || bytes[..4] != RAW_WASM_HEADER[..] && bytes[..3] != GZIPPED_WASM_HEADER[..]
    {
        bail!("The file does not look like a valid ICP Wasm module.");
    }

    Ok(bytes)
}

pub async fn exec(args: UpgradeSnsControlledCanisterArgs, agent: &Agent) -> Result<()> {
    eprintln!("Preparing to propose an SNS-controlled canister upgrade ...");

    // Prepare.

    let UpgradeSnsControlledCanisterArgs {
        root_canister_id,
        sns_neuron_id,
        target_canister_id,
        wasm_path,
        candid_arg,
        proposal_url,
        summary,
    } = args;

    let root_canister = sns::root::RootCanister {
        canister_id: root_canister_id.get(),
    };

    // Check that the Root canister exists, identifying some SNS.
    let SnsCanisters { sns, dapps } = root_canister.list_sns_canisters(agent).await?;

    // Check that the target canister exists, and see if it serves its Candid service definition.
    let current_module_hash = agent
        .read_state_canister_info(target_canister_id.get().0, "module_hash")
        .await
        .expect(
            "Cannot read target canister's module hash. Please make sure the target canister\
             is already installed; this tool cannot be used to *install* canisters, only \
             to propose *upgrading* already installed, SNS-controlled canisters.",
        );
    let candid_service_ast = {
        let candid_service = agent
            .read_state_canister_metadata(target_canister_id.get().0, "icp:public candid:service")
            .await
            .expect("Cannot read target canister's metadata section `icp:public candid:service`.");
        let candid_service = std::str::from_utf8(&candid_service)
            .expect("Cannot decode target canister's Candid service definition.");
        candid_service
            .parse::<IDLProg>()
            .expect("Cannot parse target canister's Candid service definition.")
    };

    // Validate the upgrade arg against the Candid service definition.
    let canister_upgrade_arg = if let Some(candid_arg) = candid_arg {
        // let args_ast =
        //.expect("Cannot parse --candid_arg as Candid");

        let mut type_env = TypeEnv::new();
        check_prog(&mut type_env, &candid_service_ast)
            .expect("")
            .expect("Target canister's Candid service definition should include the main action.");

        // Some(args_ast.to_bytes().expect("Cannot serialize upgrade arg."))
        todo!()
    } else {
        None
    };

    // Check that the target is indeed controlled by the SNS.
    if !BTreeSet::from_iter(&dapps[..]).contains(&target_canister_id.get()) {
        bail!(
            "{} is not one of the canisters controlled by the SNS with Root canister {}",
            target_canister_id,
            root_canister_id,
        );
    }

    // Check that we have a viable Wasm for this upgrade.
    let wasm_bytes = load_wasm(wasm_path)?;
    let new_module_hash = ic_crypto_sha2::Sha256::hash(&wasm_bytes);
    assert_ne!(
        new_module_hash.to_vec(),
        current_module_hash,
        "Target canister is already running Wasm module with SHA256 {}. Nothing to do.",
        format_full_hash(&new_module_hash),
    );

    // Create a store canister on the same subnet as the target.
    let subnet = nns::registry::get_subnet_for_canister(agent, target_canister_id).await?;

    let caller_principal = agent.get_principal().map_err(|err| anyhow::anyhow!(err))?;

    let store_canister_id = nns::cmc::create_canister(
        agent,
        Some(SubnetSelection::Subnet { subnet }),
        Some(CanisterSettingsArgs {
            controllers: Some(BoundedVec::new(vec![
                PrincipalId(caller_principal),
                root_canister_id.get(),
                sns.governance.canister_id,
            ])),
            ..Default::default()
        }),
    )
    .await?;

    // TODO: Add enough cycles to `store_canister_id`.

    // 4. Upload the chunks into the store canister.
    let num_chunks_expected = {
        let num_full_chunks = wasm_bytes.len() / CHUNK_SIZE;
        let remainder = wasm_bytes.len() % CHUNK_SIZE;
        if remainder == 0 {
            num_full_chunks
        } else {
            num_full_chunks + 1
        }
    };
    let uploaded_chunk_hashes = management_canister::upload_wasm_as_chunks(
        agent,
        store_canister_id,
        wasm_bytes,
        num_chunks_expected,
    )
    .await?;

    // 5. Propose to upgrade the target canister to a Wasm assembled from the uploaded chunks.
    let sns_governance = sns::governance::GovernanceCanister {
        canister_id: sns.governance.canister_id,
    };

    let proposal = Proposal {
        title: format!(
            "Upgrade SNS-controlled canister {}",
            target_canister_id.get()
        ),
        summary,
        url: proposal_url.to_string(),
        action: Some(Action::UpgradeSnsControlledCanister(
            UpgradeSnsControlledCanister {
                canister_id: Some(target_canister_id.get()),
                new_canister_wasm: vec![],
                canister_upgrade_arg,
                mode: Some(CanisterInstallMode::Upgrade as i32),
                // TODO: use `uploaded_chunk_hashes` / `sha256_hash`
            },
        )),
    };

    let proposal_id = sns_governance
        .submit_proposal(agent, sns_neuron_id.0, proposal)
        .await?;

    let proposal_url = format!(
        "https://nns.ic0.app/proposal/?u={}&proposal={}",
        root_canister_id.get(),
        proposal_id.id,
    );

    eprintln!(
        "Successfully proposed to upgrade SNS-controlled canister, see details here:\n\
         {proposal_url}",
    );

    Ok(())
}

fn format_full_hash(hash: &[u8]) -> String {
    hash.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}

#[cfg(test)]
mod tests;
