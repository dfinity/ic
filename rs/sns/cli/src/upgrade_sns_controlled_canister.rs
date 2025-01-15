use anyhow::{bail, Context, Result};
use candid::{CandidType, Decode, Deserialize, Encode, IDLArgs, Principal};
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

    // 1. Check that we have a viable Wasm and a suitable upgrade arg.
    let UpgradeSnsControlledCanisterArgs {
        root_canister_id,
        sns_neuron_id,
        target_canister_id,
        wasm_path,
        candid_arg,
        proposal_url,
        summary,
    } = args;

    let wasm_bytes = load_wasm(wasm_path)?;
    let sha256_hash = ic_crypto_sha2::Sha256::hash(&wasm_bytes);

    // TODO: Support candid args.
    let canister_upgrade_arg =
        candid_arg.map(|candid_arg| unimplemented!("Candid args are not yet supported"));

    // 2. Check that the target is controlled by the SNS specified via the Root canister ID.
    let root_canister = sns::root::RootCanister {
        canister_id: root_canister_id.get(),
    };
    let SnsCanisters { sns, dapps } = root_canister.list_sns_canisters(agent).await?;

    if !BTreeSet::from_iter(&dapps[..]).contains(&target_canister_id.get()) {
        bail!(
            "{} is not one of the canisters controlled by the SNS with Root canister {}",
            target_canister_id,
            root_canister_id,
        );
    }

    // 3. Create a store canister on the same subnet as the target.
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
