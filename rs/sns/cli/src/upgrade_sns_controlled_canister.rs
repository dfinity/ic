use crate::neuron_id_to_candid_subaccount::ParsedSnsNeuron;
use anyhow::{bail, Context, Result};
use candid::Principal;
use candid_utils::validation::validate_upgrade_args;
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
    proposal::Action, ChunkedCanisterWasm, Proposal, UpgradeSnsControlledCanister,
};
use serde_cbor::Value;
use std::{collections::BTreeSet, fs::File, io::Read, path::PathBuf};

const RAW_WASM_HEADER: [u8; 4] = [0, 0x61, 0x73, 0x6d];
const GZIPPED_WASM_HEADER: [u8; 3] = [0x1f, 0x8b, 0x08];

/// The arguments used to configure the upgrade_sns_controlled_canister command.
#[derive(Debug, Parser)]
pub struct UpgradeSnsControlledCanisterArgs {
    /// SNS neuron ID (subaccount) to be used for proposing the upgrade.
    #[clap(long)]
    sns_neuron_id: ParsedSnsNeuron,

    /// ID of the target canister to be upgraded.
    #[clap(long)]
    target_canister_id: CanisterId,

    /// Path to a ICP WASM module file (may be gzipped).
    #[clap(long)]
    wasm_path: PathBuf,

    /// Upgrade argument for the Candid service.
    #[clap(long)]
    candid_arg: Option<String>,

    /// URL (starting with https://) of a web page with a public announcement of this upgrade.
    #[clap(long)]
    proposal_url: Url,

    /// Human-readable text explaining why this upgrade is being done (may be markdown).
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
        sns_neuron_id,
        target_canister_id,
        wasm_path,
        candid_arg,
        proposal_url,
        summary,
    } = args;

    // Check that the target canister exists, and see if it serves its Candid service definition.
    let current_module_hash = agent
        .read_state_canister_info(target_canister_id.get().0, "module_hash")
        .await
        .expect(
            "Cannot read target canister's module hash. Please make sure the target canister\
             is already installed; this tool cannot be used to *install* canisters, only \
             to propose *upgrading* already installed, SNS-controlled canisters.",
        );
    let candid_service = {
        let candid_service = agent
            .read_state_canister_metadata(target_canister_id.get().0, "icp:public candid:service")
            .await
            .expect("Cannot read target canister's metadata section `icp:public candid:service`.");
        std::str::from_utf8(&candid_service)
            .expect("Cannot decode target canister's Candid service definition.")
            .to_string()
    };

    // Validate the upgrade arg against the Candid service definition.
    let canister_upgrade_arg = if let Some(candid_arg) = candid_arg {
        match validate_upgrade_args(candid_service, candid_arg) {
            Ok(candid_arg_bytes) => Some(candid_arg_bytes),
            Err(err) => {
                bail!(err);
            }
        }
    } else {
        None
    };

    // Find the Root canister of the SNS controlling the target.
    let target_controllers = {
        let controllers_blob = agent
            .read_state_canister_info(target_canister_id.get().0, "controllers")
            .await
            .expect("Cannot read target canister's controllers.");

        let cbor: Value = serde_cbor::from_slice(&controllers_blob)
            .expect("Invalid cbor data for target controller's controllers.");

        let Value::Array(controllers) = cbor else {
            panic!("Expected controllers to be an array, but got {cbor:?}");
        };

        controllers
            .into_iter()
            .map(|elem| {
                let Value::Bytes(bytes) = elem else {
                    panic!("Expected element in controllers to be of type bytes, got {elem:?}");
                };
                Principal::try_from(&bytes).unwrap()
            })
            .collect::<Vec<_>>()
    };

    let root_canister_id = {
        let sns_root_controllers = target_controllers
            .into_iter()
            .filter_map(|controller| {
                let controller = PrincipalId(controller);
                if controller.is_self_authenticating() {
                    return None;
                }
                // TODO: Check that the controller is actually an SNS Root, not soe other canister.
                Some(controller)
            })
            .collect::<BTreeSet<_>>();

        assert!(
            !sns_root_controllers.is_empty(),
            "The target canister is not controlled by an SNS Root."
        );
        assert_eq!(
            sns_root_controllers.len(),
            1,
            "The target canister is controlled by more than one SNS Root!"
        );
        CanisterId::try_from_principal_id(*sns_root_controllers.first().unwrap()).unwrap()
    };

    let root_canister = sns::root::RootCanister {
        canister_id: root_canister_id.get(),
    };

    // Check that the Root canister exists, identifying some SNS.
    let SnsCanisters { sns, dapps } = root_canister.list_sns_canisters(agent).await?;

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

    let chunk_hashes_list = uploaded_chunk_hashes
        .into_iter()
        .map(|chunk_hash| chunk_hash.hash)
        .collect();

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
                chunked_canister_wasm: Some(ChunkedCanisterWasm {
                    wasm_module_hash: new_module_hash.to_vec(),
                    store_canister_id: Some(store_canister_id.get()),
                    chunk_hashes_list,
                }),
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
