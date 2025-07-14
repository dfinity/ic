use anyhow::{anyhow, Result};
use futures::{stream, StreamExt};
use ic_agent::Agent;
use ic_base_types::CanisterId;
use ic_nervous_system_agent::nns::sns_wasm;
use ic_nns_constants::{
    CYCLES_MINTING_CANISTER_ID, GENESIS_TOKEN_CANISTER_ID, GOVERNANCE_CANISTER_ID,
    LEDGER_CANISTER_ID, LIFELINE_CANISTER_ID, NODE_REWARDS_CANISTER_ID, REGISTRY_CANISTER_ID,
    ROOT_CANISTER_ID, SNS_WASM_CANISTER_ID,
};
use sha2::Digest;
use std::env;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};

pub const NNS_CANISTER_NAME_TO_ID: [(&str, CanisterId); 10] = [
    ("registry", REGISTRY_CANISTER_ID),
    ("governance", GOVERNANCE_CANISTER_ID),
    ("governance-canister_test", GOVERNANCE_CANISTER_ID),
    ("ledger", LEDGER_CANISTER_ID),
    ("root", ROOT_CANISTER_ID),
    ("lifeline", LIFELINE_CANISTER_ID),
    ("genesis-token", GENESIS_TOKEN_CANISTER_ID),
    ("cycles-minting", CYCLES_MINTING_CANISTER_ID),
    ("sns-wasm", SNS_WASM_CANISTER_ID),
    ("node-rewards", NODE_REWARDS_CANISTER_ID),
];

async fn get_mainnet_canister_git_commit_id_and_module_hash(
    agent: &Agent,
    canister_name: &str,
    canister_id: CanisterId,
) -> Result<(String, String)> {
    use std::fmt::Write;

    let canister_id = canister_id.get().0;

    let git_commit_id = agent
        .read_state_canister_metadata(canister_id, "git_commit_id")
        .await?;
    let mut git_commit_id = String::from_utf8(git_commit_id)?;
    if git_commit_id.ends_with('\n') {
        git_commit_id.pop();
    }

    let module_hash = if canister_name.ends_with("_test") {
        // we get the module hash of a test canister from AWS
        let module_url = format!(
            "https://download.dfinity.systems/ic/{git_commit_id}/canisters/{canister_name}.wasm.gz"
        );
        let module_bytes = reqwest::get(module_url)
            .await?
            .error_for_status()?
            .bytes()
            .await?;
        sha2::Sha256::digest(&module_bytes).to_vec()
    } else {
        // we get the module hash of a production canister from the ICP mainnet
        agent
            .read_state_canister_info(canister_id, "module_hash")
            .await?
    };
    let module_hash_str = module_hash.iter().fold(String::new(), |mut output, x| {
        let _ = write!(output, "{:02x}", x);
        output
    });

    Ok((git_commit_id, module_hash_str))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!(
            "Unexpected args: {args:?}\nUsage: {} <path_to_workspace_file> <path_to_ic_wasm>",
            args[0]
        );
        std::process::exit(1);
    }

    let workspace_file_path = PathBuf::from(&args[1]);
    let ic_wasm_path = PathBuf::from(&args[2]);

    let agent = get_mainnet_agent()?;

    let mut canister_updates = stream::iter(NNS_CANISTER_NAME_TO_ID.iter())
        .then(|(canister_name, canister_id)| async {
            let canister_name = canister_name.to_string();
            let (new_git_hash, new_sha256) = get_mainnet_canister_git_commit_id_and_module_hash(
                &agent,
                &canister_name,
                *canister_id,
            )
            .await?;
            Ok(CanisterUpdate {
                canister_name,
                new_git_hash,
                new_sha256,
            })
        })
        .collect::<Vec<Result<CanisterUpdate>>>()
        .await
        .into_iter()
        .collect::<Result<Vec<CanisterUpdate>>>()?;

    let sns_upgrade_steps = sns_wasm::query_mainline_sns_upgrade_steps(&agent).await?;
    let latest_sns_version = &sns_upgrade_steps
        .steps
        .last()
        .ok_or_else(|| anyhow!("No SNS upgrade steps found"))?;

    let latest_version = latest_sns_version.version.as_ref().unwrap();
    let latest_pretty_version = latest_sns_version.pretty_version.as_ref().unwrap();
    let sns_canister_updates = {
        let latest_pretty_version = latest_pretty_version.clone();
        let canister_name_to_published_wasm_hash = [
            (
                "sns_root",
                &latest_version.root_wasm_hash,
                latest_pretty_version.root_wasm_hash,
            ),
            (
                "sns_governance",
                &latest_version.governance_wasm_hash,
                latest_pretty_version.governance_wasm_hash,
            ),
            (
                "swap",
                &latest_version.swap_wasm_hash,
                latest_pretty_version.swap_wasm_hash,
            ),
            (
                "sns_ledger",
                &latest_version.ledger_wasm_hash,
                latest_pretty_version.ledger_wasm_hash,
            ),
            (
                "sns_index",
                &latest_version.index_wasm_hash,
                latest_pretty_version.index_wasm_hash,
            ),
            (
                "sns_archive",
                &latest_version.archive_wasm_hash,
                latest_pretty_version.archive_wasm_hash,
            ),
        ]
        .into_iter();
        let results = stream::iter(canister_name_to_published_wasm_hash)
            .then(|(canister_name, hash, new_sha256)| async {
                let canister_name = canister_name.to_string();
                let new_git_hash =
                    sns_wasm::get_git_version_for_sns_hash(&agent, &ic_wasm_path, hash).await?;

                Ok(CanisterUpdate {
                    canister_name,
                    new_git_hash,
                    new_sha256,
                })
            })
            .collect::<Vec<Result<CanisterUpdate>>>()
            .await;
        results
            .into_iter()
            .collect::<Result<Vec<CanisterUpdate>>>()?
    };

    canister_updates.extend(sns_canister_updates);

    update_mainnet_canisters_bzl_file(&workspace_file_path, canister_updates)?;

    Ok(())
}

fn get_mainnet_agent() -> Result<Agent> {
    let ic_url = "https://ic0.app/";
    get_agent(ic_url)
}

fn get_agent(ic_url: &str) -> Result<Agent> {
    Agent::builder()
        .with_url(ic_url)
        .with_verify_query_signatures(false)
        .build()
        .map_err(|e| anyhow!(e))
}

#[derive(Clone, Debug)]
struct CanisterUpdate {
    canister_name: String,
    new_git_hash: String,
    new_sha256: String,
}

fn update_mainnet_canisters_bzl_file(
    canisters_json: &Path,
    updates: Vec<CanisterUpdate>,
) -> Result<()> {
    if updates.is_empty() {
        println!("No updates to apply");
        return Ok(());
    }

    // Read the existing content of the file
    let file = File::open(canisters_json)?;
    let reader = BufReader::new(file);
    let orig: serde_json::Value =
        serde_json::from_reader(reader).expect("Could not read canister data");

    // The map containing canister data
    let mut m = match orig {
        serde_json::Value::Object(m) => m.clone(),
        _ => panic!("Expected canister data to be a JSON map"),
    };

    // For each update, insert the new canister values into the map. Note that this
    // does not remove e.g. outdated canisters.
    for canister in &updates {
        let rev = serde_json::Value::String(canister.new_git_hash.clone());
        let sha256 = serde_json::Value::String(canister.new_sha256.clone());
        let mut entry = serde_json::Map::new();
        let _ = entry.insert("rev".to_string(), rev);
        let _ = entry.insert("sha256".to_string(), sha256);
        let entry = serde_json::Value::Object(entry);
        let _prev = m.insert(canister.canister_name.clone(), entry);
    }

    // Write the new content back to the file
    let file = File::create(canisters_json)?;
    serde_json::to_writer_pretty(file, &m).unwrap();

    Ok(())
}
