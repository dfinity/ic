use anyhow::{anyhow, Result};
use futures::{stream, StreamExt};
use ic_agent::Agent;
use ic_base_types::CanisterId;
use ic_nervous_system_agent::nns::sns_wasm;
use ic_nns_constants::{
    CYCLES_MINTING_CANISTER_ID, GENESIS_TOKEN_CANISTER_ID, GOVERNANCE_CANISTER_ID,
    LEDGER_CANISTER_ID, LIFELINE_CANISTER_ID, REGISTRY_CANISTER_ID, ROOT_CANISTER_ID,
    SNS_WASM_CANISTER_ID,
};
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

pub const NNS_CANISTER_NAME_TO_ID: [(&str, CanisterId); 8] = [
    ("registry", REGISTRY_CANISTER_ID),
    ("governance", GOVERNANCE_CANISTER_ID),
    ("ledger", LEDGER_CANISTER_ID),
    ("root", ROOT_CANISTER_ID),
    ("lifeline", LIFELINE_CANISTER_ID),
    ("genesis-token", GENESIS_TOKEN_CANISTER_ID),
    ("cycles-minting", CYCLES_MINTING_CANISTER_ID),
    ("sns-wasm", SNS_WASM_CANISTER_ID),
];

async fn get_mainnet_canister_git_commit_id_and_module_hash(
    agent: &Agent,
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

    let module_hash = agent
        .read_state_canister_info(canister_id, "module_hash")
        .await?;
    let module_hash = module_hash.iter().fold(String::new(), |mut output, x| {
        let _ = write!(output, "{:02x}", x);
        output
    });

    Ok((git_commit_id, module_hash))
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
            let (new_git_hash, new_sha256) =
                get_mainnet_canister_git_commit_id_and_module_hash(&agent, *canister_id).await?;
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

    let sns_upgrade_steps = sns_wasm::query_sns_upgrade_steps(&agent).await?;
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

#[derive(Debug, Clone)]
struct CanisterUpdate {
    canister_name: String,
    new_git_hash: String,
    new_sha256: String,
}

fn update_mainnet_canisters_bzl_file(
    workspace_file_path: &Path,
    updates: Vec<CanisterUpdate>,
) -> Result<()> {
    if updates.is_empty() {
        println!("No updates to apply");
        return Ok(());
    }

    // Read the existing content of the file
    let file = File::open(workspace_file_path)?;
    let reader = BufReader::new(file);

    let mut new_content = Vec::new();

    let max_canister_name_len = updates
        .iter()
        .map(|update| update.canister_name.len())
        .max()
        .unwrap();

    for line in reader.lines() {
        let mut line = line?;

        for update in &updates {
            if line.contains(&format!(r#"    "{name}": "#, name = update.canister_name)) {
                // If the canister_name matches, we store the context of what we'll update in the following lines
                let new_line = format!(
                    r#"    "{name}": ("{git_hash}", "{sha256}"),"#,
                    name = update.canister_name,
                    git_hash = update.new_git_hash,
                    sha256 = update.new_sha256
                );
                if line != new_line {
                    println!(
                        "{name:>max_canister_name_len$} | updated",
                        name = update.canister_name
                    );
                } else {
                    println!(
                        "{name:>max_canister_name_len$} | nothing to update",
                        name = update.canister_name
                    );
                }
                line = new_line;
                break;
            }
        }

        new_content.push(line);
    }

    // Write the new content back to the file
    let mut file = File::create(workspace_file_path)?;
    for line in &new_content {
        writeln!(file, "{}", line)?;
    }

    Ok(())
}
