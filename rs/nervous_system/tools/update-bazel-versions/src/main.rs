use anyhow::{anyhow, Result};
use futures::{stream, StreamExt};
use ic_agent::Agent;
use ic_base_types::CanisterId;
use ic_nns_constants::{
    CYCLES_MINTING_CANISTER_ID, GENESIS_TOKEN_CANISTER_ID, GOVERNANCE_CANISTER_ID,
    LEDGER_CANISTER_ID, LIFELINE_CANISTER_ID, REGISTRY_CANISTER_ID, ROOT_CANISTER_ID,
    SNS_WASM_CANISTER_ID,
};
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

mod sns_wasm_utils;

pub const CORE_NNS_CANISTERS: [(&str, &str, CanisterId); 8] = [
    (
        "mainnet_nns_registry_canister",
        "registry-canister.wasm.gz",
        REGISTRY_CANISTER_ID,
    ),
    (
        "mainnet_nns_governance_canister",
        "governance-canister.wasm.gz",
        GOVERNANCE_CANISTER_ID,
    ),
    (
        "mainnet_icp_ledger_canister",
        "ledger-canister_notify-method.wasm.gz",
        LEDGER_CANISTER_ID,
    ),
    (
        "mainnet_nns_root-canister",
        "root-canister.wasm.gz",
        ROOT_CANISTER_ID,
    ),
    (
        "mainnet_nns_lifeline_canister",
        "lifeline_canister.wasm.gz",
        LIFELINE_CANISTER_ID,
    ),
    (
        "mainnet_nns_genesis-token-canister",
        "genesis-token-canister.wasm.gz",
        GENESIS_TOKEN_CANISTER_ID,
    ),
    (
        "mainnet_nns_cycles-minting-canister",
        "cycles-minting-canister.wasm.gz",
        CYCLES_MINTING_CANISTER_ID,
    ),
    (
        "mainnet_nns_sns-wasm-canister",
        "sns-wasm-canister.wasm.gz",
        SNS_WASM_CANISTER_ID,
    ),
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

    let mut canister_updates = stream::iter(CORE_NNS_CANISTERS.iter())
        .then(|(bazel_target_name, wasm_file_name, id)| async {
            let bazel_target_name = bazel_target_name.to_string();
            let wasm_file_name = wasm_file_name.to_string();
            let (new_git_hash, new_sha256) =
                get_mainnet_canister_git_commit_id_and_module_hash(&agent, *id).await?;
            Ok(CanisterUpdate {
                bazel_target_name,
                wasm_file_name,
                new_git_hash,
                new_sha256,
            })
        })
        .collect::<Vec<Result<CanisterUpdate>>>()
        .await
        .into_iter()
        .collect::<Result<Vec<CanisterUpdate>>>()?;

    let sns_upgrade_steps = sns_wasm_utils::query_sns_upgrade_steps(&agent).await?;
    let latest_sns_version = &sns_upgrade_steps
        .steps
        .last()
        .ok_or_else(|| anyhow!("No SNS upgrade steps found"))?;

    let latest_version = latest_sns_version.version.as_ref().unwrap();
    let latest_pretty_version = latest_sns_version.pretty_version.as_ref().unwrap();
    let sns_canister_updates = {
        let data = [
            (
                "mainnet_sns-root-canister",
                "sns-root-canister.wasm.gz",
                &latest_version.root_wasm_hash,
                &latest_pretty_version.root_wasm_hash,
            ),
            (
                "mainnet_sns-governance-canister",
                "sns-governance-canister.wasm.gz",
                &latest_version.governance_wasm_hash,
                &latest_pretty_version.governance_wasm_hash,
            ),
            (
                "mainnet_sns-swap-canister",
                "sns-swap-canister.wasm.gz",
                &latest_version.swap_wasm_hash,
                &latest_pretty_version.swap_wasm_hash,
            ),
            (
                "mainnet_ic-icrc1-ledger",
                "ic-icrc1-ledger.wasm.gz",
                &latest_version.ledger_wasm_hash,
                &latest_pretty_version.ledger_wasm_hash,
            ),
            (
                "mainnet_ic-icrc1-index-ng",
                "ic-icrc1-index-ng.wasm.gz",
                &latest_version.index_wasm_hash,
                &latest_pretty_version.index_wasm_hash,
            ),
            (
                "mainnet_ic-icrc1-archive",
                "ic-icrc1-archive.wasm.gz",
                &latest_version.archive_wasm_hash,
                &latest_pretty_version.archive_wasm_hash,
            ),
        ]
        .into_iter();
        let stream = stream::iter(data);
        let results = stream
            .then(
                |(bazel_target_name, wasm_file_name, hash, new_sha256)| async {
                    let bazel_target_name = bazel_target_name.to_string();
                    let wasm_file_name = wasm_file_name.to_string();
                    let new_sha256 = new_sha256.clone();
                    let new_git_hash =
                        sns_wasm_utils::get_git_version_for_sns_hash(&agent, &ic_wasm_path, hash)
                            .await?;

                    // required to cause `name` to not be captured by the closure
                    #[allow(clippy::to_string_in_format_args)]
                    Ok(CanisterUpdate {
                        bazel_target_name,
                        wasm_file_name,
                        new_git_hash,
                        new_sha256,
                    })
                },
            )
            .collect::<Vec<Result<CanisterUpdate>>>()
            .await;
        results
            .into_iter()
            .collect::<Result<Vec<CanisterUpdate>>>()?
    };

    canister_updates.extend(sns_canister_updates);

    update_workspace_file(&workspace_file_path, canister_updates)?;

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
    bazel_target_name: String,
    wasm_file_name: String,
    new_git_hash: String,
    new_sha256: String,
}

fn update_workspace_file(workspace_file_path: &Path, updates: Vec<CanisterUpdate>) -> Result<()> {
    if updates.is_empty() {
        println!("No updates to apply");
        return Ok(());
    }

    // Read the existing content of the file
    let file = File::open(workspace_file_path)?;
    let reader = BufReader::new(file);

    let mut new_content = Vec::new();
    let mut update_context = None;

    for line in reader.lines() {
        let line = line?;

        // Check if the line is a http file declaration
        if line.starts_with("http_file(") {
            // Reset the context for each new canister
            update_context = None;
        }

        for update in &updates {
            if line.contains(&update.bazel_target_name) {
                // If the bazel_target_name matches, we store the context of what we'll update in the following lines
                update_context = Some(update.clone());
                break;
            }
        }

        if let Some(ref update) = update_context {
            // If we're in the context of an update, check if the line needs to be updated
            if line.contains("url = ") {
                let new_line = format!(
                    "        url = \"https://download.dfinity.systems/ic/{}/canisters/{}\",",
                    update.new_git_hash, update.wasm_file_name
                );
                if new_line != line {
                    println!("Updated url for {}", update.wasm_file_name);
                }
                new_content.push(new_line);
                update_context = None;
                continue;
            } else if line.contains("sha256 = ") {
                let new_line = format!("        sha256 = \"{}\",", update.new_sha256);
                if new_line != line {
                    println!("Updated sha256 for {}", update.wasm_file_name);
                }
                new_content.push(new_line);
                continue;
            }
        }

        // For all other lines, or if there's no current update context, just copy the line
        new_content.push(line);
    }

    // Write the new content back to the file
    let mut file = File::create(workspace_file_path)?;
    for line in &new_content {
        writeln!(file, "{}", line)?;
    }

    Ok(())
}
