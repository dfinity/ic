use anyhow::{anyhow, Result};
use futures::{stream, StreamExt};
use ic_agent::Agent;
use ic_base_types::CanisterId;
use ic_nervous_system_agent::nns::sns_wasm;
use ic_nns_constants::{
    CYCLES_LEDGER_CANISTER_ID, CYCLES_LEDGER_INDEX_CANISTER_ID, CYCLES_MINTING_CANISTER_ID,
    GENESIS_TOKEN_CANISTER_ID, GOVERNANCE_CANISTER_ID, LEDGER_CANISTER_ID, LIFELINE_CANISTER_ID,
    NODE_REWARDS_CANISTER_ID, REGISTRY_CANISTER_ID, ROOT_CANISTER_ID, SNS_WASM_CANISTER_ID,
};
use reqwest::Client;
use serde::Deserialize;
use std::env;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};

pub const NNS_CANISTER_NAME_TO_ID: [(&str, CanisterId); 10] = [
    ("registry", REGISTRY_CANISTER_ID),
    ("governance", GOVERNANCE_CANISTER_ID),
    ("ledger", LEDGER_CANISTER_ID),
    ("root", ROOT_CANISTER_ID),
    ("lifeline", LIFELINE_CANISTER_ID),
    ("genesis-token", GENESIS_TOKEN_CANISTER_ID),
    ("cycles-minting", CYCLES_MINTING_CANISTER_ID),
    ("sns-wasm", SNS_WASM_CANISTER_ID),
    ("node-rewards", NODE_REWARDS_CANISTER_ID),
    ("cycles_ledger_index", CYCLES_LEDGER_INDEX_CANISTER_ID),
];

struct ExternalCanisterInfo<'a> {
    repository: &'a str,
    canister_id: CanisterId,
    filename: &'a str,
}

const EXTERNAL_CANISTER_NAME_TO_INFO: [(&str, ExternalCanisterInfo); 1] = [(
    "cycles_ledger",
    ExternalCanisterInfo {
        repository: "dfinity/cycles-ledger",
        filename: "cycles-ledger.wasm.gz",
        canister_id: CYCLES_LEDGER_CANISTER_ID,
    },
)];

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

/// This function fetches the given canister's module hash deployed on the ICP mainnet (based on `canister_id`)
/// and then finds a git tag in the given `canister_repository` (e.g., `dfinity/cycles-ledger`)
/// which contains a release asset whose name matches `canister_name`
/// and whose sha256 hash matches the module hash deployed on the ICP mainnet
/// (the sha256 hash is fetched from a dedicated release asset whose name has the form `{canister_name}.sha256`).
/// To find the git tag, the function proceeds as follows:
///   - it crawls all git tags of the given `canister_repository`;
///   - for every git tag, it lists all release assets and looks for a release asset whose name has the form `{canister_name}.sha256`:
///     if that release asset contains the expected module hash (as deployed on the ICP mainnet),
///     then the corresponding tag is returned.
async fn get_mainnet_canister_git_tag_and_module_hash(
    agent: &Agent,
    canister_id: CanisterId,
    canister_repository: String,
    canister_name: String,
) -> Result<(String, String)> {
    use std::fmt::Write;

    #[derive(Debug, Deserialize)]
    struct Tag {
        name: String,
    }

    #[derive(Debug, Deserialize)]
    struct ReleaseAsset {
        name: String,
        browser_download_url: String,
    }

    #[derive(Debug, Deserialize)]
    struct Release {
        tag_name: String,
        assets: Vec<ReleaseAsset>,
    }

    const GITHUB_API: &str = "https://api.github.com";

    let canister_id = canister_id.get().0;

    let module_hash = agent
        .read_state_canister_info(canister_id, "module_hash")
        .await?;
    let module_hash = module_hash.iter().fold(String::new(), |mut output, x| {
        let _ = write!(output, "{:02x}", x);
        output
    });

    let token = std::env::var("GITHUB_TOKEN").expect("Set GITHUB_TOKEN env var");

    // GitHub API requires all requests to provide a user-agent header
    // so we fix an arbitrary value of this header here.
    let client = Client::builder()
        .user_agent("sync-with-released-nervous-system-wasms")
        .build()?;

    let tags_url = format!("{}/repos/{}/tags", GITHUB_API, canister_repository);
    let tags: Vec<Tag> = client
        .get(&tags_url)
        .bearer_auth(&token)
        .send()
        .await?
        .json()
        .await?;

    for tag in tags {
        let check_tag = async {
            let release_url = format!(
                "{}/repos/{}/releases/tags/{}",
                GITHUB_API, canister_repository, tag.name
            );
            let res = client.get(&release_url).bearer_auth(&token).send().await?;

            // not every tag must have a release so we do not report an error if it does not
            if res.status().is_success() {
                let release: Release = res.json().await?;

                if release.tag_name != tag.name {
                    return Err(anyhow!(
                        "Unexpected release tag {}, expected {}",
                        release.tag_name,
                        tag.name
                    ));
                }

                let canister_sha256_name = format!("{canister_name}.sha256");
                let canister_sha256_url = release
                    .assets
                    .iter()
                    .find(|asset| asset.name == canister_sha256_name)
                    .map(|asset| asset.browser_download_url.clone());
                if let Some(canister_sha256_url) = canister_sha256_url {
                    let canister_sha256 = client
                        .get(canister_sha256_url)
                        .bearer_auth(&token)
                        .send()
                        .await?
                        .text()
                        .await?;
                    if module_hash.len() != 64 {
                        return Err(anyhow!(
                            "Unexpected sha256 length {}",
                            canister_sha256.len()
                        ));
                    }
                    // The asset `{canister_name}.sha256` has the form:
                    // `a2a0c65a94559aed373801a149bf4a31b176cb8cbabf77465eb25143ae880f37  cycles-ledger.wasm.gz`
                    // so we check if it starts with the expected module hash
                    // (having checked its length before to avoid trivial matches if the expected module hash was empty due to a bug).
                    if canister_sha256.starts_with(&module_hash) {
                        return Ok(true);
                    }
                }
            }

            Ok(false)
        };

        match check_tag.await {
            Ok(true) => return Ok((tag.name, module_hash)),
            Ok(false) => (),
            Err(e) => eprintln!(
                "Error while checking the GitHub tag {} for canister {}: {}",
                tag.name, canister_name, e
            ),
        }
    }

    Err(anyhow::anyhow!(
        "Did not find GitHub tag for canister {}",
        canister_name
    ))
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
                new_git_ref: GitRef::Rev(new_git_hash),
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
                    new_git_ref: GitRef::Rev(new_git_hash),
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

    let external_canister_updates = stream::iter(EXTERNAL_CANISTER_NAME_TO_INFO.iter())
        .then(|(canister_name, canister_info)| async {
            let canister_name = canister_name.to_string();
            let canister_repository = canister_info.repository.to_string();
            let canister_filename = canister_info.filename.to_string();
            let (new_tag, new_sha256) = get_mainnet_canister_git_tag_and_module_hash(
                &agent,
                canister_info.canister_id,
                canister_repository.clone(),
                canister_filename.clone(),
            )
            .await?;
            Ok(CanisterUpdate {
                canister_name,
                new_git_ref: GitRef::Tag(new_tag),
                new_sha256,
            })
        })
        .collect::<Vec<Result<CanisterUpdate>>>()
        .await
        .into_iter()
        .collect::<Result<Vec<CanisterUpdate>>>()?;

    canister_updates.extend(external_canister_updates);

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
enum GitRef {
    Rev(String),
    Tag(String),
}

#[derive(Clone, Debug)]
struct CanisterUpdate {
    canister_name: String,
    new_git_ref: GitRef,
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
        let sha256 = serde_json::Value::String(canister.new_sha256.clone());
        let mut entry = serde_json::Map::new();
        match &canister.new_git_ref {
            GitRef::Rev(new_git_hash) => {
                let rev = serde_json::Value::String(new_git_hash.clone());
                let _ = entry.insert("rev".to_string(), rev);
            }
            GitRef::Tag(new_git_tag) => {
                let tag = serde_json::Value::String(new_git_tag.clone());
                let _ = entry.insert("tag".to_string(), tag);
            }
        }
        let _ = entry.insert("sha256".to_string(), sha256);
        let entry = serde_json::Value::Object(entry);
        let _prev = m.insert(canister.canister_name.clone(), entry);
    }

    // Write the new content back to the file
    let file = File::create(canisters_json)?;
    serde_json::to_writer_pretty(file, &m).unwrap();

    Ok(())
}
