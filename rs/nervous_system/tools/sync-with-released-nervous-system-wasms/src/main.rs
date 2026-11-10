use anyhow::{Context, Result, anyhow};
use futures::{StreamExt, stream};
use ic_agent::Agent;
use ic_base_types::CanisterId;
use ic_nervous_system_agent::nns::sns_wasm;
use ic_nervous_system_string::clamp_string_len;
use ic_nns_constants::{
    BITCOIN_TESTNET_CANISTER_ID, CYCLES_LEDGER_CANISTER_ID, CYCLES_LEDGER_INDEX_CANISTER_ID,
    CYCLES_MINTING_CANISTER_ID, DOGECOIN_CANISTER_ID, ENGINE_CONTROLLER_CANISTER_ID,
    GENESIS_TOKEN_CANISTER_ID, GOVERNANCE_CANISTER_ID, IDENTITY_CANISTER_ID,
    INTERNET_IDENTITY_FRONTEND_CANISTER_ID, LEDGER_CANISTER_ID, LIFELINE_CANISTER_ID,
    MIGRATION_CANISTER_ID, NNS_UI_CANISTER_ID, NODE_REWARDS_CANISTER_ID, REGISTRY_CANISTER_ID,
    ROOT_CANISTER_ID, SNS_AGGREGATOR_CANISTER_ID, SNS_WASM_CANISTER_ID, SUBNET_RENTAL_CANISTER_ID,
};
use reqwest::Client;
use serde::Deserialize;
use sha2::Digest;
use std::env;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};

pub const NNS_CANISTER_NAME_TO_ID: [(&str, CanisterId); 13] = [
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
    ("cycles_ledger_index", CYCLES_LEDGER_INDEX_CANISTER_ID),
    ("migration", MIGRATION_CANISTER_ID),
    ("engine-controller", ENGINE_CONTROLLER_CANISTER_ID),
];

struct ExternalCanisterInfo<'a> {
    repository: &'a str,
    tag_name_prefix: Option<&'a str>,
    canister_id: CanisterId,
    filename: &'a str,
    test_filename: Option<&'a str>,
}

const EXTERNAL_CANISTER_NAME_TO_INFO: [(&str, ExternalCanisterInfo); 8] = [
    (
        "cycles_ledger",
        ExternalCanisterInfo {
            repository: "dfinity/cycles-ledger",
            tag_name_prefix: None,
            filename: "cycles-ledger.wasm.gz",
            test_filename: None,
            canister_id: CYCLES_LEDGER_CANISTER_ID,
        },
    ),
    (
        "internet_identity_backend",
        ExternalCanisterInfo {
            repository: "dfinity/internet-identity",
            tag_name_prefix: None,
            filename: "internet_identity_production.wasm.gz",
            test_filename: None,
            canister_id: IDENTITY_CANISTER_ID,
        },
    ),
    (
        "internet_identity_frontend",
        ExternalCanisterInfo {
            repository: "dfinity/internet-identity",
            tag_name_prefix: None,
            filename: "internet_identity_frontend.wasm.gz",
            test_filename: None,
            canister_id: INTERNET_IDENTITY_FRONTEND_CANISTER_ID,
        },
    ),
    (
        "nns_dapp_test",
        ExternalCanisterInfo {
            repository: "dfinity/nns-dapp",
            tag_name_prefix: Some("proposal-"),
            filename: "nns-dapp_production.wasm.gz",
            test_filename: Some("nns-dapp_test.wasm.gz"),
            canister_id: NNS_UI_CANISTER_ID,
        },
    ),
    (
        "sns_aggregator_test",
        ExternalCanisterInfo {
            repository: "dfinity/nns-dapp",
            tag_name_prefix: Some("proposal-"),
            filename: "sns_aggregator.wasm.gz",
            test_filename: Some("sns_aggregator_dev.wasm.gz"),
            canister_id: SNS_AGGREGATOR_CANISTER_ID,
        },
    ),
    (
        "bitcoin_testnet",
        ExternalCanisterInfo {
            repository: "dfinity/bitcoin-canister",
            tag_name_prefix: Some("release/"),
            filename: "ic-btc-canister.wasm.gz",
            test_filename: None,
            canister_id: BITCOIN_TESTNET_CANISTER_ID,
        },
    ),
    (
        "dogecoin",
        ExternalCanisterInfo {
            repository: "dfinity/dogecoin-canister",
            tag_name_prefix: Some("release/"),
            filename: "ic-doge-canister.wasm.gz",
            test_filename: None,
            canister_id: DOGECOIN_CANISTER_ID,
        },
    ),
    (
        "subnet_rental",
        ExternalCanisterInfo {
            repository: "dfinity/subnet-rental-canister",
            tag_name_prefix: None,
            filename: "subnet_rental_canister.wasm.gz",
            test_filename: None,
            canister_id: SUBNET_RENTAL_CANISTER_ID,
        },
    ),
];

fn module_hash_hex(module_hash: Vec<u8>) -> String {
    use std::fmt::Write;

    module_hash.iter().fold(String::new(), |mut output, x| {
        let _ = write!(output, "{x:02x}");
        output
    })
}

async fn get_mainnet_canister_git_commit_id_and_module_hash(
    agent: &Agent,
    canister_name: &str,
    canister_id: CanisterId,
) -> Result<(String, String)> {
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

    Ok((git_commit_id, module_hash_hex(module_hash)))
}

const GITHUB_API: &str = "https://api.github.com";

fn github_api_client_and_token() -> Result<(Client, String)> {
    // GitHub API requires all requests to provide a user-agent header
    // so we fix an arbitrary value of this header here.
    let client = Client::builder()
        .user_agent("sync-with-released-nervous-system-wasms")
        .build()?;

    let token = std::env::var("GITHUB_TOKEN").expect("Set GITHUB_TOKEN env var");

    Ok((client, token))
}

// GitHub API types

#[derive(Debug, Deserialize)]
struct Tag {
    name: String,
}

impl Tag {
    /// Returns the release for this tag if a release exists and contains a release artifact (canister WASM)
    /// with a matching filename (`canister_filename`) and sha256 hash (`expected_module_hash_str`),
    /// see [`release_has_mainnet_asset`].
    /// The repository is passed separately (via `canister_repository`) because GitHub API does not include
    /// the repository in the tag and we do not want to parse it from URLs of the form
    /// `https://api.github.com/repos/dfinity/cycles-ledger/commits/93f5c0f5779e31673786c83aa50ff2bbf9650162`.
    async fn release_for_canister(
        &self,
        canister_repository: String,
        canister_filename: String,
        expected_module_hash_str: String,
    ) -> Result<Option<Release>> {
        let release_url = format!(
            "{}/repos/{}/releases/tags/{}",
            GITHUB_API, canister_repository, self.name
        );

        let (client, token) = github_api_client_and_token()?;
        let response = client.get(&release_url).bearer_auth(&token).send().await?;
        let Some(release) = release_from_lookup_response(response, &release_url).await? else {
            return Ok(None);
        };

        if release.tag_name != self.name {
            return Err(anyhow!(
                "Unexpected release tag {}, expected {}",
                release.tag_name,
                self.name
            ));
        }

        let is_mainnet_release = release_has_mainnet_asset(
            &release,
            &canister_filename,
            &expected_module_hash_str,
            &GitHubAssetFetcher,
        )
        .await?;
        if !is_mainnet_release {
            return Ok(None);
        }

        Ok(Some(release))
    }
}

/// Returns the release that the lookup of the release URL `url` answered with `response`, or `None`
/// if the tag has no release (404: not every tag has one). Any other failure is an error, so that
/// the caller cannot mistake it for a tag without a release and move on to a later tag.
async fn release_from_lookup_response(
    response: reqwest::Response,
    url: &str,
) -> Result<Option<Release>> {
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }

    let release = decode_json_response::<Release>(response, url).await?;
    Ok(Some(release))
}

/// Checks `tags` in order with `check_tag`, and returns the first release that it finds.
///
/// An error while checking a tag is returned rather than moving on to the next tag: moving on
/// could select a later tag in place of the genuine one.
async fn find_first_release(
    tags: &[&Tag],
    check_tag: impl AsyncFn(&Tag) -> Result<Option<Release>>,
) -> Result<Option<Release>> {
    for tag in tags {
        let release = check_tag(tag).await?;
        if release.is_some() {
            return Ok(release);
        }
    }
    Ok(None)
}

/// Returns whether `release` contains the asset `filename` and that asset's content has the
/// sha256 `expected_sha256`, i.e., the module hash of the canister on mainnet.
///
/// A release is only ever accepted after hashing the downloaded asset, which the module hash on
/// mainnet anchors. A `{filename}.sha256` asset is never consulted: it is text written by whoever
/// published the release, not a hash of anything. The `digest` that GitHub computes over the
/// stored asset is only used to skip non-matching releases without downloading them.
///
/// Note that this cannot stop a release publisher from getting a release of their own selected:
/// the production asset is public, so a new release can carry an identical copy of it next to any
/// other asset. Other assets of the selected release (e.g. the test variants pinned for
/// `nns_dapp_test` and `sns_aggregator_test`) are therefore not anchored by this check.
async fn release_has_mainnet_asset(
    release: &Release,
    filename: &str,
    expected_sha256: &str,
    asset_fetcher: &impl AssetFetcher,
) -> Result<bool> {
    let Some(asset) = release.asset(filename) else {
        return Ok(false);
    };

    let expected_digest = format!("sha256:{expected_sha256}");
    let is_other_build = asset
        .digest
        .as_ref()
        .is_some_and(|digest| *digest != expected_digest);

    if is_other_build {
        return Ok(false);
    }

    let asset_sha256 = asset_fetcher.fetch_sha256(&asset).await?;
    Ok(asset_sha256 == expected_sha256)
}

/// Downloads release assets. [`release_has_mainnet_asset`] takes one so that it can be tested
/// without GitHub.
trait AssetFetcher {
    /// Returns the hex sha256 of the content of `asset`.
    async fn fetch_sha256(&self, asset: &ReleaseAsset) -> Result<String>;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct GitHubAssetFetcher;

impl AssetFetcher for GitHubAssetFetcher {
    async fn fetch_sha256(&self, asset: &ReleaseAsset) -> Result<String> {
        asset.sha256().await
    }
}

#[derive(Clone, Debug, Deserialize)]
struct ReleaseAsset {
    name: String,
    browser_download_url: String,
    /// `sha256:<hex>` of the asset content, computed by GitHub. Absent for older assets.
    digest: Option<String>,
}

impl ReleaseAsset {
    // Returns the sha256 hash of the asset content.
    async fn sha256(&self) -> Result<String> {
        let response = fetch_github_url(&self.browser_download_url).await?;
        let asset_bytes = response.bytes().await?;

        Ok(module_hash_hex(sha2::Sha256::digest(&asset_bytes).to_vec()))
    }
}

#[derive(Debug, Deserialize)]
struct Release {
    tag_name: String,
    assets: Vec<ReleaseAsset>,
}

impl Release {
    // Finds and returns a release asset based on its filename
    // if the asset is part of the release.
    fn asset(&self, filename: &str) -> Option<ReleaseAsset> {
        self.assets
            .iter()
            .find(|asset| asset.name == *filename)
            .cloned()
    }
}

/// This function finds a release in the given `canister_repository` (e.g., `dfinity/cycles-ledger`)
/// which contains a release asset for the given canister with the expected sha256 hash.
/// To find the release, this function proceeds as follows:
///   - it crawls all git tags of the given `canister_repository`;
///   - git tags whose name does not start with an optionally provided tag name prefix are skipped;
///   - for every git tag, it checks if there is an associated release and then
///     looks for a release asset named `canister_filename`:
///     if the sha256 hash of that release asset's content matches `expected_module_hash_str`, then the corresponding release is returned
///     (see [`release_has_mainnet_asset`]).
///
/// An error while checking a tag is returned rather than skipping the tag, as skipping it could select a later tag.
async fn get_mainnet_canister_release(
    canister_name: String,
    canister_repository: String,
    canister_tag_name_prefix: Option<String>,
    canister_filename: String,
    expected_module_hash_str: String,
) -> Result<Release> {
    let tags_per_page = 30; // maximum allowed is 100, but let's save bandwidth since typically we should find the deployed canister WASM early
    let mut page = 1;
    loop {
        let tags_url = format!(
            "{GITHUB_API}/repos/{canister_repository}/tags?per_page={tags_per_page}&page={page}"
        );
        let response = fetch_github_url(&tags_url).await?;
        let tags: Vec<Tag> = decode_json_response(response, &tags_url).await?;

        let candidate_tags = tags
            .iter()
            .filter(|tag| {
                canister_tag_name_prefix
                    .as_ref()
                    .is_none_or(|tag_name_prefix| tag.name.starts_with(tag_name_prefix))
            })
            .collect::<Vec<&Tag>>();

        let release = find_first_release(&candidate_tags, async |tag: &Tag| {
            tag.release_for_canister(
                canister_repository.clone(),
                canister_filename.clone(),
                expected_module_hash_str.clone(),
            )
            .await
            .with_context(|| {
                format!(
                    "Error while checking the GitHub tag {} for canister {}",
                    tag.name, canister_name
                )
            })
        })
        .await?;

        if let Some(release) = release {
            return Ok(release);
        }

        // We reached the last page.
        if tags.len() < tags_per_page {
            break;
        }

        // Proceed with the next page.
        // That page migth be empty if the current page is already the last (full) page,
        // but this is fine with GitHub API.
        page += 1;
    }

    Err(anyhow::anyhow!(
        "Did not find a matching GitHub tag for canister {}",
        canister_name
    ))
}

/// This function fetches the given canister's module hash deployed on the ICP mainnet (based on `canister_id`)
/// and then finds a git tag in the given `canister_repository` (e.g., `dfinity/cycles-ledger`)
/// which contains a release asset with the given canister's module hash deployed on the ICP mainnet.
/// The git tag name starts with an optionally provided tag name prefix.
/// This function then returns the git tag and the canister's module hash.
/// If a test canister name is provided, then the returned module hash is that of the test canister in the release for the same git tag.
async fn get_mainnet_canister_git_tag_and_module_hash(
    agent: &Agent,
    canister_name: String,
    canister_id: CanisterId,
    canister_repository: String,
    canister_tag_name_prefix: Option<String>,
    canister_filename: String,
    canister_test_filename: Option<String>,
) -> Result<(String, String)> {
    let canister_id = canister_id.get().0;

    let prod_module_hash = agent
        .read_state_canister_info(canister_id, "module_hash")
        .await?;
    let prod_module_hash_str = module_hash_hex(prod_module_hash);

    if prod_module_hash_str.len() != 64 {
        return Err(anyhow!(
            "Unexpected sha256 length {}",
            prod_module_hash_str.len()
        ));
    }

    let release = get_mainnet_canister_release(
        canister_name.clone(),
        canister_repository.clone(),
        canister_tag_name_prefix.clone(),
        canister_filename.clone(),
        prod_module_hash_str.clone(),
    )
    .await?;

    let final_module_hash_str = if let Some(ref canister_test_filename) = canister_test_filename {
        let canister_test = release.asset(canister_test_filename).ok_or(anyhow!(
            "Did not find release asset {canister_test_filename}"
        ))?;
        canister_test.sha256().await?
    } else {
        prod_module_hash_str
    };

    Ok((release.tag_name, final_module_hash_str))
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
            let canister_tag_name_prefix = canister_info
                .tag_name_prefix
                .map(|tag_name_prefix| tag_name_prefix.to_string());
            let canister_filename = canister_info.filename.to_string();
            let canister_test_filename = canister_info
                .test_filename
                .map(|test_filename| test_filename.to_string());
            let (new_tag, new_sha256) = get_mainnet_canister_git_tag_and_module_hash(
                &agent,
                canister_name.clone(),
                canister_info.canister_id,
                canister_repository.clone(),
                canister_tag_name_prefix.clone(),
                canister_filename.clone(),
                canister_test_filename.clone(),
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

// Shared request plumbing and diagnostic-only helpers below. `convert_response_to_result` and
// `decode_json_response` provide more diagnostics than the Reqwest library when there is a
// failure.

/// Maximum number of response-body bytes to include in an error/log message. The GitHub API can
/// return large HTML error pages (e.g., during an outage); truncating keeps logs readable while
/// still showing enough of the body to diagnose the failure.
const MAX_LOGGED_BODY_LEN: usize = 2000;

/// Diagnostic-only: returns `response` unchanged if its status is a success. Otherwise, reads the
/// body and returns an error containing the status and the (possibly truncated) response body.
///
/// `url` is not used unless `response`'s status is not success; it is only there to add to the
/// diagnostics in that case.
async fn convert_response_to_result(
    response: reqwest::Response,
    url: &str,
) -> Result<reqwest::Response> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }

    let body = response
        .text()
        .await
        .unwrap_or_else(|e| format!("<failed to read response body: {e}>"));
    Err(anyhow!(
        "GET {url} failed with status {status}. Response body: {}",
        clamp_string_len(&body, MAX_LOGGED_BODY_LEN)
    ))
}

/// Sends an authenticated GET request to `url` (a GitHub API or release-asset-download URL) and
/// returns the response after checking (via [`convert_response_to_result`]) that its status is a
/// success.
async fn fetch_github_url(url: &str) -> Result<reqwest::Response> {
    let (client, token) = github_api_client_and_token()?;
    let response = client.get(url).bearer_auth(&token).send().await?;
    convert_response_to_result(response, url).await
}

/// Diagnostic-only: like [`reqwest::Response::json`], but on failure (either a non-success
/// status, or a body that fails to decode as JSON), the returned error includes the status and
/// the (possibly abridged) response body.
///
/// `url` is not used unless decoding fails; it is only there to add to the diagnostics in that
/// case.
async fn decode_json_response<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
    url: &str,
) -> Result<T> {
    let response = convert_response_to_result(response, url).await?;
    let body = response
        .text()
        .await
        .unwrap_or_else(|e| format!("<failed to read response body: {e}>"));

    serde_json::from_str(&body).map_err(|e| {
        anyhow!(
            "GET {url} returned a success status, but the response body failed to decode as \
             JSON: {e}. Response body: {}",
            clamp_string_len(&body, MAX_LOGGED_BODY_LEN)
        )
    })
}

#[cfg(test)]
#[path = "main_tests.rs"]
mod tests;
