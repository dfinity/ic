use super::*;
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

/// The module hash of the canister on mainnet, and the hash of some other build.
const MAINNET_SHA256: &str = "74e07d7d70ac89e254cf51d4214ec71a38789f922a82305d550a7281e4b23fc1";
const OTHER_SHA256: &str = "485e17af1fb44a4b6290e903183fceb7be7ec2110a97ea87fc861492b348f72c";
const FILENAME: &str = "nns-dapp_production.wasm.gz";

/// Serves the sha256 of asset contents from a map from asset name to sha256, and counts the
/// downloads.
#[derive(Debug)]
struct FakeAssetFetcher {
    sha256_by_asset_name: BTreeMap<String, String>,
    download_count: Cell<usize>,
}

impl FakeAssetFetcher {
    fn new(sha256_by_asset_name: &[(&str, &str)]) -> Self {
        Self {
            sha256_by_asset_name: sha256_by_asset_name
                .iter()
                .map(|(name, sha256)| (name.to_string(), sha256.to_string()))
                .collect::<BTreeMap<String, String>>(),
            download_count: Cell::new(0),
        }
    }
}

impl AssetFetcher for FakeAssetFetcher {
    async fn fetch_sha256(&self, asset: &ReleaseAsset) -> Result<String> {
        self.download_count.set(self.download_count.get() + 1);

        self.sha256_by_asset_name
            .get(&asset.name)
            .cloned()
            .ok_or_else(|| anyhow!("Download of {} failed", asset.name))
    }
}

/// Returns a release with the given assets, each given by its name and the digest that GitHub
/// reports for it (if any).
fn new_release(assets: &[(&str, Option<&str>)]) -> Release {
    Release {
        tag_name: "proposal-143823".to_string(),
        assets: assets
            .iter()
            .map(|(name, digest_sha256)| ReleaseAsset {
                name: name.to_string(),
                browser_download_url: format!("https://example.com/{name}"),
                digest: digest_sha256.map(|sha256| format!("sha256:{sha256}")),
            })
            .collect::<Vec<ReleaseAsset>>(),
    }
}

#[tokio::test]
async fn test_release_with_matching_asset_is_mainnet_release() {
    // Step 1: Prepare the world. Older assets have no digest.
    let release = new_release(&[(FILENAME, None)]);
    let asset_fetcher = FakeAssetFetcher::new(&[(FILENAME, MAINNET_SHA256)]);

    // Step 2: Run the code under test.
    let result =
        release_has_mainnet_asset(&release, FILENAME, MAINNET_SHA256, &asset_fetcher).await;

    // Step 3: Verify result(s).
    assert!(result.unwrap());
    assert_eq!(asset_fetcher.download_count.get(), 1);
}

#[tokio::test]
async fn test_matching_digest_is_confirmed_by_download() {
    // Step 1: Prepare the world.
    let release = new_release(&[(FILENAME, Some(MAINNET_SHA256))]);
    let asset_fetcher = FakeAssetFetcher::new(&[(FILENAME, MAINNET_SHA256)]);

    // Step 2: Run the code under test.
    let result =
        release_has_mainnet_asset(&release, FILENAME, MAINNET_SHA256, &asset_fetcher).await;

    // Step 3: Verify result(s).
    assert!(result.unwrap());
    assert_eq!(asset_fetcher.download_count.get(), 1);
}

#[tokio::test]
async fn test_release_with_other_digest_is_skipped_without_download() {
    // Step 1: Prepare the world.
    let release = new_release(&[(FILENAME, Some(OTHER_SHA256))]);
    let asset_fetcher = FakeAssetFetcher::new(&[(FILENAME, OTHER_SHA256)]);

    // Step 2: Run the code under test.
    let result =
        release_has_mainnet_asset(&release, FILENAME, MAINNET_SHA256, &asset_fetcher).await;

    // Step 3: Verify result(s).
    assert!(!result.unwrap());
    assert_eq!(asset_fetcher.download_count.get(), 0);
}

#[tokio::test]
async fn test_download_not_matching_its_digest_is_rejected() {
    // Step 1: Prepare the world. The digest claims a match that the downloaded content does not
    // have.
    let release = new_release(&[(FILENAME, Some(MAINNET_SHA256))]);
    let asset_fetcher = FakeAssetFetcher::new(&[(FILENAME, OTHER_SHA256)]);

    // Step 2: Run the code under test.
    let result =
        release_has_mainnet_asset(&release, FILENAME, MAINNET_SHA256, &asset_fetcher).await;

    // Step 3: Verify result(s).
    assert!(!result.unwrap());
}

#[tokio::test]
async fn test_release_without_asset_is_not_mainnet_release() {
    // Step 1: Prepare the world.
    let release = new_release(&[("nns-dapp_test.wasm.gz", None)]);
    let asset_fetcher = FakeAssetFetcher::new(&[("nns-dapp_test.wasm.gz", MAINNET_SHA256)]);

    // Step 2: Run the code under test.
    let result =
        release_has_mainnet_asset(&release, FILENAME, MAINNET_SHA256, &asset_fetcher).await;

    // Step 3: Verify result(s).
    assert!(!result.unwrap());
    assert_eq!(asset_fetcher.download_count.get(), 0);
}

#[tokio::test]
async fn test_sha256_asset_claiming_a_match_is_ignored() {
    // Step 1: Prepare the world. The `.sha256` asset names the mainnet hash, but the asset
    // itself is a different build. The fake cannot serve the `.sha256` asset, so fetching it
    // would fail the test.
    let release = new_release(&[(FILENAME, None), (&format!("{FILENAME}.sha256"), None)]);
    let asset_fetcher = FakeAssetFetcher::new(&[(FILENAME, OTHER_SHA256)]);

    // Step 2: Run the code under test.
    let result =
        release_has_mainnet_asset(&release, FILENAME, MAINNET_SHA256, &asset_fetcher).await;

    // Step 3: Verify result(s).
    assert!(!result.unwrap());
    assert_eq!(asset_fetcher.download_count.get(), 1);
}

#[tokio::test]
async fn test_sha256_asset_denying_a_match_is_ignored() {
    // Step 1: Prepare the world. Whatever a `.sha256` asset says, it cannot make the genuine
    // release be skipped.
    let release = new_release(&[(FILENAME, None), (&format!("{FILENAME}.sha256"), None)]);
    let asset_fetcher = FakeAssetFetcher::new(&[(FILENAME, MAINNET_SHA256)]);

    // Step 2: Run the code under test.
    let result =
        release_has_mainnet_asset(&release, FILENAME, MAINNET_SHA256, &asset_fetcher).await;

    // Step 3: Verify result(s).
    assert!(result.unwrap());
}

#[tokio::test]
async fn test_download_failure_is_an_error() {
    // Step 1: Prepare the world. The download fails, which must not be mistaken for a release
    // that does not match.
    let release = new_release(&[(FILENAME, None)]);
    let asset_fetcher = FakeAssetFetcher::new(&[]);

    // Step 2: Run the code under test.
    let result =
        release_has_mainnet_asset(&release, FILENAME, MAINNET_SHA256, &asset_fetcher).await;

    // Step 3: Verify result(s).
    let error = result.unwrap_err();
    assert!(error.to_string().contains("Download of"), "{error:#}");
}

/// Returns the response of a release lookup that answered `status` with `body`.
fn new_lookup_response(status: u16, body: &str) -> reqwest::Response {
    let response = http::Response::builder()
        .status(status)
        .body(body.to_string())
        .unwrap();

    reqwest::Response::from(response)
}

const RELEASE_URL: &str = "https://api.github.com/repos/dfinity/nns-dapp/releases/tags/t";

#[tokio::test]
async fn test_release_lookup_404_means_tag_without_release() {
    // Step 1: Prepare the world.
    let response = new_lookup_response(404, r#"{"message": "Not Found"}"#);

    // Step 2: Run the code under test.
    let result = release_from_lookup_response(response, RELEASE_URL).await;

    // Step 3: Verify result(s).
    assert!(result.unwrap().is_none());
}

#[tokio::test]
async fn test_release_lookup_failure_is_an_error() {
    // Step 1: Prepare the world. E.g. GitHub having an outage, or rate limiting.
    for status in [403, 500, 503] {
        let response = new_lookup_response(status, "oops");

        // Step 2: Run the code under test.
        let result = release_from_lookup_response(response, RELEASE_URL).await;

        // Step 3: Verify result(s).
        let error = result.unwrap_err();
        let is_status_reported = error.to_string().contains(&status.to_string());
        assert!(is_status_reported, "{error:#}");
    }
}

#[tokio::test]
async fn test_release_lookup_returns_release() {
    // Step 1: Prepare the world.
    let response = new_lookup_response(200, r#"{"tag_name": "t", "assets": []}"#);

    // Step 2: Run the code under test.
    let result = release_from_lookup_response(response, RELEASE_URL).await;

    // Step 3: Verify result(s).
    let release = result.unwrap().unwrap();
    assert_eq!(release.tag_name, "t");
}

fn new_tags(names: &[&str]) -> Vec<Tag> {
    names
        .iter()
        .map(|name| Tag {
            name: name.to_string(),
        })
        .collect::<Vec<Tag>>()
}

#[tokio::test]
async fn test_error_checking_a_tag_fails_the_scan() {
    // Step 1: Prepare the world. Looking up the release of the first tag fails, and a later
    // tag would match.
    let tags = new_tags(&["genuine", "later"]);
    let tag_refs = tags.iter().collect::<Vec<&Tag>>();
    let checked_tag_names = RefCell::new(Vec::<String>::new());
    let check_tag = async |tag: &Tag| {
        checked_tag_names.borrow_mut().push(tag.name.clone());
        if tag.name == "genuine" {
            return Err(anyhow!("GET {RELEASE_URL} failed with status 500"));
        }
        Ok(Some(new_release(&[])))
    };

    // Step 2: Run the code under test.
    let result = find_first_release(&tag_refs, check_tag).await;

    // Step 3: Verify result(s). The later tag is never checked.
    let error = result.unwrap_err();
    assert!(error.to_string().contains("500"), "{error:#}");
    assert_eq!(checked_tag_names.into_inner(), vec!["genuine"]);
}

#[tokio::test]
async fn test_tag_without_release_continues_the_scan() {
    // Step 1: Prepare the world. The first tag has no release (its lookup answered 404).
    let tags = new_tags(&["no-release", "matching"]);
    let tag_refs = tags.iter().collect::<Vec<&Tag>>();
    let check_tag = async |tag: &Tag| {
        if tag.name == "no-release" {
            return Ok(None);
        }
        Ok(Some(new_release(&[])))
    };

    // Step 2: Run the code under test.
    let result = find_first_release(&tag_refs, check_tag).await;

    // Step 3: Verify result(s).
    assert!(result.unwrap().is_some());
}
