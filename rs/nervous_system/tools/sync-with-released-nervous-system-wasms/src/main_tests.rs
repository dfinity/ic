use super::*;
use std::cell::Cell;
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
