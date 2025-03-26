use ic_icrc_rosetta_client::RosettaClient;
use ic_icrc_rosetta_runner::start_rosetta;
use ic_icrc_rosetta_runner::RosettaOptions;
use pocket_ic::PocketIcBuilder;
use std::path::PathBuf;
use tokio::runtime::Runtime;

fn path_from_env(var: &str) -> PathBuf {
    std::fs::canonicalize(std::env::var(var).unwrap_or_else(|_| panic!("Unable to find {}", var)))
        .unwrap()
}

// only test_health is in here to check that the client works
// as intended. All the other tests are in the rosetta tests.
#[test]
fn test() {
    let rt = Runtime::new().unwrap();
    let mut pocket_ic = PocketIcBuilder::new().with_nns_subnet().build();
    let endpoint = pocket_ic.make_live(None);
    let port = endpoint.port().unwrap();
    let replica_url = format!("http://localhost:{}", port);
    let rosetta_bin = path_from_env("ROSETTA_BIN_PATH");

    // Wrap async calls in a blocking Block
    rt.block_on(async {
        let context = start_rosetta(
            &rosetta_bin,
            RosettaOptions {
                network_url: Some(replica_url),
                ..RosettaOptions::default()
            },
        )
        .await;
        let client = RosettaClient::from_str_url(&format!("http://0.0.0.0:{}", context.port))
            .expect("Unable to parse url");
        assert!(client.health().await.is_ok())
    });
}
