use candid::Principal;
use std::path::Path;
use std::process::{Child, Command};
use std::str::FromStr;
use tokio::time::{sleep, Duration};
use url::Url;

pub mod rosetta_client;

use rosetta_client::RosettaClient;

struct KillOnDrop(Child);

pub struct RosettaContext {
    _proc: KillOnDrop,
    _state: tempfile::TempDir,
    pub port: u16,
}

impl RosettaContext {
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

pub async fn start_rosetta(
    rosetta_bin: &Path,
    rosetta_log_config_file: &Path,
    ic_url: Url,
    ledger_canister_id: Principal,
) -> (RosettaClient, RosettaContext) {
    assert!(
        rosetta_bin.exists(),
        "ic-rosetta-api path {} does not exist",
        rosetta_bin.display()
    );

    let state = tempfile::TempDir::new().expect("failed to create a temporary directory");
    let port_file = state.path().join("port");
    let store_location = state.path().join("data");

    let _proc = KillOnDrop(
        Command::new(rosetta_bin)
            .arg("--log-config-file")
            .arg(rosetta_log_config_file)
            .arg("--ic-url")
            .arg(ic_url.to_string())
            .arg("--canister-id")
            .arg(ledger_canister_id.to_string())
            .arg("--port-file")
            .arg(port_file.clone())
            .arg("--store-location")
            .arg(store_location.clone())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .unwrap_or_else(|e| {
                panic!(
                    "Failed to execute ic-rosetta-api (path = {}, exists? = {}): {}",
                    rosetta_bin.display(),
                    rosetta_bin.exists(),
                    e
                )
            }),
    );

    let mut tries_left = 100;
    while tries_left > 0 && !port_file.exists() {
        sleep(Duration::from_millis(100)).await;
        tries_left -= 1;
    }

    let port = std::fs::read_to_string(port_file).expect("Expected port in port file");
    let port = u16::from_str(&port).expect("Expected port in port file");

    let rosetta_client = RosettaClient {
        url: Url::parse(&format!("http://localhost:{}", port)).unwrap(),
    };

    let _network = match rosetta_client.network_list().await {
        Ok(network) => network,
        Err(e) => panic!("Unable to get the network_list from rosetta: {}", e),
    };

    let context = RosettaContext {
        _proc,
        _state: state,
        port,
    };

    (rosetta_client, context)
}
