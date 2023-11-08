use candid::Principal;
use std::default::Default;
use std::path::Path;
use std::process::{Child, Command};
use std::str::FromStr;

use tokio::time::{sleep, Duration};

pub const DEFAULT_DECIMAL_PLACES: u8 = 8;
pub const DEFAULT_TOKEN_SYMBOL: &str = "XTST";

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

pub struct RosettaOptions {
    pub ledger_id: Principal,

    pub store_type: String,

    pub network_type: String,

    pub network_url: Option<String>,

    pub exit_on_sync: bool,

    pub offline: bool,

    pub symbol: Option<String>,

    pub decimals: Option<u32>,
}

impl Default for RosettaOptions {
    fn default() -> Self {
        RosettaOptions {
            ledger_id: Principal::anonymous(),
            store_type: "in-memory".to_owned(),
            network_type: "testnet".to_owned(),
            network_url: None,
            exit_on_sync: false,
            offline: true,
            symbol: Some(DEFAULT_TOKEN_SYMBOL.to_string()),
            decimals: Some(DEFAULT_DECIMAL_PLACES.into()),
        }
    }
}

pub async fn start_rosetta(rosetta_bin: &Path, arguments: RosettaOptions) -> RosettaContext {
    assert!(
        rosetta_bin.exists(),
        "ic-icrc-rosetta-bin path {} does not exist",
        rosetta_bin.display()
    );

    let state = tempfile::TempDir::new().expect("failed to create a temporary directory");
    let port_file = state.path().join("port");

    let mut command = &mut Command::new(rosetta_bin);
    command = command
        .arg("--ledger-id")
        .arg(arguments.ledger_id.to_string())
        .arg("--network-type")
        .arg(arguments.network_type)
        .arg("--store-type")
        .arg(arguments.store_type)
        .arg("--port-file")
        .arg(port_file.clone())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());

    if arguments.network_url.is_some() {
        command = command
            .arg("--network-url")
            .arg(arguments.network_url.unwrap());
    }

    if arguments.offline {
        command = command.arg("--offline");
    }

    if let Some(symbol) = arguments.symbol {
        command = command.arg("--icrc1-symbol").arg(symbol);
    }

    if let Some(decimals) = arguments.decimals {
        command = command.arg("--icrc1-decimals").arg(decimals.to_string());
    }

    if arguments.exit_on_sync {
        command = command.arg("--exit-on-sync");
    }

    let _proc = KillOnDrop(command.spawn().unwrap_or_else(|e| {
        panic!(
            "Failed to execute ic-icrc-rosetta-bin (path = {}, exists? = {}): {}",
            rosetta_bin.display(),
            rosetta_bin.exists(),
            e
        )
    }));

    let mut tries_left = 100;
    while tries_left > 0 && !port_file.exists() {
        sleep(Duration::from_millis(100)).await;
        tries_left -= 1;
    }

    let port = std::fs::read_to_string(port_file).expect("Expected port in port file");
    let port = u16::from_str(&port)
        .unwrap_or_else(|e| panic!("Expected port in port file, got {}: {}", port, e));

    RosettaContext {
        _proc,
        _state: state,
        port,
    }
}
