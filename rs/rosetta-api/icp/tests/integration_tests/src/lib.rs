use candid::Principal;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::str::FromStr;
use tempfile::TempDir;
use tokio::time::{Duration, sleep};
use url::Url;

use ic_icrc_rosetta_client::RosettaClient;

const NUM_TRIES: u64 = 1000;
const WAIT_BETWEEN_ATTEMPTS: Duration = Duration::from_millis(100);

struct KillOnDrop(Child);

pub struct RosettaContext {
    _proc: KillOnDrop,
    _tempdir: Option<TempDir>,
    pub state_directory: PathBuf,
    pub port: u16,
}

impl RosettaContext {
    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn kill(self) {
        drop(self._proc);
    }
}

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        match self.0.kill() {
            Ok(_) => println!("Rosetta has been successfully stopped"),
            Err(err) => println!("Rosetta was NOT sucessfully stopped: {err:?}"),
        }
    }
}

pub async fn start_rosetta(
    rosetta_bin: &Path,
    ic_url: Url,
    ledger_canister_id: Principal,
    state_directory: Option<PathBuf>,
    enable_rosetta_blocks: bool,
    persistent_storage: bool,
) -> (RosettaClient, RosettaContext) {
    assert!(
        rosetta_bin.exists(),
        "ic-rosetta-api path {} does not exist",
        rosetta_bin.display()
    );

    let (state_directory, _tempdir) = state_directory.map_or_else(
        || {
            let tempdir = tempfile::TempDir::new().expect("failed to create a temporary directory");
            let state_directory = tempdir.path().to_owned();
            (state_directory, Some(tempdir))
        },
        |state_dir| (state_dir, None),
    );
    let port_file = state_directory.join("port");
    if port_file.exists()
        && let Err(e) = std::fs::remove_file(port_file.clone())
        && e.kind() != std::io::ErrorKind::NotFound
    {
        panic!("Unable to remove port file: {e:?}");
    }
    let mut cmd = Command::new(rosetta_bin);
    cmd.arg("--ic-url")
        .arg(ic_url.to_string())
        .arg("--canister-id")
        .arg(ledger_canister_id.to_string())
        .arg("--port-file")
        .arg(port_file.clone());

    if persistent_storage {
        let store_location = state_directory.join("data");
        cmd.arg("--store-location").arg(store_location);
    } else {
        cmd.arg("--store-type").arg("sqlite-in-memory");
    }

    if enable_rosetta_blocks {
        cmd.arg("--enable-rosetta-blocks");
    }

    let _proc = KillOnDrop(cmd.spawn().unwrap_or_else(|e| {
        panic!(
            "Failed to execute ic-rosetta-api (path = {}, exists? = {}): {}",
            rosetta_bin.display(),
            rosetta_bin.exists(),
            e
        )
    }));

    let mut tries_left = NUM_TRIES;
    while tries_left > 0 && !port_file.exists() {
        sleep(WAIT_BETWEEN_ATTEMPTS).await;
        tries_left -= 1;
    }

    let port = std::fs::read_to_string(port_file).expect("Expected port in port file");
    let port = u16::from_str(&port).expect("Expected port in port file");

    let rosetta_client = RosettaClient::from_str_url(&format!("http://localhost:{port}"))
        .expect("Unable to create the RosettaClient");

    // wait because rosetta may be recovering from existing state
    let mut tries_left = NUM_TRIES;
    while tries_left > 0 && rosetta_client.network_list().await.is_err() {
        sleep(WAIT_BETWEEN_ATTEMPTS).await;
        tries_left -= 1;
    }

    if let Err(e) = rosetta_client.network_list().await {
        panic!("Unable to get the network_list from rosetta: {e:?}");
    };

    let context = RosettaContext {
        _proc,
        _tempdir,
        state_directory,
        port,
    };

    (rosetta_client, context)
}
