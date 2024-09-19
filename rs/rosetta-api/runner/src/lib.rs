pub mod constants;
use crate::constants::{NUM_TRIES, WAIT_BETWEEN_ATTEMPTS};
use candid::Principal;
use std::path::Path;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::str::FromStr;
use tempfile::TempDir;
use tokio::time::sleep;

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

pub struct RosettaOptions {
    pub ledger_id: Option<Principal>,

    pub store_type: String,

    pub ic_url: String,

    pub offline: bool
}

impl RosettaOptions {
    pub fn builder(ic_url: String) -> RosettaOptionsBuilder {
        RosettaOptionsBuilder::new(ic_url)
    }
}

pub struct RosettaOptionsBuilder {
    ledger_id: Option<Principal>,
    persistent_storage: bool,
    ic_url: String,
    offline: bool,
}

impl RosettaOptionsBuilder {
    pub fn new(ic_url: String) -> Self {
        RosettaOptionsBuilder {
            ledger_id: None,
            persistent_storage: false,
            ic_url,
            offline:false
        }
    }

    pub fn with_ledger_id(mut self, ledger_id: Principal) -> Self {
        self.ledger_id = Some(ledger_id);
        self
    }

    pub fn with_persistent_storage(mut self) -> Self {
        self.persistent_storage = true;
        self
    }

    pub fn offline(mut self) -> Self {
        self.offline = true;
        self
    }

    pub fn build(self) -> RosettaOptions {
        RosettaOptions {
            ledger_id: self.ledger_id,
            store_type: if self.persistent_storage {
                "sqlite".to_string()
            } else {
                "sqlite-in-memory".to_string()
            },
            ic_url: self.ic_url,
            offline: self.offline
        }
    }
}

pub async fn start_rosetta(
    rosetta_bin: &Path,
    state_directory: Option<PathBuf>,
    arguments: RosettaOptions,
) -> RosettaContext {
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
    if port_file.exists() {
        if let Err(e) = std::fs::remove_file(port_file.clone()) {
            if e.kind() != std::io::ErrorKind::NotFound {
                panic!("Unable to remove port file: {:?}", e);
            }
        }
    }

    let mut cmd = Command::new(rosetta_bin);
    cmd.arg("--ic-url")
        .arg(&arguments.ic_url)
        .arg("--port-file")
        .arg(port_file.clone())
        .arg("--store-type")
        .arg(arguments.store_type);

    if arguments.ledger_id.is_some() {
        cmd.arg("--canister-id")
            .arg(arguments.ledger_id.unwrap().to_string());
    }

    if arguments.offline {
        cmd.arg("--offline");
    }

    let _proc = KillOnDrop(cmd.spawn().unwrap_or_else(|e| {
        panic!(
            "Failed to execute ic-rosetta-api (path = {}, exists? = {}): {}",
            rosetta_bin.display(),
            rosetta_bin.exists(),
            e
        )
    }));

    while !port_file.exists() {
        sleep(WAIT_BETWEEN_ATTEMPTS).await;
    }

    let port = std::fs::read_to_string(port_file).expect("Expected port in port file");
    let port = u16::from_str(&port).expect("Expected port in port file");

    let http_client = reqwest::Client::new();
    // wait because rosetta may be recovering from existing state
    let mut tries_left = NUM_TRIES;
    loop {
        let res = http_client
            .post(format!("http://localhost:{}/network/list", port).as_str())
            .header("Content-Type", "application/json")
            .send()
            .await
            .expect("Failed to send request");
        if res.status().is_success() {
            break;
        }
        sleep(WAIT_BETWEEN_ATTEMPTS).await;
        tries_left -= 1;
        if tries_left == 0 {
            panic!("Failed to start Rosetta");
        }
    }

    RosettaContext {
        _proc,
        _tempdir,
        state_directory,
        port,
    }
}
