use candid::Nat;
use candid::Principal;
use icrc_ledger_types::icrc1::account::Account;
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

pub struct RosettaClientArgs {
    pub operation_type: String,
    pub to: Option<Account>,
    pub spender: Option<Account>,
    pub from_subaccount: Option<Vec<u8>>,
    pub amount: Option<Nat>,
    pub allowance: Option<Nat>,
    pub rosetta_url: String,
    pub expires_at: Option<u64>,
    pub expected_allowance: Option<Nat>,
    pub memo: Option<Vec<u8>>,
    pub created_at_time: Option<u64>,
}

pub async fn make_transaction_with_rosetta_client_binary(
    rosetta_client_bin: &std::path::Path,
    arguments: RosettaClientArgs,
    sender_keypair_pem: String,
) -> anyhow::Result<()> {
    assert!(
        rosetta_client_bin.exists(),
        "ic-icrc-rosetta-client-bin path {} does not exist",
        rosetta_client_bin.display()
    );

    let state = tempfile::TempDir::new().expect("failed to create a temporary directory");
    let mut pem_file = state.path().join("port");
    pem_file.set_file_name("sender_pem_file.pem");
    std::fs::write(&pem_file, sender_keypair_pem).expect("Failed to write pem file");

    let mut command = &mut Command::new(rosetta_client_bin);
    command = command
        .arg("--rosetta-url")
        .arg(arguments.rosetta_url)
        .arg("--sender-pem-file")
        .arg(pem_file)
        .arg(arguments.operation_type);

    if arguments.to.is_some() {
        command = command.arg("--to").arg(arguments.to.unwrap().to_string());
    }

    if arguments.spender.is_some() {
        command = command
            .arg("--spender")
            .arg(arguments.spender.unwrap().to_string());
    }

    if arguments.from_subaccount.is_some() {
        command = command.arg("--from-subaccount").arg(format!(
            "{}",
            String::from_utf8_lossy(arguments.from_subaccount.unwrap().as_slice())
        ));
    }

    if arguments.amount.is_some() {
        command = command
            .arg("--amount")
            .arg(arguments.amount.unwrap().to_string());
    }

    if arguments.allowance.is_some() {
        command = command
            .arg("--allowance")
            .arg(arguments.allowance.unwrap().to_string());
    }

    if arguments.expires_at.is_some() {
        command = command
            .arg("--expires-at")
            .arg(arguments.expires_at.unwrap().to_string());
    }

    if arguments.expected_allowance.is_some() {
        command = command
            .arg("--expected-allowance")
            .arg(arguments.expected_allowance.unwrap().to_string());
    }

    if arguments.memo.is_some() {
        command = command.arg("--memo").arg(format!(
            "{}",
            String::from_utf8_lossy(arguments.memo.unwrap().as_slice())
        ));
    }

    if arguments.created_at_time.is_some() {
        command = command
            .arg("--created_at_time")
            .arg(arguments.created_at_time.unwrap().to_string());
    }

    let child_process = command.output();
    match child_process {
        Ok(output) => {
            if output.status.success() {
                Ok(())
            } else {
                anyhow::bail!("Child process exited with: {:?}", output);
            }
        }
        Err(err) => {
            anyhow::bail!("Error waiting for child process: {}", err);
        }
    }
}
