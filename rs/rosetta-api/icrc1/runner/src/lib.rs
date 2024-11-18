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
        .stderr(std::process::Stdio::piped());

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
    let child_process = command.spawn().unwrap_or_else(|e| {
        panic!(
            "Failed to execute ic-icrc-rosetta-bin (path = {}, exists? = {}): {}",
            rosetta_bin.display(),
            rosetta_bin.exists(),
            e
        )
    });

    let mut tries_left = 600; // 600*100ms = 60s
    let mut maybe_port: Option<u16> = None;
    while tries_left > 0 {
        if port_file.exists() {
            let port_str = std::fs::read_to_string(&port_file).expect("Expected port in port file");
            match u16::from_str(&port_str) {
                Ok(p) => {
                    maybe_port = Some(p);
                    break;
                }
                Err(e) => {
                    println!("Expected port in port file, got {}: {}", port_str, e);
                }
            }
        }
        sleep(Duration::from_millis(100)).await;
        tries_left -= 1;
    }
    match maybe_port {
        None => {
            let output = child_process
                .wait_with_output()
                .expect("Failed to wait for child process");

            panic!("Failed to start rosetta: {:?}", output);
        }
        Some(port) => RosettaContext {
            _proc: KillOnDrop(child_process),
            _state: state,
            port,
        },
    }
}

pub struct RosettaClientArgs {
    pub operation_type: String,
    pub to_account: Option<Account>,
    pub spender_account: Option<Account>,
    pub from_account: Option<Account>,
    pub from_subaccount: Option<Vec<u8>>,
    pub spender_subaccount: Option<Vec<u8>>,
    pub amount: Option<Nat>,
    pub allowance: Option<Nat>,
    pub rosetta_url: String,
    pub expires_at: Option<u64>,
    pub expected_allowance: Option<Nat>,
    pub memo: Option<Vec<u8>>,
    pub created_at_time: Option<u64>,
}

pub struct RosettaClientArgsBuilder {
    operation_type: String,
    to_account: Option<Account>,
    spender_account: Option<Account>,
    from_account: Option<Account>,
    from_subaccount: Option<Vec<u8>>,
    spender_subaccount: Option<Vec<u8>>,
    amount: Option<Nat>,
    allowance: Option<Nat>,
    rosetta_url: String,
    expires_at: Option<u64>,
    expected_allowance: Option<Nat>,
    memo: Option<Vec<u8>>,
    created_at_time: Option<u64>,
}

impl RosettaClientArgsBuilder {
    pub fn new(rosetta_url: String, operation_type: &str) -> Self {
        RosettaClientArgsBuilder {
            operation_type: operation_type.to_string(),
            to_account: None,
            spender_account: None,
            from_account: None,
            from_subaccount: None,
            spender_subaccount: None,
            amount: None,
            allowance: None,
            rosetta_url,
            expires_at: None,
            expected_allowance: None,
            memo: None,
            created_at_time: None,
        }
    }

    pub fn with_to_account(mut self, to_account: Account) -> Self {
        self.to_account = Some(to_account);
        self
    }

    pub fn with_spender_account(mut self, spender_account: Account) -> Self {
        self.spender_account = Some(spender_account);
        self
    }

    pub fn with_from_account(mut self, from_account: Account) -> Self {
        self.from_account = Some(from_account);
        self
    }

    pub fn with_from_subaccount(mut self, from_subaccount: Vec<u8>) -> Self {
        self.from_subaccount = Some(from_subaccount);
        self
    }

    pub fn with_spender_subaccount(mut self, spender_subaccount: Vec<u8>) -> Self {
        self.spender_subaccount = Some(spender_subaccount);
        self
    }

    pub fn with_amount(mut self, amount: Nat) -> Self {
        self.amount = Some(amount);
        self
    }

    pub fn with_allowance(mut self, allowance: Nat) -> Self {
        self.allowance = Some(allowance);
        self
    }

    pub fn with_expires_at(mut self, expires_at: u64) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    pub fn with_expected_allowance(mut self, expected_allowance: Nat) -> Self {
        self.expected_allowance = Some(expected_allowance);
        self
    }

    pub fn with_memo(mut self, memo: Vec<u8>) -> Self {
        self.memo = Some(memo);
        self
    }

    pub fn with_created_at_time(mut self, created_at_time: u64) -> Self {
        self.created_at_time = Some(created_at_time);
        self
    }

    pub fn build(self) -> RosettaClientArgs {
        RosettaClientArgs {
            operation_type: self.operation_type,
            to_account: self.to_account,
            spender_account: self.spender_account,
            from_account: self.from_account,
            from_subaccount: self.from_subaccount,
            spender_subaccount: self.spender_subaccount,
            amount: self.amount,
            allowance: self.allowance,
            rosetta_url: self.rosetta_url,
            expires_at: self.expires_at,
            expected_allowance: self.expected_allowance,
            memo: self.memo,
            created_at_time: self.created_at_time,
        }
    }
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

    if arguments.to_account.is_some() {
        command = command
            .arg("--to")
            .arg(arguments.to_account.unwrap().to_string());
    }

    if arguments.spender_account.is_some() {
        command = command
            .arg("--spender")
            .arg(arguments.spender_account.unwrap().to_string());
    }

    if arguments.from_account.is_some() {
        command = command
            .arg("--from")
            .arg(arguments.from_account.unwrap().to_string());
    }

    if arguments.from_subaccount.is_some() {
        command = command.arg("--from-subaccount").arg(format!(
            "{}",
            String::from_utf8_lossy(arguments.from_subaccount.unwrap().as_slice())
        ));
    }

    if arguments.spender_subaccount.is_some() {
        command = command.arg("--spender-subaccount").arg(format!(
            "{}",
            String::from_utf8_lossy(arguments.spender_subaccount.unwrap().as_slice())
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
