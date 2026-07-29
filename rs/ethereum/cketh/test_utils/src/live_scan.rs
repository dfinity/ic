//! A live [`PocketIc`] harness for the ckERC20 balance scan, driving *real* HTTPS outcalls against
//! a local anvil node that the harness owns.
//!
//! Unlike [`crate::ckerc20::CkErc20Setup`] — which runs on `StateMachine` and answers the EVM RPC
//! canister's JSON-RPC outcalls with canned mocks ([`crate::mock::MockJsonRpcProviders`]) — this
//! harness runs PocketIC in *live* mode so the EVM RPC canister issues genuine HTTPS outcalls, and
//! installs it with an `overrideProvider` that rewrites every provider URL to the harness' anvil
//! node (mirroring the `evm_rpc_local` configuration of the EVM RPC canister). The minter therefore
//! reads real Ethereum state from anvil, exercising the balance scan end to end: minter → EVM RPC
//! canister → anvil.
//!
//! Only the minter and the EVM RPC canister are installed. The full ckERC20 feature is activated by
//! pointing the minter's ledger-suite-orchestrator id at a principal this harness controls, so
//! supported tokens can be registered directly via `add_ckerc20_token` without a real orchestrator
//! or any spawned ledgers — the balance scan only needs the token contract addresses in the
//! minter's state.
//!
//! The [`Anvil`] node client and its ABI/solc helpers also back the standalone batcher tests in
//! `deposit_from_cex.rs`, which run against anvil without any IC.

use candid::{Decode, Encode, Nat, Principal};
use ethers_core::abi::{ParamType, Token};
use ethers_core::types::{Address as EthAddress, U256};
use ethers_core::utils::keccak256;
use evm_rpc_types::{InstallArgs, OverrideProvider, RegexSubstitution};
use ic_base_types::PrincipalId;
use ic_cketh_minter::endpoints::{
    AddCkErc20Token, DepositErc20Arg, DepositErc20Error, DepositErc20Response, DepositMode,
};
use ic_cketh_minter::lifecycle::upgrade::UpgradeArg;
use ic_cketh_minter::lifecycle::{EthereumNetwork, MinterArg, init::InitArg as MinterInitArgs};
use ic_cketh_minter::numeric::Erc20Value;
use ic_ethereum_types::Address;
use ic_http_types::{HttpRequest, HttpResponse};
use pocket_ic::{CanisterSettings, PocketIc, PocketIcBuilder};
use serde_bytes::ByteBuf;
use serde_json::Value;
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::time::{Duration, Instant};

use crate::{
    CKETH_MINIMUM_WITHDRAWAL_AMOUNT, DEFAULT_PRINCIPAL_ID, ERC20_HELPER_CONTRACT_ADDRESS,
    ETH_HELPER_CONTRACT_ADDRESS, USDC_ERC20_CONTRACT_ADDRESS, evm_rpc_wasm, minter_wasm,
};

/// USDT's mainnet address, the second token registered so the scan reads more than one token per
/// address. Matches the ckUSDT contract the minter prices in `balance_scan::MIN_DEPOSITS`.
pub const USDT_ERC20_CONTRACT_ADDRESS: &str = "0xdAC17F958D2ee523a2206206994597C13D831ec7";

/// Anvil's first dev account: unlocked and pre-funded, so transfers and deployments go through
/// `eth_sendTransaction` without any local signing.
pub const DEV_ACCOUNT: &str = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";

/// The whole supply minted to the deployer when deploying a [`deploy_mock_erc20`] token.
pub const TOKEN_SUPPLY: u128 = 1_000_000_000;

/// PocketIC's fiduciary subnet holds the secp256k1 test key named `key_1`, the key the minter
/// derives deposit addresses from.
const ECDSA_KEY_NAME: &str = "key_1";

pub struct CkErc20LiveScanSetup {
    env: PocketIc,
    anvil: Anvil,
    minter_id: Principal,
    /// The default depositing user, matching [`crate::ckerc20::CkErc20Setup`]'s caller.
    caller: Principal,
}

impl CkErc20LiveScanSetup {
    /// Starts a local anvil node, installs the minter and EVM RPC canister (the latter routed to
    /// anvil via `overrideProvider`), registers ckUSDC/ckUSDT, and switches PocketIC to live mode so
    /// the EVM RPC canister's outcalls reach anvil for real.
    pub fn new_live() -> Self {
        let anvil = Anvil::start();

        let mut env = PocketIcBuilder::new()
            .with_nns_subnet() // make_live requires an NNS subnet.
            .with_fiduciary_subnet() // holds the secp256k1 `key_1` used by the minter.
            .build();

        let controller = Principal::from_slice(&[0x0a; 10]);
        let settings = CanisterSettings {
            controllers: Some(vec![controller]),
            ..Default::default()
        };

        // A placeholder ckETH ledger: the minter stores its id at init but never calls it on the
        // balance-scan path, so it is left uninstalled.
        let ledger_id = env.create_canister();
        let evm_rpc_id =
            env.create_canister_with_settings(Some(controller), Some(settings.clone()));
        env.add_cycles(evm_rpc_id, u128::from(u64::MAX));
        install_evm_rpc(&env, evm_rpc_id, controller, anvil.url());

        let minter_id = env.create_canister_with_settings(Some(controller), Some(settings));
        env.add_cycles(minter_id, u128::from(u64::MAX));

        // Go live *before* installing the minter: its install schedules immediate refresh and
        // balance-scan timers that issue HTTPS outcalls, which would stall (holding the task guards)
        // if they fired while the outcalls could not be answered.
        let _gateway = env.make_live(None);

        install_minter(&env, minter_id, ledger_id, evm_rpc_id, controller);
        activate_ckerc20(&env, minter_id, controller);
        register_supported_tokens(&env, minter_id, controller);

        Self {
            env,
            anvil,
            minter_id,
            caller: PrincipalId::new_user_test_id(DEFAULT_PRINCIPAL_ID).into(),
        }
    }

    /// The default depositing user, matching [`crate::ckerc20::CkErc20Setup`]'s caller.
    pub fn caller(&self) -> Principal {
        self.caller
    }

    /// Registers a deposit address for `caller`'s `subaccount` and returns the Ethereum address the
    /// minter derived for it.
    pub fn register_deposit_address(&self, caller: Principal, subaccount: [u8; 32]) -> Address {
        Address::from_str(&self.deposit_erc20(caller, subaccount).address)
            .expect("BUG: minter returned an invalid deposit address")
    }

    /// Calls `deposit_erc20` as `caller`, which registers (idempotently) that user's deposit
    /// address for balance scanning and reports its scan progress.
    pub fn deposit_erc20(&self, caller: Principal, subaccount: [u8; 32]) -> DepositErc20Response {
        let arg = DepositErc20Arg {
            mode: DepositMode::Unsponsored {
                subaccount: Some(subaccount),
            },
        };
        let reply = self
            .env
            .update_call(
                self.minter_id,
                caller,
                "deposit_erc20",
                Encode!(&arg).unwrap(),
            )
            .expect("BUG: deposit_erc20 was rejected");
        Decode!(&reply, Result<DepositErc20Response, DepositErc20Error>)
            .unwrap()
            .expect("BUG: deposit_erc20 returned an error")
    }

    /// Places the supported ERC-20s (ckUSDC, ckUSDT) at their real mainnet addresses on the owned
    /// anvil node and credits `deposit` with `amount` of each, so the scan reads real,
    /// above-threshold balances. Both tokens get code, or the fail-loud batcher would revert the
    /// whole scan.
    pub fn credit_deposit(&self, deposit: &Address, amount: u128) {
        let dev = address_from_hex(DEV_ACCOUNT);
        // Reuse MockUSDT's deployed bytecode to give each token a working `balanceOf`, then credit
        // the deposit address by writing the `balanceOf` mapping slot directly.
        let runtime = self.anvil.code(&deploy_mock_erc20(&self.anvil, &dev));
        for address in [USDC_ERC20_CONTRACT_ADDRESS, USDT_ERC20_CONTRACT_ADDRESS] {
            let token = Address::from_str(address).unwrap();
            self.anvil.set_code(&token, &runtime);
            self.anvil
                .set_storage_at(&token, &erc20_balance_slot(deposit), &u256_be(amount));
            assert_eq!(
                self.anvil.erc20_balance(&token, deposit),
                Erc20Value::from(amount),
                "the deposit balance should be readable on anvil"
            );
        }
    }

    /// Waits until the minter's periodic balance scan has scanned `caller`'s deposit address —
    /// observed through `deposit_erc20`'s own scan progress — and returns that progress. A failing
    /// batch never advances an address, so `scan_count >= 1` already proves the `eth_call` against
    /// anvil succeeded and decoded. Panics if no scan completes within `deadline`.
    ///
    /// Whether the address' balance made it a deposit *candidate* is not surfaced by
    /// `deposit_erc20`; read that from [`Self::balance_scan_candidates`].
    pub fn await_scan(
        &self,
        caller: Principal,
        subaccount: [u8; 32],
        deadline: Duration,
    ) -> DepositErc20Response {
        let start = Instant::now();
        loop {
            let progress = self.deposit_erc20(caller, subaccount);
            if progress.scan_count >= 1 {
                return progress;
            }
            assert!(
                start.elapsed() <= deadline,
                "the deposit address was not scanned within {deadline:?}"
            );
            std::thread::sleep(Duration::from_secs(2));
        }
    }

    /// The number of deposit candidates the minter's most recent balance scan found, read from its
    /// metrics — `deposit_erc20` reports that an address was scanned but not whether its balance
    /// cleared the candidate threshold. `0` if no scan has recorded statistics yet.
    pub fn balance_scan_candidates(&self) -> u64 {
        gauge(&self.metrics(), "cketh_minter_balance_scan_candidates").unwrap_or(0.0) as u64
    }

    fn metrics(&self) -> String {
        let request = HttpRequest {
            method: "GET".to_string(),
            url: "/metrics".to_string(),
            headers: vec![],
            body: ByteBuf::default(),
        };
        let reply = self
            .env
            .query_call(
                self.minter_id,
                Principal::anonymous(),
                "http_request",
                Encode!(&request).unwrap(),
            )
            .expect("BUG: the metrics query was rejected");
        let response = Decode!(&reply, HttpResponse).unwrap();
        String::from_utf8(response.body.into_vec()).expect("BUG: metrics are not valid UTF-8")
    }
}

fn install_evm_rpc(env: &PocketIc, evm_rpc_id: Principal, controller: Principal, anvil_url: &str) {
    let args = InstallArgs {
        override_provider: Some(OverrideProvider {
            override_url: Some(RegexSubstitution {
                pattern: ".*".into(),
                replacement: anvil_url.to_string(),
            }),
        }),
        ..Default::default()
    };
    env.install_canister(
        evm_rpc_id,
        evm_rpc_wasm(),
        Encode!(&args).unwrap(),
        Some(controller),
    );
}

fn install_minter(
    env: &PocketIc,
    minter_id: Principal,
    ledger_id: Principal,
    evm_rpc_id: Principal,
    controller: Principal,
) {
    let args = MinterInitArgs {
        ethereum_network: EthereumNetwork::Mainnet,
        ecdsa_key_name: ECDSA_KEY_NAME.to_string(),
        ethereum_contract_address: Some(ETH_HELPER_CONTRACT_ADDRESS.to_string()),
        ledger_id,
        // anvil is a fresh chain with no finalized blocks, so track its "latest" head.
        ethereum_block_height: ic_cketh_minter::endpoints::CandidBlockTag::Latest,
        minimum_withdrawal_amount: Nat::from(CKETH_MINIMUM_WITHDRAWAL_AMOUNT),
        next_transaction_nonce: Nat::from(0_u8),
        last_scraped_block_number: Nat::from(0_u8),
        evm_rpc_id: Some(evm_rpc_id),
    };
    env.install_canister(
        minter_id,
        minter_wasm(),
        Encode!(&MinterArg::InitArg(args)).unwrap(),
        Some(controller),
    );
}

/// Activates the ckERC20 feature by pointing the minter's orchestrator id at `controller` (so this
/// harness can register tokens) and setting the ERC-20 deposit helper contract.
fn activate_ckerc20(env: &PocketIc, minter_id: Principal, controller: Principal) {
    let upgrade = UpgradeArg {
        ledger_suite_orchestrator_id: Some(controller),
        erc20_helper_contract_address: Some(ERC20_HELPER_CONTRACT_ADDRESS.to_string()),
        ..Default::default()
    };
    env.upgrade_canister(
        minter_id,
        minter_wasm(),
        Encode!(&MinterArg::UpgradeArg(upgrade)).unwrap(),
        Some(controller),
    )
    .expect("BUG: failed to activate the ckERC20 feature");
}

fn register_supported_tokens(env: &PocketIc, minter_id: Principal, controller: Principal) {
    for (address, symbol) in [
        (USDC_ERC20_CONTRACT_ADDRESS, "ckUSDC"),
        (USDT_ERC20_CONTRACT_ADDRESS, "ckUSDT"),
    ] {
        let arg = AddCkErc20Token {
            chain_id: Nat::from(1_u8),
            address: address.to_string(),
            ckerc20_token_symbol: symbol.to_string(),
            // A distinct placeholder ledger per token: the minter rejects duplicate ledger ids and
            // never calls these on the balance-scan path.
            ckerc20_ledger_id: env.create_canister(),
        };
        env.update_call(
            minter_id,
            controller,
            "add_ckerc20_token",
            Encode!(&arg).unwrap(),
        )
        .expect("BUG: add_ckerc20_token was rejected");
    }
}

/// Reads the value of a Prometheus gauge line `"<name> <value> [timestamp]"`, or `None` if the
/// metric is absent (e.g. no balance scan has run yet).
fn gauge(metrics: &str, name: &str) -> Option<f64> {
    metrics.lines().find_map(|line| {
        let rest = line.strip_prefix(name)?;
        rest.strip_prefix(' ')?
            .split_whitespace()
            .next()?
            .parse()
            .ok()
    })
}

/// The storage slot of `balanceOf[holder]` for a Solidity `mapping(address => uint256)` declared at
/// slot 0 (as in `MockUSDT`): `keccak256(pad32(holder) ‖ pad32(0))`.
fn erc20_balance_slot(holder: &Address) -> [u8; 32] {
    let mut key = [0_u8; 64];
    key[12..32].copy_from_slice(holder.as_ref());
    keccak256(key)
}

/// A `u128` as a big-endian 32-byte EVM word.
fn u256_be(value: u128) -> [u8; 32] {
    let mut word = [0_u8; 32];
    word[16..].copy_from_slice(&value.to_be_bytes());
    word
}

/// Deploys `MockUSDT` with the whole supply minted to `holder`, returning its address.
pub fn deploy_mock_erc20(anvil: &Anvil, holder: &Address) -> Address {
    let code = deploy_code(
        &compile("MOCKUSDT_SOL", "MockUSDT"),
        &[address_token(holder), uint_token(TOKEN_SUPPLY)],
    );
    anvil.deploy(holder, &code)
}

// ---------------------------------------------------------------------------
// ABI encoding / decoding via ethers-core (ethabi).
// ---------------------------------------------------------------------------

/// A function call: the 4-byte selector followed by the ABI-encoded arguments.
fn call(signature: &str, tokens: &[Token]) -> Vec<u8> {
    let selector = &keccak256(signature.as_bytes())[..4];
    [selector, &ethers_core::abi::encode(tokens)].concat()
}

fn address_token(address: &Address) -> Token {
    Token::Address(EthAddress::from_slice(address.as_ref()))
}

fn uint_token(value: u128) -> Token {
    Token::Uint(U256::from(value))
}

fn decode_uint(data: &[u8]) -> u128 {
    ethers_core::abi::decode(&[ParamType::Uint(256)], data)
        .expect("ABI decode failed")
        .pop()
        .unwrap()
        .into_uint()
        .unwrap()
        .as_u128()
}

fn deploy_code(bytecode: &[u8], constructor_args: &[Token]) -> Vec<u8> {
    [bytecode, &ethers_core::abi::encode(constructor_args)].concat()
}

/// Compiles `contract` from the Solidity source at env var `source_var` using the vendored `solc`,
/// returning its creation bytecode.
fn compile(source_var: &str, contract: &str) -> Vec<u8> {
    let solc = std::env::var("SOLC_BIN").expect("SOLC_BIN not set by Bazel");
    let source = std::env::var(source_var).expect("contract source env var not set by Bazel");
    let output = Command::new(&solc)
        .args([
            "--combined-json",
            "bin",
            "--optimize",
            "--optimize-runs",
            "200",
            &source,
        ])
        .output()
        .unwrap_or_else(|e| panic!("failed to run solc at {solc}: {e}"));
    assert!(
        output.status.success(),
        "solc failed for {source}:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let compiled: Value = serde_json::from_slice(&output.stdout).unwrap();
    let (_, artifact) = compiled["contracts"]
        .as_object()
        .unwrap()
        .iter()
        .find(|(key, _)| key.ends_with(&format!(":{contract}")))
        .unwrap_or_else(|| panic!("solc did not produce contract {contract} from {source}"));
    hex::decode(artifact["bin"].as_str().unwrap()).unwrap()
}

// ---------------------------------------------------------------------------
// Local anvil node + JSON-RPC transport.
// ---------------------------------------------------------------------------

pub struct Anvil {
    child: Child,
    url: String,
}

impl Anvil {
    pub fn start() -> Self {
        let bin = std::env::var("ANVIL_BIN").expect("ANVIL_BIN not set by Bazel");
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let mut child = Command::new(&bin)
            .arg("--host")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|e| panic!("failed to spawn anvil at {bin}: {e}"));
        let url = format!("http://127.0.0.1:{port}");
        wait_until_ready(&mut child, &bin, &url);
        Self { child, url }
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// Sends a JSON-RPC request, returning the raw `result`/`error` body so the caller can decide
    /// whether an error is a failure.
    fn rpc_result(&self, method: &str, params: Value) -> Result<Value, String> {
        let body: Value = reqwest::blocking::Client::new()
            .post(&self.url)
            .json(
                &serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}),
            )
            .send()
            .unwrap()
            .json()
            .unwrap();
        match body.get("error") {
            Some(error) if !error.is_null() => Err(error.to_string()),
            _ => Ok(body["result"].clone()),
        }
    }

    fn rpc(&self, method: &str, params: Value) -> Value {
        self.rpc_result(method, params)
            .unwrap_or_else(|e| panic!("RPC {method} failed: {e}"))
    }

    pub fn code(&self, address: &Address) -> Vec<u8> {
        from_hex(
            self.rpc(
                "eth_getCode",
                serde_json::json!([to_hex(address.as_ref()), "latest"]),
            )
            .as_str()
            .unwrap(),
        )
    }

    /// Places `code` as the runtime bytecode at `address` (foundry's `anvil_setCode` cheatcode).
    pub fn set_code(&self, address: &Address, code: &[u8]) {
        self.rpc(
            "anvil_setCode",
            serde_json::json!([to_hex(address.as_ref()), to_hex(code)]),
        );
    }

    /// Writes a 32-byte storage `value` at `slot` of `address` (foundry's `anvil_setStorageAt`).
    pub fn set_storage_at(&self, address: &Address, slot: &[u8; 32], value: &[u8; 32]) {
        self.rpc(
            "anvil_setStorageAt",
            serde_json::json!([to_hex(address.as_ref()), to_hex(slot), to_hex(value)]),
        );
    }

    /// A create-style `eth_call` (no `to`): anvil runs `data` as init code and returns whatever it
    /// `RETURN`s, exactly as the minter invokes the batcher.
    pub fn eth_call_create(&self, from: &Address, data: &[u8]) -> Result<Vec<u8>, String> {
        self.rpc_result(
            "eth_call",
            serde_json::json!([{"from": to_hex(from.as_ref()), "input": to_hex(data)}, "latest"]),
        )
        .map(|value| from_hex(value.as_str().unwrap()))
    }

    pub fn erc20_balance(&self, token: &Address, holder: &Address) -> Erc20Value {
        let out = from_hex(
            self.rpc(
                "eth_call",
                serde_json::json!([
                    {"to": to_hex(token.as_ref()),
                     "input": to_hex(&call("balanceOf(address)", &[address_token(holder)]))},
                    "latest"
                ]),
            )
            .as_str()
            .unwrap(),
        );
        Erc20Value::from(decode_uint(&out))
    }

    /// Transfers `amount` of `token` from `from` to `to` via a plain ERC-20 `transfer`.
    pub fn fund(&self, token: &Address, from: &Address, to: &Address, amount: u128) {
        let tx = self.send_transaction(
            from,
            Some(token),
            &call(
                "transfer(address,uint256)",
                &[address_token(to), uint_token(amount)],
            ),
        );
        assert!(
            status_ok(&self.await_receipt(&tx)),
            "ERC-20 transfer failed"
        );
    }

    pub fn send_transaction(&self, from: &Address, to: Option<&Address>, data: &[u8]) -> String {
        let mut tx = serde_json::json!({"from": to_hex(from.as_ref()), "input": to_hex(data)});
        if let Some(to) = to {
            tx["to"] = serde_json::json!(to_hex(to.as_ref()));
        }
        self.rpc("eth_sendTransaction", serde_json::json!([tx]))
            .as_str()
            .unwrap()
            .to_string()
    }

    pub fn deploy(&self, from: &Address, code: &[u8]) -> Address {
        let hash = self.send_transaction(from, None, code);
        let receipt = self.await_receipt(&hash);
        assert!(status_ok(&receipt), "deployment reverted");
        address_from_hex(receipt["contractAddress"].as_str().unwrap())
    }

    pub fn await_receipt(&self, tx_hash: &str) -> Value {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            let receipt = self.rpc("eth_getTransactionReceipt", serde_json::json!([tx_hash]));
            if !receipt.is_null() {
                return receipt;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("no receipt for {tx_hash} within 10s");
    }
}

impl Drop for Anvil {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn wait_until_ready(child: &mut Child, bin: &str, url: &str) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("failed to poll anvil") {
            panic!("anvil ({bin}) exited early with {status} before serving {url}");
        }
        let ready = reqwest::blocking::Client::new()
            .post(url)
            .json(&serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": []}))
            .send()
            .map(|r| r.status().is_success())
            .unwrap_or(false);
        if ready {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("anvil did not become ready within 30s at {url}");
}

// ---------------------------------------------------------------------------
// Small hex / receipt helpers.
// ---------------------------------------------------------------------------

fn status_ok(receipt: &Value) -> bool {
    receipt["status"] == "0x1"
}

fn to_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn from_hex(hex_str: &str) -> Vec<u8> {
    hex::decode(hex_str.trim_start_matches("0x")).unwrap()
}

pub fn address_from_hex(hex_str: &str) -> Address {
    Address::new(from_hex(hex_str).try_into().unwrap())
}
