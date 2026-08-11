//! A local [`Anvil`] node (foundry) with a small JSON-RPC client and the ABI/solc helpers used to
//! drive it. Backs both the standalone batcher tests in `deposit_from_cex.rs` (which run against
//! anvil with no IC) and the live balance-scan harness in [`crate::live_scan`].
//!
//! Runs the `anvil` and `solc` binaries vendored via Bazel (`ANVIL_BIN`, `SOLC_BIN`).

use ethers_core::abi::{ParamType, Token};
use ethers_core::types::{Address as EthAddress, U256};
use ethers_core::utils::keccak256;
use ic_cketh_minter::numeric::Erc20Value;
use ic_ethereum_types::Address;
use serde_json::Value;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Anvil's first dev account: unlocked and pre-funded, so transfers and deployments go through
/// `eth_sendTransaction` without any local signing.
pub const DEV_ACCOUNT: &str = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";

/// The whole supply minted to the deployer when deploying a [`deploy_mock_erc20`] token.
const TOKEN_SUPPLY: u128 = 1_000_000_000;

/// Per-request timeout for the anvil JSON-RPC client. Without it a stuck node would hang a
/// `send()` indefinitely, defeating [`wait_until_ready`]'s deadline and, ultimately, the bazel
/// test timeout; with it a wedged connection fails fast and the caller can retry or panic.
const RPC_TIMEOUT: Duration = Duration::from_secs(10);

fn rpc_client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(RPC_TIMEOUT)
        .build()
        .expect("failed to build the anvil RPC client")
}

pub struct Anvil {
    child: Child,
    url: String,
    /// Built once and reused across RPCs, so calls share a connection pool instead of paying for a
    /// fresh client (and TCP connection) each time.
    client: reqwest::blocking::Client,
}

impl Anvil {
    pub fn start() -> Self {
        Self::start_with_args(&[])
    }

    /// Starts anvil impersonating Ethereum mainnet: chain id 1, so transactions the minter signs for
    /// `EthereumNetwork::Mainnet` are accepted, with one slot per epoch so the `finalized` block tag
    /// trails `latest` by two blocks instead of the default 64 (2 epochs x 32 slots) — which is what
    /// lets a test drive the minter at its production `BlockTag::Finalized`.
    pub fn start_mainnet_like() -> Self {
        Self::start_with_args(&["--chain-id", "1", "--slots-in-an-epoch", "1"])
    }

    fn start_with_args(extra_args: &[&str]) -> Self {
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
            .args(extra_args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|e| panic!("failed to spawn anvil at {bin}: {e}"));
        let url = format!("http://127.0.0.1:{port}");
        let client = rpc_client();
        wait_until_ready(&mut child, &bin, &url, &client);
        Self { child, url, client }
    }

    pub(crate) fn url(&self) -> &str {
        &self.url
    }

    /// Sends a JSON-RPC request, returning the raw `result`/`error` body so the caller can decide
    /// whether an error is a failure. Transport and decode failures — including a `RPC_TIMEOUT`
    /// timeout — are returned as `Err` (tagged with the method) rather than panicking, so callers
    /// can distinguish them.
    fn rpc_result(&self, method: &str, params: Value) -> Result<Value, String> {
        let response = self
            .client
            .post(&self.url)
            .json(
                &serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}),
            )
            .send()
            .map_err(|e| format!("RPC {method} request failed: {e}"))?;
        let body: Value = response
            .json()
            .map_err(|e| format!("RPC {method} returned an undecodable body: {e}"))?;
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
    pub(crate) fn set_code(&self, address: &Address, code: &[u8]) {
        self.rpc(
            "anvil_setCode",
            serde_json::json!([to_hex(address.as_ref()), to_hex(code)]),
        );
    }

    /// Writes a 32-byte storage `value` at `slot` of `address` (foundry's `anvil_setStorageAt`).
    pub(crate) fn set_storage_at(&self, address: &Address, slot: &[u8; 32], value: &[u8; 32]) {
        self.rpc(
            "anvil_setStorageAt",
            serde_json::json!([to_hex(address.as_ref()), to_hex(slot), to_hex(value)]),
        );
    }

    /// Credits `address` with `wei` of native ETH (foundry's `anvil_setBalance`).
    pub(crate) fn set_balance(&self, address: &Address, wei: u128) {
        self.rpc(
            "anvil_setBalance",
            serde_json::json!([to_hex(address.as_ref()), format!("0x{wei:x}")]),
        );
    }

    /// The native ETH balance of `address` at `block`, read straight from anvil, i.e. the
    /// ground truth an `eth_getBalance` routed through the EVM RPC canister must reproduce.
    pub(crate) fn eth_balance(&self, address: &Address, block: &str) -> u128 {
        let hex = self.rpc(
            "eth_getBalance",
            serde_json::json!([to_hex(address.as_ref()), block]),
        );
        let hex = hex.as_str().expect("eth_getBalance must return a string");
        u128::from_str_radix(hex.trim_start_matches("0x"), 16)
            .expect("eth_getBalance must return a hex quantity")
    }

    /// Mines `count` blocks (foundry's `anvil_mine`).
    pub(crate) fn mine(&self, count: u64) {
        self.rpc("anvil_mine", serde_json::json!([format!("0x{count:x}")]));
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

    fn send_transaction(&self, from: &Address, to: Option<&Address>, data: &[u8]) -> String {
        let mut tx = serde_json::json!({"from": to_hex(from.as_ref()), "input": to_hex(data)});
        if let Some(to) = to {
            tx["to"] = serde_json::json!(to_hex(to.as_ref()));
        }
        self.rpc("eth_sendTransaction", serde_json::json!([tx]))
            .as_str()
            .unwrap()
            .to_string()
    }

    /// Emits a `ReceivedEth(from, value, principal)` log from `helper`, the way the real ckETH helper
    /// contract does, so the minter's log scraping credits a deposit against it.
    ///
    /// Places runtime code at `helper` that emits the log and stops, then calls it: a bare `eth_call`
    /// would not produce a log in a block, and the minter only sees logs that were mined.
    pub(crate) fn emit_received_eth(
        &self,
        helper: &Address,
        from: &Address,
        value: u128,
        principal_topic: &[u8; 32],
    ) {
        // Keccak256("ReceivedEth(address,uint256,bytes32)")
        let received_eth_topic = keccak256(b"ReceivedEth(address,uint256,bytes32)");
        let mut from_topic = [0_u8; 32];
        from_topic[12..].copy_from_slice(from.as_ref());

        let mut code = Vec::new();
        // mstore(0, value) — the log's data word.
        code.push(0x7f);
        code.extend_from_slice(&u256_be(value));
        code.extend_from_slice(&[0x60, 0x00, 0x52]);
        // LOG3 pops offset, size, topic1, topic2, topic3, so push them in reverse.
        code.push(0x7f);
        code.extend_from_slice(principal_topic);
        code.push(0x7f);
        code.extend_from_slice(&from_topic);
        code.push(0x7f);
        code.extend_from_slice(&received_eth_topic);
        // PUSH1 32 (size), PUSH1 0 (offset), LOG3, STOP. LOG3 is 0xa3 — 0xa2 is LOG2, which would
        // drop the principal topic and the minter would reject the event as having invalid topics.
        code.extend_from_slice(&[0x60, 0x20, 0x60, 0x00, 0xa3, 0x00]);

        self.set_code(helper, &code);
        let hash = self.send_transaction(from, Some(helper), &[]);
        assert!(
            status_ok(&self.await_receipt(&hash)),
            "emitting the deposit log reverted"
        );
        // The minter reads at `finalized`, which trails `latest`.
        self.mine(3);
    }

    pub(crate) fn deploy(&self, from: &Address, code: &[u8]) -> Address {
        let hash = self.send_transaction(from, None, code);
        let receipt = self.await_receipt(&hash);
        assert!(status_ok(&receipt), "deployment reverted");
        address_from_hex(receipt["contractAddress"].as_str().unwrap())
    }

    fn await_receipt(&self, tx_hash: &str) -> Value {
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

fn wait_until_ready(child: &mut Child, bin: &str, url: &str, client: &reqwest::blocking::Client) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("failed to poll anvil") {
            panic!("anvil ({bin}) exited early with {status} before serving {url}");
        }
        let ready = client
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

/// Deploys `MockUSDT` with the whole supply minted to `holder`, returning its address.
pub fn deploy_mock_erc20(anvil: &Anvil, holder: &Address) -> Address {
    let code = deploy_code(
        &compile("MOCKUSDT_SOL", "MockUSDT"),
        &[address_token(holder), uint_token(TOKEN_SUPPLY)],
    );
    anvil.deploy(holder, &code)
}

/// The storage slot of `balanceOf[holder]` for a Solidity `mapping(address => uint256)` declared at
/// slot 0 (as in `MockUSDT`): `keccak256(pad32(holder) ‖ pad32(0))`.
pub(crate) fn erc20_balance_slot(holder: &Address) -> [u8; 32] {
    let mut key = [0_u8; 64];
    key[12..32].copy_from_slice(holder.as_ref());
    keccak256(key)
}

/// A `u128` as a big-endian 32-byte EVM word.
pub(crate) fn u256_be(value: u128) -> [u8; 32] {
    let mut word = [0_u8; 32];
    word[16..].copy_from_slice(&value.to_be_bytes());
    word
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
