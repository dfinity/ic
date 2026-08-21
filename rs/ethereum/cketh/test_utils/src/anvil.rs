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

/// The chain the harness pretends to be, matching the `EthereumNetwork::Mainnet` the fixture
/// installs the minter with.
pub const CHAIN_ID: u64 = 1;

/// Seconds between blocks on the harness' chain. Fast enough that a test does not wait on it, slow
/// enough that a block still holds several transactions.
const BLOCK_TIME_SECS: u64 = 1;

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
            // Interval mining, so the chain advances on its own. By default anvil only mines when it
            // receives a transaction, which leaves a chain that looks frozen to everything reading
            // it: the balance scan measures its backoff in elapsed *blocks*, so no scan after the
            // first is ever due, and `finalized` never moves at all.
            .arg("--block-time")
            .arg(BLOCK_TIME_SECS.to_string())
            // One slot per epoch, so `finalized` follows `latest` within a couple of blocks instead
            // of the 32 a real chain takes. The sweeper pipeline finalizes against `finalized`
            // regardless of the block height the minter is configured with.
            .arg("--slots-in-an-epoch")
            .arg("1")
            // Anvil defaults to chain id 31337, but the fixture installs the minter as Mainnet. Both
            // of a sweep's signatures commit to the chain id — the EIP-7702 authorization tuple and
            // the attestation digest — so a mismatch makes the protocol skip the delegation and the
            // delegate's `ecrecover` fail, reverting the whole batch.
            .arg("--chain-id")
            .arg(CHAIN_ID.to_string())
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

    pub(crate) fn deploy(&self, from: &Address, code: &[u8]) -> Address {
        let hash = self.send_transaction(from, None, code);
        let receipt = self.await_receipt(&hash);
        assert!(status_ok(&receipt), "deployment reverted");
        address_from_hex(receipt["contractAddress"].as_str().unwrap())
    }

    /// A plain `eth_call` against `to`, for reading contract state in assertions.
    pub fn call(&self, to: &Address, data: &[u8]) -> Vec<u8> {
        from_hex(
            self.rpc(
                "eth_call",
                serde_json::json!([
                    {"to": to_hex(to.as_ref()), "input": to_hex(data)},
                    "latest"
                ]),
            )
            .as_str()
            .unwrap(),
        )
    }

    /// The ETH balance of `address`, so a test can see the sweeper pay for its own gas.
    pub fn balance(&self, address: &Address) -> u128 {
        let balance = self.rpc(
            "eth_getBalance",
            serde_json::json!([to_hex(address.as_ref()), "latest"]),
        );
        let balance = balance.as_str().unwrap();
        u128::from_str_radix(balance.trim_start_matches("0x"), 16)
            .unwrap_or_else(|e| panic!("not a u128 balance {balance}: {e}"))
    }

    /// The receipt of the most recent transaction `sender` sent, searching back from the chain head,
    /// together with the gas the transaction was allowed. A reverted sweep whose `gasUsed` equals its
    /// `gas` ran out of gas; one below it hit a `require`.
    pub fn last_transaction_of(&self, sender: &Address) -> Option<SentTransaction> {
        let head = self.block_number();
        for height in (0..=head).rev() {
            let block = self.rpc(
                "eth_getBlockByNumber",
                serde_json::json!([format!("0x{height:x}"), true]),
            );
            let Some(transactions) = block["transactions"].as_array() else {
                continue;
            };
            for transaction in transactions {
                if transaction["from"].as_str() != Some(&to_hex(sender.as_ref())) {
                    continue;
                }
                let hash = transaction["hash"].as_str().unwrap().to_string();
                let receipt = self.rpc("eth_getTransactionReceipt", serde_json::json!([&hash]));
                return Some(SentTransaction {
                    succeeded: status_ok(&receipt),
                    gas_used: hex_u64(&receipt["gasUsed"]),
                    gas_limit: hex_u64(&transaction["gas"]),
                    transaction_type: hex_u64(&transaction["type"]),
                    hash,
                });
            }
        }
        None
    }

    /// The height of the chain's latest block.
    pub fn block_number(&self) -> u64 {
        let number = self.rpc("eth_blockNumber", serde_json::json!([]));
        let number = number.as_str().unwrap();
        u64::from_str_radix(number.trim_start_matches("0x"), 16)
            .unwrap_or_else(|e| panic!("not a u64 block number {number}: {e}"))
    }

    /// How many transactions `address` has sent, so a test can pin that a batch really was one
    /// transaction. An EIP-7702 authority's nonce also advances when one of its own authorizations
    /// is applied, which is how a swept deposit address ends up with a nonce of 1 without ever
    /// having sent anything.
    pub fn transaction_count(&self, address: &Address) -> u64 {
        let count = self.rpc(
            "eth_getTransactionCount",
            serde_json::json!([to_hex(address.as_ref()), "latest"]),
        );
        let count = count.as_str().unwrap();
        u64::from_str_radix(count.trim_start_matches("0x"), 16)
            .unwrap_or_else(|e| panic!("not a u64 transaction count {count}: {e}"))
    }

    /// Credits `address` with `wei` of ETH (foundry's `anvil_setBalance`). The minter's sweeper
    /// address is funded this way rather than through the ckETH burn-and-withdraw pipeline, which is
    /// a separate concern from sweeping.
    pub fn set_balance(&self, address: &Address, wei: u128) {
        self.rpc(
            "anvil_setBalance",
            serde_json::json!([to_hex(address.as_ref()), format!("0x{wei:x}")]),
        );
        assert_eq!(self.balance(address), wei, "the balance should be credited");
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

/// The two contracts a sweep goes through, deployed on the node before the fixture is built so the
/// minter can be installed already knowing where they are.
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub struct SweepContracts {
    /// The real `DepositHelperWithSubaccount.sol`, which the sweep transfers through and whose
    /// `ReceivedEthOrErc20` event the minter's unchanged deposit pipeline mints from.
    pub helper: Address,
    /// The EIP-7702 delegate every deposit address delegates to.
    pub delegate: Address,
}

/// Compiles and deploys the real deposit helper and the attested sweeper delegate, wiring the
/// delegate to that helper exactly as production does.
pub fn deploy_sweep_contracts(anvil: &Anvil, minter: &Address) -> SweepContracts {
    let deployer = address_from_hex(DEV_ACCOUNT);
    let helper = anvil.deploy(
        &deployer,
        &deploy_code(
            &compile("CKDEPOSIT_SOL", "CkDeposit"),
            &[address_token(minter)],
        ),
    );
    assert_eq!(
        &decode_address(&anvil.call(&helper, &call("getMinterAddress()", &[]))),
        minter,
        "the helper should pay out to the minter's main address"
    );
    let delegate = anvil.deploy(
        &deployer,
        &deploy_code(
            &compile("CKSWEEPER_ATTESTED_SOL", "CkSweeperAttested"),
            &[address_token(&helper)],
        ),
    );
    SweepContracts { helper, delegate }
}

fn decode_address(data: &[u8]) -> Address {
    Address::new(
        <[u8; 20]>::try_from(&data[12..32]).expect("a 32-byte word holds a 20-byte address"),
    )
}

/// What a transaction the harness went looking for actually did on chain.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct SentTransaction {
    pub hash: String,
    pub succeeded: bool,
    pub gas_used: u64,
    pub gas_limit: u64,
    /// EIP-2718 type: `2` for EIP-1559, `4` for the EIP-7702 transaction a first sweep rides.
    pub transaction_type: u64,
}

fn hex_u64(value: &Value) -> u64 {
    let raw = value.as_str().unwrap_or("0x0");
    u64::from_str_radix(raw.trim_start_matches("0x"), 16).unwrap_or(0)
}
