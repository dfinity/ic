//! Semantic verification of the deployless balance batcher (`BATCHER_INITCODE`)
//! against a real EVM: a local anvil node runs the exact bytecode the minter
//! ships, so this complements the byte-level assembler golden
//! (`balance_scan::batcher::tests::initcode_matches_readable_assembly`) by
//! proving the program actually *does* the right thing end to end.
//!
//! It deploys `MockUSDT` (a standard ERC-20 with `balanceOf(address)`), funds a
//! set of holders, and issues the batcher exactly as the minter does — a
//! create-style `eth_call` (`to` omitted) whose calldata is
//! `encode_balance_batch(..)`. The returned blob is decoded with
//! `decode_balance_batch` and checked against the balances anvil reports
//! directly. A separate test pins the fail-loud contract: a batch touching a
//! non-contract "token" reverts the whole call rather than reporting a zero
//! balance.
//!
//! Runs the `anvil` and `solc` binaries vendored via Bazel (`ANVIL_BIN`,
//! `SOLC_BIN`); see BUILD.bazel.

use ethers_core::abi::{ParamType, Token};
use ethers_core::types::{Address as EthAddress, U256};
use ethers_core::utils::keccak256;
use ic_cketh_minter::balance_scan::batcher::{
    decode_balance_batch, encode_balance_batch, BalanceOfCall,
};
use ic_cketh_minter::numeric::Erc20Value;
use ic_cketh_test_utils::live_scan::{
    default_caller, CkErc20LiveScanSetup, USDT_ERC20_CONTRACT_ADDRESS,
};
use ic_cketh_test_utils::USDC_ERC20_CONTRACT_ADDRESS;
use ic_ethereum_types::Address;
use serde_json::Value;
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::time::{Duration, Instant};

/// Anvil's first dev account: unlocked and pre-funded, so transfers can go
/// through `eth_sendTransaction` without any local signing.
const DEV_ACCOUNT: &str = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
const TOKEN_SUPPLY: u128 = 1_000_000_000;

#[test]
fn should_read_erc20_balances_across_tokens_and_holders() {
    let anvil = Anvil::start();
    let dev = address_from_hex(DEV_ACCOUNT);

    // Two ERC-20s so we exercise positional decoding across different tokens.
    let token_a = deploy_mock_erc20(&anvil, &dev);
    let token_b = deploy_mock_erc20(&anvil, &dev);

    let h1 = Address::new([0x11; 20]);
    let h2 = Address::new([0x22; 20]);
    let h3 = Address::new([0x33; 20]); // never funded -> balance 0

    fund(&anvil, &token_a, &dev, &h1, 100);
    fund(&anvil, &token_a, &dev, &h2, 250);
    fund(&anvil, &token_b, &dev, &h1, 7);
    fund(&anvil, &token_b, &dev, &h3, 999);

    let calls = vec![
        BalanceOfCall {
            token: token_a,
            holder: h1,
        },
        BalanceOfCall {
            token: token_a,
            holder: h2,
        },
        BalanceOfCall {
            token: token_a,
            holder: h3,
        },
        BalanceOfCall {
            token: token_b,
            holder: h1,
        },
        BalanceOfCall {
            token: token_b,
            holder: h2,
        },
        BalanceOfCall {
            token: token_b,
            holder: h3,
        },
    ];

    let out = anvil
        .eth_call_create(&dev, &encode_balance_batch(&calls))
        .expect("the balance batch must not revert");
    let balances = decode_balance_batch(&out, calls.len()).expect("decode failed");

    assert_eq!(
        balances,
        vec![
            Erc20Value::from(100_u64),
            Erc20Value::from(250_u64),
            Erc20Value::from(0_u64),
            Erc20Value::from(7_u64),
            Erc20Value::from(0_u64),
            Erc20Value::from(999_u64),
        ]
    );

    // The batcher must agree with anvil's own view of every balance.
    for call in &calls {
        let expected = anvil.erc20_balance(&call.token, &call.holder);
        let single = anvil
            .eth_call_create(&dev, &encode_balance_batch(std::slice::from_ref(call)))
            .expect("single-call batch reverted");
        assert_eq!(decode_balance_batch(&single, 1).unwrap()[0], expected);
    }
}

#[test]
fn should_read_many_balances_in_a_single_call() {
    let anvil = Anvil::start();
    let dev = address_from_hex(DEV_ACCOUNT);
    let token = deploy_mock_erc20(&anvil, &dev);

    // A single create-style eth_call carrying many balanceOf sub-calls, to
    // exercise the loop and the per-pair CODECOPY offset arithmetic at scale.
    const N: u64 = 32;
    let holders: Vec<Address> = (0..N).map(holder_at).collect();
    for (i, holder) in holders.iter().enumerate() {
        fund(&anvil, &token, &dev, holder, (i as u128 + 1) * 1_000);
    }

    let calls: Vec<BalanceOfCall> = holders
        .iter()
        .map(|holder| BalanceOfCall {
            token,
            holder: *holder,
        })
        .collect();

    let out = anvil
        .eth_call_create(&dev, &encode_balance_batch(&calls))
        .expect("the balance batch must not revert");
    let balances = decode_balance_batch(&out, calls.len()).expect("decode failed");

    let expected: Vec<Erc20Value> = (0..N)
        .map(|i| Erc20Value::from((i as u128 + 1) * 1_000))
        .collect();
    assert_eq!(balances, expected);
}

#[test]
fn should_revert_the_whole_call_when_a_token_is_not_a_contract() {
    let anvil = Anvil::start();
    let dev = address_from_hex(DEV_ACCOUNT);
    let token = deploy_mock_erc20(&anvil, &dev);
    let holder = Address::new([0x11; 20]);
    fund(&anvil, &token, &dev, &holder, 500);

    // A "token" with no code: STATICCALL succeeds with empty return data, which
    // is not the 32 bytes the batcher requires, so it reverts the whole call
    // rather than reporting a phantom zero balance.
    let not_a_contract = Address::new([0x99; 20]);
    assert!(
        anvil.code(&not_a_contract).is_empty(),
        "the bad token must genuinely have no code"
    );

    // The same batch without the bad token succeeds, so the revert is caused by
    // the non-contract token and nothing else.
    let good = vec![BalanceOfCall { token, holder }];
    assert!(
        anvil
            .eth_call_create(&dev, &encode_balance_batch(&good))
            .is_ok(),
        "the well-formed batch should succeed"
    );

    let bad = vec![
        BalanceOfCall { token, holder },
        BalanceOfCall {
            token: not_a_contract,
            holder,
        },
    ];
    assert!(
        anvil
            .eth_call_create(&dev, &encode_balance_batch(&bad))
            .is_err(),
        "a batch touching a non-contract token must revert"
    );
}

/// End-to-end balance scan against a real EVM: a live PocketIC runs the minter and the *real* EVM
/// RPC canister (configured to route every provider to this anvil node), so the minter's periodic
/// balance scan issues genuine HTTPS outcalls and reads real ERC-20 balances from anvil.
///
/// The two supported tokens (ckUSDC, ckUSDT) are placed at their real mainnet addresses via
/// `anvil_setCode`, and the minter's derived deposit address is credited above the scan's candidate
/// threshold via `anvil_setStorageAt`. The scan must then flag that address as a deposit candidate
/// for both tokens.
#[test]
fn should_scan_real_erc20_balances_through_the_evm_rpc_canister() {
    const DEPOSIT_SUBACCOUNT: [u8; 32] = [42; 32];
    // 20 USDC/USDT (6 decimals), comfortably above each token's ~$10 candidate minimum.
    const DEPOSIT_BALANCE: u128 = 20_000_000;

    let anvil = Anvil::start();
    let dev = address_from_hex(DEV_ACCOUNT);

    let setup = CkErc20LiveScanSetup::new_live(anvil.url());
    let user = default_caller();
    let deposit = setup.register_deposit_address(user, DEPOSIT_SUBACCOUNT);

    // Reuse MockUSDT's deployed bytecode to give both supported tokens a working `balanceOf`, then
    // credit the deposit address on each by writing the `balanceOf` mapping slot directly.
    let runtime = anvil.code(&deploy_mock_erc20(&anvil, &dev));
    let tokens = [
        Address::from_str(USDC_ERC20_CONTRACT_ADDRESS).unwrap(),
        Address::from_str(USDT_ERC20_CONTRACT_ADDRESS).unwrap(),
    ];
    for token in &tokens {
        anvil.set_code(token, &runtime);
        anvil.set_storage_at(
            token,
            &erc20_balance_slot(&deposit),
            &u256_be(DEPOSIT_BALANCE),
        );
        assert_eq!(
            anvil.erc20_balance(token, &deposit),
            Erc20Value::from(DEPOSIT_BALANCE as u64),
            "the deposit balance should be readable on anvil"
        );
    }

    // deposit_erc20 reports the address as scanned (a failed batch would never advance it), and the
    // scan flags it as a candidate for both supported tokens whose real balances it read from anvil.
    let progress = setup.await_scan(user, DEPOSIT_SUBACCOUNT, Duration::from_secs(180));
    assert!(progress.scan_count >= 1, "the address should report a scan");
    assert!(
        progress.last_scanned_block.is_some(),
        "a scanned address should report the block it was scanned at"
    );
    assert_eq!(
        setup.balance_scan_candidates(),
        2,
        "the funded address should be a candidate for both supported tokens"
    );
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

fn holder_at(index: u64) -> Address {
    let mut bytes = [0_u8; 20];
    bytes[..8].copy_from_slice(&index.to_be_bytes());
    // Offset so no holder collides with the deployer or a low reserved address.
    bytes[0] = 0xd0;
    Address::new(bytes)
}

/// Deploys `MockUSDT` with the whole supply minted to `holder`.
fn deploy_mock_erc20(anvil: &Anvil, holder: &Address) -> Address {
    let code = deploy_code(
        &compile("MOCKUSDT_SOL", "MockUSDT"),
        &[address_token(holder), uint_token(TOKEN_SUPPLY)],
    );
    anvil.deploy(holder, &code)
}

/// Transfers `amount` of `token` from `dev` to `holder`.
fn fund(anvil: &Anvil, token: &Address, dev: &Address, holder: &Address, amount: u128) {
    let tx = anvil.send_transaction(
        dev,
        Some(token),
        &call(
            "transfer(address,uint256)",
            &[address_token(holder), uint_token(amount)],
        ),
    );
    assert!(
        status_ok(&anvil.await_receipt(&tx)),
        "ERC-20 transfer failed"
    );
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

/// Compiles `contract` from the Solidity source at env var `source_var` using
/// the vendored `solc`, returning its creation bytecode.
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

struct Anvil {
    child: Child,
    url: String,
}

impl Anvil {
    fn start() -> Self {
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

    /// Sends a JSON-RPC request, returning the raw `result`/`error` body so the
    /// caller can decide whether an error is a failure.
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

    fn url(&self) -> &str {
        &self.url
    }

    fn code(&self, address: &Address) -> Vec<u8> {
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
    fn set_code(&self, address: &Address, code: &[u8]) {
        self.rpc(
            "anvil_setCode",
            serde_json::json!([to_hex(address.as_ref()), to_hex(code)]),
        );
    }

    /// Writes a 32-byte storage `value` at `slot` of `address` (foundry's `anvil_setStorageAt`).
    fn set_storage_at(&self, address: &Address, slot: &[u8; 32], value: &[u8; 32]) {
        self.rpc(
            "anvil_setStorageAt",
            serde_json::json!([to_hex(address.as_ref()), to_hex(slot), to_hex(value)]),
        );
    }

    /// A create-style `eth_call` (no `to`): anvil runs `data` as init code and
    /// returns whatever it `RETURN`s, exactly as the minter invokes the batcher.
    fn eth_call_create(&self, from: &Address, data: &[u8]) -> Result<Vec<u8>, String> {
        self.rpc_result(
            "eth_call",
            serde_json::json!([{"from": to_hex(from.as_ref()), "input": to_hex(data)}, "latest"]),
        )
        .map(|value| from_hex(value.as_str().unwrap()))
    }

    fn erc20_balance(&self, token: &Address, holder: &Address) -> Erc20Value {
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

    fn deploy(&self, from: &Address, code: &[u8]) -> Address {
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

fn address_from_hex(hex_str: &str) -> Address {
    Address::new(from_hex(hex_str).try_into().unwrap())
}
