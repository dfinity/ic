//! Runnable demo of the "deposit from CEX" flow (variant B, the decided
//! variant) from `docs/deposit_from_cex.md`, exercising the minter's *productive*
//! EIP-7702 transaction layer (`ic_cketh_minter::tx`) against a local anvil node.
//!
//! The minter is simulated by a plain EOA controlling a family of derived EOAs
//! (stand-in for threshold ECDSA key derivation on the IC). For each batch size
//! it: deploys a USDT-style ERC-20, the real ckETH helper (`CkDeposit`, compiled
//! from `DepositHelperWithSubaccount.sol`) and the `CkSweeperViaHelper` EIP-7702
//! delegate; has the CEX fund a set of fresh, unfunded deposit EOAs with plain
//! ERC-20 transfers; then sweeps them all to the minter in ONE type-0x04
//! (EIP-7702) transaction whose gas is paid entirely by the minter. Each sweep
//! goes through the helper's `depositErc20`, emitting the canonical
//! `ReceivedEthOrErc20` event (carrying the IC principal) that the minter's
//! existing deposit pipeline already scrapes and mints from.
//!
//! The test is table-driven over the design doc's two batch extremes (its "Cost
//! estimation" section): a single deposit swept in one batch (`B=1`) versus a
//! batch of twenty (`B=20`), asserting that per-deposit gas amortizes as the
//! batch grows.
//!
//! Runs the `anvil` binary vendored via `@foundry_bin_*` (see BUILD.bazel);
//! `ANVIL_BIN` points at it. Requires EIP-7702 support (foundry >= v1.0).

use candid::Principal;
use ic_cketh_minter::numeric::{GasAmount, TransactionNonce, Wei, WeiPerGas};
use ic_cketh_minter::tx::{
    AccessList, Authorization, Eip1559Signature, Eip1559TransactionRequest,
    Eip7702TransactionRequest, SignableTransaction, Signed, SignedAuthorization,
};
use ic_ethereum_types::Address;
use ic_secp256k1::{PrivateKey, PublicKey};
use ic_sha3::Keccak256;
use serde_json::{Value, json};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

// The demo contracts are compiled from source at test time by the vendored
// `solc` (see BUILD.bazel). `CkDeposit` is the real minter helper
// `DepositHelperWithSubaccount.sol`, compiled from its canonical source.

// Anvil's first well-known dev accounts (unlocked, so the CEX transfers can go
// through `eth_sendTransaction`).
const MINTER_PRIVATE_KEY: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const CEX_PRIVATE_KEY: &str = "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const ATTACKER_PRIVATE_KEY: &str =
    "5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";

const USDT_SUPPLY: u128 = 1_000_000_000_000; // 1M USDT (6 decimals)
const DEPOSIT_AMOUNT: u128 = 10_000_000; // 10 USDT per deposit

// Generous, deterministic fees and a gas limit large enough for a batch of 20;
// the minter dev account is funded with 10000 ETH. Gas *used* (asserted below)
// is independent of these.
const PRIORITY_FEE: u128 = 1_000_000_000; // 1 gwei
const MAX_FEE: u128 = 50_000_000_000; // 50 gwei
const SWEEP_GAS_LIMIT: u128 = 5_000_000;

/// The design doc's two batch extremes: a single deposit swept in one batch
/// (`B=1`) versus a batch of twenty (`B=20`). The flow is fully deterministic
/// (fixed keys, fixed contracts, fresh chain), so each batch's total gas is a
/// constant; the point is that per-deposit gas shrinks as the batch grows.
struct BatchScenario {
    deposits: usize,
    total_gas_used: u64,
}

const SCENARIOS: [BatchScenario; 2] = [
    BatchScenario {
        deposits: 1,
        total_gas_used: 94_932,
    },
    BatchScenario {
        deposits: 20,
        total_gas_used: 1_113_373,
    },
];

#[test]
fn batched_sweep_amortizes_gas_across_the_batch() {
    let anvil = Anvil::start();
    let chain_id = anvil.chain_id();

    let minter_key = key_from_hex(MINTER_PRIVATE_KEY);
    let minter = eth_address(&minter_key.public_key());
    let cex = eth_address(&key_from_hex(CEX_PRIVATE_KEY).public_key());

    let contracts = deploy_contracts(&anvil, &minter, &cex);

    let mut previous_per_deposit = u64::MAX;
    for scenario in SCENARIOS {
        let gas = sweep_batch(
            &anvil,
            chain_id,
            &minter_key,
            &minter,
            &cex,
            &contracts,
            scenario.deposits,
        );
        let per_deposit = gas / scenario.deposits as u64;
        println!(
            "batch of {}: {gas} gas total, {per_deposit} per deposit",
            scenario.deposits
        );
        assert_gas(
            gas,
            scenario.total_gas_used,
            &format!("batch of {}", scenario.deposits),
        );
        assert!(
            per_deposit < previous_per_deposit,
            "per-deposit gas should shrink as the batch grows"
        );
        previous_per_deposit = per_deposit;
    }
}

fn assert_gas(actual: u64, expected: u64, label: &str) {
    if expected != 0 {
        assert_eq!(actual, expected, "unexpected {label} gas used");
    }
}

/// Because the IC principal to credit is a sweep argument, sweeping is gated to
/// the minter: anyone else calling a delegated deposit address is rejected, so a
/// deposit cannot be credited to an attacker's principal.
#[test]
fn a_non_minter_cannot_sweep_a_deposit() {
    let anvil = Anvil::start();
    let chain_id = anvil.chain_id();

    let minter_key = key_from_hex(MINTER_PRIVATE_KEY);
    let minter = eth_address(&minter_key.public_key());
    let cex = eth_address(&key_from_hex(CEX_PRIVATE_KEY).public_key());
    let attacker = eth_address(&key_from_hex(ATTACKER_PRIVATE_KEY).public_key());

    let Contracts {
        usdt,
        helper,
        via_helper,
    } = deploy_contracts(&anvil, &minter, &cex);

    // A single funded deposit address.
    let principal = Principal::self_authenticating([42u8]);
    let key = derive_deposit_key(&principal);
    let deposit = eth_address(&key.public_key());
    let tx = anvil.send_transaction(
        &cex,
        Some(&usdt),
        &call(
            "transfer(address,uint256)",
            &[
                Token::Word(word_addr(&deposit)),
                Token::Word(word_u256(DEPOSIT_AMOUNT)),
            ],
        ),
        None,
    );
    assert!(status_ok(&anvil.await_receipt(&tx)), "CEX transfer failed");

    // The minter installs the delegation without sweeping: the authorization
    // rides in an otherwise-empty batch, so the deposit gets the sweeper's code
    // while keeping its funds.
    let authorization = sign_authorization(&key, chain_id, &via_helper, 0);
    let delegate_only = call(
        "sweepErc20Batch(address[],bytes32[],bytes32[],address[])",
        &[
            Token::Array(vec![]),
            Token::Array(vec![]),
            Token::Array(vec![]),
            Token::Array(vec![word_addr(&usdt)]),
        ],
    );
    assert!(
        status_ok(&anvil.send_eip7702(
            &minter_key,
            chain_id,
            &via_helper,
            delegate_only,
            vec![authorization]
        )),
        "delegation setup reverted"
    );
    assert!(
        !anvil.code(&deposit).is_empty(),
        "deposit should now be delegated to the sweeper"
    );
    assert_eq!(
        anvil.usdt_balance(&usdt, &deposit),
        DEPOSIT_AMOUNT,
        "installing the delegation should not move funds"
    );

    // The attacker tries to credit the deposit to their own principal. Gas
    // estimation would already fail ("caller is not the minter"), so the attacker
    // forces an explicit gas limit to get the transaction mined (and reverted).
    let attack = anvil.send_transaction(
        &attacker,
        Some(&deposit),
        &call(
            "sweepErc20(address[],bytes32,bytes32)",
            &[
                Token::Array(vec![word_addr(&usdt)]),
                Token::Word(encode_principal(&Principal::anonymous())),
                Token::Word([0u8; 32]),
            ],
        ),
        Some(300_000),
    );
    assert!(
        !status_ok(&anvil.await_receipt(&attack)),
        "the attacker's sweep should have reverted"
    );
    assert_eq!(
        anvil.usdt_balance(&usdt, &deposit),
        DEPOSIT_AMOUNT,
        "the attacker must not move the funds"
    );

    // The minter sweeps it correctly: the delegation persists, so no new
    // authorization is needed — a plain EIP-1559 transaction suffices.
    let sweep = call(
        "sweepErc20(address[],bytes32,bytes32)",
        &[
            Token::Array(vec![word_addr(&usdt)]),
            Token::Word(encode_principal(&principal)),
            Token::Word([0u8; 32]),
        ],
    );
    let receipt = anvil.send_eip1559(&minter_key, chain_id, &deposit, sweep);
    assert!(status_ok(&receipt), "the minter's sweep reverted");
    assert_eq!(anvil.usdt_balance(&usdt, &deposit), 0, "deposit not swept");
    let events = received_events(&receipt, &helper);
    assert_eq!(events.len(), 1, "expected one ReceivedEthOrErc20 event");
    assert_eq!(events[0].owner, deposit);
    assert_eq!(events[0].principal, encode_principal(&principal));
}

struct Contracts {
    usdt: Address,
    helper: Address,
    via_helper: Address,
}

/// Compiles and deploys the ERC-20, the real helper and the sweeper delegate.
fn deploy_contracts(anvil: &Anvil, minter: &Address, cex: &Address) -> Contracts {
    let usdt = anvil.deploy(
        cex,
        &deploy_code(
            &compile("MOCKUSDT_SOL", "MockUSDT"),
            &[
                Token::Word(word_addr(cex)),
                Token::Word(word_u256(USDT_SUPPLY)),
            ],
        ),
    );
    let helper = anvil.deploy(
        minter,
        &deploy_code(
            &compile("CKDEPOSIT_SOL", "CkDeposit"),
            &[Token::Word(word_addr(minter))],
        ),
    );
    let via_helper = anvil.deploy(
        minter,
        &deploy_code(
            &compile("CKSWEEPER_VIA_HELPER_SOL", "CkSweeperViaHelper"),
            &[
                Token::Word(word_addr(minter)),
                Token::Word(word_addr(&helper)),
            ],
        ),
    );
    assert_eq!(
        address_from_word(&anvil.call(&helper, &call("getMinterAddress()", &[]))),
        *minter,
        "helper minter mismatch"
    );
    Contracts {
        usdt,
        helper,
        via_helper,
    }
}

/// Funds `n` fresh, unfunded deposit EOAs from the CEX, then sweeps them all to
/// the minter in ONE EIP-7702 batch transaction (gas paid by the minter). The
/// deposit EOAs' authorizations ride in the same transaction's authorization
/// list. Asserts every deposit is swept and emits the canonical event, and
/// returns the batch's gas used.
fn sweep_batch(
    anvil: &Anvil,
    chain_id: u64,
    minter_key: &PrivateKey,
    minter: &Address,
    cex: &Address,
    contracts: &Contracts,
    n: usize,
) -> u64 {
    let Contracts {
        usdt,
        helper,
        via_helper,
    } = contracts;

    // Distinct principals per batch size keep the deposit addresses fresh.
    let principals: Vec<Principal> = (0..n)
        .map(|i| Principal::self_authenticating([n as u8, i as u8]))
        .collect();
    let keys: Vec<PrivateKey> = principals.iter().map(derive_deposit_key).collect();
    let deposits: Vec<Address> = keys.iter().map(|k| eth_address(&k.public_key())).collect();

    for deposit in &deposits {
        assert_eq!(
            anvil.balance(deposit),
            0,
            "deposit address should have no ETH"
        );
        assert!(
            anvil.code(deposit).is_empty(),
            "deposit address should have no code"
        );
        let tx = anvil.send_transaction(
            cex,
            Some(usdt),
            &call(
                "transfer(address,uint256)",
                &[
                    Token::Word(word_addr(deposit)),
                    Token::Word(word_u256(DEPOSIT_AMOUNT)),
                ],
            ),
            None,
        );
        assert!(status_ok(&anvil.await_receipt(&tx)), "CEX transfer failed");
    }

    let minter_before = anvil.usdt_balance(usdt, minter);

    let authorizations: Vec<SignedAuthorization> = keys
        .iter()
        .map(|key| sign_authorization(key, chain_id, via_helper, 0))
        .collect();
    let data = call(
        "sweepErc20Batch(address[],bytes32[],bytes32[],address[])",
        &[
            Token::Array(deposits.iter().map(word_addr).collect()),
            Token::Array(principals.iter().map(encode_principal).collect()),
            Token::Array(vec![[0u8; 32]; n]),
            Token::Array(vec![word_addr(usdt)]),
        ],
    );
    let receipt = anvil.send_eip7702(minter_key, chain_id, via_helper, data, authorizations);
    assert!(status_ok(&receipt), "batch sweep reverted");

    let events = received_events(&receipt, helper);
    assert_eq!(events.len(), n, "one ReceivedEthOrErc20 event per deposit");
    for (event, (deposit, principal)) in events.iter().zip(deposits.iter().zip(&principals)) {
        assert_eq!(event.owner, *deposit);
        assert_eq!(event.principal, encode_principal(principal));
        assert_eq!(event.amount, DEPOSIT_AMOUNT);
    }
    for deposit in &deposits {
        assert_eq!(anvil.usdt_balance(usdt, deposit), 0, "deposit not swept");
    }
    assert_eq!(
        anvil.usdt_balance(usdt, minter),
        minter_before + DEPOSIT_AMOUNT * n as u128,
        "minter did not receive every deposit"
    );

    gas_used(&receipt)
}

// ---------------------------------------------------------------------------
// Keys, addresses and signatures (local stand-in for threshold ECDSA).
// ---------------------------------------------------------------------------

fn key_from_hex(hex_key: &str) -> PrivateKey {
    PrivateKey::deserialize_sec1(&hex::decode(hex_key).unwrap()).unwrap()
}

/// Demo stand-in for threshold ECDSA derivation: one deterministic child key per
/// IC principal. On the IC the private key never exists; `sign_with_ecdsa` signs.
fn derive_deposit_key(principal: &Principal) -> PrivateKey {
    let seed = Keccak256::hash(format!("cketh-deposit|{principal}").as_bytes());
    PrivateKey::deserialize_sec1(&seed).unwrap()
}

fn eth_address(public_key: &PublicKey) -> Address {
    let uncompressed = public_key.serialize_sec1(false);
    let hash = Keccak256::hash(&uncompressed[1..]);
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    Address::new(address)
}

fn sign(key: &PrivateKey, digest: &[u8; 32]) -> Eip1559Signature {
    let signature = key.sign_digest_with_ecdsa(digest);
    let recovery_id = key
        .public_key()
        .try_recovery_from_digest(digest, &signature)
        .expect("failed to recover the signing key");
    let (mut r, mut s) = ([0u8; 32], [0u8; 32]);
    r.copy_from_slice(&signature[..32]);
    s.copy_from_slice(&signature[32..]);
    Eip1559Signature {
        signature_y_parity: recovery_id.is_y_odd(),
        r: ethnum::u256::from_be_bytes(r),
        s: ethnum::u256::from_be_bytes(s),
    }
}

fn sign_authorization(
    key: &PrivateKey,
    chain_id: u64,
    delegate: &Address,
    nonce: u64,
) -> SignedAuthorization {
    let authorization = Authorization {
        chain_id,
        delegate: *delegate,
        nonce: TransactionNonce::from(nonce),
    };
    let signature = sign(key, &authorization.hash().0);
    SignedAuthorization {
        chain_id,
        delegate: *delegate,
        nonce: TransactionNonce::from(nonce),
        y_parity: signature.signature_y_parity,
        r: signature.r,
        s: signature.s,
    }
}

// ---------------------------------------------------------------------------
// Minimal ABI encoding / event decoding (no eth library needed).
// ---------------------------------------------------------------------------

enum Token {
    Word([u8; 32]),
    Array(Vec<[u8; 32]>),
}

fn abi(tokens: &[Token]) -> Vec<u8> {
    let head_len = 32 * tokens.len();
    let (mut head, mut tail) = (Vec::new(), Vec::new());
    for token in tokens {
        match token {
            Token::Word(word) => head.extend_from_slice(word),
            Token::Array(elements) => {
                head.extend_from_slice(&word_u256((head_len + tail.len()) as u128));
                tail.extend_from_slice(&word_u256(elements.len() as u128));
                elements.iter().for_each(|e| tail.extend_from_slice(e));
            }
        }
    }
    [head, tail].concat()
}

fn call(signature: &str, tokens: &[Token]) -> Vec<u8> {
    let selector = &Keccak256::hash(signature.as_bytes())[..4];
    [selector, &abi(tokens)].concat()
}

fn word_addr(address: &Address) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(address.as_ref());
    word
}

fn word_u256(value: u128) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[16..].copy_from_slice(&value.to_be_bytes());
    word
}

fn address_from_word(word: &[u8]) -> Address {
    let mut address = [0u8; 20];
    address.copy_from_slice(&word[12..32]);
    Address::new(address)
}

/// The bytes32 expected by the helper: byte 0 is the principal length, followed
/// by the principal bytes.
fn encode_principal(principal: &Principal) -> [u8; 32] {
    let bytes = principal.as_slice();
    let mut encoded = [0u8; 32];
    encoded[0] = bytes.len() as u8;
    encoded[1..=bytes.len()].copy_from_slice(bytes);
    encoded
}

/// Compiles `contract` from the Solidity source at env var `source_var` using the
/// vendored `solc`, returning its creation bytecode.
fn compile(source_var: &str, contract: &str) -> Vec<u8> {
    let solc = std::env::var("SOLC_BIN").expect("SOLC_BIN not set by Bazel");
    let source = std::env::var(source_var).expect("contract source env var not set by Bazel");
    let output = Command::new(&solc)
        .args([
            "--combined-json",
            "bin",
            // Pin the EVM version: EIP-7702 is a Prague feature, and this is the
            // fork anvil runs. Explicit so a newer solc default (osaka/fusaka)
            // cannot silently change the bytecode.
            "--evm-version",
            "prague",
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

fn deploy_code(bytecode: &[u8], constructor_args: &[Token]) -> Vec<u8> {
    [bytecode, &abi(constructor_args)].concat()
}

struct ReceivedEvent {
    owner: Address,
    principal: [u8; 32],
    amount: u128,
}

fn received_events(receipt: &Value, helper: &Address) -> Vec<ReceivedEvent> {
    let topic0 = to_hex(&Keccak256::hash(
        b"ReceivedEthOrErc20(address,address,uint256,bytes32,bytes32)".as_ref(),
    ));
    receipt["logs"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|log| {
            let topics = log["topics"].as_array().unwrap();
            topics[0].as_str().unwrap().eq_ignore_ascii_case(&topic0)
                && log["address"]
                    .as_str()
                    .unwrap()
                    .eq_ignore_ascii_case(&to_hex(helper.as_ref()))
        })
        .map(|log| {
            let topics = log["topics"].as_array().unwrap();
            let data = from_hex(log["data"].as_str().unwrap());
            ReceivedEvent {
                owner: address_from_word(&from_hex(topics[2].as_str().unwrap())),
                principal: from_hex(topics[3].as_str().unwrap()).try_into().unwrap(),
                amount: u128_from_be(&data[16..32]),
            }
        })
        .collect()
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

    fn rpc(&self, method: &str, params: Value) -> Value {
        let body: Value = reqwest::blocking::Client::new()
            .post(&self.url)
            .json(&json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}))
            .send()
            .unwrap()
            .json()
            .unwrap();
        assert!(
            body.get("error").map(Value::is_null).unwrap_or(true),
            "RPC {method} failed: {}",
            body["error"]
        );
        body["result"].clone()
    }

    fn chain_id(&self) -> u64 {
        hex_to_u64(&self.rpc("eth_chainId", json!([])))
    }

    fn nonce(&self, address: &Address) -> u64 {
        hex_to_u64(&self.rpc(
            "eth_getTransactionCount",
            json!([to_hex(address.as_ref()), "latest"]),
        ))
    }

    fn balance(&self, address: &Address) -> u128 {
        let balance = self.rpc(
            "eth_getBalance",
            json!([to_hex(address.as_ref()), "latest"]),
        );
        u128::from_str_radix(balance.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
    }

    fn code(&self, address: &Address) -> Vec<u8> {
        from_hex(
            self.rpc("eth_getCode", json!([to_hex(address.as_ref()), "latest"]))
                .as_str()
                .unwrap(),
        )
    }

    fn call(&self, to: &Address, data: &[u8]) -> Vec<u8> {
        from_hex(
            self.rpc(
                "eth_call",
                json!([{"to": to_hex(to.as_ref()), "input": to_hex(data)}, "latest"]),
            )
            .as_str()
            .unwrap(),
        )
    }

    fn usdt_balance(&self, usdt: &Address, who: &Address) -> u128 {
        let out = self.call(
            usdt,
            &call("balanceOf(address)", &[Token::Word(word_addr(who))]),
        );
        u128_from_be(&out[16..32])
    }

    fn send_transaction(
        &self,
        from: &Address,
        to: Option<&Address>,
        data: &[u8],
        gas: Option<u64>,
    ) -> String {
        let mut tx = json!({"from": to_hex(from.as_ref()), "input": to_hex(data)});
        if let Some(to) = to {
            tx["to"] = json!(to_hex(to.as_ref()));
        }
        if let Some(gas) = gas {
            tx["gas"] = json!(format!("0x{gas:x}"));
        }
        self.rpc("eth_sendTransaction", json!([tx]))
            .as_str()
            .unwrap()
            .to_string()
    }

    fn send_raw(&self, raw: &[u8]) -> String {
        self.rpc("eth_sendRawTransaction", json!([to_hex(raw)]))
            .as_str()
            .unwrap()
            .to_string()
    }

    fn deploy(&self, from: &Address, code: &[u8]) -> Address {
        let hash = self.send_transaction(from, None, code, None);
        let receipt = self.await_receipt(&hash);
        assert!(status_ok(&receipt), "deployment reverted");
        address_from_hex(receipt["contractAddress"].as_str().unwrap())
    }

    fn send_eip7702(
        &self,
        key: &PrivateKey,
        chain_id: u64,
        to: &Address,
        data: Vec<u8>,
        authorization_list: Vec<SignedAuthorization>,
    ) -> Value {
        let from = eth_address(&key.public_key());
        let tx = Eip7702TransactionRequest {
            chain_id,
            nonce: TransactionNonce::from(self.nonce(&from)),
            max_priority_fee_per_gas: WeiPerGas::new(PRIORITY_FEE),
            max_fee_per_gas: WeiPerGas::new(MAX_FEE),
            gas_limit: GasAmount::new(SWEEP_GAS_LIMIT),
            destination: *to,
            amount: Wei::ZERO,
            data,
            access_list: AccessList::new(),
            authorization_list,
        };
        let signature = sign(key, &tx.hash().0);
        let hash = self.send_raw(&Signed::from((tx, signature)).raw_transaction_hex());
        self.await_receipt(&hash)
    }

    fn send_eip1559(&self, key: &PrivateKey, chain_id: u64, to: &Address, data: Vec<u8>) -> Value {
        let from = eth_address(&key.public_key());
        let tx = Eip1559TransactionRequest {
            chain_id,
            nonce: TransactionNonce::from(self.nonce(&from)),
            max_priority_fee_per_gas: WeiPerGas::new(PRIORITY_FEE),
            max_fee_per_gas: WeiPerGas::new(MAX_FEE),
            gas_limit: GasAmount::new(SWEEP_GAS_LIMIT),
            destination: *to,
            amount: Wei::ZERO,
            data,
            access_list: AccessList::new(),
        };
        let signature = sign(key, &tx.hash().0);
        let hash = self.send_raw(&Signed::from((tx, signature)).raw_transaction_hex());
        self.await_receipt(&hash)
    }

    fn await_receipt(&self, tx_hash: &str) -> Value {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            let receipt = self.rpc("eth_getTransactionReceipt", json!([tx_hash]));
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
            .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": []}))
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

fn gas_used(receipt: &Value) -> u64 {
    hex_to_u64(&receipt["gasUsed"])
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

fn hex_to_u64(value: &Value) -> u64 {
    u64::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

fn u128_from_be(bytes: &[u8]) -> u128 {
    u128::from_be_bytes(bytes.try_into().unwrap())
}
