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
//! The test is table-driven over batch sizes 1, 10 and 20 (the design doc's
//! "Cost estimation" section sizes the `B=1` and `B=20` extremes). Each batch is
//! swept twice for the same addresses: first with an EIP-7702 transaction that
//! installs the delegations, then — after re-funding — with a plain EIP-1559
//! transaction reusing the persisted delegations. It asserts that per-deposit gas
//! amortizes as the batch grows and that the already-delegated EIP-1559 sweep is
//! cheaper than the EIP-7702 one.
//!
//! The same batch scenarios run against a second, `CkSweeperAttested` delegate
//! matching the proposed design where sweeping is *permissionless* but each sweep
//! carries a minter attestation (a deposit-key signature binding the address to
//! its IC account). Those sweeps are submitted by a non-minter relayer, and a
//! separate test shows a forged attestation is rejected.
//!
//! Runs the `anvil` binary vendored via `@foundry_bin_*` (see BUILD.bazel);
//! `ANVIL_BIN` points at it. Requires EIP-7702 support (foundry >= v1.0).

use candid::Principal;
use ethers_core::abi::{ParamType, Token};
use ethers_core::types::{Address as EthAddress, U256};
use ic_cketh_minter::numeric::{GasAmount, TransactionNonce, Wei, WeiPerGas};
use ic_cketh_minter::tx::{
    AccessList, Authorization, Eip1559TransactionRequest, Eip7702TransactionRequest,
    SignableTransaction, Signed, SignedAuthorization, TransactionSignature,
};
use ic_ethereum_types::Address;
use ic_secp256k1::{PrivateKey, PublicKey};
use ic_sha3::Keccak256;
use serde_json::Value;
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
// A fourth dev account standing in for an arbitrary third party (relayer): it
// submits the permissionless attested sweeps, demonstrating the sender need not
// be the minter.
const RELAYER_PRIVATE_KEY: &str =
    "7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6";

const USDT_SUPPLY: u128 = 1_000_000_000_000; // 1M USDT (6 decimals)
const DEPOSIT_AMOUNT: u128 = 10_000_000; // 10 USDT per deposit

// Generous, deterministic fees and a gas limit large enough for a batch of 20;
// the minter dev account is funded with 10000 ETH. Gas *used* (asserted below)
// is independent of these.
const PRIORITY_FEE: u128 = 1_000_000_000; // 1 gwei
const MAX_FEE: u128 = 50_000_000_000; // 50 gwei
const SWEEP_GAS_LIMIT: u128 = 5_000_000;

/// Each batch size is swept twice, for the same deposit addresses:
///   * `eip7702_*`: the first sweep, a type-0x04 transaction that installs each
///     deposit EOA's delegation (its authorization rides in the transaction) and
///     sweeps it — the full EIP-7702 cost.
///   * `eip1559_*`: a second sweep of the same addresses after re-funding; the
///     delegation already persists, so a plain EIP-1559 transaction suffices.
///
/// The flow is fully deterministic (fixed keys, fixed contracts, fresh chain), so
/// every figure is a constant. Per-deposit gas amortizes as the batch grows, and
/// the already-delegated EIP-1559 sweep is cheaper than the EIP-7702 one by the
/// delegation-install overhead.
struct BatchScenario {
    deposits: usize,
    eip7702_total_gas_used: u64,
    eip7702_average_gas_used: u64,
    eip1559_total_gas_used: u64,
    eip1559_average_gas_used: u64,
}

const SCENARIOS: [BatchScenario; 3] = [
    BatchScenario {
        deposits: 1,
        eip7702_total_gas_used: 94_932,
        eip7702_average_gas_used: 94_932,
        eip1559_total_gas_used: 63_252,
        eip1559_average_gas_used: 63_252,
    },
    BatchScenario {
        deposits: 10,
        eip7702_total_gas_used: 570_151,
        eip7702_average_gas_used: 57_015,
        eip1559_total_gas_used: 390_151,
        eip1559_average_gas_used: 39_015,
    },
    BatchScenario {
        deposits: 20,
        eip7702_total_gas_used: 1_113_373,
        eip7702_average_gas_used: 55_668,
        eip1559_total_gas_used: 753_373,
        eip1559_average_gas_used: 37_668,
    },
];

/// The same scenarios for the permissionless attested sweeper. Its per-sweep cost
/// is slightly higher than the caller-gated variant: the attestation adds an
/// `ecrecover` plus the signature calldata (r/s/v) per deposit.
const ATTESTED_SCENARIOS: [BatchScenario; 3] = [
    BatchScenario {
        deposits: 1,
        eip7702_total_gas_used: 98_000,
        eip7702_average_gas_used: 98_000,
        eip1559_total_gas_used: 66_320,
        eip1559_average_gas_used: 66_320,
    },
    BatchScenario {
        deposits: 10,
        eip7702_total_gas_used: 609_431,
        eip7702_average_gas_used: 60_943,
        eip1559_total_gas_used: 429_431,
        eip1559_average_gas_used: 42_943,
    },
    BatchScenario {
        deposits: 20,
        eip7702_total_gas_used: 1_192_900,
        eip7702_average_gas_used: 59_645,
        eip1559_total_gas_used: 832_900,
        eip1559_average_gas_used: 41_645,
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

    let mut previous_average = u64::MAX;
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
        let deposits = scenario.deposits as u64;
        let eip7702_average = gas.eip7702 / deposits;
        let eip1559_average = gas.eip1559 / deposits;
        println!(
            "batch of {}: EIP-7702 {} ({eip7702_average}/deposit), EIP-1559 {} ({eip1559_average}/deposit)",
            scenario.deposits, gas.eip7702, gas.eip1559
        );
        assert_gas(
            gas.eip7702,
            scenario.eip7702_total_gas_used,
            &format!("batch of {} EIP-7702 total", scenario.deposits),
        );
        assert_gas(
            eip7702_average,
            scenario.eip7702_average_gas_used,
            &format!("batch of {} EIP-7702 average", scenario.deposits),
        );
        assert_gas(
            gas.eip1559,
            scenario.eip1559_total_gas_used,
            &format!("batch of {} EIP-1559 total", scenario.deposits),
        );
        assert_gas(
            eip1559_average,
            scenario.eip1559_average_gas_used,
            &format!("batch of {} EIP-1559 average", scenario.deposits),
        );
        assert!(
            gas.eip1559 < gas.eip7702,
            "an already-delegated (EIP-1559) sweep must cost less than one installing the delegation (EIP-7702)"
        );
        assert!(
            eip7702_average < previous_average,
            "per-deposit gas should shrink as the batch grows"
        );
        previous_average = eip7702_average;
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
        ..
    } = deploy_contracts(&anvil, &minter, &cex);

    // A single funded deposit address.
    let principal = Principal::self_authenticating([42_u8]);
    let key = derive_deposit_key(&principal);
    let deposit = eth_address(&key.public_key());
    let tx = anvil.send_transaction(
        &cex,
        Some(&usdt),
        &call(
            "transfer(address,uint256)",
            &[address_token(&deposit), uint_token(DEPOSIT_AMOUNT)],
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
            Token::Array(vec![address_token(&usdt)]),
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
                Token::Array(vec![address_token(&usdt)]),
                bytes32_token(encode_principal(&Principal::anonymous())),
                bytes32_token([0_u8; 32]),
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
            Token::Array(vec![address_token(&usdt)]),
            bytes32_token(encode_principal(&principal)),
            bytes32_token([0_u8; 32]),
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

/// The proposed permissionless variant: the same batch sweeps, but through the
/// attested sweeper and submitted by a relayer that is NOT the minter.
#[test]
fn attested_sweep_is_permissionless_and_amortizes_gas() {
    let anvil = Anvil::start();
    let chain_id = anvil.chain_id();

    let minter = eth_address(&key_from_hex(MINTER_PRIVATE_KEY).public_key());
    let cex = eth_address(&key_from_hex(CEX_PRIVATE_KEY).public_key());
    let relayer_key = key_from_hex(RELAYER_PRIVATE_KEY);
    assert_ne!(
        eth_address(&relayer_key.public_key()),
        minter,
        "the relayer must not be the minter"
    );

    let contracts = deploy_contracts(&anvil, &minter, &cex);

    let mut previous_average = u64::MAX;
    for scenario in ATTESTED_SCENARIOS {
        let gas = sweep_batch_attested(
            &anvil,
            chain_id,
            &relayer_key,
            &minter,
            &cex,
            &contracts,
            scenario.deposits,
        );
        let deposits = scenario.deposits as u64;
        let eip7702_average = gas.eip7702 / deposits;
        let eip1559_average = gas.eip1559 / deposits;
        println!(
            "attested batch of {}: EIP-7702 {} ({eip7702_average}/deposit), EIP-1559 {} ({eip1559_average}/deposit)",
            scenario.deposits, gas.eip7702, gas.eip1559
        );
        assert_gas(
            gas.eip7702,
            scenario.eip7702_total_gas_used,
            &format!("attested batch of {} EIP-7702 total", scenario.deposits),
        );
        assert_gas(
            eip7702_average,
            scenario.eip7702_average_gas_used,
            &format!("attested batch of {} EIP-7702 average", scenario.deposits),
        );
        assert_gas(
            gas.eip1559,
            scenario.eip1559_total_gas_used,
            &format!("attested batch of {} EIP-1559 total", scenario.deposits),
        );
        assert_gas(
            eip1559_average,
            scenario.eip1559_average_gas_used,
            &format!("attested batch of {} EIP-1559 average", scenario.deposits),
        );
        assert!(
            gas.eip1559 < gas.eip7702,
            "an already-delegated (EIP-1559) sweep must cost less than one installing the delegation (EIP-7702)"
        );
        assert!(
            eip7702_average < previous_average,
            "per-deposit gas should shrink as the batch grows"
        );
        previous_average = eip7702_average;
    }
}

/// The attestation is what makes permissionless sweeping safe: a caller cannot
/// forge one for their own principal, and the genuine one credits the attested
/// account no matter who submits it.
#[test]
fn attested_sweep_rejects_a_forged_attestation() {
    let anvil = Anvil::start();
    let chain_id = anvil.chain_id();

    let minter = eth_address(&key_from_hex(MINTER_PRIVATE_KEY).public_key());
    let cex = eth_address(&key_from_hex(CEX_PRIVATE_KEY).public_key());
    let attacker_key = key_from_hex(ATTACKER_PRIVATE_KEY);
    let attacker = eth_address(&attacker_key.public_key());

    let Contracts {
        usdt,
        helper,
        attested,
        ..
    } = deploy_contracts(&anvil, &minter, &cex);

    // A single funded deposit, delegated to the attested sweeper (its
    // authorization rides in an otherwise-empty batch).
    let principal = Principal::self_authenticating([0xB0]);
    let key = derive_deposit_key(&principal);
    let deposit = eth_address(&key.public_key());
    fund(&anvil, &cex, &usdt, &[deposit]);
    let authorization = sign_authorization(&key, chain_id, &attested, 0);
    let delegate_only = call(
        "sweepErc20Batch((address,bytes32,bytes32,bytes32,bytes32,uint8)[],address[])",
        &[
            Token::Array(vec![]),
            Token::Array(vec![address_token(&usdt)]),
        ],
    );
    assert!(
        status_ok(&anvil.send_eip7702(
            &attacker_key,
            chain_id,
            &attested,
            delegate_only,
            vec![authorization]
        )),
        "delegation setup reverted"
    );
    assert!(
        !anvil.code(&deposit).is_empty(),
        "deposit should be delegated to the attested sweeper"
    );

    // The attacker forges an attestation for their own principal, signed with
    // their own key: it recovers to the attacker, not the deposit address.
    let attacker_principal = Principal::self_authenticating([0xC0]);
    let forged = attest(
        &attacker_key,
        chain_id,
        &helper,
        &attacker_principal,
        &[0_u8; 32],
    );
    let attack = anvil.send_transaction(
        &attacker,
        Some(&deposit),
        &call(
            "sweepErc20(address[],bytes32,bytes32,bytes32,bytes32,uint8)",
            &[
                Token::Array(vec![address_token(&usdt)]),
                bytes32_token(encode_principal(&attacker_principal)),
                bytes32_token([0_u8; 32]),
                bytes32_token(forged.r),
                bytes32_token(forged.s),
                uint_token(forged.v as u128),
            ],
        ),
        Some(300_000),
    );
    assert!(
        !status_ok(&anvil.await_receipt(&attack)),
        "a forged attestation must be rejected"
    );
    assert_eq!(
        anvil.usdt_balance(&usdt, &deposit),
        DEPOSIT_AMOUNT,
        "the attacker must not move the funds"
    );

    // The genuine attestation (deposit key over the real principal) sweeps it,
    // even when submitted by the attacker — sweeping is permissionless.
    let attestation = attest(&key, chain_id, &helper, &principal, &[0_u8; 32]);
    let sweep = call(
        "sweepErc20(address[],bytes32,bytes32,bytes32,bytes32,uint8)",
        &[
            Token::Array(vec![address_token(&usdt)]),
            bytes32_token(encode_principal(&principal)),
            bytes32_token([0_u8; 32]),
            bytes32_token(attestation.r),
            bytes32_token(attestation.s),
            uint_token(attestation.v as u128),
        ],
    );
    let receipt = anvil.send_eip1559(&attacker_key, chain_id, &deposit, sweep);
    assert!(status_ok(&receipt), "the genuine attested sweep reverted");
    assert_eq!(anvil.usdt_balance(&usdt, &deposit), 0, "deposit not swept");
    let events = received_events(&receipt, &helper);
    assert_eq!(events.len(), 1, "expected one ReceivedEthOrErc20 event");
    assert_eq!(events[0].principal, encode_principal(&principal));
}

struct Contracts {
    usdt: Address,
    helper: Address,
    /// Caller-gated sweeper delegate (only the minter may sweep).
    via_helper: Address,
    /// Permissionless sweeper delegate gated by a minter attestation.
    attested: Address,
}

/// Compiles and deploys the ERC-20, the real helper and both sweeper delegates.
fn deploy_contracts(anvil: &Anvil, minter: &Address, cex: &Address) -> Contracts {
    let usdt = anvil.deploy(
        cex,
        &deploy_code(
            &compile("MOCKUSDT_SOL", "MockUSDT"),
            &[address_token(cex), uint_token(USDT_SUPPLY)],
        ),
    );
    let helper = anvil.deploy(
        minter,
        &deploy_code(
            &compile("CKDEPOSIT_SOL", "CkDeposit"),
            &[address_token(minter)],
        ),
    );
    let via_helper = anvil.deploy(
        minter,
        &deploy_code(
            &compile("CKSWEEPER_VIA_HELPER_SOL", "CkSweeperViaHelper"),
            &[address_token(minter), address_token(&helper)],
        ),
    );
    let attested = anvil.deploy(
        minter,
        &deploy_code(
            &compile("CKSWEEPER_ATTESTED_SOL", "CkSweeperAttested"),
            &[address_token(&helper)],
        ),
    );
    assert_eq!(
        to_address(decode_one(
            ParamType::Address,
            &anvil.call(&helper, &call("getMinterAddress()", &[])),
        )),
        *minter,
        "helper minter mismatch"
    );
    Contracts {
        usdt,
        helper,
        via_helper,
        attested,
    }
}

/// Funds `n` fresh, unfunded deposit EOAs from the CEX, then sweeps them all to
/// the minter in ONE EIP-7702 batch transaction (gas paid by the minter). The
/// deposit EOAs' authorizations ride in the same transaction's authorization
/// list. Asserts every deposit is swept and emits the canonical event, and
/// returns the batch's gas used.
struct BatchGas {
    eip7702: u64,
    eip1559: u64,
}

/// Sweeps `n` deposit addresses to the minter twice, returning the gas each
/// sweep used. The first sweep is a type-0x04 (EIP-7702) transaction that
/// installs the delegations; the second, after re-funding the same addresses, is
/// a plain EIP-1559 transaction reusing the now-persisted delegations.
fn sweep_batch(
    anvil: &Anvil,
    chain_id: u64,
    minter_key: &PrivateKey,
    minter: &Address,
    cex: &Address,
    contracts: &Contracts,
    n: usize,
) -> BatchGas {
    let Contracts {
        usdt, via_helper, ..
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
    }

    let sweep_call = call(
        "sweepErc20Batch(address[],bytes32[],bytes32[],address[])",
        &[
            Token::Array(deposits.iter().map(address_token).collect()),
            Token::Array(
                principals
                    .iter()
                    .map(|p| bytes32_token(encode_principal(p)))
                    .collect(),
            ),
            Token::Array(vec![bytes32_token([0_u8; 32]); n]),
            Token::Array(vec![address_token(usdt)]),
        ],
    );

    // First sweep: an EIP-7702 transaction whose authorization list installs each
    // deposit EOA's delegation before the batch sweeps it.
    fund(anvil, cex, usdt, &deposits);
    let minter_before = anvil.usdt_balance(usdt, minter);
    let authorizations: Vec<SignedAuthorization> = keys
        .iter()
        .map(|key| sign_authorization(key, chain_id, via_helper, 0))
        .collect();
    let receipt = anvil.send_eip7702(
        minter_key,
        chain_id,
        via_helper,
        sweep_call.clone(),
        authorizations,
    );
    let eip7702 = assert_batch_swept(
        anvil,
        &receipt,
        contracts,
        minter,
        &deposits,
        &principals,
        minter_before,
    );

    // Second sweep of the SAME addresses: the delegation persists, so no
    // authorization is needed — a plain EIP-1559 transaction.
    for deposit in &deposits {
        assert!(
            !anvil.code(deposit).is_empty(),
            "the delegation should persist after the first sweep"
        );
    }
    fund(anvil, cex, usdt, &deposits);
    let minter_before = anvil.usdt_balance(usdt, minter);
    let receipt = anvil.send_eip1559(minter_key, chain_id, via_helper, sweep_call);
    let eip1559 = assert_batch_swept(
        anvil,
        &receipt,
        contracts,
        minter,
        &deposits,
        &principals,
        minter_before,
    );

    BatchGas { eip7702, eip1559 }
}

/// Funds each address with `DEPOSIT_AMOUNT` via a plain ERC-20 transfer from the
/// CEX.
fn fund(anvil: &Anvil, cex: &Address, usdt: &Address, deposits: &[Address]) {
    for deposit in deposits {
        let tx = anvil.send_transaction(
            cex,
            Some(usdt),
            &call(
                "transfer(address,uint256)",
                &[address_token(deposit), uint_token(DEPOSIT_AMOUNT)],
            ),
            None,
        );
        assert!(status_ok(&anvil.await_receipt(&tx)), "CEX transfer failed");
    }
}

/// Asserts the sweep credited each deposit to the minter via the canonical
/// helper event, and returns its gas used.
fn assert_batch_swept(
    anvil: &Anvil,
    receipt: &Value,
    contracts: &Contracts,
    minter: &Address,
    deposits: &[Address],
    principals: &[Principal],
    minter_before: u128,
) -> u64 {
    let Contracts { usdt, helper, .. } = contracts;
    assert!(status_ok(receipt), "batch sweep reverted");
    let events = received_events(receipt, helper);
    assert_eq!(
        events.len(),
        deposits.len(),
        "one ReceivedEthOrErc20 event per deposit"
    );
    for (event, (deposit, principal)) in events.iter().zip(deposits.iter().zip(principals)) {
        assert_eq!(event.owner, *deposit);
        assert_eq!(event.principal, encode_principal(principal));
        assert_eq!(event.amount, DEPOSIT_AMOUNT);
    }
    for deposit in deposits {
        assert_eq!(anvil.usdt_balance(usdt, deposit), 0, "deposit not swept");
    }
    assert_eq!(
        anvil.usdt_balance(usdt, minter),
        minter_before + DEPOSIT_AMOUNT * deposits.len() as u128,
        "minter did not receive every deposit"
    );
    gas_used(receipt)
}

/// Like [`sweep_batch`] but through the permissionless attested sweeper: the
/// sweeps are submitted by `sender_key` (a non-minter relayer) and each carries
/// an attestation by the deposit key instead of relying on minter caller-gating.
fn sweep_batch_attested(
    anvil: &Anvil,
    chain_id: u64,
    sender_key: &PrivateKey,
    minter: &Address,
    cex: &Address,
    contracts: &Contracts,
    n: usize,
) -> BatchGas {
    let Contracts {
        usdt,
        helper,
        attested,
        ..
    } = contracts;

    // Distinct principals, disjoint from the caller-gated test's addresses.
    let principals: Vec<Principal> = (0..n)
        .map(|i| Principal::self_authenticating([0xA0, n as u8, i as u8]))
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
    }

    // Each deposit key attests (as the minter would, via threshold ECDSA) to its
    // own IC account; the attestations become the batch's SweepItem structs.
    let items: Vec<Token> = keys
        .iter()
        .zip(&deposits)
        .zip(&principals)
        .map(|((key, deposit), principal)| {
            let a = attest(key, chain_id, helper, principal, &[0_u8; 32]);
            Token::Tuple(vec![
                address_token(deposit),
                bytes32_token(encode_principal(principal)),
                bytes32_token([0_u8; 32]), // subaccount
                bytes32_token(a.r),
                bytes32_token(a.s),
                uint_token(a.v as u128),
            ])
        })
        .collect();
    let sweep_call = call(
        "sweepErc20Batch((address,bytes32,bytes32,bytes32,bytes32,uint8)[],address[])",
        &[Token::Array(items), Token::Array(vec![address_token(usdt)])],
    );

    // First sweep: an EIP-7702 transaction (submitted by the relayer) whose
    // authorization list installs each deposit EOA's delegation.
    fund(anvil, cex, usdt, &deposits);
    let minter_before = anvil.usdt_balance(usdt, minter);
    let authorizations: Vec<SignedAuthorization> = keys
        .iter()
        .map(|key| sign_authorization(key, chain_id, attested, 0))
        .collect();
    let receipt = anvil.send_eip7702(
        sender_key,
        chain_id,
        attested,
        sweep_call.clone(),
        authorizations,
    );
    let eip7702 = assert_batch_swept(
        anvil,
        &receipt,
        contracts,
        minter,
        &deposits,
        &principals,
        minter_before,
    );

    // Second sweep of the SAME addresses: the delegation persists, so a plain
    // EIP-1559 transaction reusing the attestations suffices (replay is intended).
    fund(anvil, cex, usdt, &deposits);
    let minter_before = anvil.usdt_balance(usdt, minter);
    let receipt = anvil.send_eip1559(sender_key, chain_id, attested, sweep_call);
    let eip1559 = assert_batch_swept(
        anvil,
        &receipt,
        contracts,
        minter,
        &deposits,
        &principals,
        minter_before,
    );

    BatchGas { eip7702, eip1559 }
}

/// A minter attestation binding a deposit address to an IC account, as its
/// (r, s, v) signature components.
struct Attestation {
    r: [u8; 32],
    s: [u8; 32],
    v: u8,
}

/// Signs the attestation digest with the deposit address' own key (the minter's
/// role on the IC). The digest mirrors `CkSweeperAttested._attestationDigest`:
/// `keccak256("ck-deposit-owner" ‖ chain_id ‖ helper ‖ principal ‖ subaccount)`.
fn attest(
    key: &PrivateKey,
    chain_id: u64,
    helper: &Address,
    principal: &Principal,
    subaccount: &[u8; 32],
) -> Attestation {
    // The packed preimage mirrors the contract's
    // `abi.encodePacked("ck-deposit-owner", block.chainid, HELPER, principal,
    // subaccount)`: fixed-length fields, no padding between them.
    let mut chain_id_bytes = [0_u8; 32];
    chain_id_bytes[24..].copy_from_slice(&chain_id.to_be_bytes());
    let preimage: Vec<u8> = [
        b"ck-deposit-owner".as_ref(),
        &chain_id_bytes,
        helper.as_ref(),
        &encode_principal(principal),
        subaccount,
    ]
    .concat();
    let signature = sign(key, &Keccak256::hash(&preimage));
    Attestation {
        r: signature.r.to_be_bytes(),
        s: signature.s.to_be_bytes(),
        v: 27 + signature.signature_y_parity as u8,
    }
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
    let mut address = [0_u8; 20];
    address.copy_from_slice(&hash[12..]);
    Address::new(address)
}

fn sign(key: &PrivateKey, digest: &[u8; 32]) -> TransactionSignature {
    let signature = key.sign_digest_with_ecdsa(digest);
    let recovery_id = key
        .public_key()
        .try_recovery_from_digest(digest, &signature)
        .expect("failed to recover the signing key");
    let (mut r, mut s) = ([0_u8; 32], [0_u8; 32]);
    r.copy_from_slice(&signature[..32]);
    s.copy_from_slice(&signature[32..]);
    TransactionSignature {
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
// ABI encoding / decoding via ethers-core (ethabi).
// ---------------------------------------------------------------------------

/// A function call: the 4-byte selector followed by the ABI-encoded arguments.
fn call(signature: &str, tokens: &[Token]) -> Vec<u8> {
    let selector = &Keccak256::hash(signature.as_bytes())[..4];
    [selector, &ethers_core::abi::encode(tokens)].concat()
}

fn address_token(address: &Address) -> Token {
    Token::Address(EthAddress::from_slice(address.as_ref()))
}

fn uint_token(value: u128) -> Token {
    Token::Uint(U256::from(value))
}

fn bytes32_token(value: [u8; 32]) -> Token {
    Token::FixedBytes(value.to_vec())
}

/// Decodes a single ABI-encoded return value.
fn decode_one(param: ParamType, data: &[u8]) -> Token {
    ethers_core::abi::decode(&[param], data)
        .expect("ABI decode failed")
        .pop()
        .unwrap()
}

fn to_address(token: Token) -> Address {
    Address::new(token.into_address().unwrap().0)
}

/// The bytes32 expected by the helper: byte 0 is the principal length, followed
/// by the principal bytes.
fn encode_principal(principal: &Principal) -> [u8; 32] {
    let bytes = principal.as_slice();
    let mut encoded = [0_u8; 32];
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
    [bytecode, &ethers_core::abi::encode(constructor_args)].concat()
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
            // `amount` and `subaccount` are the non-indexed event fields; the
            // indexed `owner` and `principal` come from the topics.
            let amount = decode_one(ParamType::Uint(256), &data[..32])
                .into_uint()
                .unwrap()
                .as_u128();
            ReceivedEvent {
                owner: to_address(decode_one(
                    ParamType::Address,
                    &from_hex(topics[2].as_str().unwrap()),
                )),
                principal: from_hex(topics[3].as_str().unwrap()).try_into().unwrap(),
                amount,
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
            .json(
                &serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}),
            )
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
        hex_to_u64(&self.rpc("eth_chainId", serde_json::json!([])))
    }

    fn nonce(&self, address: &Address) -> u64 {
        hex_to_u64(&self.rpc(
            "eth_getTransactionCount",
            serde_json::json!([to_hex(address.as_ref()), "latest"]),
        ))
    }

    fn balance(&self, address: &Address) -> u128 {
        let balance = self.rpc(
            "eth_getBalance",
            serde_json::json!([to_hex(address.as_ref()), "latest"]),
        );
        u128::from_str_radix(balance.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
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

    fn call(&self, to: &Address, data: &[u8]) -> Vec<u8> {
        from_hex(
            self.rpc(
                "eth_call",
                serde_json::json!([{"to": to_hex(to.as_ref()), "input": to_hex(data)}, "latest"]),
            )
            .as_str()
            .unwrap(),
        )
    }

    fn usdt_balance(&self, usdt: &Address, who: &Address) -> u128 {
        let out = self.call(usdt, &call("balanceOf(address)", &[address_token(who)]));
        decode_one(ParamType::Uint(256), &out)
            .into_uint()
            .unwrap()
            .as_u128()
    }

    fn send_transaction(
        &self,
        from: &Address,
        to: Option<&Address>,
        data: &[u8],
        gas: Option<u64>,
    ) -> String {
        let mut tx = serde_json::json!({"from": to_hex(from.as_ref()), "input": to_hex(data)});
        if let Some(to) = to {
            tx["to"] = serde_json::json!(to_hex(to.as_ref()));
        }
        if let Some(gas) = gas {
            tx["gas"] = serde_json::json!(format!("0x{gas:x}"));
        }
        self.rpc("eth_sendTransaction", serde_json::json!([tx]))
            .as_str()
            .unwrap()
            .to_string()
    }

    fn send_raw(&self, raw: &[u8]) -> String {
        self.rpc("eth_sendRawTransaction", serde_json::json!([to_hex(raw)]))
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
        let hash = self.send_raw(&Signed::from((tx, signature)).raw_transaction_bytes());
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
        let hash = self.send_raw(&Signed::from((tx, signature)).raw_transaction_bytes());
        self.await_receipt(&hash)
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
