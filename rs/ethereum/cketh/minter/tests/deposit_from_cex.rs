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
//! A final test drives the whole balance scan end to end through a live
//! PocketIC and the real EVM RPC canister (see
//! [`ic_cketh_test_utils::live_scan`]).
//!
//! The anvil node client and its ABI/solc helpers live in
//! [`ic_cketh_test_utils::anvil`]; `anvil` and `solc` are vendored via Bazel
//! (`ANVIL_BIN`, `SOLC_BIN`); see BUILD.bazel.

use assert_matches::assert_matches;
use candid::{Nat, Principal};
use ic_cketh_minter::balance_scan::batcher::{
    BalanceOfCall, decode_balance_batch, encode_balance_batch,
};
use ic_cketh_minter::deposit_address::DepositAddress;
use ic_cketh_minter::endpoints::DepositStatus;
use ic_cketh_minter::numeric::Erc20Value;
use ic_cketh_test_utils::anvil::{Anvil, DEV_ACCOUNT, address_from_hex, deploy_mock_erc20};
use ic_cketh_test_utils::ckerc20::Erc20Token;
use ic_cketh_test_utils::live_scan::{Holding, LiveBalanceScanSetup};
use ic_cketh_test_utils::{MINTER_ADDRESS, SWEEPER_ADDRESS};
use ic_ethereum_types::Address;
use icrc_ledger_types::icrc1::account::Account;
use std::str::FromStr;
use std::time::{Duration, Instant};

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

    anvil.fund(&token_a, &dev, &h1, 100);
    anvil.fund(&token_a, &dev, &h2, 250);
    anvil.fund(&token_b, &dev, &h1, 7);
    anvil.fund(&token_b, &dev, &h3, 999);

    let calls = vec![
        BalanceOfCall {
            token: token_a,
            holder: DepositAddress::new(h1),
        },
        BalanceOfCall {
            token: token_a,
            holder: DepositAddress::new(h2),
        },
        BalanceOfCall {
            token: token_a,
            holder: DepositAddress::new(h3),
        },
        BalanceOfCall {
            token: token_b,
            holder: DepositAddress::new(h1),
        },
        BalanceOfCall {
            token: token_b,
            holder: DepositAddress::new(h2),
        },
        BalanceOfCall {
            token: token_b,
            holder: DepositAddress::new(h3),
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
        let expected = anvil.erc20_balance(&call.token, call.holder.as_address());
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
        anvil.fund(&token, &dev, holder, (i as u128 + 1) * 1_000);
    }

    let calls: Vec<BalanceOfCall> = holders
        .iter()
        .map(|holder| BalanceOfCall {
            token,
            holder: DepositAddress::new(*holder),
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
    let holder = DepositAddress::new(Address::new([0x11; 20]));
    anvil.fund(&token, &dev, holder.as_address(), 500);

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
/// RPC canister (configured to route every provider to the harness' anvil node), so the minter's
/// periodic balance scan makes genuine outcalls through the IC's HTTPS-outcalls feature — reaching
/// anvil over HTTP — and reads real ERC-20 balances from it.
///
/// Three independent depositors each fund a single token — 20 USDT, 15 USDC and 1 USDT — so the
/// scan reads several addresses and tokens and must apply the per-token minimum to each. Only the
/// two at-or-above-minimum deposits are flagged as candidates; the 1 USDT deposit is scanned but,
/// being below the ~$10 minimum, is not.
#[test]
fn should_flag_only_deposits_at_or_above_the_per_token_minimum() {
    const DEPOSIT_SUBACCOUNT: [u8; 32] = [42; 32];
    // 6-decimal amounts; ckUSDC and ckUSDT share a 10_000_000 (~$10) candidate minimum.
    const USDT_ABOVE_MINIMUM: u128 = 20_000_000;
    const USDC_ABOVE_MINIMUM: u128 = 15_000_000;
    const USDT_BELOW_MINIMUM: u128 = 1_000_000;

    let setup = LiveBalanceScanSetup::new_live();
    // `supported_erc20_tokens()` registers ckUSDC then ckUSDT, in that order.
    let [usdc, usdt] = setup.supported_erc20_tokens() else {
        panic!("expected exactly 2 supported tokens")
    };
    let deposits = [
        (setup.depositor(1), usdt, USDT_ABOVE_MINIMUM),
        (setup.depositor(2), usdc, USDC_ABOVE_MINIMUM),
        (setup.depositor(3), usdt, USDT_BELOW_MINIMUM),
    ];

    let holdings: Vec<Holding<'_>> = deposits
        .iter()
        .map(|&(depositor, token, amount)| Holding {
            deposit: setup.register_deposit_address(depositor, DEPOSIT_SUBACCOUNT, token),
            token,
            amount,
        })
        .collect();
    setup.credit_deposits(&holdings);

    let deadline = Duration::from_secs(180);
    assert_matches!(
        setup.await_scan(setup.depositor(1), DEPOSIT_SUBACCOUNT, usdt, deadline).status,
        DepositStatus::AwaitingSweep(detected)
            if detected.erc20_contract_address == usdt.contract.address
                && detected.scanned_balance == USDT_ABOVE_MINIMUM
                && detected.detected_at_block > 0_u8
    );
    assert_matches!(
        setup.await_scan(setup.depositor(2), DEPOSIT_SUBACCOUNT, usdc, deadline).status,
        DepositStatus::AwaitingSweep(detected)
            if detected.erc20_contract_address == usdc.contract.address
                && detected.scanned_balance == USDC_ABOVE_MINIMUM
                && detected.detected_at_block > 0_u8
    );
    assert_matches!(
        setup.await_scan(setup.depositor(3), DEPOSIT_SUBACCOUNT, usdt, deadline).status,
        DepositStatus::Scanning { scan_count, last_scanned_block, .. }
            if scan_count >= 1 && last_scanned_block.is_some()
    );
}

fn holder_at(index: u64) -> Address {
    let mut bytes = [0_u8; 20];
    bytes[..8].copy_from_slice(&index.to_be_bytes());
    // Offset so no holder collides with the deployer or a low reserved address.
    bytes[0] = 0xd0;
    Address::new(bytes)
}

/// The whole deposit-from-CEX flow against a real EVM, end to end: two users register deposit
/// addresses for two different tokens, a CEX-style plain `transfer` funds each, and the minter —
/// with no further user action — detects both, sweeps them in **one** EIP-7702 transaction through
/// the real deposit helper, and credits each user the full amount on its ckERC20 ledger.
///
/// Everything runs for real: a live PocketIC hosting the minter, the EVM RPC canister, the
/// orchestrator and the ckUSDC/ckUSDT ledgers, making genuine HTTPS outcalls to an anvil node that
/// holds the deployed `CkDeposit` helper and `CkSweeperAttested` delegate. Only the sweeper
/// address' gas is shortcut: anvil credits it directly instead of the ckETH burn pipeline.
#[test]
fn should_credit_two_cex_deposits_through_one_eip7702_sweep() {
    const DEPOSIT_SUBACCOUNT: [u8; 32] = [7; 32];
    // 6-decimal amounts, both far above the ~$10 per-token candidate minimum.
    const USDC_DEPOSIT: u128 = 100_000_000;
    const USDT_DEPOSIT: u128 = 150_000_000;
    /// Enough for one batch sweep at anvil's gas price, with room for a fee bump.
    const SWEEPER_GAS_WEI: u128 = 1_000_000_000_000_000_000;

    let sweeper = address_from_hex(SWEEPER_ADDRESS);
    let setup = LiveBalanceScanSetup::new_live_with_sweeping(&sweeper, SWEEPER_GAS_WEI);
    let contracts = setup.sweep_contracts();
    let [usdc, usdt] = setup.supported_erc20_tokens() else {
        panic!("expected exactly 2 supported tokens")
    };

    let (user_one, user_two) = (setup.depositor(1), setup.depositor(2));
    let deposit_one = setup.register_deposit_address(user_one, DEPOSIT_SUBACCOUNT, usdc);
    let deposit_two = setup.register_deposit_address(user_two, DEPOSIT_SUBACCOUNT, usdt);
    assert_ne!(
        deposit_one, deposit_two,
        "distinct accounts must get distinct deposit addresses"
    );
    for deposit in [&deposit_one, &deposit_two] {
        assert!(
            setup.anvil().code(deposit).is_empty(),
            "a deposit address starts with no code"
        );
        assert_eq!(
            setup.anvil().balance(deposit),
            0,
            "a deposit address never needs ETH of its own"
        );
    }

    // The CEX withdrawal: a plain ERC-20 transfer to each address, carrying no principal.
    setup.credit_deposits(&[
        Holding {
            deposit: deposit_one,
            token: usdc,
            amount: USDC_DEPOSIT,
        },
        Holding {
            deposit: deposit_two,
            token: usdt,
            amount: USDT_DEPOSIT,
        },
    ]);

    // Generous: the mint waits for the sweep's own helper event to be scraped, and log scraping runs
    // on a three-minute interval.
    let deadline = Duration::from_secs(600);
    assert_matches!(
        setup.await_scan(user_one, DEPOSIT_SUBACCOUNT, usdc, deadline).status,
        DepositStatus::AwaitingSweep(detected) if detected.scanned_balance == USDC_DEPOSIT
    );
    assert_matches!(
        setup.await_scan(user_two, DEPOSIT_SUBACCOUNT, usdt, deadline).status,
        DepositStatus::AwaitingSweep(detected) if detected.scanned_balance == USDT_DEPOSIT
    );

    // Fail here rather than at the mint if the sweep itself never goes out: the mint is downstream
    // of the sweep's own helper event, so a missing credit says nothing about which step broke.
    await_sweep(&setup, &sweeper, deadline);

    let minter = address_from_hex(MINTER_ADDRESS);
    let ck_usdc = setup.ckerc20_token("ckUSDC");
    let ck_usdt = setup.ckerc20_token("ckUSDT");
    await_credited(
        &setup,
        ck_usdc.ledger_canister_id,
        account(user_one, DEPOSIT_SUBACCOUNT),
        USDC_DEPOSIT,
        deadline,
    );
    await_credited(
        &setup,
        ck_usdt.ledger_canister_id,
        account(user_two, DEPOSIT_SUBACCOUNT),
        USDT_DEPOSIT,
        deadline,
    );

    // The funds left the deposit addresses and landed at the minter's main address.
    for (deposit, token, amount) in [
        (&deposit_one, usdc, USDC_DEPOSIT),
        (&deposit_two, usdt, USDT_DEPOSIT),
    ] {
        let contract = contract_address(token);
        assert_eq!(
            setup.anvil().erc20_balance(&contract, deposit),
            Erc20Value::from(0_u8),
            "the deposit address should have been swept empty"
        );
        assert_eq!(
            setup.anvil().erc20_balance(&contract, &minter),
            Erc20Value::from(amount),
            "the minter's main address should hold the swept balance"
        );
    }

    // Each address is now delegated to the sweeper contract, by the 23-byte EIP-7702 designator
    // `0xef0100 || delegate`, so a later sweep of it needs no authorization at all.
    for deposit in [&deposit_one, &deposit_two] {
        let mut designator = vec![0xef, 0x01, 0x00];
        designator.extend_from_slice(contracts.delegate.as_ref());
        assert_eq!(
            setup.anvil().code(deposit),
            designator,
            "the sweep should have installed the delegation"
        );
    }

    // The sweeper paid for the sweep itself; `await_sweep` already pinned it to one transaction.
    assert!(
        setup.anvil().balance(&sweeper) < SWEEPER_GAS_WEI,
        "the sweeper address pays for the sweep out of its own prepaid gas"
    );
}

/// Waits for the sweeper address to send its one transaction.
fn await_sweep(setup: &LiveBalanceScanSetup, sweeper: &Address, deadline: Duration) {
    let start = Instant::now();
    loop {
        // Read the chain, not the IC: anvil is a separate process, so these stay readable even if the
        // PocketIC instance goes away — which is exactly when a diagnostic is most wanted.
        let sent = setup.anvil().transaction_count(sweeper);
        println!(
            "[await_sweep] {:?} block={} sweeper_nonce={} sweeper_wei={}",
            start.elapsed(),
            setup.anvil().block_number(),
            sent,
            setup.anvil().balance(sweeper),
        );
        if sent > 0 {
            assert_eq!(
                sent, 1,
                "both deposits must be swept by a single transaction"
            );
            return;
        }
        assert!(
            start.elapsed() <= deadline,
            "the sweeper {sweeper} sent no transaction within {deadline:?}"
        );
        std::thread::sleep(Duration::from_secs(5));
    }
}

/// Waits until `account` holds exactly `expected` on `ledger_id`. The mint follows the sweep's own
/// finalized helper event through the minter's unchanged deposit pipeline, so this is what proves
/// the whole chain ran.
fn await_credited(
    setup: &LiveBalanceScanSetup,
    ledger_id: Principal,
    account: Account,
    expected: u128,
    deadline: Duration,
) {
    let start = Instant::now();
    loop {
        let balance = setup.balance_of_ledger(ledger_id, account);
        if balance == Nat::from(expected) {
            return;
        }
        assert!(
            start.elapsed() <= deadline,
            "{account:?} was credited {balance} instead of {expected} within {deadline:?}"
        );
        std::thread::sleep(Duration::from_secs(2));
    }
}

fn account(owner: Principal, subaccount: [u8; 32]) -> Account {
    Account {
        owner,
        subaccount: Some(subaccount),
    }
}

fn contract_address(token: &Erc20Token) -> Address {
    Address::from_str(&token.contract.address).unwrap()
}
