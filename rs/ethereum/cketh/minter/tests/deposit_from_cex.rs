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
use ic_cketh_minter::balance_scan::batcher::{
    BalanceOfCall, decode_balance_batch, encode_balance_batch,
};
use ic_cketh_minter::endpoints::DepositStatus;
use ic_cketh_minter::numeric::Erc20Value;
use ic_cketh_test_utils::anvil::{Anvil, DEV_ACCOUNT, address_from_hex, deploy_mock_erc20};
use ic_cketh_test_utils::live_scan::{CkErc20LiveScanSetup, Holding, SupportedToken};
use ic_ethereum_types::Address;
use std::time::Duration;

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
        anvil.fund(&token, &dev, holder, (i as u128 + 1) * 1_000);
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
    anvil.fund(&token, &dev, &holder, 500);

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

    let setup = CkErc20LiveScanSetup::new_live();
    let deposits = [
        (
            setup.depositor(1),
            SupportedToken::CkUsdt,
            USDT_ABOVE_MINIMUM,
        ),
        (
            setup.depositor(2),
            SupportedToken::CkUsdc,
            USDC_ABOVE_MINIMUM,
        ),
        (
            setup.depositor(3),
            SupportedToken::CkUsdt,
            USDT_BELOW_MINIMUM,
        ),
    ];

    let holdings: Vec<Holding> = deposits
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
        setup.await_scan(setup.depositor(1), DEPOSIT_SUBACCOUNT, SupportedToken::CkUsdt, deadline).status,
        DepositStatus::AwaitingSweep(detected)
            if detected.token == SupportedToken::CkUsdt.contract().to_string()
                && detected.scanned_balance == USDT_ABOVE_MINIMUM
                && detected.detected_at_block > 0_u8
    );
    assert_matches!(
        setup.await_scan(setup.depositor(2), DEPOSIT_SUBACCOUNT, SupportedToken::CkUsdc, deadline).status,
        DepositStatus::AwaitingSweep(detected)
            if detected.token == SupportedToken::CkUsdc.contract().to_string()
                && detected.scanned_balance == USDC_ABOVE_MINIMUM
                && detected.detected_at_block > 0_u8
    );
    assert_matches!(
        setup.await_scan(setup.depositor(3), DEPOSIT_SUBACCOUNT, SupportedToken::CkUsdt, deadline).status,
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
