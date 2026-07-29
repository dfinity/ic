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
//! [`ic_cketh_test_utils::live_scan`]; `anvil` and `solc` are vendored via Bazel
//! (`ANVIL_BIN`, `SOLC_BIN`); see BUILD.bazel.

use ic_cketh_minter::balance_scan::batcher::{
    BalanceOfCall, decode_balance_batch, encode_balance_batch,
};
use ic_cketh_minter::numeric::Erc20Value;
use ic_cketh_test_utils::live_scan::{
    Anvil, CkErc20LiveScanSetup, DEV_ACCOUNT, address_from_hex, address_token, call,
    default_caller, deploy_mock_erc20, status_ok, uint_token,
};
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
/// RPC canister (configured to route every provider to the harness' anvil node), so the minter's
/// periodic balance scan issues genuine HTTPS outcalls and reads real ERC-20 balances from anvil.
///
/// The harness places the two supported tokens (ckUSDC, ckUSDT) at their real mainnet addresses and
/// credits the minter's derived deposit address above the scan's candidate threshold. The scan must
/// then flag that address as a deposit candidate for both tokens.
#[test]
fn should_scan_real_erc20_balances_through_the_evm_rpc_canister() {
    const DEPOSIT_SUBACCOUNT: [u8; 32] = [42; 32];
    // 20 USDC/USDT (6 decimals), comfortably above each token's ~$10 candidate minimum.
    const DEPOSIT_BALANCE: u128 = 20_000_000;

    let setup = CkErc20LiveScanSetup::new_live();
    let user = default_caller();
    let deposit = setup.register_deposit_address(user, DEPOSIT_SUBACCOUNT);
    setup.credit_deposit(&deposit, DEPOSIT_BALANCE);

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

fn holder_at(index: u64) -> Address {
    let mut bytes = [0_u8; 20];
    bytes[..8].copy_from_slice(&index.to_be_bytes());
    // Offset so no holder collides with the deployer or a low reserved address.
    bytes[0] = 0xd0;
    Address::new(bytes)
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
