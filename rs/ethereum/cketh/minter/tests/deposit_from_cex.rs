//! Integration tests showcasing the support of deposits from central exchanges:
//! 1) the user notifies the minter of an upcoming deposit of a given token.
//! 2) the minter watches the balance of that address for roughly 24H
//! 3) if the address' balance is sufficient (roughly at least $10 equivalent), the minter proceeds with consolidating the funds.
//! 4) the deposit address delegates to a sweeper contract,
//!    whose purpose is to move the ERC-20 from the deposit address by calling the helper smart contract (DepositHelperWithSubaccount.sol),
//!    to trigger the original deposit flow. This requires in particular the minter attesting that the given deposit address is for a given
//!    principal and subaccount.

use assert_matches::assert_matches;
use ic_cketh_minter::balance_scan::batcher::{
    BalanceOfCall, decode_balance_batch, encode_balance_batch,
};
use ic_cketh_minter::deposit_address::DepositAddress;
use ic_cketh_minter::endpoints::DepositStatus;
use ic_cketh_minter::endpoints::events::EventPayload;
use ic_cketh_minter::numeric::Erc20Value;
use ic_cketh_test_utils::anvil::{
    Anvil, DEV_ACCOUNT, SentTransaction, address_from_hex, deploy_mock_erc20,
};
use ic_cketh_test_utils::ckerc20::{CkErc20Setup, Erc20Token};
use ic_cketh_test_utils::live::{CexDeposit, DepositPlan, LiveSetup};
use ic_cketh_test_utils::{CkEthSetup, SWEEPER_ADDRESS};
use ic_ethereum_types::Address;

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
/// Three independent depositors each fund a single token — USDT at twice its minimum, USDC at
/// exactly its minimum, and USDT at a tenth of it, every amount derived from the minimum the
/// minter itself reports through `get_minter_info` — so the scan reads several addresses and
/// tokens and must apply the per-token minimum to each. Only the two at-or-above-minimum deposits
/// are flagged as candidates; the below-minimum deposit is scanned but not flagged.
#[test]
fn should_flag_only_deposits_at_or_above_the_per_token_minimum() {
    const DEPOSIT_SUBACCOUNT: [u8; 32] = [42; 32];

    let setup = LiveSetup::<CkErc20Setup>::new();
    // `supported_erc20_tokens_owned()` registers ckUSDC then ckUSDT, in that order.
    let [usdc, usdt]: [Erc20Token; 2] = setup
        .supported_erc20_tokens_owned()
        .try_into()
        .expect("expected exactly 2 supported tokens");
    let usdt_minimum = setup.minimum_deposit_amount(&usdt);
    let usdt_above_minimum = 2 * usdt_minimum;
    let usdc_at_minimum = setup.minimum_deposit_amount(&usdc);
    let usdt_below_minimum = usdt_minimum / 10;
    let plans = [
        (setup.depositor(1), usdt.clone(), usdt_above_minimum),
        (setup.depositor(2), usdc.clone(), usdc_at_minimum),
        (setup.depositor(3), usdt.clone(), usdt_below_minimum),
    ]
    .map(|(owner, token, amount)| DepositPlan {
        owner,
        subaccount: DEPOSIT_SUBACCOUNT,
        token,
        amount,
    });

    let (setup, deposits) = setup
        .call_minter_deposit_erc20(plans)
        .expect_deposit_responses();
    let setup = setup
        .credit_deposits_from_cex(&deposits)
        .expect_deposit_balances_on_anvil()
        .setup;

    assert_matches!(
        setup.await_scan(setup.depositor(1), DEPOSIT_SUBACCOUNT, &usdt).status,
        DepositStatus::AwaitingSweep(detected)
            if detected.erc20_contract_address == usdt.contract.address
                && detected.scanned_balance == usdt_above_minimum
                && detected.detected_at_block > 0_u8
    );
    assert_matches!(
        setup.await_scan(setup.depositor(2), DEPOSIT_SUBACCOUNT, &usdc).status,
        DepositStatus::AwaitingSweep(detected)
            if detected.erc20_contract_address == usdc.contract.address
                && detected.scanned_balance == usdc_at_minimum
                && detected.detected_at_block > 0_u8
    );
    assert_matches!(
        setup.await_scan(setup.depositor(3), DEPOSIT_SUBACCOUNT, &usdt).status,
        DepositStatus::Scanning { scan_count, last_scanned_block, .. }
            if scan_count >= 1 && last_scanned_block.is_some()
    );
}

#[test]
fn should_fund_the_sweeper_address_by_burning_cketh_from_the_fee_account() {
    let setup = LiveSetup::<CkEthSetup>::new()
        .fund_fee_account()
        .expect_fee_account_credited();
    // Only the fee account is funded: sweep gas must come from there and nowhere else. Read before
    // the minter is armed, since the funding decision reads nothing off the chain and so its first
    // run burns within milliseconds of the upgrade below — far too fast to snapshot after it.
    let baseline = setup.funding_baseline();
    setup
        .upgrade_minter()
        .expect_sweeper_address(&address_from_hex(SWEEPER_ADDRESS))
        .expect_sweeper_starts_empty()
        .expect_eth_received()
        .expect_funding_backed_by_burn(&baseline);
}

#[test]
fn should_credit_twenty_cex_deposits_through_one_sweep_per_token() {
    /// Ten depositors per token, so each sweep is a ten-deposit single-token batch — directly
    /// comparable with `deposit_from_cex_demo`'s measured scenarios.
    const DEPOSITORS_PER_TOKEN: u64 = 10;

    let setup = LiveSetup::<CkErc20Setup>::new()
        .fund_fee_account()
        .expect_fee_account_credited()
        .upgrade_minter()
        .expect_sweeper_address_derived()
        .expect_eth_received()
        .expect_funding_finalized();

    let sweeper = setup.await_sweeper_address();
    let funded_gas = setup.anvil_eth_balance(&sweeper);
    let delegate = setup.sweep_contracts().delegate;
    let [usdc, usdt]: [Erc20Token; 2] = setup
        .supported_erc20_tokens_owned()
        .try_into()
        .expect("expected exactly 2 supported tokens");
    let usdc_deposit = 10 * setup.minimum_deposit_amount(&usdc);
    let usdt_deposit = 15 * setup.minimum_deposit_amount(&usdt);

    // Every depositor gets a distinct principal and a distinct subaccount, so no two share a
    // deposit address and each attestation binds a different account.
    let plans: Vec<DepositPlan> = (0..2 * DEPOSITORS_PER_TOKEN)
        .map(|index| {
            let (token, amount) = if index < DEPOSITORS_PER_TOKEN {
                (usdc.clone(), usdc_deposit)
            } else {
                (usdt.clone(), usdt_deposit)
            };
            DepositPlan {
                owner: setup.depositor(index),
                subaccount: [u8::try_from(index).unwrap(); 32],
                token,
                amount,
            }
        })
        .collect();

    let (setup, deposits) = setup
        .call_minter_deposit_erc20(plans)
        .expect_deposit_responses();
    let setup = setup.assert_deposit_addresses_bare(&deposits);

    // The CEX withdrawals: a plain ERC-20 transfer to each address, carrying no principal.
    let setup = setup
        .credit_deposits_from_cex(&deposits)
        .expect_deposit_balances_on_anvil()
        .expect_each_awaiting_sweep();

    // One sweep per token, and nothing more.
    let (setup, sweeps) = setup
        .await_sweeps(&sweeper, 2)
        .expect_all_delegating_sweeps();
    assert_sweep_gas_near_demo(&sweeps, DEPOSITORS_PER_TOKEN);

    let setup = setup
        .assert_sweeps_batched_per_token(&deposits)
        .assert_addresses_swept_empty(&deposits)
        .assert_minter_holds_swept_totals(&deposits)
        .assert_delegations_installed(&deposits, &delegate)
        .assert_sweeper_spent_gas(&sweeper, funded_gas);

    setup.expect_mints(&deposits);
}

#[test]
fn should_sweep_a_second_deposit_despite_resending_a_stale_authorization() {
    const DEPOSIT_SUBACCOUNT: [u8; 32] = [7; 32];

    let setup = LiveSetup::<CkErc20Setup>::new()
        .fund_fee_account()
        .expect_fee_account_credited()
        .upgrade_minter()
        .expect_sweeper_address_derived()
        .expect_eth_received()
        .expect_funding_finalized();

    let sweeper = setup.await_sweeper_address();
    let delegate = setup.sweep_contracts().delegate;
    let [usdc, _usdt]: [Erc20Token; 2] = setup
        .supported_erc20_tokens_owned()
        .try_into()
        .expect("expected exactly 2 supported tokens");
    let usdc_minimum = setup.minimum_deposit_amount(&usdc);
    let owner = setup.depositor(1);

    let (setup, first_deposits) = setup
        .call_minter_deposit_erc20([DepositPlan {
            owner,
            subaccount: DEPOSIT_SUBACCOUNT,
            token: usdc.clone(),
            amount: 3 * usdc_minimum,
        }])
        .expect_deposit_responses();
    let setup = setup
        .credit_deposits_from_cex(&first_deposits)
        .expect_deposit_balances_on_anvil()
        .expect_each_awaiting_sweep();
    let (setup, _first_sweeps) = setup
        .await_sweeps(&sweeper, 1)
        .expect_all_delegating_sweeps();
    let setup = setup
        .expect_sweeps_finalized(1)
        .expect_mints(&first_deposits);
    let address = first_deposits[0].address;
    assert_eq!(
        setup.anvil().transaction_count(&address),
        1,
        "applying the first sweep's authorization must spend the deposit address' nonce 0"
    );

    let second_deposits = [CexDeposit {
        amount: 2 * usdc_minimum,
        ..first_deposits[0].clone()
    }];
    let setup = setup
        .credit_deposits_from_cex(&second_deposits)
        .expect_deposit_balances_on_anvil()
        .setup;
    let (setup, second_registrations) = setup
        .call_minter_deposit_erc20([DepositPlan {
            owner,
            subaccount: DEPOSIT_SUBACCOUNT,
            token: usdc.clone(),
            amount: second_deposits[0].amount,
        }])
        .expect_deposit_responses();
    assert_eq!(
        second_registrations[0].address, address,
        "re-registering the pair must yield the same deposit address"
    );
    assert_matches!(
        setup.await_detection(owner, DEPOSIT_SUBACCOUNT, &usdc).status,
        DepositStatus::AwaitingSweep(detected) if detected.scanned_balance == second_deposits[0].amount
    );

    let (setup, sweeps) = setup
        .await_sweeps(&sweeper, 2)
        .expect_all_delegating_sweeps();
    let second_sweep = &sweeps[1];
    assert_eq!(
        setup.anvil().authorization_nonces(&second_sweep.hash),
        vec![0],
        "the re-sent authorization still names nonce 0, stale now that the address is at nonce 1"
    );
    assert_eq!(
        setup.anvil().transaction_count(&address),
        1,
        "a skipped stale authorization must not advance the deposit address' nonce"
    );

    let all_deposits = [first_deposits[0].clone(), second_deposits[0].clone()];
    let setup = setup
        .assert_delegations_installed(&all_deposits, &delegate)
        .assert_addresses_swept_empty(&second_deposits)
        .assert_minter_holds_swept_totals(&all_deposits)
        .expect_mints(&all_deposits);
    let mints = setup
        .minter_events()
        .into_iter()
        .filter(|event| matches!(event.payload, EventPayload::MintedCkErc20 { .. }))
        .count();
    assert_eq!(mints, 2, "each deposit flow must be credited exactly once");
}

fn assert_sweep_gas_near_demo(sweeps: &[SentTransaction], deposits_per_sweep: u64) {
    // `ATTESTED_SCENARIOS` in deposit_from_cex_demo.rs, EIP-7702 (first sweep) column.
    const DEMO_ONE_DEPOSIT: u64 = 98_000;
    const DEMO_TEN_DEPOSITS: u64 = 609_431;
    const GAS_BAND_PERCENT: u64 = 10;

    assert_eq!(
        deposits_per_sweep, 10,
        "the demo baseline is measured for ten-deposit sweeps"
    );
    for sweep in sweeps {
        let per_deposit = sweep.gas_used / deposits_per_sweep;
        println!(
            "[gas] {} deposits: {} total, {} per deposit \
             (demo: {DEMO_TEN_DEPOSITS} total, {} per deposit for ten; {DEMO_ONE_DEPOSIT} for one)",
            deposits_per_sweep,
            sweep.gas_used,
            per_deposit,
            DEMO_TEN_DEPOSITS / 10,
        );
        assert!(
            sweep.gas_used.abs_diff(DEMO_TEN_DEPOSITS) * 100
                <= DEMO_TEN_DEPOSITS * GAS_BAND_PERCENT,
            "a ten-deposit sweep used {} gas, more than {GAS_BAND_PERCENT}% away from the \
             demo-measured {DEMO_TEN_DEPOSITS}: {sweep:?}",
            sweep.gas_used,
        );
    }
}

fn holder_at(index: u64) -> Address {
    let mut bytes = [0_u8; 20];
    bytes[..8].copy_from_slice(&index.to_be_bytes());
    // Offset so no holder collides with the deployer or a low reserved address.
    bytes[0] = 0xd0;
    Address::new(bytes)
}
