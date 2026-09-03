//! Integration tests showcasing the support of deposits from central exchanges:
//! 1) the user notifies the minter of an upcoming deposit of a given token.
//! 2) the minter watches the balance of that address for roughly 24H
//! 3) if the address' balance is sufficient (roughly at least $10 equivalent), the minter proceeds with consolidating the funds.
//! 4) the deposit address delegates to a sweeper contract,
//!    whose purpose is to move the ERC-20 from the deposit address by calling the helper smart contract (DepositHelperWithSubaccount.sol),
//!    to trigger the original deposit flow. This requires in particular the minter attesting that the given deposit address is for a given
//!    principal and subaccount.
//!
//! Three further tests drive sweeper fee funding adversarially: each takes a distinct way it can go
//! wrong through the same live pipeline and asserts the minter fails safe. Two are bounded
//! *negative* assertions — "the minter must not do X" cannot be proven outright — so they watch
//! across several withdrawal-timer ticks, bought by pushing the instance's clock forward. There is
//! no live fee-spike test: that ceiling is pinned exactly by the unit tests, and reproducing it here
//! would mean driving anvil's base fee up over several ticks for little extra signal.

use assert_matches::assert_matches;
use candid::Principal;
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
use ic_cketh_test_utils::ckerc20::Erc20Token;
use ic_cketh_test_utils::live::{
    AWAIT_DEADLINE, Holding, LiveSetup, SWEEPER_BURNED_NOT_YET_SPENT, SWEEPER_ETH_SPENT,
    SWEEPER_GAS_BALANCE, contract_address,
};
use ic_cketh_test_utils::{CkEthSetup, MINTER_ADDRESS, SWEEPER_ADDRESS};
use ic_ethereum_types::Address;
use icrc_ledger_types::icrc1::account::Account;
use std::collections::BTreeSet;
use std::str::FromStr;

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

    let setup = LiveSetup::new_balance_scan();
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

    assert_matches!(
        setup.await_scan(setup.depositor(1), DEPOSIT_SUBACCOUNT, usdt).status,
        DepositStatus::AwaitingSweep(detected)
            if detected.erc20_contract_address == usdt.contract.address
                && detected.scanned_balance == USDT_ABOVE_MINIMUM
                && detected.detected_at_block > 0_u8
    );
    assert_matches!(
        setup.await_scan(setup.depositor(2), DEPOSIT_SUBACCOUNT, usdc).status,
        DepositStatus::AwaitingSweep(detected)
            if detected.erc20_contract_address == usdc.contract.address
                && detected.scanned_balance == USDC_ABOVE_MINIMUM
                && detected.detected_at_block > 0_u8
    );
    assert_matches!(
        setup.await_scan(setup.depositor(3), DEPOSIT_SUBACCOUNT, usdt).status,
        DepositStatus::Scanning { scan_count, last_scanned_block, .. }
            if scan_count >= 1 && last_scanned_block.is_some()
    );
}

/// A budget, not a cost: driving stops the moment the transfer lands, so this only has to be more
/// ticks than the run needs. One sends the transfer; the spares cover a tick landing before the
/// funding task has burned, and a tick lost to an outcall the jump timed out.
const FUNDING_TICKS: u32 = 6;

#[test]
fn should_fund_the_sweeper_address_by_burning_cketh_from_the_fee_account() {
    let setup = LiveSetup::new_funding();

    // Only the fee account is funded: sweep gas must come from there and nowhere else. Read before
    // the minter is armed, since the funding decision reads nothing off the chain and so its first
    // run burns within milliseconds of the upgrade below — far too fast to snapshot after it.
    let supply_before = setup.cketh_total_supply();
    let fee_account_before = setup.cketh_balance_of(setup.fee_account());
    let minter_eth_before = setup.anvil_eth_balance(&setup.minter_address());

    setup.upgrade_minter();
    let sweeper = setup.await_sweeper_address();
    assert_eq!(
        setup.anvil_eth_balance(&sweeper),
        0,
        "the sweeper address must start empty, so any balance proves the funding landed"
    );

    let received = setup.await_eth_received(&sweeper, FUNDING_TICKS);

    let burned = supply_before
        .checked_sub(setup.cketh_total_supply())
        .expect("the funding must have burned ckETH, not minted it");
    assert!(burned > 0, "funding must burn ckETH");
    assert_eq!(
        fee_account_before - setup.cketh_balance_of(setup.fee_account()),
        burned,
        "the burn must be debited from the fee account"
    );

    // The ETH moved, and never more than was burned — the backing invariant, observed end to end.
    let spent = minter_eth_before - setup.anvil_eth_balance(&setup.minter_address());
    assert!(
        received > 0 && received < burned,
        "the sweeper receives the burned amount minus the fee, got received={received} burned={burned}"
    );
    assert!(
        spent <= burned,
        "the ETH debited from the main address ({spent}) must never exceed the ckETH \
         burned for it ({burned})"
    );
}

/// Several withdrawal-timer ticks, so a transfer that was going to happen would have — and would
/// have had more than one chance to.
const OBSERVATION_TICKS: u32 = 3;
/// Sending the transaction and seeing it confirmed are separate runs of the withdrawal timer, and
/// the minter has to observe `finalized` move past it in between. A budget rather than a cost —
/// driving stops as soon as the row clears — so it is set well above the three ticks that suffice.
const FINALIZATION_TICKS: u32 = 8;
#[test]
fn should_not_fund_when_the_fee_account_is_empty() {
    let setup = LiveSetup::new_funding_with_empty_fee_account();
    assert_eq!(setup.cketh_balance_of(setup.fee_account()), 0);

    // Armed only now: before this the check refuses for a different reason — no deposit has been
    // credited yet — and this test is about the burn failing, not the balance guard.
    setup.upgrade_minter();
    let sweeper = setup.await_sweeper_address();
    // Asserted here rather than after the observation window: the minter's canister log is a ring
    // buffer, and every tick that window buys makes each of the minter's periodic timers due at
    // once, so the window ends with this line long since evicted. Read now it also says something
    // sharper — the check ran, decided a funding was due, and reported why it could not make one.
    setup.await_minter_log("[fund_sweeper]: SKIPPING: failed to burn");

    let supply_before = setup.cketh_total_supply();
    let minter_eth_before = setup.anvil_eth_balance(&setup.minter_address());

    setup.assert_no_eth_received(&sweeper, OBSERVATION_TICKS);

    assert_eq!(
        setup.cketh_total_supply(),
        supply_before,
        "nothing may be burned when the fee account cannot cover the funding"
    );
    assert_eq!(
        setup.anvil_eth_balance(&setup.minter_address()),
        minter_eth_before,
        "no ETH may leave the main address"
    );
}

/// A sweeper that already holds plenty of gas must not be topped up again: burning ckETH for gas
/// already in place would be pure loss.
///
/// Arranged by letting a real funding land, which is the only thing that moves the balance bound the
/// decision reads — putting ETH at the address behind the minter's back would not, and that is the
/// point of the bound.
#[test]
fn should_not_fund_a_sweeper_above_the_low_water_mark() {
    let setup = LiveSetup::new_funding();
    setup.upgrade_minter();
    let sweeper = setup.await_sweeper_address();
    let funded = setup.await_eth_received(&sweeper, FUNDING_TICKS);
    // Waits for the transfer to finalize, not merely to land: the minter credits the bound when it
    // records the finalized transaction, so before that the next check would still see zero.
    setup.await_funding_finalized(FINALIZATION_TICKS);

    // Captured before the timers are re-armed, not after: the post-upgrade check runs on a
    // zero-delay timer and reads nothing off the chain, so a minter that wrongly funded again could
    // burn before these queries returned, and both assertions below would then compare against an
    // already-debited state — passing precisely when the behaviour they reject had happened.
    let supply_before = setup.cketh_total_supply();
    let fee_account_before = setup.cketh_balance_of(setup.fee_account());

    // The next scheduled check is a whole interval away, so re-arm the timers: from here a second
    // funding could succeed, and the point is that it declines.
    setup.upgrade_minter();
    // Without this the test passes for the wrong reason: a task that never ran also produces no
    // burn. Proving it ran and *declined* is the point. Read before the observation window for the
    // same ring-buffer reason as in the test above.
    setup.await_minter_log("at or above the low-water mark");

    // Watched by letting withdrawal-timer ticks pass rather than the wall clock: there is nothing
    // here to poll for — only ticks to give the minter the chance to act, and the assertions below
    // to show it did not.
    setup.advance_ticks(OBSERVATION_TICKS);

    assert_eq!(
        setup.cketh_total_supply(),
        supply_before,
        "a topped-up sweeper must not trigger a second burn"
    );
    assert_eq!(
        setup.cketh_balance_of(setup.fee_account()),
        fee_account_before,
        "the fee account must be untouched"
    );
    assert_eq!(
        setup.anvil_eth_balance(&sweeper),
        funded,
        "the sweeper balance must be left exactly as the first funding delivered it"
    );
    assert!(
        setup.metric_value(SWEEPER_GAS_BALANCE) > 0.0,
        "the bound must carry the funding that landed, or the decision above declined for the \
         wrong reason"
    );
}

/// A funding transaction that fails on chain is never reimbursed. No ETH reaches the sweeper — only
/// the gas the failed transaction still pays leaves the main address — and the ckETH stays burned,
/// so the burn minus that gas ends up as extra backing.
///
/// Has to be arranged, because it is otherwise unreachable: the sweeper is a code-less EOA precisely
/// so a bare transfer cannot fail. Placing code there gives the 21'000 base gas something to run and
/// nothing to run it with, so the transaction fails.
#[test]
fn should_not_reimburse_a_funding_transaction_that_fails_on_chain() {
    // Starts with an empty fee account for the same reason as the test above: the sweeper cannot be
    // arranged before the minter derives its address, and a funded fee account would let the
    // funding it attempts right afterwards succeed while the sweeper is still a plain EOA.
    let setup = LiveSetup::new_funding_with_empty_fee_account();
    setup.upgrade_minter();
    let sweeper = setup.await_sweeper_address();
    setup.await_minter_log("[fund_sweeper]: SKIPPING: failed to burn");

    // All 21'000 gas of a bare transfer is intrinsic, so the callee runs with none and the first
    // opcode that costs anything halts it. That is what fails the transaction here — `PUSH1` costs
    // 3 — and it is why the bytecode is not arbitrary: code beginning with the zero-cost `STOP`
    // would run to completion and succeed. Spelled PUSH1 0, PUSH1 0, REVERT, so the call would also
    // fail on its own terms if it were ever reached with gas to spare.
    setup.set_code(&sweeper, &[0x60, 0x00, 0x60, 0x00, 0xfd]);
    // Read back rather than assumed: an arrangement placed on the wrong account makes the whole
    // test vacuous, and the transfer then simply succeeds.
    assert!(
        !setup.code(&sweeper).is_empty(),
        "the code must be at {sweeper}"
    );

    // Deposited, not minted: the fee account is credited the way production credits it, which means
    // waiting for the scrape that finds the deposit before the baseline below is taken.
    setup.fund_fee_account();
    let supply_before = setup.cketh_total_supply();
    // The next scheduled check is a whole interval away, so re-arm the timers: from here the
    // funding proceeds, and the point is what happens when its transaction fails.
    setup.upgrade_minter();

    let burned = await_burn(&setup, supply_before);
    assert!(burned > 0, "funding must burn ckETH up front");

    // Waits for the transaction to finalize rather than watching for a fixed window: without this
    // the assertions below all hold while it is merely still in flight, which proves nothing about
    // what happens when it fails.
    //
    // What the minter's status endpoint reports for the funding is deliberately not asserted: it is
    // the ordinary pending-reimbursement state, imprecise here because nothing will ever settle it,
    // and giving it a status of its own would mean a new `retrieve_eth_status` variant — breaking
    // every existing client — for a state mainnet cannot reach. What matters is asserted below.
    setup.await_funding_finalized(FINALIZATION_TICKS);

    assert_eq!(
        setup.anvil_eth_balance(&sweeper),
        0,
        "the transfer failed, so no ETH may have reached the sweeper"
    );
    assert_eq!(
        setup.cketh_total_supply(),
        supply_before - burned,
        "a failed funding must NOT be reimbursed — the supply must stay reduced"
    );
    // Read as numbers rather than asserted non-zero: "some burn remains" would also hold if
    // finalization had recorded no gas at all, which is the other half of what this test claims.
    let spent = setup.metric_value(SWEEPER_ETH_SPENT);
    let surplus = setup.metric_value(SWEEPER_BURNED_NOT_YET_SPENT);
    assert!(
        spent > 0.0,
        "a failed transaction still pays its gas, so spend must be recorded"
    );
    assert_eq!(
        surplus,
        burned as f64 - spent,
        "the burn minus that gas is what stays as backing"
    );

    // Reimbursement runs on its own timer, so "never reimbursed" is not established by looking once
    // at finalization: a funding wrongly queued for reimbursement would mint on the next run of
    // that timer. One tick is longer than its interval, so it has had its chance.
    setup.advance_ticks(1);
    assert_eq!(
        setup.cketh_total_supply(),
        supply_before - burned,
        "the reimbursement timer must have found nothing to pay back"
    );
}

/// What a funding burned, waiting for the supply to drop.
fn await_burn(setup: &LiveSetup<CkEthSetup>, supply_before: u128) -> u128 {
    setup.poll_until(
        AWAIT_DEADLINE,
        |_| "no burn observed".to_string(),
        |setup| {
            supply_before
                .checked_sub(setup.cketh_total_supply())
                .filter(|burned| *burned > 0)
        },
    )
}

#[test]
fn should_credit_twenty_cex_deposits_through_one_sweep_per_token() {
    /// Ten depositors per token, so each sweep is a ten-deposit single-token batch — directly
    /// comparable with `deposit_from_cex_demo`'s measured scenarios.
    const DEPOSITORS_PER_TOKEN: u64 = 10;
    // 6-decimal amounts, both far above the ~$10 per-token candidate minimum.
    const USDC_DEPOSIT: u128 = 100_000_000;
    const USDT_DEPOSIT: u128 = 150_000_000;

    let sweeper = address_from_hex(SWEEPER_ADDRESS);
    let setup = LiveSetup::new_sweep();
    let funded_gas = setup.anvil_eth_balance(&sweeper);
    let contracts = setup.sweep_contracts();
    let [usdc, usdt] = setup.supported_erc20_tokens() else {
        panic!("expected exactly 2 supported tokens")
    };

    // Every depositor gets a distinct principal and a distinct subaccount, so no two share a
    // deposit address and each attestation binds a different account.
    let deposits: Vec<Deposit> = (0..2 * DEPOSITORS_PER_TOKEN)
        .map(|index| {
            let (token, amount) = if index < DEPOSITORS_PER_TOKEN {
                (usdc, USDC_DEPOSIT)
            } else {
                (usdt, USDT_DEPOSIT)
            };
            let owner = setup.depositor(index);
            let subaccount = [u8::try_from(index).unwrap(); 32];
            Deposit {
                owner,
                subaccount,
                token,
                amount,
                address: setup.register_deposit_address(owner, subaccount, token),
            }
        })
        .collect();

    let distinct: BTreeSet<_> = deposits.iter().map(|deposit| deposit.address).collect();
    assert_eq!(
        distinct.len(),
        deposits.len(),
        "every account must get its own deposit address"
    );
    for deposit in &deposits {
        assert!(
            setup.anvil().code(&deposit.address).is_empty(),
            "a deposit address starts with no code"
        );
        assert_eq!(
            setup.anvil().balance(&deposit.address),
            0,
            "a deposit address never needs ETH of its own"
        );
    }

    // The CEX withdrawals: a plain ERC-20 transfer to each address, carrying no principal.
    let holdings: Vec<Holding<'_>> = deposits.iter().map(Deposit::holding).collect();
    setup.credit_deposits(&holdings);

    for deposit in &deposits {
        assert_matches!(
            setup.await_scan(deposit.owner, deposit.subaccount, deposit.token).status,
            DepositStatus::AwaitingSweep(detected) if detected.scanned_balance == deposit.amount
        );
    }

    // One sweep per token, and nothing more.
    let sweeps = setup.await_sweeps(&sweeper, 2);
    for sweep in &sweeps {
        assert_eq!(
            sweep.transaction_type, 4,
            "a first sweep installs delegations, so it must be an EIP-7702 transaction: {sweep:?}"
        );
        assert!(sweep.succeeded, "the sweep reverted: {sweep:?}");
    }
    assert_sweep_gas_near_demo(&sweeps, DEPOSITORS_PER_TOKEN);

    // What each sweep actually batched, so that two transactions cannot pass as one per token.
    let mut batched: Vec<(Address, usize)> = setup
        .minter_events()
        .into_iter()
        .filter_map(|event| match event.payload {
            EventPayload::AcceptedSweepRequest { token, items, .. } => Some((
                Address::from_str(&token).expect("BUG: the sweep names an invalid token"),
                items.len(),
            )),
            _ => None,
        })
        .collect();
    batched.sort();
    let per_token = usize::try_from(DEPOSITORS_PER_TOKEN).unwrap();
    let mut expected = vec![
        (contract_address(usdc), per_token),
        (contract_address(usdt), per_token),
    ];
    expected.sort();
    assert_eq!(
        batched, expected,
        "each sweep must batch one token's ten deposits, not a mixed batch and a redundant one"
    );

    // The funds left every deposit address and landed at the minter's main address.
    let minter = address_from_hex(MINTER_ADDRESS);
    for deposit in &deposits {
        assert_eq!(
            setup
                .anvil()
                .erc20_balance(&contract_address(deposit.token), &deposit.address),
            Erc20Value::from(0_u8),
            "the deposit address should have been swept empty"
        );
    }
    for (token, amount) in [
        (usdc, USDC_DEPOSIT * u128::from(DEPOSITORS_PER_TOKEN)),
        (usdt, USDT_DEPOSIT * u128::from(DEPOSITORS_PER_TOKEN)),
    ] {
        assert_eq!(
            setup
                .anvil()
                .erc20_balance(&contract_address(token), &minter),
            Erc20Value::from(amount),
            "the minter's main address should hold everything swept of {}",
            token.contract.address
        );
    }

    // Every address is now delegated, by the 23-byte EIP-7702 designator `0xef0100 || delegate`.
    let mut designator = vec![0xef, 0x01, 0x00];
    designator.extend_from_slice(contracts.delegate.as_ref());
    for deposit in &deposits {
        assert_eq!(
            setup.anvil().code(&deposit.address),
            designator,
            "the sweep should have installed the delegation"
        );
    }
    assert!(
        setup.anvil().balance(&sweeper) < funded_gas,
        "the sweeper address pays for the sweeps out of its own prepaid gas"
    );

    // Only now the mint, which the unchanged deposit pipeline drives off each sweep's own helper
    // event — downstream of every effect asserted above.
    let ledgers = [
        (usdc, setup.ckerc20_token("ckUSDC").ledger_canister_id),
        (usdt, setup.ckerc20_token("ckUSDT").ledger_canister_id),
    ];
    for deposit in &deposits {
        let (_, ledger_id) = ledgers
            .iter()
            .find(|(token, _)| token.contract.address == deposit.token.contract.address)
            .expect("every deposited token has a ledger");
        let account = Account {
            owner: deposit.owner,
            subaccount: Some(deposit.subaccount),
        };
        setup.await_credited(*ledger_id, account, deposit.amount);
    }
}

/// One user's deposit: who it credits, which token, and the address the CEX sends to.
struct Deposit<'a> {
    owner: Principal,
    subaccount: [u8; 32],
    token: &'a Erc20Token,
    amount: u128,
    address: Address,
}

impl<'a> Deposit<'a> {
    fn holding(&self) -> Holding<'a> {
        Holding {
            deposit: self.address,
            token: self.token,
            amount: self.amount,
        }
    }
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
