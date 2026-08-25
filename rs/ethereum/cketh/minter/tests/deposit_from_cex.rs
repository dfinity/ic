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
//! Two further tests drive whole features end to end through a live PocketIC
//! and the real EVM RPC canister: the balance scan (see
//! [`ic_cketh_test_utils::live_scan`]) and sweeper fee funding, which deposits
//! through the production helper contract and then watches the minter burn
//! ckETH from its fee subaccount to pay for sweep gas (see
//! [`ic_cketh_test_utils::sweeper_funding`]).
//!
//! Three further tests drive funding adversarially: each one takes a distinct
//! way it can go wrong through that same live pipeline and asserts the minter
//! fails safe. Two are bounded *negative* assertions — "the minter must not do
//! X" cannot be proven outright, so they watch across several
//! withdrawal-timer ticks, bought by pushing the instance's clock forward.
//! There is no live fee-spike test: that ceiling is pinned exactly by the unit
//! tests, and reproducing it here would mean driving anvil's base fee up over
//! several ticks for little extra signal.
//!
//! The anvil node client and its ABI/solc helpers live in
//! [`ic_cketh_test_utils::anvil`]; `anvil` and `solc` are vendored via Bazel
//! (`ANVIL_BIN`, `SOLC_BIN`); see BUILD.bazel.

use assert_matches::assert_matches;
use ic_cketh_minter::balance_scan::batcher::{
    BalanceOfCall, decode_balance_batch, encode_balance_batch,
};
use ic_cketh_minter::deposit_address::DepositAddress;
use ic_cketh_minter::endpoints::DepositStatus;
use ic_cketh_minter::numeric::Erc20Value;
use ic_cketh_test_utils::anvil::{Anvil, DEV_ACCOUNT, address_from_hex, deploy_mock_erc20};
use ic_cketh_test_utils::live_scan::{Holding, LiveBalanceScanSetup};
use ic_cketh_test_utils::sweeper_funding::{
    AWAIT_DEADLINE, FEE_ACCOUNT_BALANCE, SweeperFundingSetup,
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

/// A budget, not a cost: driving stops the moment the transfer lands, so this only has to be more
/// ticks than the run needs. One sends the transfer; the spares cover a tick landing before the
/// funding task has burned, and a tick lost to an outcall the jump timed out.
const FUNDING_TICKS: u32 = 6;

#[test]
fn should_fund_the_sweeper_address_by_burning_cketh_from_the_fee_account() {
    let setup = SweeperFundingSetup::new_live();

    // Only the fee account is funded: sweep gas must come from there and nowhere else. The ledger
    // baselines come from the harness, which took them before the minter could burn — the decision
    // reads nothing off the chain, so its first run lands too fast to snapshot from here.
    let supply_before = setup.supply_before_funding();
    let fee_account_before = setup.fee_account_before_funding();
    let minter_eth_before = setup.anvil_eth_balance(&setup.minter_address());

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
    let setup = SweeperFundingSetup::new_live_with_empty_fee_account();
    assert_eq!(setup.cketh_balance_of(setup.fee_account()), 0);

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
    let setup = SweeperFundingSetup::new_live();
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
    let prepaid = setup
        .dashboard_row("sweeper-prepaid-gas")
        .expect("the dashboard must have a prepaid-gas row");
    assert_ne!(
        prepaid, "0 Wei",
        "the bound must carry the funding that landed, or the decision above declined for the \
         wrong reason"
    );
}

/// A funding transaction that fails on chain is never reimbursed. No ETH reaches the sweeper — only
/// the gas the failed transaction still pays leaves the main address — and the ckETH stays burned,
/// so the burn minus that gas ends up as extra backing.
///
/// Has to be arranged, because it is otherwise unreachable: the sweeper is a code-less EOA precisely
/// so a bare transfer cannot fail. Placing code there leaves the 21'000 base gas with nothing to run
/// it, so the transaction fails.
#[test]
fn should_not_reimburse_a_funding_transaction_that_fails_on_chain() {
    // Starts with an empty fee account for the same reason as the test above: the sweeper cannot be
    // arranged before the minter derives its address, and a funded fee account would let the
    // funding it attempts right afterwards succeed while the sweeper is still a plain EOA.
    let setup = SweeperFundingSetup::new_live_with_empty_fee_account();
    let sweeper = setup.await_sweeper_address();
    setup.await_minter_log("[fund_sweeper]: SKIPPING: failed to burn");

    // PUSH1 0, PUSH1 0, REVERT — reverts on any call, with no return data.
    setup.set_code(&sweeper, &[0x60, 0x00, 0x60, 0x00, 0xfd]);
    // Read back rather than assumed: an arrangement placed on the wrong account makes the whole
    // test vacuous, and the transfer then simply succeeds.
    assert!(
        !setup.code(&sweeper).is_empty(),
        "the reverting code must be at {sweeper}"
    );

    // Deposited, not minted: the fee account is credited the way production credits it, which means
    // waiting for the scrape that finds the deposit before the baseline below is taken.
    setup.deposit(setup.fee_account(), FEE_ACCOUNT_BALANCE);
    setup.await_fee_account_credited();
    let supply_before = setup.cketh_total_supply();
    // The next scheduled check is a whole interval away, so re-arm the timers: from here the
    // funding proceeds, and the point is what happens when its transaction fails.
    setup.upgrade_minter();

    let burned = await_burn(&setup, supply_before);
    assert!(burned > 0, "funding must burn ckETH up front");
    // Polled, not read once: the minter records the funding only after the ledger call it awaited
    // returns, so the supply `await_burn` watches drops before the dashboard shows the request.
    // Bounded well below the time to finalization, since the row clears again once that happens.
    let burn_index = await_in_flight_burn_index(&setup);

    // Waits for the transaction to finalize rather than watching for a fixed window: without this
    // the assertions below all hold while it is merely still in flight, which proves nothing about
    // what happens when it fails.
    setup.await_funding_finalized(FINALIZATION_TICKS);
    let status = setup.withdrawal_status(burn_index);
    // Pending reimbursement is imprecise here — nothing will ever settle it — and deliberately so:
    // a status of its own meant adding a variant to `retrieve_eth_status`, which breaks every
    // existing client, to describe a state mainnet cannot reach. This test reaches it only by
    // placing code at an address derived from the minter's own key. The invariant that actually
    // matters is asserted below: the burn is never paid back.
    assert!(
        status.starts_with("PendingReimbursement("),
        "unexpected status for a failed funding: {status} (sweeper {sweeper}, {} bytes of code, \
         balance {})",
        setup.code(&sweeper).len(),
        setup.anvil_eth_balance(&sweeper),
    );

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
    let spent = wei_row(&setup, "sweeper-eth-spent");
    let surplus = wei_row(&setup, "sweeper-burned-not-yet-spent");
    assert!(
        spent > 0,
        "a failed transaction still pays its gas, so spend must be recorded"
    );
    assert_eq!(
        surplus,
        burned - spent,
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

/// A dashboard cell rendered as `1_000_000 Wei`, as a number.
fn wei_row(setup: &SweeperFundingSetup, id: &str) -> u128 {
    let cell = setup
        .dashboard_row(id)
        .unwrap_or_else(|| panic!("the dashboard must have a {id} row"));
    cell.trim_end_matches(" Wei")
        .replace('_', "")
        .parse()
        .unwrap_or_else(|e| panic!("unexpected {id} cell {cell:?}: {e}"))
}

/// The burn index of the funding the minter currently has in flight, waiting for it to appear.
fn await_in_flight_burn_index(setup: &SweeperFundingSetup) -> u64 {
    let start = std::time::Instant::now();
    loop {
        if let Some(index) = setup.in_flight_funding_burn_index() {
            return index;
        }
        assert!(
            start.elapsed() <= AWAIT_DEADLINE,
            "the minter burned ckETH but recorded no in-flight funding within {AWAIT_DEADLINE:?}; \
             minter logs:\n{}",
            setup.minter_logs().join("\n")
        );
        std::thread::sleep(Duration::from_secs(2));
    }
}

fn await_burn(setup: &SweeperFundingSetup, supply_before: u128) -> u128 {
    let start = std::time::Instant::now();
    loop {
        let supply = setup.cketh_total_supply();
        if supply < supply_before {
            return supply_before - supply;
        }
        assert!(
            start.elapsed() <= AWAIT_DEADLINE,
            "no burn observed within {AWAIT_DEADLINE:?}; minter logs:\n{}",
            setup.minter_logs().join("\n")
        );
        std::thread::sleep(Duration::from_secs(2));
    }
}

fn holder_at(index: u64) -> Address {
    let mut bytes = [0_u8; 20];
    bytes[..8].copy_from_slice(&index.to_be_bytes());
    // Offset so no holder collides with the deployer or a low reserved address.
    bytes[0] = 0xd0;
    Address::new(bytes)
}
