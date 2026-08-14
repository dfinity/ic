//! Adversarial end-to-end coverage of sweeper fee funding, complementing the happy path in
//! `sweeper_funding.rs`. Each test drives a way funding can go wrong through the real pipeline and
//! asserts the minter fails safe.
//!
//! Two are bounded *negative* assertions — "the minter must not do X" cannot be proven outright, so
//! they watch for longer than a withdrawal-timer tick.
//!
//! No live fee-spike test: that ceiling is pinned exactly by the unit tests, and reproducing it here
//! would mean driving anvil's base fee up and waiting out several ticks for little extra signal.

use ic_cketh_test_utils::sweeper_funding::{FEE_ACCOUNT_BALANCE, SweeperFundingSetup};
use std::time::Duration;

/// Longer than a withdrawal-timer tick, so a transfer that was going to happen would have.
const OBSERVATION_WINDOW: Duration = Duration::from_secs(8 * 60);
const ABOVE_LOW_WATER_MARK: u128 = 500_000_000_000_000_000; // 0.5 ETH
/// Sending and finalizing both wait on the 6-minute withdrawal timer, so allow for two ticks.
const FINALIZATION_DEADLINE: Duration = Duration::from_secs(15 * 60);
/// How long to wait for the minter to record a funding it has already burned for. Generous for an
/// inter-canister hop, yet far below the six minutes before the transaction can finalize and clear
/// the row again.
const IN_FLIGHT_DEADLINE: Duration = Duration::from_secs(2 * 60);

#[test]
fn should_not_fund_when_the_fee_account_is_empty() {
    let setup = SweeperFundingSetup::new_live_with_empty_fee_account();
    assert_eq!(setup.cketh_balance_of(setup.fee_account()), 0);

    let sweeper = setup.await_sweeper_address(Duration::from_secs(180));
    let supply_before = setup.cketh_total_supply();
    let minter_eth_before = setup.anvil_eth_balance(&setup.minter_address());

    setup.assert_no_eth_received(&sweeper, OBSERVATION_WINDOW);

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
    assert!(
        setup
            .minter_logs()
            .iter()
            .any(|line| line.contains("[fund_sweeper]") && line.contains("failed to burn")),
        "the minter should report why funding was skipped; logs:\n{}",
        setup.minter_logs().join("\n")
    );
}

/// A sweeper that still holds plenty of gas must not be topped up: burning ckETH for gas already in
/// place would be pure loss, and it is the failure mode a wrongly-defaulted balance read would
/// cause.
#[test]
fn should_not_fund_a_sweeper_above_the_low_water_mark() {
    // Starts with an empty fee account so the install-time check cannot fund anything: it decides a
    // funding is due, fails to burn, and changes nothing. That is the only window in which the
    // sweeper can be arranged, since its address is undiscoverable until the minter caches its key.
    let setup = SweeperFundingSetup::new_live_with_empty_fee_account();
    let sweeper = setup.await_sweeper_address(Duration::from_secs(180));
    // Waits for the install-time check to have *finished* failing, not merely for the address to
    // exist: it reads the balance and attempts its burn immediately afterwards, so funding the fee
    // account any earlier would let that burn succeed and a funding proceed.
    setup.await_minter_log(
        "[fund_sweeper]: SKIPPING: failed to burn",
        Duration::from_secs(180),
    );

    setup.set_eth_balance(&sweeper, ABOVE_LOW_WATER_MARK);
    // The minter reads at `finalized`, which trails `latest` by two blocks.
    setup.mine(3);
    setup.mint_cketh(setup.fee_account(), FEE_ACCOUNT_BALANCE);

    // Captured before the timers are re-armed, not after: the post-upgrade check runs on a
    // zero-delay timer, so a minter that wrongly funded could burn before these queries returned
    // and both assertions below would then compare against an already-debited state — passing
    // precisely when the behaviour they reject had happened.
    let supply_before = setup.cketh_total_supply();
    let fee_account_before = setup.cketh_balance_of(setup.fee_account());

    // The next scheduled check is a whole interval away, so re-arm the timers: from here a funding
    // could succeed, and the point is that it declines.
    setup.upgrade_minter();

    let start = std::time::Instant::now();
    while start.elapsed() <= OBSERVATION_WINDOW {
        std::thread::sleep(Duration::from_secs(10));
        // Keeps the PocketIC instance — and the minter's timers — alive.
        let _ = setup.cketh_total_supply();
    }

    assert_eq!(
        setup.cketh_total_supply(),
        supply_before,
        "a topped-up sweeper must not trigger a burn"
    );
    assert_eq!(
        setup.cketh_balance_of(setup.fee_account()),
        fee_account_before,
        "the fee account must be untouched"
    );
    assert_eq!(
        setup.anvil_eth_balance(&sweeper),
        ABOVE_LOW_WATER_MARK,
        "the sweeper balance must be left exactly as it was"
    );
    // Without this the test passes for the wrong reason: a task that never read the balance also
    // produces no burn. Proving it ran and *declined* is the point.
    let prepaid = setup
        .dashboard_row("sweeper-prepaid-gas")
        .expect("the dashboard must have a prepaid-gas row");
    assert_ne!(
        prepaid, "never observed",
        "the funding task must have observed the balance and declined, not merely skipped"
    );
}

/// A funding transaction that fails on chain is never reimbursed; the burn becomes prepaid gas.
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
    let sweeper = setup.await_sweeper_address(Duration::from_secs(180));
    setup.await_minter_log(
        "[fund_sweeper]: SKIPPING: failed to burn",
        Duration::from_secs(180),
    );

    // PUSH1 0, PUSH1 0, REVERT — reverts on any call, with no return data.
    setup.set_code(&sweeper, &[0x60, 0x00, 0x60, 0x00, 0xfd]);
    // Read back rather than assumed: an arrangement placed on the wrong account makes the whole
    // test vacuous, and the transfer then simply succeeds.
    assert!(
        !setup.code(&sweeper).is_empty(),
        "the reverting code must be at {sweeper}"
    );

    setup.mint_cketh(setup.fee_account(), FEE_ACCOUNT_BALANCE);
    let supply_before = setup.cketh_total_supply();
    // The next scheduled check is a whole interval away, so re-arm the timers: from here the
    // funding proceeds, and the point is what happens when its transaction fails.
    setup.upgrade_minter();

    let burned = await_burn(&setup, supply_before, Duration::from_secs(180));
    assert!(burned > 0, "funding must burn ckETH up front");
    // Polled, not read once: the minter records the funding only after the ledger call it awaited
    // returns, so the supply `await_burn` watches drops before the dashboard shows the request.
    // Bounded well below the time to finalization, since the row clears again once that happens.
    let burn_index = await_in_flight_burn_index(&setup, IN_FLIGHT_DEADLINE);

    // Waits for the transaction to finalize rather than watching for a fixed window: without this
    // the assertions below all hold while it is merely still in flight, which proves nothing about
    // what happens when it fails.
    setup.await_funding_finalized(FINALIZATION_DEADLINE);
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
    let surplus = setup
        .dashboard_row("sweeper-burned-not-yet-spent")
        .expect("the dashboard must report the unspent burn");
    assert_ne!(
        surplus, "0 Wei",
        "the unreimbursed burn must be tracked as prepaid gas, got {surplus}"
    );
}

/// The burn index of the funding the minter currently has in flight, waiting for it to appear.
fn await_in_flight_burn_index(setup: &SweeperFundingSetup, deadline: Duration) -> u64 {
    let start = std::time::Instant::now();
    loop {
        if let Some(index) = setup.in_flight_funding_burn_index() {
            return index;
        }
        assert!(
            start.elapsed() <= deadline,
            "the minter burned ckETH but recorded no in-flight funding within {deadline:?}; \
             minter logs:\n{}",
            setup.minter_logs().join("\n")
        );
        std::thread::sleep(Duration::from_secs(2));
    }
}

fn await_burn(setup: &SweeperFundingSetup, supply_before: u128, deadline: Duration) -> u128 {
    let start = std::time::Instant::now();
    loop {
        let supply = setup.cketh_total_supply();
        if supply < supply_before {
            return supply_before - supply;
        }
        assert!(
            start.elapsed() <= deadline,
            "no burn observed within {deadline:?}; minter logs:\n{}",
            setup.minter_logs().join("\n")
        );
        std::thread::sleep(Duration::from_secs(2));
    }
}
