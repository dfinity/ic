//! Adversarial end-to-end coverage of sweeper fee funding, complementing the happy path in
//! `sweeper_funding.rs`. Each test drives a way funding can go wrong through the real pipeline and
//! asserts the minter fails safe.
//!
//! Two are bounded *negative* assertions — "the minter must not do X" cannot be proven outright, so
//! they watch across several withdrawal-timer ticks, bought by pushing the instance's clock forward
//! rather than waiting them out.
//!
//! No live fee-spike test: that ceiling is pinned exactly by the unit tests, and reproducing it here
//! would mean driving anvil's base fee up and waiting out several ticks for little extra signal.

use ic_cketh_test_utils::sweeper_funding::{
    AWAIT_DEADLINE, FEE_ACCOUNT_BALANCE, SweeperFundingSetup,
};
use std::time::Duration;

/// Several withdrawal-timer ticks, so a transfer that was going to happen would have — and would
/// have had more than one chance to.
const OBSERVATION_TICKS: u32 = 3;
/// Sending the transaction and seeing it confirmed are separate runs of the withdrawal timer, and
/// the minter has to observe `finalized` move past it in between. A budget rather than a cost —
/// driving stops as soon as the row clears — so it is set well above the three ticks that suffice.
const FINALIZATION_TICKS: u32 = 8;
/// A budget for the transfer of the one funding a test arranges, on the same footing as the happy
/// path's: one tick sends it, the spares cover a tick landing before the burn and a tick lost to an
/// outcall the jump timed out.
const FUNDING_TICKS: u32 = 6;
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

/// A funding transaction that fails on chain is never reimbursed. The ETH never leaves the main
/// address and the ckETH stays burned, so the burn ends up as extra backing.
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

    setup.mint_cketh(setup.fee_account(), FEE_ACCOUNT_BALANCE);
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
    let surplus = setup
        .dashboard_row("sweeper-burned-not-yet-spent")
        .expect("the dashboard must report the unspent burn");
    assert_ne!(
        surplus, "0 Wei",
        "the unreimbursed burn must still show as burned but unspent, got {surplus}"
    );
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
