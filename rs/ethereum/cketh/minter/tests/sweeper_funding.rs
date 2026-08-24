//! End-to-end proof of sweeper fee funding against a real EVM with nothing mocked: real ckETH
//! ledger, real EVM RPC canister, threshold-ECDSA signature, local anvil. The harness lives in
//! [`ic_cketh_test_utils::sweeper_funding`].
//!
//! The transfer is only sent by the minter's 6-minute withdrawal timer, which the harness buys by
//! pushing the instance's clock forward rather than waiting it out.

use ic_cketh_test_utils::sweeper_funding::SweeperFundingSetup;
use std::time::Duration;

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

    let sweeper = setup.await_funding_decision(Duration::from_secs(120));
    assert_eq!(
        setup.anvil_eth_balance(&sweeper),
        0,
        "the sweeper address must start empty, so any balance proves the funding landed"
    );

    let received = setup.await_eth_received(&sweeper, FUNDING_TICKS);

    let burned = supply_before - setup.cketh_total_supply();
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
