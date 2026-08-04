//! Pins the ledger contract that `LedgerClient::burn_from_own_subaccount` relies on: the minter
//! can burn ckETH out of a subaccount it owns itself — in production its fee subaccount
//! `CKETH_FEE_SUBACCOUNT` (`0x…0fee`, the ledger's fee collector) — without holding an ICRC-2
//! allowance, provided it names that same subaccount as the spender.
//!
//! This matters because the ledger's allowance bypass compares the **full account**, not just the
//! owner (`Operation::Burn` in `rs/ledger_suite/icrc1/src/lib.rs`:
//! `spender.is_some() && from != &spender.unwrap()`). Spending the minter's default subaccount —
//! what the allowance-based `burn_from` used for user withdrawals does — yields `{minter, None}`,
//! which is a *different account* from `{minter, 0fee}` and is therefore rejected. Both directions
//! are asserted below, since silently taking the wrong branch would make sweeper funding fail at
//! runtime with a confusing `InsufficientAllowance`.
//!
//! The ledger is driven directly, with the minter canister impersonated as the caller, exactly as
//! the funding task will call it. `LedgerClient` itself is canister-side code (it reads
//! `canister_self()`), so it is exercised end to end only once a task calls it.

use candid::{Decode, Encode, Nat};
use ic_base_types::CanisterId;
use ic_cketh_minter::CKETH_FEE_SUBACCOUNT;
use ic_cketh_test_utils::CkEthSetup;
use ic_state_machine_tests::{StateMachine, WasmResult};
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::{TransferArg, TransferError};
use icrc_ledger_types::icrc2::transfer_from::{TransferFromArgs, TransferFromError};
use std::sync::Arc;

/// Minted into the fee account, then partly burned: 1 ETH in wei.
const FUNDING_AMOUNT: u64 = 1_000_000_000_000_000_000;

fn assert_reply(result: WasmResult) -> Vec<u8> {
    match result {
        WasmResult::Reply(bytes) => bytes,
        WasmResult::Reject(reject) => panic!("expected a reply, got a reject: {reject}"),
    }
}

struct Setup {
    env: Arc<StateMachine>,
    ledger_id: CanisterId,
    minter_id: CanisterId,
}

impl Setup {
    fn new() -> Self {
        let setup = CkEthSetup::default();
        Self {
            env: setup.env.clone(),
            ledger_id: setup.ledger_id,
            minter_id: setup.minter_id,
        }
    }

    fn fee_account(&self) -> Account {
        Account {
            owner: self.minter_id.get().0,
            subaccount: Some(CKETH_FEE_SUBACCOUNT),
        }
    }

    /// The ckETH minting account: the minter's default subaccount. A transfer *to* it burns, a
    /// transfer *from* it mints.
    fn minting_account(&self) -> Account {
        Account {
            owner: self.minter_id.get().0,
            subaccount: None,
        }
    }

    fn balance_of(&self, account: Account) -> Nat {
        Decode!(
            &assert_reply(
                self.env
                    .query(
                        self.ledger_id,
                        "icrc1_balance_of",
                        Encode!(&account).unwrap()
                    )
                    .expect("failed to query icrc1_balance_of")
            ),
            Nat
        )
        .unwrap()
    }

    fn total_supply(&self) -> Nat {
        Decode!(
            &assert_reply(
                self.env
                    .query(self.ledger_id, "icrc1_total_supply", Encode!().unwrap())
                    .expect("failed to query icrc1_total_supply")
            ),
            Nat
        )
        .unwrap()
    }

    fn mint(&self, to: Account, amount: u64) {
        let args = TransferArg {
            from_subaccount: None,
            to,
            fee: None,
            created_at_time: None,
            memo: None,
            amount: Nat::from(amount),
        };
        Decode!(
            &assert_reply(
                self.env
                    .execute_ingress_as(
                        self.minter_id.get(),
                        self.ledger_id,
                        "icrc1_transfer",
                        Encode!(&args).unwrap(),
                    )
                    .expect("icrc1_transfer (mint) was rejected")
            ),
            Result<Nat, TransferError>
        )
        .unwrap()
        .expect("minting into the fee account must succeed");
    }

    /// Burns from the fee account with the minter as caller, letting the test choose the spender
    /// subaccount so both branches of the ledger's allowance bypass can be exercised.
    fn burn_from_fee_account(
        &self,
        amount: u64,
        spender_subaccount: Option<[u8; 32]>,
    ) -> Result<Nat, TransferFromError> {
        let args = TransferFromArgs {
            spender_subaccount,
            from: self.fee_account(),
            to: self.minting_account(),
            amount: Nat::from(amount),
            fee: None,
            memo: None,
            created_at_time: None,
        };
        Decode!(
            &assert_reply(
                self.env
                    .execute_ingress_as(
                        self.minter_id.get(),
                        self.ledger_id,
                        "icrc2_transfer_from",
                        Encode!(&args).unwrap(),
                    )
                    .expect("icrc2_transfer_from was rejected at the ingress level")
            ),
            Result<Nat, TransferFromError>
        )
        .unwrap()
    }
}

/// What `burn_from_own_subaccount` does: spender subaccount == `from` subaccount.
#[test]
fn should_burn_from_fee_account_without_an_allowance() {
    let setup = Setup::new();
    setup.mint(setup.fee_account(), FUNDING_AMOUNT);
    assert_eq!(
        setup.balance_of(setup.fee_account()),
        Nat::from(FUNDING_AMOUNT)
    );

    let supply_before = setup.total_supply();
    let burn_amount = FUNDING_AMOUNT / 4;

    let result = setup.burn_from_fee_account(burn_amount, Some(CKETH_FEE_SUBACCOUNT));

    assert!(
        result.is_ok(),
        "burning from the fee account while naming it as the spender must need no allowance, \
         got {result:?}"
    );
    assert_eq!(
        setup.balance_of(setup.fee_account()),
        Nat::from(FUNDING_AMOUNT - burn_amount),
        "the fee account must be debited by exactly the burned amount (burns are fee-free)"
    );
    assert_eq!(
        setup.total_supply(),
        supply_before - Nat::from(burn_amount),
        "a transfer to the minting account must reduce total supply, i.e. be a real burn"
    );
}

/// What plain `burn_from` would do, and why sweeper funding cannot use it.
#[test]
fn should_reject_burning_from_fee_account_with_the_default_spender_subaccount() {
    let setup = Setup::new();
    setup.mint(setup.fee_account(), FUNDING_AMOUNT);

    let result = setup.burn_from_fee_account(FUNDING_AMOUNT / 4, None);

    assert!(
        matches!(result, Err(TransferFromError::InsufficientAllowance { .. })),
        "spending {{minter, None}} against {{minter, 0fee}} must be rejected for want of an \
         allowance, got {result:?}"
    );
    assert_eq!(
        setup.balance_of(setup.fee_account()),
        Nat::from(FUNDING_AMOUNT),
        "a rejected burn must not move funds"
    );
}
