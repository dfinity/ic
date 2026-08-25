//! Sweeper fee funding on the shared live fixture: the ckETH ledger, minter and EVM RPC canister
//! [`CkEthSetup`] installs, pointed at an anvil node this harness owns, driving the *production*
//! path end to end with nothing mocked
//! (`rs/ethereum/cketh/docs/deposit_from_cex.md`, "Fund the transaction fees without touching the
//! ckETH backing"):
//!
//! ```text
//! deposit through the real helper contract -> minter scrapes it -> ckETH minted
//!   -> funding task (no chain read: the balance bound comes from the minter's own events)
//!   -> burn ckETH from the minter's 0x…0fee subaccount on a real ledger
//!   -> withdrawal request -> tECDSA signature
//!   -> eth_sendRawTransaction via the EVM RPC canister -> anvil mines it
//!   -> receipt -> finalized, with anvil's own balance confirming the ETH arrived
//! ```
//!
//! The fixture is built on an ordinary PocketIC instance and only then switched to live outcalls, by
//! [`switch_to_live`], for the reasons [`crate::live_scan`] documents. What this harness adds on top
//! is the anvil-side arranging these tests need and one thing the balance scan never needs: minter
//! *time*.
//!
//! The transfer is only sent by the withdrawal timer, six minutes after the funding task queued the
//! request. Rather than wait that out, these tests *buy* the tick: live mode keeps adding wall-clock
//! deltas to whatever the instance's time already is, so pushing it forward with
//! [`PocketIc::advance_time`] is additive and never undone — the instance simply runs that far ahead
//! of the host from then on, and every timer that has come due fires on the next round. That makes
//! two rules, both explained on [`SweeperFundingSetup::settle`]: ticks are bought one at a time, and
//! each one is paid for in real seconds rather than instance time.
//!
//! Two further pieces of wiring are easy to get wrong:
//!
//! * anvil runs with **chain id 1** ([`Anvil::start_mainnet_like`]): the fixture's minter signs for
//!   `EthereumNetwork::Mainnet`, and a chain-id mismatch makes anvil reject the transaction. The
//!   same flag gives one slot per epoch, so `finalized` trails `latest` by 2 blocks instead of 64.
//! * Any loop waiting on a minter timer **must poll a canister while it waits**. The PocketIC server
//!   shuts an idle instance down, which stops the minter's timers and looks exactly like a minter
//!   bug.

use candid::{Decode, Encode, Nat, Principal};
use ic_cketh_minter::PROCESS_ETH_RETRIEVE_TRANSACTIONS_INTERVAL;
use ic_cketh_minter::lifecycle::MinterArg;
use ic_cketh_minter::lifecycle::upgrade::UpgradeArg;
use ic_ethereum_types::Address;
use icrc_ledger_types::icrc1::account::Account;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::anvil::{Anvil, DEV_ACCOUNT, address_from_hex, deploy_deposit_helper, deposit_eth};
use crate::{CkEthSetup, EthereumBackend, minter_wasm, switch_to_live};

/// Deposited for a test principal, so funding has deposit-backed ETH to spend. Comfortably above the
/// 0.3 ETH funding target that the fixture's minimum withdrawal amount implies.
const DEPOSIT_AMOUNT: u128 = 5_000_000_000_000_000_000; // 5 ETH

pub const FEE_ACCOUNT_BALANCE: u128 = 1_000_000_000_000_000_000; // 1 ckETH

/// Ticks granted for the minter's log scrape to find the harness' deposits. One suffices, since a
/// tick is longer than the scraping interval; the spares cover a scrape that lands mid-tick.
const DEPOSIT_SCRAPE_TICKS: u32 = 3;

/// One withdrawal-timer interval, plus slack so the timer is unambiguously due. The unit these tests
/// buy minter time in: however far a single jump goes, each timer that has come due fires *once*, so
/// two ticks cost two jumps and not one large one.
const WITHDRAWAL_TICK: Duration =
    Duration::from_secs(PROCESS_ETH_RETRIEVE_TRANSACTIONS_INTERVAL.as_secs() + 30);

/// Real time granted after each tick, for the outcalls that tick starts to be dispatched and
/// answered before the clock moves again.
///
/// This is the one number that has to be generous. PocketIC drives the *real* consensus payload
/// builder, so an outcall still in flight when instance time jumps past
/// `CANISTER_HTTP_TIMEOUT_INTERVAL` (60 seconds) from when it was made is rejected with
/// `SysTransient: "Canister http request timed out"` — and every tick here is a jump of six minutes.
/// The minter retries such a rejection on its next run, so the effect is a wasted tick rather than a
/// failure, but a settle window too short to drain a whole outcall chain wastes every tick and the
/// pipeline never advances: at two seconds these tests fail reliably.
const TICK_SETTLE: Duration = Duration::from_secs(5);

/// Blocks mined per poll, so `finalized` — which trails `latest` by two — keeps moving well ahead of
/// the transaction the minter is waiting to see confirmed. Mined per poll rather than per tick
/// because it is `latest` advancing that a tick then lets the minter observe.
const BLOCKS_PER_POLL: u64 = 2;

/// Deliberately short: the PocketIC client panics on a transient HTTP failure rather than retrying,
/// and a pooled connection left idle for ~10s gets closed server-side, which surfaces as
/// `hyper::Error(IncompleteMessage)` on the next request.
const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// How long any wait here gives the minter before it fails with its logs. Sized well inside the
/// 300-second budget `size = "medium"` grants the target that runs these tests, so that a hang
/// reports what the minter was doing rather than being killed by Bazel with nothing to show.
pub const AWAIT_DEADLINE: Duration = Duration::from_secs(60);

/// The shared ckETH fixture against an owned anvil node, with the sweeper-funding tests' own
/// arranging on top.
///
/// `cketh` is declared first so it drops first: the PocketIC instance goes away, and only then does
/// the node its canisters were calling out to.
pub struct SweeperFundingSetup {
    cketh: CkEthSetup,
    anvil: Arc<Anvil>,
    minter_address: Address,
    deposit_helper: Address,
    supply_before_funding: u128,
    fee_account_before_funding: u128,
}

impl SweeperFundingSetup {
    /// The fee account is credited once the deposits are in and before the timers are re-armed: with
    /// nothing in it, the check that runs at install cannot burn whether it beats the deposit scrape
    /// or trails it, so the post-upgrade run is deterministically the first that can fund.
    pub fn new_live() -> Self {
        Self::new_live_with_fee_account_balance(FEE_ACCOUNT_BALANCE)
    }

    fn new_live_with_fee_account_balance(fee_account_balance: u128) -> Self {
        let anvil = Arc::new(Anvil::start_mainnet_like());
        let cketh = CkEthSetup::new(EthereumBackend::Anvil(Arc::clone(&anvil)));
        switch_to_live(&cketh);

        let minter_address = fetch_minter_address(&cketh);
        // The production helper contract, deployed against the address the minter just derived, so
        // deposits reach the minter the way they do on mainnet — the ETH really arrives at the
        // minter's address and the event the minter scrapes is the one the contract emits. The
        // minter learns about it by upgrade, which is also how mainnet gained the contract.
        let deposit_helper =
            deploy_deposit_helper(&anvil, &address_from_hex(DEV_ACCOUNT), &minter_address);

        let mut setup = Self {
            cketh,
            anvil,
            minter_address,
            deposit_helper,
            supply_before_funding: 0,
            fee_account_before_funding: 0,
        };
        setup.upgrade_minter_with(UpgradeArg {
            deposit_with_subaccount_helper_contract_address: Some(setup.deposit_helper.to_string()),
            ..Default::default()
        });

        // Funding may only spend ETH the minter received through deposits, so it needs a real one.
        let depositor = Account {
            owner: setup.cketh.caller.into(),
            subaccount: None,
        };
        setup.deposit(depositor, DEPOSIT_AMOUNT);
        // The fee account earns its ckETH the way it does in production — the ckETH ledger collects
        // its fees there — but at 2e12 wei a transfer it would take 150'000 transfers to reach the
        // funding target, so the test deposits to that account directly instead. Deposited rather
        // than minted so nothing here mints ckETH the minter did not back with ETH.
        if fee_account_balance > 0 {
            setup.deposit(setup.fee_account(), fee_account_balance);
        }
        let mut credited = vec![depositor];
        if fee_account_balance > 0 {
            credited.push(setup.fee_account());
        }
        setup.await_deposits_credited(&credited);

        // Taken here, before the timers are re-armed, and not left to the test: the funding decision
        // reads nothing off the chain, so the first post-upgrade check burns within milliseconds of
        // the minter restarting — well before a test that queried the ledger afterwards could see
        // the pre-burn numbers. Compared against an already-debited baseline, a burn assertion would
        // report zero burned and fail.
        setup.supply_before_funding = setup.cketh_total_supply();
        setup.fee_account_before_funding = setup.cketh_balance_of(setup.fee_account());
        setup.upgrade_minter();
        setup
    }

    /// ckETH total supply as it stood before the minter could fund anything, so that a test can
    /// measure the burn a funding made. See [`Self::new_live`] for why the harness holds it.
    pub fn supply_before_funding(&self) -> u128 {
        self.supply_before_funding
    }

    /// The fee account's ckETH balance at that same point, for measuring what the burn debited.
    pub fn fee_account_before_funding(&self) -> u128 {
        self.fee_account_before_funding
    }

    /// Deposits `value` wei for `beneficiary` through the helper contract, as a depositor does.
    pub fn deposit(&self, beneficiary: Account, value: u128) {
        deposit_eth(
            &self.anvil,
            &self.deposit_helper,
            &address_from_hex(DEV_ACCOUNT),
            beneficiary,
            value,
        );
    }

    /// Waits until the minter has credited the deposits, buying the ticks its log scrape needs: they
    /// were mined after the scrape that runs at install, so the next scheduled one is what finds
    /// them.
    ///
    /// Observed through the mint a deposit produces: crediting the minter's ETH balance and minting
    /// ckETH to the beneficiary are the same state transition.
    fn await_deposits_credited(&self, accounts: &[Account]) {
        self.drive_until(
            DEPOSIT_SCRAPE_TICKS,
            |_| "the minter never credited the deposits".to_string(),
            |setup| {
                accounts
                    .iter()
                    .all(|account| setup.cketh_balance_of(*account) > 0)
            },
        );
    }

    /// Waits until a deposit made to the fee account has been credited, for a test that arranges the
    /// account after construction.
    pub fn await_fee_account_credited(&self) {
        self.await_deposits_credited(&[self.fee_account()]);
    }

    /// Re-arms the minter's periodic timers by upgrading it, so a funding check runs again inside the
    /// test rather than at the next 24-hour tick.
    pub fn upgrade_minter(&self) {
        self.upgrade_minter_with(UpgradeArg::default());
    }

    /// As [`Self::upgrade_minter`], carrying a configuration change.
    ///
    /// The minter is stopped first, as any upgrade must be: upgrading a running canister leaves its
    /// in-flight HTTPS outcalls to resolve into fresh Wasm, which traps it with "CallFutureState for
    /// in-flight calls" and corrupts its heap.
    ///
    /// Stopped through the client rather than through `CkEthSetup::stop_minter`, which drives the
    /// instance with explicit `tick`s and answers outcalls with mocks: on an auto-progressing
    /// instance the rounds arrive on their own, and an ingress awaited tick-by-tick alongside them
    /// runs out its round budget unanswered.
    pub fn upgrade_minter_with(&self, arg: UpgradeArg) {
        let minter_id = self.cketh.minter_id;
        self.cketh
            .env
            .stop_canister(minter_id, None)
            .expect("stopping the minter must succeed");
        self.cketh
            .env
            .upgrade_canister(
                minter_id,
                minter_wasm(),
                Encode!(&MinterArg::UpgradeArg(arg)).unwrap(),
                None,
            )
            .expect("upgrading the minter must succeed");
        self.cketh
            .env
            .start_canister(minter_id, None)
            .expect("starting the minter must succeed");
    }

    /// Gives the minter [`TICK_SETTLE`] of *real* time to carry out whatever the last tick started,
    /// mining meanwhile so `finalized` keeps advancing, and returns as soon as `observe` reports
    /// what it watches for has happened.
    ///
    /// Real time, not instance time, is the currency here: the outcalls a tick starts are dispatched
    /// by PocketIC's auto-progress loop and answered by anvil, and neither needs the instance's
    /// clock to move. Advancing time faster than this would only pile more due timers onto a minter
    /// that has not finished the last batch — `ic-cdk-timers` caps a canister at five concurrent
    /// global-timer calls and reschedules the rest, so the work is not lost, but nothing is gained
    /// either.
    fn settle(&self, observe: &mut impl FnMut(&Self) -> bool) -> bool {
        let start = Instant::now();
        loop {
            self.anvil.mine(BLOCKS_PER_POLL);
            if observe(self) {
                return true;
            }
            // Required, not diagnostics: the PocketIC server shuts down an instance with no HTTP
            // traffic, which stops the minter's timers and looks exactly like a minter bug. A loop
            // that only talks to anvil sends none.
            let _ = self.cketh_total_supply();
            if start.elapsed() >= TICK_SETTLE {
                return false;
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    /// Settles, and buys withdrawal-timer ticks until `observe` is satisfied or `max_ticks` are
    /// spent. Settling first means a condition already met costs no ticks at all.
    ///
    /// `what` is rendered only on failure, so it can read state that is worth knowing at that point
    /// and would say nothing at the start.
    fn drive_until(
        &self,
        max_ticks: u32,
        what: impl Fn(&Self) -> String,
        mut observe: impl FnMut(&Self) -> bool,
    ) {
        let mut spent = 0;
        while !self.settle(&mut observe) {
            assert!(
                spent < max_ticks,
                "{} within {max_ticks} withdrawal-timer ticks ({:?} of minter time); \
                 minter logs:\n{}",
                what(self),
                WITHDRAWAL_TICK * max_ticks,
                self.minter_logs().join("\n")
            );
            spent += 1;
            self.cketh.env.advance_time(WITHDRAWAL_TICK);
        }
    }

    pub fn fee_account(&self) -> Account {
        Account {
            owner: self.cketh.minter_id,
            subaccount: Some(ic_cketh_minter::CKETH_FEE_SUBACCOUNT),
        }
    }

    /// The sweeper address the minter derived, scraped from its log line: there is no getter for it
    /// yet, and it cannot be derived test-side without the master public key.
    pub fn sweeper_address(&self) -> Option<Address> {
        self.minter_logs().iter().find_map(|line| {
            let rest = line.split("[fund_sweeper]: ").nth(1)?;
            let hex = rest.split_whitespace().next()?;
            hex.parse().ok()
        })
    }

    /// Waits until the funding task has logged the sweeper address, polling a canister meanwhile.
    pub fn await_funding_decision(&self) -> Address {
        let start = Instant::now();
        loop {
            if let Some(address) = self.sweeper_address() {
                return address;
            }
            assert!(
                start.elapsed() <= AWAIT_DEADLINE,
                "the funding task did not decide to fund within {AWAIT_DEADLINE:?}; minter logs:\n{}",
                self.minter_logs().join("\n")
            );
            std::thread::sleep(Duration::from_secs(2));
        }
    }

    pub fn minter_address(&self) -> Address {
        self.minter_address
    }

    pub fn cketh_balance_of(&self, account: Account) -> u128 {
        nat_to_u128(self.cketh.balance_of(account))
    }

    pub fn cketh_total_supply(&self) -> u128 {
        let reply = self
            .cketh
            .env
            .query_call(
                self.cketh.ledger_id,
                Principal::anonymous(),
                "icrc1_total_supply",
                Encode!().unwrap(),
            )
            .expect("icrc1_total_supply rejected");
        nat_to_u128(Decode!(&reply, Nat).unwrap())
    }

    /// Drives the minter until `recipient` holds ETH on anvil, mining so `finalized` keeps
    /// advancing, and returns the balance it received.
    ///
    /// Budget at least two ticks: the funding task's burn is on its own timer, so the first tick can
    /// land before there is any request to send.
    pub fn await_eth_received(&self, recipient: &Address, max_ticks: u32) -> u128 {
        self.drive_until(
            max_ticks,
            |setup| {
                format!(
                    "no ETH reached {recipient} (minter address {}, balance {}, ckETH supply {})",
                    setup.minter_address,
                    setup.anvil.eth_balance(&setup.minter_address, "latest"),
                    setup.cketh_total_supply(),
                )
            },
            |setup| setup.anvil.eth_balance(recipient, "latest") > 0,
        );
        self.anvil.eth_balance(recipient, "latest")
    }

    pub fn anvil_eth_balance(&self, address: &Address) -> u128 {
        self.anvil.eth_balance(address, "latest")
    }

    pub fn minter_logs(&self) -> Vec<String> {
        self.cketh
            .minter_canister_logs()
            .into_iter()
            .map(|record| record.content)
            .collect()
    }
}

/// The minter's Ethereum address, awaited without ticking.
///
/// Not [`CkEthSetup::minter_address`]: that awaits its update call by driving the instance with
/// explicit `tick`s, and on an auto-progressing instance the rounds arrive on their own — the
/// tick-driven await runs out its round budget and reports the ingress as unanswerable.
fn fetch_minter_address(cketh: &CkEthSetup) -> Address {
    let message_id = cketh
        .env
        .submit_call(
            cketh.minter_id,
            Principal::anonymous(),
            "minter_address",
            Encode!().unwrap(),
        )
        .expect("minter_address submission rejected");
    let reply = cketh
        .env
        .await_call_no_ticks(message_id)
        .expect("minter_address rejected");
    Address::from_str(&Decode!(&reply, String).unwrap())
        .expect("the minter returned an invalid address")
}

fn nat_to_u128(nat: Nat) -> u128 {
    use num_traits::ToPrimitive;
    nat.0.to_u128().expect("balance does not fit into u128")
}
