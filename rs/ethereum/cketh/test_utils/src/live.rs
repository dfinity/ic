//! One live harness for the ckETH fixtures: the canisters [`CkEthSetup`] installs — extended with
//! the ckERC20 layer where a test needs it — pointed at a local anvil node the harness owns, with
//! *real* canister outcalls reaching that node (see [`crate::anvil`]).
//!
//! [`LiveSetup`] is generic over the fixture it wraps, so the facilities every live test needs live
//! in one place: buying minter time, depositing through the production helper contract, reading the
//! dashboard and the canister log, and arranging state on anvil. The two flavours differ only in
//! what they build and seed — [`LiveSetup::new_balance_scan`] for the ckERC20 balance scan,
//! [`LiveSetup::new_funding`] for sweeper fee funding.
//!
//! The whole fixture is built on an ordinary (non-live) PocketIC instance, exactly as the mocked
//! fixtures are: `await_call` ticks deterministically, and every setup call completes in a bounded
//! number of rounds. Only once construction is complete is the instance switched to auto-progress,
//! by [`switch_to_live`], so the EVM RPC canister's outcalls reach anvil for real from that point
//! on. Building the fixture itself against an auto-progressing (wall-clock-paced) instance instead
//! made every setup call race a round deadline it did not control, which reproducibly failed under
//! CPU contention.
//!
//! Two consequences of a live instance are worth knowing before adding to this harness:
//!
//! * An ingress message may not be awaited by driving the instance with explicit `tick`s: the rounds
//!   arrive on their own, and a tick-driven await runs out its round budget and reports the message
//!   as unanswerable. `CkEthSetup`'s own `minter_address` and `stop_minter` do exactly that, which is
//!   why this module fetches the address and upgrades the minter itself.
//! * Any loop waiting on a minter timer must poll a canister while it waits. The PocketIC server
//!   shuts an idle instance down, which stops the minter's timers and looks exactly like a minter
//!   bug.
//!
//! The EVM RPC canister is installed with an `overrideProvider` that rewrites every provider URL to
//! the harness' anvil node (reached over HTTP, mirroring the `evm_rpc_local` configuration of the
//! EVM RPC canister), so the minter reads real Ethereum state from anvil once live: minter → EVM RPC
//! canister → anvil. anvil itself runs with **chain id 1** ([`Anvil::start_mainnet_like`]), which the
//! fixture's minter assumes — it signs for `EthereumNetwork::Mainnet`, and a chain-id mismatch makes
//! anvil reject anything it sends. The same flag gives one slot per epoch, so `finalized` trails
//! `latest` by 2 blocks instead of 64.
//!
//! Sweeper funding also needs minter *time*, which the balance scan never does: its transfer is only
//! sent by the withdrawal timer, six minutes after the funding task queued the request. Rather than
//! wait that out, a test *buys* the tick: live mode keeps adding wall-clock deltas to whatever the
//! instance's time already is, so pushing it forward with [`pocket_ic::PocketIc::advance_time`] is
//! additive and never undone — the instance simply runs that far ahead of the host from then on, and
//! every timer that has come due fires on the next round. That makes two rules, both explained on
//! [`LiveSetup::settle`]: ticks are bought one at a time, and each one is paid for in real seconds
//! rather than instance time.

use candid::{Decode, Encode, Nat, Principal};
use ic_base_types::PrincipalId;
use ic_cketh_minter::PROCESS_ETH_RETRIEVE_TRANSACTIONS_INTERVAL;
use ic_cketh_minter::endpoints::{
    DepositErc20Arg, DepositErc20Error, DepositErc20Response, DepositMode, DepositStatus,
};
use ic_cketh_minter::lifecycle::MinterArg;
use ic_cketh_minter::lifecycle::upgrade::UpgradeArg;
use ic_cketh_minter::numeric::Erc20Value;
use ic_ethereum_types::Address;
use ic_http_types::{HttpRequest, HttpResponse};
use icrc_ledger_types::icrc1::account::Account;
use pocket_ic::PocketIc;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::anvil::{
    Anvil, DEV_ACCOUNT, address_from_hex, deploy_deposit_helper, deploy_mock_erc20, deposit_eth,
    erc20_balance_slot, u256_be,
};
use crate::ckerc20::{CkErc20Setup, Erc20Token};
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
/// budget Bazel grants the target that runs these tests, so that a hang reports what the minter was
/// doing rather than being killed with nothing to show.
pub const AWAIT_DEADLINE: Duration = Duration::from_secs(60);

/// The balance scan waits on a periodic scan of its own rather than on a minter timer, and that scan
/// is slower to come round, so it gets its own budget.
const SCAN_DEADLINE: Duration = Duration::from_secs(180);

/// Cumulative ETH the minter has spent on funding transfers, which only a finalized funding moves.
pub const SWEEPER_ETH_SPENT: &str = "cketh_minter_sweeper_funding_eth_spent_total";
/// How far the ckETH burned for sweeping runs ahead of the ETH spent.
pub const SWEEPER_BURNED_NOT_YET_SPENT: &str = "cketh_minter_sweeper_funding_burned_not_yet_spent";
/// The lower bound the minter tracks on the sweeper address' balance.
pub const SWEEPER_GAS_BALANCE: &str = "cketh_minter_sweeper_gas_balance";

/// A balance to place on the owned anvil node: `amount` of `token` credited to the `deposit`
/// address, so the scan reads a real balance for that (address, token) pair.
pub struct Holding<'a> {
    pub deposit: Address,
    pub token: &'a Erc20Token,
    pub amount: u128,
}

/// `token.contract.address`, parsed: every canister and anvil call the harness makes needs an
/// [`Address`], not the raw string the orchestrator registered the token with.
fn contract_address(token: &Erc20Token) -> Address {
    Address::from_str(&token.contract.address)
        .expect("BUG: registered token has an invalid contract address")
}

/// A ckETH fixture — `CkEthSetup`, or `CkErc20Setup` for the tests that need tokens — against an
/// owned anvil node, on a live instance.
///
/// `fixture` is declared first so it drops first: the PocketIC instance goes away, and only then
/// does the node its canisters were calling out to.
pub struct LiveSetup<S> {
    fixture: S,
    anvil: Arc<Anvil>,
    minter_address: Address,
    /// The production deposit helper, for fixtures that deposit. Deployed only where it is needed:
    /// it costs a minter upgrade, which a test that never deposits should not pay for.
    deposit_helper: Option<Address>,
}

impl LiveSetup<CkErc20Setup> {
    /// Starts a local anvil node and builds the full [`CkErc20Setup`] fixture against it — minter,
    /// EVM RPC canister, orchestrator, and the ckUSDC/ckUSDT ledger and index canisters it spawns —
    /// then switches the instance to live outcalls.
    pub fn new_balance_scan() -> Self {
        let anvil = Arc::new(Anvil::start_mainnet_like());
        let cketh = CkEthSetup::new(EthereumBackend::Anvil(Arc::clone(&anvil)));
        let ckerc20 = CkErc20Setup::with_cketh(cketh).add_supported_erc20_tokens();
        Self::go_live(ckerc20, anvil)
    }

    /// A distinct non-anonymous depositing principal for `seed`, so a test can register several
    /// independent deposit addresses.
    pub fn depositor(&self, seed: u64) -> Principal {
        PrincipalId::new_user_test_id(seed).into()
    }

    /// The tokens the orchestrator actually registered, in registration order — the same set
    /// [`Self::credit_deposits`] gives code on anvil, by construction rather than by convention.
    pub fn supported_erc20_tokens(&self) -> &[Erc20Token] {
        &self.fixture.supported_erc20_tokens
    }

    /// Registers a `(caller/subaccount, token)` deposit and returns the Ethereum address the minter
    /// derived for it (shared across the caller's tokens).
    pub fn register_deposit_address(
        &self,
        caller: Principal,
        subaccount: [u8; 32],
        token: &Erc20Token,
    ) -> Address {
        Address::from_str(&self.deposit_erc20(caller, subaccount, token).address)
            .expect("BUG: minter returned an invalid deposit address")
    }

    /// Calls `deposit_erc20` as `caller`, which registers (idempotently) that user's
    /// `(address, token)` pair for balance scanning and reports its scan progress.
    pub fn deposit_erc20(
        &self,
        caller: Principal,
        subaccount: [u8; 32],
        token: &Erc20Token,
    ) -> DepositErc20Response {
        let arg = DepositErc20Arg {
            erc20_contract_address: token.contract.address.clone(),
            mode: DepositMode::Unsponsored {
                subaccount: Some(subaccount),
            },
        };
        let reply = self
            .env()
            .update_call(
                self.minter_id(),
                caller,
                "deposit_erc20",
                Encode!(&arg).unwrap(),
            )
            .expect("BUG: deposit_erc20 was rejected");
        Decode!(&reply, Result<DepositErc20Response, DepositErc20Error>)
            .unwrap()
            .expect("BUG: deposit_erc20 returned an error")
    }

    /// Places every token [`Self::supported_erc20_tokens`] returns at its real mainnet address on
    /// the owned anvil node, and credits each holding by writing its `balanceOf` mapping slot
    /// directly.
    ///
    /// Every balance is written *before* any token gets code. The fail-loud batcher only returns a
    /// (scan-advancing) result once every token has code — by which point all balances are already
    /// in place — so a concurrent scan can never observe a partially-credited state.
    pub fn credit_deposits(&self, holdings: &[Holding<'_>]) {
        let dev = address_from_hex(DEV_ACCOUNT);
        // Reuse MockUSDT's deployed bytecode to give each token a working `balanceOf`.
        let runtime = self.anvil.code(&deploy_mock_erc20(&self.anvil, &dev));

        for holding in holdings {
            self.anvil.set_storage_at(
                &contract_address(holding.token),
                &erc20_balance_slot(&holding.deposit),
                &u256_be(holding.amount),
            );
        }
        // Every registered token is read in the shared batch, so a token without code would revert
        // the whole scan even for holdings that do not involve it.
        for token in self.supported_erc20_tokens() {
            self.anvil.set_code(&contract_address(token), &runtime);
        }
        for holding in holdings {
            assert_eq!(
                self.anvil
                    .erc20_balance(&contract_address(holding.token), &holding.deposit),
                Erc20Value::from(holding.amount),
                "the deposit balance should be readable on anvil"
            );
        }
    }

    /// Waits until the minter's periodic balance scan has scanned `caller`'s deposit address —
    /// observed through `deposit_erc20`'s own status — and returns that response. An address counts
    /// as scanned once its status is `Scanning` with `scan_count >= 1` (a below-minimum address,
    /// advanced in place) or `AwaitingSweep` (a funded address, detected and queued). Either proves
    /// the `eth_call` against anvil succeeded and decoded, since a failing batch never advances or
    /// queues an address. Panics if no scan completes within `deadline`.
    pub fn await_scan(
        &self,
        caller: Principal,
        subaccount: [u8; 32],
        token: &Erc20Token,
    ) -> DepositErc20Response {
        self.poll_until(
            SCAN_DEADLINE,
            |_| "the deposit address was not scanned".to_string(),
            |setup| {
                let progress = setup.deposit_erc20(caller, subaccount, token);
                let scanned = match &progress.status {
                    DepositStatus::Scanning { scan_count, .. } => *scan_count >= 1,
                    DepositStatus::AwaitingSweep(_) => true,
                };
                scanned.then_some(progress)
            },
        )
    }
}

impl LiveSetup<CkEthSetup> {
    /// The ckETH fixture alone — funding touches no ERC-20 — with a deposit already credited, so
    /// there is deposit-backed ETH to spend, and the fee account holding the ckETH a funding burns.
    ///
    /// The minter's timers are left un-armed: a funding check runs on the next upgrade, so a test
    /// takes its ledger baselines and then calls [`Self::upgrade_minter`] when it is ready for the
    /// minter to act. Arming here instead would let the first check burn within milliseconds, before
    /// a test could read the pre-burn numbers.
    pub fn new_funding() -> Self {
        Self::new_funding_with_fee_account_balance(FEE_ACCOUNT_BALANCE)
    }

    /// As [`Self::new_funding`], but leaves the fee account empty, so that the first check that
    /// could fund finds nothing to burn.
    pub fn new_funding_with_empty_fee_account() -> Self {
        Self::new_funding_with_fee_account_balance(0)
    }

    fn new_funding_with_fee_account_balance(fee_account_balance: u128) -> Self {
        let anvil = Arc::new(Anvil::start_mainnet_like());
        let cketh = CkEthSetup::new(EthereumBackend::Anvil(Arc::clone(&anvil)));
        let setup = Self::go_live(cketh, anvil).with_deposit_helper();

        // Funding may only spend ETH the minter received through deposits, so it needs a real one.
        let depositor = Account {
            owner: setup.cketh().caller.into(),
            subaccount: None,
        };
        setup.deposit(depositor, DEPOSIT_AMOUNT);
        // The fee account earns its ckETH the way it does in production — the ckETH ledger collects
        // its fees there — but at 2e12 wei a transfer it would take 150'000 transfers to reach the
        // funding target, so the harness deposits to that account directly instead. Deposited rather
        // than minted so nothing here mints ckETH the minter did not back with ETH.
        let mut credited = vec![depositor];
        if fee_account_balance > 0 {
            setup.deposit(setup.fee_account(), fee_account_balance);
            credited.push(setup.fee_account());
        }
        setup.await_deposits_credited(&credited);
        setup
    }

    /// Waits until a deposit made to the fee account has been credited, for a test that arranges the
    /// account after construction.
    pub fn await_fee_account_credited(&self) {
        self.await_deposits_credited(&[self.fee_account()]);
    }

    /// Deploys the production deposit helper (`DepositHelperWithSubaccount.sol`) against the address
    /// the minter derived, so deposits reach the minter the way they do on mainnet — the ETH really
    /// arrives at the minter's address and the event the minter scrapes is the one the contract
    /// emits. The minter learns about it by upgrade, which is also how mainnet gained the contract.
    fn with_deposit_helper(mut self) -> Self {
        let helper = deploy_deposit_helper(
            &self.anvil,
            &address_from_hex(DEV_ACCOUNT),
            &self.minter_address,
        );
        self.deposit_helper = Some(helper);
        self.upgrade_minter_with(UpgradeArg {
            deposit_with_subaccount_helper_contract_address: Some(helper.to_string()),
            ..Default::default()
        });
        self
    }

    /// Deposits `value` wei for `beneficiary` through the helper contract, as a depositor does.
    pub fn deposit(&self, beneficiary: Account, value: u128) {
        let helper = self
            .deposit_helper
            .expect("BUG: the funding fixture always deploys a deposit helper");
        deposit_eth(
            &self.anvil,
            &helper,
            &address_from_hex(DEV_ACCOUNT),
            beneficiary,
            value,
        );
    }
}

impl<S: AsRef<CkEthSetup>> LiveSetup<S> {
    /// Switches `fixture` to live outcalls and reads the address the minter derived, which needs the
    /// instance to be making progress.
    fn go_live(fixture: S, anvil: Arc<Anvil>) -> Self {
        switch_to_live(fixture.as_ref());
        let minter_address = fetch_minter_address(fixture.as_ref());
        Self {
            fixture,
            anvil,
            minter_address,
            deposit_helper: None,
        }
    }

    /// Polls until `observe` produces a value, or fails with what the minter was doing. The shape
    /// every wait here had spelled out for itself; the sleep is [`POLL_INTERVAL`], as for the ticks.
    pub fn poll_until<T>(
        &self,
        deadline: Duration,
        what: impl Fn(&Self) -> String,
        mut observe: impl FnMut(&Self) -> Option<T>,
    ) -> T {
        let start = Instant::now();
        loop {
            if let Some(value) = observe(self) {
                return value;
            }
            assert!(
                start.elapsed() <= deadline,
                "{} within {deadline:?}; minter logs:\n{}",
                what(self),
                self.minter_logs().join("\n")
            );
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    /// The instance is shut down by the PocketIC server when nothing talks to it, which stops the
    /// minter's timers and looks exactly like a minter bug. Any loop that only talks to anvil has to
    /// send this.
    fn keep_instance_awake(&self) {
        let _ = self.cketh_total_supply();
    }

    fn cketh(&self) -> &CkEthSetup {
        self.fixture.as_ref()
    }

    fn env(&self) -> &PocketIc {
        &self.cketh().env
    }

    fn minter_id(&self) -> Principal {
        self.cketh().minter_id
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

    /// Re-arms the minter's periodic timers by upgrading it, so its checks run again inside the test
    /// rather than at the next scheduled tick.
    pub fn upgrade_minter(&self) {
        self.upgrade_minter_with(UpgradeArg::default());
    }

    /// As [`Self::upgrade_minter`], carrying a configuration change.
    ///
    /// The minter is stopped first, as any upgrade must be: upgrading a running canister leaves its
    /// in-flight HTTPS outcalls to resolve into fresh Wasm, which traps it with "CallFutureState for
    /// in-flight calls" and corrupts its heap. Stopped through the client rather than through
    /// `CkEthSetup::stop_minter`, which drives the instance with explicit `tick`s (see the module
    /// documentation).
    fn upgrade_minter_with(&self, arg: UpgradeArg) {
        let minter_id = self.minter_id();
        self.env()
            .stop_canister(minter_id, None)
            .expect("stopping the minter must succeed");
        self.env()
            .upgrade_canister(
                minter_id,
                minter_wasm(),
                Encode!(&MinterArg::UpgradeArg(arg)).unwrap(),
                None,
            )
            .expect("upgrading the minter must succeed");
        self.env()
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
            self.keep_instance_awake();
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
            self.env().advance_time(WITHDRAWAL_TICK);
        }
    }

    pub fn fee_account(&self) -> Account {
        Account {
            owner: self.minter_id(),
            subaccount: Some(ic_cketh_minter::CKETH_FEE_SUBACCOUNT),
        }
    }

    /// The sweeper address the minter derived, scraped from its log line: there is no getter for it
    /// yet, and it cannot be derived test-side without the master public key.
    fn sweeper_address(&self) -> Option<Address> {
        self.minter_logs().iter().find_map(|line| {
            let rest = line.split("[fund_sweeper]: ").nth(1)?;
            let hex = rest.split_whitespace().next()?;
            hex.parse().ok()
        })
    }

    /// Waits until the minter has derived its sweeper address, which happens once the master public
    /// key is cached — before the first funding check acts on it.
    pub fn await_sweeper_address(&self) -> Address {
        self.poll_until(
            AWAIT_DEADLINE,
            |_| "the minter did not derive a sweeper address".to_string(),
            |setup| setup.sweeper_address(),
        )
    }

    /// The value of a minter metric, or `None` if it is not exported. Reads the same HTTP endpoint
    /// an operator scrapes, so a test asserts on the numbers the minter publishes rather than on a
    /// rendering of them.
    pub fn metric(&self, name: &str) -> Option<f64> {
        let request = HttpRequest {
            method: "GET".to_string(),
            url: "/metrics".to_string(),
            headers: vec![],
            body: serde_bytes::ByteBuf::new(),
        };
        let reply = self
            .env()
            .query_call(
                self.minter_id(),
                Principal::anonymous(),
                "http_request",
                Encode!(&request).unwrap(),
            )
            .expect("the metrics query was rejected");
        let response = Decode!(&reply, HttpResponse).unwrap();
        String::from_utf8_lossy(&response.body)
            .lines()
            .filter(|line| !line.starts_with('#'))
            .find_map(|line| {
                let rest = line.strip_prefix(name)?.trim_start();
                rest.split_whitespace().next()?.parse().ok()
            })
    }

    /// As [`Self::metric`], for a metric a test knows the minter exports.
    pub fn metric_value(&self, name: &str) -> f64 {
        self.metric(name)
            .unwrap_or_else(|| panic!("the minter does not export {name}"))
    }

    /// Waits until the minter has logged a line containing `needle`.
    pub fn await_minter_log(&self, needle: &str) {
        self.poll_until(
            AWAIT_DEADLINE,
            |_| format!("the minter never logged {needle:?}"),
            |setup| {
                setup
                    .minter_logs()
                    .iter()
                    .any(|line| line.contains(needle))
                    .then_some(())
            },
        )
    }

    /// Lets `ticks` withdrawal-timer ticks pass, giving the minter real time to act on each. The
    /// window a bounded negative assertion watches, for a test whose "must not happen" is not a
    /// balance the harness can poll for.
    pub fn advance_ticks(&self, ticks: u32) {
        self.settle(&mut |_| false);
        for _ in 0..ticks {
            self.env().advance_time(WITHDRAWAL_TICK);
            self.settle(&mut |_| false);
        }
    }

    /// Places code at `address`, so a plain value transfer to it no longer succeeds: with the
    /// 21'000 gas of a bare transfer there is nothing left to execute it.
    pub fn set_code(&self, address: &Address, code: &[u8]) {
        self.anvil.set_code(address, code);
    }

    /// The runtime bytecode at `address`, so a test can check that what it arranged is where it
    /// meant to put it rather than assuming so.
    pub fn code(&self, address: &Address) -> Vec<u8> {
        self.anvil.code(address)
    }

    /// Asserts that `address` receives no ETH across `ticks` withdrawal-timer ticks. A bounded
    /// negative check — the best available shape for "the minter must not do this" — and a stronger
    /// one than watching the wall clock for the same number of seconds, since every tick is a
    /// withdrawal-timer interval the minter genuinely runs.
    pub fn assert_no_eth_received(&self, address: &Address, ticks: u32) {
        let mut assert_empty = |setup: &Self| {
            let balance = setup.anvil.eth_balance(address, "latest");
            assert_eq!(
                balance,
                0,
                "{address} unexpectedly received {balance} wei; minter logs:\n{}",
                setup.minter_logs().join("\n")
            );
            false // Never satisfied: watching for the whole window is the point.
        };
        // Settles before the first tick as well as after the last, so a transfer already in flight
        // is caught and the final tick's work is observed rather than merely started.
        self.settle(&mut assert_empty);
        for _ in 0..ticks {
            self.env().advance_time(WITHDRAWAL_TICK);
            self.settle(&mut assert_empty);
        }
    }

    /// Drives the minter until a funding has finalized, mining meanwhile so the minter's `finalized`
    /// view keeps advancing.
    ///
    /// Costs at least one tick beyond the one that sent the transaction: fetching the receipt is the
    /// *next* run of the withdrawal timer, and a single jump — however large — only ever makes a due
    /// timer fire once.
    ///
    /// Watched through the spend counter, which only a finalized funding moves — a mined transaction
    /// pays its gas whether it succeeded or failed. The age gauge beside it would not do: it reads
    /// zero both when nothing is outstanding and when a funding was accepted less than a second of
    /// instance time ago, which is every moment between the burn and the next tick.
    pub fn await_funding_finalized(&self, max_ticks: u32) {
        let spent_before = self.metric_value(SWEEPER_ETH_SPENT);
        self.drive_until(
            max_ticks,
            |_| "the funding had not finalized".to_string(),
            |setup| setup.metric_value(SWEEPER_ETH_SPENT) > spent_before,
        );
    }

    pub fn minter_address(&self) -> Address {
        self.minter_address
    }

    pub fn cketh_balance_of(&self, account: Account) -> u128 {
        nat_to_u128(self.cketh().balance_of(account))
    }

    pub fn cketh_total_supply(&self) -> u128 {
        let reply = self
            .env()
            .query_call(
                self.cketh().ledger_id,
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
        self.cketh()
            .minter_canister_logs()
            .into_iter()
            .map(|record| record.content)
            .collect()
    }
}

/// The minter's Ethereum address, awaited without ticking (see the module documentation).
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
