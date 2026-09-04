//! One live harness for the ckETH fixtures: the canisters [`CkEthSetup`] installs — extended with
//! the ckERC20 layer where a test needs it — pointed at a local anvil node the harness owns, with
//! *real* canister outcalls reaching that node (see [`crate::anvil`]).
//!
//! [`LiveSetup`] is generic over the fixture it wraps, so the facilities every live test needs live
//! in one place: buying minter time, depositing through the production helper contract, reading the
//! minter's canister log, and arranging state on anvil. The flavours differ only in what they build
//! and seed — [`LiveSetup::new_balance_scan`] for the ckERC20 balance scan,
//! [`LiveSetup::new_funding`] for sweeper fee funding, and [`LiveSetup::new_sweep`] for the sweep
//! of detected ckERC20 deposits.
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
//! * An ingress message whose completion depends on canister-http traffic must be *polled* for
//!   ([`pocket_ic::PocketIc::ingress_status`]), never awaited. The client's blocking awaits —
//!   `await_call`, and everything built on it: `update_call`, `stop_canister`, … — run as one
//!   server-side operation that executes up to 100 rounds back to back, and while it holds the
//!   instance the auto-progress loop cannot run `ProcessCanisterHttpInternal`, so no outcall is
//!   dispatched or answered until the await has already failed. A call that completes on rounds
//!   alone finishes well within the budget; one waiting on an outcall response never can.
//!   `CkEthSetup`'s tick-driving `minter_address` and `stop_minter` are unusable here for the same
//!   reason, which is why this module fetches the address and upgrades the minter itself.
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
//! Every flow past the setup needs minter *time*: the balance scan runs on its own thirty-second
//! timer, and a sweeper funding's transfer is only sent by the withdrawal timer, six minutes after
//! the funding task queued the request. Rather than wait that out, a test *buys* the tick: live mode
//! keeps adding wall-clock deltas to whatever the instance's time already is, so pushing it forward
//! with [`pocket_ic::PocketIc::advance_time`] is additive and never undone — the instance simply
//! runs that far ahead of the host from then on, and every timer that has come due fires on the
//! next round. That makes two rules, both explained on
//! [`LiveSetup::settle`]: ticks are bought one at a time, and each one is paid for in real seconds
//! rather than instance time.

use candid::{Decode, Encode, Nat, Principal};
use ic_base_types::PrincipalId;
use ic_cketh_minter::endpoints::events::{Event, EventPayload, TransactionStatus};
use ic_cketh_minter::endpoints::{
    CkErc20Token, DepositErc20Arg, DepositErc20Error, DepositErc20Response, DepositMode,
    DepositStatus,
};
use ic_cketh_minter::lifecycle::MinterArg;
use ic_cketh_minter::lifecycle::upgrade::UpgradeArg;
use ic_cketh_minter::numeric::Erc20Value;
use ic_cketh_minter::{BALANCE_SCAN_INTERVAL, PROCESS_ETH_RETRIEVE_TRANSACTIONS_INTERVAL};
use ic_ethereum_types::Address;
use icrc_ledger_types::icrc1::account::Account;
use pocket_ic::PocketIc;
use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::anvil::{
    Anvil, DEV_ACCOUNT, SentTransaction, SweepContracts, address_from_hex, deploy_deposit_helper,
    deploy_mock_erc20, deploy_sweep_contracts, deposit_eth, erc20_balance_slot, u256_be,
};
use crate::ckerc20::{CkErc20Setup, Erc20Token};
use crate::{
    CkEthSetup, EthereumBackend, MINTER_ADDRESS, SWEEPER_ADDRESS, minter_wasm, switch_to_live,
};

const FEE_ACCOUNT_BALANCE: u128 = 1_000_000_000_000_000_000; // 1 ckETH

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
const AWAIT_DEADLINE: Duration = Duration::from_secs(60);

/// One balance-scan interval, plus slack so the scan is unambiguously due. Also long enough for the
/// latest-block refresh the scan reads, which shares the interval, and short enough that an outcall
/// in flight across the jump stays inside `CANISTER_HTTP_TIMEOUT_INTERVAL`.
const SCAN_TICK: Duration = Duration::from_secs(BALANCE_SCAN_INTERVAL.as_secs() + 5);

/// A budget, not a cost: one tick refreshes the latest block height the scan needs, the next scans;
/// the spares cover a tick lost to an outcall the jump timed out, and the blocks the pair's
/// block-based backoff gap demands before it is due again — up to 300 block-seconds (25 blocks)
/// once an address has been scanned a few times, against the ~10 blocks each tick's settle mines.
const SCAN_TICKS: u32 = 8;

/// A budget, not a cost: the sweep path crosses the enqueue, send, and finalization timers, and
/// driving stops the moment the expected transactions are on chain.
const SWEEP_TICKS: u32 = 8;

/// The mint follows the sweep through the log scrape, one more timer downstream.
const CREDIT_TICKS: u32 = 6;

const FUNDING_TICKS: u32 = 6;

/// A balance to place on the owned anvil node: `amount` of `token` credited to the `deposit`
/// address, so the scan reads a real balance for that (address, token) pair.
pub struct Holding<'a> {
    pub deposit: Address,
    pub token: &'a Erc20Token,
    pub amount: u128,
}

/// `token.contract.address`, parsed: every canister and anvil call the harness makes needs an
/// [`Address`], not the raw string the orchestrator registered the token with.
pub fn contract_address(token: &Erc20Token) -> Address {
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
    /// The contracts a sweep goes through, for the fixture that deploys them.
    sweep_contracts: Option<SweepContracts>,
}

impl LiveSetup<CkErc20Setup> {
    /// Starts a local anvil node and builds the full [`CkErc20Setup`] fixture against it — minter,
    /// EVM RPC canister, orchestrator, and the ckUSDC/ckUSDT ledger and index canisters it spawns —
    /// then switches the instance to live outcalls.
    pub fn new_balance_scan() -> Self {
        let anvil = Arc::new(Anvil::start_mainnet_like());
        let cketh = CkEthSetup::new(EthereumBackend::Anvil {
            anvil: Arc::clone(&anvil),
            sweep_contracts: None,
        });
        let ckerc20 = CkErc20Setup::with_cketh(cketh).add_supported_erc20_tokens();
        Self::go_live(ckerc20, anvil)
    }

    /// Like [`Self::new_balance_scan`], but with the real deposit helper and the attested sweeper
    /// delegate deployed on the node first, so the minter is installed knowing both, and with the
    /// minter's sweeper address ([`SWEEPER_ADDRESS`]) funded the way production funds it: a ckETH
    /// burn out of the minter's fee account, delivered by the funding pipeline — which is also
    /// what lets the minter know the sweeper can pay for a sweep, since it only accepts sweeps
    /// whose fee its own funding accounting covers.
    pub fn new_sweep() -> Self {
        let anvil = Arc::new(Anvil::start_mainnet_like());
        // The helper pays out to the minter's main address, which the minter only derives once
        // installed. It is only ever read back out of the helper event, never by the helper
        // itself, so the deployment can name the address the test asserts against.
        let contracts = deploy_sweep_contracts(&anvil, &address_from_hex(MINTER_ADDRESS));
        let cketh = CkEthSetup::new(EthereumBackend::Anvil {
            anvil: Arc::clone(&anvil),
            sweep_contracts: Some(contracts),
        });
        let ckerc20 = CkErc20Setup::with_cketh(cketh)
            .add_supported_erc20_tokens()
            .add_support_for_subaccount_helper(contracts.helper);
        let mut setup = Self::go_live(ckerc20, anvil);
        assert_eq!(
            setup.minter_address,
            address_from_hex(MINTER_ADDRESS),
            "BUG: the helper was deployed paying out to an address the installed minter does not \
             control, so a sweep would move every balance out of reach while still minting"
        );
        setup.sweep_contracts = Some(contracts);
        setup.deposit_helper = Some(contracts.helper);

        setup.fund_fee_account();
        setup.upgrade_minter();
        let sweeper = address_from_hex(SWEEPER_ADDRESS);
        assert_eq!(
            setup.await_sweeper_address(),
            sweeper,
            "BUG: the minter derived a sweeper address other than the pinned SWEEPER_ADDRESS"
        );
        setup.await_eth_received(&sweeper, FUNDING_TICKS);
        setup.await_funding_finalized();
        setup
    }

    /// The ckERC20 token the orchestrator spawned for `symbol`, whose ledger the mint lands on.
    pub fn ckerc20_token(&self, symbol: &str) -> CkErc20Token {
        self.fixture.find_ckerc20_token(symbol)
    }

    /// `account`'s balance on `ledger_id`, i.e. what the deposit was credited.
    pub fn balance_of_ledger(&self, ledger_id: Principal, account: impl Into<Account>) -> Nat {
        self.fixture.balance_of_ledger(ledger_id, account)
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
    /// the owned anvil node, and funds each holding with a plain ERC-20 `transfer` from a seeded
    /// CEX-style account — all mined in a single block, so a concurrent scan (whose batched
    /// `eth_call` pins one block) sees either every holding funded or none of them.
    pub fn credit_deposits(&self, holdings: &[Holding<'_>]) {
        let cex = address_from_hex(DEV_ACCOUNT);
        // Reuse MockUSDT's deployed bytecode to give each token a working `balanceOf`.
        let runtime = self.anvil.code(&deploy_mock_erc20(&self.anvil, &cex));
        // Every registered token is read in the shared batch, so a token without code would revert
        // the whole scan even for holdings that do not involve it.
        for token in self.supported_erc20_tokens() {
            self.anvil.set_code(&contract_address(token), &runtime);
        }

        let mut cex_totals: BTreeMap<Address, u128> = BTreeMap::new();
        for holding in holdings {
            let total = cex_totals
                .entry(contract_address(holding.token))
                .or_default();
            *total = total
                .checked_add(holding.amount)
                .expect("BUG: the CEX account's balance overflows");
        }
        for (token, total) in &cex_totals {
            self.anvil
                .set_storage_at(token, &erc20_balance_slot(&cex), &u256_be(*total));
        }

        let transfers: Vec<(Address, Address, u128)> = holdings
            .iter()
            .map(|holding| {
                (
                    contract_address(holding.token),
                    holding.deposit,
                    holding.amount,
                )
            })
            .collect();
        self.anvil.fund_in_one_block(&cex, &transfers);

        for holding in holdings {
            assert_eq!(
                self.anvil
                    .erc20_balance(&contract_address(holding.token), &holding.deposit),
                Erc20Value::from(holding.amount),
                "the deposit balance should be readable on anvil"
            );
        }
    }

    /// Waits until the minter's periodic balance scan has scanned `caller`'s deposit address *at a
    /// block where its funding is visible* — observed through `deposit_erc20`'s own status — and
    /// returns that response. An address counts as scanned once its status is `AwaitingSweep` (a
    /// funded address, detected and queued — terminal by construction) or `Scanning` with
    /// `scan_count >= 1` and a `last_scanned_block` at or past the chain head as of entry (a
    /// below-minimum address, advanced in place). Either proves the `eth_call` against anvil
    /// succeeded, decoded, and read the funded balance. Buys balance-scan ticks rather than waiting
    /// the interval out, and panics if no such scan completes within [`SCAN_TICKS`] of them.
    ///
    /// The pinned-block requirement is what makes the wait sound: the scan reads every balance at
    /// the minter's *cached* latest block height, refreshed on its own thirty-second timer — so a
    /// scan can run after [`Self::credit_deposits`] funded the addresses and still read them at a
    /// pre-funding block, bumping `scan_count` without having seen the funds. Accepting any
    /// `scan_count >= 1` returned that transient verdict and made the caller's `AwaitingSweep`
    /// assertion flaky; a scan pinned at or past the entry head (the funding is mined before a
    /// test awaits its scan) cannot have missed the balance.
    pub fn await_scan(
        &self,
        caller: Principal,
        subaccount: [u8; 32],
        token: &Erc20Token,
    ) -> DepositErc20Response {
        let funded_by = Nat::from(self.anvil.block_number());
        let mut scanned = None;
        self.drive_until_with(
            SCAN_TICK,
            SCAN_TICKS,
            |_| format!("the deposit address was not scanned at or past block {funded_by}"),
            |setup| {
                let progress = setup.deposit_erc20(caller, subaccount, token);
                let is_scanned = match &progress.status {
                    DepositStatus::Scanning {
                        scan_count,
                        last_scanned_block,
                        ..
                    } => {
                        *scan_count >= 1
                            && last_scanned_block
                                .as_ref()
                                .is_some_and(|block| *block >= funded_by)
                    }
                    DepositStatus::AwaitingSweep(_) => true,
                };
                if is_scanned {
                    scanned = Some(progress);
                }
                is_scanned
            },
        );
        scanned.expect("drive_until_with returns only once observe held")
    }

    /// Waits for the sweeper address to send exactly `expected` transactions, returning what each
    /// did. An extra sweep is caught rather than ignored: sending more than `expected` fails
    /// immediately.
    pub fn await_sweeps(&self, sweeper: &Address, expected: u64) -> Vec<SentTransaction> {
        self.drive_until(
            SWEEP_TICKS,
            |setup| {
                format!(
                    "the sweeper {sweeper} sent {} of {expected} transactions (stages: {})",
                    setup.anvil.transaction_count(sweeper),
                    setup.sweep_stages(),
                )
            },
            |setup| {
                let sent = setup.anvil.transaction_count(sweeper);
                assert!(
                    sent <= expected,
                    "the sweeper sent {sent} transactions, more than the {expected} expected"
                );
                sent == expected
            },
        );
        self.anvil.transactions_of(sweeper)
    }

    /// Waits until `account` holds exactly `expected` on `ledger_id`. The mint follows the sweep's
    /// own finalized helper event through the minter's unchanged deposit pipeline, so this is what
    /// proves the whole chain ran.
    pub fn await_credited(&self, ledger_id: Principal, account: Account, expected: u128) {
        let credited = Nat::from(expected);
        self.drive_until(
            CREDIT_TICKS,
            |setup| {
                format!(
                    "{account:?} was credited {} instead of {expected} (stages: {})",
                    setup.balance_of_ledger(ledger_id, account),
                    setup.sweep_stages(),
                )
            },
            |setup| setup.balance_of_ledger(ledger_id, account) == credited,
        );
    }

    /// How far the sweep pipeline has got, counted off the minter's audit events. Unlike its
    /// canister log, which is a rolling buffer the EVM RPC canister's tracing evicts within
    /// minutes, the event log is durable — so this says which stage stalled even late in a run.
    fn sweep_stages(&self) -> String {
        let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
        for event in self.minter_events() {
            let stage = match event.payload {
                EventPayload::AutomaticDepositReceived { .. } => "detected",
                EventPayload::AcceptedSweepRequest { .. } => "accepted",
                EventPayload::CreatedSweeperTransaction { .. } => "created",
                EventPayload::SignedSweeperTransaction { .. } => "signed",
                EventPayload::ReplacedSweeperTransaction { .. } => "replaced",
                EventPayload::FinalizedSweeperTransaction { .. } => "finalized",
                EventPayload::AcceptedDeposit { .. }
                | EventPayload::AcceptedErc20Deposit { .. } => "scraped",
                EventPayload::MintedCkErc20 { .. } => "minted",
                _ => continue,
            };
            *counts.entry(stage).or_default() += 1;
        }
        format!("{counts:?}")
    }
}

impl LiveSetup<CkEthSetup> {
    /// The ckETH fixture alone — funding touches no ERC-20 — with the fee account already holding
    /// the ckETH a funding burns, its deposit also being the deposit-backed ETH the funding spends.
    ///
    /// The minter's timers are left un-armed: a funding check runs on the next upgrade, so a test
    /// takes its ledger baselines and then calls [`Self::upgrade_minter`] when it is ready for the
    /// minter to act. Arming here instead would let the first check burn within milliseconds, before
    /// a test could read the pre-burn numbers.
    pub fn new_funding() -> Self {
        let anvil = Arc::new(Anvil::start_mainnet_like());
        let cketh = CkEthSetup::new(EthereumBackend::Anvil {
            anvil: Arc::clone(&anvil),
            sweep_contracts: None,
        });
        let setup = Self::go_live(cketh, anvil).with_deposit_helper();
        setup.fund_fee_account();
        setup
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
            sweep_contracts: None,
        }
    }

    /// The contracts the sweep goes through, if this harness deployed them.
    pub fn sweep_contracts(&self) -> SweepContracts {
        self.sweep_contracts
            .expect("BUG: this harness was built without sweeping")
    }

    /// The owned anvil node, so a test can read balances and code straight off the chain.
    pub fn anvil(&self) -> &Anvil {
        &self.anvil
    }

    /// The audit events the minter has recorded, to see how far a sweep got.
    pub fn minter_events(&self) -> Vec<Event> {
        self.cketh().get_all_events()
    }

    /// Polls until `observe` produces a value, or fails with what the minter was doing. The shape
    /// every wait here had spelled out for itself; the sleep is [`POLL_INTERVAL`], as for the ticks.
    fn poll_until<T>(
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
    /// in-flight calls" and corrupts its heap.
    ///
    /// The stop is submitted and then polled for, rather than awaited through the client's
    /// `stop_canister` (see the module documentation): a stop only replies once every open call
    /// context of the minter has closed, and when the stop lands while one of the minter's
    /// timer-driven outcall chains is in flight, closing them takes the very canister-http
    /// deliveries the blocking await prevents — so it deterministically burns its round budget
    /// (which advances instance time by mere nanoseconds, so not even the 60-second outcall
    /// timeout can fire inside it) and fails with `BadIngressMessage`. Nor can such a chain be
    /// waited out beforehand: `get_canister_http()` lists only requests not yet handed to the
    /// HTTP adapter, which auto-progress does within one ~100ms iteration, so on a live instance
    /// a probe of it reads empty for virtually an outcall's whole lifetime — a stop gated on it
    /// still races every chain. Polling the ingress status instead leaves the auto-progress loop
    /// free to deliver the responses the stop is waiting on, however the stop lands.
    fn upgrade_minter_with(&self, arg: UpgradeArg) {
        let minter_id = self.minter_id();
        let stop_message_id = self.cketh().submit_stop_minter();
        self.poll_until(
            AWAIT_DEADLINE,
            |_| "the minter never stopped".to_string(),
            |setup| setup.env().ingress_status(stop_message_id.clone()),
        )
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
    pub fn drive_until(
        &self,
        max_ticks: u32,
        what: impl Fn(&Self) -> String,
        observe: impl FnMut(&Self) -> bool,
    ) {
        self.drive_until_with(WITHDRAWAL_TICK, max_ticks, what, observe)
    }

    fn drive_until_with(
        &self,
        tick: Duration,
        max_ticks: u32,
        what: impl Fn(&Self) -> String,
        mut observe: impl FnMut(&Self) -> bool,
    ) {
        let mut spent = 0;
        while !self.settle(&mut observe) {
            assert!(
                spent < max_ticks,
                "{} within {max_ticks} ticks of {tick:?} ({:?} of minter time); minter logs:\n{}",
                what(self),
                tick * max_ticks,
                self.minter_logs().join("\n")
            );
            spent += 1;
            self.env().advance_time(tick);
        }
    }

    pub fn fee_account(&self) -> Account {
        Account {
            owner: self.minter_id(),
            subaccount: Some(ic_cketh_minter::CKETH_FEE_SUBACCOUNT),
        }
    }

    fn await_funding_finalized(&self) {
        self.drive_until(
            FUNDING_TICKS,
            |_| "the minter never finalized the funding transfer successfully".to_string(),
            |setup| {
                setup.minter_events().iter().any(|event| {
                    matches!(
                        &event.payload,
                        EventPayload::FinalizedTransaction {
                            transaction_receipt,
                            ..
                        } if transaction_receipt.status == TransactionStatus::Success
                    )
                })
            },
        );
    }

    fn fund_fee_account(&self) {
        // The fee account earns its ckETH the way it does in production — the ckETH ledger collects
        // its fees there — but at 2e12 wei a transfer it would take 150'000 transfers to reach the
        // funding target, so the harness deposits to that account directly instead. Deposited rather
        // than minted so nothing here mints ckETH the minter did not back with ETH.
        self.deposit(self.fee_account(), FEE_ACCOUNT_BALANCE);
        self.await_deposits_credited(&[self.fee_account()]);
    }

    /// Deposits `value` wei for `beneficiary` through the helper contract, as a depositor does.
    fn deposit(&self, beneficiary: Account, value: u128) {
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

    fn minter_logs(&self) -> Vec<String> {
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
