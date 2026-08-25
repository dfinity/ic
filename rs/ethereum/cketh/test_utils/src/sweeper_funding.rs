//! A live harness for the sweeper fee-funding task
//! (`rs/ethereum/cketh/docs/deposit_from_cex.md`, "Fund the transaction fees without touching the
//! ckETH backing"), driving the *production* path end to end with nothing mocked:
//!
//! ```text
//! funding task (no chain read: the balance bound comes from the minter's own events)
//!   -> burn ckETH from the minter's 0x…0fee subaccount on a real ledger
//!   -> withdrawal request -> tECDSA signature
//!   -> eth_sendRawTransaction via the EVM RPC canister -> anvil mines it
//!   -> receipt -> finalized, with anvil's own balance confirming the ETH arrived
//! ```
//!
//! Runs on a PocketIC instance in live mode, so the canister's HTTPS outcalls genuinely reach anvil.
//! Wiring that is easy to get wrong:
//!
//! * anvil runs with **chain id 1** ([`Anvil::start_mainnet_like`]): the minter signs for
//!   `EthereumNetwork::Mainnet`, and a chain-id mismatch makes anvil reject the transaction.
//! * The same flag gives one slot per epoch, so `finalized` trails `latest` by 2 blocks instead of
//!   64 and the minter can keep its production `BlockTag::Finalized`.
//! * Any loop waiting on a minter timer **must poll a canister while it waits**. The PocketIC server
//!   shuts an idle instance down, which stops the minter's timers and looks exactly like a minter
//!   bug.
//! * The transfer is only sent by the withdrawal timer, six minutes after the funding task queued
//!   the request. Rather than wait that out, these tests *buy* the tick: live mode keeps adding
//!   wall-clock deltas to whatever the instance's time already is, so pushing it forward with
//!   [`PocketIc::advance_time`] is additive and never undone — the instance simply runs that far
//!   ahead of the host from then on, and every timer that has come due fires on the next round.
//!   That makes two rules, both explained on `SweeperFundingSetup::settle`: ticks are bought one at
//!   a time, and each one is paid for in real seconds rather than instance time.

use candid::{Decode, Encode, Nat, Principal};
use evm_rpc_types::{InstallArgs, OverrideProvider, RegexSubstitution};
use ic_cketh_minter::PROCESS_ETH_RETRIEVE_TRANSACTIONS_INTERVAL;
use ic_cketh_minter::endpoints::{CandidBlockTag, RetrieveEthStatus};
use ic_cketh_minter::lifecycle::{EthereumNetwork, MinterArg, init::InitArg as MinterInitArgs};
use ic_ethereum_types::Address;
use ic_http_types::{HttpRequest, HttpResponse};
use ic_icrc1_ledger::{FeatureFlags, LedgerArgument};
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::{TransferArg, TransferError};
use pocket_ic::{CanisterSettings, PocketIc, PocketIcBuilder};
use std::str::FromStr;
use std::time::{Duration, Instant, SystemTime};

use crate::anvil::{Anvil, DEV_ACCOUNT, address_from_hex};
use crate::{
    CKETH_MINIMUM_WITHDRAWAL_AMOUNT, ETH_HELPER_CONTRACT_ADDRESS, evm_rpc_wasm, ledger_wasm,
    minter_wasm,
};

const ECDSA_KEY_NAME: &str = "key_1";

const CKETH_TRANSFER_FEE: u64 = 2_000_000_000_000;

/// Credited to the minter as a deposit, so funding has deposit-backed ETH to spend. Comfortably
/// above the 0.3 ETH funding target that [`CKETH_MINIMUM_WITHDRAWAL_AMOUNT`] implies.
const DEPOSIT_AMOUNT: u128 = 5_000_000_000_000_000_000; // 5 ETH
const MINTER_ETH_BALANCE: u128 = 100_000_000_000_000_000_000; // 100 ETH

pub const FEE_ACCOUNT_BALANCE: u128 = 1_000_000_000_000_000_000; // 1 ckETH

/// One withdrawal-timer interval, plus slack so the timer is unambiguously due. The unit these
/// tests buy minter time in: however far a single jump goes, each timer that has come due fires
/// *once*, so two ticks cost two jumps and not one large one.
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

fn controller() -> Principal {
    Principal::from_slice(&[0x0c; 10])
}

pub struct SweeperFundingSetup {
    env: PocketIc,
    anvil: Anvil,
    minter_id: Principal,
    ledger_id: Principal,
    minter_address: Address,
    supply_before_funding: u128,
    fee_account_before_funding: u128,
}

impl SweeperFundingSetup {
    /// The fee account is funded once the deposit has been credited and before the timers are
    /// re-armed: with nothing in it, the check that runs at install cannot burn whether it beats the
    /// deposit scrape or trails it, so the post-upgrade run is deterministically the first that can
    /// fund.
    pub fn new_live() -> Self {
        Self::new_live_with_fee_account_balance(FEE_ACCOUNT_BALANCE)
    }

    /// As [`Self::new_live`], but leaves the fee account empty, so that the first check that could
    /// fund finds nothing to burn.
    pub fn new_live_with_empty_fee_account() -> Self {
        Self::new_live_with_fee_account_balance(0)
    }

    fn new_live_with_fee_account_balance(fee_account_balance: u128) -> Self {
        let anvil = Anvil::start_mainnet_like();

        let mut env = PocketIcBuilder::new()
            .with_nns_subnet() // make_live requires an NNS subnet.
            .with_fiduciary_subnet() // holds the secp256k1 `key_1` the minter signs with.
            .build();

        let settings = CanisterSettings {
            controllers: Some(vec![controller()]),
            ..Default::default()
        };

        let ledger_id =
            env.create_canister_with_settings(Some(controller()), Some(settings.clone()));
        let evm_rpc_id =
            env.create_canister_with_settings(Some(controller()), Some(settings.clone()));
        let minter_id = env.create_canister_with_settings(Some(controller()), Some(settings));
        for canister in [ledger_id, evm_rpc_id, minter_id] {
            env.add_cycles(canister, u128::from(u64::MAX));
        }

        install_ledger(&env, ledger_id, minter_id);
        install_evm_rpc(&env, evm_rpc_id, anvil.url());

        // Before `make_live`, whose auto-progress task sets the time asynchronously: an ingress
        // message submitted below would otherwise race that five-year jump, be retroactively
        // expired and never answered. Same fix as #11299, which explains it at length.
        env.set_certified_time(SystemTime::now().into());
        // Live before installing the minter: its install-time timers issue outcalls immediately.
        let _gateway = env.make_live(None);

        // Emitted before the minter exists, so its install-time log scrape credits the deposit.
        // Funding may only spend ETH the minter received through deposits, so without this every
        // funding is refused: setting a balance on anvil credits the accounting nothing.
        let mut principal_topic = [0_u8; 32];
        let principal_bytes = controller().as_slice().to_vec();
        principal_topic[0] = principal_bytes.len() as u8;
        principal_topic[1..1 + principal_bytes.len()].copy_from_slice(&principal_bytes);
        anvil.emit_received_eth(
            &address_from_hex(ETH_HELPER_CONTRACT_ADDRESS),
            &address_from_hex(DEV_ACCOUNT),
            DEPOSIT_AMOUNT,
            &principal_topic,
        );

        install_minter(&env, minter_id, ledger_id, evm_rpc_id);

        let mut setup = Self {
            env,
            anvil,
            minter_id,
            ledger_id,
            minter_address: Address::new([0; 20]),
            supply_before_funding: 0,
            fee_account_before_funding: 0,
        };
        setup.minter_address = setup.fetch_minter_address();
        setup
            .anvil
            .set_balance(&setup.minter_address, MINTER_ETH_BALANCE);
        setup.await_deposit_credited(Duration::from_secs(300));
        // Funded here rather than at install: with an empty fee account the check that runs at
        // install cannot burn, whichever way it and the scrape interleave. Safe to do now because
        // the next scheduled check is a whole interval away, so nothing is watching until the
        // upgrade below re-arms the timers — which makes that run the first one able to fund.
        if fee_account_balance > 0 {
            setup.mint_cketh(setup.fee_account(), fee_account_balance);
        }
        // Taken here, in that same window, and not left to the test: the funding decision reads
        // nothing off the chain, so the first post-upgrade check burns within milliseconds of the
        // minter restarting — well before a test that queried the ledger afterwards could see the
        // pre-burn numbers. Compared against an already-debited baseline, a burn assertion would
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

    /// Waits until the minter has credited the harness' deposit, i.e. its ETH balance is non-zero.
    pub fn await_deposit_credited(&self, deadline: Duration) {
        let start = Instant::now();
        loop {
            // Observed through the mint the deposit produces: crediting the minter's ETH balance
            // and minting ckETH to the beneficiary are the same state transition.
            if self.cketh_balance_of(Account {
                owner: controller(),
                subaccount: None,
            }) > 0
            {
                return;
            }
            assert!(
                start.elapsed() <= deadline,
                "the minter never credited the deposit within {deadline:?}; logs:\n{}",
                self.minter_logs().join("\n")
            );
            self.anvil.mine(1);
            std::thread::sleep(Duration::from_secs(2));
        }
    }

    /// Re-arms the minter's periodic timers by upgrading it, so a funding check runs again inside the
    /// test rather than at the next 24-hour tick.
    ///
    /// Stopped first, as any upgrade must be: upgrading a running canister leaves its in-flight
    /// HTTPS outcalls to resolve into fresh Wasm, which traps it with
    /// "CallFutureState for in-flight calls" and corrupts its heap.
    pub fn upgrade_minter(&self) {
        self.env
            .stop_canister(self.minter_id, Some(controller()))
            .expect("stopping the minter must succeed");
        self.env
            .upgrade_canister(
                self.minter_id,
                minter_wasm(),
                Encode!(&None::<MinterArg>).unwrap(),
                Some(controller()),
            )
            .expect("upgrading the minter must succeed");
        self.env
            .start_canister(self.minter_id, Some(controller()))
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
            self.env.advance_time(WITHDRAWAL_TICK);
        }
    }

    /// Lets `ticks` withdrawal-timer ticks pass, giving the minter real time to act on each. The
    /// window a bounded negative assertion watches, for a test whose "must not happen" is not a
    /// balance the harness can poll for.
    pub fn advance_ticks(&self, ticks: u32) {
        self.settle(&mut |_| false);
        for _ in 0..ticks {
            self.env.advance_time(WITHDRAWAL_TICK);
            self.settle(&mut |_| false);
        }
    }

    pub fn fee_account(&self) -> Account {
        Account {
            owner: self.minter_id,
            subaccount: Some(ic_cketh_minter::CKETH_FEE_SUBACCOUNT),
        }
    }

    /// The sweeper address the minter derived, read from its dashboard: available as soon as the
    /// master public key is, i.e. before the funding task has decided anything.
    pub fn sweeper_address(&self) -> Option<Address> {
        let dashboard = self.dashboard_html();
        let row = dashboard.split(r#"id="sweeper-address""#).nth(1)?;
        // Bounded to the row: until the minter has cached its key the cell holds no address at all,
        // and an unbounded search then runs on into later rows and returns an unrelated one — the
        // deposit helper contract's — as if it were the sweeper's, leaving a test to arrange the
        // wrong account. Returning `None` is what keeps `await_sweeper_address` waiting.
        let row = row.split("</tr>").next()?;
        let start = row.find("0x")?;
        row.get(start..start + 42)?.parse().ok()
    }

    /// The minter's rendered dashboard.
    pub fn dashboard_html(&self) -> String {
        let request = HttpRequest {
            method: "GET".to_string(),
            url: "/dashboard".to_string(),
            headers: vec![],
            body: serde_bytes::ByteBuf::new(),
        };
        let reply = self
            .env
            .query_call(
                self.minter_id,
                Principal::anonymous(),
                "http_request",
                Encode!(&request).unwrap(),
            )
            .expect("the dashboard query was rejected");
        let response = Decode!(&reply, HttpResponse).unwrap();
        String::from_utf8_lossy(&response.body).to_string()
    }

    /// The value rendered in a dashboard row, e.g. `sweeper-cketh-burned`.
    pub fn dashboard_row(&self, id: &str) -> Option<String> {
        let dashboard = self.dashboard_html();
        let row = dashboard.split(&format!(r#"id="{id}""#)).nth(1)?;
        let cell = row.split("<td>").nth(1)?.split("</td>").next()?;
        Some(cell.trim().to_string())
    }

    /// Waits until the minter has derived its sweeper address, which happens once the master public
    /// key is cached — before the first funding check acts on it.
    pub fn await_sweeper_address(&self, deadline: Duration) -> Address {
        let start = Instant::now();
        loop {
            if let Some(address) = self.sweeper_address() {
                return address;
            }
            assert!(
                start.elapsed() <= deadline,
                "the minter did not derive a sweeper address within {deadline:?}; minter logs:\n{}",
                self.minter_logs().join("\n")
            );
            std::thread::sleep(Duration::from_secs(2));
        }
    }

    /// Waits until the minter has logged a line containing `needle`, polling its log endpoint.
    pub fn await_minter_log(&self, needle: &str, deadline: Duration) {
        let start = Instant::now();
        loop {
            let logs = self.minter_logs();
            if logs.iter().any(|line| line.contains(needle)) {
                return;
            }
            assert!(
                start.elapsed() <= deadline,
                "the minter never logged {needle:?} within {deadline:?}; logs:\n{}",
                logs.join("\n")
            );
            std::thread::sleep(Duration::from_secs(2));
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
            self.env.advance_time(WITHDRAWAL_TICK);
            self.settle(&mut assert_empty);
        }
    }

    /// Drives the minter until the in-flight funding row clears, i.e. its transaction has finalized,
    /// mining meanwhile so the minter's `finalized` view keeps advancing.
    ///
    /// Costs at least one tick beyond the one that sent the transaction: fetching the receipt is
    /// the *next* run of the withdrawal timer, and a single jump — however large — only ever makes
    /// a due timer fire once.
    ///
    /// Polls the dashboard rather than the status endpoint: that endpoint is an update call, and a
    /// steady stream of ingress messages is enough load to destabilise the PocketIC instance.
    pub fn await_funding_finalized(&self, max_ticks: u32) {
        self.drive_until(
            max_ticks,
            |setup| {
                format!(
                    "the funding had not finalized (in-flight row {:?})",
                    setup.dashboard_row("sweeper-in-flight-funding")
                )
            },
            |setup| setup.dashboard_row("sweeper-in-flight-funding").as_deref() == Some("none"),
        );
    }

    /// The burn index of the funding currently in flight, read from the dashboard. `None` once it has
    /// finalized, so a test needing it must read it between the burn and the finalization.
    pub fn in_flight_funding_burn_index(&self) -> Option<u64> {
        let row = self.dashboard_row("sweeper-in-flight-funding")?;
        let rest = row.strip_prefix("burn index ")?;
        rest.split(',').next()?.trim().parse().ok()
    }

    /// The minter's public status for `burn_index`, rendered.
    pub fn withdrawal_status(&self, burn_index: u64) -> String {
        let message_id = self
            .env
            .submit_call(
                self.minter_id,
                Principal::anonymous(),
                "retrieve_eth_status",
                Encode!(&burn_index).unwrap(),
            )
            .expect("retrieve_eth_status submission rejected");
        let reply = self
            .env
            .await_call_no_ticks(message_id)
            .expect("retrieve_eth_status rejected");
        Decode!(&reply, RetrieveEthStatus).unwrap().to_string()
    }

    fn fetch_minter_address(&self) -> Address {
        let message_id = self
            .env
            .submit_call(
                self.minter_id,
                Principal::anonymous(),
                "minter_address",
                Encode!().unwrap(),
            )
            .expect("minter_address submission rejected");
        let reply = self
            .env
            .await_call_no_ticks(message_id)
            .expect("minter_address rejected");
        let address = Decode!(&reply, String).unwrap();
        Address::from_str(&address).expect("the minter returned an invalid address")
    }

    pub fn minter_address(&self) -> Address {
        self.minter_address
    }

    pub fn mint_cketh(&self, to: Account, amount: u128) {
        let args = TransferArg {
            from_subaccount: None,
            to,
            fee: None,
            created_at_time: None,
            memo: None,
            amount: Nat::from(amount),
        };
        let message_id = self
            .env
            .submit_call(
                self.ledger_id,
                self.minter_id,
                "icrc1_transfer",
                Encode!(&args).unwrap(),
            )
            .expect("icrc1_transfer submission rejected");
        let reply = self
            .env
            .await_call_no_ticks(message_id)
            .expect("icrc1_transfer rejected");
        Decode!(&reply, Result<Nat, TransferError>)
            .unwrap()
            .expect("minting ckETH must succeed");
    }

    pub fn cketh_balance_of(&self, account: Account) -> u128 {
        let reply = self
            .env
            .query_call(
                self.ledger_id,
                Principal::anonymous(),
                "icrc1_balance_of",
                Encode!(&account).unwrap(),
            )
            .expect("icrc1_balance_of rejected");
        nat_to_u128(Decode!(&reply, Nat).unwrap())
    }

    pub fn cketh_total_supply(&self) -> u128 {
        let reply = self
            .env
            .query_call(
                self.ledger_id,
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
        self.env
            .fetch_canister_logs(self.minter_id, controller())
            .expect("fetching the minter's canister logs failed")
            .into_iter()
            .map(|record| String::from_utf8_lossy(&record.content).to_string())
            .collect()
    }
}

fn nat_to_u128(nat: Nat) -> u128 {
    use num_traits::ToPrimitive;
    nat.0.to_u128().expect("balance does not fit into u128")
}

/// Installs the ckETH ledger with every balance empty. The fee account is credited afterwards, by
/// [`SweeperFundingSetup::new_live`], for the reason given there.
fn install_ledger(env: &PocketIc, ledger_id: Principal, minter_id: Principal) {
    use ic_icrc1_ledger::InitArgsBuilder as LedgerInitArgsBuilder;

    let builder = LedgerInitArgsBuilder::with_symbol_and_name("ckETH", "ckETH")
        .with_minting_account(minter_id)
        .with_transfer_fee(CKETH_TRANSFER_FEE)
        .with_max_memo_length(80)
        .with_decimals(18)
        .with_feature_flags(FeatureFlags {
            icrc2: true,
            icrc152: false,
        });
    let args = LedgerArgument::Init(builder.build());
    env.install_canister(
        ledger_id,
        ledger_wasm(),
        Encode!(&args).unwrap(),
        Some(controller()),
    );
}

fn install_evm_rpc(env: &PocketIc, evm_rpc_id: Principal, anvil_url: &str) {
    let args = InstallArgs {
        override_provider: Some(OverrideProvider {
            override_url: Some(RegexSubstitution {
                pattern: ".*".into(),
                replacement: anvil_url.to_string(),
            }),
        }),
        ..Default::default()
    };
    env.install_canister(
        evm_rpc_id,
        evm_rpc_wasm(),
        Encode!(&args).unwrap(),
        Some(controller()),
    );
}

fn install_minter(
    env: &PocketIc,
    minter_id: Principal,
    ledger_id: Principal,
    evm_rpc_id: Principal,
) {
    let args = MinterInitArgs {
        ethereum_network: EthereumNetwork::Mainnet,
        ecdsa_key_name: ECDSA_KEY_NAME.to_string(),
        ethereum_contract_address: Some(ETH_HELPER_CONTRACT_ADDRESS.to_string()),
        ledger_id,
        // The production block tag: usable because anvil runs with one slot per epoch.
        ethereum_block_height: CandidBlockTag::Finalized,
        minimum_withdrawal_amount: Nat::from(CKETH_MINIMUM_WITHDRAWAL_AMOUNT),
        next_transaction_nonce: Nat::from(0_u8),
        // The sweeper's own nonce lane starts fresh, as on a new deployment.
        next_sweeper_transaction_nonce: None,
        last_scraped_block_number: Nat::from(0_u8),
        evm_rpc_id: Some(evm_rpc_id),
        // Sweeping through the contract is out of scope here: funding is what these tests drive.
        ethereum_sweeper_contract_address: None,
    };
    env.install_canister(
        minter_id,
        minter_wasm(),
        Encode!(&MinterArg::InitArg(args)).unwrap(),
        Some(controller()),
    );
}
