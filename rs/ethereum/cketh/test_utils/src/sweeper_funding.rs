//! A live harness for the sweeper fee-funding task
//! (`rs/ethereum/cketh/docs/deposit_from_cex.md`, "Fund the transaction fees without touching the
//! ckETH backing"), driving the *production* path end to end with nothing mocked:
//!
//! ```text
//! funding task -> eth_getBalance via the EVM RPC canister -> anvil
//!              -> burn ckETH from the minter's 0x…0fee subaccount on a real ledger
//!              -> SweeperFundingRequest -> tECDSA signature -> eth_sendRawTransaction
//!              -> anvil mines it -> receipt -> finalized
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
//! * The transfer is only sent by the withdrawal timer, so this harness genuinely waits minutes.

use candid::{Decode, Encode, Nat, Principal};
use evm_rpc_types::{InstallArgs, OverrideProvider, RegexSubstitution};
use ic_cketh_minter::endpoints::CandidBlockTag;
use ic_cketh_minter::lifecycle::{EthereumNetwork, MinterArg, init::InitArg as MinterInitArgs};
use ic_ethereum_types::Address;
use ic_icrc1_ledger::{FeatureFlags, LedgerArgument};
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::{TransferArg, TransferError};
use pocket_ic::{CanisterSettings, PocketIc, PocketIcBuilder, StartServerParams, start_server};
use reqwest::Url;
use std::process::Child;
use std::str::FromStr;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use crate::anvil::{Anvil, DEV_ACCOUNT, address_from_hex};
use crate::{
    CKETH_MINIMUM_WITHDRAWAL_AMOUNT, ETH_HELPER_CONTRACT_ADDRESS, evm_rpc_wasm, ledger_wasm,
    minter_wasm,
};

const ECDSA_KEY_NAME: &str = "key_1";

const CKETH_TRANSFER_FEE: u64 = 2_000_000_000_000;

/// Credited to the minter as a deposit, so funding has deposit-backed ETH to spend. Comfortably
/// above the default 0.1 ETH funding target.
const DEPOSIT_AMOUNT: u128 = 5_000_000_000_000_000_000; // 5 ETH
const MINTER_ETH_BALANCE: u128 = 100_000_000_000_000_000_000; // 100 ETH

pub const FEE_ACCOUNT_BALANCE: u128 = 1_000_000_000_000_000_000; // 1 ckETH

/// Live mode advances IC time with the wall clock, so the 6-minute withdrawal timer costs 6 real
/// minutes. This dominates the test's runtime and is why its Bazel target needs a long timeout.
pub const WITHDRAWAL_DEADLINE: Duration = Duration::from_secs(13 * 60);

fn controller() -> Principal {
    Principal::from_slice(&[0x0c; 10])
}

pub struct SweeperFundingSetup {
    env: PocketIc,
    anvil: Anvil,
    minter_id: Principal,
    ledger_id: Principal,
    minter_address: Address,
}

impl SweeperFundingSetup {
    /// The fee account is funded before the minter is installed, not after: the funding task starts
    /// with the minter, so a test seeding it afterwards would race its own arrangement.
    pub fn new_live() -> Self {
        Self::new_live_with_fee_account_balance(FEE_ACCOUNT_BALANCE)
    }

    /// As [`Self::new_live`], but leaves the fee account empty.
    pub fn new_live_with_empty_fee_account() -> Self {
        Self::new_live_with_fee_account_balance(0)
    }

    fn new_live_with_fee_account_balance(fee_account_balance: u128) -> Self {
        let anvil = Anvil::start_mainnet_like();

        let mut env = PocketIcBuilder::new()
            .with_server_url(long_lived_server_url())
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

        install_ledger(&env, ledger_id, minter_id, fee_account_balance);
        install_evm_rpc(&env, evm_rpc_id, anvil.url());

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
        };
        setup.minter_address = setup.fetch_minter_address();
        setup
            .anvil
            .set_balance(&setup.minter_address, MINTER_ETH_BALANCE);
        // The install-time funding check races the scrape, so it will have seen a zero balance, and
        // the next scheduled one is a whole interval away. Re-arm the timers once the deposit has
        // landed so tests start from a minter that can actually fund.
        setup.await_deposit_credited(Duration::from_secs(300));
        setup.upgrade_minter();
        setup
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

    /// Mines `blocks` on the owned anvil node, so a change made with `set_eth_balance` or `set_code`
    /// becomes visible at `finalized`, which trails `latest` by two blocks.
    pub fn mine(&self, blocks: u64) {
        self.anvil.mine(blocks);
    }

    pub fn fee_account(&self) -> Account {
        Account {
            owner: self.minter_id,
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
    pub fn await_funding_decision(&self, deadline: Duration) -> Address {
        let start = Instant::now();
        loop {
            if let Some(address) = self.sweeper_address() {
                return address;
            }
            assert!(
                start.elapsed() <= deadline,
                "the funding task did not decide to fund within {deadline:?}; minter logs:\n{}",
                self.minter_logs().join("\n")
            );
            std::thread::sleep(Duration::from_secs(2));
        }
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

    /// Waits until `recipient` holds ETH on anvil, mining so `finalized` keeps advancing.
    pub fn await_eth_received(&self, recipient: &Address, deadline: Duration) -> u128 {
        let start = Instant::now();
        let mut statuses: Vec<u128> = Vec::new();
        loop {
            self.anvil.mine(1);
            let balance = self.anvil.eth_balance(recipient, "latest");
            if balance > 0 {
                return balance;
            }
            // Required, not diagnostics: the PocketIC server shuts down an instance with no HTTP
            // traffic, and a loop that only talks to anvil sends none.
            let supply = self.cketh_total_supply();
            if statuses.last() != Some(&supply) {
                statuses.push(supply);
            }
            if start.elapsed() > deadline {
                panic!(
                    "no ETH reached {recipient} within {deadline:?}\n\
                     minter address: {} (balance {})\n\
                     ckETH total supply over time: {statuses:?}\n\
                     --- minter logs ---\n{}",
                    self.minter_address,
                    self.anvil.eth_balance(&self.minter_address, "latest"),
                    self.minter_logs().join("\n"),
                );
            }
            std::thread::sleep(Duration::from_secs(5));
        }
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

/// URL of a PocketIC server started by this process with a hard TTL above the Bazel timeout.
///
/// `PocketIc::new` starts every server with `--hard-ttl 600`, and the server then calls
/// `exit(124)` 600s after launch regardless of activity or requests in flight. That budget covers
/// *every* test in the binary combined, and these tests wait on the minter's 6-minute withdrawal
/// timer, so they cross it and have the server shot out from under them mid-request — surfacing as
/// `hyper::Error(IncompleteMessage)` with no hint of the cause. Starting the server here is the only
/// way to raise it: the value is not exposed through `PocketIcBuilder`.
fn long_lived_server_url() -> Url {
    // Above the target's `timeout = "eternal"` (3600s), so Bazel's own timeout is what bounds a
    // stuck run, and the hard TTL stays only a backstop against an orphaned server.
    const HARD_TTL: Duration = Duration::from_secs(4200);

    static SERVER: OnceLock<(Child, Url)> = OnceLock::new();
    SERVER
        .get_or_init(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("building a runtime for the PocketIC server must succeed");
            runtime.block_on(start_server(StartServerParams {
                reuse: true,
                hard_ttl: Some(HARD_TTL),
                ..Default::default()
            }))
        })
        .1
        .clone()
}

fn install_ledger(
    env: &PocketIc,
    ledger_id: Principal,
    minter_id: Principal,
    fee_account_balance: u128,
) {
    use ic_icrc1_ledger::InitArgsBuilder as LedgerInitArgsBuilder;

    let mut builder = LedgerInitArgsBuilder::with_symbol_and_name("ckETH", "ckETH")
        .with_minting_account(minter_id)
        .with_transfer_fee(CKETH_TRANSFER_FEE)
        .with_max_memo_length(80)
        .with_decimals(18)
        .with_feature_flags(FeatureFlags {
            icrc2: true,
            icrc152: false,
        });
    if fee_account_balance > 0 {
        builder = builder.with_initial_balance(
            Account {
                owner: minter_id,
                subaccount: Some(ic_cketh_minter::CKETH_FEE_SUBACCOUNT),
            },
            fee_account_balance,
        );
    }
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
        last_scraped_block_number: Nat::from(0_u8),
        evm_rpc_id: Some(evm_rpc_id),
    };
    env.install_canister(
        minter_id,
        minter_wasm(),
        Encode!(&MinterArg::InitArg(args)).unwrap(),
        Some(controller()),
    );
}
