use crate::common::{index_ng_wasm, ledger_wasm, load_wasm_using_env_var};
use crate::index::verify_ledger_archive_and_index_block_parity;
use candid::{Decode, Encode, Nat, Principal};
use canister_test::Wasm;
use ic_base_types::{CanisterId, PrincipalId};
use ic_icrc1::Block;
use ic_icrc1::endpoints::StandardRecord;
use ic_icrc1_index_ng::{IndexArg, UpgradeArg as IndexUpgradeArg};
use ic_ledger_suite_in_memory_ledger::{
    AllowancesRecentlyPurged, BlockConsumer, BurnsWithoutSpender, InMemoryLedger,
};
use ic_ledger_suite_state_machine_helpers::{
    TransactionGenerationParameters, generate_transactions, get_all_ledger_and_archive_blocks,
    get_blocks, list_archives, retrieve_metrics,
};
use ic_nns_test_utils_golden_nns_state::new_state_machine_with_golden_fiduciary_state_or_panic;
use ic_state_machine_tests::{StateMachine, UserError};
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc106::errors::Icrc106Error;
use lazy_static::lazy_static;
use std::str::FromStr;
use std::time::Duration;

mod common;

const NUM_TRANSACTIONS_PER_TYPE: usize = 20;
const MINT_MULTIPLIER: u64 = 10_000;
const TRANSFER_MULTIPLIER: u64 = 1000;
const APPROVE_MULTIPLIER: u64 = 100;
const TRANSFER_FROM_MULTIPLIER: u64 = 10;
const BURN_MULTIPLIER: u64 = 1;
// Corresponds to ic_icrc1_ledger::LEDGER_VERSION where blocks are migrated to stable structures
const LEDGER_VERSION_3: u64 = 3;

#[cfg(not(feature = "u256-tokens"))]
type Tokens = ic_icrc1_tokens_u64::U64;

#[cfg(feature = "u256-tokens")]
type Tokens = ic_icrc1_tokens_u256::U256;

#[cfg(not(feature = "u256-tokens"))]
lazy_static! {
    pub static ref MAINNET_CKBTC_WASMS: Wasms = Wasms::new(
        Wasm::from_bytes(load_wasm_using_env_var(
            "CKBTC_IC_ICRC1_INDEX_DEPLOYED_VERSION_WASM_PATH",
        )),
        Wasm::from_bytes(load_wasm_using_env_var(
            "CKBTC_IC_ICRC1_LEDGER_DEPLOYED_VERSION_WASM_PATH",
        )),
        Wasm::from_bytes(load_wasm_using_env_var(
            "CKBTC_IC_ICRC1_ARCHIVE_DEPLOYED_VERSION_WASM_PATH",
        )),
        LEDGER_VERSION_3,
        None,
    );
    pub static ref MAINNET_SNS_WASMS: Wasms = Wasms::new(
        Wasm::from_bytes(load_wasm_using_env_var(
            "IC_ICRC1_INDEX_DEPLOYED_VERSION_WASM_PATH",
        )),
        Wasm::from_bytes(load_wasm_using_env_var(
            "IC_ICRC1_LEDGER_DEPLOYED_VERSION_WASM_PATH",
        )),
        Wasm::from_bytes(load_wasm_using_env_var(
            "IC_ICRC1_ARCHIVE_DEPLOYED_VERSION_WASM_PATH",
        )),
        LEDGER_VERSION_3,
        Some(Wasm::from_bytes(load_wasm_using_env_var(
            "IC_ICRC1_LEDGER_DEPLOYED_VERSION_2_WASM_PATH"
        ))),
    );
    pub static ref MASTER_WASMS: Wasms = Wasms::new(
        Wasm::from_bytes(index_ng_wasm()),
        Wasm::from_bytes(ledger_wasm()),
        Wasm::from_bytes(archive_wasm()),
        ic_icrc1_ledger::LEDGER_VERSION,
        None,
    );
    // Corresponds to https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc-2025-02-27
    // This shall be the ledger version referenced using
    // `CKBTC_IC_ICRC1_LEDGER_DEPLOYED_VERSION_WASM_PATH` and
    // `IC_ICRC1_LEDGER_DEPLOYED_VERSION_WASM_PATH` above.
    pub static ref BLOCKS_MIGRATED_LEDGER_MODULE_HASH: Vec<u8> =
        hex::decode("dca85fc694c18181b5c67c93194a7fc72f00226f3b54ac6e4630a9dfe8187503").unwrap();
}

#[cfg(feature = "u256-tokens")]
lazy_static! {
    pub static ref MAINNET_U256_WASMS: Wasms = Wasms::new(
        Wasm::from_bytes(load_wasm_using_env_var(
            "CKETH_IC_ICRC1_INDEX_DEPLOYED_VERSION_WASM_PATH",
        )),
        Wasm::from_bytes(load_wasm_using_env_var(
            "CKETH_IC_ICRC1_LEDGER_DEPLOYED_VERSION_WASM_PATH",
        )),
        Wasm::from_bytes(load_wasm_using_env_var(
            "CKETH_IC_ICRC1_ARCHIVE_DEPLOYED_VERSION_WASM_PATH",
        )),
        LEDGER_VERSION_3,
        None,
    );
    pub static ref MASTER_WASMS: Wasms = Wasms::new(
        Wasm::from_bytes(index_ng_wasm()),
        Wasm::from_bytes(ledger_wasm()),
        Wasm::from_bytes(archive_wasm()),
        ic_icrc1_ledger::LEDGER_VERSION,
        None,
    );
    // Corresponds to https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc-2025-02-27
    // This shall be the ledger version referenced using
    // `CKETH_IC_ICRC1_LEDGER_DEPLOYED_VERSION_WASM_PATH` above.
    pub static ref BLOCKS_MIGRATED_LEDGER_MODULE_HASH: Vec<u8> =
        hex::decode("d94d8283e2a71550bac5da0365ca719545e97d05c88787efb679993e2e8c12f4").unwrap();
}

pub struct Wasms {
    index_wasm: Wasm,
    ledger_wasm: Wasm,
    archive_wasm: Wasm,
    ledger_version: u64,
    ledger_wasm_v2: Option<Wasm>,
}

impl Wasms {
    fn new(
        index_wasm: Wasm,
        ledger_wasm: Wasm,
        archive_wasm: Wasm,
        ledger_version: u64,
        ledger_wasm_v2: Option<Wasm>,
    ) -> Self {
        Self {
            index_wasm,
            ledger_wasm,
            archive_wasm,
            ledger_version,
            ledger_wasm_v2,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Icrc106CheckError {
    IndexPrincipalNotSet,
    NotSupported,
}

struct LedgerSuiteConfig {
    ledger_id: &'static str,
    index_id: &'static str,
    canister_name: &'static str,
    burns_without_spender: Option<BurnsWithoutSpender<Account>>,
    extended_testing: bool,
    mainnet_wasms: &'static Wasms,
    master_wasms: &'static Wasms,
}

impl LedgerSuiteConfig {
    fn new(
        canister_ids_and_name: (&'static str, &'static str, &'static str),
        mainnet_wasms: &'static Wasms,
        master_wasms: &'static Wasms,
    ) -> Self {
        let (ledger_id, index_id, canister_name) = canister_ids_and_name;
        Self {
            ledger_id,
            index_id,
            canister_name,
            burns_without_spender: None,
            extended_testing: false,
            mainnet_wasms,
            master_wasms,
        }
    }

    fn new_with_params(
        canister_ids_and_name: (&'static str, &'static str, &'static str),
        mainnet_wasms: &'static Wasms,
        master_wasms: &'static Wasms,
        burns_without_spender: Option<BurnsWithoutSpender<Account>>,
        extended_testing: bool,
    ) -> Self {
        Self {
            burns_without_spender,
            extended_testing,
            ..Self::new(canister_ids_and_name, mainnet_wasms, master_wasms)
        }
    }

    fn perform_upgrade_downgrade_testing(&self, state_machine: &StateMachine) {
        println!(
            "Processing {}, ledger id: {}, index id: {}",
            self.canister_name, self.ledger_id, self.index_id
        );
        let ledger_canister_id =
            CanisterId::unchecked_from_principal(PrincipalId::from_str(self.ledger_id).unwrap());
        let index_canister_id =
            CanisterId::unchecked_from_principal(PrincipalId::from_str(self.index_id).unwrap());
        // Top up the ledger suite canisters so that they do not risk running out of cycles as
        // part of the upgrade/downgrade testing.
        top_up_canisters(state_machine, ledger_canister_id, index_canister_id);
        // Advance the time to make sure the ledger gets the current time for checking allowances.
        state_machine.advance_time(Duration::from_secs(1u64));
        state_machine.tick();
        let mut previous_ledger_state = None;
        if self.extended_testing {
            previous_ledger_state = Some(LedgerState::verify_state_and_generate_transactions(
                state_machine,
                ledger_canister_id,
                index_canister_id,
                self.burns_without_spender.clone(),
                None,
                AllowancesRecentlyPurged::No,
            ));
        }
        // Check if the ledger supports ICRC-106, and if so, if the index principal is set.
        let index_principal_set = self
            .check_index_principal(state_machine, ledger_canister_id, index_canister_id)
            .is_ok();
        // Upgrade to the new canister versions
        self.upgrade_to_master(state_machine);
        if self.extended_testing {
            previous_ledger_state = Some(LedgerState::verify_state_and_generate_transactions(
                state_machine,
                ledger_canister_id,
                index_canister_id,
                self.burns_without_spender.clone(),
                previous_ledger_state,
                AllowancesRecentlyPurged::Yes,
            ));
        }
        // Verify that the index principal was set in the ledger
        if index_principal_set {
            let index_principal_check =
                self.check_index_principal(state_machine, ledger_canister_id, index_canister_id);
            assert!(
                index_principal_check.is_ok(),
                "ICRC-106 index principal was set before upgrading the ledger to master, but now it is no longer set: {index_principal_check:?}"
            );
        }
        // Downgrade back to the mainnet canister versions
        self.downgrade_to_mainnet(state_machine);
        if self.extended_testing {
            let _ = LedgerState::verify_state_and_generate_transactions(
                state_machine,
                ledger_canister_id,
                index_canister_id,
                self.burns_without_spender.clone(),
                previous_ledger_state,
                AllowancesRecentlyPurged::Yes,
            );
        }
    }

    fn check_index_principal(
        &self,
        env: &StateMachine,
        ledger_canister_id: CanisterId,
        index_canister_id: CanisterId,
    ) -> Result<(), Icrc106CheckError> {
        // Check if the ledger supports ICRC-106
        let supported_standards = Decode!(
            &env.query(
                ledger_canister_id,
                "icrc1_supported_standards",
                Encode!().unwrap()
            )
            .expect("failed to query supported standards")
            .bytes(),
            Vec<StandardRecord>
        )
        .expect("failed to decode icrc1_supported_standards response");
        let mut found = false;
        for standard in supported_standards {
            if standard.name == "ICRC-106" {
                found = true;
                break;
            }
        }
        if !found {
            return Err(Icrc106CheckError::NotSupported);
        }
        // If the ledger supports ICRC-106, check if the index principal is set
        match Decode!(
            &env.query(ledger_canister_id, "icrc106_get_index_principal", Encode!().unwrap())
                .expect("failed to query icrc106_get_index_principal")
                .bytes(),
            Result<Principal, Icrc106Error>
        )
        .expect("failed to decode icrc106_get_index_principal response")
        {
            Ok(index_principal) => {
                assert_eq!(
                    index_principal,
                    index_canister_id.get().0,
                    "Index principal does not match index canister id"
                );
                Ok(())
            }
            Err(err) => {
                println!("Failed to get index principal for ledger {ledger_canister_id}: {err:?}");
                Err(Icrc106CheckError::IndexPrincipalNotSet)
            }
        }
    }

    fn print_ledger_metrics(&self, state_machine: &StateMachine) {
        let ledger_id =
            CanisterId::unchecked_from_principal(PrincipalId::from_str(self.ledger_id).unwrap());
        let metrics = retrieve_metrics(state_machine, ledger_id);
        println!("Ledger metrics:");
        for metric in metrics {
            println!("  {metric}");
        }
    }

    fn upgrade_archives_or_panic(&self, state_machine: &StateMachine, wasm: &Wasm) {
        let canister_id =
            CanisterId::unchecked_from_principal(PrincipalId::from_str(self.ledger_id).unwrap());
        let archives = list_archives(state_machine, canister_id);
        let num_archives = archives.len();
        for archive in archives {
            let archive_canister_id =
                CanisterId::unchecked_from_principal(PrincipalId(archive.canister_id));
            state_machine
                .upgrade_canister(archive_canister_id, wasm.clone().bytes(), vec![])
                .unwrap_or_else(|e| {
                    panic!("should successfully upgrade archive '{archive_canister_id}': {e}")
                });
        }
        println!("Upgraded {num_archives} archive(s)");
    }

    fn upgrade_index_or_panic(&self, state_machine: &StateMachine, wasm: &Wasm) {
        let canister_id =
            CanisterId::unchecked_from_principal(PrincipalId::from_str(self.index_id).unwrap());
        let index_upgrade_arg = IndexArg::Upgrade(IndexUpgradeArg {
            ledger_id: None,
            retrieve_blocks_from_ledger_interval_seconds: None,
        });
        let args = Encode!(&index_upgrade_arg).unwrap();
        state_machine
            .upgrade_canister(canister_id, wasm.clone().bytes(), args.clone())
            .expect("should successfully upgrade index canister");
        println!("Upgraded {} index '{}'", self.canister_name, self.index_id);
    }

    fn upgrade_ledger(&self, state_machine: &StateMachine, wasm: &Wasm) -> Result<(), UserError> {
        let canister_id =
            CanisterId::unchecked_from_principal(PrincipalId::from_str(self.ledger_id).unwrap());
        let args = ic_icrc1_ledger::LedgerArgument::Upgrade(None);
        let args = Encode!(&args).unwrap();
        match state_machine.upgrade_canister(canister_id, wasm.clone().bytes(), args.clone()) {
            Ok(_) => {
                println!(
                    "Upgraded {} ledger '{}'",
                    self.canister_name, self.ledger_id
                );
                self.print_ledger_metrics(state_machine);
                Ok(())
            }
            Err(e) => {
                println!(
                    "Error upgrading {} ledger '{}': {:?}",
                    self.canister_name, self.ledger_id, e
                );
                Err(e)
            }
        }
    }

    fn downgrade_to_mainnet(&self, state_machine: &StateMachine) {
        // Downgrade each canister twice to exercise pre-upgrade
        self.upgrade_index_or_panic(state_machine, &self.mainnet_wasms.index_wasm);
        self.upgrade_index_or_panic(state_machine, &self.mainnet_wasms.index_wasm);
        let expected_downgrade_result =
            self.mainnet_wasms.ledger_version == self.master_wasms.ledger_version;
        let ledger_upgrade_res =
            self.upgrade_ledger(state_machine, &self.mainnet_wasms.ledger_wasm);
        match (expected_downgrade_result, ledger_upgrade_res) {
            (true, Ok(_)) => {
                // Perform another downgrade to exercise the pre-upgrade
                self.upgrade_ledger(state_machine, &self.mainnet_wasms.ledger_wasm)
                    .expect("should downgrade to mainnet ledger version");
            }
            (true, Err(e)) => {
                panic!("should successfully downgrade to mainnet ledger version: {e}");
            }
            (false, Ok(_)) => {
                panic!("should not successfully downgrade to mainnet ledger version");
            }
            (false, Err(_)) => {
                println!("Failed to downgrade to mainnet ledger version as expected");
            }
        }
        self.upgrade_archives_or_panic(state_machine, &self.mainnet_wasms.archive_wasm);
        self.upgrade_archives_or_panic(state_machine, &self.mainnet_wasms.archive_wasm);
    }

    fn upgrade_to_master(&self, state_machine: &StateMachine) {
        // Upgrade each canister twice to exercise pre-upgrade
        self.upgrade_index_or_panic(state_machine, &self.master_wasms.index_wasm);
        self.upgrade_index_or_panic(state_machine, &self.master_wasms.index_wasm);
        self.upgrade_ledger(state_machine, &self.master_wasms.ledger_wasm)
            .or_else(|e| {
                match (
                    e.description().contains(
                        "Cannot upgrade from scratch stable memory, please upgrade to memory manager first."
                    ),
                    &self.mainnet_wasms.ledger_wasm_v2
                ) {
                    // The upgrade may fail if the target canister is too old - in the case of
                    // migration to stable structures, the ledger canister must be at least at V2,
                    // i.e., the ledger state must be managed by the memory manager.
                    (true, Some(wasm_v2)) => {
                        self.upgrade_ledger(state_machine, wasm_v2)
                            .expect("should successfully upgrade ledger to V2");
                        self.upgrade_ledger(state_machine, &self.master_wasms.ledger_wasm)
                    }
                    _ => Err(e)
                }
            })
            .expect("should successfully upgrade ledger");
        // No migration expected in second upgrade to the same version
        self.upgrade_ledger(state_machine, &self.master_wasms.ledger_wasm)
            .expect("should successfully upgrade ledger");
        self.upgrade_archives_or_panic(state_machine, &self.master_wasms.archive_wasm);
        self.upgrade_archives_or_panic(state_machine, &self.master_wasms.archive_wasm);
    }
}

struct FetchedBlocks {
    blocks: Vec<Block<Tokens>>,
    start_index: u64,
}

struct LedgerState {
    in_memory_ledger: InMemoryLedger<Account, Tokens>,
    num_blocks: u64,
}

impl LedgerState {
    fn assert_eq(&self, other: &Self) {
        assert_eq!(
            other.num_blocks, self.num_blocks,
            "Number of blocks ({}) does not match number of blocks in previous state ({})",
            self.num_blocks, other.num_blocks,
        );
        assert!(
            other.in_memory_ledger == self.in_memory_ledger,
            "In-memory ledger state does not match previous state"
        );
    }

    /// Fetch the next blocks from the ledger canister and ingest them into the in-memory ledger.
    /// If `total_num_blocks` is `None`, fetch all blocks from the ledger canister, otherwise fetch
    /// `total_num_blocks - self.num_blocks` blocks (some amount of latest blocks that the in-memory
    /// ledger does not hold yet).
    fn fetch_and_ingest_next_ledger_and_archive_blocks(
        &mut self,
        state_machine: &StateMachine,
        canister_id: CanisterId,
        total_num_blocks: Option<u64>,
    ) -> FetchedBlocks {
        let num_blocks = total_num_blocks
            .unwrap_or(u64::MAX)
            .saturating_sub(self.num_blocks);
        let start_index = self.num_blocks;
        let blocks = get_all_ledger_and_archive_blocks(
            state_machine,
            canister_id,
            Some(start_index),
            Some(num_blocks),
        );
        self.num_blocks = self
            .num_blocks
            .checked_add(blocks.len() as u64)
            .expect("number of blocks should fit in u64");
        self.in_memory_ledger.consume_blocks(&blocks);
        FetchedBlocks {
            blocks,
            start_index,
        }
    }

    fn new(burns_without_spender: Option<BurnsWithoutSpender<Account>>) -> Self {
        let in_memory_ledger = InMemoryLedger::new(burns_without_spender);
        Self {
            in_memory_ledger,
            num_blocks: 0,
        }
    }

    fn verify_balances_and_allowances(
        &self,
        state_machine: &StateMachine,
        canister_id: CanisterId,
        allowances_recently_purged: AllowancesRecentlyPurged,
    ) {
        let num_ledger_blocks =
            get_blocks(state_machine, Principal::from(canister_id), 0, 0).chain_length;
        self.in_memory_ledger.verify_balances_and_allowances(
            state_machine,
            canister_id,
            num_ledger_blocks,
            allowances_recently_purged,
        );
    }

    /// Verify the ledger state and generate new transactions. In particular:
    /// - Create a new instance of an in-memory ledger by fetching blocks from the ledger
    ///   - If a previous ledger state is provided, only fetch the blocks that were present when
    ///     the previous state was generated.
    /// - Verify that the balances and allowances in the in-memory ledger match the ledger
    ///   canister state
    /// - If a previous ledger state is provided, assert that the state of the newly-generated
    ///   in-memory ledger state matches that of the previous state
    /// - Generate transactions on the ledger canister
    /// - Fetch all blocks from the ledger canister into the new `ledger_state`
    /// - Return the new `ledger_state`
    fn verify_state_and_generate_transactions(
        state_machine: &StateMachine,
        ledger_id: CanisterId,
        index_id: CanisterId,
        burns_without_spender: Option<BurnsWithoutSpender<Account>>,
        previous_ledger_state: Option<LedgerState>,
        allowances_recently_purged: AllowancesRecentlyPurged,
    ) -> Self {
        let num_blocks_to_fetch = previous_ledger_state
            .as_ref()
            .map(|previous_ledger_state| previous_ledger_state.num_blocks);

        let mut ledger_state = LedgerState::new(burns_without_spender);
        // Only fetch the blocks that were present when the previous state was generated. This is
        // necessary since there may have been in-transit messages for the ledger in the backup,
        // or new transactions triggered e.g., by timers running in other canisters on the subnet,
        // that get applied after the `StateMachine` is initialized, and are not part of the
        // transactions in `generate_transactions`.
        let ledger_and_archive_blocks = ledger_state
            .fetch_and_ingest_next_ledger_and_archive_blocks(
                state_machine,
                ledger_id,
                num_blocks_to_fetch,
            );
        ledger_state.verify_balances_and_allowances(
            state_machine,
            ledger_id,
            allowances_recently_purged,
        );
        // Verify parity between the blocks in the ledger+archive, and those in the index
        verify_ledger_archive_and_index_block_parity(
            state_machine,
            ledger_and_archive_blocks,
            ledger_id,
            index_id,
        );
        // Verify the reconstructed ledger state matches the previous state
        if let Some(previous_ledger_state) = &previous_ledger_state {
            ledger_state.assert_eq(previous_ledger_state);
        }
        generate_transactions(
            state_machine,
            ledger_id,
            TransactionGenerationParameters {
                mint_multiplier: MINT_MULTIPLIER,
                transfer_multiplier: TRANSFER_MULTIPLIER,
                approve_multiplier: APPROVE_MULTIPLIER,
                transfer_from_multiplier: TRANSFER_FROM_MULTIPLIER,
                burn_multiplier: BURN_MULTIPLIER,
                num_transactions_per_type: NUM_TRANSACTIONS_PER_TYPE,
            },
        );
        // Fetch all blocks into the new `ledger_state`. This call only retrieves blocks that were
        // not fetched in the previous call to `fetch_next_blocks`.
        let ledger_and_archive_blocks = ledger_state
            .fetch_and_ingest_next_ledger_and_archive_blocks(state_machine, ledger_id, None);
        verify_ledger_archive_and_index_block_parity(
            state_machine,
            ledger_and_archive_blocks,
            ledger_id,
            index_id,
        );
        ledger_state
    }
}

#[cfg(not(feature = "u256-tokens"))]
#[test]
fn should_upgrade_icrc_ck_btc_canister_with_golden_state() {
    const CK_BTC_LEDGER_CANISTER_ID: &str = "mxzaz-hqaaa-aaaar-qaada-cai";
    const CK_BTC_INDEX_CANISTER_ID: &str = "n5wcd-faaaa-aaaar-qaaea-cai";
    const CK_BTC_LEDGER_CANISTER_NAME: &str = "ckBTC";

    let ck_btc_minter = icrc_ledger_types::icrc1::account::Account {
        owner: PrincipalId::from_str("mqygn-kiaaa-aaaar-qaadq-cai")
            .unwrap()
            .0,
        subaccount: None,
    };
    let burns_without_spender = BurnsWithoutSpender {
        minter: ck_btc_minter,
        burn_indexes: vec![
            100785, 101298, 104447, 116240, 454395, 455558, 458776, 460251,
        ],
    };

    let state_machine = new_state_machine_with_golden_fiduciary_state_or_panic();

    LedgerSuiteConfig::new_with_params(
        (
            CK_BTC_LEDGER_CANISTER_ID,
            CK_BTC_INDEX_CANISTER_ID,
            CK_BTC_LEDGER_CANISTER_NAME,
        ),
        &MAINNET_CKBTC_WASMS,
        &MASTER_WASMS,
        Some(burns_without_spender),
        true,
    )
    .perform_upgrade_downgrade_testing(&state_machine);
}

#[cfg(feature = "u256-tokens")]
#[test]
fn should_upgrade_icrc_ck_u256_canisters_with_golden_state() {
    // u256 testnet ledgers
    const CK_SEPOLIA_LINK_LEDGER_SUITE: (&str, &str, &str) = (
        "r52mc-qaaaa-aaaar-qafzq-cai",
        "ri55p-riaaa-aaaar-qaf2a-cai",
        "ckSepoliaLINK",
    );
    const CK_SEPOLIA_PEPE_LEDGER_SUITE: (&str, &str, &str) = (
        "hw4ru-taaaa-aaaar-qagdq-cai",
        "g3sv2-4iaaa-aaaar-qagea-cai",
        "ckSepoliaPEPE",
    );
    const CK_SEPOLIA_USDC_LEDGER_SUITE: (&str, &str, &str) = (
        "yfumr-cyaaa-aaaar-qaela-cai",
        "ycvkf-paaaa-aaaar-qaelq-cai",
        "ckSepoliaUSDC",
    );
    // u256 production ledgers
    const CK_ETH_LEDGER_SUITE: (&str, &str, &str) = (
        "ss2fx-dyaaa-aaaar-qacoq-cai",
        "s3zol-vqaaa-aaaar-qacpa-cai",
        "ckETH",
    );
    const CK_EURC_LEDGER_SUITE: (&str, &str, &str) = (
        "pe5t5-diaaa-aaaar-qahwa-cai",
        "pd4vj-oqaaa-aaaar-qahwq-cai",
        "ckEURC",
    );
    const CK_LINK_LEDGER_SUITE: (&str, &str, &str) = (
        "g4tto-rqaaa-aaaar-qageq-cai",
        "gvqys-hyaaa-aaaar-qagfa-cai",
        "ckLINK",
    );
    const CK_OCT_LEDGER_SUITE: (&str, &str, &str) = (
        "ebo5g-cyaaa-aaaar-qagla-cai",
        "egp3s-paaaa-aaaar-qaglq-cai",
        "ckOCT",
    );
    const CK_PEPE_LEDGER_SUITE: (&str, &str, &str) = (
        "etik7-oiaaa-aaaar-qagia-cai",
        "eujml-dqaaa-aaaar-qagiq-cai",
        "ckPEPE",
    );
    const CK_SHIB_LEDGER_SUITE: (&str, &str, &str) = (
        "fxffn-xiaaa-aaaar-qagoa-cai",
        "fqedz-2qaaa-aaaar-qagoq-cai",
        "ckSHIB",
    );
    const CK_UNI_LEDGER_SUITE: (&str, &str, &str) = (
        "ilzky-ayaaa-aaaar-qahha-cai",
        "imymm-naaaa-aaaar-qahhq-cai",
        "ckUNI",
    );
    const CK_USDC_LEDGER_SUITE: (&str, &str, &str) = (
        "xevnm-gaaaa-aaaar-qafnq-cai",
        "xrs4b-hiaaa-aaaar-qafoa-cai",
        "ckUSDC",
    );
    const CK_USDT_LEDGER_SUITE: (&str, &str, &str) = (
        "cngnf-vqaaa-aaaar-qag4q-cai",
        "cefgz-dyaaa-aaaar-qag5a-cai",
        "ckUSDT",
    );
    const CK_WBTC_LEDGER_SUITE: (&str, &str, &str) = (
        "bptq2-faaaa-aaaar-qagxq-cai",
        "dso6s-wiaaa-aaaar-qagya-cai",
        "ckWBTC",
    );
    const CK_WSTETH_LEDGER_SUITE: (&str, &str, &str) = (
        "j2tuh-yqaaa-aaaar-qahcq-cai",
        "jtq73-oyaaa-aaaar-qahda-cai",
        "ckWSTETH",
    );
    const CK_XAUT_LEDGER_SUITE: (&str, &str, &str) = (
        "nza5v-qaaaa-aaaar-qahzq-cai",
        "nmhmy-riaaa-aaaar-qah2a-cai",
        "ckXAUT",
    );

    let ck_eth_minter = icrc_ledger_types::icrc1::account::Account {
        owner: PrincipalId::from_str("sv3dd-oaaaa-aaaar-qacoa-cai")
            .unwrap()
            .0,
        subaccount: None,
    };
    let ck_eth_burns_without_spender = BurnsWithoutSpender {
        minter: ck_eth_minter,
        burn_indexes: vec![
            1051, 1094, 1276, 1759, 1803, 1929, 2449, 2574, 2218, 2219, 2231, 1777, 4, 9, 31, 1540,
            1576, 1579, 1595, 1607, 1617, 1626, 1752, 1869, 1894, 2013, 2555,
        ],
    };

    let mut canister_configs = vec![LedgerSuiteConfig::new_with_params(
        CK_ETH_LEDGER_SUITE,
        &MAINNET_U256_WASMS,
        &MASTER_WASMS,
        Some(ck_eth_burns_without_spender),
        true,
    )];
    for canister_id_and_name in vec![
        CK_SEPOLIA_LINK_LEDGER_SUITE,
        CK_SEPOLIA_PEPE_LEDGER_SUITE,
        CK_SEPOLIA_USDC_LEDGER_SUITE,
        CK_EURC_LEDGER_SUITE,
        CK_USDC_LEDGER_SUITE,
        CK_LINK_LEDGER_SUITE,
        CK_OCT_LEDGER_SUITE,
        CK_PEPE_LEDGER_SUITE,
        CK_SHIB_LEDGER_SUITE,
        CK_UNI_LEDGER_SUITE,
        CK_USDT_LEDGER_SUITE,
        CK_WBTC_LEDGER_SUITE,
        CK_WSTETH_LEDGER_SUITE,
        CK_XAUT_LEDGER_SUITE,
    ] {
        canister_configs.push(LedgerSuiteConfig::new(
            canister_id_and_name,
            &MAINNET_U256_WASMS,
            &MASTER_WASMS,
        ));
    }

    let state_machine = new_state_machine_with_golden_fiduciary_state_or_panic();

    for canister_config in canister_configs {
        canister_config.perform_upgrade_downgrade_testing(&state_machine);
    }
}

#[cfg(not(feature = "u256-tokens"))]
#[test]
fn should_upgrade_icrc_sns_canisters_with_golden_state() {
    // SNS canisters
    const ALICE_LEDGER_SUITE: (&str, &str, &str) = (
        "oj6if-riaaa-aaaaq-aaeha-cai",
        "mtcaz-pyaaa-aaaaq-aaeia-cai",
        "Alice",
    );
    const BOOMDAO_LEDGER_SUITE: (&str, &str, &str) = (
        "vtrom-gqaaa-aaaaq-aabia-cai",
        "v5tde-5aaaa-aaaaq-aabja-cai",
        "BoomDAO",
    );
    const CATALYZE_LEDGER_SUITE: (&str, &str, &str) = (
        "uf2wh-taaaa-aaaaq-aabna-cai",
        "ux4b6-7qaaa-aaaaq-aaboa-cai",
        "Catalyze",
    );
    const CECIL_THE_LION_DAO_LEDGER_SUITE: (&str, &str, &str) = (
        "jg2ra-syaaa-aaaaq-aaewa-cai",
        "jiy4i-jiaaa-aaaaq-aaexa-cai",
        "Cecil The Lion DAO",
    );
    const DECIDEAI_LEDGER_SUITE: (&str, &str, &str) = (
        "xsi2v-cyaaa-aaaaq-aabfq-cai",
        "xaonm-oiaaa-aaaaq-aabgq-cai",
        "DecideAI",
    );
    const DOLR_AI_LEDGER_SUITE: (&str, &str, &str) = (
        "6rdgd-kyaaa-aaaaq-aaavq-cai",
        "6dfr2-giaaa-aaaaq-aaawq-cai",
        "DOLR",
    );
    const DRAGGINZ_LEDGER_SUITE: (&str, &str, &str) = (
        "zfcdd-tqaaa-aaaaq-aaaga-cai",
        "zlaol-iaaaa-aaaaq-aaaha-cai",
        "DRAGGINZ",
    );
    const ELNAAI_LEDGER_SUITE: (&str, &str, &str) = (
        "gemj7-oyaaa-aaaaq-aacnq-cai",
        "gwk6g-ciaaa-aaaaq-aacoq-cai",
        "ELNA AI",
    );
    const ESTATEDAO_LEDGER_SUITE: (&str, &str, &str) = (
        "bliq2-niaaa-aaaaq-aac4q-cai",
        "bfk5s-wyaaa-aaaaq-aac5q-cai",
        "EstateDAO",
    );
    const FOMOWELL_LEDGER_SUITE: (&str, &str, &str) = (
        "o4zzi-qaaaa-aaaaq-aaeeq-cai",
        "os3ua-lqaaa-aaaaq-aaefq-cai",
        "FomoWell",
    );
    // const FUEL_EV_LEDGER_SUITE: (&str, &str, &str) = (
    //     "nfjys-2iaaa-aaaaq-aaena-cai",
    //     "nxppl-wyaaa-aaaaq-aaeoa-cai",
    //     "FuelEV",
    // );
    const GOLDDAO_LEDGER_SUITE: (&str, &str, &str) = (
        "tyyy3-4aaaa-aaaaq-aab7a-cai",
        "efv5g-kqaaa-aaaaq-aacaa-cai",
        "GoldDAO",
    );
    const IC_EXPLORER_LEDGER_SUITE: (&str, &str, &str) = (
        "ifwyg-gaaaa-aaaaq-aaeqq-cai",
        "iluvo-5qaaa-aaaaq-aaerq-cai",
        "IC Explorer",
    );
    const ICFC_LEDGER_SUITE: (&str, &str, &str) = (
        "ddsp7-7iaaa-aaaaq-aacqq-cai",
        "dnqcx-eyaaa-aaaaq-aacrq-cai",
        "ICFC",
    );
    const ICLIGHTHOUSE_LEDGER_SUITE: (&str, &str, &str) = (
        "hhaaz-2aaaa-aaaaq-aacla-cai",
        "gnpcd-yqaaa-aaaaq-aacma-cai",
        "ICLighthouse DAO",
    );
    const ICPANDA_LEDGER_SUITE: (&str, &str, &str) = (
        "druyg-tyaaa-aaaaq-aactq-cai",
        "c3324-riaaa-aaaaq-aacuq-cai",
        "ICPanda DAO",
    );
    const ICPEX_LEDGER_SUITE: (&str, &str, &str) = (
        "lvfsa-2aaaa-aaaaq-aaeyq-cai",
        "l3h7i-bqaaa-aaaaq-aaezq-cai",
        "ICPEX",
    );
    const ICPSWAP_LEDGER_SUITE: (&str, &str, &str) = (
        "ca6gz-lqaaa-aaaaq-aacwa-cai",
        "co4lr-qaaaa-aaaaq-aacxa-cai",
        "ICPSwap",
    );
    const KINIC_LEDGER_SUITE: (&str, &str, &str) = (
        "73mez-iiaaa-aaaaq-aaasq-cai",
        "7vojr-tyaaa-aaaaq-aaatq-cai",
        "Kinic",
    );
    const KONG_SWAP_LEDGER_SUITE: (&str, &str, &str) = (
        "o7oak-iyaaa-aaaaq-aadzq-cai",
        "onixt-eiaaa-aaaaq-aad2q-cai",
        "KongSwap",
    );
    const MIMIC_LEDGER_SUITE: (&str, &str, &str) = (
        "4c4fd-caaaa-aaaaq-aaa3a-cai",
        "5ithz-aqaaa-aaaaq-aaa4a-cai",
        "Mimic",
    );
    const MOTOKO_LEDGER_SUITE: (&str, &str, &str) = (
        "k45jy-aiaaa-aaaaq-aadcq-cai",
        "ks7eq-3yaaa-aaaaq-aaddq-cai",
        "Motoko",
    );
    const NEUTRINITE_LEDGER_SUITE: (&str, &str, &str) = (
        "f54if-eqaaa-aaaaq-aacea-cai",
        "ft6fn-7aaaa-aaaaq-aacfa-cai",
        "Neutrinite",
    );
    const NFID_WALLET_LEDGER_SUITE: (&str, &str, &str) = (
        "mih44-vaaaa-aaaaq-aaekq-cai",
        "mgfru-oqaaa-aaaaq-aaelq-cai",
        "NFID Wallet",
    );
    const NUANCE_LEDGER_SUITE: (&str, &str, &str) = (
        "rxdbk-dyaaa-aaaaq-aabtq-cai",
        "q5mdq-biaaa-aaaaq-aabuq-cai",
        "Nuance",
    );
    const OPENCHAT_LEDGER_SUITE: (&str, &str, &str) = (
        "2ouva-viaaa-aaaaq-aaamq-cai",
        "2awyi-oyaaa-aaaaq-aaanq-cai",
        "OpenChat",
    );
    const ORIGYN_LEDGER_SUITE: (&str, &str, &str) = (
        "lkwrt-vyaaa-aaaaq-aadhq-cai",
        "jqkzp-liaaa-aaaaq-aadiq-cai",
        "Origyn",
    );
    const PERSONAL_DAO_LEDGER_SUITE: (&str, &str, &str) = (
        "ixqp7-kqaaa-aaaaq-aaetq-cai",
        "j57nf-iaaaa-aaaaq-aaeuq-cai",
        "Personal DAO",
    );
    const POKEDBOTS_LEDGER_SUITE: (&str, &str, &str) = (
        "np5km-uyaaa-aaaaq-aadrq-cai",
        "n535v-yiaaa-aaaaq-aadsq-cai",
        "PokedBots",
    );
    const SNEED_LEDGER_SUITE: (&str, &str, &str) = (
        "hvgxa-wqaaa-aaaaq-aacia-cai",
        "h3e2i-naaaa-aaaaq-aacja-cai",
        "Sneed",
    );
    const SONIC_LEDGER_SUITE: (&str, &str, &str) = (
        "qbizb-wiaaa-aaaaq-aabwq-cai",
        "qpkuj-nyaaa-aaaaq-aabxq-cai",
        "Sonic",
    );
    const SWAMPIES_LEDGER_SUITE: (&str, &str, &str) = (
        "lrtnw-paaaa-aaaaq-aadfa-cai",
        "ldv2p-dqaaa-aaaaq-aadga-cai",
        "Swampies",
    );
    const TACO_LEDGER_SUITE: (&str, &str, &str) = (
        "kknbx-zyaaa-aaaaq-aae4a-cai",
        "kepm7-ciaaa-aaaaq-aae5a-cai",
        "TACO DAO",
    );
    const TRAX_LEDGER_SUITE: (&str, &str, &str) = (
        "emww2-4yaaa-aaaaq-aacbq-cai",
        "e6qbd-qiaaa-aaaaq-aaccq-cai",
        "Trax",
    );
    const WATERNEURON_LEDGER_SUITE: (&str, &str, &str) = (
        "jcmow-hyaaa-aaaaq-aadlq-cai",
        "iidmm-fiaaa-aaaaq-aadmq-cai",
        "WaterNeuron",
    );
    const YUKU_LEDGER_SUITE: (&str, &str, &str) = (
        "atbfz-diaaa-aaaaq-aacyq-cai",
        "a5dir-yyaaa-aaaaq-aaczq-cai",
        "Yuku DAO",
    );

    let mut canister_configs = vec![LedgerSuiteConfig::new_with_params(
        OPENCHAT_LEDGER_SUITE,
        &MAINNET_SNS_WASMS,
        &MASTER_WASMS,
        None,
        true,
    )];
    for canister_id_and_name in vec![
        ALICE_LEDGER_SUITE,
        BOOMDAO_LEDGER_SUITE,
        CATALYZE_LEDGER_SUITE,
        CECIL_THE_LION_DAO_LEDGER_SUITE,
        DECIDEAI_LEDGER_SUITE,
        DOLR_AI_LEDGER_SUITE,
        DRAGGINZ_LEDGER_SUITE,
        ELNAAI_LEDGER_SUITE,
        ESTATEDAO_LEDGER_SUITE,
        FOMOWELL_LEDGER_SUITE,
        // FUEL_EV_LEDGER_SUITE, // Skipping FuelEV for now, as the index canister was uninstalled
        GOLDDAO_LEDGER_SUITE,
        IC_EXPLORER_LEDGER_SUITE,
        ICFC_LEDGER_SUITE,
        ICLIGHTHOUSE_LEDGER_SUITE,
        ICPANDA_LEDGER_SUITE,
        ICPEX_LEDGER_SUITE,
        ICPSWAP_LEDGER_SUITE,
        KINIC_LEDGER_SUITE,
        KONG_SWAP_LEDGER_SUITE,
        MIMIC_LEDGER_SUITE,
        MOTOKO_LEDGER_SUITE,
        NEUTRINITE_LEDGER_SUITE,
        NFID_WALLET_LEDGER_SUITE,
        NUANCE_LEDGER_SUITE,
        ORIGYN_LEDGER_SUITE,
        PERSONAL_DAO_LEDGER_SUITE,
        POKEDBOTS_LEDGER_SUITE,
        SNEED_LEDGER_SUITE,
        SONIC_LEDGER_SUITE,
        SWAMPIES_LEDGER_SUITE,
        TACO_LEDGER_SUITE,
        TRAX_LEDGER_SUITE,
        WATERNEURON_LEDGER_SUITE,
        YUKU_LEDGER_SUITE,
    ] {
        canister_configs.push(LedgerSuiteConfig::new(
            canister_id_and_name,
            &MAINNET_SNS_WASMS,
            &MASTER_WASMS,
        ));
    }

    let state_machine =
        ic_nns_test_utils_golden_nns_state::new_state_machine_with_golden_sns_state_or_panic();

    for canister_config in canister_configs {
        canister_config.perform_upgrade_downgrade_testing(&state_machine);
    }
}

fn archive_wasm() -> Vec<u8> {
    load_wasm_using_env_var("IC_ICRC1_ARCHIVE_WASM_PATH")
}

fn top_up_canisters(
    state_machine: &StateMachine,
    ledger_canister_id: CanisterId,
    index_canister_id: CanisterId,
) {
    const TOP_UP_AMOUNT: u128 = 2_000_000_000_000_000; // 2_000 T cycles
    let archives = list_archives(state_machine, ledger_canister_id);
    for archive in archives {
        let archive_canister_id =
            CanisterId::unchecked_from_principal(PrincipalId(archive.canister_id));
        state_machine.add_cycles(archive_canister_id, TOP_UP_AMOUNT);
    }
    state_machine.add_cycles(ledger_canister_id, TOP_UP_AMOUNT);
    state_machine.add_cycles(index_canister_id, TOP_UP_AMOUNT);
}

mod index {
    use super::*;
    use candid::Decode;
    use ic_icrc1_index_ng::Status;
    use ic_state_machine_tests::WasmResult;
    use icrc_ledger_types::icrc3::blocks::GetBlocksRequest;
    use std::time::{Duration, Instant};

    pub fn get_all_index_blocks(
        state_machine: &StateMachine,
        index_id: CanisterId,
        start_index: Option<u64>,
        num_blocks: Option<u64>,
    ) -> Vec<Block<Tokens>> {
        let start_index = start_index.unwrap_or(0);
        let num_blocks = num_blocks.unwrap_or(u32::MAX as u64);

        let res = get_index_blocks(state_machine, index_id, 0_u64, 0_u64);
        let length = num_blocks.min(res.chain_length.saturating_sub(start_index));
        let mut blocks: Vec<_> = vec![];
        let mut curr_start = start_index;
        while length > blocks.len() as u64 {
            let new_blocks = get_index_blocks(
                state_machine,
                index_id,
                curr_start,
                length - (curr_start - start_index),
            )
            .blocks;
            assert!(!new_blocks.is_empty());
            curr_start += new_blocks.len() as u64;
            blocks.extend(new_blocks);
        }
        blocks
            .into_iter()
            .map(ic_icrc1::Block::try_from)
            .collect::<Result<Vec<Block<Tokens>>, String>>()
            .expect("should convert generic blocks to ICRC1 blocks")
    }

    pub fn verify_ledger_archive_and_index_block_parity(
        state_machine: &StateMachine,
        ledger_and_archive_blocks: FetchedBlocks,
        ledger_id: CanisterId,
        index_id: CanisterId,
    ) {
        if ledger_and_archive_blocks.blocks.is_empty() {
            println!("No blocks to retrieve from index");
            return;
        } else {
            println!(
                "Verifying ledger and archives vs index block parity for {} blocks starting at index {}",
                ledger_and_archive_blocks.blocks.len(),
                ledger_and_archive_blocks.start_index
            );
        }
        wait_until_index_sync_is_completed(state_machine, index_id, ledger_id);
        let start = Instant::now();
        let index_blocks = get_all_index_blocks(
            state_machine,
            index_id,
            Some(ledger_and_archive_blocks.start_index),
            Some(ledger_and_archive_blocks.blocks.len() as u64),
        );
        assert_eq!(
            ledger_and_archive_blocks.blocks.len(),
            index_blocks.len(),
            "Number of blocks fetched from the ledger and index do not match: {} vs {}",
            ledger_and_archive_blocks.blocks.len(),
            index_blocks.len()
        );
        assert_eq!(ledger_and_archive_blocks.blocks, index_blocks);
        println!(
            "Verified ledger and archives vs index block parity for {} blocks starting at index {} in {:?}",
            index_blocks.len(),
            ledger_and_archive_blocks.start_index,
            start.elapsed()
        );
    }

    pub fn wait_until_index_sync_is_completed(
        env: &StateMachine,
        index_id: CanisterId,
        ledger_id: CanisterId,
    ) {
        const MAX_ATTEMPTS: u8 = 100;
        const SYNC_STEP_SECONDS: Duration = Duration::from_secs(1);

        let mut num_blocks_synced = u64::MAX;
        let mut chain_length = u64::MAX;
        for _i in 0..MAX_ATTEMPTS {
            env.advance_time(SYNC_STEP_SECONDS);
            env.tick();
            num_blocks_synced = u64::try_from(status(env, index_id).num_blocks_synced.0)
                .expect("num_blocks_synced should fit in u64");
            chain_length = get_index_blocks(env, ledger_id, 0u64, 0u64).chain_length;
            if num_blocks_synced == chain_length {
                return;
            }
        }
        panic!(
            "The index canister was unable to sync all the blocks with the ledger. Number of blocks synced {num_blocks_synced} but the Ledger chain length is {chain_length}"
        );
    }

    fn get_index_blocks<I>(
        state_machine: &StateMachine,
        index_id: CanisterId,
        start_index: I,
        num_blocks: I,
    ) -> ic_icrc1_index_ng::GetBlocksResponse
    where
        I: Into<Nat>,
    {
        let req = GetBlocksRequest {
            start: start_index.into(),
            length: num_blocks.into(),
        };
        let req = Encode!(&req).expect("Failed to encode GetBlocksRequest");
        let res = state_machine
            .query(index_id, "get_blocks", req)
            .expect("Failed to send get_blocks request")
            .bytes();
        Decode!(&res, ic_icrc1_index_ng::GetBlocksResponse)
            .expect("Failed to decode GetBlocksResponse")
    }

    fn status(state_machine: &StateMachine, canister_id: CanisterId) -> Status {
        let arg = Encode!(&()).unwrap();
        match state_machine.query(canister_id, "status", arg) {
            Err(err) => {
                panic!("{canister_id}.status query failed with error {err}");
            }
            Ok(WasmResult::Reject(err)) => {
                panic!("{canister_id}.status query rejected with error {err}");
            }
            Ok(WasmResult::Reply(res)) => {
                Decode!(&res, Status).expect("error decoding response to status query")
            }
        }
    }
}
