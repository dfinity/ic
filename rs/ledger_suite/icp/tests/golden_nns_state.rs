use candid::{Decode, Encode};
use canister_test::Wasm;
use ic_base_types::CanisterId;
use ic_ledger_core::Tokens;
use ic_ledger_core::block::BlockType;
use ic_ledger_suite_in_memory_ledger::{
    AllowancesRecentlyPurged, BlockConsumer, BurnsWithoutSpender, InMemoryLedger,
};
use ic_ledger_suite_state_machine_helpers::{
    TransactionGenerationParameters, generate_transactions, parse_metric, retrieve_metrics,
};
use ic_ledger_test_utils::state_machine_helpers::index::{
    get_all_blocks, wait_until_sync_is_completed,
};
use ic_ledger_test_utils::state_machine_helpers::ledger::{icp_get_blocks, icp_ledger_tip};
use ic_nns_test_utils_golden_nns_state::new_state_machine_with_golden_nns_state_or_panic;
use ic_state_machine_tests::{ErrorCode, StateMachine, UserError};
use icp_ledger::{
    AccountIdentifier, Archives, Block, FeatureFlags, LEDGER_CANISTER_ID, LEDGER_INDEX_CANISTER_ID,
    LedgerCanisterPayload, UpgradeArgs,
};
use std::time::{Duration, Instant};

/// The number of instructions that can be executed in a single canister upgrade as per
/// https://internetcomputer.org/docs/current/developer-docs/smart-contracts/maintain/resource-limits#resource-constraints-and-limits
const CANISTER_UPGRADE_INSTRUCTION_LIMIT: u64 = 300_000_000_000;
const NUM_TRANSACTIONS_PER_TYPE: usize = 200;
const MINT_MULTIPLIER: u64 = 10_000;
const TRANSFER_MULTIPLIER: u64 = 1000;
const APPROVE_MULTIPLIER: u64 = 100;
const TRANSFER_FROM_MULTIPLIER: u64 = 10;
const BURN_MULTIPLIER: u64 = 1;

struct FetchedBlocks {
    blocks: Vec<Block>,
    start_index: usize,
}

struct LedgerState {
    in_memory_ledger: InMemoryLedger<AccountIdentifier, Tokens>,
    num_blocks: usize,
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
        total_num_blocks: Option<usize>,
    ) -> FetchedBlocks {
        let num_blocks = total_num_blocks
            .unwrap_or(u32::MAX as usize)
            .saturating_sub(self.num_blocks);
        let start_index = self.num_blocks;
        let blocks = icp_get_blocks(
            state_machine,
            canister_id,
            Some(start_index as u64),
            Some(num_blocks),
        );
        self.num_blocks = self
            .num_blocks
            .checked_add(blocks.len())
            .expect("number of blocks should fit in usize");
        self.in_memory_ledger.consume_blocks(&blocks);
        FetchedBlocks {
            blocks,
            start_index,
        }
    }

    fn new(burns_without_spender: Option<BurnsWithoutSpender<AccountIdentifier>>) -> Self {
        let in_memory_ledger = InMemoryLedger::new(burns_without_spender);
        Self {
            in_memory_ledger,
            num_blocks: 0,
        }
    }

    fn verify_balances_and_allowances(
        &mut self,
        state_machine: &StateMachine,
        canister_id: CanisterId,
        allowances_recently_purged: AllowancesRecentlyPurged,
    ) {
        let num_ledger_blocks = icp_ledger_tip(state_machine, canister_id) + 1;
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
        _index_id: CanisterId,
        burns_without_spender: Option<BurnsWithoutSpender<AccountIdentifier>>,
        previous_ledger_state: Option<LedgerState>,
        should_verify_balances_and_allowances: bool,
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
        if should_verify_balances_and_allowances {
            ledger_state.verify_balances_and_allowances(
                state_machine,
                ledger_id,
                allowances_recently_purged,
            );
        }
        // Verify parity between the blocks in the ledger+archive, and those in the index
        LedgerState::verify_ledger_archive_index_block_parity(
            state_machine,
            ledger_and_archive_blocks,
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
        // Verify parity between the blocks in the ledger+archive, and those in the index
        LedgerState::verify_ledger_archive_index_block_parity(
            state_machine,
            ledger_and_archive_blocks,
        );
        ledger_state
    }

    fn verify_ledger_archive_index_block_parity(
        state_machine: &StateMachine,
        ledger_and_archive_blocks: FetchedBlocks,
    ) {
        println!("Verifying ledger, archive, and index block parity");
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
        let now = Instant::now();
        // Wait for the index to sync with the ledger and archives
        wait_until_sync_is_completed(state_machine, LEDGER_INDEX_CANISTER_ID, LEDGER_CANISTER_ID);
        println!(
            "Retrieving {} blocks from the index",
            ledger_and_archive_blocks.blocks.len()
        );
        let index_blocks = get_all_blocks(
            state_machine,
            LEDGER_INDEX_CANISTER_ID,
            ledger_and_archive_blocks.start_index as u64,
            ledger_and_archive_blocks.blocks.len() as u64,
        )
        .blocks
        .into_iter()
        .map(icp_ledger::Block::decode)
        .collect::<Result<Vec<icp_ledger::Block>, String>>()
        .unwrap();
        assert_eq!(ledger_and_archive_blocks.blocks.len(), index_blocks.len());
        assert_eq!(ledger_and_archive_blocks.blocks, index_blocks);
        println!(
            "Ledger, archive, and index block parity for {} blocks starting at index {} verified in {:?}",
            ledger_and_archive_blocks.blocks.len(),
            ledger_and_archive_blocks.start_index,
            now.elapsed()
        );
    }
}

/// Create a state machine with the golden NNS state, then upgrade and downgrade the ICP
/// ledger canister suite.
#[test]
fn should_create_state_machine_with_golden_nns_state() {
    let mut setup = Setup::new();

    // Advance the time to make sure the ledger gets the current time for checking allowances.
    setup.state_machine.advance_time(Duration::from_secs(1u64));
    setup.state_machine.tick();

    // Perform upgrade and downgrade testing
    // (verify ledger balances and allowances, parity between ledger+archives and index)
    // Verifying the balances requires the ledger having the (currently test-only) allowance
    // endpoint for retrieving allowances based on AccountIdentifier pair key, so this check needs
    // to be skipped for a ledger running the mainnet production version of the ledger.
    setup.perform_upgrade_downgrade_testing(false, AllowancesRecentlyPurged::No);

    // Upgrade all the canisters to the latest version
    setup.upgrade_to_master();
    // Upgrade again to test the pre-upgrade
    setup.upgrade_to_master();

    // Perform upgrade and downgrade testing
    setup.perform_upgrade_downgrade_testing(true, AllowancesRecentlyPurged::Yes);

    // Downgrade all the canisters to the mainnet version
    // For breaking changes, e.g., if mainnet is running a version with balances and allowances in
    // stable structures, but master also has blocks in stable structures, `ledger_is_downgradable`
    // should be set to `false`, otherwise `true`.
    setup.downgrade_to_mainnet(true);

    // Verify ledger balance and allowance state
    // As before, the allowance check needs to be skipped for the mainnet version of the ledger.
    setup.perform_upgrade_downgrade_testing(false, AllowancesRecentlyPurged::Yes);
}

struct Wasms {
    ledger: Wasm,
    index: Wasm,
    archive: Wasm,
}

struct Setup {
    state_machine: StateMachine,
    master_wasms: Wasms,
    mainnet_wasms: Wasms,
    previous_ledger_state: Option<LedgerState>,
}

impl Setup {
    pub fn new() -> Self {
        let state_machine = new_state_machine_with_golden_nns_state_or_panic();

        let master_wasms = Wasms {
            ledger: Wasm::from_bytes(
                std::fs::read(std::env::var("LEDGER_CANISTER_WASM_PATH").unwrap())
                    .expect("Could not read ledger wasm"),
            ),
            index: Wasm::from_bytes(
                std::fs::read(std::env::var("IC_ICP_INDEX_CANISTER_WASM_PATH").unwrap())
                    .expect("Could not read index wasm"),
            ),
            archive: Wasm::from_bytes(
                std::fs::read(std::env::var("LEDGER_ARCHIVE_NODE_CANISTER_WASM_PATH").unwrap())
                    .expect("Could not read archive wasm"),
            ),
        };

        let mainnet_wasms = Wasms {
            ledger: Wasm::from_bytes(
                std::fs::read(std::env::var("MAINNET_ICP_LEDGER_CANISTER_WASM_PATH").unwrap())
                    .expect("Could not read mainnet ledger wasm"),
            ),
            index: Wasm::from_bytes(
                std::fs::read(std::env::var("MAINNET_ICP_INDEX_CANISTER_WASM_PATH").unwrap())
                    .expect("Could not read mainnet index wasm"),
            ),
            archive: Wasm::from_bytes(
                std::fs::read(
                    std::env::var("MAINNET_ICP_LEDGER_ARCHIVE_NODE_CANISTER_WASM_PATH").unwrap(),
                )
                .expect("Could not read mainnet archive wasm"),
            ),
        };

        Self {
            state_machine,
            master_wasms,
            mainnet_wasms,
            previous_ledger_state: None,
        }
    }

    pub fn upgrade_to_master(&self) {
        println!("Upgrading to master version");
        self.upgrade_index(&self.master_wasms.index);
        self.upgrade_ledger(&self.master_wasms.ledger)
            .expect("should successfully upgrade ledger to new local version");
        self.check_ledger_metrics();
        self.upgrade_archive_canisters(
            &self.master_wasms.archive,
            Encode!(&()).expect("failed to encode archive upgrade arg"),
        );
    }

    pub fn downgrade_to_mainnet(&self, ledger_is_downgradable: bool) {
        println!("Downgrading to mainnet version");
        self.upgrade_index(&self.mainnet_wasms.index);
        match (
            ledger_is_downgradable,
            self.upgrade_ledger(&self.mainnet_wasms.ledger),
        ) {
            (false, Ok(_)) => {
                panic!("should fail to downgrade ledger to mainnet version");
            }
            (true, Ok(_)) => {
                // The ledger was downgraded successfully, which is what was expected to happen
            }
            (false, Err(err)) => {
                // The ledger will still be running the master version, while the other canisters
                // will be downgraded to the mainnet version. This is not an ideal situation, nor
                // is it expected to happen in practice, but for the moment let's run the test to
                // completion.
                err.assert_contains(
                    ErrorCode::CanisterCalledTrap,
                    "Trying to downgrade from incompatible version",
                );
            }
            (true, Err(err)) => {
                panic!("should successfully downgrade ledger to mainnet version: {err}");
            }
        }
        self.check_ledger_metrics();
        self.upgrade_archive_canisters(&self.mainnet_wasms.archive, vec![]);
    }

    pub fn perform_upgrade_downgrade_testing(
        &mut self,
        should_verify_balances_and_allowances: bool,
        allowances_recently_purged: AllowancesRecentlyPurged,
    ) {
        self.previous_ledger_state = Some(LedgerState::verify_state_and_generate_transactions(
            &self.state_machine,
            LEDGER_CANISTER_ID,
            LEDGER_INDEX_CANISTER_ID,
            None,
            self.previous_ledger_state.take(),
            should_verify_balances_and_allowances,
            allowances_recently_purged,
        ));
    }

    fn check_ledger_metrics(&self) {
        let metrics = retrieve_metrics(&self.state_machine, LEDGER_CANISTER_ID);
        println!("Ledger metrics:");
        for metric in metrics {
            println!("  {metric}");
        }
        let upgrade_instructions = parse_metric(
            &self.state_machine,
            LEDGER_CANISTER_ID,
            "ledger_total_upgrade_instructions_consumed",
        );
        assert!(
            upgrade_instructions < CANISTER_UPGRADE_INSTRUCTION_LIMIT,
            "Upgrade instructions ({upgrade_instructions}) should be less than the instruction limit ({CANISTER_UPGRADE_INSTRUCTION_LIMIT})"
        );
    }

    fn list_archives(&self) -> Archives {
        Decode!(
            &self
                .state_machine
                .query(LEDGER_CANISTER_ID, "archives", Encode!().unwrap())
                .expect("failed to query archives")
                .bytes(),
            Archives
        )
        .expect("failed to decode archives response")
    }

    fn upgrade_archive_canisters(&self, wasm: &Wasm, upgrade_arg: Vec<u8>) {
        let archives = self.list_archives().archives;
        for archive_info in &archives {
            self.state_machine
                .upgrade_canister(
                    archive_info.canister_id,
                    wasm.clone().bytes(),
                    upgrade_arg.clone(),
                )
                .expect("failed to upgrade archive");
        }
    }

    fn upgrade_index(&self, wasm: &Wasm) {
        self.state_machine
            .upgrade_canister(LEDGER_INDEX_CANISTER_ID, wasm.clone().bytes(), vec![])
            .expect("should successfully upgrade index to new local version");
    }

    fn upgrade_ledger(&self, wasm: &Wasm) -> Result<(), UserError> {
        let ledger_upgrade_args: LedgerCanisterPayload =
            LedgerCanisterPayload::Upgrade(Some(UpgradeArgs {
                icrc1_minting_account: None,
                feature_flags: Some(FeatureFlags { icrc2: true }),
            }));

        self.state_machine.upgrade_canister(
            LEDGER_CANISTER_ID,
            wasm.clone().bytes(),
            Encode!(&ledger_upgrade_args).unwrap(),
        )
    }
}
