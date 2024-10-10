use candid::{Decode, Encode};
use canister_test::Wasm;
use ic_base_types::CanisterId;
use ic_icrc1_ledger_sm_tests::{generate_transactions, TransactionGenerationParameters};
use ic_ledger_core::block::BlockType;
use ic_ledger_test_utils::state_machine_helpers::index::{
    get_all_blocks, wait_until_sync_is_completed,
};
use ic_ledger_test_utils::state_machine_helpers::ledger::icp_get_blocks;
use ic_ledger_test_utils::{
    build_ledger_archive_wasm, build_ledger_index_wasm, build_ledger_wasm,
    build_mainnet_ledger_archive_wasm, build_mainnet_ledger_index_wasm, build_mainnet_ledger_wasm,
};
use ic_nns_constants::{
    LEDGER_CANISTER_INDEX_IN_NNS_SUBNET, LEDGER_INDEX_CANISTER_INDEX_IN_NNS_SUBNET,
};
use ic_nns_test_utils_golden_nns_state::new_state_machine_with_golden_nns_state_or_panic;
use ic_pocket_ic_tests::StateMachine;
use icp_ledger::{Archives, FeatureFlags, LedgerCanisterPayload, UpgradeArgs};
use std::time::Instant;

const INDEX_CANISTER_ID: CanisterId =
    CanisterId::from_u64(LEDGER_INDEX_CANISTER_INDEX_IN_NNS_SUBNET);
const LEDGER_CANISTER_ID: CanisterId = CanisterId::from_u64(LEDGER_CANISTER_INDEX_IN_NNS_SUBNET);
const NUM_TRANSACTIONS_PER_TYPE: usize = 200;
const MINT_MULTIPLIER: u64 = 10_000;
const TRANSFER_MULTIPLIER: u64 = 1000;
const APPROVE_MULTIPLIER: u64 = 100;
const TRANSFER_FROM_MULTIPLIER: u64 = 10;
const BURN_MULTIPLIER: u64 = 1;

/// Create a state machine with the golden NNS state, then upgrade and downgrade the ICP
/// ledger canister suite.
#[test]
fn should_create_state_machine_with_golden_nns_state() {
    let setup = Setup::new();

    // Verify ledger, archives, and index block parity
    setup.verify_ledger_archive_index_block_parity();

    // Upgrade all the canisters to the latest version
    setup.upgrade_to_master();
    // Upgrade again to test the pre-upgrade
    setup.upgrade_to_master();

    // Verify ledger, archives, and index block parity
    setup.verify_ledger_archive_index_block_parity();

    setup.perform_transactions();

    // Downgrade all the canisters to the mainnet version
    setup.downgrade_to_mainnet();

    // Verify ledger, archives, and index block parity
    setup.verify_ledger_archive_index_block_parity();

    setup.perform_transactions();

    setup.verify_ledger_archive_index_block_parity();
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
}

impl Setup {
    pub fn new() -> Self {
        let state_machine = new_state_machine_with_golden_nns_state_or_panic();

        let master_wasms = Wasms {
            ledger: build_ledger_wasm(),
            index: build_ledger_index_wasm(),
            archive: build_ledger_archive_wasm(),
        };

        let mainnet_wasms = Wasms {
            ledger: build_mainnet_ledger_wasm(),
            index: build_mainnet_ledger_index_wasm(),
            archive: build_mainnet_ledger_archive_wasm(),
        };

        Self {
            state_machine,
            master_wasms,
            mainnet_wasms,
        }
    }

    pub fn upgrade_to_master(&self) {
        println!("Upgrading to master version");
        self.upgrade_index(&self.master_wasms.index);
        self.upgrade_ledger(&self.master_wasms.ledger);
        self.upgrade_archive_canisters(&self.master_wasms.archive);
    }

    pub fn downgrade_to_mainnet(&self) {
        println!("Downgrading to mainnet version");
        self.upgrade_index(&self.mainnet_wasms.index);
        self.upgrade_ledger(&self.mainnet_wasms.ledger);
        self.upgrade_archive_canisters(&self.mainnet_wasms.archive);
    }

    pub fn perform_transactions(&self) {
        generate_transactions(
            &self.state_machine,
            LEDGER_CANISTER_ID,
            TransactionGenerationParameters {
                mint_multiplier: MINT_MULTIPLIER,
                transfer_multiplier: TRANSFER_MULTIPLIER,
                approve_multiplier: APPROVE_MULTIPLIER,
                transfer_from_multiplier: TRANSFER_FROM_MULTIPLIER,
                burn_multiplier: BURN_MULTIPLIER,
                num_transactions_per_type: NUM_TRANSACTIONS_PER_TYPE,
            },
        );
        let start = Instant::now();
        wait_until_sync_is_completed(&self.state_machine, INDEX_CANISTER_ID, LEDGER_CANISTER_ID);
        println!("Time taken for index to sync: {:?}", start.elapsed());
    }

    pub fn verify_ledger_archive_index_block_parity(&self) {
        println!("Verifying ledger, archive, and index block parity");
        println!("Retrieving blocks from the ledger and archives");
        let ledger_blocks = icp_get_blocks(&self.state_machine, LEDGER_CANISTER_ID);
        // Wait for the index to sync with the ledger and archives
        wait_until_sync_is_completed(&self.state_machine, INDEX_CANISTER_ID, LEDGER_CANISTER_ID);
        println!("Retrieving {} blocks from the index", ledger_blocks.len());
        let index_blocks = get_all_blocks(
            &self.state_machine,
            INDEX_CANISTER_ID,
            0,
            ledger_blocks.len() as u64,
        )
        .blocks
        .into_iter()
        .map(icp_ledger::Block::decode)
        .collect::<Result<Vec<icp_ledger::Block>, String>>()
        .unwrap();
        assert_eq!(ledger_blocks.len(), index_blocks.len());
        assert_eq!(ledger_blocks, index_blocks);
        println!("Ledger, archive, and index block parity verified");
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

    fn upgrade_archive(&self, archive_canister_id: CanisterId, wasm_bytes: Vec<u8>) {
        self.state_machine
            .upgrade_canister(archive_canister_id, wasm_bytes, vec![])
            .unwrap_or_else(|e| {
                panic!(
                    "should successfully upgrade archive '{}' to new local version: {}",
                    archive_canister_id, e
                )
            });
    }

    fn upgrade_archive_canisters(&self, wasm: &Wasm) {
        let archives = self.list_archives().archives;
        for archive_info in &archives {
            self.upgrade_archive(archive_info.canister_id, wasm.clone().bytes());
        }
    }

    fn upgrade_index(&self, wasm: &Wasm) {
        self.state_machine
            .upgrade_canister(INDEX_CANISTER_ID, wasm.clone().bytes(), vec![])
            .expect("should successfully upgrade index to new local version");
    }

    fn upgrade_ledger(&self, wasm: &Wasm) {
        let ledger_upgrade_args: LedgerCanisterPayload =
            LedgerCanisterPayload::Upgrade(Some(UpgradeArgs {
                icrc1_minting_account: None,
                feature_flags: Some(FeatureFlags { icrc2: true }),
            }));

        self.state_machine
            .upgrade_canister(
                LEDGER_CANISTER_ID,
                wasm.clone().bytes(),
                Encode!(&ledger_upgrade_args).unwrap(),
            )
            .expect("should successfully upgrade ledger to new local version");
    }
}
