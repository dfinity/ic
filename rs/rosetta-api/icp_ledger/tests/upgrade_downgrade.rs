use candid::Encode;
use ic_base_types::PrincipalId;
use ic_crypto_sha2::Sha256;
use ic_ledger_canister_core::archive::ArchiveOptions;
use ic_ledger_core::block::BlockIndex;
use ic_ledger_core::timestamp::TimeStamp;
use ic_ledger_core::Tokens;
use ic_ledger_test_utils::pocket_ic_helpers::index::{
    get_blocks, wait_until_sync_is_completed, LEDGER_INDEX_CANISTER_ID,
};
use ic_ledger_test_utils::pocket_ic_helpers::install_canister;
use ic_ledger_test_utils::pocket_ic_helpers::ledger::{
    account_balance, archives, query_blocks, query_encoded_blocks, transfer, LEDGER_CANISTER_ID,
};
use ic_ledger_test_utils::{
    build_ledger_archive_wasm, build_ledger_index_wasm, build_ledger_wasm,
    build_mainnet_ledger_archive_wasm, build_mainnet_ledger_index_wasm, build_mainnet_ledger_wasm,
};
use icp_ledger::CandidOperation::Mint;
use icp_ledger::{
    AccountIdentifier, CandidBlock, CandidTransaction, LedgerCanisterInitPayload,
    LedgerCanisterUpgradePayload, Memo, Subaccount, TransferArgs, DEFAULT_TRANSFER_FEE,
};
use maplit::hashmap;
use pocket_ic::{PocketIc, PocketIcBuilder};
use std::time::Duration;

const ARCHIVE_NUM_BLOCKS_TO_ARCHIVE: usize = 5;
/// Trigger archiving after 20 blocks.
const ARCHIVE_TRIGGER_THRESHOLD_SMALL: usize = 20;
const INITIAL_USER_ACCOUNT_BALANCE_E8S: u64 = 1_000_000_000_000;
const MINTER_PRINCIPAL: PrincipalId = PrincipalId::new(0, [0u8; 29]);
const TOO_MANY_BLOCKS: u64 = 100;

#[derive(Eq, PartialEq, Debug)]
enum UpgradeToVersion {
    /// The version currently on mainnet
    MainNet,
    /// The version built from the latest local code
    Latest,
}

struct User {
    principal: PrincipalId,
    subaccount: Subaccount,
}

impl User {
    fn account_identifier(&self) -> AccountIdentifier {
        AccountIdentifier::from(self.principal)
    }

    fn account_identifier_with_subaccount(&self) -> AccountIdentifier {
        AccountIdentifier::new(self.principal, Some(self.subaccount))
    }
}

struct Setup {
    pocket_ic: PocketIc,
    user1: User,
    user2: User,
    ledger_blocks_created: u64,
}

impl Setup {
    fn builder() -> SetupBuilder {
        SetupBuilder {
            archive_trigger_threshold: ARCHIVE_TRIGGER_THRESHOLD_SMALL,
        }
    }

    #[track_caller]
    fn assert_canister_module_hash(
        &self,
        canister_id: candid::Principal,
        expected_module_hash: &Vec<u8>,
        eq: bool,
    ) {
        let canister_status = self.pocket_ic.canister_status(canister_id, None).unwrap();
        if eq {
            assert_eq!(
                canister_status.module_hash.as_ref(),
                Some(expected_module_hash)
            );
        } else {
            assert_ne!(
                canister_status.module_hash.as_ref(),
                Some(expected_module_hash)
            );
        }
    }

    fn assert_index_ledger_parity(&self, also_retrieve_encoded_blocks_from_archives: bool) {
        wait_until_sync_is_completed(&self.pocket_ic);

        let index_blocks = get_blocks(&self.pocket_ic);
        let ledger_blocks =
            query_encoded_blocks(&self.pocket_ic, also_retrieve_encoded_blocks_from_archives);
        assert_eq!(ledger_blocks.len(), self.ledger_blocks_created as usize);
        assert_eq!(ledger_blocks.len(), index_blocks.len());
        for (ledger_block, index_block) in ledger_blocks.iter().zip(index_blocks.iter()) {
            assert_eq!(ledger_block, index_block);
        }
    }

    fn execute_icp_transfer(&mut self) -> BlockIndex {
        self.pocket_ic.advance_time(Duration::from_secs(1));
        self.pocket_ic.tick();
        let amount = 1_000_000u64;
        let transfer_args = TransferArgs {
            memo: Memo(121u64),
            amount: Tokens::from_e8s(amount),
            fee: DEFAULT_TRANSFER_FEE,
            from_subaccount: Some(self.user1.subaccount),
            to: self.user2.account_identifier().to_address(),
            created_at_time: Some(TimeStamp::from(self.pocket_ic.get_time())),
        };
        self.ledger_blocks_created += 1;
        transfer(&self.pocket_ic, self.user1.principal, transfer_args).unwrap()
    }

    fn create_icp_transfers_until_archive_is_spawned(&mut self) {
        let initial_num_ledger_archives = archives(&self.pocket_ic).len();
        loop {
            let block_index = self.execute_icp_transfer();
            let all_blocks = query_encoded_blocks(&self.pocket_ic, true);
            assert_eq!(all_blocks.len(), block_index as usize + 1usize);

            assert_eq!(block_index + 1, self.ledger_blocks_created);
            assert!(
                self.ledger_blocks_created < TOO_MANY_BLOCKS,
                "no archive spawned after reaching {} blocks, archives created: {}",
                TOO_MANY_BLOCKS,
                archives(&self.pocket_ic).len()
            );

            let ledger_archives = archives(&self.pocket_ic);
            if ledger_archives.len() > initial_num_ledger_archives {
                break;
            }
        }
    }

    fn upgrade_ledger_canister(&self, upgrade_to_version: UpgradeToVersion) {
        let ledger_wasm = match upgrade_to_version {
            UpgradeToVersion::MainNet => build_mainnet_ledger_wasm(),
            UpgradeToVersion::Latest => build_ledger_wasm(),
        };
        let ledger_upgrade_args = LedgerCanisterUpgradePayload::builder().build().unwrap();
        let canister_id = candid::Principal::from(LEDGER_CANISTER_ID);
        self.pocket_ic
            .upgrade_canister(
                canister_id,
                ledger_wasm.bytes(),
                Encode!(&ledger_upgrade_args).unwrap(),
                None,
            )
            .unwrap();
        let expected_module_hash = mainnet_ledger_canister_sha256sum();
        self.assert_canister_module_hash(
            canister_id,
            &expected_module_hash,
            upgrade_to_version == UpgradeToVersion::MainNet,
        );
    }

    fn upgrade_archive_canisters(&self, upgrade_to_version: UpgradeToVersion) {
        let archive_wasm_bytes = match upgrade_to_version {
            UpgradeToVersion::MainNet => build_mainnet_ledger_archive_wasm().bytes(),
            UpgradeToVersion::Latest => build_ledger_archive_wasm().bytes(),
        };
        let mainnet_archive_module_hash = mainnet_archive_canister_sha256sum();
        let ledger_archives = archives(&self.pocket_ic);
        for archive_canister_id in ledger_archives
            .iter()
            .map(|archive| candid::Principal::from(archive.canister_id))
        {
            self.pocket_ic
                .upgrade_canister(
                    archive_canister_id,
                    archive_wasm_bytes.clone(),
                    vec![],
                    None,
                )
                .unwrap();

            self.assert_canister_module_hash(
                archive_canister_id,
                &mainnet_archive_module_hash,
                upgrade_to_version == UpgradeToVersion::MainNet,
            );
        }
    }

    fn upgrade_index_canister(&self, upgrade_to_version: UpgradeToVersion) {
        let index_wasm = match upgrade_to_version {
            UpgradeToVersion::MainNet => build_mainnet_ledger_index_wasm(),
            UpgradeToVersion::Latest => build_ledger_index_wasm(),
        };
        let canister_id = candid::Principal::from(LEDGER_INDEX_CANISTER_ID);
        self.pocket_ic
            .upgrade_canister(canister_id, index_wasm.bytes(), vec![], None)
            .unwrap();
        let expected_module_hash = mainnet_index_canister_sha256sum();
        self.assert_canister_module_hash(
            canister_id,
            &expected_module_hash,
            upgrade_to_version == UpgradeToVersion::MainNet,
        );
    }
}

struct SetupBuilder {
    archive_trigger_threshold: usize,
}

impl SetupBuilder {
    fn build(self) -> Setup {
        let user1_principal = PrincipalId::new_user_test_id(101);
        let user1_subaccount = Subaccount([1u8; 32]);
        let user2_principal = PrincipalId::new_user_test_id(102);
        let user2_subaccount = Subaccount([2u8; 32]);
        let user1 = User {
            principal: user1_principal,
            subaccount: user1_subaccount,
        };
        let user2 = User {
            principal: user2_principal,
            subaccount: user2_subaccount,
        };
        let initial_values = hashmap! {
            user1.account_identifier_with_subaccount() => Tokens::from_e8s(INITIAL_USER_ACCOUNT_BALANCE_E8S),
        };
        let ledger_blocks_created = initial_values.len() as u64;

        let ledger_canister_init_payload = LedgerCanisterInitPayload::builder()
            .minting_account(AccountIdentifier::from(MINTER_PRINCIPAL))
            .archive_options(ArchiveOptions {
                trigger_threshold: self.archive_trigger_threshold,
                num_blocks_to_archive: ARCHIVE_NUM_BLOCKS_TO_ARCHIVE,
                // About 10 blocks, to force creation of more than one archive
                node_max_memory_size_bytes: Some(1024 + 512),
                // 128kb
                max_message_size_bytes: Some(128 * 1024),
                controller_id: PrincipalId::from(candid::Principal::anonymous()),
                more_controller_ids: None,
                cycles_for_archive_creation: Some(0),
                max_transactions_per_response: None,
            })
            .max_message_size_bytes(128 * 1024)
            // 24 hour transaction window
            .transaction_window(Duration::from_secs(24 * 60 * 60))
            .transfer_fee(DEFAULT_TRANSFER_FEE)
            .initial_values(initial_values)
            .build()
            .unwrap();
        let index_canister_init_args = ic_icp_index::InitArg {
            ledger_id: candid::Principal::from(LEDGER_CANISTER_ID),
        };

        let pocket_ic = PocketIcBuilder::new().with_nns_subnet().build();

        // Install the (mainnet) NNS canisters.
        let ledger_wasm = build_mainnet_ledger_wasm();
        install_canister(
            &pocket_ic,
            "ICP Ledger",
            LEDGER_CANISTER_ID,
            Encode!(&ledger_canister_init_payload).unwrap(),
            ledger_wasm.bytes(),
            None,
        );

        let index_wasm = build_mainnet_ledger_index_wasm();
        install_canister(
            &pocket_ic,
            "ICP Index",
            LEDGER_INDEX_CANISTER_ID,
            Encode!(&index_canister_init_args).unwrap(),
            index_wasm.bytes(),
            None,
        );

        Setup {
            pocket_ic,
            user1,
            user2,
            ledger_blocks_created,
        }
    }
}

fn mainnet_ledger_canister_sha256sum() -> Vec<u8> {
    let ledger_wasm = build_mainnet_ledger_wasm();

    let mut state = Sha256::new();
    state.write(ledger_wasm.clone().bytes().as_slice());
    state.finish().to_vec()
}

fn mainnet_archive_canister_sha256sum() -> Vec<u8> {
    let archive_wasm = build_mainnet_ledger_archive_wasm();

    let mut state = Sha256::new();
    state.write(archive_wasm.clone().bytes().as_slice());
    state.finish().to_vec()
}

fn mainnet_index_canister_sha256sum() -> Vec<u8> {
    let index_wasm = build_mainnet_ledger_index_wasm();

    let mut state = Sha256::new();
    state.write(index_wasm.clone().bytes().as_slice());
    state.finish().to_vec()
}

#[test]
fn should_set_up_initial_state_with_mainnet_canisters() {
    let setup = Setup::builder().build();
    // Flow of time:
    //  t0: Install the ledger and create the initial mint transactions
    //  t1: Install the index
    //  t2: Current time after returning from Setup::new_with_mainnet_canisters()
    // The query operations do not cause PocketIc time to move forward.
    // The steps between t0 and t1, and t1 and t2, each take 2 nanoseconds.
    const MINT_TIME_OFFSET_NANOS: u64 = 2;
    let expected_mint_timestamp = TimeStamp::from(
        setup
            .pocket_ic
            .get_time()
            .checked_sub(Duration::from_nanos(MINT_TIME_OFFSET_NANOS))
            .unwrap(),
    );
    let expected_mint_block = CandidBlock {
        parent_hash: None,
        transaction: CandidTransaction {
            operation: Some(Mint {
                to: setup
                    .user1
                    .account_identifier_with_subaccount()
                    .to_address(),
                amount: Tokens::from_e8s(INITIAL_USER_ACCOUNT_BALANCE_E8S),
            }),
            memo: Memo(0),
            icrc1_memo: None,
            created_at_time: expected_mint_timestamp,
        },
        timestamp: expected_mint_timestamp,
    };

    // Verify the initial account balances
    assert_eq!(
        account_balance(&setup.pocket_ic, &setup.user1.account_identifier()).get_e8s(),
        0u64
    );
    assert_eq!(
        account_balance(
            &setup.pocket_ic,
            &setup.user1.account_identifier_with_subaccount()
        )
        .get_e8s(),
        INITIAL_USER_ACCOUNT_BALANCE_E8S
    );
    assert_eq!(
        account_balance(&setup.pocket_ic, &setup.user2.account_identifier()).get_e8s(),
        0u64
    );
    assert_eq!(
        account_balance(
            &setup.pocket_ic,
            &setup.user2.account_identifier_with_subaccount()
        )
        .get_e8s(),
        0u64
    );

    // Verify that we have two blocks that are the initial mints.
    let get_blocks_response = query_blocks(&setup.pocket_ic, BlockIndex::from(0u64), 2);
    assert_eq!(get_blocks_response.blocks.len(), 1);
    let first_ledger_block = get_blocks_response
        .blocks
        .first()
        .expect("should contain a block");
    assert_eq!(first_ledger_block, &expected_mint_block);

    // Verify the mainnet canister module hashes
    setup.assert_canister_module_hash(
        candid::Principal::from(LEDGER_CANISTER_ID),
        &mainnet_ledger_canister_sha256sum(),
        true,
    );
    setup.assert_canister_module_hash(
        candid::Principal::from(LEDGER_INDEX_CANISTER_ID),
        &mainnet_index_canister_sha256sum(),
        true,
    );

    // Verify that no ledger archives exist
    let ledger_archives = archives(&setup.pocket_ic);
    assert!(ledger_archives.is_empty());
}

#[ignore]
#[test]
fn should_spawn_a_new_archive_with_icp_transfers() {
    let mut setup = Setup::builder().build();
    setup.assert_index_ledger_parity(false);
    setup.create_icp_transfers_until_archive_is_spawned();
    setup.assert_index_ledger_parity(true);

    // This will break if NNS Archive and NNS Ledger get upgraded to versions from
    // different git revisions.
    let expected_archive_module_hash = mainnet_archive_canister_sha256sum();
    let ledger_archives = archives(&setup.pocket_ic);
    assert_eq!(ledger_archives.len(), 1);
    for archive in ledger_archives {
        setup.assert_canister_module_hash(
            candid::Principal::from(archive.canister_id),
            &expected_archive_module_hash,
            true,
        );
    }
}

#[test]
fn should_upgrade_and_downgrade_canister_suite() {
    let mut setup = Setup::builder().build();
    setup.create_icp_transfers_until_archive_is_spawned();

    setup.upgrade_index_canister(UpgradeToVersion::Latest);
    setup.upgrade_ledger_canister(UpgradeToVersion::Latest);
    setup.upgrade_archive_canisters(UpgradeToVersion::Latest);

    setup.assert_index_ledger_parity(true);

    setup.upgrade_index_canister(UpgradeToVersion::MainNet);
    setup.upgrade_ledger_canister(UpgradeToVersion::MainNet);
    setup.upgrade_archive_canisters(UpgradeToVersion::MainNet);

    setup.assert_index_ledger_parity(true);
}
