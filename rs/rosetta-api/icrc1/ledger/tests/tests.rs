use candid::{CandidType, Decode, Encode, Nat};
use ic_base_types::{CanisterId, PrincipalId};
use ic_icrc1::{Block, Operation, Transaction};
use ic_icrc1_ledger::{ChangeFeeCollector, FeatureFlags, InitArgs, LedgerArgument};
use ic_icrc1_ledger_sm_tests::{
    get_allowance, send_approval, send_transfer_from, ARCHIVE_TRIGGER_THRESHOLD, BLOB_META_KEY,
    BLOB_META_VALUE, DECIMAL_PLACES, FEE, INT_META_KEY, INT_META_VALUE, MINTER, NAT_META_KEY,
    NAT_META_VALUE, NUM_BLOCKS_TO_ARCHIVE, TEXT_META_KEY, TEXT_META_VALUE, TOKEN_NAME,
    TOKEN_SYMBOL,
};
use ic_ledger_canister_core::archive::ArchiveOptions;
use ic_ledger_core::block::{BlockIndex, BlockType};
use ic_ledger_hash_of::{HashOf, HASH_LENGTH};
use ic_state_machine_tests::StateMachine;
use icrc_ledger_types::icrc::generic_metadata_value::MetadataValue as Value;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::{TransferArg, TransferError};
use icrc_ledger_types::icrc2::allowance::Allowance;
use icrc_ledger_types::icrc2::approve::{ApproveArgs, ApproveError};
use icrc_ledger_types::icrc2::transfer_from::{TransferFromArgs, TransferFromError};
use icrc_ledger_types::icrc3::archive::{GetArchivesArgs, GetArchivesResult};
use num_traits::ToPrimitive;
use std::path::PathBuf;

#[derive(CandidType, Clone, Debug, PartialEq, Eq)]
pub struct LegacyInitArgs {
    pub minting_account: Account,
    pub fee_collector_account: Option<Account>,
    pub initial_balances: Vec<(Account, u64)>,
    pub transfer_fee: u64,
    pub token_name: String,
    pub token_symbol: String,
    pub metadata: Vec<(String, Value)>,
    pub archive_options: ArchiveOptions,
}

#[derive(CandidType, Clone, Debug, Default, PartialEq, Eq)]
pub struct LegacyUpgradeArgs {
    pub metadata: Option<Vec<(String, Value)>>,
    pub token_name: Option<String>,
    pub token_symbol: Option<String>,
    pub transfer_fee: Option<u64>,
    pub change_fee_collector: Option<ChangeFeeCollector>,
}

#[allow(clippy::large_enum_variant)]
#[derive(CandidType, Clone, Debug, PartialEq, Eq)]
pub enum LegacyLedgerArgument {
    Init(LegacyInitArgs),
    Upgrade(Option<LegacyUpgradeArgs>),
}

fn ledger_wasm() -> Vec<u8> {
    ic_test_utilities_load_wasm::load_wasm(
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        "ic-icrc1-ledger",
        &[],
    )
}

fn archive_wasm() -> Vec<u8> {
    ic_test_utilities_load_wasm::load_wasm(
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .parent()
            .unwrap()
            .join("archive"),
        "ic-icrc1-archive",
        &[],
    )
}

fn encode_init_args(args: ic_icrc1_ledger_sm_tests::InitArgs) -> LedgerArgument {
    LedgerArgument::Init(InitArgs {
        minting_account: MINTER,
        fee_collector_account: args.fee_collector_account,
        initial_balances: args.initial_balances,
        transfer_fee: FEE.into(),
        token_name: TOKEN_NAME.to_string(),
        decimals: Some(DECIMAL_PLACES),
        token_symbol: TOKEN_SYMBOL.to_string(),
        metadata: vec![
            Value::entry(NAT_META_KEY, NAT_META_VALUE),
            Value::entry(INT_META_KEY, INT_META_VALUE),
            Value::entry(TEXT_META_KEY, TEXT_META_VALUE),
            Value::entry(BLOB_META_KEY, BLOB_META_VALUE),
        ],
        archive_options: ArchiveOptions {
            trigger_threshold: ARCHIVE_TRIGGER_THRESHOLD as usize,
            num_blocks_to_archive: NUM_BLOCKS_TO_ARCHIVE as usize,
            node_max_memory_size_bytes: None,
            max_message_size_bytes: None,
            controller_id: PrincipalId::new_user_test_id(100),
            more_controller_ids: None,
            cycles_for_archive_creation: None,
            max_transactions_per_response: None,
        },
        max_memo_length: None,
        feature_flags: args.feature_flags,
        maximum_number_of_accounts: args.maximum_number_of_accounts,
        accounts_overflow_trim_quantity: args.accounts_overflow_trim_quantity,
    })
}

#[test]
fn test_metadata() {
    ic_icrc1_ledger_sm_tests::test_metadata(ledger_wasm(), encode_init_args)
}

#[test]
fn test_upgrade() {
    ic_icrc1_ledger_sm_tests::test_upgrade(ledger_wasm(), encode_init_args)
}

#[test]
fn test_tx_deduplication() {
    ic_icrc1_ledger_sm_tests::test_tx_deduplication(ledger_wasm(), encode_init_args);
}

#[test]
fn test_mint_burn() {
    ic_icrc1_ledger_sm_tests::test_mint_burn(ledger_wasm(), encode_init_args);
}
#[test]
fn test_single_transfer() {
    ic_icrc1_ledger_sm_tests::test_single_transfer(ledger_wasm(), encode_init_args);
}

#[test]
fn test_account_canonicalization() {
    ic_icrc1_ledger_sm_tests::test_account_canonicalization(ledger_wasm(), encode_init_args);
}

#[test]
fn test_tx_time_bounds() {
    ic_icrc1_ledger_sm_tests::test_tx_time_bounds(ledger_wasm(), encode_init_args);
}

#[test]
fn test_archiving() {
    ic_icrc1_ledger_sm_tests::test_archiving(ledger_wasm(), encode_init_args, archive_wasm());
}

#[test]
fn test_get_blocks() {
    ic_icrc1_ledger_sm_tests::test_get_blocks(ledger_wasm(), encode_init_args);
}

// Generate random blocks and check that their CBOR encoding complies with the CDDL spec.
#[test]
fn block_encoding_agrees_with_the_schema() {
    ic_icrc1_ledger_sm_tests::block_encoding_agrees_with_the_schema();
}

// Generate random blocks and check that their value encoding complies with the ICRC-3 spec.
#[test]
fn block_encoding_agrees_with_the_icrc3_schema() {
    ic_icrc1_ledger_sm_tests::block_encoding_agreed_with_the_icrc3_schema();
}

// Check that different blocks produce different hashes.
#[test]
fn transaction_hashes_are_unique() {
    ic_icrc1_ledger_sm_tests::transaction_hashes_are_unique();
}

// Check that different blocks produce different hashes.
#[test]
fn block_hashes_are_unique() {
    ic_icrc1_ledger_sm_tests::block_hashes_are_unique();
}

// Generate random blocks and check that the block hash is stable.
#[test]
fn block_hashes_are_stable() {
    ic_icrc1_ledger_sm_tests::block_hashes_are_stable();
}

#[test]
fn check_transfer_model() {
    ic_icrc1_ledger_sm_tests::check_transfer_model(ledger_wasm(), encode_init_args);
}

#[test]
fn check_fee_collector() {
    ic_icrc1_ledger_sm_tests::test_fee_collector(ledger_wasm(), encode_init_args);
}

#[test]
fn check_fee_collector_blocks() {
    ic_icrc1_ledger_sm_tests::test_fee_collector_blocks(ledger_wasm(), encode_init_args);
}

#[test]
fn check_memo_max_len() {
    ic_icrc1_ledger_sm_tests::test_memo_max_len(ledger_wasm(), encode_init_args);
}

#[test]
fn test_approve_smoke() {
    ic_icrc1_ledger_sm_tests::test_approve_smoke(ledger_wasm(), encode_init_args);
}

#[test]
fn test_approve_expiration() {
    ic_icrc1_ledger_sm_tests::test_approve_expiration(ledger_wasm(), encode_init_args);
}

#[test]
fn test_approve_self() {
    ic_icrc1_ledger_sm_tests::test_approve_self(ledger_wasm(), encode_init_args);
}

#[test]
fn test_approve_expected_allowance() {
    ic_icrc1_ledger_sm_tests::test_approve_expected_allowance(ledger_wasm(), encode_init_args);
}

#[test]
fn test_approve_cant_pay_fee() {
    ic_icrc1_ledger_sm_tests::test_approve_cant_pay_fee(ledger_wasm(), encode_init_args);
}

#[test]
fn test_approve_cap() {
    ic_icrc1_ledger_sm_tests::test_approve_cap(ledger_wasm(), encode_init_args);
}

#[test]
fn test_approve_pruning() {
    ic_icrc1_ledger_sm_tests::test_approve_pruning(ledger_wasm(), encode_init_args);
}

#[test]
fn test_approve_from_minter() {
    ic_icrc1_ledger_sm_tests::test_approve_from_minter(ledger_wasm(), encode_init_args);
}

#[test]
fn test_transfer_from_smoke() {
    ic_icrc1_ledger_sm_tests::test_transfer_from_smoke(ledger_wasm(), encode_init_args);
}

#[test]
fn test_transfer_from_self() {
    ic_icrc1_ledger_sm_tests::test_transfer_from_self(ledger_wasm(), encode_init_args);
}

#[test]
fn test_transfer_from_minter() {
    ic_icrc1_ledger_sm_tests::test_transfer_from_minter(ledger_wasm(), encode_init_args);
}

#[test]
fn test_transfer_from_burn() {
    ic_icrc1_ledger_sm_tests::test_transfer_from_burn(ledger_wasm(), encode_init_args);
}

#[test]
fn test_balances_overflow() {
    ic_icrc1_ledger_sm_tests::test_balances_overflow(ledger_wasm(), encode_init_args);
}

#[test]
fn test_approval_trimming() {
    ic_icrc1_ledger_sm_tests::test_approval_trimming(ledger_wasm(), encode_init_args);
}

#[test]
fn test_archive_controllers() {
    ic_icrc1_ledger_sm_tests::test_archive_controllers(ledger_wasm());
}

#[test]
fn test_archive_no_additional_controllers() {
    ic_icrc1_ledger_sm_tests::test_archive_no_additional_controllers(ledger_wasm());
}

#[test]
fn test_archive_duplicate_controllers() {
    ic_icrc1_ledger_sm_tests::test_archive_duplicate_controllers(ledger_wasm());
}

// #[test]
// fn test_icrc1_test_suite() {
//     ic_icrc1_ledger_sm_tests::test_icrc1_test_suite(ledger_wasm(), encode_init_args);
// }

#[cfg_attr(feature = "u256-tokens", ignore)]
#[test]
fn test_block_transformation() {
    ic_icrc1_ledger_sm_tests::icrc1_test_block_transformation(
        std::fs::read(std::env::var("IC_ICRC1_LEDGER_DEPLOYED_VERSION_WASM_PATH").unwrap())
            .unwrap(),
        ledger_wasm(),
        encode_init_args,
    );
}

// Validate upgrade of the Ledger from previous versions

fn account(n: u64) -> Account {
    Account {
        owner: PrincipalId::new_user_test_id(n).0,
        subaccount: None,
    }
}

fn transfer(
    env: &StateMachine,
    ledger_id: CanisterId,
    from: Account,
    to: Account,
    amount: u64,
) -> BlockIndex {
    let args = Encode!(&TransferArg {
        from_subaccount: None,
        to,
        amount: amount.into(),
        fee: None,
        created_at_time: None,
        memo: None
    })
    .unwrap();
    let res = env
        .execute_ingress_as(from.owner.into(), ledger_id, "icrc1_transfer", args)
        .expect("Unable to perform icrc1_transfer")
        .bytes();
    Decode!(&res, Result<Nat, TransferError>)
        .unwrap()
        .expect("Unable to decode icrc1_transfer error")
        .0
        .to_u64()
        .unwrap()
}

fn balance_of(env: &StateMachine, ledger_id: CanisterId, account: Account) -> u64 {
    let args = Encode!(&account).unwrap();
    let res = env
        .query(ledger_id, "icrc1_balance_of", args)
        .expect("Unable to perform icrc1_balance_of")
        .bytes();
    Decode!(&res, Nat).unwrap().0.to_u64().unwrap()
}

#[cfg_attr(feature = "u256-tokens", ignore)]
#[test]
fn test_upgrade_from_first_version() {
    let env = StateMachine::new();

    let ledger_wasm_first_version =
        std::fs::read(std::env::var("IC_ICRC1_LEDGER_FIRST_VERSION_WASM_PATH").unwrap()).unwrap();
    let init_args = Encode!(&LegacyInitArgs {
        minting_account: MINTER,
        fee_collector_account: None,
        initial_balances: vec![],
        transfer_fee: FEE,
        token_name: TOKEN_NAME.to_string(),
        token_symbol: TOKEN_SYMBOL.to_string(),
        metadata: vec![
            Value::entry(NAT_META_KEY, NAT_META_VALUE),
            Value::entry(INT_META_KEY, INT_META_VALUE),
            Value::entry(TEXT_META_KEY, TEXT_META_VALUE),
            Value::entry(BLOB_META_KEY, BLOB_META_VALUE),
        ],
        archive_options: ArchiveOptions {
            trigger_threshold: ARCHIVE_TRIGGER_THRESHOLD as usize,
            num_blocks_to_archive: NUM_BLOCKS_TO_ARCHIVE as usize,
            node_max_memory_size_bytes: None,
            max_message_size_bytes: None,
            controller_id: PrincipalId::new_user_test_id(100),
            more_controller_ids: None,
            cycles_for_archive_creation: None,
            max_transactions_per_response: None,
        },
    })
    .unwrap();
    let ledger_id = env
        .install_canister(ledger_wasm_first_version, init_args, None)
        .unwrap();
    transfer(&env, ledger_id, MINTER, account(1), 1_000_000);
    transfer(&env, ledger_id, MINTER, account(1), 2_000_000);
    transfer(&env, ledger_id, MINTER, account(2), 3_000_000);
    transfer(&env, ledger_id, account(1), account(3), 1_000_000);
    let balance_1 = balance_of(&env, ledger_id, account(1));
    let balance_2 = balance_of(&env, ledger_id, account(2));
    let balance_3 = balance_of(&env, ledger_id, account(3));

    let upgrade_args = Encode!(&LedgerArgument::Upgrade(None)).unwrap();
    env.upgrade_canister(ledger_id, ledger_wasm(), upgrade_args)
        .expect("Unable to upgrade the ledger canister");
    assert_eq!(balance_1, balance_of(&env, ledger_id, account(1)));
    assert_eq!(balance_2, balance_of(&env, ledger_id, account(2)));
    assert_eq!(balance_3, balance_of(&env, ledger_id, account(3)));

    // check that transfer works
    transfer(&env, ledger_id, MINTER, account(1), 1_000_000);
    transfer(&env, ledger_id, MINTER, account(1), 2_000_000);
    transfer(&env, ledger_id, MINTER, account(2), 3_000_000);
    transfer(&env, ledger_id, account(1), account(3), 1_000_000);
}

#[test]
fn test_icrc2_feature_flag_doesnt_disable_icrc2_endpoints() {
    // Disable ICRC-2 and check the endpoints still work

    let env = StateMachine::new();
    let init_args = Encode!(&LedgerArgument::Init(InitArgs {
        minting_account: MINTER,
        fee_collector_account: None,
        initial_balances: vec![],
        transfer_fee: FEE.into(),
        token_name: TOKEN_NAME.to_string(),
        decimals: Some(DECIMAL_PLACES),
        token_symbol: TOKEN_SYMBOL.to_string(),
        metadata: vec![],
        archive_options: ArchiveOptions {
            trigger_threshold: ARCHIVE_TRIGGER_THRESHOLD as usize,
            num_blocks_to_archive: NUM_BLOCKS_TO_ARCHIVE as usize,
            node_max_memory_size_bytes: None,
            max_message_size_bytes: None,
            controller_id: PrincipalId::new_user_test_id(100),
            more_controller_ids: None,
            cycles_for_archive_creation: None,
            max_transactions_per_response: None,
        },
        max_memo_length: None,
        feature_flags: Some(FeatureFlags { icrc2: false }),
        maximum_number_of_accounts: None,
        accounts_overflow_trim_quantity: None,
    }))
    .unwrap();
    let ledger_id = env
        .install_canister(ledger_wasm(), init_args, None)
        .unwrap();
    let user1 = account(1);
    let user2 = account(2);
    let user3 = account(3);

    // if ICRC-2 is enabled then none of the following operations
    // should trap

    assert_eq!(
        get_allowance(&env, ledger_id, user1, user2),
        Allowance {
            allowance: 0u32.into(),
            expires_at: None
        }
    );

    let approval_result = send_approval(
        &env,
        ledger_id,
        user1.owner,
        &ApproveArgs {
            from_subaccount: None,
            spender: user3,
            amount: 1_000_000u32.into(),
            expected_allowance: None,
            expires_at: None,
            fee: None,
            memo: None,
            created_at_time: None,
        },
    );
    assert_eq!(
        approval_result,
        Err(ApproveError::InsufficientFunds {
            balance: 0u32.into()
        })
    );

    let transfer_from_result = send_transfer_from(
        &env,
        ledger_id,
        user3.owner,
        &TransferFromArgs {
            spender_subaccount: None,
            from: user1,
            to: user2,
            amount: 1_000_000u32.into(),
            fee: None,
            memo: None,
            created_at_time: None,
        },
    );
    assert_eq!(
        transfer_from_result,
        Err(TransferFromError::InsufficientAllowance {
            allowance: 0u32.into()
        })
    );
}

fn icrc3_get_archives(
    env: &StateMachine,
    ledger_id: CanisterId,
    args: GetArchivesArgs,
) -> GetArchivesResult {
    let args = Encode!(&args).unwrap();
    let res = env
        .query(ledger_id, "icrc3_get_archives", args)
        .expect("Unable to call icrc3_get_archives")
        .bytes();
    Decode!(&res, GetArchivesResult).unwrap()
}

#[cfg(not(feature = "u256-tokens"))]
pub type Tokens = ic_icrc1_tokens_u64::U64;

#[cfg(feature = "u256-tokens")]
pub type Tokens = ic_icrc1_tokens_u256::U256;

#[test]
fn test_icrc3_get_archives() {
    let env = StateMachine::new();
    let minting_account = account(111);

    let mint_block_size = Block {
        parent_hash: Some(HashOf::new([1; HASH_LENGTH])),
        transaction: Transaction {
            operation: Operation::Mint {
                to: minting_account,
                amount: Tokens::from(1_000_000u64),
            },
            created_at_time: None,
            memo: None,
        },
        effective_fee: None,
        timestamp: 0,
        fee_collector: None,
        fee_collector_block_index: None,
    }
    .encode()
    .size_bytes();
    // Make it so an archive can keep up to two blocks. There is a
    // bit of overhead so 2.5 * mint_block_size is used
    let node_max_memory_size_bytes = Some((2.5 * mint_block_size as f64).ceil() as u64);
    // Trigger block archival every 2 blocks local to the ledger and
    // archive both blocks immediately
    let trigger_threshold = 2;
    let num_blocks_to_archive = 2;

    let args = LedgerArgument::Init(InitArgs {
        minting_account,
        fee_collector_account: None,
        initial_balances: vec![],
        transfer_fee: Nat::from(0u64),
        decimals: None,
        token_name: "Not a Token".to_string(),
        token_symbol: "NAT".to_string(),
        metadata: vec![],
        archive_options: ArchiveOptions {
            trigger_threshold,
            num_blocks_to_archive,
            node_max_memory_size_bytes,
            max_message_size_bytes: None,
            controller_id: PrincipalId(minting_account.owner),
            more_controller_ids: None,
            cycles_for_archive_creation: None,
            max_transactions_per_response: None,
        },
        max_memo_length: None,
        feature_flags: None,
        maximum_number_of_accounts: None,
        accounts_overflow_trim_quantity: None,
    });
    let args = Encode!(&args).unwrap();
    let ledger_id = env
        .install_canister(ledger_wasm(), args, None)
        .expect("Unable to install the ledger");

    // check that there are no archives if there are no blocks
    let actual = icrc3_get_archives(&env, ledger_id, GetArchivesArgs { from: None });
    assert_eq!(actual, vec![]);

    let actual = icrc3_get_archives(
        &env,
        ledger_id,
        GetArchivesArgs {
            from: Some(minting_account.owner),
        },
    );
    assert_eq!(actual, vec![]);

    // push 4 mint blocks to create 2 archives (see archive options above)
    for _block_id in 0..4 {
        let _ = transfer(&env, ledger_id, minting_account, account(1), 1_000_000);
    }
    let mut actual = icrc3_get_archives(&env, ledger_id, GetArchivesArgs { from: None });
    assert_eq!(2, actual.len());
    actual.sort_by(|i1, i2| i1.start.cmp(&i2.start));
    // the first archive contains blocks 0 and 1
    assert_eq!(0u64, actual[0].start);
    assert_eq!(1u64, actual[0].end);
    // the second archive contains blocks 2 and 3
    assert_eq!(2u64, actual[1].start);
    assert_eq!(3u64, actual[1].end);

    // query all the archives after the first one
    let from = actual.iter().map(|info| info.canister_id).min();
    let actual = icrc3_get_archives(&env, ledger_id, GetArchivesArgs { from });
    assert_eq!(1, actual.len());

    // query all the archives after the last one
    let from = Some(actual[0].canister_id);
    let actual = icrc3_get_archives(&env, ledger_id, GetArchivesArgs { from });
    assert_eq!(0, actual.len());
}

mod verify_written_blocks {
    use super::*;
    use ic_icrc1_ledger::FeatureFlags;
    use ic_icrc1_ledger_sm_tests::{system_time_to_nanos, MINTER};
    use ic_state_machine_tests::{StateMachine, WasmResult};
    use icrc_ledger_types::icrc1::account::Account;
    use icrc_ledger_types::icrc1::transfer::{Memo, NumTokens, TransferArg};
    use icrc_ledger_types::icrc2::approve::{ApproveArgs, ApproveError};
    use icrc_ledger_types::icrc2::transfer_from::{TransferFromArgs, TransferFromError};
    use icrc_ledger_types::icrc3::transactions::{
        Approve, Burn, GetTransactionsRequest, GetTransactionsResponse, Mint, Transaction, Transfer,
    };
    use num_traits::ToPrimitive;
    use serde_bytes::ByteBuf;

    const DEFAULT_FEE: u64 = 10_000;
    const DEFAULT_AMOUNT: u64 = 1_000_000;
    const DEFAULT_MEMO: [u8; 10] = [0u8; 10];

    #[test]
    fn test_verify_written_mint_block() {
        let ledger = Setup::new();
        let mint_args = TransferArg {
            from_subaccount: ledger.minter_account.subaccount,
            to: ledger.from_account,
            amount: Nat::from(10 * DEFAULT_AMOUNT),
            fee: Some(NumTokens::from(0u8)),
            created_at_time: Some(ledger.current_time_ns_since_unix_epoch),
            memo: Some(Memo(ByteBuf::from(DEFAULT_MEMO))),
        };
        ledger.mint(&mint_args).expect_mint(Mint {
            amount: mint_args.amount,
            to: mint_args.to,
            memo: mint_args.memo,
            created_at_time: mint_args.created_at_time,
        });
    }

    #[test]
    fn test_verify_written_transfer_block() {
        let ledger = Setup::new();
        let from_account = ledger.from_account;
        let transfer_args = TransferArg {
            from_subaccount: ledger.from_account.subaccount,
            to: ledger.to_account,
            fee: Some(Nat::from(DEFAULT_FEE)),
            created_at_time: Some(ledger.current_time_ns_since_unix_epoch),
            memo: Some(Memo(ByteBuf::from(DEFAULT_MEMO))),
            amount: Nat::from(DEFAULT_AMOUNT),
        };
        ledger
            .icrc1_transfer(from_account, &transfer_args)
            .expect_transfer(Transfer {
                amount: transfer_args.amount,
                from: from_account,
                to: transfer_args.to,
                spender: None,
                memo: transfer_args.memo,
                fee: transfer_args.fee,
                created_at_time: transfer_args.created_at_time,
            });
    }

    #[test]
    fn test_verify_written_initial_approve_block_and_approve_block_with_expected_allowance() {
        let ledger = Setup::new();
        let from_account = ledger.from_account;
        let spender_account = ledger.minter_account;
        let approve_args = ApproveArgs {
            from_subaccount: ledger.from_account.subaccount,
            spender: ledger.minter_account,
            amount: Nat::from(2 * DEFAULT_AMOUNT),
            expected_allowance: Some(Nat::from(0u8)),
            expires_at: Some(ledger.current_time_ns_since_unix_epoch + 1_000_000),
            fee: Some(Nat::from(DEFAULT_FEE)),
            memo: Some(Memo(ByteBuf::from(DEFAULT_MEMO))),
            created_at_time: Some(ledger.current_time_ns_since_unix_epoch),
        };
        let mut approve_args_with_expected_allowance = approve_args.clone();
        approve_args_with_expected_allowance.expected_allowance = Some(approve_args.amount.clone());
        approve_args_with_expected_allowance.amount = Nat::from(2 * DEFAULT_AMOUNT);
        ledger
            .icrc2_approve(from_account, &approve_args)
            .expect_approve(Approve {
                amount: approve_args.amount,
                expected_allowance: approve_args.expected_allowance,
                expires_at: approve_args.expires_at,
                memo: approve_args.memo,
                fee: approve_args.fee,
                created_at_time: approve_args.created_at_time,
                from: from_account,
                spender: spender_account,
            })
            .icrc2_approve(from_account, &approve_args_with_expected_allowance)
            .expect_approve(Approve {
                amount: approve_args_with_expected_allowance.amount,
                expected_allowance: approve_args_with_expected_allowance.expected_allowance,
                expires_at: approve_args_with_expected_allowance.expires_at,
                memo: approve_args_with_expected_allowance.memo,
                fee: approve_args_with_expected_allowance.fee,
                created_at_time: approve_args_with_expected_allowance.created_at_time,
                from: from_account,
                spender: spender_account,
            });
    }

    #[test]
    fn test_verify_written_approve_and_burn_blocks() {
        let ledger = Setup::new();
        let from_account = ledger.from_account;
        let spender_account = ledger.minter_account;
        let approve_args = ApproveArgs {
            from_subaccount: ledger.from_account.subaccount,
            spender: ledger.minter_account,
            amount: Nat::from(2 * DEFAULT_AMOUNT),
            expected_allowance: Some(Nat::from(0u8)),
            expires_at: Some(ledger.current_time_ns_since_unix_epoch + 1_000_000),
            fee: Some(Nat::from(DEFAULT_FEE)),
            memo: Some(Memo(ByteBuf::from(DEFAULT_MEMO))),
            created_at_time: Some(ledger.current_time_ns_since_unix_epoch),
        };
        let burn_args = TransferFromArgs {
            spender_subaccount: spender_account.subaccount,
            from: ledger.from_account,
            to: ledger.minter_account,
            amount: Nat::from(DEFAULT_AMOUNT),
            fee: Some(NumTokens::from(0u8)),
            memo: Some(Memo(ByteBuf::from(DEFAULT_MEMO))),
            created_at_time: Some(ledger.current_time_ns_since_unix_epoch),
        };
        ledger
            .icrc2_approve(from_account, &approve_args)
            .expect_approve(Approve {
                amount: approve_args.amount,
                expected_allowance: approve_args.expected_allowance,
                expires_at: approve_args.expires_at,
                memo: approve_args.memo,
                fee: approve_args.fee,
                created_at_time: approve_args.created_at_time,
                from: from_account,
                spender: spender_account,
            })
            .minter_burn(&burn_args)
            .expect_burn(Burn {
                amount: burn_args.amount,
                from: burn_args.from,
                spender: Some(spender_account),
                memo: burn_args.memo,
                created_at_time: burn_args.created_at_time,
            });
    }

    #[test]
    fn test_verify_written_approve_and_transfer_from_blocks() {
        let ledger = Setup::new();
        let from_account = ledger.from_account;
        let spender_account = ledger.spender_account;
        let approve_args = ApproveArgs {
            from_subaccount: ledger.from_account.subaccount,
            spender: ledger.spender_account,
            amount: Nat::from(2 * DEFAULT_AMOUNT),
            expected_allowance: Some(Nat::from(0u8)),
            expires_at: Some(ledger.current_time_ns_since_unix_epoch + 1_000_000),
            fee: Some(Nat::from(DEFAULT_FEE)),
            memo: Some(Memo(ByteBuf::from(DEFAULT_MEMO))),
            created_at_time: Some(ledger.current_time_ns_since_unix_epoch),
        };
        let transfer_from_args = TransferFromArgs {
            spender_subaccount: ledger.spender_account.subaccount,
            from: ledger.from_account,
            to: ledger.to_account,
            amount: Nat::from(DEFAULT_AMOUNT),
            fee: Some(Nat::from(DEFAULT_FEE)),
            memo: Some(Memo(ByteBuf::from(DEFAULT_MEMO))),
            created_at_time: Some(ledger.current_time_ns_since_unix_epoch),
        };
        ledger
            .icrc2_approve(from_account, &approve_args)
            .expect_approve(Approve {
                amount: approve_args.amount,
                expected_allowance: approve_args.expected_allowance,
                expires_at: approve_args.expires_at,
                memo: approve_args.memo,
                fee: approve_args.fee,
                created_at_time: approve_args.created_at_time,
                from: from_account,
                spender: spender_account,
            })
            .icrc2_transfer_from(spender_account, &transfer_from_args)
            .expect_transfer(Transfer {
                amount: transfer_from_args.amount,
                from: from_account,
                to: transfer_from_args.to,
                spender: Some(spender_account),
                memo: transfer_from_args.memo,
                fee: transfer_from_args.fee,
                created_at_time: transfer_from_args.created_at_time,
            });
    }

    struct Setup {
        minter_account: Account,
        from_account: Account,
        to_account: Account,
        spender_account: Account,
        env: StateMachine,
        ledger_id: CanisterId,
        current_time_ns_since_unix_epoch: u64,
    }

    impl Setup {
        fn new() -> Self {
            let minter_account = Account {
                owner: MINTER.owner,
                subaccount: Some([42u8; 32]),
            };
            let from_account = Account {
                owner: PrincipalId::new_user_test_id(1).0,
                subaccount: Some([1u8; 32]),
            };
            let to_account = Account {
                owner: PrincipalId::new_user_test_id(2).0,
                subaccount: Some([2u8; 32]),
            };
            let spender_account = Account {
                owner: PrincipalId::new_user_test_id(3).0,
                subaccount: Some([3u8; 32]),
            };
            let initial_balances = vec![
                (from_account, Nat::from(10 * DEFAULT_AMOUNT)),
                (to_account, Nat::from(10 * DEFAULT_AMOUNT)),
                (spender_account, Nat::from(10 * DEFAULT_AMOUNT)),
            ];
            let ledger_arg_init = LedgerArgument::Init(InitArgs {
                minting_account: minter_account,
                fee_collector_account: None,
                initial_balances,
                transfer_fee: FEE.into(),
                token_name: TOKEN_NAME.to_string(),
                decimals: Some(DECIMAL_PLACES),
                token_symbol: TOKEN_SYMBOL.to_string(),
                metadata: vec![
                    Value::entry(NAT_META_KEY, NAT_META_VALUE),
                    Value::entry(INT_META_KEY, INT_META_VALUE),
                    Value::entry(TEXT_META_KEY, TEXT_META_VALUE),
                    Value::entry(BLOB_META_KEY, BLOB_META_VALUE),
                ],
                archive_options: ArchiveOptions {
                    trigger_threshold: ARCHIVE_TRIGGER_THRESHOLD as usize,
                    num_blocks_to_archive: NUM_BLOCKS_TO_ARCHIVE as usize,
                    node_max_memory_size_bytes: None,
                    max_message_size_bytes: None,
                    controller_id: PrincipalId::new_user_test_id(100),
                    more_controller_ids: None,
                    cycles_for_archive_creation: None,
                    max_transactions_per_response: None,
                },
                max_memo_length: None,
                feature_flags: Some(FeatureFlags { icrc2: true }),
                maximum_number_of_accounts: None,
                accounts_overflow_trim_quantity: None,
            });

            let args = Encode!(&ledger_arg_init).unwrap();
            let env = StateMachine::new();
            let ledger_id = env.install_canister(ledger_wasm(), args, None).unwrap();

            let current_time_ns_since_unix_epoch = system_time_to_nanos(env.time());

            Self {
                minter_account,
                from_account,
                to_account,
                spender_account,
                env,
                ledger_id,
                current_time_ns_since_unix_epoch,
            }
        }

        fn get_transaction(&self, block_index: BlockIndex) -> Transaction {
            let request = GetTransactionsRequest {
                start: block_index.into(),
                length: 1u8.into(),
            };

            let wasm_result_bytes = match self
                .env
                .query(
                    self.ledger_id,
                    "get_transactions",
                    Encode!(&request).unwrap(),
                )
                .expect("failed to query get_transactions on the ledger")
            {
                WasmResult::Reply(bytes) => bytes,
                WasmResult::Reject(reject) => {
                    panic!("Expected a successful reply, got a reject: {}", reject)
                }
            };
            let mut response = Decode!(&wasm_result_bytes, GetTransactionsResponse).unwrap();
            assert_eq!(
                response.transactions.len(),
                1,
                "Expected exactly one transaction but got {:?}",
                response.transactions
            );
            response.transactions.pop().unwrap()
        }

        fn mint(self, mint_args: &TransferArg) -> TransactionAssert {
            let minter_account = self.minter_account;
            self.icrc1_transfer(minter_account, mint_args)
        }

        fn icrc1_transfer(self, from: Account, transfer_args: &TransferArg) -> TransactionAssert {
            let args = Encode!(transfer_args).unwrap();
            let res = self
                .env
                .execute_ingress_as(
                    PrincipalId::from(from.owner),
                    self.ledger_id,
                    "icrc1_transfer",
                    args,
                )
                .expect("Unable to perform icrc1_transfer")
                .bytes();
            let block_index = Decode!(&res, Result<Nat, TransferError>)
                .unwrap()
                .expect("Unable to decode icrc1_transfer error")
                .0
                .to_u64()
                .unwrap();
            TransactionAssert {
                ledger: self,
                block_index,
            }
        }

        fn icrc2_transfer_from(
            self,
            spender: Account,
            transfer_from_args: &TransferFromArgs,
        ) -> TransactionAssert {
            let args = Encode!(transfer_from_args).unwrap();
            let res = self
                .env
                .execute_ingress_as(
                    PrincipalId::from(spender.owner),
                    self.ledger_id,
                    "icrc2_transfer_from",
                    args,
                )
                .expect("Unable to perform icrc2_transfer_from")
                .bytes();
            let block_index = Decode!(&res, Result<Nat, TransferFromError>)
                .unwrap()
                .expect("Unable to decode icrc2_transfer_from error")
                .0
                .to_u64()
                .unwrap();
            TransactionAssert {
                ledger: self,
                block_index,
            }
        }

        fn icrc2_approve(self, from: Account, approve_args: &ApproveArgs) -> TransactionAssert {
            let args = Encode!(approve_args).unwrap();
            let res = self
                .env
                .execute_ingress_as(from.owner.into(), self.ledger_id, "icrc2_approve", args)
                .expect("Unable to perform icrc2_approve")
                .bytes();
            let block_index = Decode!(&res, Result<Nat, ApproveError>)
                .unwrap()
                .expect("Unable to decode icrc2_approve error")
                .0
                .to_u64()
                .unwrap();
            TransactionAssert {
                ledger: self,
                block_index,
            }
        }

        fn minter_burn(self, burn_args: &TransferFromArgs) -> TransactionAssert {
            let minter_account = self.minter_account;
            self.icrc2_transfer_from(minter_account, burn_args)
        }
    }

    struct TransactionAssert {
        ledger: Setup,
        block_index: BlockIndex,
    }

    impl TransactionAssert {
        fn expect_approve(self, expected_approve: Approve) -> Setup {
            let ledger_transaction = self.ledger.get_transaction(self.block_index);
            assert_eq!("approve", ledger_transaction.kind);
            let ledger_approve = ledger_transaction
                .approve
                .as_ref()
                .expect("expecting approve transaction");
            assert_eq!(ledger_approve, &expected_approve);
            self.ledger
        }

        fn expect_mint(self, expected_mint: Mint) -> Setup {
            let ledger_transaction = self.ledger.get_transaction(self.block_index);
            assert_eq!("mint", ledger_transaction.kind);
            let ledger_mint = ledger_transaction
                .mint
                .as_ref()
                .expect("expecting mint transaction");
            assert_eq!(ledger_mint, &expected_mint);
            self.ledger
        }

        fn expect_transfer(self, expected_transfer: Transfer) -> Setup {
            let ledger_transaction = self.ledger.get_transaction(self.block_index);
            assert_eq!("transfer", ledger_transaction.kind);
            let ledger_transfer = ledger_transaction
                .transfer
                .as_ref()
                .expect("expecting transfer transaction");
            assert_eq!(ledger_transfer, &expected_transfer);
            self.ledger
        }

        fn expect_burn(self, expected_burn: Burn) -> Setup {
            let ledger_transaction = self.ledger.get_transaction(self.block_index);
            assert_eq!("burn", ledger_transaction.kind);
            let ledger_burn = ledger_transaction
                .burn
                .as_ref()
                .expect("expecting burn transaction");
            assert_eq!(ledger_burn, &expected_burn);
            self.ledger
        }
    }
}
