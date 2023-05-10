use candid::{Decode, Encode};
use ic_base_types::{CanisterId, PrincipalId};
use ic_icrc1_index_ng::{GetBlocksResponse, IndexArg, InitArg as IndexInitArg};
use ic_icrc1_ledger::{InitArgs as LedgerInitArgs, LedgerArgument};
use ic_ledger_canister_core::archive::ArchiveOptions;
use ic_state_machine_tests::StateMachine;
use icrc_ledger_types::icrc::generic_metadata_value::MetadataValue as Value;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::{BlockIndex, TransferArg, TransferError};
use icrc_ledger_types::icrc3::blocks::{BlockRange, GenericBlock, GetBlocksRequest};
use std::convert::TryInto;
use std::path::PathBuf;
use std::time::Duration;

const FEE: u64 = 10_000;
const ARCHIVE_TRIGGER_THRESHOLD: u64 = 10;
const NUM_BLOCKS_TO_ARCHIVE: usize = 5;

const MINTER: Account = Account {
    owner: PrincipalId::new(0, [0u8; 29]).0,
    subaccount: None,
};

// Metadata-related constants
const TOKEN_NAME: &str = "Test Token";
const TOKEN_SYMBOL: &str = "XTST";
const TEXT_META_KEY: &str = "test:image";
const TEXT_META_VALUE: &str = "grumpy_cat.png";
const BLOB_META_KEY: &str = "test:blob";
const BLOB_META_VALUE: &[u8] = b"\xca\xfe\xba\xbe";
const NAT_META_KEY: &str = "test:nat";
const NAT_META_VALUE: u128 = u128::MAX;
const INT_META_KEY: &str = "test:int";
const INT_META_VALUE: i128 = i128::MIN;

fn index_wasm() -> Vec<u8> {
    ic_test_utilities_load_wasm::load_wasm(
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        "ic-icrc1-index-ng",
        &[],
    )
}

fn ledger_wasm() -> Vec<u8> {
    ic_test_utilities_load_wasm::load_wasm(
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .parent()
            .unwrap()
            .join("ledger"),
        "ic-icrc1-ledger",
        &[],
    )
}

fn default_archive_options() -> ArchiveOptions {
    ArchiveOptions {
        trigger_threshold: ARCHIVE_TRIGGER_THRESHOLD as usize,
        num_blocks_to_archive: NUM_BLOCKS_TO_ARCHIVE,
        node_max_memory_size_bytes: None,
        max_message_size_bytes: None,
        controller_id: PrincipalId::new_user_test_id(100),
        cycles_for_archive_creation: None,
        max_transactions_per_response: None,
    }
}

fn install_ledger(
    env: &StateMachine,
    initial_balances: Vec<(Account, u64)>,
    archive_options: ArchiveOptions,
) -> CanisterId {
    let args = LedgerArgument::Init(LedgerInitArgs {
        minting_account: MINTER,
        initial_balances,
        transfer_fee: FEE,
        token_name: TOKEN_NAME.to_string(),
        token_symbol: TOKEN_SYMBOL.to_string(),
        metadata: vec![
            Value::entry(NAT_META_KEY, NAT_META_VALUE),
            Value::entry(INT_META_KEY, INT_META_VALUE),
            Value::entry(TEXT_META_KEY, TEXT_META_VALUE),
            Value::entry(BLOB_META_KEY, BLOB_META_VALUE),
        ],
        archive_options,
        fee_collector_account: None,
        max_memo_length: None,
    });
    env.install_canister(ledger_wasm(), Encode!(&args).unwrap(), None)
        .unwrap()
}

fn install_index(env: &StateMachine, ledger_id: CanisterId) -> CanisterId {
    let args = IndexArg::InitArg(IndexInitArg {
        ledger_id: ledger_id.into(),
    });
    env.install_canister(index_wasm(), Encode!(&args).unwrap(), None)
        .unwrap()
}

fn account(owner: u64, subaccount: u128) -> Account {
    let mut sub: [u8; 32] = [0; 32];
    sub[..16].copy_from_slice(&subaccount.to_be_bytes());
    Account {
        owner: PrincipalId::new_user_test_id(owner).0,
        subaccount: Some(sub),
    }
}

fn icrc1_get_blocks(env: &StateMachine, ledger_id: CanisterId) -> Vec<GenericBlock> {
    let req = GetBlocksRequest {
        start: 0.into(),
        length: u64::MAX.into(),
    };
    let req = Encode!(&req).expect("Failed to encode GetBlocksRequest");
    let res = env
        .execute_ingress(ledger_id, "get_blocks", req)
        .expect("Failed to send get_blocks request")
        .bytes();
    let res = Decode!(&res, icrc_ledger_types::icrc3::blocks::GetBlocksResponse)
        .expect("Failed to decode GetBlocksResponse");
    let mut blocks = vec![];
    for archived in res.archived_blocks {
        let req = GetBlocksRequest {
            start: archived.start,
            length: archived.length,
        };
        let req = Encode!(&req).expect("Failed to encode GetBlocksRequest for archive node");
        let canister_id = archived.callback.canister_id.as_ref().try_into().unwrap();
        let res = env
            .execute_ingress(canister_id, archived.callback.method, req)
            .expect("Failed to send get_blocks request to archive")
            .bytes();
        let res = Decode!(&res, BlockRange)
            .expect("Failed to decode get_blocks response for archive node")
            .blocks;
        blocks.extend(res);
    }
    blocks.extend(res.blocks);
    blocks
}

fn get_blocks(env: &StateMachine, index_id: CanisterId) -> GetBlocksResponse {
    let req = GetBlocksRequest {
        start: 0.into(),
        length: u64::MAX.into(),
    };
    let req = Encode!(&req).expect("Failed to encode GetBlocksRequest");
    let res = env
        .execute_ingress(index_id, "get_blocks", req)
        .expect("Failed to send get_blocks request")
        .bytes();
    Decode!(&res, GetBlocksResponse).expect("Failed to decode GetBlocksResponse")
}

fn transfer(
    env: &StateMachine,
    ledger_id: CanisterId,
    from: Account,
    to: Account,
    amount: u64,
) -> BlockIndex {
    let Account { owner, subaccount } = from;
    let req = TransferArg {
        from_subaccount: subaccount,
        to,
        amount: amount.into(),
        created_at_time: None,
        fee: None,
        memo: None,
    };
    let req = Encode!(&req).expect("Failed to encode TransferArg");
    let res = env
        .execute_ingress_as(owner.into(), ledger_id, "icrc1_transfer", req)
        .expect("Failed to transfer tokens")
        .bytes();
    Decode!(&res, Result<BlockIndex, TransferError>)
        .expect("Failed to decode Result<BlockIndex, TransferError>")
        .expect("Failed to transfer tokens")
}

// Assert that the index canister contains the same blocks as the ledger
fn assert_ledger_index_parity(env: &StateMachine, ledger_id: CanisterId, index_id: CanisterId) {
    let ledger_blocks = icrc1_get_blocks(env, ledger_id);
    let index_blocks = get_blocks(env, index_id);
    assert_eq!(ledger_blocks, index_blocks.blocks);
}

fn trigger_heartbeat(env: &StateMachine) {
    env.advance_time(Duration::from_secs(60));
    env.tick();
}

#[test]
fn test_ledger_growing() {
    // check that the index canister can incrementally get the blocks from the ledger.

    let initial_balances: Vec<_> = vec![(account(1, 0), 1_000_000_000_000)];
    let env = &StateMachine::new();
    let ledger_id = install_ledger(env, initial_balances, default_archive_options());
    let index_id = install_index(env, ledger_id);

    // test initial mint block
    trigger_heartbeat(env);
    assert_ledger_index_parity(env, ledger_id, index_id);

    // test first transfer block
    transfer(env, ledger_id, account(1, 0), account(2, 0), 1);
    trigger_heartbeat(env);
    assert_ledger_index_parity(env, ledger_id, index_id);

    // test multiple blocks
    for (from, to, amount) in [
        (account(1, 0), account(1, 1), 1_000_000),
        (account(1, 0), account(2, 0), 1_000_001),
        (account(1, 1), account(2, 0), 1),
    ] {
        transfer(env, ledger_id, from, to, amount);
    }
    trigger_heartbeat(env);
    assert_ledger_index_parity(env, ledger_id, index_id);

    // test archived blocks
    for _i in 0..(ARCHIVE_TRIGGER_THRESHOLD as usize + 1) {
        transfer(env, ledger_id, account(1, 0), account(1, 2), 1);
    }
    trigger_heartbeat(env);
    assert_ledger_index_parity(env, ledger_id, index_id);
}

#[test]
fn test_archive_indexing() {
    // test that the index canister can fetch the blocks from archive correctly.
    // To avoid having a slow test, we create the blocks as mints at ledger init time.
    // We need a number of blocks equal to threshold + 2 * max num blocks in archive response.

    let initial_balances: Vec<_> = (0..(ARCHIVE_TRIGGER_THRESHOLD + 4000))
        .map(|i| (account(i, 0), 1_000_000_000_000))
        .collect();
    let env = &StateMachine::new();
    let ledger_id = install_ledger(env, initial_balances, default_archive_options());
    let index_id = install_index(env, ledger_id);

    trigger_heartbeat(env);
    assert_ledger_index_parity(env, ledger_id, index_id);
}
