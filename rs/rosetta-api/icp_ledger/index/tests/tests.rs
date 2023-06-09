use candid::{Decode, Encode};
use ic_base_types::{CanisterId, PrincipalId};
use ic_ledger_canister_core::archive::ArchiveOptions;
use ic_ledger_core::block::BlockType;
use ic_ledger_core::Tokens;
use ic_state_machine_tests::StateMachine;
use icp_ledger::LedgerCanisterInitPayload;
use icp_ledger::{AccountIdentifier, GetBlocksArgs, QueryBlocksResponse, MAX_BLOCKS_PER_REQUEST};
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::{BlockIndex, TransferArg, TransferError};
use icrc_ledger_types::icrc3::blocks::GetBlocksRequest;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::path::PathBuf;
use std::time::Duration;

const FEE: u64 = 10_000;
const ARCHIVE_TRIGGER_THRESHOLD: u64 = 10;
const NUM_BLOCKS_TO_ARCHIVE: usize = 5;

const MINTER_PRINCIPAL: PrincipalId = PrincipalId::new(0, [0u8; 29]);

// Metadata-related constants
const TOKEN_NAME: &str = "Test Token";
const TOKEN_SYMBOL: &str = "XTST";

fn index_wasm() -> Vec<u8> {
    println!("Getting Index Wasm");
    ic_test_utilities_load_wasm::load_wasm(
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        "ic-icp-index",
        &[],
    )
}

fn ledger_wasm() -> Vec<u8> {
    println!("Getting Ledger Wasm");
    ic_test_utilities_load_wasm::load_wasm(
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .parent()
            .unwrap()
            .join("ledger"),
        "ledger-canister",
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
    initial_balances: HashMap<AccountIdentifier, Tokens>,
    archive_options: ArchiveOptions,
) -> CanisterId {
    let args = LedgerCanisterInitPayload::builder()
        .minting_account(AccountIdentifier::new(MINTER_PRINCIPAL, None))
        .transfer_fee(Tokens::from_e8s(FEE))
        .token_symbol_and_name(TOKEN_SYMBOL, TOKEN_NAME)
        .archive_options(archive_options)
        .initial_values(initial_balances)
        .build()
        .unwrap();
    env.install_canister(ledger_wasm(), Encode!(&args).unwrap(), None)
        .unwrap()
}

fn install_index(env: &StateMachine, ledger_id: CanisterId) -> CanisterId {
    let args = ic_icp_index::InitArg {
        ledger_id: ledger_id.into(),
    };
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

fn icp_get_blocks(env: &StateMachine, ledger_id: CanisterId) -> Vec<icp_ledger::Block> {
    let req = GetBlocksArgs {
        start: 0u64,
        length: MAX_BLOCKS_PER_REQUEST,
    };
    let req = Encode!(&req).expect("Failed to encode GetBlocksRequest");
    let res = env
        .execute_ingress(ledger_id, "query_blocks", req)
        .expect("Failed to send get_blocks request")
        .bytes();
    let res = Decode!(&res, QueryBlocksResponse).expect("Failed to decode GetBlocksResponse");
    let mut blocks = vec![];
    for archived in res.archived_blocks {
        let req = GetBlocksArgs {
            start: archived.start,
            length: archived.length as usize,
        };
        let req = Encode!(&req).expect("Failed to encode GetBlocksArgs for archive node");
        let canister_id = archived.callback.canister_id;
        let res = env
            .execute_ingress(canister_id, archived.callback.method, req)
            .expect("Failed to send get_blocks request to archive")
            .bytes();
        let res = Decode!(&res, icp_ledger::GetBlocksResult).unwrap().unwrap();
        blocks.extend(res.blocks);
    }
    blocks.extend(res.blocks);
    blocks
        .into_iter()
        .map(icp_ledger::Block::try_from)
        .collect::<Result<Vec<icp_ledger::Block>, String>>()
        .unwrap()
}

fn index_get_blocks(env: &StateMachine, index_id: CanisterId) -> Vec<icp_ledger::Block> {
    let req = GetBlocksRequest {
        start: 0.into(),
        length: u64::MAX.into(),
    };
    let req = Encode!(&req).expect("Failed to encode GetBlocksRequest");
    let res = env
        .execute_ingress(index_id, "get_blocks", req)
        .expect("Failed to send get_blocks request")
        .bytes();
    Decode!(&res, ic_icp_index::GetBlocksResponse)
        .expect("Failed to decode ic_icp_index::GetBlocksResponse")
        .blocks
        .into_iter()
        .map(icp_ledger::Block::decode)
        .collect::<Result<Vec<icp_ledger::Block>, String>>()
        .unwrap()
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
    let ledger_blocks = icp_get_blocks(env, ledger_id);
    let index_blocks = index_get_blocks(env, index_id);
    assert_eq!(ledger_blocks, index_blocks);
}

fn trigger_sync(env: &StateMachine) {
    env.advance_time(Duration::from_secs(60));
    env.tick();
}

#[test]
fn test_ledger_growing() {
    // check that the index canister can incrementally get the blocks from the ledger.

    let mut initial_balances = HashMap::new();
    initial_balances.insert(
        AccountIdentifier::from(account(1, 0)),
        Tokens::from_e8s(1_000_000_000_000),
    );
    let env = &StateMachine::new();
    let ledger_id = install_ledger(env, initial_balances, default_archive_options());
    let index_id = install_index(env, ledger_id);

    // test initial mint block
    trigger_sync(env);
    assert_ledger_index_parity(env, ledger_id, index_id);

    // test first transfer block
    transfer(env, ledger_id, account(1, 0), account(2, 0), 1);
    trigger_sync(env);
    assert_ledger_index_parity(env, ledger_id, index_id);

    // test multiple blocks
    for (from, to, amount) in [
        (account(1, 0), account(1, 1), 1_000_000),
        (account(1, 0), account(2, 0), 1_000_001),
        (account(1, 1), account(2, 0), 1),
    ] {
        transfer(env, ledger_id, from, to, amount);
    }
    trigger_sync(env);
    assert_ledger_index_parity(env, ledger_id, index_id);

    // test archived blocks
    for _i in 0..(ARCHIVE_TRIGGER_THRESHOLD as usize + 1) {
        transfer(env, ledger_id, account(1, 0), account(1, 2), 1);
    }
    trigger_sync(env);
    assert_ledger_index_parity(env, ledger_id, index_id);
}

#[test]
fn test_archive_indexing() {
    // test that the index canister can fetch the blocks from archive correctly.
    // To avoid having a slow test, we create the blocks as mints at ledger init time.
    // We need a number of blocks equal to threshold + 2 * max num blocks in archive response.
    let mut initial_balances = HashMap::new();
    for i in 0..(ARCHIVE_TRIGGER_THRESHOLD + 4000) {
        initial_balances.insert(
            AccountIdentifier::from(account(i, 0)),
            Tokens::from_e8s(1_000_000_000_000),
        );
    }
    let env = &StateMachine::new();
    let ledger_id = install_ledger(env, initial_balances, default_archive_options());
    let index_id = install_index(env, ledger_id);

    trigger_sync(env);
    assert_ledger_index_parity(env, ledger_id, index_id);
}
