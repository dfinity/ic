use candid::types::number::Nat;
use candid::Encode;
use candid::{Decode, Principal};
use canister_test::WasmResult;
use ic_base_types::{CanisterId, PrincipalId};
use ic_ledger_core::block::BlockIndex;
use ic_ledger_core::timestamp::TimeStamp;
use ic_ledger_core::Tokens;
use ic_ledger_test_utils::statemachine_helpers::{
    assert_ledger_index_parity_query_blocks_and_query_encoded_blocks, wait_until_sync_is_completed,
};
use ic_ledger_test_utils::{
    build_ledger_archive_wasm, build_ledger_index_wasm, build_ledger_wasm,
    build_mainnet_ledger_archive_wasm, build_mainnet_ledger_index_wasm, build_mainnet_ledger_wasm,
};
use ic_nns_constants::LEDGER_CANISTER_INDEX_IN_NNS_SUBNET;
use ic_nns_test_utils_golden_nns_state::{
    new_state_machine_with_golden_nns_state_or_panic, GoldenStateLocation,
};
use ic_state_machine_tests::StateMachine;
use icp_ledger::{
    AccountIdentifier, Archives, FeatureFlags, LedgerCanisterUpgradePayload, Memo, TransferArgs,
    TransferError,
};
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc2::approve::ApproveArgs;
use icrc_ledger_types::icrc2::transfer_from::TransferFromArgs;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::Instant;

const LEDGER_CANISTER_ID: CanisterId = CanisterId::from_u64(LEDGER_CANISTER_INDEX_IN_NNS_SUBNET);
const INDEX_CANISTER_ID: CanisterId = CanisterId::from_u64(11);

/// Create a state machine with the golden NNS state and perform a series of transactions and
/// upgrades and downgrades of the ICP ledger canister suite.
/// The approximate runtime of the individual components is as follows:
/// - Assert parity between the ledger and index canisters: 6min
/// - Perform transactions: Around 0.5s per transaction
/// - Upgrade/downgrade of the canisters: Around 10s per canister
#[test]
fn should_create_state_machine_with_golden_nns_state() {
    let state_machine = new_state_machine_with_golden_nns_state_or_panic(
        GoldenStateLocation::Local(PathBuf::from(
            // "/Users/mathias/projects/crypto/workspaces/ic-FI-1301-golden-mainnet-nns-state-icp-ledger-suite-upgrade-test/rs/rosetta-api/icp_ledger/test_resources/nns_state.tar.zst"
            // "/tmp/nns_state.tar.zst",
            "/home/mathias/projects/crypto/workspaces/ic/rs/rosetta-api/icp_ledger/test_resources/nns_state.tar.zst",
        )),
    );

    let start = Instant::now();
    // This takes almost 6min to run
    assert_ledger_index_parity_query_blocks_and_query_encoded_blocks(
        &state_machine,
        LEDGER_CANISTER_ID,
        INDEX_CANISTER_ID,
    );
    println!(
        "Time taken for index-ledger parity check: {:?}",
        start.elapsed()
    );

    let minting_principal = Principal::from_text("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap();
    let governance_canister_id = CanisterId::from_u64(1);
    let governance_canister_principal_id = governance_canister_id.get();
    assert_eq!(minting_principal, governance_canister_principal_id.0);
    // let minter = PrincipalId(minting_principal);
    let minter = governance_canister_principal_id;
    let user1 = PrincipalId::new_user_test_id(101);
    let user2 = PrincipalId::new_user_test_id(102);

    // 1. Create a bunch of transactions
    perform_transactions(&state_machine, &minter, &user1, &user2);

    // 2. Verify that the ledger, archives, and index have the same blocks (start from before step 1.)
    // let start = Instant::now();
    // assert_ledger_index_parity_query_blocks_and_query_encoded_blocks(
    //     &state_machine,
    //     LEDGER_CANISTER_ID,
    //     INDEX_CANISTER_ID,
    // );
    // println!(
    //     "Time taken for index-ledger parity check: {:?}",
    //     start.elapsed()
    // );

    // 3. Upgrade the index canister
    // This takes a bit less than 1 second
    upgrade_index(&state_machine, build_ledger_index_wasm().bytes());

    //  3.1. Perform steps 1 and 2 again
    perform_transactions(&state_machine, &minter, &user1, &user2);

    // 4. Upgrade the ledger canister
    // This takes a bit less than 10 seconds
    upgrade_ledger(&state_machine, build_ledger_wasm().bytes());

    //  4.1. Perform steps 1 and 2 again
    perform_transactions(&state_machine, &minter, &user1, &user2);

    // 5. Upgrade the archive canisters and perform transactions
    // Upgrading a single archive takes a bit less than 10 seconds
    // The following function also performs transactions and waits for the index to sync
    upgrade_archive_canisters_and_perform_transactions(
        &state_machine,
        &minter,
        &user1,
        &user2,
        build_ledger_archive_wasm().bytes(),
    );

    // assert_ledger_index_parity_query_blocks_and_query_encoded_blocks(
    //     &state_machine,
    //     LEDGER_CANISTER_ID,
    //     INDEX_CANISTER_ID,
    // );

    // 6. Downgrade the archive canisters and perform transactions
    upgrade_archive_canisters_and_perform_transactions(
        &state_machine,
        &minter,
        &user1,
        &user2,
        build_mainnet_ledger_archive_wasm().bytes(),
    );

    // 7. Downgrade the ledger canister
    upgrade_ledger(&state_machine, build_mainnet_ledger_wasm().bytes());

    //  7.1. Perform steps 1 and 2 again
    perform_transactions(&state_machine, &minter, &user1, &user2);

    // 8. Downgrade the index canister
    upgrade_index(&state_machine, build_mainnet_ledger_index_wasm().bytes());

    //  8.1. Perform steps 1 and 2 again
    perform_transactions(&state_machine, &minter, &user1, &user2);

    // let start = Instant::now();
    // assert_ledger_index_parity_query_blocks_and_query_encoded_blocks(
    //     &state_machine,
    //     LEDGER_CANISTER_ID,
    //     INDEX_CANISTER_ID,
    // );
    // println!(
    //     "Time taken for index-ledger parity check: {:?}",
    //     start.elapsed()
    // );
}

fn list_archives(state_machine: &StateMachine) -> Archives {
    Decode!(
        &state_machine
            .query(LEDGER_CANISTER_ID, "archives", Encode!().unwrap())
            .expect("failed to query archives")
            .bytes(),
        Archives
    )
    .expect("failed to decode archives response")
}

const NUM_REPETITIONS_PER_TRANSACTION: usize = 10;

fn perform_transactions(
    state_machine: &StateMachine,
    minter: &PrincipalId,
    user1: &PrincipalId,
    user2: &PrincipalId,
) {
    let start = Instant::now();
    // 1. Create a bunch of transactions
    //  5 types of transactions, 10 of each takes around 25s total (0.5s per transaction)
    for _ in 0..NUM_REPETITIONS_PER_TRANSACTION {
        //  1.1. Mint
        // TODO: The below uses the ICP 'transfer' method to mint tokens. Consider using the
        //  'icrc1_transfer' method instead.
        let amount = 1_000_000_000u64;
        let transfer_args = TransferArgs {
            memo: Memo(121u64),
            amount: Tokens::from_e8s(amount),
            fee: Tokens::ZERO,
            from_subaccount: None,
            to: AccountIdentifier::from(*user1).to_address(),
            created_at_time: Some(TimeStamp::from(state_machine.time())),
        };
        let arg = Encode!(&transfer_args).unwrap();
        let res = state_machine
            .execute_ingress_as(*minter, LEDGER_CANISTER_ID, "transfer", arg)
            .expect("failed to mint tokens");
        let reply = match res {
            WasmResult::Reply(v) => v,
            WasmResult::Reject(s) => {
                panic!("should successfully make icp transfer call to mint: {}", s)
            }
        };
        let block_index = Decode!(&reply, Result<BlockIndex, TransferError>)
            .expect("should successfully decode Result<BlockIndex, TransferError>")
            .expect("should successfully make icp transfer call to mint");
        println!("mint succeeded with block_index {}", block_index);

        //  1.2. Transfer
        // TODO: The below uses the ICRC1 'icrc1_transfer' method to transfer tokens. Consider also
        //  using the ICP 'transfer' method.
        let block_index = ic_icrc1_ledger_sm_tests::transfer(
            &state_machine,
            LEDGER_CANISTER_ID,
            user1.0,
            user2.0,
            1u64,
        )
        .expect("should successfully perform icrc1_transfer from user1 to user2");
        println!("transfer succeeded with block_index {}", block_index);

        //  1.3. Burn
        let block_index = ic_icrc1_ledger_sm_tests::transfer(
            &state_machine,
            LEDGER_CANISTER_ID,
            user1.0,
            minter.0,
            10_000u64,
        )
        .expect("should successfully perform icrc1_transfer from user1 to burn");
        println!("burn succeeded with block_index {}", block_index);

        //  1.4. Approve
        let approve_args = ApproveArgs {
            from_subaccount: None,
            spender: Account::from(user2.0),
            amount: Nat::from(100_000u64),
            expected_allowance: None,
            expires_at: None,
            fee: None,
            memo: None,
            created_at_time: None,
        };
        let block_index = ic_icrc1_ledger_sm_tests::send_approval(
            &state_machine,
            LEDGER_CANISTER_ID,
            user1.0,
            &approve_args,
        )
        .expect("should successfully perform icrc2_approve from user1 to user2");
        println!("approve succeeded with block_index {}", block_index);

        //  1.5. Transfer From
        let transfer_from_args = TransferFromArgs {
            spender_subaccount: None,
            from: Account::from(user1.0),
            to: Account::from(user2.0),
            amount: Nat::from(10_000u64),
            fee: None,
            memo: None,
            created_at_time: None,
        };
        let block_index = ic_icrc1_ledger_sm_tests::send_transfer_from(
            &state_machine,
            LEDGER_CANISTER_ID,
            user2.0,
            &transfer_from_args,
        )
            .expect(
                "should successfully perform icrc2_transfer_from from user1 to user2 with user2 as spender",
            );
        println!("transfer_from succeeded with block_index {}", block_index);
    }
    println!(
        "Time taken for {} transactions: {:?}",
        5 * NUM_REPETITIONS_PER_TRANSACTION,
        start.elapsed()
    );
    let start = Instant::now();
    wait_until_sync_is_completed(&state_machine, INDEX_CANISTER_ID, LEDGER_CANISTER_ID);
    println!("Time taken for index to sync: {:?}", start.elapsed());
}

fn upgrade_archive(
    state_machine: &StateMachine,
    archive_canister_id: CanisterId,
    wasm_bytes: Vec<u8>,
) {
    let start = Instant::now();
    state_machine
        .upgrade_canister(archive_canister_id, wasm_bytes, vec![])
        .unwrap_or_else(|e| {
            panic!(
                "should successfully upgrade archive '{}' to new local version: {}",
                archive_canister_id, e
            )
        });
    println!("Time taken for to upgrade archive: {:?}", start.elapsed());
}

fn upgrade_archive_canisters_and_perform_transactions(
    state_machine: &StateMachine,
    minter: &PrincipalId,
    user1: &PrincipalId,
    user2: &PrincipalId,
    archive_wasm_bytes: Vec<u8>,
) {
    let start = Instant::now();
    let mut upgraded_archives = BTreeSet::new();
    const MAX_ITERATIONS: u8 = 10;
    for _ in 0..MAX_ITERATIONS {
        // loop {
        let archives = list_archives(&state_machine).archives;
        println!("all archives: {:?}", archives);
        println!("upgraded archives: {:?}", upgraded_archives);
        let mut all_upgraded = true;
        for archive_info in &archives {
            if !upgraded_archives.contains(&archive_info.canister_id) {
                println!("upgrading archive: {}", archive_info.canister_id);
                all_upgraded = false;
                upgrade_archive(
                    &state_machine,
                    archive_info.canister_id,
                    archive_wasm_bytes.clone(),
                );
                upgraded_archives.insert(archive_info.canister_id);
                //  5.1. Perform steps 1 and 2 again
                perform_transactions(&state_machine, &minter, &user1, &user2);
                // The above may have triggered a new archive to be spawned, so continue with the
                //  next iteration of the loop, and list the archives again.
                break;
            } else {
                println!("archive already upgraded: {}", archive_info.canister_id);
            }
        }
        if all_upgraded {
            println!("all archives upgraded");
            break;
        } else {
            println!("not all archives upgraded, continuing");
        }
    }
    println!(
        "Time taken for to upgrade all archives: {:?}",
        start.elapsed()
    );
}

fn upgrade_index(state_machine: &StateMachine, wasm_bytes: Vec<u8>) {
    let start = Instant::now();
    state_machine
        .upgrade_canister(INDEX_CANISTER_ID, wasm_bytes, vec![])
        .expect("should successfully upgrade index to new local version");
    println!("Time taken for to upgrade index: {:?}", start.elapsed());
}

fn upgrade_ledger(state_machine: &StateMachine, wasm_bytes: Vec<u8>) {
    let start = Instant::now();
    let ledger_upgrade_args = LedgerCanisterUpgradePayload::builder()
        .feature_flags(FeatureFlags { icrc2: true })
        .build()
        .unwrap();

    state_machine
        .upgrade_canister(
            LEDGER_CANISTER_ID,
            wasm_bytes,
            Encode!(&ledger_upgrade_args).unwrap(),
        )
        .expect("should successfully upgrade ledger to new local version");
    println!("Time taken for to upgrade ledger: {:?}", start.elapsed());
}
