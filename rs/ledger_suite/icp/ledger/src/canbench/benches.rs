use crate::{
    balances_len, canister_init, icrc1_send_not_async, icrc2_approve_not_async, query_blocks,
    query_encoded_blocks,
};
use canbench_rs::{BenchResult, bench};
use candid::{Nat, Principal};
use ic_ledger_core::Tokens;
use icp_ledger::{GetBlocksArgs, LedgerCanisterInitPayload};
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc2::approve::ApproveArgs;

const NUM_OPERATIONS: u64 = 10_000;
const MAX_GET_BLOCKS: u64 = 2_000;
const FEE: u64 = 10_000;

#[bench(raw)]
fn bench_endpoints() -> BenchResult {
    // Create the ledger canister
    let minter = Account {
        owner: Principal::from_slice(&[1u8; 1]),
        subaccount: None,
    };
    let args = LedgerCanisterInitPayload::builder()
        .minting_account(minter.into())
        .transfer_fee(Tokens::from_e8s(FEE))
        .build()
        .unwrap();
    canister_init(args.0);

    // Transfer funds from the minter to a regular account
    let acc = Account {
        owner: Principal::from_slice(&[2u8; 1]),
        subaccount: None,
    };
    let _ = icrc1_send_not_async(
        None,
        Nat::from(1_000_000_000u64),
        None,
        minter,
        acc,
        None,
        None,
    );

    let start_time = ic_cdk::api::time();
    const START_ID: u64 = 3;
    canbench_rs::bench_fn(|| {
        {
            let _p = canbench_rs::bench_scope("icrc1_transfer");
            for i in 0..NUM_OPERATIONS {
                let reveiver_id = (i + START_ID).to_le_bytes();
                let receiver = Account {
                    owner: Principal::from_slice(&reveiver_id),
                    subaccount: None,
                };
                let result = icrc1_send_not_async(
                    Some([20u8; 32].to_vec().into()),
                    Nat::from(3 * FEE),
                    Some(Nat::from(FEE)),
                    acc,
                    receiver,
                    None,
                    Some(start_time + i),
                );
                assert!(result.is_ok());
            }
            assert_eq!(balances_len(), NUM_OPERATIONS + 1);
        }
        {
            let _p = canbench_rs::bench_scope("icrc2_approve");
            for i in 0..NUM_OPERATIONS {
                let approver_id = (i + START_ID).to_le_bytes();
                let spender_id = (i + START_ID + NUM_OPERATIONS).to_le_bytes();
                let spender = Account {
                    owner: Principal::from_slice(&spender_id),
                    subaccount: None,
                };
                let arg = ApproveArgs {
                    from_subaccount: None,
                    spender,
                    amount: Nat::from(FEE + 1),
                    fee: Some(Nat::from(FEE)),
                    memo: None,
                    expires_at: Some(start_time + 1_000_000),
                    expected_allowance: None,
                    created_at_time: Some(start_time + i + NUM_OPERATIONS),
                };
                let result =
                    icrc2_approve_not_async(Principal::from_slice(&approver_id), arg, None);
                assert!(result.is_ok());
            }
            assert_eq!(balances_len(), NUM_OPERATIONS + 1);
        }
        {
            let _p = canbench_rs::bench_scope("icrc2_transfer_from");
            for i in 0..NUM_OPERATIONS {
                let from_id = (i + START_ID).to_le_bytes();
                let from = Account {
                    owner: Principal::from_slice(&from_id),
                    subaccount: None,
                };
                let reveiver_id = (i + START_ID + NUM_OPERATIONS).to_le_bytes();
                let receiver = Account {
                    owner: Principal::from_slice(&reveiver_id),
                    subaccount: None,
                };
                let result = icrc1_send_not_async(
                    Some([20u8; 32].to_vec().into()),
                    Nat::from(1u64),
                    Some(Nat::from(FEE)),
                    from,
                    receiver,
                    Some(receiver),
                    Some(start_time + i + 2 * NUM_OPERATIONS),
                );
                assert!(result.is_ok());
            }
            assert_eq!(balances_len(), 2 * NUM_OPERATIONS + 1);
        }
        // With this start we should query some approve and some transfer from blocks.
        let args = GetBlocksArgs {
            start: 2 * NUM_OPERATIONS - 1_000,
            length: MAX_GET_BLOCKS,
        };
        {
            let _p = canbench_rs::bench_scope("query_blocks");
            let res = query_blocks(args.clone());
            assert_eq!(res.blocks.len(), MAX_GET_BLOCKS as usize);
        }
        {
            let _p = canbench_rs::bench_scope("query_encoded_blocks");
            let res = query_encoded_blocks(args);
            assert_eq!(res.blocks.len(), MAX_GET_BLOCKS as usize);
        }
    })
}
