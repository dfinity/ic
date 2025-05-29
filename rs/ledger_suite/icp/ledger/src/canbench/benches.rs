use crate::{
    balances_len, canister_init, icrc1_send_not_async, query_blocks, query_encoded_blocks,
};
use canbench_rs::{bench, BenchResult};
use candid::{Nat, Principal};
use ic_ledger_core::Tokens;
use icp_ledger::{GetBlocksArgs, LedgerCanisterInitPayload};
use icrc_ledger_types::icrc1::account::Account;

const NUM_OPERATIONS: u64 = 10_000;
const MAX_GET_BLOCKS: u64 = 2_000;

#[bench(raw)]
fn bench_endpoints() -> BenchResult {
    // Create the ledger canister
    let minter = Account {
        owner: Principal::from_slice(&[1u8; 1]),
        subaccount: None,
    };
    let args = LedgerCanisterInitPayload::builder()
        .minting_account(minter.into())
        .transfer_fee(Tokens::from_e8s(10_000))
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
    canbench_rs::bench_fn(|| {
        {
            let _p = canbench_rs::bench_scope("icrc1_transfer");
            for i in 0..NUM_OPERATIONS {
                let reveiver_id = (i + 3).to_le_bytes();
                let receiver = Account {
                    owner: Principal::from_slice(&reveiver_id),
                    subaccount: None,
                };
                let result = icrc1_send_not_async(
                    Some([20u8; 32].to_vec().into()),
                    Nat::from(1u64),
                    Some(Nat::from(10_000u64)),
                    acc,
                    receiver,
                    None,
                    Some(start_time + i),
                );
                assert!(result.is_ok());
            }
            assert_eq!(balances_len(), NUM_OPERATIONS + 1);
        }
        let args = GetBlocksArgs {
            start: 1,
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
