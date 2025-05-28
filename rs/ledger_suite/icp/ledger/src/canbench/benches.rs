use crate::canister_init;
use crate::icrc1_send_not_async;
use canbench_rs::{bench, BenchResult};
use candid::{Nat, Principal};
use ic_ledger_core::Tokens;
use icp_ledger::LedgerCanisterInitPayload;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::TransferArg;

const NUM_OPERATIONS: u32 = 10_000;

#[bench(raw)]
fn bench_endpoints() -> BenchResult {
    let minter = Account {
        owner: Principal::from_slice(&[1u8; 1]),
        subaccount: None,
    };
    let start_time = ic_cdk::api::time();
    let args = LedgerCanisterInitPayload::builder()
        .minting_account(minter.into())
        .transfer_fee(Tokens::from_e8s(10_000))
        .build()
        .unwrap();
    canister_init(args.0);
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
    let receiver = Account {
        owner: Principal::from_slice(&[100u8; 1]),
        subaccount: None,
    };

    canbench_rs::bench_fn(|| {
        {
            let _p = canbench_rs::bench_scope("icrc1_transfer");
            for i in 0..NUM_OPERATIONS {
                let result = icrc1_send_not_async(
                    Some(MEMO.to_vec().into()),
                    Nat::from(1u64),
                    Some(Nat::from(10_000u64)),
                    acc,
                    receiver,
                    None,
                    Some(start_time + i as u64),
                );
                assert!(result.is_ok());
                // emulate_archive_blocks::<Access>(&LOG);
            }
            // assert_has_num_balances(NUM_OPERATIONS + 2);
        }
    })
}

const MEMO: [u8; 32] = [
    0x82_u8, 0x00, 0x83, 0x58, 0x20, 0x18, 0x19, 0xcc, 0xd2, 0x28, 0xad, 0x2e, 0x83, 0xc6, 0xc8,
    0x63, 0x99, 0xa0, 0xd7, 0xd0, 0x2e, 0xe9, 0x75, 0x96, 0x95, 0x86, 0xf3, 0x47, 0x85, 0xf6, 0xaf,
    0x99,
];
