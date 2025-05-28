use crate::canister_init;
use crate::icrc1_send_not_async;
use canbench_rs::{bench, BenchResult};
use candid::{Nat, Principal};
use icp_ledger::LedgerCanisterInitPayload;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::TransferArg;

#[bench(raw)]
fn bench_endpoints() -> BenchResult {
    let minter = Account {
        owner: Principal::from_slice(&[1u8; 1]),
        subaccount: None,
    };
    let args = LedgerCanisterInitPayload::builder()
        .minting_account(minter.into())
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
    canbench_rs::bench_fn(|| {})
}
