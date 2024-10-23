use candid::candid_method;
use ic_cdk_macros::{init, update};
use ic_icrc1_benchmark_worker::{BatchArgs, BatchResult, InitArgs};

fn main() {}

#[init]
fn init(args: InitArgs) {
    ic_icrc1_benchmark_worker::init(args);
}

#[update]
#[candid_method(update)]
async fn run_batch(args: BatchArgs) -> BatchResult {
    ic_icrc1_benchmark_worker::run_batch(args).await
}
