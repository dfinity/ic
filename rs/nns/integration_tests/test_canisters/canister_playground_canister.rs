// Example of ic_cdk canister - comment out the above to use
use candid::Encode;
use ic_base_types::{CanisterId, PrincipalId};
use ic_cdk::println;
use ic_cdk::{init, update};
use ic_nervous_system_runtime::{CdkRuntime, Runtime};

#[init]
fn canister_init() {
    println!("Playground Canister Init!");
}

#[update]
async fn test() {
    println!("Playground test was called");
    let _response = CdkRuntime::call_bytes_with_cleanup(
        CanisterId::try_from(PrincipalId::from(ic_cdk::api::canister_self())).unwrap(),
        "test_2",
        &Encode!(&()).unwrap(),
    )
    .await
    .unwrap();
}

#[update]
async fn test_2() {
    println!("Playground canister test_2 was called");
}

fn main() {}
