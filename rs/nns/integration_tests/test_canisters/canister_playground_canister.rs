use dfn_candid::candid_one;
use dfn_core::{over_async, println};

#[unsafe(export_name = "canister_init")]
fn canister_init() {
    println!("Playground Canister Init!");
}

#[unsafe(export_name = "canister_update test")]
fn test() {
    over_async(candid_one, |_: ()| async move { test_().await })
}

async fn test_() {
    println!("Playground canister was called");
}

// Example of ic_cdk canister - comment out the above to use
// use ic_cdk::println;
// use ic_cdk::{init, update};
// use std::time::Duration;
//
// #[init]
// fn canister_init() {
//     println!("Playground Canister Init!");
// }
//
// #[update]
// async fn test() {
//     println!("Playground test was called");
//     ic_cdk::spawn(async move {
//         let _: () = ic_cdk::call(ic_cdk::api::id(), "test_2", ()).await.unwrap();
//     });
//     ic_cdk_timers::set_timer(Duration::from_millis(0), || {
//         println!("Timer call worked!");
//     });
//     println!("Playground test - spawns were called");
//     panic!("Panic at the disco!");
// }
//
// #[update]
// async fn test_2() {
//     println!("Playground canister test_2 was called");
// }
//

fn main() {}
