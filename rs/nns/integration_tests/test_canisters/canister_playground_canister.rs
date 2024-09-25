use ic_cdk::println;
use ic_cdk_macros::{init, post_upgrade};

// #[init]
// fn canister_init(arg: Option<u32>) {
//     println!("Playground Canister Init: {:?}", arg);
// }

#[init]
fn canister_init() {
    println!("Playground Canister Init");
}

#[post_upgrade]
fn canister_post_upgrade(arg: Option<u32>) {
    println!("Playground Canister Post Upgrade: {:?}", arg);
}

fn main() {}
