// This canister is used for testing upgrades with arguments and stable memory.

use ic_cdk::{
    api::{
        call::arg_data_raw,
        stable::{stable_bytes, stable_write},
    },
    post_upgrade, println, query,
};

fn main() {}

#[post_upgrade]
fn post_upgrade() {
    let arg = arg_data_raw();
    println!("Initializing test canister with arg={:?}", arg);
    stable_write(0, &arg);
}

#[query]
fn read_stable() -> Vec<u8> {
    stable_bytes()
}
