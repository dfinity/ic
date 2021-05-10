// This canister is used for testing upgrades with arguments and stable memory.

use dfn_core::api::arg_data;
use dfn_core::endpoint::over_bytes;
use dfn_core::{println, stable};

fn main() {}

#[export_name = "canister_post_upgrade"]
fn post_upgrade() {
    dfn_core::printer::hook();

    let arg = arg_data();
    println!("Initializing test canister with arg={:?}", arg);
    stable::set(&arg);
}

#[export_name = "canister_query read_stable"]
fn read_stable() {
    over_bytes(|_| -> Vec<u8> { stable::get() })
}
