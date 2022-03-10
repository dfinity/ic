use dfn_candid::candid;
use dfn_core::over_async;

use ic_nervous_system_root::LOG_PREFIX;

#[macro_use]
extern crate ic_nervous_system_common;

#[cfg(target_arch = "wasm32")]
use dfn_core::println;

fn main() {}

#[export_name = "canister_init"]
fn canister_init() {
    dfn_core::printer::hook();
    println!("{}canister_init", LOG_PREFIX);
}

#[export_name = "canister_post_upgrade"]
fn canister_post_upgrade() {
    dfn_core::printer::hook();
    println!("{}canister_post_upgrade", LOG_PREFIX);
}

expose_build_metadata! {}

#[export_name = "canister_update canister_status"]
fn canister_status() {
    println!("{}canister_status", LOG_PREFIX);
    over_async(candid, ic_nervous_system_root::canister_status)
}
