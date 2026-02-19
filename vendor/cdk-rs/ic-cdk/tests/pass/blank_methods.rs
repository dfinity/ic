use ic_cdk::{
    heartbeat, init, inspect_message, on_low_wasm_memory, post_upgrade, pre_upgrade, query, update,
};

#[init]
fn init() {}

#[pre_upgrade]
fn pre_upgrade() {}

#[post_upgrade]
fn post_upgrade() {}

#[update]
fn update() {}

#[update(hidden)]
fn update_hidden() {}

#[update(hidden = true)]
fn update_hidden_true() {}

#[update(hidden = false)]
fn update_hidden_false() {}

#[update(manual_reply)]
fn update_manual_reply() {}

#[update(manual_reply = true)]
fn update_manual_reply_true() {}

#[update(manual_reply = false)]
fn update_manual_reply_false() {}

#[query]
fn query() {}

#[query(hidden)]
fn query_hidden() {}

#[query(hidden = true)]
fn query_hidden_true() {}

#[query(hidden = false)]
fn query_hidden_false() {}

#[query(manual_reply)]
fn query_manual_reply() {}

#[query(manual_reply = true)]
fn query_manual_reply_true() {}

#[query(manual_reply = false)]
fn query_manual_reply_false() {}

#[query(composite)]
fn query_composite() {}

#[query(composite = true)]
fn query_composite_true() {}

#[query(composite = false)]
fn query_composite_false() {}

#[heartbeat]
fn heartbeat() {}

#[inspect_message]
fn inspect_message() {}

#[on_low_wasm_memory]
fn on_low_wasm_memory() {}

fn main() {}
