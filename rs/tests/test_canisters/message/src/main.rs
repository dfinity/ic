use candid::candid_method;
use dfn_candid::candid_one;
use dfn_core::over_async_may_reject;
use ic_message::ForwardParams;
use std::cell::RefCell;

thread_local! {
    static MSG: RefCell<Option<String>> = RefCell::new(None);
}

#[ic_cdk_macros::update]
fn store(text: String) {
    MSG.with(|msg| *msg.borrow_mut() = Some(text));
}

#[ic_cdk_macros::query]
fn read() -> Option<String> {
    MSG.with(|msg| (*msg.borrow()).clone())
}

#[export_name = "canister_update forward"]
fn forward_() {
    over_async_may_reject(candid_one, forward)
}

#[candid_method(update, rename = "forward")]
pub async fn forward(
    ForwardParams {
        receiver,
        method,
        cycles,
        payload,
    }: ForwardParams,
) -> Result<Vec<u8>, String> {
    ic_cdk::api::call::call_raw128(receiver, &method, payload.as_ref(), cycles)
        .await
        .map_err(|err| err.1)
}

#[ic_cdk_macros::pre_upgrade]
fn pre_upgrade() {
    let msg = MSG.with(|msg| (*msg.borrow()).clone());
    ic_cdk::storage::stable_save((msg,)).expect("Saving message to stable memory must succeed.");
}

#[ic_cdk_macros::post_upgrade]
fn post_upgrade() {
    let m = ic_cdk::storage::stable_restore::<(Option<String>,)>()
        .expect("Failed to read message from stable memory.")
        .0;

    MSG.with(|msg| *msg.borrow_mut() = m);
}

fn main() {}
