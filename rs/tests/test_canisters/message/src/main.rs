#![allow(deprecated)]
use ic_cdk::api::call::ManualReply;
use ic_message::ForwardParams;
use std::cell::RefCell;

thread_local! {
    static MSG: RefCell<Option<String>> = const { RefCell::new(None) };
}

#[ic_cdk::update]
fn store(text: String) {
    MSG.with(|msg| *msg.borrow_mut() = Some(text));
}

#[ic_cdk::query]
fn read() -> Option<String> {
    MSG.with(|msg| (*msg.borrow()).clone())
}

#[ic_cdk::update(manual_reply = true)]
pub async fn forward(
    ForwardParams {
        receiver,
        method,
        cycles,
        payload,
    }: ForwardParams,
) -> ManualReply<Vec<u8>> {
    match ic_cdk::api::call::call_raw128(receiver, &method, &payload, cycles).await {
        Ok(res) => ManualReply::one(res),
        Err((_, err)) => ManualReply::reject(err),
    }
}

#[ic_cdk::pre_upgrade]
fn pre_upgrade() {
    let msg = MSG.with(|msg| (*msg.borrow()).clone());
    ic_cdk::storage::stable_save((msg,)).expect("Saving message to stable memory must succeed.");
}

#[ic_cdk::post_upgrade]
fn post_upgrade() {
    let m = ic_cdk::storage::stable_restore::<(Option<String>,)>()
        .expect("Failed to read message from stable memory.")
        .0;

    MSG.with(|msg| *msg.borrow_mut() = m);
}

fn main() {}
