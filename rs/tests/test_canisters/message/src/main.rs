#![allow(deprecated)]
use ic_cdk::api::{msg_reject, msg_reply};
use ic_message::ForwardParams;
use std::cell::RefCell;
use std::marker::PhantomData;

thread_local! {
    static MSG: RefCell<Option<String>> = const { RefCell::new(None) };
}

#[ic_cdk::update]
fn store(text: String) {
    ic_cdk::println!("{}", text);
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
) -> PhantomData<Vec<u8>> {
    match ic_cdk::api::call::call_raw128(receiver, &method, &payload, cycles).await {
        Ok(res) => msg_reply(candid::encode_one(res).expect("Failed to encode the reply.")),
        Err((_, err)) => msg_reject(err),
    }

    PhantomData
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
