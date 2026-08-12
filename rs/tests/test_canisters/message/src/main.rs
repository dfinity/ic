use ic_cdk::api::{msg_reject, msg_reply};
use ic_cdk::call::Call;
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
    match Call::unbounded_wait(receiver, &method)
        .with_raw_args(&payload)
        .with_cycles(cycles)
        .await
    {
        Ok(response) => msg_reply(
            candid::encode_one(response.into_bytes()).expect("Failed to encode the reply."),
        ),
        Err(err) => msg_reject(err.to_string()),
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
