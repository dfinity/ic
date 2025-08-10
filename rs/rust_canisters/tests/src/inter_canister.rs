use dfn_core::{call, CanisterId};
use dfn_json::json;
use dfn_macro::{query, update};
use std::convert::TryFrom;

#[query]
async fn compute_query(canister_id: Vec<u8>, words: Vec<String>) -> Vec<String> {
    compute(canister_id, words).await
}

#[update]
async fn compute(canister_id: Vec<u8>, words: Vec<String>) -> Vec<String> {
    let mut words: Vec<String> = call(
        CanisterId::try_from(canister_id).unwrap(),
        "reverse_words",
        json,
        words,
    )
    .await
    .unwrap();
    words.push("Inter Canister".to_string());
    words
}

fn main() {}
