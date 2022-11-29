use ic_cdk::{
    export::candid::CandidType,
    storage::{stable_restore, stable_save},
};
use ic_cdk_macros::*;
use serde::Deserialize;

include! {"lib.rs"}

#[derive(CandidType, Deserialize)]
#[candid_path("ic_cdk::export::candid")]
struct GetCert {
    val: Option<String>,
    cert: Vec<u8>,
    tree: Vec<u8>,
}

#[update]
fn get(key: String) -> Option<String> {
    kv_store::get(&key)
}

#[query]
fn get_cert(key: String) -> GetCert {
    GetCert {
        val: kv_store::get(&key),
        cert: cert::get(),
        tree: cert::get_tree(&key),
    }
}

#[update]
fn put(key: String, value: String) {
    cert::put(&key, &value);
    kv_store::put(key, value);
}

#[query]
fn http_request(req: http::HttpRequest) -> http::HttpResponse {
    http::request(req)
}

#[update]
fn http_request_update(req: http::HttpRequest) -> http::HttpResponse {
    http::request_update(req)
}

#[query]
fn http_streaming(token: http::Token) -> http::StreamingCallbackHttpResponse {
    http::streaming(token)
}

#[pre_upgrade]
fn pre_upgrade() {
    let store = kv_store::pre_upgrade();
    let cert_tree = cert::pre_upgrade();
    stable_save((store, cert_tree)).expect("Saving store to stable store must succeed.");
}

#[post_upgrade]
fn post_upgrade() {
    let (store, cert_tree) = stable_restore().expect("Failed to read store from stable memory.");
    kv_store::post_upgrade(store);
    cert::post_upgrade(cert_tree);
}

fn main() {}
