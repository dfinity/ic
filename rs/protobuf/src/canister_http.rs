#[rustfmt::skip]
pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/canister_http/canister_http.v1.rs"));
}
