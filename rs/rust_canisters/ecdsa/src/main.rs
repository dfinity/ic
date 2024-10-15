use candid::{candid_method, CandidType, Encode};
use ic_cdk::api::{call::call_raw, print};
use ic_cdk_macros::update;
use ic_management_canister_types::{
    DerivationPath, EcdsaCurve, EcdsaKeyId, Method as Ic00Method, SignWithECDSAArgs, IC_00,
};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

#[derive(Debug, CandidType, Deserialize, Serialize)]
struct Options {
    derivation_path: Vec<Vec<u8>>,
    key_name: String,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            derivation_path: vec![],
            key_name: "test_key".to_string(),
        }
    }
}

#[candid_method(update)]
#[update]
async fn get_sig(options: Options) {
    print(format!(
        "calling get sig with key {} and derivation path {:?}",
        options.key_name, options.derivation_path,
    ));
    let response = call_raw(
        IC_00.into(),
        &Ic00Method::SignWithECDSA.to_string(),
        Encode!(&SignWithECDSAArgs {
            message_hash: [0; 32],
            derivation_path: DerivationPath::new(
                options
                    .derivation_path
                    .into_iter()
                    .map(ByteBuf::from)
                    .collect()
            ),
            key_id: EcdsaKeyId {
                curve: EcdsaCurve::Secp256k1,
                name: options.key_name,
            },
        })
        .unwrap(),
        1_000_000_000_000,
    )
    .await;
    print(format!("got result {:?}", response));
}

// When run on native this prints the candid service definition of this
// canister, from the methods annotated with `candid_method` above.
//
// Note that `cargo test` calls `main`, and `export_service` (which defines
// `__export_service` in the current scope) needs to be called exactly once. So
// in addition to `not(target_arch = "wasm32")` we have a `not(test)` guard here
// to avoid calling `export_service`, which we need to call in the test below.
#[cfg(not(any(target_arch = "wasm32", test)))]
fn main() {
    // The line below generates did types and service definition from the
    // methods annotated with `candid_method` above. The definition is then
    // obtained with `__export_service()`.
    candid::export_service!();
    std::print!("{}", __export_service());
}

#[cfg(any(target_arch = "wasm32", test))]
fn main() {}

#[test]
fn check_candid_file() {
    let ecdsa_did_path = match std::env::var("ECDSA_DID_PATH") {
        Ok(v) => v,
        Err(_e) => "ecdsa.did".to_string(),
    };
    let candid = String::from_utf8(std::fs::read(ecdsa_did_path).unwrap()).unwrap();

    // See comments in main above
    candid::export_service!();
    let expected = __export_service();

    if candid != expected {
        panic!(
            "Generated candid definition does not match ecdsa.did. Run `cargo \
            run --bin ecdsa-canister > rust_canisters/ecdsa/ecdsa.did` to update \
            the candid file."
        )
    }
}
