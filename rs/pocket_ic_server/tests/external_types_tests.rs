use candid::CandidType;
use candid::types::subtype::equal;
use candid_parser::utils::{CandidSource, instantiate_candid};
use flate2::read::GzDecoder;
use pocket_ic_server::external_canister_types::InternetIdentityInit;
use std::io::Read;
use walrus::{IdsToIndices, Module};

fn check_init_arg<T: CandidType>(gzipped_canister_wasm: &[u8]) {
    let mut decoder = GzDecoder::new(gzipped_canister_wasm);
    let mut canister_wasm = Vec::new();
    decoder.read_to_end(&mut canister_wasm).unwrap();
    let module = Module::from_buffer(&canister_wasm).unwrap();
    let canister_did = module
        .customs
        .iter()
        .find(|(_, c)| c.name() == "icp:public candid:service")
        .unwrap()
        .1
        .data(&IdsToIndices::default());

    let (init_args, (env, _)) = instantiate_candid(CandidSource::Text(
        core::str::from_utf8(&canister_did).unwrap(),
    ))
    .unwrap();
    assert_eq!(init_args.len(), 1);

    // `gamma` is a helper parameter used to resolve type synonyms
    // during traversal (hence, it is initialized to an empty value).
    let mut gamma = std::collections::HashSet::new();
    equal(&mut gamma, &env, &init_args[0], &T::ty()).unwrap();
}

#[test]
fn internet_identity_candid_equality() {
    const INTERNET_IDENTITY_TEST_CANISTER_WASM: &[u8] =
        include_bytes!(env!("INTERNET_IDENTITY_TEST_CANISTER_WASM_PATH"));

    check_init_arg::<Option<InternetIdentityInit>>(INTERNET_IDENTITY_TEST_CANISTER_WASM);
}
