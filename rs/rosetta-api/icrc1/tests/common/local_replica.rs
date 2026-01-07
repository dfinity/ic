// The Local Replica is running the binary of a replica of the IC locally and thus allows for local testing
use candid::{Encode, Principal};
use ic_agent::Agent;
use ic_agent::Identity;
use ic_agent::identity::BasicIdentity;
use ic_base_types::PrincipalId;
use ic_icrc1_ledger::FeatureFlags;
use ic_icrc1_ledger::{InitArgs, InitArgsBuilder, LedgerArgument};
use ic_icrc1_test_utils::minter_identity;
use ic_ledger_canister_core::archive::ArchiveOptions;
use ic_ledger_suite_state_machine_tests_constants::{
    ARCHIVE_TRIGGER_THRESHOLD, BLOB_META_KEY, BLOB_META_VALUE, FEE, INT_META_KEY, INT_META_VALUE,
    NAT_META_KEY, NAT_META_VALUE, NUM_BLOCKS_TO_ARCHIVE, TEXT_META_KEY, TEXT_META_VALUE,
    TOKEN_NAME, TOKEN_SYMBOL,
};

use crate::common::local_replica;
use icrc_ledger_types::icrc::metadata_key::MetadataKey;
use pocket_ic::PocketIc;
use std::str::FromStr;
use std::sync::Arc;
use url::Url;

pub fn test_identity() -> BasicIdentity {
    BasicIdentity::from_pem(
        &b"-----BEGIN PRIVATE KEY-----
MFMCAQEwBQYDK2VwBCIEIJKDIfd1Ybt48Z23cVEbjL2DGj1P5iDYmthcrptvBO3z
oSMDIQCJuBJPWt2WWxv0zQmXcXMjY+fP0CJSsB80ztXpOFd2ZQ==
-----END PRIVATE KEY-----"[..],
    )
    .expect("failed to parse identity from PEM")
}

pub async fn get_testing_agent(port: u16) -> Agent {
    get_custom_agent(Arc::new(test_identity()), port).await
}

pub async fn get_custom_agent(basic_identity: Arc<dyn Identity>, port: u16) -> Agent {
    // The local replica will be running on the localhost
    let replica_url = Url::parse(&format!("http://localhost:{port}")).unwrap();

    // Setup the agent
    let agent = Agent::builder()
        .with_url(replica_url.clone())
        .with_identity(basic_identity)
        .with_http_client(reqwest::Client::new())
        .build()
        .unwrap();

    // For verification the agent needs the root key of the IC running on the local replica
    agent.fetch_root_key().await.unwrap();
    agent
}

pub fn icrc_ledger_default_args_builder() -> InitArgsBuilder {
    let test_identity = test_identity();
    InitArgsBuilder::with_symbol_and_name(TOKEN_SYMBOL, TOKEN_NAME)
        .with_transfer_fee(FEE)
        .with_feature_flags(FeatureFlags { icrc2: true })
        .with_minting_account(minter_identity().sender().unwrap())
        .with_initial_balance(test_identity.sender().unwrap(), 1_000_000_000_000u64)
        .with_archive_options(ArchiveOptions {
            trigger_threshold: ARCHIVE_TRIGGER_THRESHOLD as usize,
            num_blocks_to_archive: NUM_BLOCKS_TO_ARCHIVE as usize,
            node_max_memory_size_bytes: None,
            max_message_size_bytes: None,
            controller_id: PrincipalId::new_user_test_id(100),
            more_controller_ids: None,
            cycles_for_archive_creation: None,
            max_transactions_per_response: None,
        })
        .with_metadata_entry(NAT_META_KEY, NAT_META_VALUE)
        .with_metadata_entry(INT_META_KEY, INT_META_VALUE)
        .with_metadata_entry(TEXT_META_KEY, TEXT_META_VALUE)
        .with_metadata_entry(BLOB_META_KEY, BLOB_META_VALUE)
}

// Return the wasm of the icrc ledger
pub fn icrc_ledger_wasm() -> Vec<u8> {
    let icrc_ledger_project_path =
        std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("icrc1")
            .join("ledger");
    ic_test_utilities_load_wasm::load_wasm(icrc_ledger_project_path, "ic-icrc1-ledger", &[])
}

const STARTING_CYCLES_PER_CANISTER: u128 = 2_000_000_000_000_000;

pub fn create_and_install_icrc_ledger(
    pocket_ic: &PocketIc,
    init_args: InitArgs,
    custom_canister_id: Option<Principal>,
) -> Principal {
    let wasm_module = local_replica::icrc_ledger_wasm();
    create_and_install_custom_icrc_ledger(pocket_ic, init_args, wasm_module, custom_canister_id)
}

pub fn create_and_install_custom_icrc_ledger(
    pocket_ic: &PocketIc,
    init_args: InitArgs,
    wasm_module: Vec<u8>,
    custom_canister_id: Option<Principal>,
) -> Principal {
    let custom_encoded_init_args = Encode!(&(LedgerArgument::Init(init_args.clone()))).unwrap();
    let canister_id =
        custom_canister_id.or(Principal::from_str("2ouva-viaaa-aaaaq-aaamq-cai").ok());
    let canister_id = canister_id.unwrap();
    pocket_ic
        .create_canister_with_id(None, None, canister_id)
        .unwrap();
    pocket_ic.add_cycles(canister_id, STARTING_CYCLES_PER_CANISTER);
    pocket_ic.install_canister(canister_id, wasm_module, custom_encoded_init_args, None);
    canister_id
}
