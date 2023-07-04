// The Local Replica is running the binary of a replica of the IC locally and thus allows for local testing
use candid::{CandidType, Decode, Deserialize, Encode, Principal};
use ic_agent::agent::http_transport::ReqwestHttpReplicaV2Transport;
use ic_agent::identity::BasicIdentity;
use ic_agent::Agent;
use ic_base_types::{CanisterId, PrincipalId};
use ic_ic00_types::{CanisterInstallMode, CreateCanisterArgs, InstallCodeArgs};
use ic_icrc1_ledger::{InitArgs, LedgerArgument};
use ic_icrc1_ledger_sm_tests::{
    ARCHIVE_TRIGGER_THRESHOLD, BLOB_META_KEY, BLOB_META_VALUE, FEE, INT_META_KEY, INT_META_VALUE,
    NAT_META_KEY, NAT_META_VALUE, NUM_BLOCKS_TO_ARCHIVE, TEXT_META_KEY, TEXT_META_VALUE,
    TOKEN_NAME, TOKEN_SYMBOL,
};
use ic_ledger_canister_core::archive::ArchiveOptions;
use ic_starter_tests::{ReplicaBins, ReplicaContext, ReplicaStarterConfig};
use icrc_ledger_types::icrc::generic_metadata_value::MetadataValue as Value;
use icrc_ledger_types::icrc1::account::Account;

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

// Starts the local replica and returns a LocalReplica object
pub async fn start_new_local_replica() -> ReplicaContext {
    let canister_launcher = std::fs::canonicalize(
        std::env::var_os("CANISTER_LAUNCHER").expect("missing canister_launcher binary"),
    )
    .unwrap();

    let replica_bin =
        std::fs::canonicalize(std::env::var_os("REPLICA_BIN").expect("missing replica binary"))
            .unwrap();

    let sandbox_launcher = std::fs::canonicalize(
        std::env::var_os("SANDBOX_LAUNCHER").expect("missing sandbox_launcher binary"),
    )
    .unwrap();

    let starter_bin =
        std::fs::canonicalize(std::env::var_os("STARTER_BIN").expect("missing ic-starter binary"))
            .unwrap();

    let context = ic_starter_tests::start_replica(
        &ReplicaBins {
            canister_launcher,
            replica_bin,
            sandbox_launcher,
            starter_bin,
        },
        &ReplicaStarterConfig::default(),
    )
    .await
    .expect("Failed to start replica");

    context
}

pub async fn get_testing_agent(context: &ReplicaContext) -> Agent {
    // The local replica will be running on the localhost
    let replica_url = Url::parse(&format!("http://localhost:{}", context.port)).unwrap();

    // Setup the agent
    let client = reqwest::ClientBuilder::new().build().unwrap();
    let transport =
        ReqwestHttpReplicaV2Transport::create_with_client(replica_url.clone(), client).unwrap();
    let agent = Agent::builder()
        .with_identity(test_identity())
        .with_arc_transport(Arc::new(transport))
        .build()
        .unwrap();

    // For verification the agent needs the root key of the IC running on the local replica
    agent.fetch_root_key().await.unwrap();
    agent
}

// Deploy an icrc ledger with the default arguments from sm-tests and return the canister id of the icrc ledger
pub async fn deploy_icrc_ledger_with_default_args(context: &ReplicaContext) -> CanisterId {
    let testing_account: Account = get_testing_agent(context)
        .await
        .get_principal()
        .unwrap()
        .into();
    let default_init_args = InitArgs {
        minting_account: testing_account,
        fee_collector_account: None,
        // For testing the test identity of the local replica will receive 1 million ICP
        initial_balances: vec![(testing_account, 1_000_000_000_000)],
        transfer_fee: FEE,
        token_name: TOKEN_NAME.to_string(),
        token_symbol: TOKEN_SYMBOL.to_string(),
        metadata: vec![
            Value::entry(NAT_META_KEY, NAT_META_VALUE),
            Value::entry(INT_META_KEY, INT_META_VALUE),
            Value::entry(TEXT_META_KEY, TEXT_META_VALUE),
            Value::entry(BLOB_META_KEY, BLOB_META_VALUE),
        ],
        archive_options: ArchiveOptions {
            trigger_threshold: ARCHIVE_TRIGGER_THRESHOLD as usize,
            num_blocks_to_archive: NUM_BLOCKS_TO_ARCHIVE as usize,
            node_max_memory_size_bytes: None,
            max_message_size_bytes: None,
            controller_id: PrincipalId::new_user_test_id(100),
            cycles_for_archive_creation: None,
            max_transactions_per_response: None,
        },
        max_memo_length: None,
        feature_flags: None,
    };
    deploy_icrc_ledger_with_custom_args(context, default_init_args).await
}

// Deploy the icrc ledger with custom arguments and return the canister id of the icrc ledger
pub async fn deploy_icrc_ledger_with_custom_args(
    context: &ReplicaContext,
    init_args: InitArgs,
) -> CanisterId {
    let custom_encoded_init_args = Encode!(&(LedgerArgument::Init(init_args))).unwrap();
    let icrc_ledger_canister_id = create_canister(context).await;
    install_canister(context, custom_encoded_init_args, icrc_ledger_canister_id).await;
    icrc_ledger_canister_id
}

// Installs the wasm of a canister to the local replica
async fn install_canister(context: &ReplicaContext, init_arg: Vec<u8>, canister_id: CanisterId) {
    let _ = get_testing_agent(context)
        .await
        .update(&Principal::management_canister(), "install_code")
        .with_effective_canister_id(canister_id.into())
        .with_arg(
            &Encode!(&InstallCodeArgs {
                canister_id: canister_id.into(),
                wasm_module: icrc_ledger_wasm(),
                arg: init_arg,
                mode: CanisterInstallMode::Install,
                query_allocation: None,
                sender_canister_version: None,
                memory_allocation: None,
                compute_allocation: None,
            })
            .unwrap(),
        )
        .call_and_wait()
        .await
        .unwrap();
}

// Create an empty canister on the local replica and return the canister id of the empty canister
async fn create_canister(context: &ReplicaContext) -> CanisterId {
    let response: Vec<u8> = get_testing_agent(context)
        .await
        .update(
            &Principal::management_canister(),
            "provisional_create_canister_with_cycles",
        )
        .with_arg(&Encode!(&CreateCanisterArgs::default()).unwrap())
        .call_and_wait()
        .await
        .unwrap();

    // The return type of the method 'provisional_create_canister_with_cycles' is a CreateCanisterResult struct.
    // To decode it with candid we need a representation of that struct. Since it is only used in this section
    // we will only define it in this function
    #[derive(CandidType, Deserialize)]
    struct CreateCanisterResult {
        pub canister_id: Principal,
    }
    let create_response = Decode!(&response, CreateCanisterResult).unwrap();
    CanisterId::new(create_response.canister_id.into()).unwrap()
}

// Return the wasm of the icrc ledger
fn icrc_ledger_wasm() -> Vec<u8> {
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
