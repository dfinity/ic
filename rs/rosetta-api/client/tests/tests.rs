use candid::Encode;
use candid::Principal;
use ic_icp_rosetta_client::RosettaClient;
use ic_icp_rosetta_runner::start_rosetta;
use ic_icp_rosetta_runner::RosettaOptions;
use ic_ledger_test_utils::build_ledger_wasm;
use ic_ledger_test_utils::pocket_ic_helpers::ledger::LEDGER_CANISTER_ID;
use icp_ledger::LedgerCanisterInitPayload;
use pocket_ic::PocketIcBuilder;
use std::path::PathBuf;
use tokio::runtime::Runtime;

fn path_from_env(var: &str) -> PathBuf {
    std::fs::canonicalize(std::env::var(var).unwrap_or_else(|_| panic!("Unable to find {}", var)))
        .unwrap()
}

// only test_health is in here to check that the client works
// as intended. All the other tests are in the rosetta tests.
#[test]
fn smoke_test() {
    let rt = Runtime::new().unwrap();
    let mut pocket_ic = PocketIcBuilder::new().with_nns_subnet().build();
    let endpoint = pocket_ic.make_live(None);

    let ledger_wasm = build_ledger_wasm();
    let ledger_canister_id = Principal::from(LEDGER_CANISTER_ID);
    let ledger_canister_id = pocket_ic
        .create_canister_with_id(None, None, ledger_canister_id)
        .expect("Unable to create the canister in which the Ledger would be installed");
    pocket_ic.install_canister(
        ledger_canister_id,
        ledger_wasm.bytes(),
        Encode!(&LedgerCanisterInitPayload::builder()
            .minting_account(Principal::anonymous().into())
            .initial_values(
                [(
                    Principal::from_slice(&[1]).into(),
                    icp_ledger::Tokens::from_tokens(1_000_000_000).unwrap(),
                )]
                .into()
            )
            .build()
            .unwrap())
        .unwrap(),
        None,
    );
    let port = endpoint.port().unwrap();
    let replica_url = format!("http://localhost:{}", port);
    let rosetta_bin = path_from_env("ROSETTA_BIN_PATH");
    let rosetta_state_directory =
        tempfile::TempDir::new().expect("failed to create a temporary directory");

    // Wrap async calls in a blocking Block
    rt.block_on(async {
        let context = start_rosetta(
            &rosetta_bin,
            Some(rosetta_state_directory.path().to_owned()),
            RosettaOptions::builder(replica_url).build(),
        )
        .await;
        let client = RosettaClient::from_str_url(&format!("http://localhost:{}", context.port))
            .expect("Unable to parse url");
        assert!(client.network_list().await.is_ok())
    });
}
