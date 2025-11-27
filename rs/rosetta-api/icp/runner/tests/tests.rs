use candid::Encode;
use candid::Principal;
use ic_icp_rosetta_runner::RosettaOptionsBuilder;
use ic_icp_rosetta_runner::start_rosetta;
use ic_nns_constants::LEDGER_CANISTER_ID;
use ic_rosetta_test_utils::path_from_env;
use icp_ledger::LedgerCanisterInitPayload;
use pocket_ic::PocketIcBuilder;
use reqwest::StatusCode;
use tokio::runtime::Runtime;

#[test]
fn smoke_test() {
    let rt = Runtime::new().unwrap();
    let mut pocket_ic = PocketIcBuilder::new().with_nns_subnet().build();
    let endpoint = pocket_ic.make_live(None);

    let ledger_wasm_bytes = std::fs::read(std::env::var("LEDGER_CANISTER_WASM_PATH").unwrap())
        .expect("Could not read ledger wasm");
    let ledger_canister_id = Principal::from(LEDGER_CANISTER_ID);
    let ledger_canister_id = pocket_ic
        .create_canister_with_id(None, None, ledger_canister_id)
        .expect("Unable to create the canister in which the Ledger would be installed");
    pocket_ic.install_canister(
        ledger_canister_id,
        ledger_wasm_bytes,
        Encode!(
            &LedgerCanisterInitPayload::builder()
                .minting_account(Principal::anonymous().into())
                .initial_values(
                    [(
                        Principal::from_slice(&[1]).into(),
                        icp_ledger::Tokens::from_tokens(1_000_000_000).unwrap(),
                    )]
                    .into()
                )
                .build()
                .unwrap()
        )
        .unwrap(),
        None,
    );
    let port = endpoint.port().unwrap();
    let replica_url = format!("http://localhost:{port}");
    let rosetta_bin = path_from_env("ROSETTA_BIN_PATH");
    let rosetta_state_directory =
        tempfile::TempDir::new().expect("failed to create a temporary directory");
    let http_client = reqwest::Client::new();

    rt.block_on(async {
        let context = start_rosetta(
            &rosetta_bin,
            rosetta_state_directory,
            RosettaOptionsBuilder::new(replica_url).build(),
        )
        .await;
        let res = http_client
            .post(format!("http://localhost:{}/network/list", context.port).as_str())
            .send()
            .await
            .expect("Failed to send request");
        assert_eq!(
            res.status(),
            StatusCode::OK,
            "GET /network_list failed. Response: {res:?}"
        );
    });
}
