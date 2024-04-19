use candid::{Encode, Nat, Principal};
use ic_agent::agent::http_transport::reqwest_transport::ReqwestTransport;
use ic_agent::identity::BasicIdentity;
use ic_agent::{Agent, Identity};
use ic_ledger_test_utils::pocket_ic_helpers;
use ic_ledger_test_utils::pocket_ic_helpers::ledger::LEDGER_CANISTER_ID;
use icp_ledger::AccountIdentifier;
use icp_rosetta_integration_tests::start_rosetta;
use icrc_ledger_agent::Icrc1Agent;
use icrc_ledger_types::icrc1::{account::Account, transfer::TransferArg};
use pocket_ic::PocketIcBuilder;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
use tokio::runtime::Runtime;
use url::Url;

pub const LEDGER_CANISTER_INDEX_IN_NNS_SUBNET: u64 = 2;
const MAX_ATTEMPTS: u8 = 100;
const DURATION_BETWEEN_ATTEMPTS: Duration = Duration::from_millis(1000);

fn get_rosetta_path() -> std::path::PathBuf {
    std::fs::canonicalize(std::env::var_os("ROSETTA_PATH").expect("missing ic-rosetta-api binary"))
        .unwrap()
}

fn icp_ledger_wasm_bytes() -> Vec<u8> {
    let icp_ledger_project_path =
        std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("icp_ledger")
            .join("ledger");
    ic_test_utilities_load_wasm::load_wasm(
        icp_ledger_project_path,
        "ledger-canister",
        &["notify-method"],
    )
}

fn icp_ledger_init() -> Vec<u8> {
    let sender = test_identity()
        .sender()
        .expect("test identity sender not found!");
    Encode!(&icp_ledger::LedgerCanisterInitPayload::builder()
        .minting_account(AccountIdentifier::new(sender.into(), None))
        .build()
        .unwrap())
    .unwrap()
}

fn test_identity() -> BasicIdentity {
    BasicIdentity::from_pem(
        &b"-----BEGIN PRIVATE KEY-----
MFMCAQEwBQYDK2VwBCIEIJKDIfd1Ybt48Z23cVEbjL2DGj1P5iDYmthcrptvBO3z
oSMDIQCJuBJPWt2WWxv0zQmXcXMjY+fP0CJSsB80ztXpOFd2ZQ==
-----END PRIVATE KEY-----"[..],
    )
    .expect("failed to parse identity from PEM")
}

#[test]
fn test() {
    // this is a "demo" test, it shows how to setup a replica with the icp ledger installed
    // and a rosetta node connected to it.
    let rt = Runtime::new().unwrap();
    let mut pocket_ic = PocketIcBuilder::new().with_nns_subnet().build();
    let ledger_canister_id = Principal::from(LEDGER_CANISTER_ID);
    pocket_ic_helpers::install_canister(
        &pocket_ic,
        "ICP Ledger",
        LEDGER_CANISTER_ID,
        icp_ledger_init(),
        icp_ledger_wasm_bytes(),
        None,
    );
    let endpoint = pocket_ic.make_live(None);
    let port = endpoint.port().unwrap();
    let replica_url = Url::parse(&format!("http://localhost:{}", port)).unwrap();

    let transport = ReqwestTransport::create(replica_url.clone()).unwrap();

    let agent = Agent::builder()
        .with_identity(test_identity())
        .with_arc_transport(Arc::new(transport))
        .build()
        .unwrap();

    // Wrap async calls in a blocking Block
    rt.block_on(async {
        agent.fetch_root_key().await.unwrap();

        // rosetta prints a lot of errors if there are no blocks in the chain so we first
        // create a block and only after start rosetta.
        let ledger_agent = Icrc1Agent {
            agent,
            ledger_canister_id,
        };
        let to = Account {
            owner: Principal::anonymous(),
            subaccount: None,
        };
        let amount = Nat::from(10_000_000_u64);
        let _ = ledger_agent
            .transfer(TransferArg {
                from_subaccount: None,
                to,
                amount,
                fee: None,
                created_at_time: None,
                memo: None,
            })
            .await
            .expect("Unable to transfer tokens!")
            .expect("Unable to transfer tokens!");

        // start rosetta
        let (client, _rosetta_context) =
            start_rosetta(&get_rosetta_path(), replica_url, ledger_canister_id).await;
        let network = client
            .network_list()
            .await
            .expect("Unable to list networks")[0]
            .clone();

        // check that block 0 exists
        //
        // We don't know when Rosetta finishes the synchronization.
        // So we try multiple times.
        let mut block = None;
        let mut attempts = 0;
        while block.is_none() && attempts < MAX_ATTEMPTS {
            match client.block(network.clone(), 0).await {
                Ok(b) => {
                    block = b;
                }
                Err(err) => {
                    if attempts == MAX_ATTEMPTS - 1 {
                        panic!("Unable to fetch block 0: {}", err)
                    }
                }
            };
            sleep(DURATION_BETWEEN_ATTEMPTS);
            attempts += 1;
        }
        assert!(block.is_some())
    });
}
