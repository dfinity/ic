use candid::{Encode, Principal};
use ic_agent::identity::BasicIdentity;
use ic_agent::Identity;
use ic_icrc_rosetta::common::types::Error;
use ic_icrc_rosetta_client::RosettaClient;
use ic_ledger_test_utils::pocket_ic_helpers::ledger::LEDGER_CANISTER_ID;
use ic_rosetta_api::models::{NetworkIdentifier, NetworkListResponse, NetworkStatusResponse};
use ic_rosetta_api::request_types::{RosettaBlocksMode, RosettaStatus};
use icp_ledger::{AccountIdentifier, Subaccount};
use icp_rosetta_integration_tests::{start_rosetta, RosettaContext};
use pocket_ic::{nonblocking::PocketIc, PocketIcBuilder};
use std::path::PathBuf;
use std::thread::sleep;
use std::time::Duration;
use tempfile::TempDir;
use url::Url;

pub const LEDGER_CANISTER_INDEX_IN_NNS_SUBNET: u64 = 2;
const MAX_ATTEMPTS: u16 = 1000;
const DURATION_BETWEEN_ATTEMPTS: Duration = Duration::from_millis(100);

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
    let minter = AccountIdentifier::new(sender.into(), None);
    let mut subaccount = [0u8; 32];
    subaccount[..2].copy_from_slice(&451u16.to_be_bytes());
    let first_account = AccountIdentifier::new(sender.into(), Some(Subaccount(subaccount)));
    Encode!(&icp_ledger::LedgerCanisterInitPayload::builder()
        .minting_account(minter)
        .initial_values([(first_account, icp_ledger::Tokens::from_e8s(42))].into())
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

// Wrapper of [RosettaClient] with utility functions that
// can panic in case it cannot communicates with the
// Rosetta node.
struct RosettaTestingClient {
    rosetta_client: RosettaClient,
}

impl RosettaTestingClient {
    async fn network_list_or_panic(&self) -> NetworkListResponse {
        self.rosetta_client
            .network_list()
            .await
            .expect("Unable to call /network/list")
    }

    // Rosetta always returns a single network in /network/list.
    // This utility calls /network/list and extracts the single network
    async fn network_or_panic(&self) -> NetworkIdentifier {
        let mut networks = self.network_list_or_panic().await.network_identifiers;
        assert_eq!(networks.len(), 1); // sanity check
        networks.remove(0)
    }

    async fn network_status_or_panic(&self) -> NetworkStatusResponse {
        let network = self.network_or_panic().await;
        self.rosetta_client
            .network_status(network)
            .await
            .expect("Unable to call /network/status")
    }

    async fn status_or_panic(&self) -> RosettaStatus {
        let url = self.rosetta_client.url("/status");
        self.rosetta_client
            .http_client
            .get(url)
            .send()
            .await
            .expect("Unable to call /status")
            .json()
            .await
            .expect("Unable to parse response body for /status")
    }

    async fn wait_or_panic_until_synced_up_to(&self, block_index: u64) {
        let mut network_status = self.network_status_or_panic().await;
        let mut attempts = 0;
        while network_status.current_block_identifier.index < block_index {
            if attempts >= MAX_ATTEMPTS {
                panic!(
                    "Rosetta was unable to sync up to block index: {}. Last network status was: {:#?}",
                    block_index, network_status
                );
            }
            attempts += 1;
            sleep(DURATION_BETWEEN_ATTEMPTS);
            network_status = self.network_status_or_panic().await;
        }
    }
}

// Environment with a PocketIc instance, an ICP Ledger instance and a
// ICP Rosetta node instance.
// Note that because of how Rosetta works, the Ledger is setup with one
// initial block so that Rosetta doesn't panic.
struct TestEnv {
    pocket_ic: PocketIc,
    rosetta_context: Option<RosettaContext>,
    pub rosetta: RosettaTestingClient,
}

impl TestEnv {
    fn new(
        pocket_ic: PocketIc,
        rosetta_context: RosettaContext,
        rosetta_client: RosettaClient,
    ) -> Self {
        Self {
            pocket_ic,
            rosetta_context: Some(rosetta_context),
            rosetta: RosettaTestingClient { rosetta_client },
        }
    }

    async fn setup_rosetta(
        replica_url: Url,
        ledger_canister_id: Principal,
        rosetta_state_directory: PathBuf,
        enable_rosetta_blocks: bool,
    ) -> (RosettaClient, RosettaContext) {
        let (rosetta_client, rosetta_context) = start_rosetta(
            &get_rosetta_path(),
            replica_url,
            ledger_canister_id,
            Some(rosetta_state_directory),
            enable_rosetta_blocks,
        )
        .await;

        let mut networks = rosetta_client
            .network_list()
            .await
            .expect("Unable to call /network/list")
            .network_identifiers;
        assert_eq!(
            networks.len(),
            1,
            "The ICP Rosetta node should always return a list of networks with 1 element!"
        );
        let network = networks.remove(0);

        // Rosetta may not be synced with the Ledger for a while after it started.
        // If the test calls /network/status while it is syncing, Rosetta will reply
        // with an error `Error { code: 700, message: "Internal server error",
        // description: None, retriable: false, details: Some({"error_message":
        // String("Blockchain is empty")}) }` while then fails the test.
        // The following code waits until network status doesn't return that error anymore or a maximum number of retries have been attempted.
        let mut retries = MAX_ATTEMPTS;
        while retries > 0 {
            match rosetta_client.network_status(network.clone()).await {
                Ok(_) => {
                    println!("call to /network/status was successfull");
                    break;
                }
                Err(Error(err)) if matches_blockchain_is_empty_error(&err) => {
                    println!("Found \"Blockchain is empty\" error, retrying in {DURATION_BETWEEN_ATTEMPTS:?} (retries: {retries})");
                    retries -= 1;
                    sleep(DURATION_BETWEEN_ATTEMPTS);
                }
                Err(Error(err)) => {
                    panic!("Unable to call /network/status: {err:?}")
                }
            }
        }

        (rosetta_client, rosetta_context)
    }

    async fn setup_or_panic(enable_rosetta_blocks: bool) -> Self {
        let mut pocket_ic = PocketIcBuilder::new().with_nns_subnet().build_async().await;
        let ledger_canister_id = Principal::from(LEDGER_CANISTER_ID);
        let canister_id = pocket_ic
            .create_canister_with_id(None, None, ledger_canister_id)
            .await
            .expect("Unable to create the canister in which the Ledger would be installed");
        pocket_ic
            .install_canister(
                canister_id,
                icp_ledger_wasm_bytes(),
                icp_ledger_init(),
                None,
            )
            .await;
        const STARTING_CYCLES_PER_CANISTER: u128 = 2_000_000_000_000_000;
        pocket_ic
            .add_cycles(canister_id, STARTING_CYCLES_PER_CANISTER)
            .await;
        println!(
            "Installed the Ledger canister ({canister_id}) onto {}",
            pocket_ic.get_subnet(canister_id).await.unwrap()
        );
        let replica_url = pocket_ic.make_live(None).await;

        let rosetta_state_directory =
            TempDir::new().expect("failed to create a temporary directory");

        let (rosetta_client, rosetta_context) = Self::setup_rosetta(
            replica_url,
            ledger_canister_id,
            rosetta_state_directory.path().to_owned(),
            enable_rosetta_blocks,
        )
        .await;

        let env = TestEnv::new(pocket_ic, rosetta_context, rosetta_client);

        // block 0 always exists in this setup
        env.rosetta.wait_or_panic_until_synced_up_to(0).await;

        env
    }

    async fn restart_rosetta_node(&mut self, enable_rosetta_blocks: bool) {
        let rosetta_state_directory;
        if let Some(rosetta_context) = std::mem::take(&mut self.rosetta_context) {
            rosetta_state_directory = rosetta_context.state_directory.clone();
            rosetta_context.kill();
        } else {
            panic!("The Rosetta State directory should be set")
        }
        println!("Restarting rosetta with enable_rosetta_blocks={enable_rosetta_blocks}. State directory: {rosetta_state_directory:?}");
        let replica_url = self
            .pocket_ic
            .url()
            .expect("The PocketIC gateway should be set!");
        let ledger_canister_id = Principal::from(LEDGER_CANISTER_ID);
        let (rosetta_client, rosetta_context) = Self::setup_rosetta(
            replica_url,
            ledger_canister_id,
            rosetta_state_directory,
            enable_rosetta_blocks,
        )
        .await;
        self.rosetta = RosettaTestingClient { rosetta_client };
        self.rosetta_context = Some(rosetta_context);

        // block 0 always exists in this setup
        self.rosetta.wait_or_panic_until_synced_up_to(0).await;
    }
}

fn matches_blockchain_is_empty_error(error: &rosetta_core::miscellaneous::Error) -> bool {
    error.code == 700
        && error.details.is_some()
        && error
            .details
            .as_ref()
            .unwrap()
            .get("error_message")
            .map_or(false, |e| e == "Blockchain is empty")
}

#[tokio::test]
async fn test_rosetta_blocks() {
    let mut env = TestEnv::setup_or_panic(false).await;
    // Check that by default the rosetta blocks mode is not enabled
    assert_eq!(
        env.rosetta.status_or_panic().await.rosetta_blocks_mode,
        RosettaBlocksMode::Disabled
    );

    // Check that restarting Rosetta doesn't enable the
    // rosetta blocks mode
    env.restart_rosetta_node(false).await;
    assert_eq!(
        env.rosetta.status_or_panic().await.rosetta_blocks_mode,
        RosettaBlocksMode::Disabled
    );

    // Check that passing --enable-rosetta-blocks enables the
    // rosetta blocks mode for the next block

    // The first rosetta block index is the same as the index
    // of the next block to sync (i.e. current block index + 1)
    let first_rosetta_block_index = env
        .rosetta
        .network_status_or_panic()
        .await
        .current_block_identifier
        .index
        + 1;
    env.restart_rosetta_node(true).await;
    assert_eq!(
        env.rosetta.status_or_panic().await.rosetta_blocks_mode,
        RosettaBlocksMode::Enabled {
            first_rosetta_block_index
        }
    );

    // Check that once rosetta blocks mode is enabled then
    // it will be enabled every time Rosetta restarts even
    // without passing --enable-rosetta-blocks
    env.restart_rosetta_node(false).await;
    assert_eq!(
        env.rosetta.status_or_panic().await.rosetta_blocks_mode,
        RosettaBlocksMode::Enabled {
            first_rosetta_block_index
        }
    );
}
