use candid::{Encode, Principal};
use ic_agent::agent::http_transport::reqwest_transport::ReqwestTransport;
use ic_agent::identity::BasicIdentity;
use ic_agent::{Agent, Identity};
use ic_icrc_rosetta::common::types::Error;
use ic_icrc_rosetta_client::RosettaClient;
use ic_ledger_test_utils::pocket_ic_helpers;
use ic_ledger_test_utils::pocket_ic_helpers::ledger::LEDGER_CANISTER_ID;
use ic_rosetta_api::models::{NetworkIdentifier, NetworkListResponse, NetworkStatusResponse};
use ic_rosetta_api::request_types::{RosettaBlocksMode, RosettaStatus};
use icp_ledger::{AccountIdentifier, Subaccount};
use icp_rosetta_integration_tests::{start_rosetta, RosettaContext};
use pocket_ic::{PocketIc, PocketIcBuilder};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
use tempfile::TempDir;
use tokio::runtime::Runtime;

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

    async fn restart_rosetta_node(&mut self, enable_rosetta_blocks: bool) {
        let mut state_directory = None;
        if let Some(rosetta_context) = std::mem::take(&mut self.rosetta_context) {
            state_directory = Some(rosetta_context.state_directory.clone());
            rosetta_context.kill();
        }
        let replica_url = self
            .pocket_ic
            .url()
            .expect("The PocketIC gateway should be set!");
        let ledger_canister_id = Principal::from(LEDGER_CANISTER_ID);
        let (rosetta_client, rosetta_context) = start_rosetta(
            &get_rosetta_path(),
            replica_url,
            ledger_canister_id,
            state_directory,
            enable_rosetta_blocks,
        )
        .await;
        self.rosetta = RosettaTestingClient { rosetta_client };
        self.rosetta_context = Some(rosetta_context);
    }
}

fn is_blockchain_is_empty_error(error: &rosetta_core::miscellaneous::Error) -> bool {
    error.code == 700
        && error.details.is_some()
        && error
            .details
            .as_ref()
            .unwrap()
            .get("error_message")
            .map_or(false, |e| e == "Blockchain is empty")
}

// Create a [TestEnv] and then pass it to the test logic.
//
// This is required because `PocketIc` doesn't support
// async yet (see https://dfinity.atlassian.net/browse/VER-2765)
// and should be replaced with a better and simpler solution
// once it does.
//
// Note: the result is boxed because of https://users.rust-lang.org/t/async-function-taking-a-reference-lifetimes-problem/83252/2
fn run_pocket_ic_test<F>(f: F)
where
    F: for<'a> FnOnce(&'a mut TestEnv) -> Pin<Box<dyn Future<Output = ()> + 'a>>,
{
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
    let replica_url = pocket_ic.make_live(None);
    let transport = ReqwestTransport::create(replica_url.clone()).unwrap();

    let agent = Agent::builder()
        .with_identity(test_identity())
        .with_arc_transport(Arc::new(transport))
        .build()
        .unwrap();

    let rosetta_state_directory = TempDir::new().expect("failed to create a temporary directory");

    // PocketIc is using blocking Reqwest and therefore must be dropped outside
    // an async context (otherwise an error happens). The testing code as well as
    // the  rosetta_client are async so we run them within
    // `block_on`, then return the `pocked_ic` instance so that it can be dropped
    // correctly. Note that this is caused by https://dfinity.atlassian.net/browse/VER-2765
    // and should be removed once VER-2765 is fixed.
    let mut pocket_ic = rt.block_on(async {
        agent.fetch_root_key().await.unwrap();

        let (rosetta_client, rosetta_context) = start_rosetta(
            &get_rosetta_path(),
            replica_url,
            ledger_canister_id,
            Some(rosetta_state_directory.path().to_owned()),
            false,
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
        // The following code waits until network status doesn't return that error anymore.
        let mut retries = 100;
        while retries > 0 {
            match rosetta_client.network_status(network.clone()).await {
                Ok(_) => break,
                Err(Error(err)) if is_blockchain_is_empty_error(&err) => {
                    const WAIT_BETWEEN_RETRIES: Duration = Duration::from_millis(100);
                    println!("Found \"Blockchain is empty\" error, retrying in {WAIT_BETWEEN_RETRIES:?} (retries: {retries})");
                    retries -= 1;
                    sleep(WAIT_BETWEEN_RETRIES);
                }
                Err(Error(err)) => {
                    panic!("Unable to call /network/status: {err:?}")
                }
            }
        }

        let mut env = TestEnv::new(pocket_ic, rosetta_context, rosetta_client);

        f(&mut env).await;

        env.pocket_ic
    });

    pocket_ic.make_deterministic();
}

#[test]
fn test_example() {
    // This is an example test that shows how to use `run_pocked_ic_test` and
    // does a sanity check that there is at least one block

    run_pocket_ic_test(|env: &mut TestEnv| {
        Box::pin(async move {
            // block 0 always exists in this setup
            env.rosetta.wait_or_panic_until_synced_up_to(0).await;
        })
    });
}

#[test]
fn test_rosetta_blocks() {
    run_pocket_ic_test(|env: &mut TestEnv| {
        Box::pin(async move {
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
        })
    });
}
