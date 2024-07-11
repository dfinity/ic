use candid::{CandidType, Decode, Encode, Nat, Principal};
use ic_agent::identity::BasicIdentity;
use ic_agent::Identity;
use ic_icrc_rosetta::common::types::Error;
use ic_icrc_rosetta_client::RosettaClient;
use ic_ledger_test_utils::pocket_ic_helpers::ledger::LEDGER_CANISTER_ID;
use ic_rosetta_api::convert;
use ic_rosetta_api::models::{
    NetworkIdentifier, NetworkListResponse, NetworkStatusResponse, PartialBlockIdentifier,
};
use ic_rosetta_api::request_types::{RosettaBlocksMode, RosettaStatus};
use ic_sender_canister_lib::{SendArg, SendResult};
use icp_ledger::{
    AccountIdentifier, Memo, Operation, TimeStamp, Tokens, Transaction, DEFAULT_TRANSFER_FEE,
};
use icp_rosetta_integration_tests::{start_rosetta, RosettaContext};
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::{BlockIndex, TransferArg, TransferError};
use pocket_ic::WasmResult;
use pocket_ic::{nonblocking::PocketIc, PocketIcBuilder};
use serde::Deserialize;
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

fn icp_ledger_init(sender_id: Principal) -> Vec<u8> {
    let sender = test_identity()
        .sender()
        .expect("test identity sender not found!");
    let minter = AccountIdentifier::new(sender.into(), None);
    Encode!(&icp_ledger::LedgerCanisterInitPayload::builder()
        .minting_account(minter)
        .initial_values(
            [(
                AccountIdentifier::new(sender_id.into(), None),
                icp_ledger::Tokens::from_tokens(1_000_000_000).unwrap(),
            )]
            .into()
        )
        .build()
        .unwrap())
    .unwrap()
}

fn sender_wasm_bytes() -> Vec<u8> {
    let sender_project_path = std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("test_utils")
        .join("sender_canister");
    // rs/rosetta-api/test_utils/sender_canister/Cargo.toml
    ic_test_utilities_load_wasm::load_wasm(sender_project_path, "ic-sender-canister", &[])
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
    async fn block_or_panic(&self, id: PartialBlockIdentifier) -> rosetta_core::objects::Block {
        let network = self.network_or_panic().await;
        self.rosetta_client
            .block(network, id.clone())
            .await
            .expect("Unable to call /block")
            .block
            .unwrap_or_else(|| panic!("Block with id {id:?} not found"))
    }

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
    _tmp_dir: TempDir,
    pocket_ic: PocketIc,
    rosetta_context: Option<RosettaContext>,
    pub rosetta: RosettaTestingClient,
    ledger_id: Principal,
    sender_id: Principal,
}

impl TestEnv {
    fn new(
        tmp_dir: TempDir,
        pocket_ic: PocketIc,
        rosetta_context: RosettaContext,
        rosetta_client: RosettaClient,
        ledger_id: Principal,
        sender_id: Principal,
    ) -> Self {
        Self {
            _tmp_dir: tmp_dir,
            pocket_ic,
            rosetta_context: Some(rosetta_context),
            rosetta: RosettaTestingClient { rosetta_client },
            ledger_id,
            sender_id,
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
            replica_url.clone(),
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

        let sender_canister_id = pocket_ic.create_canister().await;
        pocket_ic
            .install_canister(
                sender_canister_id,
                sender_wasm_bytes(),
                Encode!().unwrap(),
                None,
            )
            .await;
        pocket_ic
            .add_cycles(sender_canister_id, STARTING_CYCLES_PER_CANISTER)
            .await;

        let ledger_canister_id = Principal::from(LEDGER_CANISTER_ID);
        let canister_id = pocket_ic
            .create_canister_with_id(None, None, ledger_canister_id)
            .await
            .expect("Unable to create the canister in which the Ledger would be installed");
        pocket_ic
            .install_canister(
                canister_id,
                icp_ledger_wasm_bytes(),
                icp_ledger_init(sender_canister_id),
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

        let env = TestEnv::new(
            rosetta_state_directory,
            pocket_ic,
            rosetta_context,
            rosetta_client,
            ledger_canister_id,
            sender_canister_id,
        );

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
        assert!(rosetta_state_directory.exists());
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

    pub async fn icrc1_transfers(&self, args: Vec<TransferArg>) -> Vec<BlockIndex> {
        let arg = args
            .into_iter()
            .map(|arg| SendArg {
                to: self.ledger_id,
                method: "icrc1_transfer".into(),
                arg: Encode!(&arg).unwrap(),
                payment: 0,
            })
            .collect::<Vec<_>>();
        let arg = Encode!(&arg).unwrap();
        self.pocket_ic
            .update_call(self.sender_id, Principal::anonymous(), "send", arg)
            .await
            .expect("Unable to submit send call")
            .unwrap_as::<Vec<SendResult>>()
            .into_iter()
            .map(|v| v.map(|b| Decode!(&b, Result<BlockIndex, TransferError>).unwrap()))
            .collect::<Result<Vec<_>, _>>()
            .expect("Error calling icrc1_transfer from the Sender canister")
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .expect("Error performing icrc1_transfer")
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
async fn test_rosetta_blocks_mode_enabled() {
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
    // Check that restarting Rosetta doesn't enable the
    // rosetta blocks mode
    env.restart_rosetta_node(false).await;
    assert_eq!(
        env.rosetta.status_or_panic().await.rosetta_blocks_mode,
        RosettaBlocksMode::Disabled
    );

    // Check that passing --enable-rosetta-blocks enables the
    // rosetta blocks mode for the next block
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

// a simple trait to simplify unwrapping and decoding a WasmResult
trait UnwrapCandid {
    fn unwrap(&self) -> &[u8];
    fn unwrap_as<T: CandidType + for<'a> Deserialize<'a>>(&self) -> T {
        Decode!(self.unwrap(), T).expect("Unable to decode")
    }
}

impl UnwrapCandid for WasmResult {
    fn unwrap(&self) -> &[u8] {
        match self {
            WasmResult::Reply(bytes) => bytes,
            WasmResult::Reject(err) => panic!("Cannot unwrap Reject: {err}"),
        }
    }
}

#[tokio::test]
async fn test_rosetta_blocks_enabled_after_first_block() {
    let mut env = TestEnv::setup_or_panic(false).await;

    // enable rosetta blocks mode
    env.restart_rosetta_node(true).await;
    env.pocket_ic.stop_progress().await;

    env.icrc1_transfers(vec![
        // create block 1 and Rosetta Block 1
        TransferArg {
            from_subaccount: None,
            to: Account::from(Principal::anonymous()),
            fee: None,
            created_at_time: None,
            memo: None,
            amount: Nat::from(1u64),
        },
        // create block 2 which will go inside Rosetta Block 1
        TransferArg {
            from_subaccount: None,
            to: Account::from(Principal::anonymous()),
            fee: None,
            created_at_time: None,
            memo: None,
            amount: Nat::from(2u64),
        },
    ])
    .await;

    let rosetta_block1_expected_time_ts = TimeStamp::from(env.pocket_ic.get_time().await);
    let rosetta_block1_expected_time_millis =
        rosetta_block1_expected_time_ts.as_nanos_since_unix_epoch() / 1_000_000;

    env.pocket_ic.auto_progress().await;

    let old_block0 = env
        .rosetta
        .block_or_panic(PartialBlockIdentifier {
            index: Some(0),
            hash: None,
        })
        .await;

    env.rosetta.wait_or_panic_until_synced_up_to(2).await;

    // Enabling Rosetta Blocks Mode should not change blocks before
    // the first rosetta index, in this case block 0
    let block0 = env
        .rosetta
        .block_or_panic(PartialBlockIdentifier {
            index: Some(0),
            hash: None,
        })
        .await;
    assert_eq!(old_block0, block0);

    // Block 1 must be a Rosetta block with 2 transactions
    let block1_hash = env
        .rosetta
        .block_or_panic(PartialBlockIdentifier {
            index: Some(1),
            hash: None,
        })
        .await
        .block_identifier
        .hash;
    for (index, hash) in [(Some(1), None), (Some(1), Some(block1_hash.clone()))] {
        let block1 = env
            .rosetta
            .block_or_panic(PartialBlockIdentifier { index, hash })
            .await;
        assert_eq!(block1.block_identifier.index, 1);
        assert_eq!(block1.block_identifier.hash, block1_hash);
        assert_eq!(block1.parent_block_identifier, block0.block_identifier);
        assert_eq!(block1.timestamp, rosetta_block1_expected_time_millis);
        assert_eq!(block1.metadata, None);
        assert_eq!(block1.transactions.len(), 2);

        // Check the first transaction of the first Rossetta Block
        assert_eq!(
            block1.transactions.first().unwrap(),
            &convert::to_rosetta_core_transaction(
                /* block_index: */ 1,
                Transaction {
                    operation: Operation::Transfer {
                        from: AccountIdentifier::new(env.sender_id.into(), None),
                        to: AccountIdentifier::new(Principal::anonymous().into(), None),
                        amount: Tokens::from_e8s(1u64),
                        fee: DEFAULT_TRANSFER_FEE,
                        spender: None,
                    },
                    memo: Memo(0),
                    created_at_time: None,
                    icrc1_memo: None,
                },
                rosetta_block1_expected_time_ts,
                "ICP"
            )
            .unwrap(),
        );

        // Check the second transaction of the firsst Rosetta Block
        assert_eq!(
            block1.transactions.get(1).unwrap(),
            &convert::to_rosetta_core_transaction(
                /* block_index: */ 2,
                Transaction {
                    operation: Operation::Transfer {
                        from: AccountIdentifier::new(env.sender_id.into(), None),
                        to: AccountIdentifier::new(Principal::anonymous().into(), None),
                        amount: Tokens::from_e8s(2u64),
                        fee: DEFAULT_TRANSFER_FEE,
                        spender: None,
                    },
                    memo: Memo(0),
                    created_at_time: None,
                    icrc1_memo: None,
                },
                rosetta_block1_expected_time_ts,
                "ICP"
            )
            .unwrap(),
        );
    }
}

#[tokio::test]
async fn test_rosetta_blocks_dont_contain_transactions_duplicates() {
    // let env = TestEnv::setup_or_panic(true).await;

    // // Rosetta block 0 contains transaction 0

    // env.pocket_ic.stop_progress().await;

    // // Create block 1 and Rosetta Block 1
    // let from = test_identity()
    //     .sender()
    //     .expect("Unable to create the test sender");
    // let id1 = env
    //     .submit_transfer_or_panic(from, Principal::anonymous(), 1u64)
    //     .await;
    // // Create block 2 with the same transaction as block 1.
    // // This must create a new Rosetta Block at index 2
    // let id2 = env
    //     .submit_transfer_or_panic(from, Principal::anonymous(), 1u64)
    //     .await;
    // // Create block 3 with a different transaction than the one in block 2.
    // // block 3 will therefore go inside Rosetta Block 2
    // let id3 = env
    //     .submit_transfer_or_panic(from, Principal::anonymous(), 2u64)
    //     .await;
    // // Create block 4 with the same transaction as block 2.
    // // This must create a new Rosetta Block at index 3
    // let id4 = env
    //     .submit_transfer_or_panic(from, Principal::anonymous(), 1u64)
    //     .await;

    // for id in [id1, id2, id3, id4] {
    //     env.pocket_ic
    //         .await_call(id)
    //         .await
    //         .unwrap()
    //         .unwrap_as::<Result<BlockIndex, TransferError>>()
    //         .expect("Unable to mint");
    // }

    // let rosetta_block1_expected_time_ts = TimeStamp::from(env.pocket_ic.get_time().await);
    // let rosetta_block1_expected_time_millis =
    //     rosetta_block1_expected_time_ts.as_nanos_since_unix_epoch() / 1_000_000;

    // env.pocket_ic.auto_progress().await;

    // // wait for all the blocks to be processed by rosetta
    // for i in 0..1000 {
    //     match env
    //         .rosetta
    //         .rosetta_client
    //         .block(
    //             env.rosetta.network_or_panic().await,
    //             PartialBlockIdentifier {
    //                 index: Some(3),
    //                 hash: None,
    //             },
    //         )
    //         .await
    //     {
    //         Ok(_) => break,
    //         Err(_) if i == 999 => {
    //             panic!("Timeout waiting for block 3 to be synced by Roseta")
    //         }
    //         Err(_) => {
    //             sleep(Duration::from_millis(100));
    //         }
    //     }
    // }

    // let block0 = env
    //     .rosetta
    //     .block_or_panic(PartialBlockIdentifier {
    //         index: Some(0),
    //         hash: None,
    //     })
    //     .await;
    // let block1 = env
    //     .rosetta
    //     .block_or_panic(PartialBlockIdentifier {
    //         index: Some(1),
    //         hash: None,
    //     })
    //     .await;
    // assert_eq!(block1.block_identifier.index, 1);
    // assert_eq!(block1.parent_block_identifier, block0.block_identifier);
    // assert_eq!(block1.timestamp, rosetta_block1_expected_time_millis);
    // assert_eq!(block1.metadata, None);
    // assert_eq!(
    //     block1.transactions,
    //     vec![convert::to_rosetta_core_transaction(
    //         /* block_index: */ 1,
    //         Transaction {
    //             operation: Operation::Mint {
    //                 to: AccountIdentifier::new(Principal::anonymous().into(), None),
    //                 amount: Tokens::from_e8s(1u64),
    //             },
    //             memo: Memo(0),
    //             created_at_time: None,
    //             icrc1_memo: None,
    //         },
    //         rosetta_block1_expected_time_ts,
    //         "ICP"
    //     )
    //     .unwrap()]
    // );

    // let block2 = env
    //     .rosetta
    //     .block_or_panic(PartialBlockIdentifier {
    //         index: Some(2),
    //         hash: None,
    //     })
    //     .await;

    // let block3 = env
    //     .rosetta
    //     .block_or_panic(PartialBlockIdentifier {
    //         index: Some(3),
    //         hash: None,
    //     })
    //     .await;
}
