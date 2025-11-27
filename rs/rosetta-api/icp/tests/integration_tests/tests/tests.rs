use candid::{CandidType, Decode, Encode, Nat, Principal};
use ic_agent::Identity;
use ic_agent::identity::BasicIdentity;
use ic_icrc_rosetta::common::types::Error;
use ic_icrc_rosetta_client::RosettaClient;
use ic_nns_constants::LEDGER_CANISTER_ID;
use ic_rosetta_api::convert;
use ic_rosetta_api::models::{
    BlockIdentifier, CallResponse, NetworkIdentifier, NetworkListResponse, NetworkStatusResponse,
    PartialBlockIdentifier, QueryBlockRangeRequest, QueryBlockRangeResponse, TransactionIdentifier,
};
use ic_rosetta_api::request_types::{RosettaBlocksMode, RosettaStatus};
use ic_sender_canister_lib::{SendArg, SendResult};
use icp_ledger::{
    AccountIdentifier, DEFAULT_TRANSFER_FEE, Memo, Operation, TimeStamp, Tokens, Transaction,
};
use icp_rosetta_integration_tests::{RosettaContext, start_rosetta};
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::{BlockIndex, TransferArg, TransferError};
use num_traits::cast::ToPrimitive;
use pocket_ic::{PocketIcBuilder, nonblocking::PocketIc};
use rosetta_core::objects::ObjectMap;
use serde::Deserialize;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, SystemTime};
use tempfile::TempDir;
use tokio::time::sleep;
use url::Url;

pub const LEDGER_CANISTER_INDEX_IN_NNS_SUBNET: u64 = 2;
const MAX_ATTEMPTS: u16 = 10;
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
    ic_test_utilities_load_wasm::load_wasm(icp_ledger_project_path, "ledger-canister", &[])
}

fn icp_ledger_init(sender_id: Principal) -> Vec<u8> {
    let sender = test_identity()
        .sender()
        .expect("test identity sender not found!");
    let minter = AccountIdentifier::new(sender.into(), None);
    Encode!(
        &icp_ledger::LedgerCanisterInitPayload::builder()
            .minting_account(minter)
            .initial_values(
                [(
                    AccountIdentifier::new(sender_id.into(), None),
                    icp_ledger::Tokens::from_tokens(1_000_000_000).unwrap(),
                )]
                .into()
            )
            .build()
            .unwrap()
    )
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
    // rs/rosetta-api/icp/test_utils/sender_canister/Cargo.toml
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
    async fn block(
        &self,
        id: PartialBlockIdentifier,
    ) -> Result<rosetta_core::response_types::BlockResponse, Error> {
        let network = self.network_or_panic().await;
        self.rosetta_client.block(network, id.clone()).await
    }

    async fn block_transaction(
        &self,
        block_id: BlockIdentifier,
        tx_id: TransactionIdentifier,
    ) -> Result<rosetta_core::response_types::BlockTransactionResponse, Error> {
        let network = self.network_or_panic().await;
        self.rosetta_client
            .block_transaction(network, block_id.clone(), tx_id.clone())
            .await
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

    async fn network_status(&self) -> Result<NetworkStatusResponse, Error> {
        let network = self.network_or_panic().await;
        self.rosetta_client.network_status(network).await
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

    async fn wait_until_synced_up_to(&self, block_index: u64) -> anyhow::Result<()> {
        let mut attempts = 0;
        loop {
            let status = self.network_status().await;
            if status.is_ok() && status.unwrap().current_block_identifier.index >= block_index {
                break;
            }
            if attempts >= MAX_ATTEMPTS {
                anyhow::bail!(
                    "Rosetta was unable to sync up to block index: {}",
                    block_index
                );
            }
            attempts += 1;
            sleep(DURATION_BETWEEN_ATTEMPTS).await;
        }
        Ok(())
    }

    pub async fn call_or_panic(&self, method: String, arg: ObjectMap) -> CallResponse {
        let network_identifier = self.network_or_panic().await;
        self.rosetta_client
            .call(network_identifier, method, arg)
            .await
            .expect("Unable to call method")
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
        persistent_storage: bool,
    ) -> (RosettaClient, RosettaContext) {
        let (rosetta_client, rosetta_context) = start_rosetta(
            &get_rosetta_path(),
            replica_url.clone(),
            ledger_canister_id,
            Some(rosetta_state_directory),
            enable_rosetta_blocks,
            persistent_storage,
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
                    retries -= 1;
                    sleep(DURATION_BETWEEN_ATTEMPTS).await;
                }
                Err(Error(err)) => {
                    panic!("Unable to call /network/status: {err:?}")
                }
            }
        }

        (rosetta_client, rosetta_context)
    }

    async fn setup(enable_rosetta_blocks: bool, persistent_storage: bool) -> anyhow::Result<Self> {
        let mut attempts = 2;
        loop {
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
                persistent_storage,
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
            match env.rosetta.wait_until_synced_up_to(0).await {
                Ok(_) => break Ok(env),
                Err(e) => {
                    println!("Error during setup waiting for Rosetta to sync up to block 0: {e}");
                    if attempts == 0 {
                        anyhow::bail!("Unable to setup TestEnv");
                    }
                    attempts -= 1;
                }
            }
        }
    }

    async fn restart_rosetta_node(
        &mut self,
        enable_rosetta_blocks: bool,
        persistent_storage: bool,
    ) -> anyhow::Result<()> {
        let rosetta_state_directory;
        match std::mem::take(&mut self.rosetta_context) {
            Some(rosetta_context) => {
                rosetta_state_directory = rosetta_context.state_directory.clone();
                rosetta_context.kill();
            }
            _ => {
                panic!("The Rosetta State directory should be set")
            }
        }
        assert!(rosetta_state_directory.exists());
        println!(
            "Restarting rosetta with enable_rosetta_blocks={enable_rosetta_blocks}. State directory: {rosetta_state_directory:?}"
        );
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
            persistent_storage,
        )
        .await;
        self.rosetta = RosettaTestingClient { rosetta_client };
        self.rosetta_context = Some(rosetta_context);
        Ok(())
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
    (error.code == 700 || error.code == 712 || error.code == 721)
        && error.details.is_some()
        && error
            .details
            .as_ref()
            .unwrap()
            .get("error_message")
            .is_some_and( |e| {
                e == "Blockchain is empty" || e == "Block not found: 0" || e == "RosettaBlocks was activated and there are no RosettaBlocks in the database yet. The synch is ongoing, please wait until the first RosettaBlock is written to the database."
            })
}

#[tokio::test]
async fn test_rosetta_blocks_mode_enabled() {
    let mut env = TestEnv::setup(false, true).await.unwrap();

    // Check that by default the rosetta blocks mode is not enabled
    assert_eq!(
        env.rosetta.status_or_panic().await.rosetta_blocks_mode,
        RosettaBlocksMode::Disabled
    );

    // Check that restarting Rosetta doesn't enable the
    // rosetta blocks mode
    env.restart_rosetta_node(false, true).await.unwrap();
    assert_eq!(
        env.rosetta.status_or_panic().await.rosetta_blocks_mode,
        RosettaBlocksMode::Disabled
    );
    // Check that restarting Rosetta doesn't enable the
    // rosetta blocks mode
    env.restart_rosetta_node(false, true).await.unwrap();
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
        .network_status()
        .await
        .unwrap()
        .current_block_identifier
        .index
        + 1;

    env.restart_rosetta_node(true, true).await.unwrap();
    assert_eq!(
        env.rosetta.status_or_panic().await.rosetta_blocks_mode,
        RosettaBlocksMode::Enabled {
            first_rosetta_block_index
        }
    );

    // Currently there exists no rosetta block.
    // We need to create one or otherwise rosetta will simply return an error stating that the blockchain is empty
    assert!(env.rosetta.network_status().await.is_err());
    env.icrc1_transfers(vec![TransferArg {
        from_subaccount: None,
        to: Account::from(Principal::anonymous()),
        fee: None,
        created_at_time: None,
        memo: None,
        amount: Nat::from(1u64),
    }])
    .await;
    // Let rosetta catch up to the latest block
    env.rosetta.wait_until_synced_up_to(1).await.unwrap();
    // The first rosetta block index is the same as the index of the most recently fetched block
    let first_rosetta_block_index = env
        .rosetta
        .network_status()
        .await
        .unwrap()
        .current_block_identifier
        .index;
    env.restart_rosetta_node(true, true).await.unwrap();
    assert_eq!(
        env.rosetta.status_or_panic().await.rosetta_blocks_mode,
        RosettaBlocksMode::Enabled {
            first_rosetta_block_index
        }
    );

    // Check that once rosetta blocks mode is enabled then
    // it will be enabled every time Rosetta restarts even
    // without passing --enable-rosetta-blocks
    env.restart_rosetta_node(false, true).await.unwrap();
    assert_eq!(
        env.rosetta.status_or_panic().await.rosetta_blocks_mode,
        RosettaBlocksMode::Enabled {
            first_rosetta_block_index
        }
    );
}

// a simple trait to simplify unwrapping and decoding Vec<u8>
trait UnwrapCandid {
    fn unwrap(&self) -> &[u8];
    fn unwrap_as<T: CandidType + for<'a> Deserialize<'a>>(&self) -> T {
        Decode!(self.unwrap(), T).expect("Unable to decode")
    }
}

impl UnwrapCandid for Vec<u8> {
    fn unwrap(&self) -> &[u8] {
        self.as_slice()
    }
}

#[tokio::test]
async fn test_rosetta_blocks_enabled_after_first_block() {
    let mut env = TestEnv::setup(false, true).await.unwrap();
    env.restart_rosetta_node(true, true).await.unwrap();
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
        // create block 2 which will go inside Rosetta Block 2
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

    let system_time: SystemTime = env.pocket_ic.get_time().await.try_into().unwrap();
    let rosetta_block1_expected_time_ts = TimeStamp::from(system_time);
    let rosetta_block1_expected_time_millis =
        rosetta_block1_expected_time_ts.as_nanos_since_unix_epoch() / 1_000_000;

    env.pocket_ic.auto_progress().await;

    let old_block0 = env
        .rosetta
        .block(PartialBlockIdentifier {
            index: Some(0),
            hash: None,
        })
        .await
        .unwrap()
        .block
        .unwrap();
    env.rosetta.wait_until_synced_up_to(1).await.unwrap();
    // Enabling Rosetta Blocks Mode should not change blocks before
    // the first rosetta index, in this case block 0
    let block0 = env
        .rosetta
        .block(PartialBlockIdentifier {
            index: Some(0),
            hash: None,
        })
        .await
        .unwrap()
        .block
        .unwrap();
    assert_eq!(old_block0, block0);

    // Block 1 must be a Rosetta block with 2 transactions
    let block1_hash = env
        .rosetta
        .block(PartialBlockIdentifier {
            index: Some(1),
            hash: None,
        })
        .await
        .unwrap()
        .block
        .unwrap()
        .block_identifier
        .hash;
    for (index, hash) in [(Some(1), None), (Some(1), Some(block1_hash.clone()))] {
        let block1 = env
            .rosetta
            .block(PartialBlockIdentifier { index, hash })
            .await
            .unwrap()
            .block
            .unwrap();
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
    let env = TestEnv::setup(true, true).await.unwrap();

    // Rosetta block 0 contains transaction 0
    env.pocket_ic.stop_progress().await;

    // Create block 1 and Rosetta Block 1
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
        // Create block 2 with the same transaction as block 1.
        // This must create a new Rosetta Block at index 2
        TransferArg {
            from_subaccount: None,
            to: Account::from(Principal::anonymous()),
            fee: None,
            created_at_time: None,
            memo: None,
            amount: Nat::from(1u64),
        },
        // Create block 3 with a different transaction than the one in block 2.
        // block 3 will therefore go inside Rosetta Block 2
        TransferArg {
            from_subaccount: None,
            to: Account::from(Principal::anonymous()),
            fee: None,
            created_at_time: None,
            memo: None,
            amount: Nat::from(2u64),
        },
        // Create block 4 with the same transaction as block 2.
        // This must create a new Rosetta Block at index 3
        TransferArg {
            from_subaccount: None,
            to: Account::from(Principal::anonymous()),
            fee: None,
            created_at_time: None,
            memo: None,
            amount: Nat::from(1u64),
        },
    ])
    .await;

    let system_time: SystemTime = env.pocket_ic.get_time().await.try_into().unwrap();
    let rosetta_block1_expected_time_ts = TimeStamp::from(system_time);
    let rosetta_block1_expected_time_millis =
        rosetta_block1_expected_time_ts.as_nanos_since_unix_epoch() / 1_000_000;

    env.pocket_ic.auto_progress().await;

    env.rosetta.wait_until_synced_up_to(3).await.unwrap();

    // check block 1
    let block0 = env
        .rosetta
        .block(PartialBlockIdentifier {
            index: Some(0),
            hash: None,
        })
        .await
        .unwrap()
        .block
        .unwrap();
    let block1 = env
        .rosetta
        .block(PartialBlockIdentifier {
            index: Some(1),
            hash: None,
        })
        .await
        .unwrap()
        .block
        .unwrap();
    assert_eq!(block1.block_identifier.index, 1);
    assert_eq!(block1.parent_block_identifier, block0.block_identifier);
    assert_eq!(block1.timestamp, rosetta_block1_expected_time_millis);
    assert_eq!(block1.metadata, None);
    assert_eq!(
        block1.transactions,
        vec![
            convert::to_rosetta_core_transaction(
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
            .unwrap()
        ]
    );

    // check block 2
    let block2 = env
        .rosetta
        .block(PartialBlockIdentifier {
            index: Some(2),
            hash: None,
        })
        .await
        .unwrap()
        .block
        .unwrap();
    assert_eq!(block2.block_identifier.index, 2);
    assert_eq!(block2.parent_block_identifier, block1.block_identifier);
    assert_eq!(block2.timestamp, rosetta_block1_expected_time_millis);
    assert_eq!(block2.metadata, None);
    assert_eq!(
        block2.transactions,
        vec![
            convert::to_rosetta_core_transaction(
                /* block_index: */ 2,
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
            convert::to_rosetta_core_transaction(
                /* block_index: */ 3,
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
            .unwrap()
        ]
    );

    // check block 3
    let block3 = env
        .rosetta
        .block(PartialBlockIdentifier {
            index: Some(3),
            hash: None,
        })
        .await
        .unwrap()
        .block
        .unwrap();
    assert_eq!(block3.block_identifier.index, 3);
    assert_eq!(block3.parent_block_identifier, block2.block_identifier);
    assert_eq!(block3.timestamp, rosetta_block1_expected_time_millis);
    assert_eq!(block3.metadata, None);
    assert_eq!(
        block3.transactions,
        vec![
            convert::to_rosetta_core_transaction(
                /* block_index: */ 4,
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
            .unwrap()
        ]
    );
}

#[tokio::test]
async fn test_query_block_range() {
    let env = TestEnv::setup(false, true).await.unwrap();

    let minter = test_identity()
        .sender()
        .expect("test identity sender not found!");
    let mut block_indices: Vec<Nat> = vec![];
    for i in 0..100u64 {
        let mint_arg = TransferArg {
            from_subaccount: None,
            to: Account::from(Principal::anonymous()),
            fee: None,
            created_at_time: None,
            memo: None,
            amount: Nat::from(i),
        };
        let arg = Encode!(&mint_arg).unwrap();
        block_indices.push(
            env.pocket_ic
                .update_call(env.ledger_id, minter, "icrc1_transfer", arg)
                .await
                .expect("Unable to submit call")
                .unwrap_as::<Result<BlockIndex, TransferError>>()
                .expect("Error performing icrc1_transfer"),
        );
    }

    env.rosetta
        .wait_until_synced_up_to(block_indices.last().unwrap().0.to_u64().unwrap())
        .await
        .unwrap();

    let response: QueryBlockRangeResponse = env
        .rosetta
        .call_or_panic(
            "query_block_range".to_owned(),
            ObjectMap::try_from(QueryBlockRangeRequest {
                highest_block_index: 100,
                number_of_blocks: 10,
            })
            .unwrap(),
        )
        .await
        .result
        .try_into()
        .unwrap();

    assert_eq!(response.blocks.len(), 10);
}

#[tokio::test]
async fn test_block_transaction() {
    let env = TestEnv::setup(true, true).await.unwrap();
    env.pocket_ic.stop_progress().await;
    assert!(
        env.rosetta
            .block_transaction(
                BlockIdentifier {
                    index: 100,
                    hash: "INVALID_HASH".to_owned()
                },
                TransactionIdentifier {
                    hash: "INVALID_TX_HASH".to_owned()
                }
            )
            .await
            .unwrap_err()
            .0
            .message
            .contains("Block not found")
    );

    // We are creating a second rosetta block that contains 4 transactions with each having a unique tx hash
    env.icrc1_transfers(vec![
        TransferArg {
            from_subaccount: None,
            to: Account::from(Principal::anonymous()),
            fee: None,
            created_at_time: None,
            memo: Some(1.into()),
            amount: Nat::from(1u64),
        },
        TransferArg {
            from_subaccount: None,
            to: Account::from(Principal::anonymous()),
            fee: None,
            created_at_time: None,
            memo: Some(2.into()),
            amount: Nat::from(1u64),
        },
        TransferArg {
            from_subaccount: None,
            to: Account::from(Principal::anonymous()),
            fee: None,
            created_at_time: None,
            memo: Some(3.into()),
            amount: Nat::from(2u64),
        },
        TransferArg {
            from_subaccount: None,
            to: Account::from(Principal::anonymous()),
            memo: Some(4.into()),
            created_at_time: None,
            fee: None,
            amount: Nat::from(1u64),
        },
    ])
    .await;
    env.pocket_ic.auto_progress().await;
    // All the previous transactions are stored in a single rosetta block so we wait until rosetta block 1 is finished
    env.rosetta.wait_until_synced_up_to(1).await.unwrap();

    // We try to fetch the RosettaBlock we just created earlier
    let rosetta_core::objects::Block {
        block_identifier,
        transactions,
        ..
    } = env
        .rosetta
        .block(PartialBlockIdentifier {
            index: Some(1),
            hash: None,
        })
        .await
        .unwrap()
        .block
        .unwrap();

    let transaction = env
        .rosetta
        .block_transaction(
            block_identifier.clone(),
            transactions[0].transaction_identifier.clone(),
        )
        .await
        .unwrap()
        .transaction;
    assert!(transaction == transactions[0]);

    let transaction = env
        .rosetta
        .block_transaction(
            block_identifier.clone(),
            transactions[1].transaction_identifier.clone(),
        )
        .await
        .unwrap()
        .transaction;
    assert!(transaction == transactions[1]);

    assert!(
        env.rosetta
            .block_transaction(
                block_identifier,
                TransactionIdentifier {
                    hash: "INVALID_TX_HASH".to_owned()
                }
            )
            .await
            .unwrap_err()
            .0
            .message
            .contains("Invalid transaction id")
    );
}

#[tokio::test]
async fn test_network_status_multiple_genesis_transactions() {
    // We start off by testing the case with no rosetta blocks enabled
    let mut env = TestEnv::setup(false, true).await.unwrap();
    let network_status = env.rosetta.network_status().await.unwrap();
    let genesis_block = env
        .rosetta
        .block(PartialBlockIdentifier {
            index: Some(0),
            hash: None,
        })
        .await
        .unwrap()
        .block
        .unwrap();

    // We expect the genesis block to be present and be in the network status
    assert_eq!(
        network_status.current_block_identifier,
        genesis_block.block_identifier
    );
    assert_eq!(
        network_status.current_block_timestamp,
        genesis_block.timestamp
    );
    assert_eq!(
        network_status.genesis_block_identifier,
        genesis_block.block_identifier
    );
    // If only the genesis block exists than the oldest block identifier is expected to be None
    assert_eq!(network_status.oldest_block_identifier, None);

    // Now we restart rosetta with rosetta blocks enabled
    // We need to restart it into memory or otherwise we will trigger the rosetta block mode detection from earlier restarts
    env.restart_rosetta_node(true, false).await.unwrap();
    let network_status = env.rosetta.network_status().await.unwrap();
    // There are no rosettablocks created yet so we return an empty blockchain error
    let current_block = env
        .rosetta
        .block(PartialBlockIdentifier {
            index: Some(0),
            hash: None,
        })
        .await
        .unwrap()
        .block
        .unwrap();
    let genesis_block = env
        .rosetta
        .block(PartialBlockIdentifier {
            index: Some(0),
            hash: None,
        })
        .await
        .unwrap()
        .block
        .unwrap();
    assert_eq!(
        network_status.current_block_identifier,
        current_block.block_identifier
    );
    assert_eq!(
        network_status.current_block_timestamp,
        current_block.timestamp
    );
    assert_eq!(
        network_status.genesis_block_identifier,
        genesis_block.block_identifier
    );
    // If only the genesis block exists than the oldest block identifier is expected to be None
    assert_eq!(network_status.oldest_block_identifier, None);

    // Now we test the case where we have produced some blocks
    env.restart_rosetta_node(false, false).await.unwrap();
    // After this call we should have 4 icp blocks, genesis and three transfers. The maximum block idx should be 3
    env.pocket_ic.stop_progress().await;
    env.icrc1_transfers(vec![
        TransferArg {
            from_subaccount: None,
            to: Account::from(Principal::anonymous()),
            fee: None,
            created_at_time: None,
            memo: None,
            amount: Nat::from(1u64),
        },
        TransferArg {
            from_subaccount: None,
            to: Account::from(Principal::anonymous()),
            fee: None,
            created_at_time: None,
            memo: None,
            amount: Nat::from(2u64),
        },
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
    env.pocket_ic.auto_progress().await;
    env.rosetta.wait_until_synced_up_to(3).await.unwrap();

    let network_status = env.rosetta.network_status().await.unwrap();
    let genesis_block = env
        .rosetta
        .block(PartialBlockIdentifier {
            index: Some(0),
            hash: None,
        })
        .await
        .unwrap()
        .block
        .unwrap();
    let current_block = env
        .rosetta
        .block(PartialBlockIdentifier {
            index: Some(3),
            hash: None,
        })
        .await
        .unwrap()
        .block
        .unwrap();
    assert_eq!(
        network_status.current_block_identifier,
        current_block.block_identifier
    );
    assert_eq!(
        network_status.current_block_timestamp,
        current_block.timestamp
    );
    assert_eq!(
        network_status.genesis_block_identifier,
        genesis_block.block_identifier.clone()
    );
    // Genesis block is verified so there is no need for the oldest block identifier
    assert_eq!(network_status.oldest_block_identifier, None);

    // If we restart rosetta now we have 3 icp blocks to sync out of which the first two will go into the rosetta block
    env.restart_rosetta_node(true, false).await.unwrap();
    // Now we have 3 rosetta blocks, the genesis block and the first transfer go into rosetta block 0, the second and third transfer each go into a separate rosetta block. The maximum block idx is thus 2
    env.rosetta.wait_until_synced_up_to(2).await.unwrap();
    let network_status = env.rosetta.network_status().await.unwrap();
    let current_block = env
        .rosetta
        .block(PartialBlockIdentifier {
            index: Some(2),
            hash: None,
        })
        .await
        .unwrap()
        .block
        .unwrap();
    let genesis_block = env
        .rosetta
        .block(PartialBlockIdentifier {
            index: Some(0),
            hash: None,
        })
        .await
        .unwrap()
        .block
        .unwrap();
    assert_eq!(
        network_status.current_block_identifier,
        current_block.block_identifier
    );
    assert_eq!(
        network_status.current_block_timestamp,
        current_block.timestamp
    );
    assert_eq!(
        network_status.genesis_block_identifier,
        genesis_block.block_identifier
    );
    assert_eq!(network_status.oldest_block_identifier, None);
    // We should not be able to call block with block index 3 at this point
    assert!(
        env.rosetta
            .block(PartialBlockIdentifier {
                index: Some(3),
                hash: None,
            })
            .await
            .unwrap_err()
            .0
            .message
            .contains("Block not found")
    );
}

#[tokio::test]
async fn test_network_status_single_genesis_transaction() {
    let mut env = TestEnv::setup(false, true).await.unwrap();
    let t1 = env.pocket_ic.get_time().await;
    // We need to advance the time to make sure only a single transaction gets into the genesis block
    sleep(Duration::from_secs(1)).await;
    let t2 = env.pocket_ic.get_time().await;
    assert!(t1 < t2);
    env.pocket_ic.stop_progress().await;
    // We want two transactions with unique tx hashes
    env.icrc1_transfers(vec![
        TransferArg {
            from_subaccount: None,
            to: Account::from(Principal::anonymous()),
            fee: None,
            created_at_time: None,
            memo: Some(1.into()),
            amount: Nat::from(1u64),
        },
        TransferArg {
            from_subaccount: None,
            to: Account::from(Principal::anonymous()),
            fee: None,
            created_at_time: None,
            memo: Some(2.into()),
            amount: Nat::from(2u64),
        },
    ])
    .await;
    env.pocket_ic.auto_progress().await;
    // We should have 3 ICP blocks by now
    env.rosetta.wait_until_synced_up_to(2).await.unwrap();
    let genesis_block = env
        .rosetta
        .block(PartialBlockIdentifier {
            index: Some(0),
            hash: None,
        })
        .await
        .unwrap()
        .block
        .unwrap();
    let current_block = env
        .rosetta
        .block(PartialBlockIdentifier {
            index: Some(2),
            hash: None,
        })
        .await
        .unwrap()
        .block
        .unwrap();
    let network_status = env.rosetta.network_status().await.unwrap();
    assert_eq!(
        network_status.current_block_identifier,
        current_block.block_identifier
    );
    assert_eq!(
        network_status.current_block_timestamp,
        current_block.timestamp
    );
    assert_eq!(
        network_status.genesis_block_identifier,
        genesis_block.block_identifier
    );

    // Now we restart rosetta with rosetta blocks
    env.restart_rosetta_node(true, false).await.unwrap();
    // We should now have 2 Rosetta blocks, genesis block with a single transaction and a second rosetta block with two transfers
    env.rosetta.wait_until_synced_up_to(1).await.unwrap();

    // The genesis block stays the same but the current block changes
    let current_block = env
        .rosetta
        .block(PartialBlockIdentifier {
            index: Some(1),
            hash: None,
        })
        .await
        .unwrap()
        .block
        .unwrap();

    // Even though both the ICP genesis block and the Rosetta Block genesis block have only one transaction in them they have different hashes. One hashes a single transaction the other an array that contains a single transaction
    let genesis_block = env
        .rosetta
        .block(PartialBlockIdentifier {
            index: Some(0),
            hash: None,
        })
        .await
        .unwrap()
        .block
        .unwrap();
    let network_status = env.rosetta.network_status().await.unwrap();
    assert_eq!(
        network_status.current_block_identifier,
        current_block.block_identifier
    );
    assert_eq!(
        network_status.current_block_timestamp,
        current_block.timestamp
    );

    assert_eq!(
        network_status.genesis_block_identifier,
        genesis_block.block_identifier
    );
}

#[test]
fn test_mainnet_and_env_flag_set_returns_error() {
    let output = Command::new(get_rosetta_path())
        .args(["--environment", "test", "--mainnet"])
        .output()
        .expect("Failed to execute binary");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Cannot specify both --mainnet and --environment flags"));
}
