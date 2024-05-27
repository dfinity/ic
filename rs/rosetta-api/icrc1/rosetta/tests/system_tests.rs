use crate::common::local_replica;
use crate::common::local_replica::{create_and_install_icrc_ledger, test_identity};
use crate::common::utils::{get_rosetta_blocks_from_icrc1_ledger, wait_for_rosetta_block};
use candid::Nat;
use candid::Principal;
use common::local_replica::get_custom_agent;
use ic_agent::identity::BasicIdentity;
use ic_agent::Identity;
use ic_base_types::CanisterId;
use ic_base_types::PrincipalId;
use ic_icrc1_ledger::{InitArgs, InitArgsBuilder};
use ic_icrc1_test_utils::{
    minter_identity, valid_transactions_strategy, ArgWithCaller, LedgerEndpointArg,
    DEFAULT_TRANSFER_FEE,
};
use ic_icrc1_tokens_u256::U256;
use ic_icrc_rosetta::common::constants::STATUS_COMPLETED;
use ic_icrc_rosetta::common::types::Error;
use ic_icrc_rosetta::common::types::OperationType;
use ic_icrc_rosetta::common::utils::utils::icrc1_rosetta_block_to_rosetta_core_transaction;
use ic_icrc_rosetta::common::utils::utils::{
    icrc1_operation_to_rosetta_core_operations, icrc1_rosetta_block_to_rosetta_core_block,
};
use ic_icrc_rosetta::construction_api::types::ConstructionMetadataRequestOptions;
use ic_icrc_rosetta_client::RosettaClient;
use ic_icrc_rosetta_runner::RosettaClientArgsBuilder;
use ic_icrc_rosetta_runner::{make_transaction_with_rosetta_client_binary, DEFAULT_TOKEN_SYMBOL};
use ic_icrc_rosetta_runner::{
    start_rosetta, RosettaContext, RosettaOptions, DEFAULT_DECIMAL_PLACES,
};
use ic_rosetta_api::DEFAULT_BLOCKCHAIN;
use icrc_ledger_agent::CallMode;
use icrc_ledger_agent::Icrc1Agent;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::TransferArg;
use icrc_ledger_types::icrc2::approve::ApproveArgs;
use lazy_static::lazy_static;
use num_traits::cast::ToPrimitive;
use pocket_ic::{PocketIc, PocketIcBuilder};
use proptest::prelude::ProptestConfig;
use proptest::proptest;
use proptest::strategy::Strategy;
use proptest::test_runner::Config as TestRunnerConfig;
use proptest::test_runner::TestRunner;
use rosetta_core::identifiers::*;
use rosetta_core::miscellaneous::OperationStatus;
pub use rosetta_core::models::Ed25519KeyPair as EdKeypair;
use rosetta_core::models::RosettaSupportedKeyPair;
use rosetta_core::objects::*;
use rosetta_core::request_types::*;
use rosetta_core::response_types::BlockResponse;
use rosetta_core::response_types::ConstructionPreprocessResponse;
use std::collections::HashMap;
use std::collections::HashSet;
use std::time::Instant;
use std::{
    path::PathBuf,
    process::Command,
    sync::Arc,
    time::{Duration, SystemTime},
};
use strum::IntoEnumIterator;
use tokio::runtime::Runtime;

pub mod common;

lazy_static! {
    pub static ref TEST_ACCOUNT: Account = test_identity().sender().unwrap().into();
    pub static ref MAX_NUM_GENERATED_BLOCKS: usize = 20;
    pub static ref MAX_BLOCKS_PER_REQUEST: usize = 2000;
    pub static ref NUM_TEST_CASES: u32 = 1;
    pub static ref MINTING_IDENTITY: Arc<BasicIdentity> = Arc::new(minter_identity());
}

fn path_from_env(var: &str) -> PathBuf {
    std::fs::canonicalize(
        std::env::var(var).unwrap_or_else(|_| panic!("Environment variable {} is not set", var)),
    )
    .unwrap()
}

fn rosetta_bin() -> PathBuf {
    path_from_env("ROSETTA_BIN_PATH")
}

fn rosetta_client_bin() -> PathBuf {
    path_from_env("ROSETTA_CLIENT_BIN_PATH")
}

fn rosetta_cli() -> String {
    match std::env::var("ROSETTA_CLI").ok() {
        Some(binary) => binary,
        None => String::from("rosetta-cli"),
    }
}

fn local(file: &str) -> String {
    match std::env::var("CARGO_MANIFEST_DIR") {
        Ok(path) => std::path::PathBuf::from(path)
            .join(file)
            .into_os_string()
            .into_string()
            .unwrap(),
        Err(_) => String::from(file),
    }
}

struct Setup {
    minting_account: Account,
    pocket_ic: PocketIc,
    port: u16,
    icrc1_ledger_canister_id: Principal,
    icrc1_ledger_canister_init_args: InitArgs,
}

impl Setup {
    fn builder() -> SetupBuilder {
        SetupBuilder {
            icrc1_ledger_init_args_builder: None,
        }
    }
}

impl Drop for Setup {
    fn drop(&mut self) {
        self.pocket_ic.stop_live();
    }
}

struct SetupBuilder {
    icrc1_ledger_init_args_builder: Option<InitArgsBuilder>,
}

impl SetupBuilder {
    fn with_initial_balance(mut self, account: impl Into<Account>, amount: impl Into<Nat>) -> Self {
        self.icrc1_ledger_init_args_builder = Some(
            self.icrc1_ledger_init_args_builder
                .unwrap_or_else(local_replica::icrc_ledger_default_args_builder)
                .with_initial_balance(account, amount),
        );
        self
    }

    fn build(self) -> Setup {
        let minting_account = Account::from(MINTING_IDENTITY.sender().unwrap());
        let mut pocket_ic = PocketIcBuilder::new()
            .with_nns_subnet()
            .with_sns_subnet()
            .build();

        let init_args = self
            .icrc1_ledger_init_args_builder
            .unwrap_or(local_replica::icrc_ledger_default_args_builder())
            .with_minting_account(minting_account)
            .build();
        let canister_id = create_and_install_icrc_ledger(&pocket_ic, init_args.clone());

        let subnet_id = pocket_ic.get_subnet(canister_id).unwrap();
        println!(
            "Installed the ICRC1 ledger canister ({}) onto {:?}",
            canister_id, subnet_id
        );
        let sns_subnet_id = pocket_ic.topology().get_sns().unwrap();
        assert_eq!(
            subnet_id, sns_subnet_id,
            "The canister subnet {} does not match the SNS subnet {}",
            subnet_id, sns_subnet_id
        );

        let endpoint = pocket_ic.make_live(None);
        let port = endpoint.port().unwrap();
        Setup {
            minting_account,
            pocket_ic,
            port,
            icrc1_ledger_canister_id: canister_id,
            icrc1_ledger_canister_init_args: init_args,
        }
    }
}

pub struct RosettaTestingEnvironment {
    // The '_' character is needed for the rosetta context to be allowed to never be used as it must not go out of scope and be killed.
    _rosetta_context: RosettaContext,
    rosetta_client: RosettaClient,
    icrc1_agent: Arc<Icrc1Agent>,
    icrc1_ledger_id: Principal,
    icrc1_ledger_init_args: InitArgs,
    network_identifier: NetworkIdentifier,
}

struct RosettaTestingEnvironmentBuilder {
    icrc1_ledger_canister_id: Principal,
    icrc1_ledger_init_args: InitArgs,
    transfer_args_for_block_generating: Option<Vec<ArgWithCaller>>,
    offline: bool,
    port: u16,
}

impl RosettaTestingEnvironmentBuilder {
    pub fn new(setup: &Setup) -> Self {
        Self {
            icrc1_ledger_canister_id: setup.icrc1_ledger_canister_id,
            icrc1_ledger_init_args: setup.icrc1_ledger_canister_init_args.clone(),
            transfer_args_for_block_generating: None,
            offline: false,
            port: setup.port,
        }
    }

    pub fn with_args_with_caller(mut self, transfer_args: Vec<ArgWithCaller>) -> Self {
        self.transfer_args_for_block_generating = Some(transfer_args);
        self
    }

    pub fn with_offline_rosetta(mut self, offline: bool) -> Self {
        self.offline = offline;
        self
    }

    pub async fn build(&self) -> RosettaTestingEnvironment {
        let mut block_idxes = vec![];

        if let Some(args) = &self.transfer_args_for_block_generating {
            for ArgWithCaller {
                caller,
                arg,
                principal_to_basic_identity: _,
            } in args.clone().into_iter()
            {
                let caller_agent = Icrc1Agent {
                    agent: get_custom_agent(caller.clone(), self.port).await,
                    ledger_canister_id: self.icrc1_ledger_canister_id,
                };
                block_idxes.push(match arg {
                    LedgerEndpointArg::ApproveArg(approve_arg) => caller_agent
                        .approve(approve_arg.clone())
                        .await
                        .unwrap()
                        .unwrap()
                        .0
                        .to_u64()
                        .unwrap(),
                    LedgerEndpointArg::TransferArg(transfer_arg) => caller_agent
                        .transfer(transfer_arg.clone())
                        .await
                        .unwrap()
                        .unwrap()
                        .0
                        .to_u64()
                        .unwrap(),
                });
            }
        }
        // Create a testing agent
        let icrc1_agent = Arc::new(Icrc1Agent {
            agent: local_replica::get_testing_agent(self.port).await,
            ledger_canister_id: self.icrc1_ledger_canister_id,
        });
        let replica_url = format!("http://localhost:{}", self.port);
        let rosetta_context = start_rosetta(
            &rosetta_bin(),
            RosettaOptions {
                ledger_id: self.icrc1_ledger_canister_id,
                network_url: Some(replica_url),
                offline: self.offline,
                ..RosettaOptions::default()
            },
        )
        .await;
        let rosetta_client =
            RosettaClient::from_str_url(&format!("http://0.0.0.0:{}", rosetta_context.port))
                .expect("Unable to parse url");

        let network_identifier = NetworkIdentifier::new(
            DEFAULT_BLOCKCHAIN.to_owned(),
            CanisterId::try_from(PrincipalId(self.icrc1_ledger_canister_id))
                .unwrap()
                .to_string(),
        );

        // Wait for rosetta to catch up with the ledger
        if let Some(last_block_idx) = block_idxes.last() {
            let rosetta_last_block_idx = wait_for_rosetta_block(
                &rosetta_client,
                network_identifier.clone(),
                *last_block_idx,
            )
            .await;
            assert_eq!(
                Some(*last_block_idx),
                rosetta_last_block_idx,
                "Wait for rosetta sync failed."
            );
        }

        RosettaTestingEnvironment {
            _rosetta_context: rosetta_context,
            rosetta_client,
            icrc1_agent,
            icrc1_ledger_id: self.icrc1_ledger_canister_id,
            icrc1_ledger_init_args: self.icrc1_ledger_init_args.clone(),
            network_identifier,
        }
    }
}

async fn assert_rosetta_balance(
    account: Account,
    block_index: u64,
    balance: u64,
    rosetta_client: &RosettaClient,
    network_identifier: NetworkIdentifier,
) {
    println!(
        "Checking balance for account: {:?} at block index {}",
        account, block_index
    );
    let start = Instant::now();
    let timeout = Duration::from_secs(30);
    loop {
        let latest_rosetta_block =
            wait_for_rosetta_block(rosetta_client, network_identifier.clone(), block_index)
                .await
                .expect("Unable to call wait_for_rosetta_block");
        if latest_rosetta_block >= block_index {
            break;
        } else {
            println!(
                "Waited for rosetta, received block index {} but expected {}, waiting some more...",
                latest_rosetta_block, block_index
            );
        }
        if start.elapsed() > timeout {
            panic!(
                "Failed to get block index {} within {:?}",
                block_index, timeout
            );
        }
    }
    let rosetta_balance = rosetta_client
        .account_balance(block_index, account.into(), network_identifier.clone())
        .await
        .expect("Unable to call account_balance")
        .balances
        .first()
        .unwrap()
        .clone()
        .value;
    assert_eq!(rosetta_balance, balance.to_string());
}

#[test]
fn test_network_list() {
    let rt = Runtime::new().unwrap();
    let setup = Setup::builder().build();

    rt.block_on(async {
        let env = RosettaTestingEnvironmentBuilder::new(&setup)
            .with_offline_rosetta(true)
            .build()
            .await;
        let network_list = env
            .rosetta_client
            .network_list()
            .await
            .expect("Unable to call network_list")
            .network_identifiers;
        let expected = NetworkIdentifier::new(
            DEFAULT_BLOCKCHAIN.to_owned(),
            env.icrc1_ledger_id.to_string(),
        );
        assert_eq!(network_list, vec![expected]);
    });
}

#[test]
fn test_network_options() {
    let rt = Runtime::new().unwrap();
    let setup = Setup::builder().build();

    rt.block_on(async {
        let env = RosettaTestingEnvironmentBuilder::new(&setup)
            .with_offline_rosetta(true)
            .build()
            .await;
        let network_options = env
            .rosetta_client
            .network_options(env.network_identifier.clone())
            .await
            .expect("Unable to call network_options");

        assert_eq!(
            network_options.allow.operation_statuses,
            vec![OperationStatus::new("COMPLETED".to_string(), true)]
        );
        assert_eq!(
            network_options.allow.operation_types,
            OperationType::iter()
                .map(|op| op.to_string())
                .collect::<Vec<String>>()
        );
        assert_eq!(network_options.allow.errors.len(), 13);
        assert!(network_options.allow.historical_balance_lookup);
    });
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(*NUM_TEST_CASES))]
    #[test]
fn test_network_status(args_with_caller in valid_transactions_strategy(
        (*MINTING_IDENTITY).clone(),
        DEFAULT_TRANSFER_FEE,
        *MAX_NUM_GENERATED_BLOCKS,
        SystemTime::now(),
    )) {
    // Create a tokio environment to conduct async calls
    let rt = Runtime::new().unwrap();
    let setup = Setup::builder().build();

    // Wrap async calls in a blocking Block
    rt.block_on(async {
        let env = RosettaTestingEnvironmentBuilder::new(&setup)
            .with_args_with_caller(args_with_caller.clone())
            .build()
            .await;
        wait_for_rosetta_block(&env.rosetta_client, env.network_identifier.clone(), 0).await;

        // Get the blocks from the ledger to compare against rosetta
        let rosetta_blocks = get_rosetta_blocks_from_icrc1_ledger(env.icrc1_agent,0,*MAX_BLOCKS_PER_REQUEST).await;

        if !args_with_caller.is_empty(){
        assert!(
            !rosetta_blocks.is_empty(),
            "there should be blocks in the ledger"
        );

        let rosetta_response = env.rosetta_client
            .network_status(env.network_identifier.clone())
            .await
            .expect("Unable to call network_status");

        assert_eq!(
            rosetta_blocks.last().unwrap().index,
            rosetta_response.current_block_identifier.index,
            "Chain length does not match"
        );
        assert_eq!(
            rosetta_response.current_block_identifier.index, args_with_caller.len() as u64,
            "current_block_identifier index should be args_with_caller.len()"
        );

        assert_eq!(
            hex::encode(rosetta_blocks.first().unwrap().clone().get_block_hash().clone()),
            rosetta_response.genesis_block_identifier.hash,
            "Genesis block hashes do not match"
        );
        assert_eq!(
            hex::encode(rosetta_blocks.last().unwrap().clone().get_block_hash().clone()),
            rosetta_response.current_block_identifier.hash,
            "Current block hashes do not match"
        );
        assert_eq!(
            hex::encode(rosetta_blocks.first().unwrap().clone().get_block_hash().clone()),
            rosetta_response.oldest_block_identifier.unwrap().hash,
            "Genesis block hashes do not match"
        );
        assert_eq!(
            Duration::from_nanos(rosetta_blocks.last().unwrap().get_timestamp()).as_millis() as u64,
            rosetta_response.current_block_timestamp
        );
    }
    });

}

}
proptest! {
    #![proptest_config(ProptestConfig::with_cases(*NUM_TEST_CASES))]
    #[test]
    fn test_blocks(args_with_caller in valid_transactions_strategy(
        (*MINTING_IDENTITY).clone(),
        DEFAULT_TRANSFER_FEE,
        *MAX_NUM_GENERATED_BLOCKS,
        SystemTime::now(),
    )) {
    // Create a tokio environment to conduct async calls
    let rt = Runtime::new().unwrap();
    let setup = Setup::builder().build();

    // Wrap async calls in a blocking Block
     rt.block_on(async {
        let env = RosettaTestingEnvironmentBuilder::new(&setup)
            .with_args_with_caller(args_with_caller.clone())
            .build()
            .await;
        wait_for_rosetta_block(&env.rosetta_client, env.network_identifier.clone(), 0).await;

        if !args_with_caller.is_empty(){

    for block in get_rosetta_blocks_from_icrc1_ledger(env.icrc1_agent,0,*MAX_BLOCKS_PER_REQUEST).await.into_iter(){
        let mut expected_block_response = BlockResponse::new(
            Some(
                icrc1_rosetta_block_to_rosetta_core_block(block.clone(), Currency {
                    symbol: env.icrc1_ledger_init_args.token_symbol.clone(),
                    decimals: env.icrc1_ledger_init_args
                    .decimals
                    .unwrap_or(DEFAULT_DECIMAL_PLACES) as u32,
                    ..Default::default()
                }).unwrap(),
            ));
            expected_block_response.block.iter_mut().for_each(|block| block.transactions.iter_mut().for_each(|tx| {
                tx.operations.iter_mut().for_each(|op| {
                    op.status = Some(STATUS_COMPLETED.to_string());
                })
            }));

        assert_eq!(hex::encode(block.clone().get_block_hash().clone()),expected_block_response.clone().block.unwrap().block_identifier.hash);
                // Rosetta should be able to handle blockidentifieres with both the hash and the block index set
        let actual_block_response = env.rosetta_client.block(env.network_identifier.clone(), PartialBlockIdentifier{
            hash:Some(hex::encode(block.clone().get_block_hash().clone())),
            index:Some(block.index)
        })
        .await
        .expect("Failed to find block in Rosetta");
        assert_eq!(expected_block_response,actual_block_response);

        // Rosetta should be able to handle blockidentifieres with only the hash set
        let actual_block_response = env.rosetta_client.block(env.network_identifier.clone(), PartialBlockIdentifier{
            hash:Some(hex::encode(block.clone().get_block_hash())),
            index:None
        })
        .await
        .expect("Failed to find block in Rosetta");
        assert_eq!(expected_block_response,actual_block_response);

        // Rosetta should be able to handle blockidentifieres with only the index set
        let actual_block_response = env.rosetta_client.block(env.network_identifier.clone(), PartialBlockIdentifier{
            hash:None,
            index:Some(block.index)
        })
        .await
        .expect("Failed to find block in Rosetta");
        assert_eq!(expected_block_response,actual_block_response);
    }}

    // If no hash or index was provided rosetta should return the last block
    let last_block = env.rosetta_client.block(env.network_identifier.clone(), PartialBlockIdentifier{
        hash:None,
        index:None
    }).await.expect("failed to get last block");
    assert_eq!(last_block.block.unwrap().block_identifier.index as usize, args_with_caller.len());
  });
 }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(*NUM_TEST_CASES))]
    #[test]
    fn test_block_transaction(args_with_caller in valid_transactions_strategy(
        (*MINTING_IDENTITY).clone(),
        DEFAULT_TRANSFER_FEE,
        *MAX_NUM_GENERATED_BLOCKS,
        SystemTime::now(),
    )) {
    // Create a tokio environment to conduct async calls
    let rt = Runtime::new().unwrap();
    let setup = Setup::builder().build();

    // Wrap async calls in a blocking Block
     rt.block_on(async {
        let env = RosettaTestingEnvironmentBuilder::new(&setup)
            .with_args_with_caller(args_with_caller.clone())
            .build()
            .await;
        wait_for_rosetta_block(&env.rosetta_client, env.network_identifier.clone(), 0).await;

        if !args_with_caller.is_empty(){

    for block in get_rosetta_blocks_from_icrc1_ledger(env.icrc1_agent,0,*MAX_BLOCKS_PER_REQUEST).await.into_iter() {
        let mut expected_block_transaction_response =   rosetta_core::response_types::BlockTransactionResponse {
            transaction: icrc1_rosetta_block_to_rosetta_core_transaction(block.clone(), Currency {
                symbol: env.icrc1_ledger_init_args.token_symbol.clone(),
                decimals: env.icrc1_ledger_init_args
                .decimals
                .unwrap_or(DEFAULT_DECIMAL_PLACES) as u32,
                ..Default::default()
            }).unwrap()};

            expected_block_transaction_response.transaction.operations.iter_mut().for_each(|op| {
                    op.status = Some(STATUS_COMPLETED.to_string());
                });

        assert_eq!(hex::encode(block.clone().get_transaction_hash().clone()),expected_block_transaction_response.clone().transaction.transaction_identifier.hash);

                // Rosetta should be able to handle blockidentifieres with both the hash and the block index set
        let actual_block_transaction_response = env.rosetta_client.block_transaction(env.network_identifier.clone(),
            BlockIdentifier {
                            index: block.index,
                            hash: hex::encode(block.clone().get_block_hash().clone()),

        }, TransactionIdentifier{ hash: hex::encode(block.clone().get_transaction_hash().clone()) })
        .await
        .expect("Failed to find block in Rosetta");
        assert_eq!(expected_block_transaction_response,actual_block_transaction_response);

        assert!(env.rosetta_client.block_transaction(env.network_identifier.clone(),
        BlockIdentifier {
                        index: u64::MAX,
                        hash: hex::encode(block.clone().get_block_hash().clone()),

    }, TransactionIdentifier{ hash: hex::encode(block.clone().get_transaction_hash().clone()) })
    .await.is_err());

    assert!(env.rosetta_client.block_transaction(env.network_identifier.clone(),
    BlockIdentifier {
                    index: block.index,
                    hash: hex::encode("wrong hash"),

    }, TransactionIdentifier{ hash: hex::encode(block.clone().get_transaction_hash()) })
    .await.is_err());

    assert!(env.rosetta_client.block_transaction(env.network_identifier.clone(),
        BlockIdentifier {
                        index: block.index,
                        hash: hex::encode(block.clone().get_block_hash()),

}, TransactionIdentifier{ hash: hex::encode("wrong tx hash") })
.await.is_err());
    }
}
 });
 }
}

#[test]
fn test_mempool() {
    let rt = Runtime::new().unwrap();
    let setup = Setup::builder().build();

    rt.block_on(async {
        let env = RosettaTestingEnvironmentBuilder::new(&setup).build().await;
        wait_for_rosetta_block(&env.rosetta_client, env.network_identifier.clone(), 0).await;

        let transaction_identifiers = env
            .rosetta_client
            .mempool(env.network_identifier.clone())
            .await
            .expect("Unable to call mempool")
            .transaction_identifiers;
        assert_eq!(transaction_identifiers, vec![]);

        let transaction_id = TransactionIdentifier {
            hash: "1234".to_string(),
        };
        let mempool_transaction_request =
            MempoolTransactionRequest::new(env.network_identifier, transaction_id);
        let response = env
            .rosetta_client
            .mempool_transaction(mempool_transaction_request)
            .await;
        let err = response.expect_err("expected an error");
        assert_eq!(err, Error::mempool_transaction_missing());
    });
}

#[test]
fn test_construction_preprocess() {
    let rt = Runtime::new().unwrap();
    let setup = Setup::builder().build();

    rt.block_on(async {
        let env = RosettaTestingEnvironmentBuilder::new(&setup).build().await;
        wait_for_rosetta_block(&env.rosetta_client, env.network_identifier.clone(), 0).await;

        let construction_preprocess_response = env
            .rosetta_client
            .construction_preprocess(vec![], env.network_identifier)
            .await
            .expect("Unable to call Construction Preprocess");
        let expected = ConstructionPreprocessResponse {
            options: Some(
                ConstructionMetadataRequestOptions {
                    suggested_fee: true,
                }
                .try_into()
                .unwrap(),
            ),
            required_public_keys: None,
        };
        assert_eq!(construction_preprocess_response, expected);
    });
}

#[test]
fn test_construction_derive() {
    let rt = Runtime::new().unwrap();
    let setup = Setup::builder().build();

    rt.block_on(async {
        let env = RosettaTestingEnvironmentBuilder::new(&setup).build().await;
        wait_for_rosetta_block(&env.rosetta_client, env.network_identifier.clone(), 0).await;

        let key_pair = EdKeypair::generate_from_u64(10);
        let principal_id = key_pair.generate_principal_id().unwrap();
        let public_key = ic_rosetta_test_utils::to_public_key(&key_pair);
        let account = Account {
            owner: principal_id.into(),
            subaccount: None,
        };

        let request = ConstructionDeriveRequest {
            network_identifier: env.network_identifier.clone(),
            public_key: public_key.clone(),
            metadata: None,
        };
        let account_identifier = env
            .rosetta_client
            .construction_derive(request.clone())
            .await
            .expect("Unable to call /construction/derive")
            .account_identifier
            .expect("/construction/derive did not return an account identifier");
        assert_eq!(account_identifier, account.into());
    });
}

#[test]
fn test_account_balance() {
    let mut runner = TestRunner::new(TestRunnerConfig {
        max_shrink_iters: 0,
        cases: *NUM_TEST_CASES,
        ..Default::default()
    });

    runner
        .run(
            &(valid_transactions_strategy(
                (*MINTING_IDENTITY).clone(),
                DEFAULT_TRANSFER_FEE,
                50,
                SystemTime::now(),
            )
            .no_shrink()),
            |args_with_caller| {
                let rt = Runtime::new().unwrap();
                let setup = Setup::builder().build();

                rt.block_on(async {
                    let env = RosettaTestingEnvironmentBuilder::new(&setup)
                        .with_args_with_caller(args_with_caller.clone())
                        .build()
                        .await;
                    wait_for_rosetta_block(&env.rosetta_client, env.network_identifier.clone(), 0)
                        .await;

                    // Keep track of the account balances
                    let mut accounts_balances: HashMap<Account, u64> = HashMap::new();

                    let current_index = env
                        .rosetta_client
                        .network_status(env.network_identifier.clone())
                        .await
                        .expect("Unable to call network_status")
                        .current_block_identifier
                        .index;

                    // We start at the block index before any transactions were created by the strategy
                    let mut block_start_index = current_index - args_with_caller.len() as u64 + 1;

                    let mut all_involved_accounts = HashSet::new();

                    for ArgWithCaller {
                        caller,
                        arg,
                        principal_to_basic_identity: _,
                    } in args_with_caller.iter()
                    {
                        let sender_principal = caller.sender().unwrap();
                        let mut involved_accounts = vec![];
                        match arg {
                            LedgerEndpointArg::ApproveArg(ApproveArgs {
                                from_subaccount,
                                spender,
                                ..
                            }) => {
                                let from = Account {
                                    owner: sender_principal,
                                    subaccount: *from_subaccount,
                                };

                                // We are not interested in collisions with the minting account
                                if from != setup.minting_account {
                                    accounts_balances.entry(from).and_modify(|balance| {
                                        *balance -= DEFAULT_TRANSFER_FEE;
                                    });
                                    involved_accounts.push(from);
                                }
                                if *spender != setup.minting_account {
                                    accounts_balances.entry(*spender).or_insert(0);
                                    involved_accounts.push(*spender);
                                }
                            }
                            LedgerEndpointArg::TransferArg(TransferArg {
                                from_subaccount,
                                to,
                                amount,
                                ..
                            }) => {
                                let from = Account {
                                    owner: sender_principal,
                                    subaccount: *from_subaccount,
                                };

                                // For Mint transactions we do not keep track of the balance of the minter
                                if from != setup.minting_account {
                                    accounts_balances.entry(from).and_modify(|balance| {
                                        *balance -= amount.0.to_u64().unwrap();
                                        // If the transfer is a burn no transfer fee should be deducted
                                        if *to != setup.minting_account {
                                            *balance -= DEFAULT_TRANSFER_FEE;
                                        }
                                    });
                                    involved_accounts.push(from);
                                }
                                if *to != setup.minting_account {
                                    accounts_balances
                                        .entry(*to)
                                        .and_modify(|balance| {
                                            *balance += amount.0.to_u64().unwrap();
                                        })
                                        .or_insert(amount.0.to_u64().unwrap());
                                    involved_accounts.push(*to);
                                }
                            }
                        };

                        for account in involved_accounts {
                            all_involved_accounts.insert(account);
                            assert_rosetta_balance(
                                account,
                                block_start_index,
                                *accounts_balances.get(&account).unwrap(),
                                &env.rosetta_client,
                                env.network_identifier.clone(),
                            )
                            .await;
                        }

                        block_start_index += 1;
                    }

                    // Assert that the current balance on the ledger is the same as that of icrc rosetta
                    for account in all_involved_accounts.into_iter() {
                        let ledger_balance = env
                            .icrc1_agent
                            .balance_of(account, icrc_ledger_agent::CallMode::Query)
                            .await
                            .unwrap()
                            .0
                            .to_u64()
                            .unwrap();
                        let current_block_index = env
                            .rosetta_client
                            .network_status(env.network_identifier.clone())
                            .await
                            .expect("Unable to call network_status")
                            .current_block_identifier
                            .index;
                        assert_rosetta_balance(
                            account,
                            current_block_index,
                            ledger_balance,
                            &env.rosetta_client,
                            env.network_identifier.clone(),
                        )
                        .await;
                    }
                });
                Ok(())
            },
        )
        .unwrap();
}

#[test]
fn test_continuous_block_sync() {
    let rt = Runtime::new().unwrap();
    let setup = Setup::builder().build();

    rt.block_on(async {
        let env = RosettaTestingEnvironmentBuilder::new(&setup).build().await;
        wait_for_rosetta_block(&env.rosetta_client, env.network_identifier.clone(), 0).await;

        // The empty test ledger has 1 block at index 0 - mint to the test identity.
        let mut last_block_idx_start = 0;

        let args = TransferArg {
            from_subaccount: None,
            to: *TEST_ACCOUNT,
            fee: Some(DEFAULT_TRANSFER_FEE.into()),
            amount: 1u64.into(),
            memo: None,
            created_at_time: None,
        };

        for blocks in 1..6 {
            for i in 0..blocks {
                let block_index = env
                    .icrc1_agent
                    .transfer(args.clone())
                    .await
                    .expect("sending transfer failed")
                    .expect("transfer resulted in an error");
                assert_eq!(block_index, last_block_idx_start + i + 1);
            }

            let last_block_idx = wait_for_rosetta_block(
                &env.rosetta_client,
                env.network_identifier.clone(),
                last_block_idx_start + blocks,
            )
            .await;

            assert_eq!(
                last_block_idx,
                Some(last_block_idx_start + blocks),
                "Rosetta did not sync the last block!"
            );

            last_block_idx_start = last_block_idx.expect("Last block not found");
        }
    });
}

#[test]
fn test_construction_submit() {
    let mut runner = TestRunner::new(TestRunnerConfig {
        max_shrink_iters: 0,
        cases: *NUM_TEST_CASES,
        ..Default::default()
    });

    runner
        .run(
            &(valid_transactions_strategy(
                MINTING_IDENTITY.clone(),
                DEFAULT_TRANSFER_FEE,
                50,
                SystemTime::now(),
            )
            .no_shrink(),),
            |(args_with_caller,)| {
                let rt = Runtime::new().unwrap();
                let setup = Setup::builder().build();

                rt.block_on(async {
                    let env = RosettaTestingEnvironmentBuilder::new(&setup).build().await;
                    wait_for_rosetta_block(&env.rosetta_client, env.network_identifier.clone(), 0)
                        .await;

                    for arg_with_caller in args_with_caller.into_iter() {
                        let currency = Currency {
                            symbol: DEFAULT_TOKEN_SYMBOL.to_owned(),
                            decimals: DEFAULT_DECIMAL_PLACES as u32,
                            metadata: None,
                        };
                        let icrc1_transaction: ic_icrc1::Transaction<U256> =
                            arg_with_caller.to_transaction(setup.minting_account);
                        let fee = match icrc1_transaction.operation {
                            ic_icrc1::Operation::Transfer { fee, .. } => fee,
                            ic_icrc1::Operation::Approve { fee, .. } => fee,
                            ic_icrc1::Operation::Mint { .. } => None,
                            ic_icrc1::Operation::Burn { .. } => None,
                        };

                        // Rosetta does not support mint and burn operations
                        // To keep the balances in sync we need to call the ledger agent directly and then go to the next iteration of args with caller
                        if matches!(
                            icrc1_transaction.operation,
                            ic_icrc1::Operation::Mint { .. }
                        ) || matches!(
                            icrc1_transaction.operation,
                            ic_icrc1::Operation::Burn { .. }
                        ) {
                            let caller_agent = Icrc1Agent {
                                agent: get_custom_agent(arg_with_caller.caller.clone(), setup.port)
                                    .await,
                                ledger_canister_id: env.icrc1_ledger_id,
                            };
                            match arg_with_caller.arg {
                                LedgerEndpointArg::TransferArg(transfer_arg) => caller_agent
                                    .transfer(transfer_arg.clone())
                                    .await
                                    .unwrap()
                                    .unwrap()
                                    .0
                                    .to_u64()
                                    .unwrap(),
                                _ => panic!("Expected TransferArg for Mint and Burns"),
                            };
                            continue;
                        }

                        let rosetta_core_operations = icrc1_operation_to_rosetta_core_operations(
                            icrc1_transaction.operation.clone().into(),
                            currency.clone(),
                            fee.map(|fee| fee.into()),
                        )
                        .unwrap();

                        let expected_balances = match icrc1_transaction.operation {
                            ic_icrc1::Operation::Transfer {
                                from,
                                to,
                                amount,
                                spender,
                                ..
                            } => {
                                let mut account_balances = HashMap::new();
                                let from_balance = env
                                    .icrc1_agent
                                    .balance_of(from, CallMode::Query)
                                    .await
                                    .unwrap();
                                let to_balance = env
                                    .icrc1_agent
                                    .balance_of(to, CallMode::Query)
                                    .await
                                    .unwrap();
                                account_balances.insert(
                                    from,
                                    from_balance
                                        - Nat::from(amount)
                                        - Nat::from(DEFAULT_TRANSFER_FEE),
                                );
                                account_balances.insert(to, to_balance + Nat::from(amount));
                                if let Some(spender) = spender {
                                    let spender_balance = env
                                        .icrc1_agent
                                        .balance_of(spender, CallMode::Query)
                                        .await
                                        .unwrap();
                                    account_balances.insert(spender, spender_balance);
                                }
                                account_balances
                            }
                            ic_icrc1::Operation::Approve { from, spender, .. } => {
                                let mut account_balances = HashMap::new();
                                let from_balance = env
                                    .icrc1_agent
                                    .balance_of(from, CallMode::Query)
                                    .await
                                    .unwrap();
                                let spender_balance = env
                                    .icrc1_agent
                                    .balance_of(spender, CallMode::Query)
                                    .await
                                    .unwrap();
                                account_balances
                                    .insert(from, from_balance - Nat::from(DEFAULT_TRANSFER_FEE));
                                account_balances.insert(spender, spender_balance);
                                account_balances
                            }
                            _ => panic!("Mint and Burn operations are not supported"),
                        };

                        env.rosetta_client
                            .make_submit_and_wait_for_transaction(
                                &arg_with_caller.caller,
                                env.network_identifier.clone(),
                                rosetta_core_operations.clone(),
                                None,
                                None,
                            )
                            .await
                            .unwrap();
                        println!("Transaction submitted and confirmed");
                        for (account, expected_balance) in expected_balances.into_iter() {
                            let actual_balance = env
                                .icrc1_agent
                                .balance_of(account, CallMode::Query)
                                .await
                                .unwrap();
                            assert_eq!(actual_balance, expected_balance);
                        }
                    }
                    Ok(())
                })
            },
        )
        .unwrap();
}

#[test]
fn test_rosetta_client_construction_api_flow() {
    let sender_keypair = EdKeypair::generate_from_u64(0);
    let receiver_keypair = EdKeypair::generate_from_u64(1);
    let rt = Runtime::new().unwrap();
    let setup = Setup::builder()
        .with_initial_balance(
            sender_keypair.generate_principal_id().unwrap().0,
            1_000_000_000_000u64,
        )
        .build();

    rt.block_on(async {
        let env = RosettaTestingEnvironmentBuilder::new(&setup).build().await;

        wait_for_rosetta_block(&env.rosetta_client, env.network_identifier.clone(), 0).await;

        // Test the transfer functionality of the rosetta client
        let transfer_amount: Nat = 1_000_000_000u64.into();

        let operations = env
            .rosetta_client
            .build_transfer_operations(
                &sender_keypair,
                None,
                receiver_keypair.generate_principal_id().unwrap().0.into(),
                transfer_amount.clone(),
                env.network_identifier.clone(),
            )
            .await
            .unwrap();

        let balance_before_transfer = env
            .icrc1_agent
            .balance_of(
                sender_keypair.generate_principal_id().unwrap().0.into(),
                CallMode::Query,
            )
            .await
            .unwrap();

        env.rosetta_client
            .make_submit_and_wait_for_transaction(
                &sender_keypair,
                env.network_identifier.clone(),
                operations,
                None,
                None,
            )
            .await
            .unwrap();

        let current_balance = env
            .icrc1_agent
            .balance_of(
                sender_keypair.generate_principal_id().unwrap().0.into(),
                CallMode::Query,
            )
            .await
            .unwrap();

        assert_eq!(
            current_balance,
            balance_before_transfer - Nat::from(DEFAULT_TRANSFER_FEE) - transfer_amount
        );

        // Test the approve functionality of the rosetta client
        let approve_amount: Nat = 1_000_000_000u64.into();

        let operations = env
            .rosetta_client
            .build_approve_operations(
                &sender_keypair,
                None,
                receiver_keypair.generate_principal_id().unwrap().0.into(),
                approve_amount.clone(),
                None,
                env.network_identifier.clone(),
                None,
            )
            .await
            .unwrap();

        let balance_before_approve = env
            .icrc1_agent
            .balance_of(
                sender_keypair.generate_principal_id().unwrap().0.into(),
                CallMode::Query,
            )
            .await
            .unwrap();

        env.rosetta_client
            .make_submit_and_wait_for_transaction(
                &sender_keypair,
                env.network_identifier.clone(),
                operations,
                None,
                None,
            )
            .await
            .unwrap();

        let current_balance = env
            .icrc1_agent
            .balance_of(
                sender_keypair.generate_principal_id().unwrap().0.into(),
                CallMode::Query,
            )
            .await
            .unwrap();

        assert_eq!(
            current_balance,
            balance_before_approve - Nat::from(DEFAULT_TRANSFER_FEE)
        );
    });
}

#[test]
fn test_rosetta_client_binary() {
    let sender_keypair = EdKeypair::generate_from_u64(0);
    let receiver_keypair = EdKeypair::generate_from_u64(1);

    let sender_account = Account {
        owner: sender_keypair.generate_principal_id().unwrap().0,
        subaccount: Some([1; 32]),
    };
    let rt = Runtime::new().unwrap();
    let setup = Setup::builder()
        .with_initial_balance(sender_account, 1_000_000_000_000u64)
        .build();

    rt.block_on(async {
        let env = RosettaTestingEnvironmentBuilder::new(&setup).build().await;
        wait_for_rosetta_block(&env.rosetta_client, env.network_identifier.clone(), 0).await;

        // Test the transfer functionality of the rosetta client binary
        let transfer_amount: Nat = 1_000_000_000u64.into();

        let balance_before_transfer = env
            .icrc1_agent
            .balance_of(sender_account, CallMode::Query)
            .await
            .unwrap();

        let rosetta_client_args =
            RosettaClientArgsBuilder::new(env.rosetta_client.url.clone().to_string(), "transfer")
                .with_to_account(receiver_keypair.generate_principal_id().unwrap().0.into())
                .with_from_subaccount(sender_account.subaccount.map(|s| s.to_vec()).unwrap())
                .with_amount(transfer_amount.clone())
                .build();

        make_transaction_with_rosetta_client_binary(
            &rosetta_client_bin(),
            rosetta_client_args,
            sender_keypair.to_pem(),
        )
        .await
        .unwrap();

        let current_balance = env
            .icrc1_agent
            .balance_of(sender_account, CallMode::Query)
            .await
            .unwrap();

        assert_eq!(
            current_balance,
            balance_before_transfer - Nat::from(DEFAULT_TRANSFER_FEE) - transfer_amount
        );

        // Test the approve functionality of the rosetta client binary
        let approve_amount: Nat = 1_000_000_000u64.into();

        let balance_before_approve = env
            .icrc1_agent
            .balance_of(sender_account, CallMode::Query)
            .await
            .unwrap();

        let rosetta_client_args =
            RosettaClientArgsBuilder::new(env.rosetta_client.url.clone().to_string(), "approve")
                .with_spender_account(receiver_keypair.generate_principal_id().unwrap().0.into())
                .with_from_subaccount(sender_account.subaccount.map(|s| s.to_vec()).unwrap())
                .with_allowance(approve_amount.clone())
                .with_memo(b"test_bytes".to_vec())
                .build();

        make_transaction_with_rosetta_client_binary(
            &rosetta_client_bin(),
            rosetta_client_args,
            sender_keypair.to_pem(),
        )
        .await
        .unwrap();

        let current_balance = env
            .icrc1_agent
            .balance_of(sender_account, CallMode::Query)
            .await
            .unwrap();

        assert_eq!(
            current_balance,
            balance_before_approve - Nat::from(DEFAULT_TRANSFER_FEE)
        );
    });
}

#[test]
fn test_rosetta_transfer_from() {
    let from_keypair = EdKeypair::generate_from_u64(0);
    let to_keypair = EdKeypair::generate_from_u64(1);
    let spender_keypair = EdKeypair::generate_from_u64(2);

    let spender_account = Account {
        owner: spender_keypair.generate_principal_id().unwrap().0,
        subaccount: Some([1; 32]),
    };
    let from_account = Account {
        owner: from_keypair.generate_principal_id().unwrap().0,
        subaccount: Some([2; 32]),
    };
    let to_account = Account {
        owner: to_keypair.generate_principal_id().unwrap().0,
        subaccount: Some([3; 32]),
    };
    let rt = Runtime::new().unwrap();
    let setup = Setup::builder()
        .with_initial_balance(from_account, 1_000_000_000_000u64)
        .build();

    rt.block_on(async {
        let env = RosettaTestingEnvironmentBuilder::new(&setup).build().await;
        wait_for_rosetta_block(&env.rosetta_client, env.network_identifier.clone(), 0).await;

        // Approve a certain amount to the spender so we can then transfer some of the approved amount
        let approve_amount: Nat = 1_000_000_000u64.into();

        let rosetta_client_args =
            RosettaClientArgsBuilder::new(env.rosetta_client.url.clone().to_string(), "approve")
                .with_spender_account(spender_account)
                .with_from_subaccount(from_account.subaccount.map(|s| s.to_vec()).unwrap())
                .with_allowance(approve_amount.clone())
                .build();

        make_transaction_with_rosetta_client_binary(
            &rosetta_client_bin(),
            rosetta_client_args,
            from_keypair.to_pem(),
        )
        .await
        .unwrap();

        // Test the transfer from functionality of the rosetta client binary
        let transfer_amount: Nat = 1_000_000u64.into();

        let balance_before_transfer = env
            .icrc1_agent
            .balance_of(from_account, CallMode::Query)
            .await
            .unwrap();

        let rosetta_client_args = RosettaClientArgsBuilder::new(
            env.rosetta_client.url.clone().to_string(),
            "transfer-from",
        )
        .with_to_account(to_account)
        .with_from_account(from_account)
        .with_spender_subaccount(spender_account.subaccount.map(|s| s.to_vec()).unwrap())
        .with_amount(transfer_amount.clone())
        .build();

        make_transaction_with_rosetta_client_binary(
            &rosetta_client_bin(),
            rosetta_client_args,
            spender_keypair.to_pem(),
        )
        .await
        .unwrap();

        let current_balance = env
            .icrc1_agent
            .balance_of(from_account, CallMode::Query)
            .await
            .unwrap();

        assert_eq!(
            current_balance,
            balance_before_transfer - Nat::from(DEFAULT_TRANSFER_FEE) - transfer_amount.clone()
        );

        let balance_receiver = env
            .icrc1_agent
            .balance_of(to_account, CallMode::Query)
            .await
            .unwrap();

        assert_eq!(balance_receiver, transfer_amount);
    });
}

#[test]
fn test_search_transactions() {
    let mut runner = TestRunner::new(TestRunnerConfig {
        max_shrink_iters: 0,
        cases: *NUM_TEST_CASES,
        ..Default::default()
    });

    runner
        .run(
            &(valid_transactions_strategy(
                (*MINTING_IDENTITY).clone(),
                DEFAULT_TRANSFER_FEE,
                50,
                SystemTime::now(),
            )
            .no_shrink()),
            |args_with_caller| {
                let rt = Runtime::new().unwrap();
                let setup = Setup::builder().build();

                rt.block_on(async {
                    let env = RosettaTestingEnvironmentBuilder::new(&setup)
                        .with_args_with_caller(args_with_caller.clone())
                        .build()
                        .await;
                    wait_for_rosetta_block(&env.rosetta_client, env.network_identifier.clone(), 0)
                        .await;

                    if !args_with_caller.is_empty() {
                        let rosetta_blocks = get_rosetta_blocks_from_icrc1_ledger(
                            env.icrc1_agent,
                            0,
                            *MAX_BLOCKS_PER_REQUEST,
                        )
                        .await;

                        let transaction_identifier = rosetta_blocks
                            .first()
                            .unwrap()
                            .clone()
                            .get_transaction_identifier();

                        let search_transactions_request = SearchTransactionsRequest {
                            network_identifier: env.network_identifier.clone(),
                            transaction_identifier: Some(transaction_identifier.clone()),
                            ..Default::default()
                        };

                        let search_transactions_response = env
                            .rosetta_client
                            .search_transactions(
                                search_transactions_request.network_identifier,
                                search_transactions_request.transaction_identifier,
                                search_transactions_request.account_identifier,
                                search_transactions_request.type_,
                                search_transactions_request.max_block,
                                search_transactions_request.limit,
                                search_transactions_request.offset,
                            )
                            .await
                            .expect("Unable to call search_transactions");

                        search_transactions_response
                            .transactions
                            .iter()
                            .for_each(|transaction| {
                                assert_eq!(
                                    transaction.transaction.transaction_identifier,
                                    transaction_identifier
                                );
                            });
                    }

                    Ok(())
                })
            },
        )
        .unwrap()
}

#[test]
fn test_cli_data() {
    let mut runner = TestRunner::new(TestRunnerConfig {
        max_shrink_iters: 0,
        cases: *NUM_TEST_CASES,
        ..Default::default()
    });
    runner
        .run(
            &(valid_transactions_strategy(
                (*MINTING_IDENTITY).clone(),
                DEFAULT_TRANSFER_FEE,
                *MAX_NUM_GENERATED_BLOCKS,
                SystemTime::now(),
            )
            .no_shrink()),
            |args_with_caller| {
                // Create a tokio environment to conduct async calls
                let rt = Runtime::new().unwrap();
                let setup = Setup::builder().build();

                // Wrap async calls in a blocking Block
                rt.block_on(async {
                    let env = RosettaTestingEnvironmentBuilder::new(&setup)
                        .with_args_with_caller(args_with_caller.clone())
                        .build()
                        .await;
                    wait_for_rosetta_block(&env.rosetta_client, env.network_identifier.clone(), 0)
                        .await;

                    let output = Command::new(rosetta_cli())
                        .args([
                            "check:data",
                            "--configuration-file",
                            local("tests/rosetta-cli_data_test.json").as_str(),
                            "--online-url",
                            &format!("http://0.0.0.0:{}", env._rosetta_context.port),
                        ])
                        .output()
                        .expect("failed to execute rosetta-cli");

                    assert!(
                        output.status.success(),
                        "rosetta-cli did not finish successfully: {},/\
                        \n\n--------------------------\nstdout: {}, \
                        \n\n--------------------------\nstderr: {}",
                        output.status,
                        String::from_utf8(output.stdout).unwrap(),
                        String::from_utf8(output.stderr).unwrap()
                    );
                });
                Ok(())
            },
        )
        .unwrap();
}

#[ignore]
#[test]
fn test_cli_construction() {
    let mut runner = TestRunner::new(TestRunnerConfig {
        max_shrink_iters: 0,
        cases: *NUM_TEST_CASES,
        ..Default::default()
    });
    runner
        .run(
            &(valid_transactions_strategy(
                (*MINTING_IDENTITY).clone(),
                DEFAULT_TRANSFER_FEE,
                *MAX_NUM_GENERATED_BLOCKS,
                SystemTime::now(),
            )
            .no_shrink()),
            |args_with_caller| {
                // Create a tokio environment to conduct async calls
                let rt = Runtime::new().unwrap();
                let setup = Setup::builder().build();

                // Wrap async calls in a blocking Block
                rt.block_on(async {
                    let env = RosettaTestingEnvironmentBuilder::new(&setup)
                        .with_args_with_caller(args_with_caller.clone())
                        .build()
                        .await;
                    wait_for_rosetta_block(&env.rosetta_client, env.network_identifier.clone(), 0)
                        .await;

                    let mut args = TransferArg {
                        from_subaccount: None,
                        to: *TEST_ACCOUNT,
                        fee: Some(DEFAULT_TRANSFER_FEE.into()),
                        amount: 1_000_000_000u64.into(),
                        memo: None,
                        created_at_time: None,
                    };

                    let block_index = env
                        .rosetta_client
                        .network_status(env.network_identifier.clone())
                        .await
                        .expect("failed to get the last block index")
                        .current_block_identifier
                        .index;

                    const NUM_ACCOUNTS: u64 = 7;

                    // Fund the accounts from rosetta-cli_construction_test.json
                    // The accounts are created from seed 1-7.
                    for seed in 1..NUM_ACCOUNTS + 1 {
                        let key_pair = EdKeypair::generate_from_u64(seed);
                        let account: Account = key_pair
                            .generate_principal_id()
                            .expect("failed to get principal")
                            .0
                            .into();
                        args.to = account;

                        env.icrc1_agent
                            .transfer(args.clone())
                            .await
                            .expect("sending transfer failed")
                            .expect("transfer resulted in an error");
                    }

                    let new_block_index = wait_for_rosetta_block(
                        &env.rosetta_client,
                        env.network_identifier.clone(),
                        block_index + NUM_ACCOUNTS,
                    )
                    .await
                    .unwrap();

                    if new_block_index < block_index + NUM_ACCOUNTS {
                        panic!("failed to sync the funding transactions");
                    }

                    let output = Command::new(rosetta_cli())
                        .args([
                            "check:construction",
                            "--configuration-file",
                            local("tests/rosetta-cli_construction_test.json").as_str(),
                            "--online-url",
                            &format!("http://0.0.0.0:{}", env._rosetta_context.port),
                            "--offline-url",
                            &format!("http://0.0.0.0:{}", env._rosetta_context.port),
                        ])
                        .output()
                        .expect("failed to execute rosetta-cli");

                    assert!(
                        output.status.success(),
                        "rosetta-cli did not finish successfully: {},/\
                    \n\n--------------------------\nstdout: {}, \
                    \n\n--------------------------\nstderr: {}",
                        output.status,
                        String::from_utf8(output.stdout).unwrap(),
                        String::from_utf8(output.stderr).unwrap()
                    );
                });
                Ok(())
            },
        )
        .unwrap();
}
