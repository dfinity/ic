use crate::common::local_replica;
use crate::common::local_replica::{create_and_install_icrc_ledger, test_identity};
use crate::common::utils::{
    get_rosetta_blocks_from_icrc1_ledger, metrics_gauge_value, wait_for_rosetta_block,
};
use candid::Nat;
use candid::Principal;
use common::local_replica::get_custom_agent;
use ic_agent::Identity;
use ic_agent::identity::BasicIdentity;
use ic_base_types::CanisterId;
use ic_base_types::PrincipalId;
use ic_icrc_rosetta::common::constants::STATUS_COMPLETED;
use ic_icrc_rosetta::common::types::Error;
use ic_icrc_rosetta::common::types::OperationType;
use ic_icrc_rosetta::common::utils::utils::icrc1_rosetta_block_to_rosetta_core_transaction;
use ic_icrc_rosetta::common::utils::utils::{
    icrc1_operation_to_rosetta_core_operations, icrc1_rosetta_block_to_rosetta_core_block,
};
use ic_icrc_rosetta::construction_api::types::ConstructionMetadataRequestOptions;
use ic_icrc_rosetta::data_api::types::{QueryBlockRangeRequest, QueryBlockRangeResponse};
use ic_icrc_rosetta_client::RosettaClient;
use ic_icrc_rosetta_runner::RosettaClientArgsBuilder;
use ic_icrc_rosetta_runner::{
    DEFAULT_DECIMAL_PLACES, RosettaContext, RosettaOptions, start_rosetta,
};
use ic_icrc_rosetta_runner::{DEFAULT_TOKEN_SYMBOL, make_transaction_with_rosetta_client_binary};
use ic_icrc1_ledger::{InitArgs, InitArgsBuilder};
use ic_icrc1_test_utils::KeyPairGenerator;
use ic_icrc1_test_utils::{
    ArgWithCaller, DEFAULT_TRANSFER_FEE, LedgerEndpointArg, minter_identity,
    valid_transactions_strategy,
};
use ic_icrc1_tokens_u256::U256;
use ic_rosetta_api::DEFAULT_BLOCKCHAIN;
use icrc_ledger_agent::Icrc1Agent;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::TransferArg;
use icrc_ledger_types::icrc2::approve::ApproveArgs;
use icrc_ledger_types::icrc2::transfer_from::TransferFromArgs;
use lazy_static::lazy_static;
use num_traits::cast::ToPrimitive;
use pocket_ic::{PocketIc, PocketIcBuilder};
use proptest::strategy::Strategy;
use proptest::test_runner::Config as TestRunnerConfig;
use proptest::test_runner::TestRunner;
use rosetta_core::identifiers::*;
use rosetta_core::miscellaneous::OperationStatus;
pub use rosetta_core::models::Ed25519KeyPair as EdKeypair;
use rosetta_core::models::RosettaSupportedKeyPair;
pub use rosetta_core::models::Secp256k1KeyPair;
use rosetta_core::objects::*;
use rosetta_core::request_types::*;
use rosetta_core::response_types::BlockResponse;
use rosetta_core::response_types::ConstructionPreprocessResponse;
use std::collections::HashMap;
use std::collections::HashSet;
use std::str::FromStr;
use std::time::Instant;
use std::{
    path::PathBuf,
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
    pub static ref TEST_LEDGER_CANISTER_ID: Principal =
        Principal::from_str("2ouva-viaaa-aaaaq-aaamq-cai").unwrap();
    pub static ref TEST_LEDGER_CANISTER_ID_OTHER: Principal =
        Principal::from_str("tyyy3-4aaaa-aaaaq-aab7a-cai").unwrap();
}

fn path_from_env(var: &str) -> PathBuf {
    std::fs::canonicalize(
        std::env::var(var).unwrap_or_else(|_| panic!("Environment variable {var} is not set")),
    )
    .unwrap()
}

fn rosetta_bin() -> PathBuf {
    path_from_env("ROSETTA_BIN_PATH")
}

fn rosetta_client_bin() -> PathBuf {
    path_from_env("ROSETTA_CLIENT_BIN_PATH")
}

/// Represents an ICRC-1 ledger canister with its configuration and agent
#[derive(Clone, Debug)]
struct Icrc1Ledger {
    canister_id: Principal,
    init_args: InitArgs,
    /// If true, after canister installation, the ledger will be configured to have an infinite
    /// freezing threshold.
    infinite_freezing_threshold: bool,
    agent: Arc<Icrc1Agent>,
}

impl Icrc1Ledger {
    pub fn network_identifier(&self) -> NetworkIdentifier {
        NetworkIdentifier::new(DEFAULT_BLOCKCHAIN.to_owned(), self.canister_id.to_string())
    }
}

/// Builder for creating an ICRC-1 ledger configuration
struct Icrc1LedgerBuilder {
    canister_id: Principal,
    init_args_builder: InitArgsBuilder,
    infinite_freezing_threshold: bool,
}

impl Icrc1LedgerBuilder {
    fn new(canister_id: Principal) -> Self {
        Self {
            canister_id,
            init_args_builder: local_replica::icrc_ledger_default_args_builder(),
            infinite_freezing_threshold: false,
        }
    }

    fn with_initial_balance(mut self, account: impl Into<Account>, amount: impl Into<Nat>) -> Self {
        self.init_args_builder = self.init_args_builder.with_initial_balance(account, amount);
        self
    }

    fn with_minting_account(mut self, account: Account) -> Self {
        self.init_args_builder = self.init_args_builder.with_minting_account(account);
        self
    }

    fn with_symbol(mut self, symbol: &str) -> Self {
        self.init_args_builder = self.init_args_builder.with_token_symbol(symbol);
        self
    }

    fn with_decimals(mut self, decimals: u8) -> Self {
        self.init_args_builder = self.init_args_builder.with_decimals(decimals);
        self
    }

    fn with_infinite_freezing_threshold(mut self) -> Self {
        self.infinite_freezing_threshold = true;
        self
    }

    fn build(self, agent: Arc<Icrc1Agent>) -> Icrc1Ledger {
        Icrc1Ledger {
            canister_id: self.canister_id,
            init_args: self.init_args_builder.build(),
            infinite_freezing_threshold: self.infinite_freezing_threshold,
            agent: agent.clone(),
        }
    }
}

/// Core test environment setup with PocketIC and ICRC-1 ledgers
struct Setup {
    minting_account: Account,
    pocket_ic: PocketIc,
    port: u16,
    icrc1_ledgers: Vec<Icrc1Ledger>,
}

impl Setup {
    fn builder() -> SetupBuilder {
        SetupBuilder {
            icrc1_ledger_builders: vec![],
        }
    }
}

impl Drop for Setup {
    fn drop(&mut self) {
        self.pocket_ic.stop_live();
    }
}

/// Builder for creating the test environment setup
struct SetupBuilder {
    icrc1_ledger_builders: Vec<Icrc1LedgerBuilder>,
}

impl SetupBuilder {
    fn add_icrc1_ledger_builder(mut self, builder: Icrc1LedgerBuilder) -> Self {
        self.icrc1_ledger_builders.push(builder);
        self
    }

    fn build(self, runtime: &Runtime) -> Setup {
        let minting_account = Account::from(MINTING_IDENTITY.sender().unwrap());
        let mut pocket_ic = PocketIcBuilder::new()
            .with_nns_subnet()
            .with_sns_subnet()
            .build();
        let endpoint = pocket_ic.make_live(None);
        let ic_port = endpoint.port().unwrap();

        let sns_subnet_id = pocket_ic.topology().get_sns().unwrap();
        let mut icrc1_ledgers = vec![];
        for icrc1_ledger_builder in self.icrc1_ledger_builders {
            let icrc1_agent = Arc::new(Icrc1Agent {
                agent: runtime.block_on(local_replica::get_testing_agent(ic_port)),
                ledger_canister_id: icrc1_ledger_builder.canister_id,
            });

            let icrc1_ledger = icrc1_ledger_builder
                .with_minting_account(minting_account)
                .build(icrc1_agent.clone());
            create_and_install_icrc_ledger(
                &pocket_ic,
                icrc1_ledger.init_args.clone(),
                Some(icrc1_ledger.canister_id),
            );
            if icrc1_ledger.infinite_freezing_threshold {
                // If configured, set the freezing threshold to a very high value so that any calls
                // to the ledger will return an out-of-cycles error.
                pocket_ic
                    .update_canister_settings(
                        ic_management_canister_types::CanisterId::from(icrc1_ledger.canister_id),
                        None,
                        ic_management_canister_types::CanisterSettings {
                            freezing_threshold: Some(Nat::from(u64::MAX - 2)),
                            ..Default::default()
                        },
                    )
                    .unwrap();
            }
            let subnet_id = pocket_ic.get_subnet(icrc1_ledger.canister_id).unwrap();
            assert_eq!(
                subnet_id, sns_subnet_id,
                "The canister subnet {subnet_id} does not match the SNS subnet {sns_subnet_id}"
            );
            icrc1_ledgers.push(icrc1_ledger);
        }

        Setup {
            minting_account,
            pocket_ic,
            port: ic_port,
            icrc1_ledgers,
        }
    }
}

/// Test environment for a specific ICRC-1 ledger with Rosetta API
#[derive(Clone, Debug)]
pub struct RosettaLedgerTestingEnvironment {
    icrc1_ledger: Icrc1Ledger,
    network_identifier: NetworkIdentifier,
}

/// Builder for creating a Rosetta ledger testing environment
#[derive(Clone, Debug)]
struct RosettaLedgerTestingEnvironmentBuilder {
    icrc1_ledger: Icrc1Ledger,
    transfer_args_for_block_generating: Option<Vec<ArgWithCaller>>,
    ic_port: u16,
    icrc1_symbol: Option<String>,
    icrc1_decimals: Option<u8>,
}

impl RosettaLedgerTestingEnvironmentBuilder {
    pub fn new(ledger: &Icrc1Ledger, ic_port: u16) -> Self {
        Self {
            icrc1_ledger: ledger.clone(),
            transfer_args_for_block_generating: None,
            icrc1_symbol: None,
            icrc1_decimals: None,
            ic_port,
        }
    }

    pub fn with_args_with_caller(mut self, transfer_args: Vec<ArgWithCaller>) -> Self {
        self.transfer_args_for_block_generating = Some(transfer_args);
        self
    }

    pub fn with_icrc1_symbol(mut self, symbol: String) -> Self {
        self.icrc1_symbol = Some(symbol);
        self
    }

    pub fn with_icrc1_decimals(mut self, decimals: u8) -> Self {
        self.icrc1_decimals = Some(decimals);
        self
    }

    /// Formats the multi-token parameters in the format "canister_id:s=symbol:d=decimals"
    pub fn multitoken_param_format(&self) -> String {
        let symbol_part = self
            .icrc1_symbol
            .as_ref()
            .map_or("".to_string(), |symbol| format!(":s={symbol}"));
        let decimals_part = self
            .icrc1_decimals
            .as_ref()
            .map_or("".to_string(), |decimals| format!(":d={decimals}"));

        format!(
            "{}{}{}",
            self.icrc1_ledger.canister_id, symbol_part, decimals_part
        )
    }

    pub async fn build(&self, rosetta_client: &RosettaClient) -> RosettaLedgerTestingEnvironment {
        let block_idxes = generate_block_indices(
            self.transfer_args_for_block_generating.clone(),
            self.ic_port,
            self.icrc1_ledger.canister_id,
        )
        .await;

        let network_identifier = NetworkIdentifier::new(
            DEFAULT_BLOCKCHAIN.to_owned(),
            CanisterId::try_from(PrincipalId(self.icrc1_ledger.canister_id))
                .unwrap()
                .to_string(),
        );

        // Wait for rosetta to catch up with the ledger
        if let Some(last_block_idx) = block_idxes.last() {
            let rosetta_last_block_idx =
                wait_for_rosetta_block(rosetta_client, network_identifier.clone(), *last_block_idx)
                    .await;
            assert_eq!(
                Some(*last_block_idx),
                rosetta_last_block_idx,
                "Wait for rosetta sync failed."
            );
        }

        RosettaLedgerTestingEnvironment {
            icrc1_ledger: self.icrc1_ledger.clone(),
            network_identifier,
        }
    }
}

/// Complete Rosetta testing environment with multiple ledgers
struct RosettaTestingEnvironment {
    // The '_' character is needed for the rosetta context to be allowed to never be used as it must not go out of scope and be killed.
    _rosetta_context: RosettaContext,
    rosetta_ledger_testing_envs: Vec<RosettaLedgerTestingEnvironment>,
    rosetta_client: RosettaClient,
}

/// Builder for creating the complete Rosetta testing environment
struct RosettaTestingEnvironmentBuilder {
    rosetta_ledger_testing_env_builders: Vec<RosettaLedgerTestingEnvironmentBuilder>,
    offline: bool,
    port: u16,
}

impl RosettaTestingEnvironmentBuilder {
    pub fn new(offline: bool, port: u16) -> Self {
        Self {
            rosetta_ledger_testing_env_builders: vec![],
            offline,
            port,
        }
    }

    pub fn add_rosetta_ledger_testing_env_builder(
        mut self,
        env: RosettaLedgerTestingEnvironmentBuilder,
    ) -> Self {
        self.rosetta_ledger_testing_env_builders.push(env);
        self
    }

    /// Creates a comma-separated string of multi-token parameter values
    fn multitoken_param_value(&self) -> String {
        self.rosetta_ledger_testing_env_builders
            .iter()
            .map(|env| env.multitoken_param_format())
            .collect::<Vec<_>>()
            .join(",")
    }

    pub async fn build(&self) -> RosettaTestingEnvironment {
        let replica_url = format!("http://localhost:{}", self.port);
        let rosetta_context = start_rosetta(
            &rosetta_bin(),
            RosettaOptions {
                multi_tokens: Some(self.multitoken_param_value()),
                network_url: Some(replica_url),
                offline: self.offline,
                symbol: None,
                decimals: None,
                ..RosettaOptions::default()
            },
        )
        .await;

        let rosetta_client =
            RosettaClient::from_str_url(&format!("http://0.0.0.0:{}", rosetta_context.port))
                .expect("Unable to parse url");

        let rosetta_ledger_testing_envs = futures::future::join_all(
            self.rosetta_ledger_testing_env_builders
                .iter()
                .map(|env| env.build(&rosetta_client)),
        )
        .await;

        RosettaTestingEnvironment {
            _rosetta_context: rosetta_context,
            rosetta_ledger_testing_envs,
            rosetta_client,
        }
    }
}

/// Generates blocks on the ledger by executing the provided transfer/approve arguments
async fn generate_block_indices(
    transfer_args: Option<Vec<ArgWithCaller>>,
    port: u16,
    ledger_canister_id: Principal,
) -> Vec<u64> {
    let mut block_idxes = vec![];

    if let Some(args) = transfer_args {
        for ArgWithCaller {
            caller,
            arg,
            principal_to_basic_identity: _,
        } in args
        {
            let caller_agent = Icrc1Agent {
                agent: get_custom_agent(caller.clone(), port).await,
                ledger_canister_id,
            };

            let idx = match arg {
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
                LedgerEndpointArg::TransferFromArg(transfer_from_arg) => caller_agent
                    .transfer_from(transfer_from_arg.clone())
                    .await
                    .unwrap()
                    .unwrap()
                    .0
                    .to_u64()
                    .unwrap(),
            };

            block_idxes.push(idx);
        }
    }

    block_idxes
}

/// Asserts that the balance from Rosetta matches the expected value
async fn assert_rosetta_balance(
    account: Account,
    block_index: u64,
    balance: u64,
    rosetta_client: &RosettaClient,
    network_identifier: NetworkIdentifier,
) {
    let start = Instant::now();
    let timeout = Duration::from_secs(30);

    // Wait for Rosetta to sync to the required block
    loop {
        let latest_rosetta_block =
            wait_for_rosetta_block(rosetta_client, network_identifier.clone(), block_index)
                .await
                .expect("Unable to call wait_for_rosetta_block");

        if latest_rosetta_block >= block_index {
            break;
        } else {
            println!(
                "Waited for rosetta, received block index {latest_rosetta_block} but expected {block_index}, waiting some more..."
            );
        }

        if start.elapsed() > timeout {
            panic!("Failed to get block index {block_index} within {timeout:?}");
        }
    }

    // Verify the balance
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
fn test_multi_tokens_mode() {
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
                let rt = Runtime::new().unwrap();
                let icrc1_ledger_1_builder = Icrc1LedgerBuilder::new(*TEST_LEDGER_CANISTER_ID)
                    .with_symbol("SYM1")
                    .with_decimals(6);

                let icrc1_ledger_2_builder =
                    Icrc1LedgerBuilder::new(*TEST_LEDGER_CANISTER_ID_OTHER).with_symbol("SYM2");

                let setup = Setup::builder()
                    .add_icrc1_ledger_builder(icrc1_ledger_1_builder)
                    .add_icrc1_ledger_builder(icrc1_ledger_2_builder)
                    .build(&rt);

                let rosetta_ledger_setup_1_builder = RosettaLedgerTestingEnvironmentBuilder::new(
                    &setup.icrc1_ledgers[0],
                    setup.port,
                )
                .with_args_with_caller(args_with_caller.clone())
                .with_icrc1_symbol("SYM1".to_string());

                let rosetta_ledger_setup_2_builder = RosettaLedgerTestingEnvironmentBuilder::new(
                    &setup.icrc1_ledgers[1],
                    setup.port,
                )
                .with_args_with_caller(args_with_caller.clone())
                .with_icrc1_symbol("SYM2".to_string());

                let rosetta_env = rt.block_on(
                    RosettaTestingEnvironmentBuilder::new(false, setup.port)
                        .add_rosetta_ledger_testing_env_builder(rosetta_ledger_setup_1_builder)
                        .add_rosetta_ledger_testing_env_builder(rosetta_ledger_setup_2_builder)
                        .build(),
                );

                let rosetta_client = rosetta_env.rosetta_client.clone();

                // Call /network/list endpoint.
                let network_list = rt
                    .block_on(rosetta_client.network_list())
                    .expect("unable to call network_list")
                    .network_identifiers;
                // Expect two network identifiers.
                let network_id1 = NetworkIdentifier::new(
                    "Internet Computer".to_string(),
                    TEST_LEDGER_CANISTER_ID.to_string(),
                );
                let network_id2 = NetworkIdentifier::new(
                    "Internet Computer".to_string(),
                    TEST_LEDGER_CANISTER_ID_OTHER.to_string(),
                );
                assert_eq!(network_list.len(), 2);
                assert!(network_list.contains(&network_id1));
                assert!(network_list.contains(&network_id2));

                for net in network_list {
                    let status = rt
                        .block_on(rosetta_client.network_status(net.clone()))
                        .expect("unable to call network_status");
                    // We must have a valid current block identifier.
                    assert_eq!(
                        status.current_block_identifier.index,
                        *MAX_NUM_GENERATED_BLOCKS as u64
                    );
                }
                Ok(())
            },
        )
        .unwrap();
}

#[test]
fn test_multi_tokens_mode_with_one_ledger_out_of_cycles() {
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
                let rt = Runtime::new().unwrap();
                let icrc1_ledger_1_builder = Icrc1LedgerBuilder::new(*TEST_LEDGER_CANISTER_ID)
                    .with_symbol("SYM1")
                    .with_decimals(6);

                let icrc1_ledger_2_builder =
                    Icrc1LedgerBuilder::new(*TEST_LEDGER_CANISTER_ID_OTHER)
                        .with_symbol("SYM2")
                        .with_decimals(6)
                        // After canister installation, set an infinite freezing threshold, so that
                        // any calls to the ledger will return an out of cycles error.
                        .with_infinite_freezing_threshold();

                let setup = Setup::builder()
                    .add_icrc1_ledger_builder(icrc1_ledger_1_builder)
                    .add_icrc1_ledger_builder(icrc1_ledger_2_builder)
                    .build(&rt);

                let rosetta_ledger_setup_1_builder = RosettaLedgerTestingEnvironmentBuilder::new(
                    &setup.icrc1_ledgers[0],
                    setup.port,
                )
                .with_args_with_caller(args_with_caller.clone())
                .with_icrc1_symbol("SYM1".to_string());

                let rosetta_ledger_setup_2_builder = RosettaLedgerTestingEnvironmentBuilder::new(
                    &setup.icrc1_ledgers[1],
                    setup.port,
                )
                .with_icrc1_symbol("SYM2".to_string());

                // Initialize the Rosetta testing environment with the two ledgers should succeed.
                let rosetta_env = rt.block_on(
                    RosettaTestingEnvironmentBuilder::new(false, setup.port)
                        .add_rosetta_ledger_testing_env_builder(rosetta_ledger_setup_1_builder)
                        .add_rosetta_ledger_testing_env_builder(rosetta_ledger_setup_2_builder)
                        .build(),
                );

                let rosetta_client = rosetta_env.rosetta_client.clone();

                // Call /network/list endpoint.
                let network_list = rt
                    .block_on(rosetta_client.network_list())
                    .expect("unable to call network_list")
                    .network_identifiers;
                // Expect two network identifiers.
                let network_id1 = NetworkIdentifier::new(
                    "Internet Computer".to_string(),
                    TEST_LEDGER_CANISTER_ID.to_string(),
                );
                let network_id2 = NetworkIdentifier::new(
                    "Internet Computer".to_string(),
                    TEST_LEDGER_CANISTER_ID_OTHER.to_string(),
                );
                // Since the second ledger is out of cycles, it should not be listed.
                assert_eq!(network_list.len(), 1);
                assert!(network_list.contains(&network_id1));
                assert!(!network_list.contains(&network_id2));

                for net in network_list {
                    let status = rt
                        .block_on(rosetta_client.network_status(net.clone()))
                        .expect("unable to call network_status");
                    // We must have a valid current block identifier.
                    assert_eq!(
                        status.current_block_identifier.index,
                        *MAX_NUM_GENERATED_BLOCKS as u64
                    );
                }
                Ok(())
            },
        )
        .unwrap();
}

#[should_panic = "Error: No metadata loaded for any token."]
#[test]
fn test_multi_tokens_mode_with_all_ledgers_out_of_cycles() {
    let rt = Runtime::new().unwrap();
    let icrc1_ledger_1_builder = Icrc1LedgerBuilder::new(*TEST_LEDGER_CANISTER_ID)
        .with_symbol("SYM1")
        .with_decimals(6)
        .with_infinite_freezing_threshold();

    let icrc1_ledger_2_builder = Icrc1LedgerBuilder::new(*TEST_LEDGER_CANISTER_ID_OTHER)
        .with_symbol("SYM2")
        .with_decimals(6)
        // After canister installation, set an infinite freezing threshold, so that
        // any calls to the ledger will return an out of cycles error.
        .with_infinite_freezing_threshold();

    let setup = Setup::builder()
        .add_icrc1_ledger_builder(icrc1_ledger_1_builder)
        .add_icrc1_ledger_builder(icrc1_ledger_2_builder)
        .build(&rt);

    let rosetta_ledger_setup_1_builder =
        RosettaLedgerTestingEnvironmentBuilder::new(&setup.icrc1_ledgers[0], setup.port)
            .with_icrc1_symbol("SYM1".to_string());

    let rosetta_ledger_setup_2_builder =
        RosettaLedgerTestingEnvironmentBuilder::new(&setup.icrc1_ledgers[1], setup.port)
            .with_icrc1_symbol("SYM2".to_string());

    let rosetta_testing_env_builder = RosettaTestingEnvironmentBuilder::new(false, setup.port)
        .add_rosetta_ledger_testing_env_builder(rosetta_ledger_setup_1_builder)
        .add_rosetta_ledger_testing_env_builder(rosetta_ledger_setup_2_builder);

    let replica_url = format!("http://localhost:{}", setup.port);
    let _ = rt.block_on(start_rosetta(
        &rosetta_bin(),
        RosettaOptions {
            multi_tokens: Some(rosetta_testing_env_builder.multitoken_param_value()),
            network_url: Some(replica_url),
            offline: false,
            symbol: None,
            decimals: None,
            ..RosettaOptions::default()
        },
    ));
}

#[test]
fn test_blocks() {
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
                let icrc1_ledger_1_builder = Icrc1LedgerBuilder::new(*TEST_LEDGER_CANISTER_ID)
                    .with_symbol("SYM1")
                    .with_decimals(6);

                let icrc1_ledger_2_builder =
                    Icrc1LedgerBuilder::new(*TEST_LEDGER_CANISTER_ID_OTHER).with_symbol("SYM2");

                let setup = Setup::builder()
                    .add_icrc1_ledger_builder(icrc1_ledger_1_builder)
                    .add_icrc1_ledger_builder(icrc1_ledger_2_builder)
                    .build(&rt);

                let icrc1_ledgers = setup.icrc1_ledgers.clone();

                let rosetta_ledger_setup_1_builder =
                    RosettaLedgerTestingEnvironmentBuilder::new(&icrc1_ledgers[0], setup.port)
                        .with_args_with_caller(args_with_caller.clone())
                        .with_icrc1_symbol("SYM1".to_string());

                let rosetta_ledger_setup_2_builder =
                    RosettaLedgerTestingEnvironmentBuilder::new(&icrc1_ledgers[1], setup.port)
                        .with_args_with_caller(args_with_caller.clone())
                        .with_icrc1_symbol("SYM2".to_string());

                let rosetta_env = rt.block_on(
                    RosettaTestingEnvironmentBuilder::new(false, setup.port)
                        .add_rosetta_ledger_testing_env_builder(rosetta_ledger_setup_1_builder)
                        .add_rosetta_ledger_testing_env_builder(rosetta_ledger_setup_2_builder)
                        .build(),
                );

                let rosetta_client = rosetta_env.rosetta_client.clone();
                rt.block_on(async move {
                    if !args_with_caller.is_empty() {
                        for block in get_rosetta_blocks_from_icrc1_ledger(
                            icrc1_ledgers[0].agent.clone(),
                            0,
                            *MAX_BLOCKS_PER_REQUEST,
                        )
                        .await
                        .into_iter()
                        {
                            let mut expected_block_response = BlockResponse::new(Some(
                                icrc1_rosetta_block_to_rosetta_core_block(
                                    block.clone(),
                                    Currency {
                                        symbol: icrc1_ledgers[0].init_args.token_symbol.clone(),
                                        decimals: icrc1_ledgers[0]
                                            .init_args
                                            .decimals
                                            .unwrap_or(DEFAULT_DECIMAL_PLACES)
                                            as u32,
                                        ..Default::default()
                                    },
                                )
                                .unwrap(),
                            ));
                            expected_block_response.block.iter_mut().for_each(|block| {
                                block.transactions.iter_mut().for_each(|tx| {
                                    tx.operations.iter_mut().for_each(|op| {
                                        op.status = Some(STATUS_COMPLETED.to_string());
                                    })
                                })
                            });

                            assert_eq!(
                                hex::encode(block.clone().get_block_hash().clone()),
                                expected_block_response
                                    .clone()
                                    .block
                                    .unwrap()
                                    .block_identifier
                                    .hash
                            );
                            // Rosetta should be able to handle block identifieres with both the hash and the block index set
                            let actual_block_response = rosetta_client
                                .block(
                                    icrc1_ledgers[0].network_identifier().clone(),
                                    PartialBlockIdentifier {
                                        hash: Some(hex::encode(
                                            block.clone().get_block_hash().clone(),
                                        )),
                                        index: Some(block.index),
                                    },
                                )
                                .await
                                .expect("Failed to find block in Rosetta");
                            assert_eq!(expected_block_response, actual_block_response);

                            // Rosetta should be able to handle block identifieres with only the hash set
                            let actual_block_response = rosetta_client
                                .block(
                                    icrc1_ledgers[0].network_identifier().clone(),
                                    PartialBlockIdentifier {
                                        hash: Some(hex::encode(block.clone().get_block_hash())),
                                        index: None,
                                    },
                                )
                                .await
                                .expect("Failed to find block in Rosetta");
                            assert_eq!(expected_block_response, actual_block_response);

                            // Rosetta should be able to handle block identifieres with only the index set
                            let actual_block_response = rosetta_client
                                .block(
                                    icrc1_ledgers[0].network_identifier().clone(),
                                    PartialBlockIdentifier {
                                        hash: None,
                                        index: Some(block.index),
                                    },
                                )
                                .await
                                .expect("Failed to find block in Rosetta");
                            assert_eq!(expected_block_response, actual_block_response);
                        }
                    }

                    // If no hash or index was provided rosetta should return the last block
                    let last_block = rosetta_client
                        .block(
                            icrc1_ledgers[0].network_identifier().clone(),
                            PartialBlockIdentifier {
                                hash: None,
                                index: None,
                            },
                        )
                        .await
                        .expect("failed to get last block");
                    assert_eq!(
                        last_block.block.unwrap().block_identifier.index as usize,
                        args_with_caller.len()
                    );
                });
                Ok(())
            },
        )
        .unwrap();
}

#[test]
fn test_block_transaction() {
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
                let icrc1_ledger_1_builder = Icrc1LedgerBuilder::new(*TEST_LEDGER_CANISTER_ID)
                    .with_symbol("SYM1")
                    .with_decimals(6);

                let icrc1_ledger_2_builder =
                    Icrc1LedgerBuilder::new(*TEST_LEDGER_CANISTER_ID_OTHER).with_symbol("SYM2");

                let setup = Setup::builder()
                    .add_icrc1_ledger_builder(icrc1_ledger_1_builder)
                    .add_icrc1_ledger_builder(icrc1_ledger_2_builder)
                    .build(&rt);

                let icrc1_ledgers = setup.icrc1_ledgers.clone();

                let rosetta_ledger_setup_1_builder = RosettaLedgerTestingEnvironmentBuilder::new(
                    &setup.icrc1_ledgers[0],
                    setup.port,
                )
                .with_icrc1_symbol("SYM1".to_string());

                let rosetta_ledger_setup_2_builder = RosettaLedgerTestingEnvironmentBuilder::new(
                    &setup.icrc1_ledgers[1],
                    setup.port,
                )
                .with_icrc1_symbol("SYM2".to_string());

                let rosetta_env = rt.block_on(
                    RosettaTestingEnvironmentBuilder::new(false, setup.port)
                        .add_rosetta_ledger_testing_env_builder(rosetta_ledger_setup_1_builder)
                        .add_rosetta_ledger_testing_env_builder(rosetta_ledger_setup_2_builder)
                        .build(),
                );

                let rosetta_client = rosetta_env.rosetta_client.clone();

                // Wrap async calls in a blocking Block
                rt.block_on(async {
                    if !args_with_caller.is_empty() {
                        for block in get_rosetta_blocks_from_icrc1_ledger(
                            icrc1_ledgers[0].agent.clone(),
                            0,
                            *MAX_BLOCKS_PER_REQUEST,
                        )
                        .await
                        .into_iter()
                        {
                            let mut expected_block_transaction_response =
                                rosetta_core::response_types::BlockTransactionResponse {
                                    transaction: icrc1_rosetta_block_to_rosetta_core_transaction(
                                        block.clone(),
                                        Currency {
                                            symbol: icrc1_ledgers[0].init_args.token_symbol.clone(),
                                            decimals: icrc1_ledgers[0]
                                                .init_args
                                                .decimals
                                                .unwrap_or(DEFAULT_DECIMAL_PLACES)
                                                as u32,
                                            ..Default::default()
                                        },
                                    )
                                    .unwrap(),
                                };

                            expected_block_transaction_response
                                .transaction
                                .operations
                                .iter_mut()
                                .for_each(|op| {
                                    op.status = Some(STATUS_COMPLETED.to_string());
                                });

                            assert_eq!(
                                hex::encode(block.clone().get_transaction_hash().clone()),
                                expected_block_transaction_response
                                    .clone()
                                    .transaction
                                    .transaction_identifier
                                    .hash
                            );

                            // Wait for rosetta to catch up with the ledger
                            wait_for_rosetta_block(
                                &rosetta_client,
                                icrc1_ledgers[0].network_identifier().clone(),
                                block.index,
                            )
                            .await;
                            // Rosetta should be able to handle block identifieres with both the hash and the block index set
                            let actual_block_transaction_response = rosetta_client
                                .block_transaction(
                                    icrc1_ledgers[0].network_identifier(),
                                    BlockIdentifier {
                                        index: block.index,
                                        hash: hex::encode(block.clone().get_block_hash().clone()),
                                    },
                                    TransactionIdentifier {
                                        hash: hex::encode(
                                            block.clone().get_transaction_hash().clone(),
                                        ),
                                    },
                                )
                                .await
                                .expect("Failed to find block in Rosetta");
                            assert_eq!(
                                expected_block_transaction_response,
                                actual_block_transaction_response
                            );

                            assert!(
                                rosetta_client
                                    .block_transaction(
                                        icrc1_ledgers[0].network_identifier(),
                                        BlockIdentifier {
                                            index: u64::MAX,
                                            hash: hex::encode(
                                                block.clone().get_block_hash().clone()
                                            ),
                                        },
                                        TransactionIdentifier {
                                            hash: hex::encode(
                                                block.clone().get_transaction_hash().clone()
                                            )
                                        }
                                    )
                                    .await
                                    .is_err()
                            );

                            assert!(
                                rosetta_client
                                    .block_transaction(
                                        icrc1_ledgers[0].network_identifier().clone(),
                                        BlockIdentifier {
                                            index: block.index,
                                            hash: hex::encode("wrong hash"),
                                        },
                                        TransactionIdentifier {
                                            hash: hex::encode(block.clone().get_transaction_hash())
                                        }
                                    )
                                    .await
                                    .is_err()
                            );

                            assert!(
                                rosetta_client
                                    .block_transaction(
                                        icrc1_ledgers[0].network_identifier().clone(),
                                        BlockIdentifier {
                                            index: block.index,
                                            hash: hex::encode(block.clone().get_block_hash()),
                                        },
                                        TransactionIdentifier {
                                            hash: hex::encode("wrong tx hash")
                                        }
                                    )
                                    .await
                                    .is_err()
                            );
                        }
                    }
                });
                Ok(())
            },
        )
        .unwrap();
}

#[test]
fn test_ledger_symbol_check() {
    let result = std::panic::catch_unwind(|| {
        let rt = Runtime::new().unwrap();
        let icrc1_ledger_1_builder =
            Icrc1LedgerBuilder::new(*TEST_LEDGER_CANISTER_ID).with_symbol("SYM1");

        let setup = Setup::builder()
            .add_icrc1_ledger_builder(icrc1_ledger_1_builder)
            .build(&rt);

        let rosetta_ledger_setup_builder =
            RosettaLedgerTestingEnvironmentBuilder::new(&setup.icrc1_ledgers[0], setup.port)
                .with_icrc1_symbol("WRONG_SYM".to_string());

        rt.block_on(
            RosettaTestingEnvironmentBuilder::new(false, setup.port)
                .add_rosetta_ledger_testing_env_builder(rosetta_ledger_setup_builder)
                .build(),
        );
    });
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .downcast_ref::<String>()
            .unwrap()
            .contains("Provided symbol does not match symbol retrieved in online mode.")
    );
}

#[test]
fn test_network_options() {
    let rt = Runtime::new().unwrap();
    let icrc1_ledger_1_builder =
        Icrc1LedgerBuilder::new(*TEST_LEDGER_CANISTER_ID).with_symbol("SYM1");

    let setup = Setup::builder()
        .add_icrc1_ledger_builder(icrc1_ledger_1_builder)
        .build(&rt);

    let rosetta_ledger_setup_builder =
        RosettaLedgerTestingEnvironmentBuilder::new(&setup.icrc1_ledgers[0], setup.port)
            .with_icrc1_symbol("SYM1".to_string())
            .with_icrc1_decimals(8);

    rt.block_on(async {
        let env = RosettaTestingEnvironmentBuilder::new(true, setup.port)
            .add_rosetta_ledger_testing_env_builder(rosetta_ledger_setup_builder.clone())
            .build()
            .await;

        let network_options = env
            .rosetta_client
            .network_options(
                env.rosetta_ledger_testing_envs[0]
                    .network_identifier
                    .clone(),
            )
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

#[test]
fn test_network_status() {
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
                let icrc1_ledger_1_builder =
                    Icrc1LedgerBuilder::new(*TEST_LEDGER_CANISTER_ID).with_symbol("SYM1");

                let setup = Setup::builder()
                    .add_icrc1_ledger_builder(icrc1_ledger_1_builder)
                    .build(&rt);

                let rosetta_ledger_setup_builder = RosettaLedgerTestingEnvironmentBuilder::new(
                    &setup.icrc1_ledgers[0],
                    setup.port,
                )
                .with_args_with_caller(args_with_caller.clone())
                .with_icrc1_symbol("SYM1".to_string())
                .with_icrc1_decimals(8);

                // Wrap async calls in a blocking Block
                rt.block_on(async {
                    let env = RosettaTestingEnvironmentBuilder::new(false, setup.port)
                        .add_rosetta_ledger_testing_env_builder(
                            rosetta_ledger_setup_builder.clone(),
                        )
                        .build()
                        .await;
                    wait_for_rosetta_block(
                        &env.rosetta_client,
                        env.rosetta_ledger_testing_envs[0]
                            .network_identifier
                            .clone(),
                        0,
                    )
                    .await;

                    // Get the blocks from the ledger to compare against rosetta
                    let rosetta_blocks = get_rosetta_blocks_from_icrc1_ledger(
                        env.rosetta_ledger_testing_envs[0]
                            .icrc1_ledger
                            .agent
                            .clone(),
                        0,
                        *MAX_BLOCKS_PER_REQUEST,
                    )
                    .await;

                    if !args_with_caller.is_empty() {
                        assert!(
                            !rosetta_blocks.is_empty(),
                            "there should be blocks in the ledger"
                        );

                        let rosetta_response = env
                            .rosetta_client
                            .network_status(
                                env.rosetta_ledger_testing_envs[0]
                                    .network_identifier
                                    .clone(),
                            )
                            .await
                            .expect("Unable to call network_status");

                        assert_eq!(
                            rosetta_blocks.last().unwrap().index,
                            rosetta_response.current_block_identifier.index,
                            "Chain length does not match"
                        );
                        assert_eq!(
                            rosetta_response.current_block_identifier.index,
                            args_with_caller.len() as u64,
                            "current_block_identifier index should be args_with_caller.len()"
                        );

                        assert_eq!(
                            hex::encode(
                                rosetta_blocks
                                    .first()
                                    .unwrap()
                                    .clone()
                                    .get_block_hash()
                                    .clone()
                            ),
                            rosetta_response.genesis_block_identifier.hash,
                            "Genesis block hashes do not match"
                        );
                        assert_eq!(
                            hex::encode(
                                rosetta_blocks
                                    .last()
                                    .unwrap()
                                    .clone()
                                    .get_block_hash()
                                    .clone()
                            ),
                            rosetta_response.current_block_identifier.hash,
                            "Current block hashes do not match"
                        );
                        assert_eq!(
                            hex::encode(
                                rosetta_blocks
                                    .first()
                                    .unwrap()
                                    .clone()
                                    .get_block_hash()
                                    .clone()
                            ),
                            rosetta_response.oldest_block_identifier.unwrap().hash,
                            "Genesis block hashes do not match"
                        );
                        assert_eq!(
                            Duration::from_nanos(rosetta_blocks.last().unwrap().get_timestamp())
                                .as_millis() as u64,
                            rosetta_response.current_block_timestamp
                        );
                    }
                });
                Ok(())
            },
        )
        .unwrap();
}

#[test]
fn test_mempool() {
    let rt = Runtime::new().unwrap();
    let icrc1_ledger_1_builder =
        Icrc1LedgerBuilder::new(*TEST_LEDGER_CANISTER_ID).with_symbol("SYM1");

    let setup = Setup::builder()
        .add_icrc1_ledger_builder(icrc1_ledger_1_builder)
        .build(&rt);

    let rosetta_ledger_setup_builder =
        RosettaLedgerTestingEnvironmentBuilder::new(&setup.icrc1_ledgers[0], setup.port);

    rt.block_on(async {
        let env = RosettaTestingEnvironmentBuilder::new(false, setup.port)
            .add_rosetta_ledger_testing_env_builder(rosetta_ledger_setup_builder.clone())
            .build()
            .await;
        let network_identifier = env.rosetta_ledger_testing_envs[0]
            .network_identifier
            .clone();
        wait_for_rosetta_block(&env.rosetta_client, network_identifier.clone(), 0).await;

        let transaction_identifiers = env
            .rosetta_client
            .mempool(network_identifier.clone())
            .await
            .expect("Unable to call mempool")
            .transaction_identifiers;
        assert_eq!(transaction_identifiers, vec![]);

        let transaction_id = TransactionIdentifier {
            hash: "1234".to_string(),
        };
        let mempool_transaction_request =
            MempoolTransactionRequest::new(network_identifier, transaction_id);
        let response = env
            .rosetta_client
            .mempool_transaction(mempool_transaction_request)
            .await;
        let err = response.expect_err("expected an error");
        assert_eq!(err, Error::mempool_transaction_missing());
    });
}

#[test]
fn test_metrics() {
    const NUM_BLOCKS: u64 = 2;
    let sender_keypair = Secp256k1KeyPair::generate(0);
    let rt = Runtime::new().unwrap();
    let icrc1_ledger_1_builder = Icrc1LedgerBuilder::new(*TEST_LEDGER_CANISTER_ID)
        .with_symbol("SYM1")
        .with_decimals(6)
        // The Icrc1LedgerBuilder already includes one initial balance, but we add another one here
        // so that the index of the latest block is non-zero.
        .with_initial_balance(
            sender_keypair.generate_principal_id().unwrap().0,
            1_000_000_000_000u64,
        );
    let setup = Setup::builder()
        .add_icrc1_ledger_builder(icrc1_ledger_1_builder)
        .build(&rt);

    let rosetta_ledger_setup_builder =
        RosettaLedgerTestingEnvironmentBuilder::new(&setup.icrc1_ledgers[0], setup.port)
            .with_icrc1_symbol("SYM1".to_string());

    let icrc1_ledgers = setup.icrc1_ledgers.clone();

    rt.block_on(async {
        let env = RosettaTestingEnvironmentBuilder::new(false, setup.port)
            .add_rosetta_ledger_testing_env_builder(rosetta_ledger_setup_builder)
            .build()
            .await;
        wait_for_rosetta_block(
            &env.rosetta_client,
            env.rosetta_ledger_testing_envs[0]
                .network_identifier
                .clone(),
            NUM_BLOCKS - 1,
        )
        .await;

        let metrics = env
            .rosetta_client
            .metrics()
            .await
            .expect("should return metrics");

        let network_identifier = env.rosetta_ledger_testing_envs[0]
            .network_identifier
            .clone();

        let current_index = env
            .rosetta_client
            .network_status(network_identifier.clone())
            .await
            .expect("Unable to call network_status")
            .current_block_identifier
            .index;

        let ledger_num_blocks = get_rosetta_blocks_from_icrc1_ledger(
            icrc1_ledgers[0].agent.clone(),
            0,
            *MAX_BLOCKS_PER_REQUEST,
        )
        .await
        .len();
        assert_eq!(ledger_num_blocks as u64, NUM_BLOCKS);
        assert_eq!(current_index, NUM_BLOCKS - 1);

        let rosetta_synched_block_height =
            metrics_gauge_value(&metrics, "rosetta_synched_block_height")
                .expect("should export rosetta_synched_block_height metric");
        assert_eq!(rosetta_synched_block_height as u64, NUM_BLOCKS - 1);
        let rosetta_verified_block_height =
            metrics_gauge_value(&metrics, "rosetta_verified_block_height")
                .expect("should export rosetta_verified_block_height metric");
        assert_eq!(rosetta_verified_block_height as u64, NUM_BLOCKS - 1);
        let rosetta_target_block_height =
            metrics_gauge_value(&metrics, "rosetta_target_block_height")
                .expect("should export rosetta_target_block_height metric");
        assert_eq!(rosetta_target_block_height as u64, NUM_BLOCKS - 1);
    });
}

#[test]
fn test_construction_preprocess() {
    let rt = Runtime::new().unwrap();
    let icrc1_ledger_1_builder =
        Icrc1LedgerBuilder::new(*TEST_LEDGER_CANISTER_ID).with_symbol("SYM1");

    let setup = Setup::builder()
        .add_icrc1_ledger_builder(icrc1_ledger_1_builder)
        .build(&rt);

    let rosetta_ledger_setup_builder =
        RosettaLedgerTestingEnvironmentBuilder::new(&setup.icrc1_ledgers[0], setup.port);

    rt.block_on(async {
        let env = RosettaTestingEnvironmentBuilder::new(false, setup.port)
            .add_rosetta_ledger_testing_env_builder(rosetta_ledger_setup_builder.clone())
            .build()
            .await;
        let network_identifier = env.rosetta_ledger_testing_envs[0]
            .network_identifier
            .clone();

        let construction_preprocess_response = env
            .rosetta_client
            .construction_preprocess(vec![], network_identifier.clone())
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
    let icrc1_ledger_1_builder =
        Icrc1LedgerBuilder::new(*TEST_LEDGER_CANISTER_ID).with_symbol("SYM1");

    let setup = Setup::builder()
        .add_icrc1_ledger_builder(icrc1_ledger_1_builder)
        .build(&rt);

    let rosetta_ledger_setup_builder =
        RosettaLedgerTestingEnvironmentBuilder::new(&setup.icrc1_ledgers[0], setup.port);

    rt.block_on(async {
        let env = RosettaTestingEnvironmentBuilder::new(false, setup.port)
            .add_rosetta_ledger_testing_env_builder(rosetta_ledger_setup_builder.clone())
            .build()
            .await;
        let network_identifier = env.rosetta_ledger_testing_envs[0]
            .network_identifier
            .clone();

        let key_pair = EdKeypair::generate(10);
        let principal_id = key_pair.generate_principal_id().unwrap();
        let public_key = ic_rosetta_test_utils::to_public_key(&key_pair);
        let account = Account {
            owner: principal_id.into(),
            subaccount: None,
        };

        let request = ConstructionDeriveRequest {
            network_identifier: network_identifier.clone(),
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
                let icrc1_ledger_1_builder =
                    Icrc1LedgerBuilder::new(*TEST_LEDGER_CANISTER_ID).with_symbol("SYM1");

                let setup = Setup::builder()
                    .add_icrc1_ledger_builder(icrc1_ledger_1_builder)
                    .build(&rt);

                let rosetta_ledger_setup_builder = RosettaLedgerTestingEnvironmentBuilder::new(
                    &setup.icrc1_ledgers[0],
                    setup.port,
                )
                .with_args_with_caller(args_with_caller.clone());

                rt.block_on(async {
                    let env = RosettaTestingEnvironmentBuilder::new(false, setup.port)
                        .add_rosetta_ledger_testing_env_builder(
                            rosetta_ledger_setup_builder.clone(),
                        )
                        .build()
                        .await;
                    let network_identifier = env.rosetta_ledger_testing_envs[0]
                        .network_identifier
                        .clone();
                    // Keep track of the account balances
                    let mut accounts_balances: HashMap<Account, u64> = HashMap::new();

                    let current_index = env
                        .rosetta_client
                        .network_status(network_identifier.clone())
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
                            LedgerEndpointArg::TransferFromArg(TransferFromArgs {
                                from,
                                to,
                                amount,
                                ..
                            }) => {
                                // For TransferFrom we always deduct the transfer fee. TransferFrom
                                // from or to the minter account is not allowed, so we do not need
                                // to check for it.
                                accounts_balances.entry(*from).and_modify(|balance| {
                                    *balance -= amount.0.to_u64().unwrap();
                                    *balance -= DEFAULT_TRANSFER_FEE;
                                });
                                involved_accounts.push(*from);

                                accounts_balances
                                    .entry(*to)
                                    .and_modify(|balance| {
                                        *balance += amount.0.to_u64().unwrap();
                                    })
                                    .or_insert(amount.0.to_u64().unwrap());
                                involved_accounts.push(*to);
                            }
                        };

                        for account in involved_accounts {
                            all_involved_accounts.insert(account);
                            assert_rosetta_balance(
                                account,
                                block_start_index,
                                *accounts_balances.get(&account).unwrap(),
                                &env.rosetta_client,
                                network_identifier.clone(),
                            )
                            .await;
                        }

                        block_start_index += 1;
                    }

                    // Assert that the current balance on the ledger is the same as that of icrc rosetta
                    for account in all_involved_accounts.into_iter() {
                        let ledger_balance = env.rosetta_ledger_testing_envs[0]
                            .icrc1_ledger
                            .agent
                            .balance_of(account, icrc_ledger_agent::CallMode::Query)
                            .await
                            .unwrap()
                            .0
                            .to_u64()
                            .unwrap();
                        let current_block_index = env
                            .rosetta_client
                            .network_status(network_identifier.clone())
                            .await
                            .expect("Unable to call network_status")
                            .current_block_identifier
                            .index;
                        assert_rosetta_balance(
                            account,
                            current_block_index,
                            ledger_balance,
                            &env.rosetta_client,
                            network_identifier.clone(),
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
    let icrc1_ledger_1_builder =
        Icrc1LedgerBuilder::new(*TEST_LEDGER_CANISTER_ID).with_symbol("SYM1");

    let setup = Setup::builder()
        .add_icrc1_ledger_builder(icrc1_ledger_1_builder)
        .build(&rt);

    let rosetta_ledger_setup_builder =
        RosettaLedgerTestingEnvironmentBuilder::new(&setup.icrc1_ledgers[0], setup.port);

    rt.block_on(async {
        let env = RosettaTestingEnvironmentBuilder::new(false, setup.port)
            .add_rosetta_ledger_testing_env_builder(rosetta_ledger_setup_builder.clone())
            .build()
            .await;
        let network_identifier = env.rosetta_ledger_testing_envs[0]
            .network_identifier
            .clone();

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
                let block_index = env.rosetta_ledger_testing_envs[0]
                    .icrc1_ledger
                    .agent
                    .transfer(args.clone())
                    .await
                    .expect("sending transfer failed")
                    .expect("transfer resulted in an error");
                assert_eq!(block_index, last_block_idx_start + i + 1);
            }

            let last_block_idx = wait_for_rosetta_block(
                &env.rosetta_client,
                network_identifier.clone(),
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
                (*MINTING_IDENTITY).clone(),
                DEFAULT_TRANSFER_FEE,
                50,
                SystemTime::now(),
            )
            .no_shrink(),),
            |(args_with_caller,)| {
                let rt = Runtime::new().unwrap();
                let icrc1_ledger_1_builder = Icrc1LedgerBuilder::new(*TEST_LEDGER_CANISTER_ID)
                    .with_symbol("SYM1")
                    .with_decimals(6);
                let setup = Setup::builder()
                    .add_icrc1_ledger_builder(icrc1_ledger_1_builder)
                    .build(&rt);

                let rosetta_ledger_setup_builder = RosettaLedgerTestingEnvironmentBuilder::new(
                    &setup.icrc1_ledgers[0],
                    setup.port,
                )
                .with_icrc1_symbol("SYM1".to_string());

                rt.block_on(async {
                    let env = RosettaTestingEnvironmentBuilder::new(false, setup.port)
                        .add_rosetta_ledger_testing_env_builder(rosetta_ledger_setup_builder)
                        .build()
                        .await;
                    wait_for_rosetta_block(
                        &env.rosetta_client,
                        env.rosetta_ledger_testing_envs[0]
                            .network_identifier
                            .clone(),
                        0,
                    )
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
                            ic_icrc1::Operation::FeeCollector { .. } => None,
                        };

                        if matches!(
                            icrc1_transaction.operation,
                            ic_icrc1::Operation::Mint { .. } | ic_icrc1::Operation::Burn { .. }
                        ) {
                            let caller_agent = Icrc1Agent {
                                agent: get_custom_agent(arg_with_caller.caller.clone(), setup.port)
                                    .await,
                                ledger_canister_id: setup.icrc1_ledgers[0].canister_id,
                            };
                            match arg_with_caller.arg {
                                LedgerEndpointArg::TransferArg(transfer_arg) => {
                                    let _ = caller_agent
                                        .transfer(transfer_arg.clone())
                                        .await
                                        .unwrap()
                                        .unwrap();
                                }
                                _ => panic!("Expected TransferArg for Mint and Burns"),
                            }
                            continue;
                        }

                        let rosetta_core_operations = icrc1_operation_to_rosetta_core_operations(
                            icrc1_transaction.operation.clone().into(),
                            currency.clone(),
                            fee.map(|f| f.into()),
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
                                let from_balance = env.rosetta_ledger_testing_envs[0]
                                    .icrc1_ledger
                                    .agent
                                    .balance_of(from, icrc_ledger_agent::CallMode::Query)
                                    .await
                                    .unwrap();
                                let to_balance = env.rosetta_ledger_testing_envs[0]
                                    .icrc1_ledger
                                    .agent
                                    .balance_of(to, icrc_ledger_agent::CallMode::Query)
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
                                    let spender_balance = env.rosetta_ledger_testing_envs[0]
                                        .icrc1_ledger
                                        .agent
                                        .balance_of(spender, icrc_ledger_agent::CallMode::Query)
                                        .await
                                        .unwrap();
                                    account_balances.insert(spender, spender_balance);
                                }
                                account_balances
                            }
                            ic_icrc1::Operation::Approve { from, spender, .. } => {
                                let mut account_balances = HashMap::new();
                                let from_balance = env.rosetta_ledger_testing_envs[0]
                                    .icrc1_ledger
                                    .agent
                                    .balance_of(from, icrc_ledger_agent::CallMode::Query)
                                    .await
                                    .unwrap();
                                let spender_balance = env.rosetta_ledger_testing_envs[0]
                                    .icrc1_ledger
                                    .agent
                                    .balance_of(spender, icrc_ledger_agent::CallMode::Query)
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
                                env.rosetta_ledger_testing_envs[0]
                                    .network_identifier
                                    .clone(),
                                rosetta_core_operations.clone(),
                                None,
                                None,
                            )
                            .await
                            .unwrap();

                        for (account, expected_balance) in expected_balances.into_iter() {
                            let actual_balance = env.rosetta_ledger_testing_envs[0]
                                .icrc1_ledger
                                .agent
                                .balance_of(account, icrc_ledger_agent::CallMode::Query)
                                .await
                                .unwrap();
                            assert_eq!(actual_balance, expected_balance);
                        }
                    }
                });
                Ok(())
            },
        )
        .unwrap()
}

#[test]
fn test_rosetta_client_construction_api_flow() {
    let sender_keypair = Secp256k1KeyPair::generate(0);
    let receiver_keypair = Secp256k1KeyPair::generate(1);
    let rt = Runtime::new().unwrap();
    let icrc1_ledger_1_builder = Icrc1LedgerBuilder::new(*TEST_LEDGER_CANISTER_ID)
        .with_symbol("SYM1")
        .with_decimals(6)
        .with_initial_balance(
            sender_keypair.generate_principal_id().unwrap().0,
            1_000_000_000_000u64,
        );
    let setup = Setup::builder()
        .add_icrc1_ledger_builder(icrc1_ledger_1_builder)
        .build(&rt);

    let rosetta_ledger_setup_builder =
        RosettaLedgerTestingEnvironmentBuilder::new(&setup.icrc1_ledgers[0], setup.port)
            .with_icrc1_symbol("SYM1".to_string());

    rt.block_on(async {
        let env = RosettaTestingEnvironmentBuilder::new(false, setup.port)
            .add_rosetta_ledger_testing_env_builder(rosetta_ledger_setup_builder)
            .build()
            .await;
        wait_for_rosetta_block(
            &env.rosetta_client,
            env.rosetta_ledger_testing_envs[0]
                .network_identifier
                .clone(),
            0,
        )
        .await;

        let transfer_amount: Nat = 1_000_000_000u64.into();
        let operations = env
            .rosetta_client
            .build_transfer_operations(
                &sender_keypair,
                None,
                receiver_keypair.generate_principal_id().unwrap().0.into(),
                transfer_amount.clone(),
                env.rosetta_ledger_testing_envs[0]
                    .network_identifier
                    .clone(),
            )
            .await
            .unwrap();
        let balance_before_transfer = env.rosetta_ledger_testing_envs[0]
            .icrc1_ledger
            .agent
            .balance_of(
                sender_keypair.generate_principal_id().unwrap().0.into(),
                icrc_ledger_agent::CallMode::Query,
            )
            .await
            .unwrap();
        env.rosetta_client
            .make_submit_and_wait_for_transaction(
                &sender_keypair,
                env.rosetta_ledger_testing_envs[0]
                    .network_identifier
                    .clone(),
                operations,
                None,
                None,
            )
            .await
            .unwrap();
        let current_balance = env.rosetta_ledger_testing_envs[0]
            .icrc1_ledger
            .agent
            .balance_of(
                sender_keypair.generate_principal_id().unwrap().0.into(),
                icrc_ledger_agent::CallMode::Query,
            )
            .await
            .unwrap();
        assert_eq!(
            current_balance,
            balance_before_transfer - Nat::from(DEFAULT_TRANSFER_FEE) - transfer_amount
        );

        let approve_amount: Nat = 1_000_000_000u64.into();
        let operations = env
            .rosetta_client
            .build_approve_operations(
                &sender_keypair,
                None,
                receiver_keypair.generate_principal_id().unwrap().0.into(),
                approve_amount.clone(),
                None,
                env.rosetta_ledger_testing_envs[0]
                    .network_identifier
                    .clone(),
                None,
            )
            .await
            .unwrap();
        let balance_before_approve = env.rosetta_ledger_testing_envs[0]
            .icrc1_ledger
            .agent
            .balance_of(
                sender_keypair.generate_principal_id().unwrap().0.into(),
                icrc_ledger_agent::CallMode::Query,
            )
            .await
            .unwrap();
        env.rosetta_client
            .make_submit_and_wait_for_transaction(
                &sender_keypair,
                env.rosetta_ledger_testing_envs[0]
                    .network_identifier
                    .clone(),
                operations,
                None,
                None,
            )
            .await
            .unwrap();
        let current_balance = env.rosetta_ledger_testing_envs[0]
            .icrc1_ledger
            .agent
            .balance_of(
                sender_keypair.generate_principal_id().unwrap().0.into(),
                icrc_ledger_agent::CallMode::Query,
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
    let sender_keypair = EdKeypair::generate(0);
    let receiver_keypair = EdKeypair::generate(1);

    let sender_account = Account {
        owner: sender_keypair.generate_principal_id().unwrap().0,
        subaccount: Some([1; 32]),
    };
    let rt = Runtime::new().unwrap();
    let icrc1_ledger_1_builder = Icrc1LedgerBuilder::new(*TEST_LEDGER_CANISTER_ID)
        .with_symbol("SYM1")
        .with_initial_balance(sender_account, 1_000_000_000_000u64);
    let setup = Setup::builder()
        .add_icrc1_ledger_builder(icrc1_ledger_1_builder)
        .build(&rt);

    let rosetta_ledger_setup_builder =
        RosettaLedgerTestingEnvironmentBuilder::new(&setup.icrc1_ledgers[0], setup.port)
            .with_icrc1_symbol("SYM1".to_string());

    rt.block_on(async {
        let env = RosettaTestingEnvironmentBuilder::new(false, setup.port)
            .add_rosetta_ledger_testing_env_builder(rosetta_ledger_setup_builder)
            .build()
            .await;
        wait_for_rosetta_block(
            &env.rosetta_client,
            env.rosetta_ledger_testing_envs[0]
                .network_identifier
                .clone(),
            0,
        )
        .await;
        let transfer_amount: Nat = 1_000_000_000u64.into();
        let balance_before_transfer = env.rosetta_ledger_testing_envs[0]
            .icrc1_ledger
            .agent
            .balance_of(sender_account, icrc_ledger_agent::CallMode::Query)
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
        let current_balance = env.rosetta_ledger_testing_envs[0]
            .icrc1_ledger
            .agent
            .balance_of(sender_account, icrc_ledger_agent::CallMode::Query)
            .await
            .unwrap();
        assert_eq!(
            current_balance,
            balance_before_transfer - Nat::from(DEFAULT_TRANSFER_FEE) - transfer_amount
        );

        let approve_amount: Nat = 1_000_000_000u64.into();
        let balance_before_approve = env.rosetta_ledger_testing_envs[0]
            .icrc1_ledger
            .agent
            .balance_of(sender_account, icrc_ledger_agent::CallMode::Query)
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
        let current_balance = env.rosetta_ledger_testing_envs[0]
            .icrc1_ledger
            .agent
            .balance_of(sender_account, icrc_ledger_agent::CallMode::Query)
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
    let from_keypair = EdKeypair::generate(0);
    let to_keypair = EdKeypair::generate(1);
    let spender_keypair = EdKeypair::generate(2);

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
    let icrc1_ledger_1_builder = Icrc1LedgerBuilder::new(*TEST_LEDGER_CANISTER_ID)
        .with_symbol("SYM1")
        .with_initial_balance(from_account, 1_000_000_000_000u64);
    let setup = Setup::builder()
        .add_icrc1_ledger_builder(icrc1_ledger_1_builder)
        .build(&rt);
    let rosetta_ledger_setup_builder =
        RosettaLedgerTestingEnvironmentBuilder::new(&setup.icrc1_ledgers[0], setup.port)
            .with_icrc1_symbol("SYM1".to_string());
    rt.block_on(async {
        let env = RosettaTestingEnvironmentBuilder::new(false, setup.port)
            .add_rosetta_ledger_testing_env_builder(rosetta_ledger_setup_builder)
            .build()
            .await;
        wait_for_rosetta_block(
            &env.rosetta_client,
            env.rosetta_ledger_testing_envs[0]
                .network_identifier
                .clone(),
            0,
        )
        .await;
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
        let transfer_amount: Nat = 1_000u64.into();
        let balance_before_transfer = env.rosetta_ledger_testing_envs[0]
            .icrc1_ledger
            .agent
            .balance_of(from_account, icrc_ledger_agent::CallMode::Query)
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
        let current_balance = env.rosetta_ledger_testing_envs[0]
            .icrc1_ledger
            .agent
            .balance_of(from_account, icrc_ledger_agent::CallMode::Query)
            .await
            .unwrap();
        assert_eq!(
            current_balance,
            balance_before_transfer - Nat::from(DEFAULT_TRANSFER_FEE) - transfer_amount.clone()
        );
        let balance_receiver = env.rosetta_ledger_testing_envs[0]
            .icrc1_ledger
            .agent
            .balance_of(to_account, icrc_ledger_agent::CallMode::Query)
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
                let icrc1_ledger_1_builder = Icrc1LedgerBuilder::new(*TEST_LEDGER_CANISTER_ID)
                    .with_symbol("SYM1")
                    .with_decimals(6);
                let setup = Setup::builder()
                    .add_icrc1_ledger_builder(icrc1_ledger_1_builder)
                    .build(&rt);
                let rosetta_ledger_setup_builder = RosettaLedgerTestingEnvironmentBuilder::new(
                    &setup.icrc1_ledgers[0],
                    setup.port,
                )
                .with_args_with_caller(args_with_caller.clone())
                .with_icrc1_symbol("SYM1".to_string());
                rt.block_on(async {
                    let env = RosettaTestingEnvironmentBuilder::new(false, setup.port)
                        .add_rosetta_ledger_testing_env_builder(rosetta_ledger_setup_builder)
                        .build()
                        .await;
                    wait_for_rosetta_block(
                        &env.rosetta_client,
                        env.rosetta_ledger_testing_envs[0]
                            .network_identifier
                            .clone(),
                        0,
                    )
                    .await;
                    if !args_with_caller.is_empty() {
                        let rosetta_blocks = get_rosetta_blocks_from_icrc1_ledger(
                            env.rosetta_ledger_testing_envs[0]
                                .icrc1_ledger
                                .agent
                                .clone(),
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
                            network_identifier: env.rosetta_ledger_testing_envs[0]
                                .network_identifier
                                .clone(),
                            transaction_identifier: Some(transaction_identifier.clone()),
                            ..Default::default()
                        };
                        let search_transactions_response = env
                            .rosetta_client
                            .search_transactions(&search_transactions_request)
                            .await
                            .expect("Unable to call search_transactions");
                        for transaction in search_transactions_response.transactions.iter() {
                            assert_eq!(
                                transaction.transaction.transaction_identifier,
                                transaction_identifier
                            );
                        }
                    }
                });
                Ok(())
            },
        )
        .unwrap()
}

#[cfg(not(target_os = "macos"))]
#[test]
fn test_cli_data() {
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
                let rt = Runtime::new().unwrap();
                let icrc1_ledger_1_builder = Icrc1LedgerBuilder::new(*TEST_LEDGER_CANISTER_ID)
                    .with_symbol("SYM1")
                    .with_decimals(6);
                let setup = Setup::builder()
                    .add_icrc1_ledger_builder(icrc1_ledger_1_builder)
                    .build(&rt);
                let rosetta_ledger_setup_builder = RosettaLedgerTestingEnvironmentBuilder::new(
                    &setup.icrc1_ledgers[0],
                    setup.port,
                )
                .with_args_with_caller(args_with_caller.clone())
                .with_icrc1_symbol("SYM1".to_string());
                rt.block_on(async {
                    let env = RosettaTestingEnvironmentBuilder::new(false, setup.port)
                        .add_rosetta_ledger_testing_env_builder(rosetta_ledger_setup_builder)
                        .build()
                        .await;
                    wait_for_rosetta_block(
                        &env.rosetta_client,
                        env.rosetta_ledger_testing_envs[0]
                            .network_identifier
                            .clone(),
                        0,
                    )
                    .await;
                    let output = std::process::Command::new(rosetta_cli())
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
                        "rosetta-cli did not finish successfully: {}\n\nstdout: {}\n\nstderr: {}",
                        output.status,
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    );
                });
                Ok(())
            },
        )
        .unwrap()
}

#[test]
fn test_query_blocks_range() {
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
                let icrc1_ledger_1_builder = Icrc1LedgerBuilder::new(*TEST_LEDGER_CANISTER_ID)
                    .with_symbol("SYM1")
                    .with_decimals(6);
                let setup = Setup::builder()
                    .add_icrc1_ledger_builder(icrc1_ledger_1_builder)
                    .build(&rt);
                let rosetta_ledger_setup_builder = RosettaLedgerTestingEnvironmentBuilder::new(
                    &setup.icrc1_ledgers[0],
                    setup.port,
                )
                .with_args_with_caller(args_with_caller.clone())
                .with_icrc1_symbol("SYM1".to_string());
                rt.block_on(async {
                    let env = RosettaTestingEnvironmentBuilder::new(false, setup.port)
                        .add_rosetta_ledger_testing_env_builder(rosetta_ledger_setup_builder)
                        .build()
                        .await;
                    wait_for_rosetta_block(
                        &env.rosetta_client,
                        env.rosetta_ledger_testing_envs[0]
                            .network_identifier
                            .clone(),
                        0,
                    )
                    .await;
                    if !args_with_caller.is_empty() {
                        let rosetta_blocks = get_rosetta_blocks_from_icrc1_ledger(
                            env.rosetta_ledger_testing_envs[0]
                                .icrc1_ledger
                                .agent
                                .clone(),
                            0,
                            *MAX_BLOCKS_PER_REQUEST,
                        )
                        .await;

                        let highest_block_index = rosetta_blocks.last().unwrap().index;
                        let num_blocks = rosetta_blocks.len();
                        let query_blocks_request = QueryBlockRangeRequest {
                            highest_block_index,
                            number_of_blocks: num_blocks as u64,
                        };
                        let query_block_range_response: QueryBlockRangeResponse = env
                            .rosetta_client
                            .call(
                                env.rosetta_ledger_testing_envs[0]
                                    .network_identifier
                                    .clone(),
                                "query_block_range".to_owned(),
                                query_blocks_request.try_into().unwrap(),
                            )
                            .await
                            .unwrap()
                            .result
                            .try_into()
                            .unwrap();
                        assert_eq!(query_block_range_response.blocks.len(), num_blocks);
                        assert!(
                            query_block_range_response
                                .blocks
                                .iter()
                                .all(|block| block.block_identifier.index <= highest_block_index)
                        );
                    }
                });
                Ok(())
            },
        )
        .unwrap()
}
