use crate::common::local_replica;
use crate::common::local_replica::test_identity;
use crate::common::utils::get_rosetta_blocks_from_icrc1_ledger;
use candid::Encode;
use candid::Nat;
use candid::Principal;
use common::local_replica::get_custom_agent;
use ic_agent::agent::EnvelopeContent;
use ic_agent::identity::BasicIdentity;
use ic_agent::Identity;
use ic_base_types::CanisterId;
use ic_base_types::PrincipalId;
pub use ic_canister_client_sender::Ed25519KeyPair as EdKeypair;
use ic_icrc1_ledger::{InitArgs, InitArgsBuilder};
use ic_icrc1_test_utils::{
    minter_identity, valid_transactions_strategy, ArgWithCaller, LedgerEndpointArg,
    DEFAULT_TRANSFER_FEE,
};
use ic_icrc_rosetta::common::types::Error;
use ic_icrc_rosetta::common::utils::utils::icrc1_rosetta_block_to_rosetta_core_block;
use ic_icrc_rosetta::common::utils::utils::icrc1_rosetta_block_to_rosetta_core_transaction;
use ic_icrc_rosetta::construction_api::types::ConstructionMetadataRequestOptions;
use ic_icrc_rosetta::construction_api::types::UnsignedTransaction;
use ic_icrc_rosetta_client::RosettaClient;
use ic_icrc_rosetta_runner::{
    start_rosetta, RosettaContext, RosettaOptions, DEFAULT_DECIMAL_PLACES,
};
use ic_rosetta_api::DEFAULT_BLOCKCHAIN;
use ic_starter_tests::ReplicaContext;
use icrc_ledger_agent::CallMode;
use icrc_ledger_agent::Icrc1Agent;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::Memo;
use icrc_ledger_types::icrc1::transfer::TransferArg;
use lazy_static::lazy_static;
use num_traits::cast::ToPrimitive;
use proptest::prelude::ProptestConfig;
use proptest::proptest;
use rosetta_core::identifiers::*;
use rosetta_core::models::RosettaSupportedKeyPair;
use rosetta_core::objects::*;
use rosetta_core::request_types::*;
use rosetta_core::response_types::BlockResponse;
use rosetta_core::response_types::ConstructionPreprocessResponse;
use std::thread;
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime},
};
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

pub struct RosettaTestingEnvironment {
    // The '_' character is needed for the replica and rosetta context be allowed to never be used as the must not go out of scope and be killed.
    _replica_context: ReplicaContext,
    _rosetta_context: RosettaContext,
    rosetta_client: RosettaClient,
    icrc1_agent: Arc<Icrc1Agent>,
    icrc1_ledger_id: Principal,
    icrc1_ledger_init_args: InitArgs,
    network_identifier: NetworkIdentifier,
}

#[derive(Default)]
struct RosettaTestingEnvironmentBuilder {
    icrc1_ledger_init_arg_builder: Option<InitArgsBuilder>,
    transfer_args_for_block_generating: Option<Vec<ArgWithCaller>>,
    offline: bool,
}

impl RosettaTestingEnvironmentBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_init_args_builder(mut self, builder: InitArgsBuilder) -> Self {
        self.icrc1_ledger_init_arg_builder = Some(builder);
        self
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

        let replica_context = local_replica::start_new_local_replica().await;
        let replica_url = format!("http://localhost:{}", replica_context.port);

        // Deploy an ICRC-1 ledger canister
        let icrc1_ledger_init_args = match self.icrc1_ledger_init_arg_builder.clone() {
            None => local_replica::icrc_ledger_default_args_builder().build(),
            Some(builder) => builder.build(),
        };
        let icrc1_ledger_id = local_replica::deploy_icrc_ledger_with_custom_args(
            &replica_context,
            icrc1_ledger_init_args.clone(),
        )
        .await
        .into();

        if let Some(args) = &self.transfer_args_for_block_generating {
            for ArgWithCaller {
                caller,
                arg,
                principal_to_basic_identity: _,
            } in args.clone().into_iter()
            {
                let caller_agent = Icrc1Agent {
                    agent: get_custom_agent(caller.clone(), &replica_context).await,
                    ledger_canister_id: icrc1_ledger_id,
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
            agent: local_replica::get_testing_agent(&replica_context).await,
            ledger_canister_id: icrc1_ledger_id,
        });
        let rosetta_context = start_rosetta(
            &rosetta_bin(),
            RosettaOptions {
                ledger_id: icrc1_ledger_id,
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
            CanisterId::try_from(PrincipalId(icrc1_ledger_id))
                .unwrap()
                .to_string(),
        );

        // Wait for rosetta to catch up with the ledger
        if let Some(last_block_idx) = block_idxes.last() {
            while rosetta_client
                .block(
                    network_identifier.clone(),
                    PartialBlockIdentifier {
                        index: Some(*last_block_idx),
                        hash: None,
                    },
                )
                .await
                .unwrap()
                .block
                .is_none()
            {
                thread::sleep(Duration::from_secs(1));
            }
        }

        RosettaTestingEnvironment {
            _replica_context: replica_context,
            _rosetta_context: rosetta_context,
            rosetta_client,
            icrc1_agent,
            icrc1_ledger_id,
            icrc1_ledger_init_args,
            network_identifier,
        }
    }
}

#[tokio::test]
async fn test_network_list() {
    let env = RosettaTestingEnvironmentBuilder::new()
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

    // Wrap async calls in a blocking Block
    rt.block_on(async {
        let env = RosettaTestingEnvironmentBuilder::new()
            .with_args_with_caller(args_with_caller.clone())
            .with_init_args_builder(local_replica::icrc_ledger_default_args_builder().with_minting_account((*MINTING_IDENTITY).clone().sender().unwrap()))
            .build()
            .await;

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
            hex::encode(rosetta_blocks.first().unwrap().block_hash.clone()),
            rosetta_response.genesis_block_identifier.hash,
            "Genesis block hashes do not match"
        );
        assert_eq!(
            hex::encode(rosetta_blocks.last().unwrap().block_hash.clone()),
            rosetta_response.current_block_identifier.hash,
            "Current block hashes do not match"
        );
        assert_eq!(
            hex::encode(rosetta_blocks.first().unwrap().block_hash.clone()),
            rosetta_response.oldest_block_identifier.unwrap().hash,
            "Genesis block hashes do not match"
        );
        assert_eq!(
            Duration::from_nanos(rosetta_blocks.last().unwrap().timestamp).as_millis() as u64,
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

    // Wrap async calls in a blocking Block
     rt.block_on(async {
        let env = RosettaTestingEnvironmentBuilder::new()
            .with_args_with_caller(args_with_caller.clone())
            .with_init_args_builder(local_replica::icrc_ledger_default_args_builder().with_minting_account((*MINTING_IDENTITY).clone().sender().unwrap()))
            .build()
            .await;

        if !args_with_caller.is_empty(){

    for block in get_rosetta_blocks_from_icrc1_ledger(env.icrc1_agent,0,*MAX_BLOCKS_PER_REQUEST).await.into_iter(){
        let expected_block_response = BlockResponse::new(
            Some(
                icrc1_rosetta_block_to_rosetta_core_block(block.clone(), Currency {
                    symbol: env.icrc1_ledger_init_args.token_symbol.clone(),
                    decimals: env.icrc1_ledger_init_args
                    .decimals
                    .unwrap_or(DEFAULT_DECIMAL_PLACES) as u32,
                    ..Default::default()
                }).unwrap(),
            ));

        assert_eq!(hex::encode(block.block_hash.clone()),expected_block_response.clone().block.unwrap().block_identifier.hash);
                // Rosetta should be able to handle blockidentifieres with both the hash and the block index set
        let actual_block_response = env.rosetta_client.block(env.network_identifier.clone(), PartialBlockIdentifier{
            hash:Some(hex::encode(block.block_hash.clone())),
            index:Some(block.index)
        })
        .await
        .expect("Failed to find block in Rosetta");
        assert_eq!(expected_block_response,actual_block_response);

        // Rosetta should be able to handle blockidentifieres with only the hash set
        let actual_block_response = env.rosetta_client.block(env.network_identifier.clone(), PartialBlockIdentifier{
            hash:Some(hex::encode(block.block_hash)),
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

        // If no hash was provided rosetta should return an error
        assert!(env.rosetta_client.block(env.network_identifier.clone(), PartialBlockIdentifier{
            hash:None,
            index:None
        })
        .await.is_err());
    }}
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

    // Wrap async calls in a blocking Block
     rt.block_on(async {
        let env = RosettaTestingEnvironmentBuilder::new()
            .with_args_with_caller(args_with_caller.clone())
            .with_init_args_builder(local_replica::icrc_ledger_default_args_builder().with_minting_account((*MINTING_IDENTITY).clone().sender().unwrap()))
            .build()
            .await;

        if !args_with_caller.is_empty(){

    for block in get_rosetta_blocks_from_icrc1_ledger(env.icrc1_agent,0,*MAX_BLOCKS_PER_REQUEST).await.into_iter(){
        let expected_block_transaction_response =   rosetta_core::response_types::BlockTransactionResponse {
            transaction: icrc1_rosetta_block_to_rosetta_core_transaction(block.clone(), Currency {
                symbol: env.icrc1_ledger_init_args.token_symbol.clone(),
                decimals: env.icrc1_ledger_init_args
                .decimals
                .unwrap_or(DEFAULT_DECIMAL_PLACES) as u32,
                ..Default::default()
            }).unwrap()};

        assert_eq!(hex::encode(block.transaction_hash.clone()),expected_block_transaction_response.clone().transaction.transaction_identifier.hash);

                // Rosetta should be able to handle blockidentifieres with both the hash and the block index set
        let actual_block_transaction_response = env.rosetta_client.block_transaction(env.network_identifier.clone(),
            BlockIdentifier {
                            index: block.index,
                            hash: hex::encode(block.block_hash.clone()),

        }, TransactionIdentifier{ hash: hex::encode(block.transaction_hash.clone()) })
        .await
        .expect("Failed to find block in Rosetta");
        assert_eq!(expected_block_transaction_response,actual_block_transaction_response);

        assert!(env.rosetta_client.block_transaction(env.network_identifier.clone(),
        BlockIdentifier {
                        index: u64::MAX,
                        hash: hex::encode(block.block_hash.clone()),

    }, TransactionIdentifier{ hash: hex::encode(block.transaction_hash.clone()) })
    .await.is_err());

    assert!(env.rosetta_client.block_transaction(env.network_identifier.clone(),
    BlockIdentifier {
                    index: block.index,
                    hash: hex::encode("wrong hash"),

    }, TransactionIdentifier{ hash: hex::encode(block.transaction_hash) })
    .await.is_err());

    assert!(env.rosetta_client.block_transaction(env.network_identifier.clone(),
        BlockIdentifier {
                        index: block.index,
                        hash: hex::encode(block.block_hash),

}, TransactionIdentifier{ hash: hex::encode("wrong tx hash") })
.await.is_err());
    }
}
 });
 }
}

#[tokio::test]
async fn test_mempool() {
    let env = RosettaTestingEnvironmentBuilder::new().build().await;

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
}

#[tokio::test]
async fn test_construction_preprocess() {
    let env = RosettaTestingEnvironmentBuilder::new().build().await;

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
}

#[tokio::test]
async fn test_construction_derive() {
    let env = RosettaTestingEnvironmentBuilder::new().build().await;

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
}

#[tokio::test]
async fn test_construction_submit() {
    let keypair = EdKeypair::generate_from_u64(0);

    let env = RosettaTestingEnvironmentBuilder::new()
        .with_init_args_builder(
            local_replica::icrc_ledger_default_args_builder()
                .with_minting_account((*MINTING_IDENTITY).clone().sender().unwrap())
                .with_initial_balance(
                    keypair.generate_principal_id().unwrap().0,
                    1_000_000_000_000u64,
                ),
        )
        .build()
        .await;

    let transfer_arg = TransferArg {
        to: (*MINTING_IDENTITY).clone().sender().unwrap().into(),
        // Transfer Fee is the minimum burn amount
        amount: Nat::from(DEFAULT_TRANSFER_FEE),
        memo: Some(Memo::default()),
        from_subaccount: None,
        fee: None,
        created_at_time: None,
    };

    let ingress_expiry = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .saturating_add(Duration::from_secs(4 * 60))
        .as_nanos()
        .to_u64()
        .unwrap();

    let sender = keypair.generate_principal_id().unwrap().0;

    let call_envelope_content = EnvelopeContent::Call {
        nonce: None,
        ingress_expiry,
        sender,
        canister_id: env.icrc1_ledger_id,
        method_name: "icrc1_transfer".to_owned(),
        arg: Encode!(&transfer_arg).unwrap(),
    };
    let call_envelope_request_id = call_envelope_content.to_request_id();
    let call_envelope_signable_bytes = call_envelope_request_id.signable();
    let call_envelope_signature = Signature {
        signing_payload: SigningPayload {
            address: None,
            hex_bytes: hex::encode(call_envelope_signable_bytes.clone()),
            signature_type: Some(SignatureType::Ed25519),
            account_identifier: Some(
                Account::from(keypair.generate_principal_id().unwrap().0).into(),
            ),
        },
        public_key: (&keypair).into(),
        signature_type: SignatureType::Ed25519,
        hex_bytes: hex::encode(keypair.sign(&call_envelope_signable_bytes)),
    };

    let read_state_envelope_content = EnvelopeContent::ReadState {
        ingress_expiry,
        sender,
        paths: vec![vec![
            "request_status".into(),
            call_envelope_request_id.to_vec().into(),
        ]],
    };
    let read_state_envelope_signable_bytes = read_state_envelope_content.to_request_id().signable();
    let read_state_envelope_signature = Signature {
        signing_payload: SigningPayload {
            address: None,
            hex_bytes: hex::encode(read_state_envelope_signable_bytes.clone()),
            signature_type: Some(SignatureType::Ed25519),
            account_identifier: Some(
                Account::from(keypair.generate_principal_id().unwrap().0).into(),
            ),
        },
        public_key: (&keypair).into(),
        signature_type: SignatureType::Ed25519,
        hex_bytes: hex::encode(keypair.sign(&read_state_envelope_signable_bytes)),
    };

    let unsinged_transaction = UnsignedTransaction {
        envelope_contents: vec![
            call_envelope_content.clone(),
            read_state_envelope_content.clone(),
        ],
    };

    let signatures = vec![call_envelope_signature, read_state_envelope_signature];

    let construction_combine_response = env
        .rosetta_client
        .construction_combine(
            env.network_identifier.clone(),
            unsinged_transaction.to_string(),
            signatures,
        )
        .await
        .expect("Unable to call /construction/combine");

    let signed_transaction = construction_combine_response.signed_transaction;

    let balance_before_transfer = env
        .icrc1_agent
        .balance_of(
            keypair.generate_principal_id().unwrap().0.into(),
            CallMode::Query,
        )
        .await
        .unwrap();

    let construction_submit_response = env
        .rosetta_client
        .construction_submit(
            env.network_identifier.clone(),
            signed_transaction.to_string(),
        )
        .await
        .expect("Unable to call /construction/submit");

    let construction_hash_response = env
        .rosetta_client
        .construction_hash(env.network_identifier, signed_transaction.to_string())
        .await
        .expect("Unable to call /construction/hash");

    assert_eq!(
        construction_submit_response.transaction_identifier.hash,
        construction_hash_response.transaction_identifier.hash
    );

    let current_balance = env
        .icrc1_agent
        .balance_of(
            keypair.generate_principal_id().unwrap().0.into(),
            CallMode::Query,
        )
        .await
        .unwrap();

    // Since we do not yet get the actual response back from the submit endpoint, we need to check that the transaction was successful by confirming the balance change
    assert_eq!(
        current_balance,
        balance_before_transfer - Nat::from(DEFAULT_TRANSFER_FEE)
    );
}
