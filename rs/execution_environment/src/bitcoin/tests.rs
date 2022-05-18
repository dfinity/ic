use crate::{ExecutionEnvironment, ExecutionEnvironmentImpl, Hypervisor, IngressHistoryWriterImpl};
use bitcoin::{Address, Network};
use candid::Encode;
use ic_btc_test_utils::{random_p2pkh_address, BlockBuilder, TransactionBuilder};
use ic_btc_types::{GetUtxosResponse, OutPoint, Satoshi, Utxo, UtxosFilter};
use ic_config::execution_environment;
use ic_error_types::{ErrorCode, RejectCode, UserError};
use ic_ic00_types::{
    self as ic00, BitcoinGetBalanceArgs, BitcoinGetUtxosArgs, BitcoinNetwork, Method,
    Payload as Ic00Payload,
};
use ic_interfaces::execution_environment::SubnetAvailableMemory;
use ic_interfaces::{execution_environment::AvailableMemory, messages::CanisterInputMessage};
use ic_metrics::MetricsRegistry;
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
use ic_registry_subnet_features::BitcoinFeature;
use ic_registry_subnet_features::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    bitcoin_state::BitcoinState,
    testing::{CanisterQueuesTesting, ReplicatedStateTesting},
    ReplicatedState,
};
use ic_replicated_state::{
    canister_state::QUEUE_INDEX_NONE, InputQueueType, NetworkTopology, SubnetTopology,
};
use ic_test_utilities::{
    crypto::mock_random_number_generator,
    cycles_account_manager::CyclesAccountManagerBuilder,
    mock_time,
    state::{CanisterStateBuilder, ReplicatedStateBuilder},
    types::{
        ids::{canister_test_id, message_test_id, subnet_test_id, user_test_id},
        messages::{IngressBuilder, RequestBuilder, ResponseBuilder},
    },
    with_test_replica_logger,
};
use ic_types::{
    ingress::{IngressState, IngressStatus, WasmResult},
    messages::{MessageId, Payload, RejectContext, RequestOrResponse},
    CanisterId, NumInstructions, SubnetId, UserId,
};
use lazy_static::lazy_static;
use maplit::btreemap;
use std::str::FromStr;
use std::{collections::BTreeSet, convert::TryFrom, sync::Arc};
use tempfile::TempDir;

const MAX_NUM_INSTRUCTIONS: NumInstructions = NumInstructions::new(1_000_000_000);
lazy_static! {
    static ref MAX_SUBNET_AVAILABLE_MEMORY: SubnetAvailableMemory =
        AvailableMemory::new(i64::MAX / 2, i64::MAX / 2).into();
}
const MAX_NUMBER_OF_CANISTERS: u64 = 0;

// TODO(EXC-1120): This is copied from `tests/execution_environment.rs`.
// Refactor the code so that this method is defined only once.
fn initial_state(
    subnet_type: SubnetType,
) -> (TempDir, SubnetId, Arc<NetworkTopology>, ReplicatedState) {
    let tmpdir = tempfile::Builder::new().prefix("test").tempdir().unwrap();
    let subnet_id = subnet_test_id(1);
    let routing_table = Arc::new(
        RoutingTable::try_from(btreemap! {
            CanisterIdRange{ start: CanisterId::from(0), end: CanisterId::from(0xff) } => subnet_id,
        })
        .unwrap(),
    );
    let mut replicated_state = ReplicatedState::new_rooted_at(
        subnet_id,
        SubnetType::Application,
        tmpdir.path().to_path_buf(),
    );
    replicated_state.metadata.network_topology.routing_table = Arc::clone(&routing_table);
    replicated_state.metadata.network_topology.subnets.insert(
        subnet_id,
        SubnetTopology {
            subnet_type,
            ..SubnetTopology::default()
        },
    );
    (
        tmpdir,
        subnet_id,
        Arc::new(replicated_state.metadata.network_topology.clone()),
        replicated_state,
    )
}

// TODO(EXC-1120): This is copied from `tests/execution_environment.rs`.
// Refactor the code so that this method is defined only once.
fn with_setup<F>(subnet_type: SubnetType, f: F)
where
    F: FnOnce(ExecutionEnvironmentImpl, ReplicatedState, SubnetId, Arc<NetworkTopology>),
{
    with_test_replica_logger(|log| {
        let (_, subnet_id, network_topology, state) = initial_state(subnet_type);
        let metrics_registry = MetricsRegistry::new();
        let cycles_account_manager = Arc::new(
            CyclesAccountManagerBuilder::new()
                .with_subnet_id(subnet_id)
                .build(),
        );
        let hypervisor = Hypervisor::new(
            execution_environment::Config::default(),
            &metrics_registry,
            subnet_id,
            subnet_type,
            log.clone(),
            Arc::clone(&cycles_account_manager),
        );
        let hypervisor = Arc::new(hypervisor);
        let ingress_history_writer = IngressHistoryWriterImpl::new(
            execution_environment::Config::default(),
            log.clone(),
            &metrics_registry,
        );
        let ingress_history_writer = Arc::new(ingress_history_writer);
        let exec_env = ExecutionEnvironmentImpl::new(
            log,
            hypervisor,
            ingress_history_writer,
            &metrics_registry,
            subnet_id,
            subnet_type,
            1,
            execution_environment::Config::default(),
            cycles_account_manager,
        );
        f(exec_env, state, subnet_id, network_topology)
    });
}

fn execute_get_balance(
    message_id: MessageId,
    exec_env: &ExecutionEnvironmentImpl,
    state: ReplicatedState,
    sender: UserId,
    receiver: CanisterId,
    address: String,
    network: BitcoinNetwork,
    min_confirmations: Option<u32>,
) -> ReplicatedState {
    let bitcoin_get_balance_args = BitcoinGetBalanceArgs {
        address,
        network,
        min_confirmations,
    };
    let state = exec_env
        .execute_subnet_message(
            CanisterInputMessage::Ingress(
                IngressBuilder::new()
                    .message_id(message_id)
                    .source(sender)
                    .receiver(receiver)
                    .method_name(Method::BitcoinGetBalance)
                    .method_payload(bitcoin_get_balance_args.encode())
                    .build(),
            ),
            state,
            MAX_NUM_INSTRUCTIONS,
            &mut mock_random_number_generator(),
            &None,
            &ProvisionalWhitelist::Set(BTreeSet::new()),
            MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            MAX_NUMBER_OF_CANISTERS,
        )
        .0;
    state
}

fn execute_get_utxos(
    exec_env: &ExecutionEnvironmentImpl,
    bitcoin_get_utxos_args: BitcoinGetUtxosArgs,
    bitcoin_feature: &str,
    bitcoin_state: BitcoinState,
    expected_payload: Payload,
) {
    let mut state = ReplicatedStateBuilder::new()
        .with_subnet_id(subnet_test_id(1))
        .with_canister(
            CanisterStateBuilder::new()
                .with_canister_id(canister_test_id(0))
                .build(),
        )
        .with_subnet_features(SubnetFeatures::from_str(bitcoin_feature).unwrap())
        .with_bitcoin_state(bitcoin_state)
        .build();

    state
        .subnet_queues_mut()
        .push_input(
            QUEUE_INDEX_NONE,
            RequestOrResponse::Request(
                RequestBuilder::new()
                    .sender(canister_test_id(0))
                    .receiver(ic00::IC_00)
                    .method_name(Method::BitcoinGetUtxos)
                    .method_payload(bitcoin_get_utxos_args.encode())
                    .build(),
            ),
            InputQueueType::RemoteSubnet,
        )
        .unwrap();

    let mut state = exec_env
        .execute_subnet_message(
            state.subnet_queues_mut().pop_input().unwrap(),
            state,
            MAX_NUM_INSTRUCTIONS,
            &mut mock_random_number_generator(),
            &None,
            &ProvisionalWhitelist::Set(BTreeSet::new()),
            MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            MAX_NUMBER_OF_CANISTERS,
        )
        .0;

    let subnet_id = subnet_test_id(1);
    assert_eq!(
        state
            .subnet_queues_mut()
            .pop_canister_output(&canister_test_id(0))
            .unwrap()
            .1,
        RequestOrResponse::Response(
            ResponseBuilder::new()
                .originator(canister_test_id(0))
                .respondent(CanisterId::new(subnet_id.get()).unwrap())
                .response_payload(expected_payload)
                .build()
        )
    );
}

#[test]
fn get_balance_feature_not_enabled() {
    with_setup(SubnetType::Application, |exec_env, mut state, _, _| {
        // Disable bitcoin testnet feature.
        state.metadata.own_subnet_features.bitcoin_testnet_feature = Some(BitcoinFeature::Disabled);
        let sender = user_test_id(1);
        let receiver = ic00::IC_00;
        let network = BitcoinNetwork::Testnet;
        let address = String::from("not an address");
        let min_confirmations = None;

        let state = execute_get_balance(
            message_test_id(0),
            &exec_env,
            state,
            sender,
            receiver,
            address,
            network,
            min_confirmations,
        );

        assert_eq!(
            state.get_ingress_status(&message_test_id(0)),
            IngressStatus::Known {
                receiver: receiver.get(),
                user_id: sender,
                time: mock_time(),
                state: IngressState::Failed(UserError::new(
                    ErrorCode::CanisterRejectedMessage,
                    "The bitcoin API is not enabled on this subnet.",
                )),
            }
        );
    });
}

#[test]
fn get_balance_mainnet_rejected() {
    with_setup(SubnetType::Application, |exec_env, mut state, _, _| {
        state.metadata.own_subnet_features.bitcoin_testnet_feature = Some(BitcoinFeature::Enabled);
        let sender = user_test_id(1);
        let receiver = ic00::IC_00;
        let network = BitcoinNetwork::Mainnet;
        let address = String::from("not an address");
        let min_confirmations = None;

        let state = execute_get_balance(
            message_test_id(0),
            &exec_env,
            state,
            sender,
            receiver,
            address,
            network,
            min_confirmations,
        );

        assert_eq!(
            state.get_ingress_status(&message_test_id(0)),
            IngressStatus::Known {
                receiver: receiver.get(),
                user_id: sender,
                time: mock_time(),
                state: IngressState::Failed(UserError::new(
                    ErrorCode::CanisterRejectedMessage,
                    "The bitcoin_get_balance API supports only the Testnet network.",
                )),
            }
        );
    });
}

#[test]
fn get_balance_api_rejects_malformed_address() {
    with_setup(SubnetType::Application, |exec_env, mut state, _, _| {
        state.metadata.own_subnet_features.bitcoin_testnet_feature = Some(BitcoinFeature::Enabled);
        let sender = user_test_id(1);
        let receiver = ic00::IC_00;
        let network = BitcoinNetwork::Testnet;
        let address = String::from("not an address");
        let min_confirmations = None;

        let state = execute_get_balance(
            message_test_id(0),
            &exec_env,
            state,
            sender,
            receiver,
            address,
            network,
            min_confirmations,
        );

        assert_eq!(
            state.get_ingress_status(&message_test_id(0)),
            IngressStatus::Known {
                receiver: receiver.get(),
                user_id: sender,
                time: mock_time(),
                state: IngressState::Failed(UserError::new(
                    ErrorCode::CanisterRejectedMessage,
                    "bitcoin_get_balance failed: Malformed address.",
                )),
            }
        );
    });
}

fn state_with_balance(
    network: Network,
    satoshi: Satoshi,
    address_1: &Address,
    address_2: &Address,
) -> ic_btc_canister::state::State {
    // Create a genesis block where the provided satoshis are given to the address_1, followed
    // by a block where address_1 transfers the satoshis to address_2.
    let coinbase_tx = TransactionBuilder::coinbase()
        .with_output(address_1, satoshi)
        .build();
    let block_0 = BlockBuilder::genesis()
        .with_transaction(coinbase_tx.clone())
        .build();
    let tx = TransactionBuilder::with_input(bitcoin::OutPoint::new(coinbase_tx.txid(), 0))
        .with_output(address_2, satoshi)
        .build();
    let block_1 = BlockBuilder::with_prev_header(block_0.header)
        .with_transaction(tx)
        .build();

    let mut state = ic_btc_canister::state::State::new(2, network, block_0);
    ic_btc_canister::store::insert_block(&mut state, block_1).unwrap();
    state
}

#[test]
fn get_balance_single_request_succeeds() {
    with_setup(SubnetType::Application, |exec_env, mut state, _, _| {
        state.metadata.own_subnet_features.bitcoin_testnet_feature = Some(BitcoinFeature::Enabled);
        let sender = user_test_id(1);
        let receiver = ic00::IC_00;
        let (network, btc_network) = (BitcoinNetwork::Testnet, Network::Testnet);
        let address_1 = random_p2pkh_address(btc_network);
        let address_2 = random_p2pkh_address(btc_network);
        let min_confirmations = None;
        let satoshi: Satoshi = 123;
        state.put_bitcoin_state(BitcoinState::from(state_with_balance(
            btc_network,
            satoshi,
            &address_1,
            &address_2,
        )));

        let state = execute_get_balance(
            message_test_id(0),
            &exec_env,
            state,
            sender,
            receiver,
            address_2.to_string(),
            network,
            min_confirmations,
        );

        let satoshi_response: Satoshi = 123;
        let expected_balance_payload = Encode!(&candid::Nat::from(satoshi_response)).unwrap();
        assert_eq!(
            state.get_ingress_status(&message_test_id(0)),
            IngressStatus::Known {
                receiver: receiver.get(),
                user_id: sender,
                time: mock_time(),
                state: IngressState::Completed(WasmResult::Reply(expected_balance_payload)),
            }
        );
    });
}

#[test]
fn get_balance_repeated_request_succeeded() {
    with_setup(SubnetType::Application, |exec_env, mut state, _, _| {
        state.metadata.own_subnet_features.bitcoin_testnet_feature = Some(BitcoinFeature::Enabled);
        let sender = user_test_id(1);
        let receiver = ic00::IC_00;
        let (network, btc_network) = (BitcoinNetwork::Testnet, Network::Testnet);
        let address_1 = random_p2pkh_address(btc_network);
        let address_2 = random_p2pkh_address(btc_network);
        let min_confirmations = None;
        let satoshi: Satoshi = 123;
        state.put_bitcoin_state(BitcoinState::from(state_with_balance(
            btc_network,
            satoshi,
            &address_1,
            &address_2,
        )));

        // First requrest.
        let state = execute_get_balance(
            message_test_id(0),
            &exec_env,
            state,
            sender,
            receiver,
            address_2.to_string(),
            network,
            min_confirmations,
        );
        // Second requrest.
        let state = execute_get_balance(
            message_test_id(1),
            &exec_env,
            state,
            sender,
            receiver,
            address_2.to_string(),
            network,
            min_confirmations,
        );

        let satoshi_response: Satoshi = 123;
        let expected_balance_payload = Encode!(&candid::Nat::from(satoshi_response)).unwrap();
        assert_eq!(
            state.get_ingress_status(&message_test_id(1)),
            IngressStatus::Known {
                receiver: receiver.get(),
                user_id: sender,
                time: mock_time(),
                state: IngressState::Completed(WasmResult::Reply(expected_balance_payload)),
            }
        );
    });
}

#[test]
fn get_balance_with_min_confirmations_1() {
    with_setup(SubnetType::Application, |exec_env, mut state, _, _| {
        state.metadata.own_subnet_features.bitcoin_testnet_feature = Some(BitcoinFeature::Enabled);
        let sender = user_test_id(1);
        let receiver = ic00::IC_00;
        let (network, btc_network) = (BitcoinNetwork::Testnet, Network::Testnet);
        let address_1 = random_p2pkh_address(btc_network);
        let address_2 = random_p2pkh_address(btc_network);
        let min_confirmations = Some(1);
        let satoshi: Satoshi = 123;
        state.put_bitcoin_state(BitcoinState::from(state_with_balance(
            btc_network,
            satoshi,
            &address_1,
            &address_2,
        )));

        let state = execute_get_balance(
            message_test_id(0),
            &exec_env,
            state,
            sender,
            receiver,
            address_2.to_string(),
            network,
            min_confirmations,
        );

        let satoshi_response: Satoshi = 123;
        let expected_balance_payload = Encode!(&candid::Nat::from(satoshi_response)).unwrap();
        assert_eq!(
            state.get_ingress_status(&message_test_id(0)),
            IngressStatus::Known {
                receiver: receiver.get(),
                user_id: sender,
                time: mock_time(),
                state: IngressState::Completed(WasmResult::Reply(expected_balance_payload)),
            }
        );
    });
}

#[test]
fn get_balance_with_min_confirmations_2() {
    with_setup(SubnetType::Application, |exec_env, mut state, _, _| {
        state.metadata.own_subnet_features.bitcoin_testnet_feature = Some(BitcoinFeature::Enabled);
        let sender = user_test_id(1);
        let receiver = ic00::IC_00;
        let (network, btc_network) = (BitcoinNetwork::Testnet, Network::Testnet);
        let address_1 = random_p2pkh_address(btc_network);
        let address_2 = random_p2pkh_address(btc_network);
        let min_confirmations = Some(2);
        let satoshi: Satoshi = 123;
        state.put_bitcoin_state(BitcoinState::from(state_with_balance(
            btc_network,
            satoshi,
            &address_1,
            &address_2,
        )));

        let state = execute_get_balance(
            message_test_id(0),
            &exec_env,
            state,
            sender,
            receiver,
            address_2.to_string(),
            network,
            min_confirmations,
        );

        let satoshi_response: Satoshi = 0;
        let expected_balance_payload = Encode!(&candid::Nat::from(satoshi_response)).unwrap();
        assert_eq!(
            state.get_ingress_status(&message_test_id(0)),
            IngressStatus::Known {
                receiver: receiver.get(),
                user_id: sender,
                time: mock_time(),
                state: IngressState::Completed(WasmResult::Reply(expected_balance_payload)),
            }
        );
    });
}

#[test]
fn get_balance_rejects_large_min_confirmations() {
    with_setup(SubnetType::Application, |exec_env, mut state, _, _| {
        state.metadata.own_subnet_features.bitcoin_testnet_feature = Some(BitcoinFeature::Enabled);
        let sender = user_test_id(1);
        let receiver = ic00::IC_00;
        let (network, btc_network) = (BitcoinNetwork::Testnet, Network::Testnet);
        let satoshi: Satoshi = 123;
        let address_1 = random_p2pkh_address(btc_network);
        let address_2 = random_p2pkh_address(btc_network);
        state.put_bitcoin_state(BitcoinState::from(state_with_balance(
            btc_network,
            satoshi,
            &address_1,
            &address_2,
        )));

        let state = execute_get_balance(
            message_test_id(0),
            &exec_env,
            state,
            sender,
            receiver,
            address_2.to_string(),
            network,
            Some(1000), // A large value of min_confirmations
        );

        assert_eq!(
            state.get_ingress_status(&message_test_id(0)),
            IngressStatus::Known {
                receiver: receiver.get(),
                user_id: sender,
                time: mock_time(),
                state: IngressState::Failed(UserError::new(
                    ErrorCode::CanisterRejectedMessage,
                    "bitcoin_get_balance failed: The requested min_confirmations is too large. Given: 1000, max supported: 2"
                )),
            }
        );
    });
}

#[test]
fn get_utxos_rejects_if_feature_not_enabled() {
    with_setup(SubnetType::Application, |exec_env, _, _, _| {
        let network = BitcoinNetwork::Testnet;
        let address = String::from("not an address");

        let bitcoin_get_utxos_args = BitcoinGetUtxosArgs {
            address,
            network,
            filter: None,
        };

        execute_get_utxos(
            &exec_env,
            bitcoin_get_utxos_args,
            "None", // Bitcoin feature is disabled.
            BitcoinState::default(),
            Payload::Reject(RejectContext {
                code: RejectCode::CanisterReject,
                message: String::from("The bitcoin API is not enabled on this subnet."),
            }),
        );
    });
}

#[test]
fn get_utxos_rejects_if_address_is_malformed() {
    with_setup(SubnetType::Application, |exec_env, _, _, _| {
        let bitcoin_get_utxos_args = BitcoinGetUtxosArgs {
            address: String::from("not an address"),
            network: BitcoinNetwork::Testnet,
            filter: None,
        };

        execute_get_utxos(
            &exec_env,
            bitcoin_get_utxos_args,
            "bitcoin_testnet", // Bitcoin testnet is enabled.
            BitcoinState::default(),
            Payload::Reject(RejectContext {
                code: RejectCode::CanisterReject,
                message: String::from("bitcoin_get_utxos failed: Malformed address."),
            }),
        );
    });
}

#[test]
fn get_utxos_rejects_large_min_confirmations() {
    with_setup(SubnetType::Application, |exec_env, _, _, _| {
        let bitcoin_get_utxos_args = BitcoinGetUtxosArgs {
            address: random_p2pkh_address(Network::Testnet).to_string(),
            network: BitcoinNetwork::Testnet,
            filter: Some(UtxosFilter::MinConfirmations(1000)),
        };

        execute_get_utxos(
            &exec_env,
            bitcoin_get_utxos_args,
            "bitcoin_testnet", // Bitcoin testnet is enabled.
            BitcoinState::default(),
            Payload::Reject(RejectContext {
                code: RejectCode::CanisterReject,
                message: String::from("bitcoin_get_utxos failed: The requested min_confirmations is too large. Given: 1000, max supported: 1")
            }),
        );
    });
}

#[test]
fn get_utxos_of_valid_request_succeeds() {
    with_setup(SubnetType::Application, |exec_env, _, _, _| {
        let address = random_p2pkh_address(Network::Testnet);

        let coinbase_tx = TransactionBuilder::coinbase()
            .with_output(&address, 1000)
            .build();
        let block_0 = BlockBuilder::genesis()
            .with_transaction(coinbase_tx.clone())
            .build();

        let bitcoin_state = BitcoinState::from(ic_btc_canister::state::State::new(
            2,
            Network::Testnet,
            block_0.clone(),
        ));

        let bitcoin_get_utxos_args = BitcoinGetUtxosArgs {
            address: address.to_string(),
            network: BitcoinNetwork::Testnet,
            filter: Some(UtxosFilter::MinConfirmations(1)),
        };

        execute_get_utxos(
            &exec_env,
            bitcoin_get_utxos_args,
            "bitcoin_testnet", // Bitcoin testnet is enabled.
            bitcoin_state,
            Payload::Data(
                Encode!(&GetUtxosResponse {
                    utxos: vec![Utxo {
                        outpoint: OutPoint {
                            txid: coinbase_tx.txid().to_vec(),
                            vout: 0
                        },
                        value: 1000,
                        height: 0,
                    }],
                    tip_block_hash: block_0.block_hash().to_vec(),
                    tip_height: 0,
                    next_page: None,
                })
                .unwrap(),
            ),
        );
    });
}
