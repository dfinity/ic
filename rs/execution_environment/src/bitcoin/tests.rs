use crate::{ExecutionEnvironment, ExecutionEnvironmentImpl, Hypervisor, IngressHistoryWriterImpl};
use bitcoin::{
    blockdata::constants::genesis_block, util::psbt::serialize::Serialize, Address, Network,
};
use candid::Encode;
use ic_btc_test_utils::{random_p2pkh_address, BlockBuilder, TransactionBuilder};
use ic_btc_types::{GetUtxosResponse, OutPoint, Satoshi, Utxo, UtxosFilter};
use ic_config::execution_environment;
use ic_error_types::RejectCode;
use ic_ic00_types::{
    self as ic00, BitcoinGetBalanceArgs, BitcoinGetCurrentFeePercentilesArgs, BitcoinGetUtxosArgs,
    BitcoinNetwork, BitcoinSendTransactionArgs, EmptyBlob, Method, Payload as Ic00Payload,
};
use ic_interfaces::execution_environment::AvailableMemory;
use ic_interfaces::execution_environment::SubnetAvailableMemory;
use ic_metrics::MetricsRegistry;
use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
use ic_registry_subnet_features::SubnetFeatures;
use ic_registry_subnet_features::{BitcoinFeature, BitcoinFeatureStatus};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    bitcoin_state::BitcoinState,
    testing::{CanisterQueuesTesting, ReplicatedStateTesting},
    ReplicatedState,
};
use ic_replicated_state::{
    canister_state::QUEUE_INDEX_NONE, InputQueueType, NetworkTopology, SubnetTopology,
};
use ic_test_utilities::execution_environment::test_registry_settings;
use ic_test_utilities::{
    crypto::mock_random_number_generator,
    cycles_account_manager::CyclesAccountManagerBuilder,
    state::{CanisterStateBuilder, ReplicatedStateBuilder},
    types::{
        ids::{canister_test_id, subnet_test_id},
        messages::{RequestBuilder, ResponseBuilder},
    },
    with_test_replica_logger,
};
use ic_types::{
    messages::{Payload, RejectContext, RequestOrResponse},
    CanisterId, Cycles, NumInstructions, SubnetId,
};
use lazy_static::lazy_static;
use maplit::btreemap;
use std::collections::BTreeMap;
use std::str::FromStr;
use std::{convert::TryFrom, sync::Arc};
use tempfile::TempDir;

// TODO(EXC-1153): Refactor to avoid copying these constants from bitcoin.rs
const SEND_TRANSACTION_FEE_BASE: Cycles = Cycles::new(5_000_000_000);
const SEND_TRANSACTION_FEE_PER_BYTE: Cycles = Cycles::new(20_000_000);

const MAX_NUM_INSTRUCTIONS: NumInstructions = NumInstructions::new(1_000_000_000);
lazy_static! {
    static ref MAX_SUBNET_AVAILABLE_MEMORY: SubnetAvailableMemory =
        AvailableMemory::new(i64::MAX / 2, i64::MAX / 2).into();
}
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

// TODO: refactor tests same way it was done in RUN-192.
fn execute_get_balance(
    exec_env: &ExecutionEnvironmentImpl,
    bitcoin_feature: &str,
    bitcoin_state: BitcoinState,
    get_balance_args: BitcoinGetBalanceArgs,
    cycles_given: Cycles,
    expected_payload: Payload,
    expected_refund: Cycles,
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
                    .method_name(Method::BitcoinGetBalance)
                    .method_payload(get_balance_args.encode())
                    .payment(cycles_given)
                    .build()
                    .into(),
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
            &BTreeMap::new(),
            MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            &test_registry_settings(),
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
                .refund(expected_refund)
                .build()
                .into()
        )
    );
}

// TODO: refactor tests same way it was done in RUN-192.
fn execute_get_utxos(
    exec_env: &ExecutionEnvironmentImpl,
    bitcoin_get_utxos_args: BitcoinGetUtxosArgs,
    bitcoin_feature: &str,
    bitcoin_state: BitcoinState,
    cycles_given: Cycles,
    expected_payload: Payload,
    expected_refund: Cycles,
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
                    .payment(cycles_given)
                    .build()
                    .into(),
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
            &BTreeMap::new(),
            MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            &test_registry_settings(),
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
                .refund(expected_refund)
                .build()
                .into()
        )
    );
}

// TODO: refactor tests same way it was done in RUN-192.
fn execute_get_current_fee_percentiles(
    exec_env: &ExecutionEnvironmentImpl,
    bitcoin_feature: &str,
    bitcoin_state: BitcoinState,
    network: BitcoinNetwork,
    payment: Cycles,
    expected_payload: Payload,
    expected_refund: Cycles,
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
            RequestBuilder::new()
                .sender(canister_test_id(0))
                .receiver(ic00::IC_00)
                .method_name(Method::BitcoinGetCurrentFeePercentiles)
                .method_payload(BitcoinGetCurrentFeePercentilesArgs { network }.encode())
                .payment(payment)
                .build()
                .into(),
            InputQueueType::RemoteSubnet,
        )
        .unwrap();

    let mut state = exec_env
        .execute_subnet_message(
            state.subnet_queues_mut().pop_input().unwrap(),
            state,
            MAX_NUM_INSTRUCTIONS,
            &mut mock_random_number_generator(),
            &BTreeMap::new(),
            MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            &test_registry_settings(),
        )
        .0;

    let subnet_id = subnet_test_id(1);
    assert_eq!(
        state
            .subnet_queues_mut()
            .pop_canister_output(&canister_test_id(0))
            .unwrap()
            .1,
        ResponseBuilder::new()
            .originator(canister_test_id(0))
            .respondent(CanisterId::new(subnet_id.get()).unwrap())
            .response_payload(expected_payload)
            .refund(expected_refund)
            .build()
            .into()
    );
}

// TODO: refactor tests same way it was done in RUN-192.
fn execute_send_transaction(
    exec_env: &ExecutionEnvironmentImpl,
    bitcoin_feature: &str,
    bitcoin_state: BitcoinState,
    bitcoin_send_transaction_args: BitcoinSendTransactionArgs,
    payment: Cycles,
    expected_payload: Payload,
    expected_refund: Cycles,
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
            RequestBuilder::new()
                .sender(canister_test_id(0))
                .receiver(ic00::IC_00)
                .method_name(Method::BitcoinSendTransaction)
                .method_payload(bitcoin_send_transaction_args.encode())
                .payment(payment)
                .build()
                .into(),
            InputQueueType::RemoteSubnet,
        )
        .unwrap();

    let mut state = exec_env
        .execute_subnet_message(
            state.subnet_queues_mut().pop_input().unwrap(),
            state,
            MAX_NUM_INSTRUCTIONS,
            &mut mock_random_number_generator(),
            &BTreeMap::new(),
            MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            &test_registry_settings(),
        )
        .0;

    let subnet_id = subnet_test_id(1);
    assert_eq!(
        state
            .subnet_queues_mut()
            .pop_canister_output(&canister_test_id(0))
            .unwrap()
            .1,
        ResponseBuilder::new()
            .originator(canister_test_id(0))
            .respondent(CanisterId::new(subnet_id.get()).unwrap())
            .response_payload(expected_payload)
            .refund(expected_refund)
            .build()
            .into()
    );
}

#[test]
fn get_balance_feature_not_enabled() {
    with_setup(SubnetType::Application, |exec_env, mut state, _, _| {
        // Disable bitcoin testnet feature.
        state.metadata.own_subnet_features.bitcoin = Some(BitcoinFeature {
            network: BitcoinNetwork::Testnet,
            status: BitcoinFeatureStatus::Disabled,
        });
        let network = BitcoinNetwork::Testnet;
        let address = String::from("not an address");
        let min_confirmations = None;
        let cycles_given = Cycles::new(0);

        execute_get_balance(
            &exec_env,
            "None",
            BitcoinState::default(),
            BitcoinGetBalanceArgs {
                address,
                network,
                min_confirmations,
            },
            cycles_given,
            Payload::Reject(RejectContext {
                code: RejectCode::CanisterReject,
                message: String::from("The bitcoin API is not enabled on this subnet."),
            }),
            Cycles::zero(),
        );
    });
}

#[test]
fn get_balance_not_enough_cycles() {
    with_setup(SubnetType::Application, |exec_env, mut state, _, _| {
        state.metadata.own_subnet_features.bitcoin = Some(BitcoinFeature {
            network: BitcoinNetwork::Mainnet,
            status: BitcoinFeatureStatus::Enabled,
        });
        let network = BitcoinNetwork::Mainnet;
        let address = String::from("not an address");
        let min_confirmations = None;
        let cycles_given = Cycles::new(100_000_000 - 1);

        execute_get_balance(
            &exec_env,
            "bitcoin_mainnet",
            BitcoinState::default(),
            BitcoinGetBalanceArgs {
                address,
                network,
                min_confirmations,
            },
            cycles_given,
            Payload::Reject(RejectContext {
                code: RejectCode::CanisterReject,
                message: String::from("Received 99999999 cycles. 100000000 cycles are required."),
            }),
            cycles_given,
        );
    });
}

#[test]
fn get_balance_api_rejects_malformed_address() {
    with_setup(SubnetType::Application, |exec_env, mut state, _, _| {
        state.metadata.own_subnet_features.bitcoin = Some(BitcoinFeature {
            network: BitcoinNetwork::Testnet,
            status: BitcoinFeatureStatus::Enabled,
        });
        let network = BitcoinNetwork::Testnet;
        let address = String::from("not an address");
        let min_confirmations = None;
        let cycles_given = Cycles::new(100_000_000);

        execute_get_balance(
            &exec_env,
            "bitcoin_testnet",
            BitcoinState::default(),
            BitcoinGetBalanceArgs {
                address,
                network,
                min_confirmations,
            },
            cycles_given,
            Payload::Reject(RejectContext {
                code: RejectCode::CanisterReject,
                message: String::from("bitcoin_get_balance failed: Malformed address."),
            }),
            Cycles::zero(),
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
    let tx = TransactionBuilder::new()
        .with_input(bitcoin::OutPoint::new(coinbase_tx.txid(), 0))
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
fn get_balance_request_succeeds() {
    with_setup(SubnetType::Application, |exec_env, mut state, _, _| {
        state.metadata.own_subnet_features.bitcoin = Some(BitcoinFeature {
            network: BitcoinNetwork::Testnet,
            status: BitcoinFeatureStatus::Enabled,
        });
        let (network, btc_network) = (BitcoinNetwork::Testnet, Network::Testnet);
        let address_1 = random_p2pkh_address(btc_network);
        let address_2 = random_p2pkh_address(btc_network);
        let min_confirmations = None;
        let satoshi: Satoshi = 123;
        let bitcoin_state = BitcoinState::from(state_with_balance(
            btc_network,
            satoshi,
            &address_1,
            &address_2,
        ));
        let expected_balance_payload = Payload::Data(Encode!(&123u64).unwrap());
        let cycles_given = Cycles::new(100_000_000);

        execute_get_balance(
            &exec_env,
            "bitcoin_testnet",
            bitcoin_state,
            BitcoinGetBalanceArgs {
                address: address_2.to_string(),
                network,
                min_confirmations,
            },
            cycles_given,
            expected_balance_payload,
            Cycles::zero(),
        );
    });
}

#[test]
fn get_balance_with_min_confirmations_1() {
    with_setup(SubnetType::Application, |exec_env, mut state, _, _| {
        state.metadata.own_subnet_features.bitcoin = Some(BitcoinFeature {
            network: BitcoinNetwork::Testnet,
            status: BitcoinFeatureStatus::Enabled,
        });
        let (network, btc_network) = (BitcoinNetwork::Testnet, Network::Testnet);
        let address_1 = random_p2pkh_address(btc_network);
        let address_2 = random_p2pkh_address(btc_network);
        let min_confirmations = Some(1);
        let satoshi: Satoshi = 123;
        let bitcoin_state = BitcoinState::from(state_with_balance(
            btc_network,
            satoshi,
            &address_1,
            &address_2,
        ));
        let cycles_given = Cycles::new(100_000_000);
        let expected_balance_payload = Payload::Data(Encode!(&123u64).unwrap());

        execute_get_balance(
            &exec_env,
            "bitcoin_testnet",
            bitcoin_state,
            BitcoinGetBalanceArgs {
                address: address_2.to_string(),
                network,
                min_confirmations,
            },
            cycles_given,
            expected_balance_payload,
            Cycles::zero(),
        );
    });
}

#[test]
fn get_balance_with_min_confirmations_2() {
    with_setup(SubnetType::Application, |exec_env, mut state, _, _| {
        state.metadata.own_subnet_features.bitcoin = Some(BitcoinFeature {
            network: BitcoinNetwork::Testnet,
            status: BitcoinFeatureStatus::Enabled,
        });
        let (network, btc_network) = (BitcoinNetwork::Testnet, Network::Testnet);
        let address_1 = random_p2pkh_address(btc_network);
        let address_2 = random_p2pkh_address(btc_network);
        let min_confirmations = Some(2);
        let satoshi: Satoshi = 123;
        let bitcoin_state = BitcoinState::from(state_with_balance(
            btc_network,
            satoshi,
            &address_1,
            &address_2,
        ));
        let cycles_given = Cycles::new(100_000_000);
        let expected_balance_payload = Payload::Data(Encode!(&0u64).unwrap());

        execute_get_balance(
            &exec_env,
            "bitcoin_testnet",
            bitcoin_state,
            BitcoinGetBalanceArgs {
                address: address_2.to_string(),
                network,
                min_confirmations,
            },
            cycles_given,
            expected_balance_payload,
            Cycles::zero(),
        );
    });
}

#[test]
fn get_balance_rejects_large_min_confirmations() {
    with_setup(SubnetType::Application, |exec_env, mut state, _, _| {
        state.metadata.own_subnet_features.bitcoin = Some(BitcoinFeature {
            network: BitcoinNetwork::Testnet,
            status: BitcoinFeatureStatus::Enabled,
        });
        let (network, btc_network) = (BitcoinNetwork::Testnet, Network::Testnet);
        let satoshi: Satoshi = 123;
        let address_1 = random_p2pkh_address(btc_network);
        let address_2 = random_p2pkh_address(btc_network);
        let bitcoin_state = BitcoinState::from(state_with_balance(
            btc_network,
            satoshi,
            &address_1,
            &address_2,
        ));
        let cycles_given = Cycles::new(100_000_000);

        execute_get_balance(
            &exec_env,
            "bitcoin_testnet",
            bitcoin_state,
            BitcoinGetBalanceArgs {
                address: address_2.to_string(),
                network,
                min_confirmations: Some(1000), // A large value of min_confirmations
            },
            cycles_given,
            Payload::Reject(RejectContext {
                code: RejectCode::CanisterReject,
                message: String::from("bitcoin_get_balance failed: The requested min_confirmations is too large. Given: 1000, max supported: 2"),
            }),
            Cycles::zero(),
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
        let cycles_given = Cycles::new(100_000_000);

        execute_get_utxos(
            &exec_env,
            bitcoin_get_utxos_args,
            "None", // Bitcoin feature is disabled.
            BitcoinState::default(),
            cycles_given,
            Payload::Reject(RejectContext {
                code: RejectCode::CanisterReject,
                message: String::from("The bitcoin API is not enabled on this subnet."),
            }),
            Cycles::new(100_000_000),
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
        let cycles_given = Cycles::new(100_000_000);

        execute_get_utxos(
            &exec_env,
            bitcoin_get_utxos_args,
            "bitcoin_testnet", // Bitcoin testnet is enabled.
            BitcoinState::default(),
            cycles_given,
            Payload::Reject(RejectContext {
                code: RejectCode::CanisterReject,
                message: String::from("bitcoin_get_utxos failed: Malformed address."),
            }),
            Cycles::zero(),
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
        let cycles_given = Cycles::new(100_000_000);

        execute_get_utxos(
            &exec_env,
            bitcoin_get_utxos_args,
            "bitcoin_testnet", // Bitcoin testnet is enabled.
            BitcoinState::default(),
            cycles_given,
            Payload::Reject(RejectContext {
                code: RejectCode::CanisterReject,
                message: String::from("bitcoin_get_utxos failed: The requested min_confirmations is too large. Given: 1000, max supported: 1")
            }),
            Cycles::zero()
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

        let cycles_given = Cycles::new(200_000_000);

        execute_get_utxos(
            &exec_env,
            bitcoin_get_utxos_args,
            "bitcoin_testnet", // Bitcoin testnet is enabled.
            bitcoin_state,
            cycles_given,
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
            Cycles::new(100_000_000), // Sent 200M cycles, should receive 100M as a refund.
        );
    });
}

#[test]
fn get_utxos_not_enough_cycles() {
    with_setup(SubnetType::Application, |exec_env, _, _, _| {
        let address = random_p2pkh_address(Network::Testnet);
        let bitcoin_state = BitcoinState::default();
        let bitcoin_get_utxos_args = BitcoinGetUtxosArgs {
            address: address.to_string(),
            network: BitcoinNetwork::Testnet,
            filter: Some(UtxosFilter::MinConfirmations(1)),
        };
        let cycles_given = Cycles::new(10_000);

        execute_get_utxos(
            &exec_env,
            bitcoin_get_utxos_args,
            "bitcoin_testnet", // Bitcoin testnet is enabled.
            bitcoin_state,
            cycles_given,
            Payload::Reject(RejectContext {
                code: RejectCode::CanisterReject,
                message: String::from("Received 10000 cycles. 100000000 cycles are required."),
            }),
            cycles_given,
        );
    });
}

#[test]
fn get_current_fee_percentiles_rejects_if_feature_not_enabled() {
    with_setup(SubnetType::Application, |exec_env, _, _, _| {
        execute_get_current_fee_percentiles(
            &exec_env,
            "None", // Bitcoin feature is disabled.
            BitcoinState::default(),
            BitcoinNetwork::Testnet,
            Cycles::from(1000),
            Payload::Reject(RejectContext {
                code: RejectCode::CanisterReject,
                message: String::from("The bitcoin API is not enabled on this subnet."),
            }),
            Cycles::from(1000),
        );
    });
}

#[test]
fn get_current_fee_percentiles_succeeds() {
    with_setup(SubnetType::Application, |exec_env, _, _, _| {
        let initial_balance: Satoshi = 1_000;
        let pay: Satoshi = 1;
        let fee: Satoshi = 2;
        let change = initial_balance - pay - fee;

        // Create 2 blocks with 2 transactions:
        // - genesis block receives initial balance on address_1
        // - the next block sends a payment to address_2 with a fee, a change is returned to address_1.
        let network = Network::Testnet;
        let address_1 = random_p2pkh_address(network);
        let address_2 = random_p2pkh_address(network);
        let coinbase_tx = TransactionBuilder::coinbase()
            .with_output(&address_1, initial_balance)
            .build();
        let block_0 = BlockBuilder::genesis()
            .with_transaction(coinbase_tx.clone())
            .build();

        let tx = TransactionBuilder::new()
            .with_input(bitcoin::OutPoint::new(coinbase_tx.txid(), 0))
            .with_output(&address_1, change)
            .with_output(&address_2, pay)
            .build();
        let block_1 = BlockBuilder::with_prev_header(block_0.header)
            .with_transaction(tx.clone())
            .build();

        let mut state = ic_btc_canister::state::State::new(0, network, block_0);
        ic_btc_canister::store::insert_block(&mut state, block_1).unwrap();

        let bitcoin_state = BitcoinState::from(state);
        let payment = Cycles::new(150_000_000);

        let millisatoshi_per_byte = (1_000 * fee) / (tx.size() as u64);
        execute_get_current_fee_percentiles(
            &exec_env,
            "bitcoin_testnet", // Bitcoin testnet is enabled.
            bitcoin_state,
            BitcoinNetwork::Testnet,
            payment,
            Payload::Data(Encode!(&vec![millisatoshi_per_byte; 100]).unwrap()),
            Cycles::new(50_000_000), // 150M - 100M in fees = refund of 50M
        );
    });
}

#[test]
fn get_current_fee_percentiles_not_enough_cycles() {
    with_setup(SubnetType::Application, |exec_env, _, _, _| {
        let bitcoin_state = BitcoinState::default();
        let payment = Cycles::new(90_000_000);

        execute_get_current_fee_percentiles(
            &exec_env,
            "bitcoin_testnet", // Bitcoin testnet is enabled.
            bitcoin_state,
            BitcoinNetwork::Testnet,
            payment,
            Payload::Reject(RejectContext {
                code: RejectCode::CanisterReject,
                message: String::from("Received 90000000 cycles. 100000000 cycles are required."),
            }),
            Cycles::new(90_000_000),
        );
    });
}

#[test]
fn get_current_fee_percentiles_different_network_fails() {
    with_setup(SubnetType::Application, |exec_env, _, _, _| {
        // Request to get_current_fee_percentiles with the network parameter set to the
        // bitcoin mainnet while the underlying state is for the bitcoin testnet.
        // Should be rejected.
        let bitcoin_state = BitcoinState::from(ic_btc_canister::state::State::new(
            0,
            Network::Testnet,
            genesis_block(Network::Testnet),
        ));
        let payment = Cycles::new(100_000_000);

        execute_get_current_fee_percentiles(
            &exec_env,
            "bitcoin_testnet", // Bitcoin testnet is enabled.
            bitcoin_state,
            BitcoinNetwork::Mainnet,
            payment,
            Payload::Reject(RejectContext {
                code: RejectCode::CanisterReject,
                message: String::from(
                    "Received request for mainnet but the subnet supports testnet",
                ),
            }),
            Cycles::zero(),
        );

        // Request to get_current_fee_percentiles with the network parameter set to the
        // bitcoin testnet while the underlying state is for the bitcoin mainnet.
        // Should be rejected.
        let bitcoin_state = BitcoinState::from(ic_btc_canister::state::State::new(
            0,
            Network::Bitcoin,
            genesis_block(Network::Bitcoin),
        ));

        execute_get_current_fee_percentiles(
            &exec_env,
            "bitcoin_mainnet", // Bitcoin mainnet is enabled.
            bitcoin_state,
            BitcoinNetwork::Testnet,
            payment,
            Payload::Reject(RejectContext {
                code: RejectCode::CanisterReject,
                message: String::from(
                    "Received request for testnet but the subnet supports mainnet",
                ),
            }),
            Cycles::zero(),
        );
    });
}

#[test]
fn get_current_fee_percentiles_cache() {
    with_setup(SubnetType::Application, |exec_env, _, _, _| {
        let initial_balance: Satoshi = 1_000;
        let pay: Satoshi = 1;
        let fee_0: Satoshi = 2;
        let change_0 = initial_balance - pay - fee_0;
        let payment = Cycles::new(150_000_000);
        let refund = Cycles::new(50_000_000); // 150M - 100M in fees = refund of 50M

        // Build ReplicatedState with a fake transaction that includes a fee.
        // Create 2 blocks with 2 transactions:
        // - genesis block receives initial balance on address_1
        // - the next block sends a payment to address_2 with a fee, a change is returned to address_1.
        let btc_network = BitcoinNetwork::Testnet;
        let network = Network::Testnet;
        let address_1 = random_p2pkh_address(network);
        let address_2 = random_p2pkh_address(network);
        // Coinbase transaction (no fee): address_1 receives initial amount.
        let coinbase_tx = TransactionBuilder::coinbase()
            .with_output(&address_1, initial_balance)
            .build();
        let block_0 = BlockBuilder::genesis()
            .with_transaction(coinbase_tx.clone())
            .build();
        // Transaction sends payment from address_1 to address_2 and return fee to address_1.
        let tx_0 = TransactionBuilder::new()
            .with_input(bitcoin::OutPoint::new(coinbase_tx.txid(), 0))
            .with_output(&address_1, change_0)
            .with_output(&address_2, pay)
            .build();
        let block_1 = BlockBuilder::with_prev_header(block_0.header)
            .with_transaction(tx_0.clone())
            .build();
        // Insert blocks into the state.
        // TODO: debug why it does not work with stability_threshold == 0.
        let mut btc_canister_state = ic_btc_canister::state::State::new(1_000, network, block_0);
        ic_btc_canister::store::insert_block(&mut btc_canister_state, block_1.clone()).unwrap();

        // Build a replicated state.
        let mut state = ReplicatedStateBuilder::new()
            .with_subnet_id(subnet_test_id(1))
            .with_canister(
                CanisterStateBuilder::new()
                    .with_canister_id(canister_test_id(0))
                    .build(),
            )
            .with_subnet_features(SubnetFeatures::from_str("bitcoin_testnet").unwrap())
            .with_bitcoin_state(BitcoinState::from(btc_canister_state))
            .build();

        // Check fee percentiles cache is empty before executing the request.
        let bitcoin_state = state.take_bitcoin_state();
        assert!(bitcoin_state.fee_percentiles_cache.is_none());
        state.put_bitcoin_state(bitcoin_state);

        // Execute request to calculate current fee percentiles.
        state
            .subnet_queues_mut()
            .push_input(
                QUEUE_INDEX_NONE,
                RequestBuilder::new()
                    .sender(canister_test_id(0))
                    .receiver(ic00::IC_00)
                    .method_name(Method::BitcoinGetCurrentFeePercentiles)
                    .method_payload(
                        BitcoinGetCurrentFeePercentilesArgs {
                            network: btc_network,
                        }
                        .encode(),
                    )
                    .payment(payment)
                    .build()
                    .into(),
                InputQueueType::RemoteSubnet,
            )
            .unwrap();
        let mut state = exec_env
            .execute_subnet_message(
                state.subnet_queues_mut().pop_input().unwrap(),
                state,
                MAX_NUM_INSTRUCTIONS,
                &mut mock_random_number_generator(),
                &BTreeMap::new(),
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
                &test_registry_settings(),
            )
            .0;

        // Check values in the cache match the response payload.
        let millisatoshi_per_byte_0 = (1_000 * fee_0) / (tx_0.size() as u64);
        let expected_values_0 = vec![millisatoshi_per_byte_0; 100];
        let expected_payload_0 = Payload::Data(Encode!(&expected_values_0).unwrap());
        let subnet_id = subnet_test_id(1);
        assert_eq!(
            state
                .subnet_queues_mut()
                .pop_canister_output(&canister_test_id(0))
                .unwrap()
                .1,
            ResponseBuilder::new()
                .originator(canister_test_id(0))
                .respondent(CanisterId::new(subnet_id.get()).unwrap())
                .response_payload(expected_payload_0)
                .refund(refund)
                .build()
                .into()
        );

        // Check fee percentiles cache is NOT empty.
        let bitcoin_state = state.take_bitcoin_state();
        let cache = &bitcoin_state.fee_percentiles_cache;
        assert!(cache.is_some());
        let cache = cache.as_ref().unwrap();
        assert_eq!(cache.tip_block_hash, block_1.block_hash());
        assert_eq!(cache.fee_percentiles, expected_values_0);
        state.put_bitcoin_state(bitcoin_state);

        // Make another request without any changes (same bitcoin main chain).
        state
            .subnet_queues_mut()
            .push_input(
                QUEUE_INDEX_NONE,
                RequestBuilder::new()
                    .sender(canister_test_id(0))
                    .receiver(ic00::IC_00)
                    .method_name(Method::BitcoinGetCurrentFeePercentiles)
                    .method_payload(
                        BitcoinGetCurrentFeePercentilesArgs {
                            network: btc_network,
                        }
                        .encode(),
                    )
                    .payment(payment)
                    .build()
                    .into(),
                InputQueueType::RemoteSubnet,
            )
            .unwrap();
        let mut state = exec_env
            .execute_subnet_message(
                state.subnet_queues_mut().pop_input().unwrap(),
                state,
                MAX_NUM_INSTRUCTIONS,
                &mut mock_random_number_generator(),
                &BTreeMap::new(),
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
                &test_registry_settings(),
            )
            .0;

        // Check fee percentiles cache DID NOT change.
        let bitcoin_state = state.take_bitcoin_state();
        let cache = &bitcoin_state.fee_percentiles_cache;
        assert!(cache.is_some());
        let cache = cache.as_ref().unwrap();
        assert_eq!(cache.tip_block_hash, block_1.block_hash());
        assert_eq!(cache.fee_percentiles, expected_values_0);
        state.put_bitcoin_state(bitcoin_state);

        // Add another transaction to bitcoin main chain with a different fee to ensure fees cache changed.
        let fee_1 = 2 * fee_0; // Fee is different from the previous one.
        let change_1 = change_0 - pay - fee_1;
        let tx_1 = TransactionBuilder::new()
            .with_input(bitcoin::OutPoint::new(tx_0.txid(), 0))
            .with_output(&address_1, change_1)
            .with_output(&address_2, pay)
            .build();
        let block_2 = BlockBuilder::with_prev_header(block_1.header)
            .with_transaction(tx_1.clone())
            .build();
        let mut btc_canister_state =
            ic_btc_canister::state::State::from(state.take_bitcoin_state());
        ic_btc_canister::store::insert_block(&mut btc_canister_state, block_2.clone()).unwrap();
        state.put_bitcoin_state(btc_canister_state.into());

        // Make request to get current fees.
        state
            .subnet_queues_mut()
            .push_input(
                QUEUE_INDEX_NONE,
                RequestBuilder::new()
                    .sender(canister_test_id(0))
                    .receiver(ic00::IC_00)
                    .method_name(Method::BitcoinGetCurrentFeePercentiles)
                    .method_payload(
                        BitcoinGetCurrentFeePercentilesArgs {
                            network: btc_network,
                        }
                        .encode(),
                    )
                    .payment(payment)
                    .build()
                    .into(),
                InputQueueType::RemoteSubnet,
            )
            .unwrap();
        let mut state = exec_env
            .execute_subnet_message(
                state.subnet_queues_mut().pop_input().unwrap(),
                state,
                MAX_NUM_INSTRUCTIONS,
                &mut mock_random_number_generator(),
                &BTreeMap::new(),
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
                &test_registry_settings(),
            )
            .0;

        // Check fee percentiles cache DID change and consist of two different fee values.
        let millisatoshi_per_byte_1 = (1_000 * fee_1) / (tx_1.size() as u64);
        let mut expected_values_1 = Vec::new();
        expected_values_1.extend_from_slice(&vec![millisatoshi_per_byte_0; 50]);
        expected_values_1.extend_from_slice(&vec![millisatoshi_per_byte_1; 50]);

        let bitcoin_state = state.take_bitcoin_state();
        let cache = &bitcoin_state.fee_percentiles_cache;
        assert!(cache.is_some());
        let cache = cache.as_ref().unwrap();
        assert_eq!(cache.tip_block_hash, block_2.block_hash());
        assert_eq!(cache.fee_percentiles, expected_values_1);
        state.put_bitcoin_state(bitcoin_state);
    });
}

#[test]
fn send_transaction_rejects_if_feature_not_enabled() {
    with_setup(SubnetType::Application, |exec_env, _, _, _| {
        let bitcoin_send_transaction_args = BitcoinSendTransactionArgs {
            transaction: vec![],
            network: BitcoinNetwork::Testnet,
        };
        execute_send_transaction(
            &exec_env,
            "None", // Bitcoin feature is disabled.
            BitcoinState::default(),
            bitcoin_send_transaction_args,
            Cycles::new(123),
            Payload::Reject(RejectContext {
                code: RejectCode::CanisterReject,
                message: String::from("The bitcoin API is not enabled on this subnet."),
            }),
            Cycles::new(123), // whatever cycles are sent are refunded back.
        );
    });
}

#[test]
fn send_transaction_malformed_transaction() {
    with_setup(SubnetType::Application, |exec_env, _, _, _| {
        let transaction = vec![1, 2, 3];
        let bitcoin_send_transaction_args = BitcoinSendTransactionArgs {
            transaction: transaction.clone(),
            network: BitcoinNetwork::Testnet,
        };
        execute_send_transaction(
            &exec_env,
            "bitcoin_testnet", // Bitcoin testnet is enabled.
            BitcoinState::default(),
            bitcoin_send_transaction_args,
            SEND_TRANSACTION_FEE_BASE + Cycles::from(transaction.len() as u64) * SEND_TRANSACTION_FEE_PER_BYTE,
            Payload::Reject(RejectContext {
                code: RejectCode::CanisterReject,
                message: String::from(
                    "bitcoin_send_transaction failed: Can't deserialize transaction because it's malformed.",
                ),
            }),
            Cycles::new(0),
        );
    });
}

#[test]
fn send_transaction_succeeds() {
    with_setup(SubnetType::Application, |exec_env, _, _, _| {
        // Create a fake transaction that passes verification check.
        let tx = TransactionBuilder::coinbase()
            .with_output(&random_p2pkh_address(Network::Testnet), 1_000)
            .build();
        let bitcoin_send_transaction_args = BitcoinSendTransactionArgs {
            transaction: tx.serialize(),
            network: BitcoinNetwork::Testnet,
        };
        execute_send_transaction(
            &exec_env,
            "bitcoin_testnet", // Bitcoin testnet is enabled.
            BitcoinState::default(),
            bitcoin_send_transaction_args,
            SEND_TRANSACTION_FEE_BASE
                + Cycles::from(tx.serialize().len() as u64) * SEND_TRANSACTION_FEE_PER_BYTE,
            Payload::Data(EmptyBlob::encode()),
            Cycles::zero(),
        );
    });
}

#[test]
fn send_transaction_cycles_charging() {
    with_setup(SubnetType::Application, |exec_env, _, _, _| {
        for network in [BitcoinNetwork::Mainnet, BitcoinNetwork::Testnet] {
            for transaction in [vec![], vec![0; 1], vec![0; 10], vec![0; 100], vec![0; 1000]] {
                let transaction_len = transaction.len();
                let bitcoin_send_transaction_args = BitcoinSendTransactionArgs {
                    transaction,
                    network,
                };

                let initial_balance = Cycles::new(100_000_000_000);
                execute_send_transaction(
                    &exec_env,
                    &format!("bitcoin_{}", network), // bitcoin feature is enabled for this network.
                    BitcoinState::new(network),
                    bitcoin_send_transaction_args,
                    initial_balance,
                    Payload::Reject(RejectContext {
                        code: RejectCode::CanisterReject,
                        message: String::from(
                            "bitcoin_send_transaction failed: Can't deserialize transaction because it's malformed.",
                        ),
                    }),
                    // the expected fee is deducted from the balance.
                    initial_balance - (SEND_TRANSACTION_FEE_BASE + Cycles::from(transaction_len as u64) * SEND_TRANSACTION_FEE_PER_BYTE)
                );
            }
        }
    });
}
