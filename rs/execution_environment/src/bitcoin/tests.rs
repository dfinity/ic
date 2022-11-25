use crate::execution::test_utilities::ExecutionTestBuilder;
use bitcoin::{
    blockdata::constants::genesis_block, util::psbt::serialize::Serialize, Address, Network,
};
use candid::Encode;
use ic_btc_test_utils::{random_p2pkh_address, BlockBuilder, TransactionBuilder};
use ic_btc_types::{
    GetUtxosResponse, NetworkInRequest as BitcoinNetwork, OutPoint, Satoshi, Utxo,
    UtxosFilterInRequest,
};
use ic_ic00_types::{
    BitcoinGetBalanceArgs, BitcoinGetCurrentFeePercentilesArgs, BitcoinGetSuccessorsArgs,
    BitcoinGetUtxosArgs, BitcoinSendTransactionArgs, EmptyBlob, Method, Payload as Ic00Payload,
    IC_00,
};
use ic_interfaces::execution_environment::SubnetAvailableMemory;
use ic_replicated_state::bitcoin_state::BitcoinState;
use ic_test_utilities::types::ids::{canister_test_id, subnet_test_id};
use ic_test_utilities::universal_canister::{call_args, wasm};
use ic_types::{
    messages::{Payload, Response},
    CanisterId, Cycles, PrincipalId,
};
use lazy_static::lazy_static;
use std::str::FromStr;
use std::sync::Arc;

// TODO(EXC-1153): Refactor to avoid copying these constants from bitcoin.rs
const SEND_TRANSACTION_FEE_BASE: Cycles = Cycles::new(5_000_000_000);
const SEND_TRANSACTION_FEE_PER_BYTE: Cycles = Cycles::new(20_000_000);

lazy_static! {
    static ref MAX_SUBNET_AVAILABLE_MEMORY: SubnetAvailableMemory =
        SubnetAvailableMemory::new(i64::MAX / 2, i64::MAX / 2);
}

fn calculate_send_transaction_payment(bytes: usize) -> Cycles {
    SEND_TRANSACTION_FEE_BASE + SEND_TRANSACTION_FEE_PER_BYTE * bytes as u64
}

fn execute_method<S: ToString>(
    features: &str,
    state: BitcoinState, //  TODO:BitcoinState::from(state)
    method_name: S,
    method_payload: Vec<u8>,
    cycles_given: Cycles,
) -> Arc<Response> {
    let mut test = ExecutionTestBuilder::new()
        .with_caller(subnet_test_id(1), canister_test_id(10))
        .with_subnet_features(features)
        .build();
    test.state_mut().put_bitcoin_state(state);
    test.inject_call_to_ic00(method_name, method_payload, cycles_given);
    test.execute_all();

    test.get_xnet_response(0).to_owned()
}

fn get_reject_message(response: &Arc<Response>) -> String {
    match &response.response_payload {
        Payload::Data(_) => panic!("Expected Reject"),
        Payload::Reject(reject) => reject.message.clone(),
    }
}

/// Creates a Bitcoin canister state with the following transactions:
///
/// 1. grant initial `amount` of funds to `address_1`
/// 2. transfer `amount` of funds from `address_1` to `address_2`
///
/// Note: all the transactions are in the unstable blocks.
fn state_with_balance(
    network: Network,
    amount: Satoshi,
    address_1: &Address,
    address_2: &Address,
) -> BitcoinState {
    let coinbase_tx = TransactionBuilder::coinbase()
        .with_output(address_1, amount)
        .build();
    let block_0 = BlockBuilder::genesis()
        .with_transaction(coinbase_tx.clone())
        .build();
    let tx = TransactionBuilder::new()
        .with_input(bitcoin::OutPoint::new(coinbase_tx.txid(), 0))
        .with_output(address_2, amount)
        .build();
    let block_1 = BlockBuilder::with_prev_header(block_0.header)
        .with_transaction(tx)
        .build();

    let stability_threshold = 2;
    let mut state = ic_btc_canister::state::State::new(stability_threshold, network, block_0);
    ic_btc_canister::store::insert_block(&mut state, block_1).unwrap();

    BitcoinState::from(state)
}

fn fake_state() -> BitcoinState {
    state_with_balance(
        Network::Testnet,
        123,
        &random_p2pkh_address(Network::Testnet),
        &random_p2pkh_address(Network::Testnet),
    )
}

fn reject_feature_not_enabled<S: ToString>(method_name: S, method_payload: Vec<u8>) {
    let cycles_given = Cycles::new(100_000_000);

    let response = execute_method(
        "", // Bitcoin feature is disabled by default.
        fake_state(),
        method_name,
        method_payload,
        cycles_given,
    );

    assert_eq!(
        get_reject_message(&response),
        "The bitcoin API is not enabled on this subnet.".to_string()
    );
    // Refund all given cycles, since the feature was not enabled.
    assert_eq!(response.refund, cycles_given);
}

fn reject_and_check_refund<S: ToString>(
    state: BitcoinState,
    method_name: S,
    method_payload: Vec<u8>,
    cycles_given: Cycles,
    expected_refund: Cycles,
    expected_reject_message: &str,
) {
    let response = execute_method(
        "bitcoin_testnet",
        state,
        method_name,
        method_payload,
        cycles_given,
    );

    assert_eq!(
        get_reject_message(&response),
        expected_reject_message.to_string()
    );
    assert_eq!(response.refund, expected_refund);
}

fn execute_and_check_refund<S: ToString>(
    method_name: S,
    method_payload: Vec<u8>,
    cycles_given: Cycles,
    expected_refund: Cycles,
) {
    let response = execute_method(
        "bitcoin_testnet",
        fake_state(),
        method_name,
        method_payload,
        cycles_given,
    );

    assert_eq!(response.refund, expected_refund); // Refund the rest of cycles left.
}

fn execute_check_payload_and_refund<S: ToString>(
    state: BitcoinState,
    method_name: S,
    method_payload: Vec<u8>,
    cycles_given: Cycles,
    expected_refund: Cycles,
    expected_response_payload: Payload,
) {
    let response = execute_method(
        "bitcoin_testnet",
        state,
        method_name,
        method_payload,
        cycles_given,
    );

    assert_eq!(response.response_payload, expected_response_payload);
    assert_eq!(response.refund, expected_refund);
}

fn fake_get_balance_args() -> BitcoinGetBalanceArgs {
    BitcoinGetBalanceArgs {
        address: random_p2pkh_address(Network::Testnet).to_string(),
        network: BitcoinNetwork::testnet,
        min_confirmations: None,
    }
}

#[test]
fn get_balance_feature_not_enabled() {
    reject_feature_not_enabled(Method::BitcoinGetBalance, fake_get_balance_args().encode());
}

#[test]
fn get_balance_not_enough_cycles() {
    reject_and_check_refund(
        fake_state(),
        Method::BitcoinGetBalance,
        fake_get_balance_args().encode(),
        Cycles::new(100_000_000 - 1), // Not enough cycles given.
        Cycles::new(100_000_000 - 1), // Refund all.
        "Received 99_999_999 cycles. 100_000_000 cycles are required.",
    );
}

#[test]
fn get_balance_charge_cycles() {
    let payment = Cycles::new(100_000_000);
    let expected_refund = Cycles::new(123); // Charge payment.
    execute_and_check_refund(
        Method::BitcoinGetBalance,
        fake_get_balance_args().encode(),
        payment + expected_refund,
        expected_refund,
    );
}

#[test]
fn get_balance_rejects_malformed_address() {
    let address = String::from("malformed address");
    let payment = Cycles::new(100_000_000);
    let expected_refund = Cycles::new(123); // Charge payment.
    reject_and_check_refund(
        fake_state(),
        Method::BitcoinGetBalance,
        BitcoinGetBalanceArgs {
            address,
            ..fake_get_balance_args()
        }
        .encode(),
        payment + expected_refund,
        expected_refund,
        "bitcoin_get_balance failed: Malformed address.",
    );
}

#[test]
fn get_balance_succeeds() {
    // Transfer `amount` of funds from `address_1` to `address_2`.
    let amount: Satoshi = 123;
    let address_1 = random_p2pkh_address(Network::Testnet);
    let address_2 = random_p2pkh_address(Network::Testnet);
    // Expect the balance of `address_2` to be `amount`.
    let expected_balance: Satoshi = 123;

    for network in [BitcoinNetwork::Testnet, BitcoinNetwork::testnet] {
        execute_check_payload_and_refund(
            state_with_balance(Network::Testnet, amount, &address_1, &address_2),
            Method::BitcoinGetBalance,
            BitcoinGetBalanceArgs {
                address: address_2.to_string(),
                network,
                ..fake_get_balance_args()
            }
            .encode(),
            Cycles::new(100_000_000),
            Cycles::zero(),
            Payload::Data(Encode!(&expected_balance).unwrap()),
        );
    }
}

#[test]
fn get_balance_succeeds_min_confirmations_1() {
    // Transfer `amount` of funds from `address_1` to `address_2`.
    let amount: Satoshi = 123;
    let address_1 = random_p2pkh_address(Network::Testnet);
    let address_2 = random_p2pkh_address(Network::Testnet);
    // Expect the balance of `address_2` to be `amount`.
    let expected_balance: Satoshi = 123;

    execute_check_payload_and_refund(
        state_with_balance(Network::Testnet, amount, &address_1, &address_2),
        Method::BitcoinGetBalance,
        BitcoinGetBalanceArgs {
            address: address_2.to_string(),
            min_confirmations: Some(1),
            ..fake_get_balance_args()
        }
        .encode(),
        Cycles::new(100_000_000),
        Cycles::zero(),
        Payload::Data(Encode!(&expected_balance).unwrap()),
    );
}

#[test]
fn get_balance_succeeds_min_confirmations_2() {
    // Transfer `amount` of funds from `address_1` to `address_2`.
    let amount: Satoshi = 123;
    let address_1 = random_p2pkh_address(Network::Testnet);
    let address_2 = random_p2pkh_address(Network::Testnet);
    // Expect the balance of `address_2` to be zero, since receiving funds was confirmed only by 1 block.
    let expected_balance: Satoshi = 0;

    execute_check_payload_and_refund(
        state_with_balance(Network::Testnet, amount, &address_1, &address_2),
        Method::BitcoinGetBalance,
        BitcoinGetBalanceArgs {
            address: address_2.to_string(),
            min_confirmations: Some(2),
            ..fake_get_balance_args()
        }
        .encode(),
        Cycles::new(100_000_000),
        Cycles::zero(),
        Payload::Data(Encode!(&expected_balance).unwrap()),
    );
}

#[test]
fn get_balance_rejects_large_min_confirmations() {
    // Transfer `amount` of funds from `address_1` to `address_2`.
    let amount: Satoshi = 123;
    let address_1 = random_p2pkh_address(Network::Testnet);
    let address_2 = random_p2pkh_address(Network::Testnet);

    reject_and_check_refund(
        state_with_balance(Network::Testnet, amount, &address_1, &address_2),
        Method::BitcoinGetBalance,
        BitcoinGetBalanceArgs {
            address: address_2.to_string(),
            min_confirmations: Some(1_000),  // Too large confirmation.
            ..fake_get_balance_args()
        }
        .encode(),
        Cycles::new(100_000_000),
        Cycles::zero(),
        "bitcoin_get_balance failed: The requested min_confirmations is too large. Given: 1000, max supported: 2"
    );
}

fn fake_get_utxos_args() -> BitcoinGetUtxosArgs {
    BitcoinGetUtxosArgs {
        address: random_p2pkh_address(Network::Testnet).to_string(),
        network: BitcoinNetwork::Testnet,
        filter: None,
    }
}

#[test]
fn get_utxos_rejects_feature_not_enabled() {
    reject_feature_not_enabled(Method::BitcoinGetUtxos, fake_get_utxos_args().encode());
}

#[test]
fn get_utxos_not_enough_cycles() {
    for network in [BitcoinNetwork::Testnet, BitcoinNetwork::testnet] {
        reject_and_check_refund(
            fake_state(),
            Method::BitcoinGetUtxos,
            BitcoinGetUtxosArgs {
                network,
                ..fake_get_utxos_args()
            }
            .encode(),
            Cycles::new(100_000_000 - 1), // Not enough cycles given.
            Cycles::new(100_000_000 - 1), // Refund all.
            "Received 99_999_999 cycles. 100_000_000 cycles are required.",
        );
    }
}

#[test]
fn get_utxos_charge_cycles() {
    let payment = Cycles::new(100_000_000);
    let expected_refund = Cycles::new(123);
    execute_and_check_refund(
        Method::BitcoinGetUtxos,
        fake_get_utxos_args().encode(),
        payment + expected_refund,
        expected_refund,
    );
}

#[test]
fn get_utxos_rejects_malformed_address() {
    let payment = Cycles::new(100_000_000);
    let expected_refund = Cycles::new(123);
    reject_and_check_refund(
        fake_state(),
        Method::BitcoinGetUtxos,
        BitcoinGetUtxosArgs {
            address: String::from("malformed address"),
            ..fake_get_utxos_args()
        }
        .encode(),
        payment + expected_refund,
        expected_refund,
        "bitcoin_get_utxos failed: Malformed address.",
    );
}

#[test]
fn get_utxos_rejects_large_min_confirmations() {
    // Transfer `amount` of funds from `address_1` to `address_2`.
    let amount: Satoshi = 123;
    let address_1 = random_p2pkh_address(Network::Testnet);
    let address_2 = random_p2pkh_address(Network::Testnet);

    // Confirmations that are too large.
    for filter in [
        UtxosFilterInRequest::MinConfirmations(1_000),
        UtxosFilterInRequest::min_confirmations(1_000),
    ] {
        reject_and_check_refund(
        state_with_balance(Network::Testnet, amount, &address_1, &address_2),
        Method::BitcoinGetUtxos,
        BitcoinGetUtxosArgs {
            address: address_2.to_string(),
            filter: Some(filter),
            ..fake_get_utxos_args()
        }
        .encode(),
        Cycles::new(100_000_000),
        Cycles::zero(),
        "bitcoin_get_utxos failed: The requested min_confirmations is too large. Given: 1000, max supported: 2"
    );
    }
}

#[test]
fn get_utxos_succeeds() {
    let address = random_p2pkh_address(Network::Testnet);
    let coinbase_tx = TransactionBuilder::coinbase()
        .with_output(&address, 1000)
        .build();
    let block_0 = BlockBuilder::genesis()
        .with_transaction(coinbase_tx.clone())
        .build();

    for filter in [
        UtxosFilterInRequest::MinConfirmations(1),
        UtxosFilterInRequest::min_confirmations(1),
    ] {
        execute_check_payload_and_refund(
            BitcoinState::from(ic_btc_canister::state::State::new(
                2,
                Network::Testnet,
                block_0.clone(),
            )),
            Method::BitcoinGetUtxos,
            BitcoinGetUtxosArgs {
                address: address.to_string(),
                filter: Some(filter),
                ..fake_get_utxos_args()
            }
            .encode(),
            Cycles::new(100_000_000),
            Cycles::zero(),
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
    }
}

fn fake_get_current_fee_percentiles_args() -> BitcoinGetCurrentFeePercentilesArgs {
    BitcoinGetCurrentFeePercentilesArgs {
        network: BitcoinNetwork::Testnet,
    }
}

#[test]
fn get_current_fee_percentiles_rejects_feature_not_enabled() {
    reject_feature_not_enabled(
        Method::BitcoinGetCurrentFeePercentiles,
        fake_get_current_fee_percentiles_args().encode(),
    );
}

#[test]
fn get_current_fee_percentiles_not_enough_cycles() {
    reject_and_check_refund(
        fake_state(),
        Method::BitcoinGetCurrentFeePercentiles,
        fake_get_current_fee_percentiles_args().encode(),
        Cycles::new(100_000_000 - 1), // Not enough cycles given.
        Cycles::new(100_000_000 - 1), // Refund all.
        "Received 99_999_999 cycles. 100_000_000 cycles are required.",
    );
}

#[test]
fn get_current_fee_percentiles_charge_cycles() {
    let payment = Cycles::new(100_000_000);
    let expected_refund = Cycles::new(123);
    execute_and_check_refund(
        Method::BitcoinGetCurrentFeePercentiles,
        fake_get_current_fee_percentiles_args().encode(),
        payment + expected_refund,
        expected_refund,
    );
}

#[test]
fn get_current_fee_percentiles_succeeds() {
    let initial_balance: Satoshi = 1_000;
    let pay: Satoshi = 1;
    let fee: Satoshi = 2;

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
        .with_output(&address_1, initial_balance - pay - fee)
        .with_output(&address_2, pay)
        .build();
    let block_1 = BlockBuilder::with_prev_header(block_0.header)
        .with_transaction(tx.clone())
        .build();
    let mut state = ic_btc_canister::state::State::new(0, network, block_0);
    ic_btc_canister::store::insert_block(&mut state, block_1).unwrap();

    let expected_fee = (1_000 * fee) / (tx.size() as u64); // Millisatoshi per byte.
    execute_check_payload_and_refund(
        BitcoinState::from(state),
        Method::BitcoinGetCurrentFeePercentiles,
        BitcoinGetCurrentFeePercentilesArgs {
            network: BitcoinNetwork::Testnet,
        }
        .encode(),
        Cycles::new(100_000_000),
        Cycles::zero(),
        Payload::Data(Encode!(&vec![expected_fee; 100]).unwrap()),
    );
}

#[test]
fn get_current_fee_percentiles_rejects_mainnet_when_testnet_is_enabled() {
    // Request to get_current_fee_percentiles with the network parameter set to the
    // bitcoin mainnet while the underlying state is for the bitcoin testnet.
    // Should be rejected.
    let network = BitcoinNetwork::Mainnet;
    let features = "bitcoin_testnet";
    let state_network = Network::Testnet;

    let response = execute_method(
        features,
        BitcoinState::from(ic_btc_canister::state::State::new(
            0,
            state_network,
            genesis_block(Network::Testnet),
        )),
        Method::BitcoinGetCurrentFeePercentiles,
        BitcoinGetCurrentFeePercentilesArgs { network }.encode(),
        Cycles::new(100_000_000),
    );

    assert_eq!(
        get_reject_message(&response),
        "Received request for mainnet but the subnet supports testnet".to_string()
    );
    assert_eq!(response.refund, Cycles::zero()); // Charge payment.
}

#[test]
fn get_current_fee_percentiles_rejects_testnet_when_mainnet_is_enabled() {
    // Request to get_current_fee_percentiles with the network parameter set to the
    // bitcoin testnet while the underlying state is for the bitcoin mainnet.
    // Should be rejected.
    let network = BitcoinNetwork::Testnet;
    let features = "bitcoin_mainnet";
    let state_network = Network::Bitcoin;

    let response = execute_method(
        features,
        BitcoinState::from(ic_btc_canister::state::State::new(
            0,
            state_network,
            genesis_block(Network::Testnet),
        )),
        Method::BitcoinGetCurrentFeePercentiles,
        BitcoinGetCurrentFeePercentilesArgs { network }.encode(),
        Cycles::new(100_000_000),
    );

    assert_eq!(
        get_reject_message(&response),
        "Received request for testnet but the subnet supports mainnet".to_string()
    );
    assert_eq!(response.refund, Cycles::zero()); // Charge payment.
}

#[test]
fn get_current_fee_percentiles_cache() {
    let initial_balance: Satoshi = 1_000;
    let pay: Satoshi = 1;
    let fee_0: Satoshi = 2;
    let change_0 = initial_balance - pay - fee_0;
    let cycles_given = Cycles::new(150_000_000);

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
    // All blocks has to be in `unstable_blocks` to calculate fees, so stability_threshold must be greater than number of blocks.
    let stability_threshold = 1_000;
    let mut btc_canister_state =
        ic_btc_canister::state::State::new(stability_threshold, network, block_0);
    ic_btc_canister::store::insert_block(&mut btc_canister_state, block_1.clone()).unwrap();

    let mut test = ExecutionTestBuilder::new()
        .with_caller(subnet_test_id(1), canister_test_id(10))
        .with_subnet_features("bitcoin_testnet")
        .build();
    test.state_mut()
        .put_bitcoin_state(BitcoinState::from(btc_canister_state));

    // Check fee percentiles cache is EMPTY before executing the request.
    let bitcoin_state = test.state_mut().take_bitcoin_state();
    assert!(bitcoin_state.fee_percentiles_cache.is_none());
    test.state_mut().put_bitcoin_state(bitcoin_state);

    // Execute request to calculate current fee percentiles.
    test.inject_call_to_ic00(
        Method::BitcoinGetCurrentFeePercentiles,
        BitcoinGetCurrentFeePercentilesArgs {
            network: btc_network,
        }
        .encode(),
        cycles_given,
    );
    test.execute_all();

    // Check values in the cache MATCH the response payload.
    let millisatoshi_per_byte_0 = (1_000 * fee_0) / (tx_0.size() as u64);
    let expected_values_0 = vec![millisatoshi_per_byte_0; 100];
    let response = test.get_xnet_response(0);
    assert_eq!(
        response.response_payload,
        Payload::Data(Encode!(&expected_values_0).unwrap())
    );

    // Check fee percentiles cache is NOT empty.
    let bitcoin_state = test.state_mut().take_bitcoin_state();
    let cache = &bitcoin_state.fee_percentiles_cache;
    assert!(cache.is_some());
    let cache = cache.as_ref().unwrap();
    assert_eq!(cache.tip_block_hash, block_1.block_hash());
    assert_eq!(cache.fee_percentiles, expected_values_0);
    test.state_mut().put_bitcoin_state(bitcoin_state);

    // Make another request without any changes (same bitcoin main chain).
    test.inject_call_to_ic00(
        Method::BitcoinGetCurrentFeePercentiles,
        BitcoinGetCurrentFeePercentilesArgs {
            network: btc_network,
        }
        .encode(),
        cycles_given,
    );
    test.execute_all();

    // Check fee percentiles cache DID NOT change.
    let bitcoin_state = test.state_mut().take_bitcoin_state();
    let cache = &bitcoin_state.fee_percentiles_cache;
    assert!(cache.is_some());
    let cache = cache.as_ref().unwrap();
    assert_eq!(cache.tip_block_hash, block_1.block_hash());
    assert_eq!(cache.fee_percentiles, expected_values_0);
    test.state_mut().put_bitcoin_state(bitcoin_state);

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
        ic_btc_canister::state::State::from(test.state_mut().take_bitcoin_state());
    ic_btc_canister::store::insert_block(&mut btc_canister_state, block_2.clone()).unwrap();
    test.state_mut()
        .put_bitcoin_state(btc_canister_state.into());

    // Make request to get current fees.
    test.inject_call_to_ic00(
        Method::BitcoinGetCurrentFeePercentiles,
        BitcoinGetCurrentFeePercentilesArgs {
            network: btc_network,
        }
        .encode(),
        cycles_given,
    );
    test.execute_all();

    // Check fee percentiles cache DID change and consist of two different fee values.
    let millisatoshi_per_byte_1 = (1_000 * fee_1) / (tx_1.size() as u64);
    let mut expected_values_1 = Vec::new();
    expected_values_1.extend_from_slice(&vec![millisatoshi_per_byte_0; 50]);
    expected_values_1.extend_from_slice(&vec![millisatoshi_per_byte_1; 50]);

    let bitcoin_state = test.state_mut().take_bitcoin_state();
    let cache = &bitcoin_state.fee_percentiles_cache;
    assert!(cache.is_some());
    let cache = cache.as_ref().unwrap();
    assert_eq!(cache.tip_block_hash, block_2.block_hash());
    assert_eq!(cache.fee_percentiles, expected_values_1);
    test.state_mut().put_bitcoin_state(bitcoin_state);
}

#[test]
fn send_transaction_rejects_if_feature_not_enabled() {
    reject_feature_not_enabled(
        Method::BitcoinSendTransaction,
        BitcoinSendTransactionArgs {
            transaction: vec![],
            network: BitcoinNetwork::Testnet,
        }
        .encode(),
    );
}

#[test]
fn send_transaction_zero_len_not_enough_cycles() {
    let transaction = vec![];
    // Not enough cycles given.
    let cycles_given = calculate_send_transaction_payment(transaction.len()) - Cycles::new(1);
    reject_and_check_refund(
        fake_state(),
        Method::BitcoinSendTransaction,
        BitcoinSendTransactionArgs {
            transaction,
            network: BitcoinNetwork::Testnet,
        }
        .encode(),
        cycles_given,
        cycles_given, // Refund all.
        "Received 4_999_999_999 cycles. 5_000_000_000 cycles are required.",
    );
}

#[test]
fn send_transaction_non_zero_len_not_enough_cycles() {
    let transaction = vec![1, 2, 3];
    // Not enough cycles given.
    let cycles_given = calculate_send_transaction_payment(transaction.len()) - Cycles::new(1);
    reject_and_check_refund(
        fake_state(),
        Method::BitcoinSendTransaction,
        BitcoinSendTransactionArgs {
            transaction,
            network: BitcoinNetwork::Testnet,
        }
        .encode(),
        cycles_given,
        cycles_given, // Refund all.
        "Received 5_059_999_999 cycles. 5_060_000_000 cycles are required.",
    );
}

#[test]
fn send_transaction_cycles_charging() {
    for network in [BitcoinNetwork::Mainnet, BitcoinNetwork::Testnet] {
        for transaction in [vec![], vec![0; 1], vec![0; 10], vec![0; 100], vec![0; 1000]] {
            let payment = calculate_send_transaction_payment(transaction.len());
            let expected_refund = Cycles::new(123);

            let response = execute_method(
                &format!("bitcoin_{}", network),
                BitcoinState::new(network.into()),
                Method::BitcoinSendTransaction,
                BitcoinSendTransactionArgs {
                    transaction,
                    network,
                }
                .encode(),
                payment + expected_refund,
            );

            assert_eq!(response.refund, expected_refund); // Refund the rest of cycles left.
            assert_eq!(
                get_reject_message(&response),
                "bitcoin_send_transaction failed: Can't deserialize transaction because it's malformed.".to_string()
            );
        }
    }
}

#[test]
fn send_transaction_malformed_transaction() {
    let transaction = vec![1, 2, 3];
    let payment = calculate_send_transaction_payment(transaction.len());
    let expected_refund = Cycles::new(123);
    reject_and_check_refund(
        fake_state(),
        Method::BitcoinSendTransaction,
        BitcoinSendTransactionArgs {
            transaction,
            network: BitcoinNetwork::Testnet,
        }
        .encode(),
        payment + expected_refund,
        expected_refund,
        "bitcoin_send_transaction failed: Can't deserialize transaction because it's malformed.",
    );
}

#[test]
fn send_transaction_succeeds() {
    // Create a fake transaction that passes verification check.
    let transaction = TransactionBuilder::coinbase()
        .with_output(&random_p2pkh_address(Network::Testnet), 1_000)
        .build()
        .serialize();
    let payment = calculate_send_transaction_payment(transaction.len());

    for network in [BitcoinNetwork::Testnet, BitcoinNetwork::testnet] {
        execute_check_payload_and_refund(
            fake_state(),
            Method::BitcoinSendTransaction,
            BitcoinSendTransactionArgs {
                transaction: transaction.clone(),
                network,
            }
            .encode(),
            payment,
            Cycles::zero(),
            Payload::Data(EmptyBlob.encode()),
        );
    }
}

#[test]
fn clears_state_of_former_bitcoin_canisters() {
    let bitcoin_canister_id =
        CanisterId::new(PrincipalId::from_str("rwlgt-iiaaa-aaaaa-aaaaa-cai").unwrap()).unwrap();

    let mut test = ExecutionTestBuilder::new()
        // Set the bitcoin canister to be the ID of the canister about to be created.
        .with_bitcoin_privileged_access(bitcoin_canister_id)
        .with_bitcoin_follow_up_responses(bitcoin_canister_id, vec![vec![1], vec![2]])
        .with_bitcoin_follow_up_responses(canister_test_id(123), vec![vec![1], vec![2], vec![3]])
        .with_provisional_whitelist_all()
        .build();

    let uni = test.universal_canister().unwrap();
    assert_eq!(
        uni.get_ref(),
        &bitcoin_canister_id.get(),
        "id of universal canister doesn't match expected id"
    );

    let call = wasm()
        .call_simple(
            IC_00,
            Method::BitcoinGetSuccessors,
            call_args()
                .other_side(BitcoinGetSuccessorsArgs::FollowUp(3).encode())
                .on_reject(wasm().reject_message().reject()),
        )
        .build();

    test.ingress(uni, "update", call).unwrap();

    assert_eq!(
        test.state()
            .metadata
            .bitcoin_get_successors_follow_up_responses,
        maplit::btreemap! { bitcoin_canister_id => vec![vec![1], vec![2]] }
    );
}
