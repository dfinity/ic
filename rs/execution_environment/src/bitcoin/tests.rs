use bitcoin::{
    blockdata::constants::genesis_block, util::psbt::serialize::Serialize, Address, Network,
};
use candid::Encode;
use ic_btc_test_utils::{random_p2pkh_address, BlockBuilder, TransactionBuilder};
use ic_btc_types::{GetUtxosResponse, OutPoint, Satoshi, Utxo, UtxosFilter};
use ic_ic00_types::{
    BitcoinGetBalanceArgs, BitcoinGetCurrentFeePercentilesArgs, BitcoinGetUtxosArgs,
    BitcoinNetwork, BitcoinSendTransactionArgs, EmptyBlob, Method, Payload as Ic00Payload,
};
use ic_interfaces::execution_environment::AvailableMemory;
use ic_interfaces::execution_environment::SubnetAvailableMemory;
use ic_replicated_state::bitcoin_state::BitcoinState;
use ic_test_utilities::execution_environment::ExecutionTestBuilder;
use ic_test_utilities::types::ids::{canister_test_id, subnet_test_id};
use ic_types::{
    messages::{Payload, Response},
    Cycles,
};
use lazy_static::lazy_static;
use std::sync::Arc;

// TODO(EXC-1153): Refactor to avoid copying these constants from bitcoin.rs
const SEND_TRANSACTION_FEE_BASE: Cycles = Cycles::new(5_000_000_000);
const SEND_TRANSACTION_FEE_PER_BYTE: Cycles = Cycles::new(20_000_000);

lazy_static! {
    static ref MAX_SUBNET_AVAILABLE_MEMORY: SubnetAvailableMemory =
        AvailableMemory::new(i64::MAX / 2, i64::MAX / 2).into();
}

fn get_reject_message(response: &Arc<Response>) -> String {
    match &response.response_payload {
        Payload::Data(_) => panic!("Expected Reject"),
        Payload::Reject(reject) => reject.message.clone(),
    }
}

#[test]
fn get_balance_feature_not_enabled() {
    // Bitcoin testnet feature is disabled by default.
    let cycles_given = Cycles::new(100_000_000);
    let mut test = ExecutionTestBuilder::new()
        .with_caller(subnet_test_id(1), canister_test_id(10))
        .build();
    test.inject_call_to_ic00(
        Method::BitcoinGetBalance,
        BitcoinGetBalanceArgs {
            address: String::from("not an address"),
            network: BitcoinNetwork::Testnet,
            min_confirmations: None,
        }
        .encode(),
        cycles_given,
    );
    test.execute_all();

    let response = test.get_xnet_response(0);
    assert_eq!(
        get_reject_message(response),
        "The bitcoin API is not enabled on this subnet.".to_string()
    );
    // Refund all given cycles, since the feature was not enabled.
    assert_eq!(response.refund, cycles_given);
}

#[test]
fn get_balance_not_enough_cycles() {
    // Not enough cycles given.
    let cycles_given = Cycles::new(100_000_000 - 1);

    let mut test = ExecutionTestBuilder::new()
        .with_caller(subnet_test_id(1), canister_test_id(10))
        .with_subnet_features("bitcoin_testnet")
        .build();
    test.inject_call_to_ic00(
        Method::BitcoinGetBalance,
        BitcoinGetBalanceArgs {
            address: String::from("not an address"),
            network: BitcoinNetwork::Testnet,
            min_confirmations: None,
        }
        .encode(),
        cycles_given,
    );
    test.execute_all();

    let response = test.get_xnet_response(0);
    assert_eq!(
        get_reject_message(response),
        "Received 99999999 cycles. 100000000 cycles are required.".to_string()
    );
    // Refund all given cycles, since it was not enough to execute the request.
    assert_eq!(response.refund, cycles_given);
}

#[test]
fn get_balance_rejects_malformed_address() {
    let malformed_address = String::from("not an address");

    let mut test = ExecutionTestBuilder::new()
        .with_caller(subnet_test_id(1), canister_test_id(10))
        .with_subnet_features("bitcoin_testnet")
        .build();
    test.inject_call_to_ic00(
        Method::BitcoinGetBalance,
        BitcoinGetBalanceArgs {
            address: malformed_address,
            network: BitcoinNetwork::Testnet,
            min_confirmations: None,
        }
        .encode(),
        Cycles::new(100_000_000),
    );
    test.execute_all();

    let response = test.get_xnet_response(0);
    assert_eq!(
        get_reject_message(response),
        "bitcoin_get_balance failed: Malformed address.".to_string()
    );
    // No refund, assumed request to be executed, but it's a gray area, difficult to be sure.
    assert_eq!(response.refund, Cycles::zero());
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
) -> ic_btc_canister::state::State {
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
    state
}

#[test]
fn get_balance_succeeds() {
    // Transfer `amount` of funds from `address_1` to `address_2`.
    let amount: Satoshi = 123;
    let address_1 = random_p2pkh_address(Network::Testnet);
    let address_2 = random_p2pkh_address(Network::Testnet);
    // Expect the balance of `address_2` to be `amount`.
    let check_address = address_2.to_string();
    let expected_balance: Satoshi = 123;

    let mut test = ExecutionTestBuilder::new()
        .with_caller(subnet_test_id(1), canister_test_id(10))
        .with_subnet_features("bitcoin_testnet")
        .build();
    test.state_mut()
        .put_bitcoin_state(BitcoinState::from(state_with_balance(
            Network::Testnet,
            amount,
            &address_1,
            &address_2,
        )));
    test.inject_call_to_ic00(
        Method::BitcoinGetBalance,
        BitcoinGetBalanceArgs {
            address: check_address,
            network: BitcoinNetwork::Testnet,
            min_confirmations: None,
        }
        .encode(),
        Cycles::new(100_000_000),
    );
    test.execute_all();

    let response = test.get_xnet_response(0);
    assert_eq!(
        response.response_payload,
        Payload::Data(Encode!(&expected_balance).unwrap())
    );
    // No refund, since it was used to execute the request.
    assert_eq!(response.refund, Cycles::zero());
}

#[test]
fn get_balance_succeeds_with_min_confirmations_1() {
    // Transfer `amount` of funds from `address_1` to `address_2`.
    let amount: Satoshi = 123;
    let address_1 = random_p2pkh_address(Network::Testnet);
    let address_2 = random_p2pkh_address(Network::Testnet);
    let min_confirmations = Some(1);
    // Expect the balance of `address_2` to be `amount`.
    let check_address = address_2.to_string();
    let expected_balance: Satoshi = 123;

    let mut test = ExecutionTestBuilder::new()
        .with_caller(subnet_test_id(1), canister_test_id(10))
        .with_subnet_features("bitcoin_testnet")
        .build();
    test.state_mut()
        .put_bitcoin_state(BitcoinState::from(state_with_balance(
            Network::Testnet,
            amount,
            &address_1,
            &address_2,
        )));
    test.inject_call_to_ic00(
        Method::BitcoinGetBalance,
        BitcoinGetBalanceArgs {
            address: check_address,
            network: BitcoinNetwork::Testnet,
            min_confirmations,
        }
        .encode(),
        Cycles::new(100_000_000),
    );
    test.execute_all();

    let response = test.get_xnet_response(0);
    assert_eq!(
        response.response_payload,
        Payload::Data(Encode!(&expected_balance).unwrap())
    );
    // No refund, since it was used to execute the request.
    assert_eq!(response.refund, Cycles::zero());
}

#[test]
fn get_balance_succeeds_with_min_confirmations_2() {
    // Transfer `amount` of funds from `address_1` to `address_2`.
    let amount: Satoshi = 123;
    let address_1 = random_p2pkh_address(Network::Testnet);
    let address_2 = random_p2pkh_address(Network::Testnet);
    let min_confirmations = Some(2);
    // Expect the balance of `address_2` to be zero, since receiving funds was confirmed only by 1 block.
    let check_address = address_2.to_string();
    let expected_balance: Satoshi = 0;

    let mut test = ExecutionTestBuilder::new()
        .with_caller(subnet_test_id(1), canister_test_id(10))
        .with_subnet_features("bitcoin_testnet")
        .build();
    test.state_mut()
        .put_bitcoin_state(BitcoinState::from(state_with_balance(
            Network::Testnet,
            amount,
            &address_1,
            &address_2,
        )));
    test.inject_call_to_ic00(
        Method::BitcoinGetBalance,
        BitcoinGetBalanceArgs {
            address: check_address,
            network: BitcoinNetwork::Testnet,
            min_confirmations,
        }
        .encode(),
        Cycles::new(100_000_000),
    );
    test.execute_all();

    let response = test.get_xnet_response(0);
    assert_eq!(
        response.response_payload,
        Payload::Data(Encode!(&expected_balance).unwrap())
    );
    // No refund, assumed request to be executed, but it's a gray area, difficult to be sure.
    assert_eq!(response.refund, Cycles::zero());
}

#[test]
fn get_balance_rejects_large_min_confirmations() {
    // Transfer `amount` of funds from `address_1` to `address_2`.
    let amount: Satoshi = 123;
    let address_1 = random_p2pkh_address(Network::Testnet);
    let address_2 = random_p2pkh_address(Network::Testnet);
    let min_confirmations = Some(1000);
    let check_address = address_2.to_string();

    let mut test = ExecutionTestBuilder::new()
        .with_caller(subnet_test_id(1), canister_test_id(10))
        .with_subnet_features("bitcoin_testnet")
        .build();
    test.state_mut()
        .put_bitcoin_state(BitcoinState::from(state_with_balance(
            Network::Testnet,
            amount,
            &address_1,
            &address_2,
        )));
    test.inject_call_to_ic00(
        Method::BitcoinGetBalance,
        BitcoinGetBalanceArgs {
            address: check_address,
            network: BitcoinNetwork::Testnet,
            min_confirmations,
        }
        .encode(),
        Cycles::new(100_000_000),
    );
    test.execute_all();

    let response = test.get_xnet_response(0);
    assert_eq!(
        get_reject_message(response),
        "bitcoin_get_balance failed: The requested min_confirmations is too large. Given: 1000, max supported: 2".to_string()
    );
    // No refund, assumed request to be executed, but it's a gray area, difficult to be sure.
    assert_eq!(response.refund, Cycles::zero());
}

#[test]
fn get_utxos_rejects_if_feature_not_enabled() {
    // Bitcoin testnet feature is disabled by default.
    let cycles_given = Cycles::new(100_000_000);
    let mut test = ExecutionTestBuilder::new()
        .with_caller(subnet_test_id(1), canister_test_id(10))
        .build();
    test.inject_call_to_ic00(
        Method::BitcoinGetUtxos,
        BitcoinGetUtxosArgs {
            address: String::from("not an address"),
            network: BitcoinNetwork::Testnet,
            filter: None,
        }
        .encode(),
        cycles_given,
    );
    test.execute_all();

    let response = test.get_xnet_response(0);
    assert_eq!(
        get_reject_message(response),
        "The bitcoin API is not enabled on this subnet.".to_string()
    );
    // Refund all given cycles, since the feature was not enabled.
    assert_eq!(response.refund, cycles_given);
}

#[test]
fn get_utxos_rejects_if_address_is_malformed() {
    let address = String::from("not an address");
    let mut test = ExecutionTestBuilder::new()
        .with_caller(subnet_test_id(1), canister_test_id(10))
        .with_subnet_features("bitcoin_testnet")
        .build();
    test.inject_call_to_ic00(
        Method::BitcoinGetUtxos,
        BitcoinGetUtxosArgs {
            address,
            network: BitcoinNetwork::Testnet,
            filter: None,
        }
        .encode(),
        Cycles::new(100_000_000),
    );
    test.execute_all();

    let response = test.get_xnet_response(0);
    assert_eq!(
        get_reject_message(response),
        "bitcoin_get_utxos failed: Malformed address.".to_string()
    );
    // No refund, assumed request to be executed, but it's a gray area, difficult to be sure.
    assert_eq!(response.refund, Cycles::zero());
}

#[test]
fn get_utxos_rejects_large_min_confirmations() {
    let min_confirmations = 1_000;
    let mut test = ExecutionTestBuilder::new()
        .with_caller(subnet_test_id(1), canister_test_id(10))
        .with_subnet_features("bitcoin_testnet")
        .build();
    test.inject_call_to_ic00(
        Method::BitcoinGetUtxos,
        BitcoinGetUtxosArgs {
            address: random_p2pkh_address(Network::Testnet).to_string(),
            network: BitcoinNetwork::Testnet,
            filter: Some(UtxosFilter::MinConfirmations(min_confirmations)),
        }
        .encode(),
        Cycles::new(100_000_000),
    );
    test.execute_all();

    let response = test.get_xnet_response(0);
    assert_eq!(
        get_reject_message(response),
        "bitcoin_get_utxos failed: The requested min_confirmations is too large. Given: 1000, max supported: 1".to_string()
    );
    // No refund, assumed request to be executed, but it's a gray area, difficult to be sure.
    assert_eq!(response.refund, Cycles::zero());
}

#[test]
fn get_utxos_of_valid_request_succeeds() {
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

    let mut test = ExecutionTestBuilder::new()
        .with_caller(subnet_test_id(1), canister_test_id(10))
        .with_subnet_features("bitcoin_testnet")
        .build();
    test.state_mut().put_bitcoin_state(bitcoin_state);
    test.inject_call_to_ic00(
        Method::BitcoinGetUtxos,
        BitcoinGetUtxosArgs {
            address: address.to_string(),
            network: BitcoinNetwork::Testnet,
            filter: Some(UtxosFilter::MinConfirmations(1)),
        }
        .encode(),
        Cycles::new(200_000_000),
    );
    test.execute_all();

    let response = test.get_xnet_response(0);
    assert_eq!(
        response.response_payload,
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
            .unwrap()
        )
    );
    // Sent 200M cycles, should receive 100M as a refund.
    assert_eq!(response.refund, Cycles::new(100_000_000));
}

#[test]
fn get_utxos_not_enough_cycles() {
    let cycles_given = Cycles::new(10_000);
    let mut test = ExecutionTestBuilder::new()
        .with_caller(subnet_test_id(1), canister_test_id(10))
        .with_subnet_features("bitcoin_testnet")
        .build();
    test.inject_call_to_ic00(
        Method::BitcoinGetUtxos,
        BitcoinGetUtxosArgs {
            address: random_p2pkh_address(Network::Testnet).to_string(),
            network: BitcoinNetwork::Testnet,
            filter: Some(UtxosFilter::MinConfirmations(1)),
        }
        .encode(),
        cycles_given,
    );
    test.execute_all();

    let response = test.get_xnet_response(0);
    assert_eq!(
        get_reject_message(response),
        "Received 10000 cycles. 100000000 cycles are required.".to_string()
    );
    // Refund all given cycles, since it was not enough to execute the request.
    assert_eq!(response.refund, cycles_given);
}

#[test]
fn get_current_fee_percentiles_rejects_feature_not_enabled() {
    // Bitcoin testnet feature is disabled by default.
    let cycles_given = Cycles::new(100_000_000);
    let mut test = ExecutionTestBuilder::new()
        .with_caller(subnet_test_id(1), canister_test_id(10))
        .build();
    test.inject_call_to_ic00(
        Method::BitcoinGetCurrentFeePercentiles,
        BitcoinGetCurrentFeePercentilesArgs {
            network: BitcoinNetwork::Testnet,
        }
        .encode(),
        cycles_given,
    );
    test.execute_all();

    let response = test.get_xnet_response(0);
    assert_eq!(
        get_reject_message(response),
        "The bitcoin API is not enabled on this subnet.".to_string()
    );
    // Refund all given cycles, since the feature was not enabled.
    assert_eq!(response.refund, cycles_given);
}

#[test]
fn get_current_fee_percentiles_succeeds() {
    let initial_balance: Satoshi = 1_000;
    let pay: Satoshi = 1;
    let fee: Satoshi = 2;
    let cycles_given = Cycles::new(150_000_000);
    let expected_refund = Cycles::new(50_000_000); // 150M - 100M in fees = refund of 50M

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

    let mut test = ExecutionTestBuilder::new()
        .with_caller(subnet_test_id(1), canister_test_id(10))
        .with_subnet_features("bitcoin_testnet")
        .build();
    test.state_mut()
        .put_bitcoin_state(BitcoinState::from(state));
    test.inject_call_to_ic00(
        Method::BitcoinGetCurrentFeePercentiles,
        BitcoinGetCurrentFeePercentilesArgs {
            network: BitcoinNetwork::Testnet,
        }
        .encode(),
        cycles_given,
    );
    test.execute_all();

    let response = test.get_xnet_response(0);
    let millisatoshi_per_byte = (1_000 * fee) / (tx.size() as u64);
    assert_eq!(
        response.response_payload,
        Payload::Data(Encode!(&vec![millisatoshi_per_byte; 100]).unwrap())
    );
    assert_eq!(response.refund, expected_refund);
}

#[test]
fn get_current_fee_percentiles_not_enough_cycles() {
    // Not enough cycles given.
    let cycles_given = Cycles::new(90_000_000);

    let mut test = ExecutionTestBuilder::new()
        .with_caller(subnet_test_id(1), canister_test_id(10))
        .with_subnet_features("bitcoin_testnet")
        .build();
    test.inject_call_to_ic00(
        Method::BitcoinGetCurrentFeePercentiles,
        BitcoinGetCurrentFeePercentilesArgs {
            network: BitcoinNetwork::Testnet,
        }
        .encode(),
        cycles_given,
    );
    test.execute_all();

    let response = test.get_xnet_response(0);
    assert_eq!(
        get_reject_message(response),
        "Received 90000000 cycles. 100000000 cycles are required.".to_string()
    );
    // Refund all given cycles, since it was not enough to execute the request.
    assert_eq!(response.refund, cycles_given);
}

#[test]
fn get_current_fee_percentiles_rejects_mainnet_when_testnet_is_enabled() {
    // Request to get_current_fee_percentiles with the network parameter set to the
    // bitcoin mainnet while the underlying state is for the bitcoin testnet.
    // Should be rejected.
    let network = BitcoinNetwork::Mainnet;
    let feature = "bitcoin_testnet";
    let bitcoin_state = BitcoinState::from(ic_btc_canister::state::State::new(
        0,
        Network::Testnet,
        genesis_block(Network::Testnet),
    ));

    let mut test = ExecutionTestBuilder::new()
        .with_caller(subnet_test_id(1), canister_test_id(10))
        .with_subnet_features(feature)
        .build();
    test.state_mut().put_bitcoin_state(bitcoin_state);
    test.inject_call_to_ic00(
        Method::BitcoinGetCurrentFeePercentiles,
        BitcoinGetCurrentFeePercentilesArgs { network }.encode(),
        Cycles::new(100_000_000),
    );
    test.execute_all();

    let response = test.get_xnet_response(0);
    assert_eq!(
        get_reject_message(response),
        "Received request for mainnet but the subnet supports testnet".to_string()
    );
    // No refund, assumed request to be executed, but it's a gray area, difficult to be sure.
    assert_eq!(response.refund, Cycles::zero());
}

#[test]
fn get_current_fee_percentiles_rejects_testnet_when_mainnet_is_enabled() {
    // Request to get_current_fee_percentiles with the network parameter set to the
    // bitcoin testnet while the underlying state is for the bitcoin mainnet.
    // Should be rejected.
    let network = BitcoinNetwork::Testnet;
    let feature = "bitcoin_mainnet";
    let bitcoin_state = BitcoinState::from(ic_btc_canister::state::State::new(
        0,
        Network::Bitcoin,
        genesis_block(Network::Bitcoin),
    ));

    let mut test = ExecutionTestBuilder::new()
        .with_caller(subnet_test_id(1), canister_test_id(10))
        .with_subnet_features(feature)
        .build();
    test.state_mut().put_bitcoin_state(bitcoin_state);
    test.inject_call_to_ic00(
        Method::BitcoinGetCurrentFeePercentiles,
        BitcoinGetCurrentFeePercentilesArgs { network }.encode(),
        Cycles::new(100_000_000),
    );
    test.execute_all();

    let response = test.get_xnet_response(0);
    assert_eq!(
        get_reject_message(response),
        "Received request for testnet but the subnet supports mainnet".to_string()
    );
    // No refund, assumed request to be executed, but it's a gray area, difficult to be sure.
    assert_eq!(response.refund, Cycles::zero());
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
    // Bitcoin testnet feature is disabled by default.
    let cycles_given = Cycles::new(100_000_000);
    let mut test = ExecutionTestBuilder::new()
        .with_caller(subnet_test_id(1), canister_test_id(10))
        .build();
    test.inject_call_to_ic00(
        Method::BitcoinSendTransaction,
        BitcoinSendTransactionArgs {
            transaction: vec![],
            network: BitcoinNetwork::Testnet,
        }
        .encode(),
        cycles_given,
    );
    test.execute_all();

    let response = test.get_xnet_response(0);
    assert_eq!(
        get_reject_message(response),
        "The bitcoin API is not enabled on this subnet.".to_string()
    );
    // Refund all given cycles, since the feature was not enabled.
    assert_eq!(response.refund, cycles_given);
}

#[test]
fn send_transaction_malformed_transaction() {
    let transaction = vec![1, 2, 3];
    let tx_len = transaction.len() as u64;
    let mut test = ExecutionTestBuilder::new()
        .with_caller(subnet_test_id(1), canister_test_id(10))
        .with_subnet_features("bitcoin_testnet")
        .build();
    test.inject_call_to_ic00(
        Method::BitcoinSendTransaction,
        BitcoinSendTransactionArgs {
            transaction,
            network: BitcoinNetwork::Testnet,
        }
        .encode(),
        SEND_TRANSACTION_FEE_BASE + SEND_TRANSACTION_FEE_PER_BYTE * tx_len as u64,
    );
    test.execute_all();

    let response = test.get_xnet_response(0);
    assert_eq!(
        get_reject_message(response),
        "bitcoin_send_transaction failed: Can't deserialize transaction because it's malformed."
            .to_string()
    );
    // No refund, assumed request to be executed, but it's a gray area, difficult to be sure.
    assert_eq!(response.refund, Cycles::zero());
}

#[test]
fn send_transaction_succeeds() {
    // Create a fake transaction that passes verification check.
    let tx = TransactionBuilder::coinbase()
        .with_output(&random_p2pkh_address(Network::Testnet), 1_000)
        .build()
        .serialize();
    let mut test = ExecutionTestBuilder::new()
        .with_caller(subnet_test_id(1), canister_test_id(10))
        .with_subnet_features("bitcoin_testnet")
        .build();
    test.inject_call_to_ic00(
        Method::BitcoinSendTransaction,
        BitcoinSendTransactionArgs {
            transaction: tx.clone(),
            network: BitcoinNetwork::Testnet,
        }
        .encode(),
        SEND_TRANSACTION_FEE_BASE + SEND_TRANSACTION_FEE_PER_BYTE * tx.serialize().len() as u64,
    );
    test.execute_all();

    let response = test.get_xnet_response(0);
    assert_eq!(
        response.response_payload,
        Payload::Data(EmptyBlob::encode()),
    );
    assert_eq!(response.refund, Cycles::zero());
}

#[test]
fn send_transaction_cycles_charging() {
    for network in [BitcoinNetwork::Mainnet, BitcoinNetwork::Testnet] {
        for transaction in [vec![], vec![0; 1], vec![0; 10], vec![0; 100], vec![0; 1000]] {
            let tx_len = transaction.len() as u64;
            let initial_balance = Cycles::new(100_000_000_000);
            let mut test = ExecutionTestBuilder::new()
                .with_caller(subnet_test_id(1), canister_test_id(10))
                .with_subnet_features(&format!("bitcoin_{}", network)) // bitcoin feature is enabled for this network.
                .build();
            test.state_mut()
                .put_bitcoin_state(BitcoinState::new(network));
            test.inject_call_to_ic00(
                Method::BitcoinSendTransaction,
                BitcoinSendTransactionArgs {
                    transaction,
                    network,
                }
                .encode(),
                initial_balance,
            );
            test.execute_all();

            let response = test.get_xnet_response(0);
            assert_eq!(
                response.refund,
                // the expected fee is deducted from the balance.
                initial_balance
                    - (SEND_TRANSACTION_FEE_BASE + SEND_TRANSACTION_FEE_PER_BYTE * tx_len as u64)
            );
            assert_eq!(
                get_reject_message(response),
                "bitcoin_send_transaction failed: Can't deserialize transaction because it's malformed."
                    .to_string()
            );
        }
    }
}
