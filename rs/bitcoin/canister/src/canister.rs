pub use crate::fees::get_current_fee_percentiles;
use crate::{metrics::BitcoinCanisterMetrics, state::State, store};
use bitcoin::{util::psbt::serialize::Deserialize, Transaction};
use ic_btc_types::{
    GetBalanceError, GetUtxosError, GetUtxosResponse, SendTransactionError, SendTransactionRequest,
    UtxosFilter,
};
use ic_btc_types_internal::{
    BitcoinAdapterRequestWrapper, SendTransactionRequest as InternalSendTransactionRequest,
};
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use ic_replicated_state::bitcoin_state::BitcoinStateError;

// The maximum number of UTXOs that are allowed to be included in a single
// `GetUtxosResponse`.
//
// Given the size of a `Utxo` is 48 bytes, this means that the size of a single
// response can be ~500KiB (considering the size of remaining fields and
// potential overhead for the candid serialization). This is still quite below
// the max response payload size of 2MiB that the IC needs to respect.

// The value also conforms to the interface spec which requires that no more
// than 100_000 `Utxo`s are returned in a single response.
const MAX_UTXOS_PER_RESPONSE: usize = 10_000;

/// The Bitcoin Canister component.
///
/// Maintains information that is needed to be accessed at the bitcoin canister's
/// runtime, such as metrics.
pub struct BitcoinCanister {
    pub(crate) metrics: BitcoinCanisterMetrics,
    pub(crate) log: ReplicaLogger,
}

impl BitcoinCanister {
    pub fn new(metrics_registry: &MetricsRegistry, log: ReplicaLogger) -> Self {
        Self {
            metrics: BitcoinCanisterMetrics::new(metrics_registry),
            log,
        }
    }
}

/// Retrieves the balance of the given Bitcoin address.
pub fn get_balance(
    state: &State,
    address: &str,
    min_confirmations: Option<u32>,
) -> Result<u64, GetBalanceError> {
    let min_confirmations = min_confirmations.unwrap_or(0);

    store::get_balance(state, address, min_confirmations)
}

pub fn get_utxos(
    state: &State,
    address: &str,
    filter: Option<UtxosFilter>,
) -> Result<GetUtxosResponse, GetUtxosError> {
    match filter {
        None => {
            // No filter is specified. Return all UTXOs for the address.
            store::get_utxos(state, address, 0, None, Some(MAX_UTXOS_PER_RESPONSE))
        }
        Some(UtxosFilter::MinConfirmations(min_confirmations)) => {
            // Return UTXOs with the requested number of confirmations.
            store::get_utxos(
                state,
                address,
                min_confirmations,
                None,
                Some(MAX_UTXOS_PER_RESPONSE),
            )
        }
        Some(UtxosFilter::Page(page)) => store::get_utxos(
            state,
            address,
            0,
            Some(page.to_vec()),
            Some(MAX_UTXOS_PER_RESPONSE),
        ),
    }
}

pub fn send_transaction(
    state: &mut State,
    request: SendTransactionRequest,
) -> Result<(), SendTransactionError> {
    if Transaction::deserialize(&request.transaction).is_err() {
        return Err(SendTransactionError::MalformedTransaction);
    }

    match state
        .adapter_queues
        .push_request(BitcoinAdapterRequestWrapper::SendTransactionRequest(
            InternalSendTransactionRequest {
                transaction: request.transaction,
            },
        )) {
        Ok(()) => {}
        Err(_err @ BitcoinStateError::QueueFull { .. }) => {
            return Err(SendTransactionError::QueueFull);
        }
        // TODO(EXC-1098): Refactor the `push_request` method to not return these
        // errors to avoid this `unreachable` statement.
        Err(BitcoinStateError::FeatureNotEnabled)
        | Err(BitcoinStateError::NonMatchingResponse { .. }) => unreachable!(),
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use bitcoin::secp256k1::rand::rngs::OsRng;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::util::psbt::serialize::Serialize;
    use bitcoin::{blockdata::constants::genesis_block, Address, Network, PublicKey};
    use ic_btc_test_utils::{random_p2tr_address, BlockBuilder, TransactionBuilder};
    use ic_btc_types::{Network as BtcTypesNetwork, OutPoint, Utxo};

    // A default state to use for tests.
    fn default_state() -> State {
        State::new(1, Network::Regtest, genesis_block(Network::Regtest))
    }

    #[test]
    fn get_utxos_from_existing_utxo_set() {
        for network in [
            Network::Bitcoin,
            Network::Regtest,
            Network::Testnet,
            Network::Signet,
        ]
        .iter()
        {
            // Generate an address.
            let address = {
                let secp = Secp256k1::new();
                let mut rng = OsRng::new().unwrap();
                Address::p2pkh(&PublicKey::new(secp.generate_keypair(&mut rng).1), *network)
            };

            // Create a genesis block where 1000 satoshis are given to the address.
            let coinbase_tx = TransactionBuilder::coinbase()
                .with_output(&address, 1000)
                .build();
            let genesis_block = BlockBuilder::genesis()
                .with_transaction(coinbase_tx.clone())
                .build();

            // Set the state.
            let state = State::new(0, *network, genesis_block.clone());

            assert_eq!(
                get_utxos(&state, &address.to_string(), None),
                Ok(GetUtxosResponse {
                    utxos: vec![Utxo {
                        outpoint: OutPoint {
                            txid: coinbase_tx.txid().to_vec(),
                            vout: 0
                        },
                        value: 1000,
                        height: 0,
                    }],
                    tip_block_hash: genesis_block.block_hash().to_vec(),
                    tip_height: 0,
                    next_page: None,
                })
            );
        }
    }

    #[test]
    fn get_balance_malformed_address() {
        assert_eq!(
            get_balance(&default_state(), "not an address", None),
            Err(GetBalanceError::MalformedAddress)
        );
    }

    #[test]
    fn get_utxos_malformed_address() {
        assert_eq!(
            get_utxos(&default_state(), "not an address", None),
            Err(GetUtxosError::MalformedAddress)
        );
    }

    #[test]
    fn get_balance_test() {
        for network in [
            Network::Bitcoin,
            Network::Regtest,
            Network::Testnet,
            Network::Signet,
        ]
        .iter()
        {
            // Generate addresses.
            let address_1 = {
                let secp = Secp256k1::new();
                let mut rng = OsRng::new().unwrap();
                Address::p2pkh(&PublicKey::new(secp.generate_keypair(&mut rng).1), *network)
            };

            let address_2 = {
                let secp = Secp256k1::new();
                let mut rng = OsRng::new().unwrap();
                Address::p2pkh(&PublicKey::new(secp.generate_keypair(&mut rng).1), *network)
            };

            // Create a genesis block where 1000 satoshis are given to the address_1, followed
            // by a block where address_1 gives 1000 satoshis to address_2.
            let coinbase_tx = TransactionBuilder::coinbase()
                .with_output(&address_1, 1000)
                .build();
            let block_0 = BlockBuilder::genesis()
                .with_transaction(coinbase_tx.clone())
                .build();
            let tx = TransactionBuilder::new()
                .with_input(bitcoin::OutPoint::new(coinbase_tx.txid(), 0))
                .with_output(&address_2, 1000)
                .build();
            let block_1 = BlockBuilder::with_prev_header(block_0.header)
                .with_transaction(tx.clone())
                .build();

            // Set the state.
            let mut state = State::new(2, *network, block_0);
            store::insert_block(&mut state, block_1).unwrap();

            // With up to one confirmation, expect address 2 to have a balance 1000, and
            // address 1 to have a balance of 0.
            for min_confirmations in [None, Some(0), Some(1)].iter() {
                assert_eq!(
                    get_balance(&state, &address_2.to_string(), *min_confirmations),
                    Ok(1000)
                );

                assert_eq!(
                    get_balance(&state, &address_1.to_string(), *min_confirmations),
                    Ok(0)
                );
            }

            // With two confirmations, expect address 2 to have a balance of 0, and address 1 to
            // have a balance of 1000.
            assert_eq!(get_balance(&state, &address_2.to_string(), Some(2)), Ok(0));
            assert_eq!(
                get_balance(&state, &address_1.to_string(), Some(2)),
                Ok(1000)
            );

            // With >= 2 confirmations, we should get an error as that's higher than
            // the chain's height.
            for i in 3..10 {
                assert_eq!(
                    get_balance(&state, &address_2.to_string(), Some(i)),
                    Err(GetBalanceError::MinConfirmationsTooLarge { given: i, max: 2 })
                );
                assert_eq!(
                    get_balance(&state, &address_1.to_string(), Some(i)),
                    Err(GetBalanceError::MinConfirmationsTooLarge { given: i, max: 2 })
                );
            }
        }
    }

    #[test]
    fn get_utxos_min_confirmations() {
        for network in [
            Network::Bitcoin,
            Network::Regtest,
            Network::Testnet,
            Network::Signet,
        ]
        .iter()
        {
            // Generate addresses.
            let address_1 = {
                let secp = Secp256k1::new();
                let mut rng = OsRng::new().unwrap();
                Address::p2pkh(&PublicKey::new(secp.generate_keypair(&mut rng).1), *network)
            };

            let address_2 = {
                let secp = Secp256k1::new();
                let mut rng = OsRng::new().unwrap();
                Address::p2pkh(&PublicKey::new(secp.generate_keypair(&mut rng).1), *network)
            };

            // Create a genesis block where 1000 satoshis are given to the address_1, followed
            // by a block where address_1 gives 1000 satoshis to address_2.
            let coinbase_tx = TransactionBuilder::coinbase()
                .with_output(&address_1, 1000)
                .build();
            let block_0 = BlockBuilder::genesis()
                .with_transaction(coinbase_tx.clone())
                .build();
            let tx = TransactionBuilder::new()
                .with_input(bitcoin::OutPoint::new(coinbase_tx.txid(), 0))
                .with_output(&address_2, 1000)
                .build();
            let block_1 = BlockBuilder::with_prev_header(block_0.header)
                .with_transaction(tx.clone())
                .build();

            // Set the state.
            let mut state = State::new(2, *network, block_0.clone());
            store::insert_block(&mut state, block_1.clone()).unwrap();

            // With up to one confirmation, expect address 2 to have one UTXO, and
            // address 1 to have no UTXOs.
            for min_confirmations in [None, Some(0), Some(1)].iter() {
                assert_eq!(
                    get_utxos(
                        &state,
                        &address_2.to_string(),
                        min_confirmations.map(UtxosFilter::MinConfirmations),
                    ),
                    Ok(GetUtxosResponse {
                        utxos: vec![Utxo {
                            outpoint: OutPoint {
                                txid: tx.txid().to_vec(),
                                vout: 0,
                            },
                            value: 1000,
                            height: 1,
                        }],
                        tip_block_hash: block_1.block_hash().to_vec(),
                        tip_height: 1,
                        next_page: None,
                    })
                );

                assert_eq!(
                    get_utxos(
                        &state,
                        &address_1.to_string(),
                        min_confirmations.map(UtxosFilter::MinConfirmations),
                    ),
                    Ok(GetUtxosResponse {
                        utxos: vec![],
                        tip_block_hash: block_1.block_hash().to_vec(),
                        tip_height: 1,
                        next_page: None,
                    })
                );
            }

            // With two confirmations, expect address 2 to have no UTXOs, and address 1 to
            // have one UTXO.
            assert_eq!(
                get_utxos(
                    &state,
                    &address_2.to_string(),
                    Some(UtxosFilter::MinConfirmations(2))
                ),
                Ok(GetUtxosResponse {
                    utxos: vec![],
                    tip_block_hash: block_0.block_hash().to_vec(),
                    tip_height: 0,
                    next_page: None,
                })
            );
            assert_eq!(
                get_utxos(
                    &state,
                    &address_1.to_string(),
                    Some(UtxosFilter::MinConfirmations(2))
                ),
                Ok(GetUtxosResponse {
                    utxos: vec![Utxo {
                        outpoint: OutPoint {
                            txid: coinbase_tx.txid().to_vec(),
                            vout: 0,
                        },
                        value: 1000,
                        height: 0,
                    }],
                    tip_block_hash: block_0.block_hash().to_vec(),
                    tip_height: 0,
                    next_page: None,
                })
            );

            // With >= 2 confirmations, we should get an error as that's higher than
            // the chain's height.
            for i in 3..10 {
                assert_eq!(
                    get_utxos(
                        &state,
                        &address_2.to_string(),
                        Some(UtxosFilter::MinConfirmations(i))
                    ),
                    Err(GetUtxosError::MinConfirmationsTooLarge { given: i, max: 2 })
                );
                assert_eq!(
                    get_utxos(
                        &state,
                        &address_1.to_string(),
                        Some(UtxosFilter::MinConfirmations(i))
                    ),
                    Err(GetUtxosError::MinConfirmationsTooLarge { given: i, max: 2 })
                );
            }
        }
    }

    #[test]
    fn send_transaction_malformed_transaction() {
        assert_eq!(
            send_transaction(
                &mut default_state(),
                SendTransactionRequest {
                    transaction: vec![1, 2, 3],
                    network: BtcTypesNetwork::Testnet,
                }
            ),
            Err(SendTransactionError::MalformedTransaction)
        );
    }

    #[test]
    fn send_transaction_adds_request_to_adapter_queue() {
        let mut state = default_state();

        // Create a fake transaction that passes verification check.
        let tx = TransactionBuilder::coinbase()
            .with_output(&random_p2tr_address(Network::Testnet), 1_000)
            .build();

        assert_eq!(state.adapter_queues.num_requests(), 0);

        let _result = send_transaction(
            &mut state,
            SendTransactionRequest {
                transaction: tx.serialize(),
                network: BtcTypesNetwork::Testnet,
            },
        );

        assert_eq!(state.adapter_queues.num_requests(), 1);
    }

    #[test]
    fn support_taproot_addresses() {
        for network in [
            Network::Bitcoin,
            Network::Regtest,
            Network::Testnet,
            Network::Signet,
        ]
        .iter()
        {
            let address = random_p2tr_address(*network);

            // Create a genesis block where 1000 satoshis are given to a taproot address.
            let coinbase_tx = TransactionBuilder::coinbase()
                .with_output(&address, 1000)
                .build();
            let block_0 = BlockBuilder::genesis()
                .with_transaction(coinbase_tx.clone())
                .build();

            let state = State::new(0, *network, block_0.clone());

            // Assert that the UTXOs of the taproot address can be retrieved.
            assert_eq!(
                get_utxos(&state, &address.to_string(), None),
                Ok(GetUtxosResponse {
                    utxos: vec![Utxo {
                        outpoint: OutPoint {
                            txid: coinbase_tx.txid().to_vec(),
                            vout: 0,
                        },
                        value: 1000,
                        height: 0,
                    }],
                    tip_block_hash: block_0.block_hash().to_vec(),
                    tip_height: 0,
                    next_page: None,
                })
            );
        }
    }
}
