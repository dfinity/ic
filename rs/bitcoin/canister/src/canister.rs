use crate::{metrics::BitcoinCanisterMetrics, state::State, store};
use bitcoin::{util::psbt::serialize::Deserialize, Transaction};
use ic_btc_types::{
    GetBalanceError, GetBalanceRequest, GetUtxosError, GetUtxosRequest, GetUtxosResponse,
    SendTransactionError, SendTransactionRequest, UtxosFilter,
};
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;

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
pub fn get_balance(state: &State, request: GetBalanceRequest) -> Result<u64, GetBalanceError> {
    let min_confirmations = request.min_confirmations.unwrap_or(0);

    store::get_balance(state, &request.address, min_confirmations)
}

pub fn get_utxos(
    state: &State,
    request: GetUtxosRequest,
) -> Result<GetUtxosResponse, GetUtxosError> {
    match request.filter {
        None => {
            // No filter is specified. Return all UTXOs for the address.
            store::get_utxos(state, &request.address, 0)
        }
        Some(UtxosFilter::MinConfirmations(min_confirmations)) => {
            // Return UTXOs with the requested number of confirmations.
            store::get_utxos(state, &request.address, min_confirmations)
        }
        Some(UtxosFilter::Page { .. }) => {
            // It's safe to use `todo!` here as this code isn't yet hooked up the rest of the
            // replica.
            todo!("EXC-1009")
        }
    }
}

pub fn send_transaction(request: SendTransactionRequest) -> Result<(), SendTransactionError> {
    if Transaction::deserialize(&request.transaction).is_err() {
        return Err(SendTransactionError::MalformedTransaction);
    }

    // TODO(EXC-911): Implement send transactions.

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use bitcoin::secp256k1::rand::rngs::OsRng;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::{blockdata::constants::genesis_block, Address, Network, PublicKey};
    use ic_btc_test_utils::{BlockBuilder, TransactionBuilder};
    use ic_btc_types::{OutPoint, Utxo};

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
                get_utxos(
                    &state,
                    GetUtxosRequest {
                        address: address.to_string(),
                        filter: None
                    },
                ),
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
            get_balance(
                &default_state(),
                GetBalanceRequest {
                    address: String::from("not an address"),
                    min_confirmations: None
                },
            ),
            Err(GetBalanceError::MalformedAddress)
        );
    }

    #[test]
    fn get_utxos_malformed_address() {
        assert_eq!(
            get_utxos(
                &default_state(),
                GetUtxosRequest {
                    address: String::from("not an address"),
                    filter: None
                },
            ),
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
            let tx = TransactionBuilder::with_input(bitcoin::OutPoint::new(coinbase_tx.txid(), 0))
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
                    get_balance(
                        &state,
                        GetBalanceRequest {
                            address: address_2.to_string(),
                            min_confirmations: *min_confirmations
                        },
                    ),
                    Ok(1000)
                );

                assert_eq!(
                    get_balance(
                        &state,
                        GetBalanceRequest {
                            address: address_1.to_string(),
                            min_confirmations: *min_confirmations
                        },
                    ),
                    Ok(0)
                );
            }

            // With two confirmations, expect address 2 to have a balance of 0, and address 1 to
            // have a balance of 1000.
            assert_eq!(
                get_balance(
                    &state,
                    GetBalanceRequest {
                        address: address_2.to_string(),
                        min_confirmations: Some(2)
                    },
                ),
                Ok(0)
            );
            assert_eq!(
                get_balance(
                    &state,
                    GetBalanceRequest {
                        address: address_1.to_string(),
                        min_confirmations: Some(2)
                    },
                ),
                Ok(1000)
            );

            // With >= 2 confirmations, we should get an error as that's higher than
            // the chain's height.
            for i in 3..10 {
                assert_eq!(
                    get_balance(
                        &state,
                        GetBalanceRequest {
                            address: address_2.to_string(),
                            min_confirmations: Some(i)
                        },
                    ),
                    Err(GetBalanceError::MinConfirmationsTooLarge { given: i, max: 2 })
                );
                assert_eq!(
                    get_balance(
                        &state,
                        GetBalanceRequest {
                            address: address_1.to_string(),
                            min_confirmations: Some(i)
                        },
                    ),
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
            let tx = TransactionBuilder::with_input(bitcoin::OutPoint::new(coinbase_tx.txid(), 0))
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
                        GetUtxosRequest {
                            address: address_2.to_string(),
                            filter: min_confirmations.map(UtxosFilter::MinConfirmations),
                        },
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
                        GetUtxosRequest {
                            address: address_1.to_string(),
                            filter: min_confirmations.map(UtxosFilter::MinConfirmations),
                        },
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
                    GetUtxosRequest {
                        address: address_2.to_string(),
                        filter: Some(UtxosFilter::MinConfirmations(2))
                    },
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
                    GetUtxosRequest {
                        address: address_1.to_string(),
                        filter: Some(UtxosFilter::MinConfirmations(2))
                    },
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
                        GetUtxosRequest {
                            address: address_2.to_string(),
                            filter: Some(UtxosFilter::MinConfirmations(i))
                        },
                    ),
                    Err(GetUtxosError::MinConfirmationsTooLarge { given: i, max: 2 })
                );
                assert_eq!(
                    get_utxos(
                        &state,
                        GetUtxosRequest {
                            address: address_1.to_string(),
                            filter: Some(UtxosFilter::MinConfirmations(i))
                        },
                    ),
                    Err(GetUtxosError::MinConfirmationsTooLarge { given: i, max: 2 })
                );
            }
        }
    }

    #[test]
    fn malformed_transaction() {
        assert_eq!(
            send_transaction(SendTransactionRequest {
                transaction: vec![1, 2, 3],
            }),
            Err(SendTransactionError::MalformedTransaction)
        );
    }
}
