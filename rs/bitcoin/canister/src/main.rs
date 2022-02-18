use bitcoin::{
    blockdata::constants::genesis_block, util::psbt::serialize::Deserialize, Address, Network,
    Transaction,
};
use ic_btc_canister::{state::State, store};
use ic_btc_types::{
    GetBalanceError, GetBalanceRequest, GetUtxosError, GetUtxosRequest, GetUtxosResponse, OutPoint,
    SendTransactionError, SendTransactionRequest, Utxo,
};
use ic_protobuf::bitcoin::v1::{GetSuccessorsRequest, GetSuccessorsResponse};
use prost::Message;
use std::{cell::RefCell, collections::VecDeque, str::FromStr};

thread_local! {
    // Initialize the canister to expect blocks from the Regtest network.
    static STATE: RefCell<State> = RefCell::new(State::new(1, Network::Regtest, genesis_block(Network::Regtest)));
    // A queue of transactions awaiting to be sent.
    static OUTGOING_TRANSACTIONS: RefCell<VecDeque<Vec<u8>>> = RefCell::new(VecDeque::new());
}

/// Retrieves the balance of the given Bitcoin address.
pub fn get_balance(state: &State, request: GetBalanceRequest) -> Result<u64, GetBalanceError> {
    if Address::from_str(&request.address).is_err() {
        return Err(GetBalanceError::MalformedAddress);
    }

    let min_confirmations = request.min_confirmations.unwrap_or(0);

    Ok(store::get_balance(
        state,
        &request.address,
        min_confirmations,
    ))
}

pub fn get_utxos(
    state: &State,
    request: GetUtxosRequest,
) -> Result<GetUtxosResponse, GetUtxosError> {
    if Address::from_str(&request.address).is_err() {
        return Err(GetUtxosError::MalformedAddress);
    }

    let min_confirmations = request.min_confirmations.unwrap_or(0);

    let main_chain_height = store::main_chain_height(state);

    let utxos: Vec<Utxo> = store::get_utxos(state, &request.address, min_confirmations)
        .into_iter()
        .map(|(outpoint, txout, height)| Utxo {
            outpoint: OutPoint {
                txid: outpoint.txid.to_vec(),
                vout: outpoint.vout,
            },
            value: txout.value,
            height,
            confirmations: main_chain_height - height + 1,
        })
        .collect();

    Ok(GetUtxosResponse {
        total_count: utxos.len() as u32,
        utxos,
    })
}

pub fn send_transaction(request: SendTransactionRequest) -> Result<(), SendTransactionError> {
    if Transaction::deserialize(&request.transaction).is_err() {
        return Err(SendTransactionError::MalformedTransaction);
    }

    // NOTE: In the final release, transactions will be cached for up to 24 hours and
    // occasionally resent to the network until the transaction is observed in a block.

    OUTGOING_TRANSACTIONS.with(|txs| {
        txs.borrow_mut().push_back(request.transaction);
    });

    Ok(())
}

// Below are helper methods used by the adapter shim. They will not be included in the main
// release.

// Retrieves a `GetSuccessorsRequest` to send to the adapter.
pub fn get_successors_request(state: &State) -> Vec<u8> {
    let block_hashes = store::get_unstable_blocks(state)
        .iter()
        .map(|b| b.block_hash().to_vec())
        .collect();

    println!("block hashes: {:?}", block_hashes);
    GetSuccessorsRequest { block_hashes }.encode_to_vec()
}

pub fn has_outgoing_transaction() -> bool {
    OUTGOING_TRANSACTIONS.with(|txs| !txs.borrow_mut().is_empty())
}

// Retrieve a raw tx to send to the network
pub fn get_outgoing_transaction() -> Option<Vec<u8>> {
    OUTGOING_TRANSACTIONS.with(|txs| txs.borrow_mut().pop_front())
}

// Process a (binary) `GetSuccessorsResponse` received from the adapter.
// Returns the height of the chain after the response is processed.
pub fn get_successors_response(state: &mut State, response_vec: Vec<u8>) -> u32 {
    let response = GetSuccessorsResponse::decode(&*response_vec).unwrap();

    for block_proto in response.blocks {
        let block = ic_btc_canister::block::from_proto(&block_proto);
        println!("Processing block with hash: {}", block.block_hash());

        let block_hash = block.block_hash();
        if store::insert_block(state, block).is_err() {
            println!(
                "Received block that doesn't extend existing blocks: {}",
                block_hash
            );
        }
    }

    store::main_chain_height(state)
}

fn main() {}

#[cfg(test)]
mod test {
    use super::*;
    use bitcoin::secp256k1::rand::rngs::OsRng;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::{Address, PublicKey};
    use ic_btc_canister::test_builder::{BlockBuilder, TransactionBuilder};

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
            let state = State::new(0, *network, genesis_block);

            assert_eq!(
                get_utxos(
                    &state,
                    GetUtxosRequest {
                        address: address.to_string(),
                        min_confirmations: None
                    },
                ),
                Ok(GetUtxosResponse {
                    utxos: vec![Utxo {
                        outpoint: OutPoint {
                            txid: coinbase_tx.txid().to_vec(),
                            vout: 0
                        },
                        value: 1000,
                        height: 1,
                        confirmations: 1
                    }],
                    total_count: 1
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
                    min_confirmations: None
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

            // With >= 2 confirmations, both addresses should have an empty UTXO set.
            for i in 3..10 {
                assert_eq!(
                    get_balance(
                        &state,
                        GetBalanceRequest {
                            address: address_2.to_string(),
                            min_confirmations: Some(i)
                        },
                    ),
                    Ok(0)
                );
                assert_eq!(
                    get_balance(
                        &state,
                        GetBalanceRequest {
                            address: address_1.to_string(),
                            min_confirmations: Some(i)
                        },
                    ),
                    Ok(0)
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
            let mut state = State::new(2, *network, block_0);
            store::insert_block(&mut state, block_1).unwrap();

            // With up to one confirmation, expect address 2 to have one UTXO, and
            // address 1 to have no UTXOs.
            for min_confirmations in [None, Some(0), Some(1)].iter() {
                assert_eq!(
                    get_utxos(
                        &state,
                        GetUtxosRequest {
                            address: address_2.to_string(),
                            min_confirmations: *min_confirmations
                        },
                    ),
                    Ok(GetUtxosResponse {
                        utxos: vec![Utxo {
                            outpoint: OutPoint {
                                txid: tx.txid().to_vec(),
                                vout: 0,
                            },
                            value: 1000,
                            height: 2,
                            confirmations: 1,
                        }],
                        total_count: 1
                    })
                );

                assert_eq!(
                    get_utxos(
                        &state,
                        GetUtxosRequest {
                            address: address_1.to_string(),
                            min_confirmations: *min_confirmations
                        },
                    ),
                    Ok(GetUtxosResponse {
                        utxos: vec![],
                        total_count: 0
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
                        min_confirmations: Some(2)
                    },
                ),
                Ok(GetUtxosResponse {
                    utxos: vec![],
                    total_count: 0
                })
            );
            assert_eq!(
                get_utxos(
                    &state,
                    GetUtxosRequest {
                        address: address_1.to_string(),
                        min_confirmations: Some(2)
                    },
                ),
                Ok(GetUtxosResponse {
                    utxos: vec![Utxo {
                        outpoint: OutPoint {
                            txid: coinbase_tx.txid().to_vec(),
                            vout: 0,
                        },
                        value: 1000,
                        height: 1,
                        confirmations: 2,
                    }],
                    total_count: 1
                })
            );

            // With >= 2 confirmations, both addresses should have an empty UTXO set.
            for i in 3..10 {
                assert_eq!(
                    get_utxos(
                        &state,
                        GetUtxosRequest {
                            address: address_2.to_string(),
                            min_confirmations: Some(i)
                        },
                    ),
                    Ok(GetUtxosResponse {
                        utxos: vec![],
                        total_count: 0
                    })
                );
                assert_eq!(
                    get_utxos(
                        &state,
                        GetUtxosRequest {
                            address: address_1.to_string(),
                            min_confirmations: Some(i)
                        },
                    ),
                    Ok(GetUtxosResponse {
                        utxos: vec![],
                        total_count: 0
                    })
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
