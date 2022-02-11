use bitcoin::{
    blockdata::constants::genesis_block, util::psbt::serialize::Deserialize, Address, Network,
    Transaction,
};
use candid::candid_method;
use ic_btc_canister::{
    proto::{GetSuccessorsRequest, GetSuccessorsResponse},
    store::State,
};
use ic_btc_types::{
    GetBalanceError, GetBalanceRequest, GetUtxosError, GetUtxosRequest, GetUtxosResponse, OutPoint,
    SendTransactionError, SendTransactionRequest, Utxo,
};
use prost::Message;
use std::{cell::RefCell, collections::VecDeque, str::FromStr};

thread_local! {
    // Initialize the canister to expect blocks from the Regtest network.
    static STATE: RefCell<State> = RefCell::new(State::new(1, Network::Regtest, genesis_block(Network::Regtest)));
    // A queue of transactions awaiting to be sent.
    static OUTGOING_TRANSACTIONS: RefCell<VecDeque<Vec<u8>>> = RefCell::new(VecDeque::new());
}

// Retrieves the balance of the given Bitcoin address.
//
// NOTE: While this endpoint could've been a query, it is exposed as an update call
//       for security reasons.
#[candid_method(update)]
pub fn get_balance(request: GetBalanceRequest) -> Result<u64, GetBalanceError> {
    if Address::from_str(&request.address).is_err() {
        return Err(GetBalanceError::MalformedAddress);
    }

    let min_confirmations = request.min_confirmations.unwrap_or(0);

    Ok(STATE.with(|s| s.borrow().get_balance(&request.address, min_confirmations)))
}

#[candid_method(update)]
pub fn get_utxos(request: GetUtxosRequest) -> Result<GetUtxosResponse, GetUtxosError> {
    if Address::from_str(&request.address).is_err() {
        return Err(GetUtxosError::MalformedAddress);
    }

    let min_confirmations = request.min_confirmations.unwrap_or(0);

    STATE.with(|s| {
        let main_chain_height = s.borrow().main_chain_height();

        let utxos: Vec<Utxo> = s
            .borrow()
            .get_utxos(&request.address, min_confirmations)
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
    })
}

#[candid_method(update)]
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
pub fn get_successors_request() -> Vec<u8> {
    let block_hashes = STATE.with(|state| {
        let state = state.borrow();
        state
            .get_unstable_blocks()
            .iter()
            .map(|b| b.block_hash().to_vec())
            .collect()
    });

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
pub fn get_successors_response(response_vec: Vec<u8>) -> u32 {
    let response = GetSuccessorsResponse::decode(&*response_vec).unwrap();

    for block_proto in response.blocks {
        let block = ic_btc_canister::block::from_proto(&block_proto);
        println!("Processing block with hash: {}", block.block_hash());

        STATE.with(|state| {
            let block_hash = block.block_hash();
            if state.borrow_mut().insert_block(block).is_err() {
                println!(
                    "Received block that doesn't extend existing blocks: {}",
                    block_hash
                );
            }
        });
    }

    STATE.with(|state| state.borrow().main_chain_height())
}

fn main() {}

#[cfg(test)]
mod test {
    use super::*;
    use bitcoin::secp256k1::rand::rngs::OsRng;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::{Address, PublicKey};
    use ic_btc_canister::test_builder::{BlockBuilder, TransactionBuilder};

    #[test]
    fn check_candid_interface_compatibility() {
        use candid::types::subtype::{subtype, Gamma};
        use candid::types::Type;
        use candid::{self};
        use std::io::Write;
        use std::path::PathBuf;

        candid::export_service!();

        let actual_interface = __export_service();
        println!("Generated DID:\n {}", actual_interface);
        let mut tmp = tempfile::NamedTempFile::new().expect("failed to create a temporary file");
        write!(tmp, "{}", actual_interface).expect("failed to write interface to a temporary file");
        let (mut env1, t1) =
            candid::pretty_check_file(tmp.path()).expect("failed to check generated candid file");
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("candid.did");
        let (env2, t2) =
            candid::pretty_check_file(path.as_path()).expect("failed to open candid.did file");

        let (t1_ref, t2) = match (t1.as_ref().unwrap(), t2.unwrap()) {
            (Type::Class(_, s1), Type::Class(_, s2)) => (s1.as_ref(), *s2),
            (Type::Class(_, s1), s2 @ Type::Service(_)) => (s1.as_ref(), s2),
            (s1 @ Type::Service(_), Type::Class(_, s2)) => (s1, *s2),
            (t1, t2) => (t1, t2),
        };

        let mut gamma = Gamma::new();
        let t2 = env1.merge_type(env2, t2);
        subtype(&mut gamma, &env1, t1_ref, &t2)
            .expect("bitcoin canister interface is not compatible with the candid.did file");
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
            STATE.with(|s| s.replace(State::new(0, *network, genesis_block)));

            assert_eq!(
                get_utxos(GetUtxosRequest {
                    address: address.to_string(),
                    min_confirmations: None
                }),
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
            get_balance(GetBalanceRequest {
                address: String::from("not an address"),
                min_confirmations: None
            }),
            Err(GetBalanceError::MalformedAddress)
        );
    }

    #[test]
    fn get_utxos_malformed_address() {
        assert_eq!(
            get_utxos(GetUtxosRequest {
                address: String::from("not an address"),
                min_confirmations: None
            }),
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
            STATE.with(|s| {
                s.replace(State::new(2, *network, block_0));
                s.borrow_mut().insert_block(block_1).unwrap();
            });

            // With up to one confirmation, expect address 2 to have a balance 1000, and
            // address 1 to have a balance of 0.
            for min_confirmations in [None, Some(0), Some(1)].iter() {
                assert_eq!(
                    get_balance(GetBalanceRequest {
                        address: address_2.to_string(),
                        min_confirmations: *min_confirmations
                    }),
                    Ok(1000)
                );

                assert_eq!(
                    get_balance(GetBalanceRequest {
                        address: address_1.to_string(),
                        min_confirmations: *min_confirmations
                    }),
                    Ok(0)
                );
            }

            // With two confirmations, expect address 2 to have a balance of 0, and address 1 to
            // have a balance of 1000.
            assert_eq!(
                get_balance(GetBalanceRequest {
                    address: address_2.to_string(),
                    min_confirmations: Some(2)
                }),
                Ok(0)
            );
            assert_eq!(
                get_balance(GetBalanceRequest {
                    address: address_1.to_string(),
                    min_confirmations: Some(2)
                }),
                Ok(1000)
            );

            // With >= 2 confirmations, both addresses should have an empty UTXO set.
            for i in 3..10 {
                assert_eq!(
                    get_balance(GetBalanceRequest {
                        address: address_2.to_string(),
                        min_confirmations: Some(i)
                    }),
                    Ok(0)
                );
                assert_eq!(
                    get_balance(GetBalanceRequest {
                        address: address_1.to_string(),
                        min_confirmations: Some(i)
                    }),
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
            STATE.with(|s| {
                s.replace(State::new(2, *network, block_0));
                s.borrow_mut().insert_block(block_1).unwrap();
            });

            // With up to one confirmation, expect address 2 to have one UTXO, and
            // address 1 to have no UTXOs.
            for min_confirmations in [None, Some(0), Some(1)].iter() {
                assert_eq!(
                    get_utxos(GetUtxosRequest {
                        address: address_2.to_string(),
                        min_confirmations: *min_confirmations
                    }),
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
                    get_utxos(GetUtxosRequest {
                        address: address_1.to_string(),
                        min_confirmations: *min_confirmations
                    }),
                    Ok(GetUtxosResponse {
                        utxos: vec![],
                        total_count: 0
                    })
                );
            }

            // With two confirmations, expect address 2 to have no UTXOs, and address 1 to
            // have one UTXO.
            assert_eq!(
                get_utxos(GetUtxosRequest {
                    address: address_2.to_string(),
                    min_confirmations: Some(2)
                }),
                Ok(GetUtxosResponse {
                    utxos: vec![],
                    total_count: 0
                })
            );
            assert_eq!(
                get_utxos(GetUtxosRequest {
                    address: address_1.to_string(),
                    min_confirmations: Some(2)
                }),
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
                    get_utxos(GetUtxosRequest {
                        address: address_2.to_string(),
                        min_confirmations: Some(i)
                    }),
                    Ok(GetUtxosResponse {
                        utxos: vec![],
                        total_count: 0
                    })
                );
                assert_eq!(
                    get_utxos(GetUtxosRequest {
                        address: address_1.to_string(),
                        min_confirmations: Some(i)
                    }),
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
