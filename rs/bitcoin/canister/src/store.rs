use crate::{
    blocktree::BlockDoesNotExtendTree, state::State, types::Height, unstable_blocks, utxoset,
};
use bitcoin::{Address, Block, Txid};
use ic_btc_types::{GetBalanceError, GetUtxosError, GetUtxosResponse, Satoshi, Utxo};
use lazy_static::lazy_static;
use std::str::FromStr;

lazy_static! {
    static ref DUPLICATE_TX_IDS: [Txid; 2] = [
        Txid::from_str("d5d27987d2a3dfc724e359870c6644b40e497bdc0589a033220fe15429d88599").unwrap(),
        Txid::from_str("e3bf3d07d4b0375638d5f1db5255fe07ba2c4cb067cd81b84ee974b6585fb468").unwrap()
    ];
}

/// Returns the balance of a bitcoin address.
pub fn get_balance(
    state: &State,
    address: &str,
    min_confirmations: u32,
) -> Result<Satoshi, GetBalanceError> {
    // NOTE: It is safe to sum up the balances here without the risk of overflow.
    // The maximum number of bitcoins is 2.1 * 10^7, which is 2.1* 10^15 satoshis.
    // That is well below the max value of a `u64`.
    let mut balance = 0;
    for utxo in get_utxos(state, address, min_confirmations)?.utxos {
        balance += utxo.value;
    }

    Ok(balance)
}

/// Returns the set of UTXOs for a given bitcoin address.
/// Transactions with confirmations < `min_confirmations` are not considered.
pub fn get_utxos(
    state: &State,
    address: &str,
    min_confirmations: u32,
) -> Result<GetUtxosResponse, GetUtxosError> {
    if Address::from_str(address).is_err() {
        return Err(GetUtxosError::MalformedAddress);
    }

    let main_chain = unstable_blocks::get_main_chain(&state.unstable_blocks);
    if main_chain.len() < min_confirmations as usize {
        return Err(GetUtxosError::MinConfirmationsTooLarge {
            given: min_confirmations,
            max: main_chain.len() as u32,
        });
    }

    let mut address_utxos = utxoset::get_utxos(&state.utxos, address);
    let main_chain_height = state.height + (main_chain.len() as u32) - 1;
    let mut tip_block_hash = None;
    let mut tip_block_height = None;

    // Apply unstable blocks to the UTXO set.
    for (i, block) in main_chain.iter().enumerate() {
        let block_height = state.height + (i as u32);
        let confirmations = main_chain_height - block_height + 1;

        if confirmations < min_confirmations {
            // The block has fewer confirmations than requested.
            // We can stop now since all remaining blocks will have fewer confirmations.
            break;
        }

        for tx in &block.txdata {
            address_utxos.insert_tx(tx, block_height);
        }

        tip_block_hash = Some(block.block_hash());
        tip_block_height = Some(block_height);
    }

    let utxos: Vec<Utxo> = address_utxos.into_vec();

    Ok(GetUtxosResponse {
        total_count: utxos.len() as u32,
        utxos,
        // TODO(EXC-1010): We are guaranteed that the tip block hash and height
        // are always available. Refactor the code to avoid this panic.
        tip_block_hash: tip_block_hash.expect("Tip block must exist").to_vec(),
        tip_height: tip_block_height.expect("Tip height must exist"),
    })
}

/// Inserts a block into the state.
/// Returns an error if the block doesn't extend any known block in the state.
pub fn insert_block(state: &mut State, block: Block) -> Result<(), BlockDoesNotExtendTree> {
    // The block is first inserted into the unstable blocks.
    unstable_blocks::push(&mut state.unstable_blocks, block)?;

    // Process a stable block, if any.
    // TODO(EXC-932): Process all stable blocks, not just one.
    if let Some(new_stable_block) = unstable_blocks::pop(&mut state.unstable_blocks) {
        for tx in &new_stable_block.txdata {
            utxoset::insert_tx(&mut state.utxos, tx, state.height);
        }

        state.height += 1;
    }

    Ok(())
}

pub fn main_chain_height(state: &State) -> Height {
    unstable_blocks::get_main_chain(&state.unstable_blocks).len() as u32 + state.height - 1
}

pub fn get_unstable_blocks(state: &State) -> Vec<&Block> {
    unstable_blocks::get_blocks(&state.unstable_blocks)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::utxos::UtxosTrait;
    use bitcoin::blockdata::constants::genesis_block;
    use bitcoin::secp256k1::rand::rngs::OsRng;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::{consensus::Decodable, Address, BlockHash, Network, PublicKey};
    use byteorder::{LittleEndian, ReadBytesExt};
    use ic_btc_test_utils::{BlockBuilder, TransactionBuilder};
    use ic_btc_types::OutPoint;
    use std::fs::File;
    use std::str::FromStr;
    use std::{collections::HashMap, io::BufReader, path::PathBuf};

    fn process_chain(state: &mut State, num_blocks: u32) {
        let mut chain: Vec<Block> = vec![];

        let mut blocks: HashMap<BlockHash, Block> = HashMap::new();

        let mut blk_file = BufReader::new(File::open("./test-data/100k_blocks.dat").unwrap());

        loop {
            let magic = match blk_file.read_u32::<LittleEndian>() {
                Err(_) => break,
                Ok(magic) => {
                    if magic == 0 {
                        // Reached EOF
                        break;
                    }
                    magic
                }
            };
            assert_eq!(magic, 0xD9B4BEF9);

            let _block_size = blk_file.read_u32::<LittleEndian>().unwrap();

            let block = Block::consensus_decode(&mut blk_file).unwrap();

            blocks.insert(block.header.prev_blockhash, block);
        }

        println!("# blocks in file: {}", blocks.len());

        // Build the chain
        chain.push(
            blocks
                .remove(&genesis_block(Network::Bitcoin).block_hash())
                .unwrap(),
        );
        for _ in 1..num_blocks {
            let next_block = blocks.remove(&chain[chain.len() - 1].block_hash()).unwrap();
            chain.push(next_block);
        }

        println!("Built chain with length: {}", chain.len());

        let mut i = 0;
        for block in chain.into_iter() {
            insert_block(state, block).unwrap();
            i += 1;
            if i % 1000 == 0 {
                println!("processed block: {}", i);
            }
        }
    }

    #[test]
    fn to_from_proto() {
        let root: PathBuf = tempfile::Builder::new()
            .prefix("bitcoin")
            .tempdir()
            .unwrap()
            .path()
            .into();

        let mut block = BlockBuilder::genesis()
            .with_transaction(TransactionBuilder::coinbase().build())
            .build();
        let mut state = State::new(2, Network::Bitcoin, block.clone());

        for _ in 0..100 {
            block = BlockBuilder::with_prev_header(block.header)
                .with_transaction(TransactionBuilder::coinbase().build())
                .build();
            insert_block(&mut state, block.clone()).unwrap();
        }

        state.serialize(&root).unwrap();

        let new_state = State::load(&root).unwrap();

        assert_eq!(new_state.height, state.height);
        assert_eq!(new_state.unstable_blocks, state.unstable_blocks);
        assert_eq!(new_state.utxos.network, state.utxos.network);
        assert_eq!(
            new_state.utxos.utxos.large_utxos,
            state.utxos.utxos.large_utxos
        );

        for (new_entry, old_entry) in new_state.utxos.utxos.iter().zip(state.utxos.utxos.iter()) {
            assert_eq!(new_entry, old_entry);
        }

        assert_eq!(
            new_state.utxos.address_to_outpoints.len(),
            state.utxos.address_to_outpoints.len()
        );

        for (new_entry, old_entry) in new_state
            .utxos
            .address_to_outpoints
            .iter()
            .zip(state.utxos.address_to_outpoints.iter())
        {
            assert_eq!(new_entry, old_entry);
        }
    }

    #[test]
    fn utxos_forks() {
        let secp = Secp256k1::new();
        let mut rng = OsRng::new().unwrap();

        // Create some BTC addresses.
        let address_1 = Address::p2pkh(
            &PublicKey::new(secp.generate_keypair(&mut rng).1),
            Network::Bitcoin,
        );
        let address_2 = Address::p2pkh(
            &PublicKey::new(secp.generate_keypair(&mut rng).1),
            Network::Bitcoin,
        );
        let address_3 = Address::p2pkh(
            &PublicKey::new(secp.generate_keypair(&mut rng).1),
            Network::Bitcoin,
        );
        let address_4 = Address::p2pkh(
            &PublicKey::new(secp.generate_keypair(&mut rng).1),
            Network::Bitcoin,
        );

        // Create a genesis block where 1000 satoshis are given to address 1.
        let coinbase_tx = TransactionBuilder::coinbase()
            .with_output(&address_1, 1000)
            .build();

        let block_0 = BlockBuilder::genesis()
            .with_transaction(coinbase_tx.clone())
            .build();

        let mut state = State::new(2, Network::Bitcoin, block_0.clone());

        let block_0_utxos = GetUtxosResponse {
            utxos: vec![Utxo {
                outpoint: OutPoint {
                    txid: coinbase_tx.txid().to_vec(),
                    vout: 0,
                },
                value: 1000,
                height: 0,
            }],
            total_count: 1,
            tip_block_hash: block_0.block_hash().to_vec(),
            tip_height: 0,
        };

        // Assert that the UTXOs of address 1 are present.
        assert_eq!(
            get_utxos(&state, &address_1.to_string(), 0),
            Ok(block_0_utxos.clone())
        );

        // Extend block 0 with block 1 that spends the 1000 satoshis and gives them to address 2.
        let tx = TransactionBuilder::with_input(bitcoin::OutPoint::new(coinbase_tx.txid(), 0))
            .with_output(&address_2, 1000)
            .build();
        let block_1 = BlockBuilder::with_prev_header(block_0.header)
            .with_transaction(tx.clone())
            .build();

        insert_block(&mut state, block_1.clone()).unwrap();

        // address 2 should now have the UTXO while address 1 has no UTXOs.
        assert_eq!(
            get_utxos(&state, &address_2.to_string(), 0),
            Ok(GetUtxosResponse {
                utxos: vec![Utxo {
                    outpoint: OutPoint {
                        txid: tx.txid().to_vec(),
                        vout: 0,
                    },
                    value: 1000,
                    height: 1,
                }],
                total_count: 1,
                tip_block_hash: block_1.block_hash().to_vec(),
                tip_height: 1,
            })
        );

        assert_eq!(
            get_utxos(&state, &address_1.to_string(), 0),
            Ok(GetUtxosResponse {
                utxos: vec![],
                total_count: 0,
                tip_block_hash: block_1.block_hash().to_vec(),
                tip_height: 1,
            })
        );

        // Extend block 0 (again) with block 1 that spends the 1000 satoshis to address 3
        // This causes a fork.
        let tx = TransactionBuilder::with_input(bitcoin::OutPoint::new(coinbase_tx.txid(), 0))
            .with_output(&address_3, 1000)
            .build();
        let block_1_prime = BlockBuilder::with_prev_header(block_0.header)
            .with_transaction(tx.clone())
            .build();
        insert_block(&mut state, block_1_prime.clone()).unwrap();

        // Because block 1 and block 1' contest with each other, neither of them are included
        // in the UTXOs. Only the UTXOs of block 0 are returned.
        assert_eq!(
            get_utxos(&state, &address_2.to_string(), 0),
            Ok(GetUtxosResponse {
                utxos: vec![],
                total_count: 0,
                tip_block_hash: block_0.block_hash().to_vec(),
                tip_height: 0,
            })
        );
        assert_eq!(
            get_utxos(&state, &address_3.to_string(), 0),
            Ok(GetUtxosResponse {
                utxos: vec![],
                total_count: 0,
                tip_block_hash: block_0.block_hash().to_vec(),
                tip_height: 0,
            })
        );
        assert_eq!(
            get_utxos(&state, &address_1.to_string(), 0),
            Ok(block_0_utxos)
        );

        // Now extend block 1' with another block that transfers the funds to address 4.
        // In this case, the fork of [block 1', block 2'] will be considered the "main"
        // chain, and will be part of the UTXOs.
        let tx = TransactionBuilder::with_input(bitcoin::OutPoint::new(tx.txid(), 0))
            .with_output(&address_4, 1000)
            .build();
        let block_2_prime = BlockBuilder::with_prev_header(block_1_prime.header)
            .with_transaction(tx.clone())
            .build();
        insert_block(&mut state, block_2_prime.clone()).unwrap();

        // Address 1 has no UTXOs since they were spent on the main chain.
        assert_eq!(
            get_utxos(&state, &address_1.to_string(), 0),
            Ok(GetUtxosResponse {
                utxos: vec![],
                total_count: 0,
                tip_block_hash: block_2_prime.block_hash().to_vec(),
                tip_height: 2,
            })
        );
        assert_eq!(
            get_utxos(&state, &address_2.to_string(), 0),
            Ok(GetUtxosResponse {
                utxos: vec![],
                total_count: 0,
                tip_block_hash: block_2_prime.block_hash().to_vec(),
                tip_height: 2,
            })
        );
        assert_eq!(
            get_utxos(&state, &address_3.to_string(), 0),
            Ok(GetUtxosResponse {
                utxos: vec![],
                total_count: 0,
                tip_block_hash: block_2_prime.block_hash().to_vec(),
                tip_height: 2,
            })
        );
        // The funds are now with address 4.
        assert_eq!(
            get_utxos(&state, &address_4.to_string(), 0),
            Ok(GetUtxosResponse {
                utxos: vec![Utxo {
                    outpoint: OutPoint {
                        txid: tx.txid().to_vec(),
                        vout: 0,
                    },
                    value: 1000,
                    height: 2,
                }],
                total_count: 1,
                tip_block_hash: block_2_prime.block_hash().to_vec(),
                tip_height: 2,
            })
        );
    }

    #[test]
    fn process_100k_blocks() {
        let mut state = State::new(10, Network::Bitcoin, genesis_block(Network::Bitcoin));

        process_chain(&mut state, 100_000);

        let mut total_supply = 0;
        for (_, (v, _)) in state.utxos.utxos.iter() {
            total_supply += v.value;
        }

        // NOTE: The duplicate transactions cause us to lose some of the supply,
        // which we deduct in this assertion.
        assert_eq!(
            ((state.height as u64) - DUPLICATE_TX_IDS.len() as u64) * 5000000000,
            total_supply
        );

        // Check some random addresses that the balance is correct:

        // https://blockexplorer.one/bitcoin/mainnet/address/1PgZsaGjvssNCqHHisshLoCFeUjxPhutTh
        assert_eq!(
            get_balance(&state, "1PgZsaGjvssNCqHHisshLoCFeUjxPhutTh", 0),
            Ok(4000000)
        );

        assert_eq!(
            get_utxos(&state, "1PgZsaGjvssNCqHHisshLoCFeUjxPhutTh", 0),
            Ok(GetUtxosResponse {
                utxos: vec![Utxo {
                    outpoint: OutPoint {
                        txid: Txid::from_str(
                            "1a592a31c79f817ed787b6acbeef29b0f0324179820949d7da6215f0f4870c42",
                        )
                        .unwrap()
                        .to_vec(),
                        vout: 1,
                    },
                    value: 4000000,
                    height: 75361,
                }],
                total_count: 1,
                // The tip should be the block hash at height 100,000
                // https://bitcoinchain.com/block_explorer/block/100000/
                tip_block_hash: BlockHash::from_str(
                    "000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506"
                )
                .unwrap()
                .to_vec(),
                tip_height: 100_000,
            })
        );

        // https://blockexplorer.one/bitcoin/mainnet/address/12tGGuawKdkw5NeDEzS3UANhCRa1XggBbK
        assert_eq!(
            get_balance(&state, "12tGGuawKdkw5NeDEzS3UANhCRa1XggBbK", 0),
            Ok(500000000)
        );
        assert_eq!(
            get_utxos(&state, "12tGGuawKdkw5NeDEzS3UANhCRa1XggBbK", 0),
            Ok(GetUtxosResponse {
                utxos: vec![Utxo {
                    outpoint: OutPoint {
                        txid: Txid::from_str(
                            "3371b3978e7285d962fd54656aca6b3191135a1db838b5c689b8a44a7ede6a31",
                        )
                        .unwrap()
                        .to_vec(),
                        vout: 0,
                    },
                    value: 500000000,
                    height: 66184,
                }],
                total_count: 1,
                // The tip should be the block hash at height 100,000
                // https://bitcoinchain.com/block_explorer/block/100000/
                tip_block_hash: BlockHash::from_str(
                    "000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506"
                )
                .unwrap()
                .to_vec(),
                tip_height: 100_000,
            })
        );

        // This address spent its BTC at height 99,996. At 0 confirmations
        // (height 100,000) it should have no BTC.
        assert_eq!(
            get_balance(&state, "1K791w8Y1CXwyG3zAf9EzpoZvpYH8Z2Rro", 0),
            Ok(0)
        );

        // At 10 confirmations it should have its BTC.
        assert_eq!(
            get_balance(&state, "1K791w8Y1CXwyG3zAf9EzpoZvpYH8Z2Rro", 10),
            Ok(48_0000_0000)
        );

        // At 6 confirmations it should have its BTC.
        assert_eq!(
            get_balance(&state, "1K791w8Y1CXwyG3zAf9EzpoZvpYH8Z2Rro", 6),
            Ok(48_0000_0000)
        );

        assert_eq!(
            get_utxos(&state, "1K791w8Y1CXwyG3zAf9EzpoZvpYH8Z2Rro", 6),
            Ok(GetUtxosResponse {
                utxos: vec![Utxo {
                    outpoint: OutPoint {
                        txid: Txid::from_str(
                            "2bdd8506980479fb57d848ddbbb29831b4d468f9dc5d572ccdea69edec677ed6",
                        )
                        .unwrap()
                        .to_vec(),
                        vout: 1,
                    },
                    value: 48_0000_0000,
                    height: 96778,
                }],
                total_count: 1,
                // The tip should be the block hash at height 99,995
                // https://blockchair.com/bitcoin/block/99995
                tip_block_hash: BlockHash::from_str(
                    "00000000000471d4db69f006cefc583aee6dec243d63c6a09cd5c02e0ef52523",
                )
                .unwrap()
                .to_vec(),
                tip_height: 99_995,
            })
        );

        // At 5 confirmations the BTC is spent.
        assert_eq!(
            get_balance(&state, "1K791w8Y1CXwyG3zAf9EzpoZvpYH8Z2Rro", 5),
            Ok(0)
        );

        // The BTC is spent to the following two addresses.
        assert_eq!(
            get_balance(&state, "1NhzJ8bsdmGK39vSJtdQw3R2HyNtUmGxcr", 5),
            Ok(3_4500_0000)
        );

        assert_eq!(
            get_balance(&state, "13U77vKQcTjpZ7gww4K8Nreq2ffGBQKxmr", 5),
            Ok(44_5500_0000)
        );

        // And these addresses should have a balance of zero before that height.
        assert_eq!(
            get_balance(&state, "1NhzJ8bsdmGK39vSJtdQw3R2HyNtUmGxcr", 6),
            Ok(0)
        );

        assert_eq!(
            get_balance(&state, "13U77vKQcTjpZ7gww4K8Nreq2ffGBQKxmr", 6),
            Ok(0)
        );
    }

    #[test]
    fn get_utxos_min_confirmations_greater_than_chain_height() {
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

            // Create a block where 1000 satoshis are given to the address_1.
            let tx = TransactionBuilder::coinbase()
                .with_output(&address_1, 1000)
                .build();
            let block_0 = BlockBuilder::genesis().with_transaction(tx.clone()).build();

            let state = State::new(1, *network, block_0.clone());

            // Expect an empty UTXO set.
            assert_eq!(
                get_utxos(&state, &address_1.to_string(), 1),
                Ok(GetUtxosResponse {
                    utxos: vec![Utxo {
                        outpoint: OutPoint {
                            txid: tx.txid().to_vec(),
                            vout: 0
                        },
                        value: 1000,
                        height: 0,
                    }],
                    total_count: 1,
                    tip_block_hash: block_0.block_hash().to_vec(),
                    tip_height: 0
                })
            );
            assert_eq!(
                get_utxos(&state, &address_1.to_string(), 2),
                Err(GetUtxosError::MinConfirmationsTooLarge { given: 2, max: 1 })
            );
        }
    }

    #[test]
    fn get_utxos_does_not_include_other_addresses() {
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

            let mut state = State::new(2, *network, block_0);
            insert_block(&mut state, block_1.clone()).unwrap();

            // Address 1 should have no UTXOs at zero confirmations.
            assert_eq!(
                get_utxos(&state, &address_1.to_string(), 0),
                Ok(GetUtxosResponse {
                    utxos: vec![],
                    total_count: 0,
                    tip_block_hash: block_1.block_hash().to_vec(),
                    tip_height: 1
                })
            );
        }
    }
}
