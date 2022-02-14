use crate::{
    blocktree::BlockDoesNotExtendTree, proto, unstable_blocks::UnstableBlocks, utxoset::UtxoSet,
};
use bitcoin::{Block, Network, OutPoint, TxOut, Txid};
use lazy_static::lazy_static;
use std::collections::HashSet;
use std::str::FromStr;

lazy_static! {
    static ref DUPLICATE_TX_IDS: [Txid; 2] = [
        Txid::from_str("d5d27987d2a3dfc724e359870c6644b40e497bdc0589a033220fe15429d88599").unwrap(),
        Txid::from_str("e3bf3d07d4b0375638d5f1db5255fe07ba2c4cb067cd81b84ee974b6585fb468").unwrap()
    ];
}

type Height = u32;
type Satoshi = u64;

// A structure used to maintain the entire state.
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct State {
    // The height of the latest block marked as stable.
    height: Height,

    // The UTXOs of all stable blocks since genesis.
    utxos: UtxoSet,

    // Blocks inserted, but are not considered stable yet.
    unstable_blocks: UnstableBlocks,
}

impl State {
    /// Create a new blockchain.
    ///
    /// The `stability_threshold` parameter specifies how many confirmations a
    /// block needs before it is considered stable. Stable blocks are assumed
    /// to be final and are never removed.
    pub fn new(stability_threshold: u64, network: Network, genesis_block: Block) -> Self {
        Self {
            height: 0,
            utxos: UtxoSet::new(true, network),
            unstable_blocks: UnstableBlocks::new(stability_threshold, genesis_block),
        }
    }

    /// Returns the balance of a bitcoin address.
    pub fn get_balance(&self, address: &str, min_confirmations: u32) -> Satoshi {
        // NOTE: It is safe to sum up the balances here without the risk of overflow.
        // The maximum number of bitcoins is 2.1 * 10^7, which is 2.1* 10^15 satoshis.
        // That is well below the max value of a `u64`.
        let mut balance = 0;
        for (_, output, _) in self.get_utxos(address, min_confirmations) {
            balance += output.value;
        }

        balance
    }

    /// Returns the set of UTXOs for a given bitcoin address.
    /// Transactions with confirmations < `min_confirmations` are not considered.
    pub fn get_utxos(
        &self,
        address: &str,
        min_confirmations: u32,
    ) -> HashSet<(OutPoint, TxOut, Height)> {
        let mut address_utxos = self.utxos.get_utxos(address);

        // Apply unstable blocks to the UTXO set.
        for (i, block) in self.unstable_blocks.get_current_chain().iter().enumerate() {
            let block_height = self.stable_height() + (i as u32) + 1;
            let confirmations = self.main_chain_height() - block_height + 1;

            if confirmations < min_confirmations {
                // The block has fewer confirmations than requested.
                // We can stop now since all remaining blocks will have fewer confirmations.
                break;
            }

            for tx in &block.txdata {
                address_utxos.insert_tx(tx, block_height);
            }
        }

        address_utxos
            // Filter out UTXOs added in unstable blocks that are not for the given address.
            .get_utxos(address)
            .into_set()
            .into_iter()
            // Filter out UTXOs that are below the `min_confirmations` threshold.
            .filter(|(_, _, height)| self.main_chain_height() - height + 1 >= min_confirmations)
            .collect()
    }

    /// Insert a block into the blockchain.
    /// Returns an error if the block doesn't extend any known block in the state.
    pub fn insert_block(&mut self, block: Block) -> Result<(), BlockDoesNotExtendTree> {
        // The block is first inserted into the unstable blocks.
        self.unstable_blocks.push(block)?;

        // Process a stable block, if any.
        // TODO(EXC-932): Process all stable blocks, not just one.
        if let Some(new_stable_block) = self.unstable_blocks.pop() {
            for tx in &new_stable_block.txdata {
                self.utxos.insert_tx(tx, self.height);
            }

            self.height += 1;
        }

        Ok(())
    }

    pub fn stable_height(&self) -> Height {
        self.height
    }

    pub fn main_chain_height(&self) -> Height {
        self.unstable_blocks.get_current_chain().len() as u32 + self.height
    }

    pub fn get_unstable_blocks(&self) -> Vec<&Block> {
        self.unstable_blocks.get_blocks()
    }

    pub fn to_proto(&self) -> proto::State {
        proto::State {
            height: self.height,
            utxos: Some(self.utxos.to_proto()),
            unstable_blocks: Some(self.unstable_blocks.to_proto()),
        }
    }

    pub fn from_proto(proto_state: proto::State) -> Self {
        Self {
            height: proto_state.height,
            utxos: UtxoSet::from_proto(proto_state.utxos.unwrap()),
            unstable_blocks: UnstableBlocks::from_proto(proto_state.unstable_blocks.unwrap()),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_builder::{BlockBuilder, TransactionBuilder};
    use bitcoin::blockdata::constants::genesis_block;
    use bitcoin::secp256k1::rand::rngs::OsRng;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::{consensus::Decodable, Address, BlockHash, Network, PublicKey};
    use byteorder::{LittleEndian, ReadBytesExt};
    use maplit::hashset;
    use std::fs::File;
    use std::str::FromStr;
    use std::{collections::HashMap, io::BufReader};

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
        for _ in 0..num_blocks - 1 {
            let next_block = blocks.remove(&chain[chain.len() - 1].block_hash()).unwrap();
            chain.push(next_block);
        }

        println!("Built chain with length: {}", chain.len());

        for block in chain.into_iter() {
            state.insert_block(block).unwrap();
        }
    }

    #[test]
    fn to_from_proto() {
        use prost::Message;
        let mut block = BlockBuilder::genesis()
            .with_transaction(TransactionBuilder::coinbase().build())
            .build();
        let mut state = State::new(2, Network::Bitcoin, block.clone());

        for _ in 0..100 {
            block = BlockBuilder::with_prev_header(block.header)
                .with_transaction(TransactionBuilder::coinbase().build())
                .build();
            state.insert_block(block.clone()).unwrap();
        }

        let state_proto = state.to_proto();
        let state_proto = proto::State::decode(&*state_proto.encode_to_vec()).unwrap();
        let new_state = State::from_proto(state_proto);

        assert_eq!(new_state, state);
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

        let block_0_utxos = maplit::hashset! {
            (
                OutPoint {
                    txid: coinbase_tx.txid(),
                    vout: 0
                },
                TxOut {
                    value: 1000,
                    script_pubkey: address_1.script_pubkey()
                },
                1
            )
        };

        // Assert that the UTXOs of address 1 are present.
        assert_eq!(state.get_utxos(&address_1.to_string(), 0), block_0_utxos);

        // Extend block 0 with block 1 that spends the 1000 satoshis and gives them to address 2.
        let tx = TransactionBuilder::with_input(OutPoint::new(coinbase_tx.txid(), 0))
            .with_output(&address_2, 1000)
            .build();
        let block_1 = BlockBuilder::with_prev_header(block_0.header)
            .with_transaction(tx.clone())
            .build();

        state.insert_block(block_1).unwrap();

        // address 2 should now have the UTXO while address 1 has no UTXOs.
        assert_eq!(
            state.get_utxos(&address_2.to_string(), 0),
            hashset! {
                (
                    OutPoint::new(tx.txid(), 0),
                    TxOut {
                        value: 1000,
                        script_pubkey: address_2.script_pubkey(),
                    },
                    2
                )
            }
        );

        assert_eq!(state.get_utxos(&address_1.to_string(), 0), hashset! {});

        // Extend block 0 (again) with block 1 that spends the 1000 satoshis to address 3
        // This causes a fork.
        let tx = TransactionBuilder::with_input(OutPoint::new(coinbase_tx.txid(), 0))
            .with_output(&address_3, 1000)
            .build();
        let block_1_prime = BlockBuilder::with_prev_header(block_0.header)
            .with_transaction(tx.clone())
            .build();
        state.insert_block(block_1_prime.clone()).unwrap();

        // Because block 1 and block 1' contest with each other, neither of them are included
        // in the UTXOs. Only the UTXOs of block 0 are returned.
        assert_eq!(state.get_utxos(&address_2.to_string(), 0), hashset! {});
        assert_eq!(state.get_utxos(&address_3.to_string(), 0), hashset! {});
        assert_eq!(state.get_utxos(&address_1.to_string(), 0), block_0_utxos);

        // Now extend block 1' with another block that transfers the funds to address 4.
        // In this case, the fork of [block 1', block 2'] will be considered the "current"
        // chain, and will be part of the UTXOs.
        let tx = TransactionBuilder::with_input(OutPoint::new(tx.txid(), 0))
            .with_output(&address_4, 1000)
            .build();
        let block_2_prime = BlockBuilder::with_prev_header(block_1_prime.header)
            .with_transaction(tx.clone())
            .build();
        state.insert_block(block_2_prime).unwrap();

        // Address 1 has no UTXOs since they were spent on the current chain.
        assert_eq!(state.get_utxos(&address_1.to_string(), 0), hashset! {});
        assert_eq!(state.get_utxos(&address_2.to_string(), 0), hashset! {});
        assert_eq!(state.get_utxos(&address_3.to_string(), 0), hashset! {});
        // The funds are now with address 4.
        assert_eq!(
            state.get_utxos(&address_4.to_string(), 0),
            hashset! {
                (
                    OutPoint {
                        txid: tx.txid(),
                        vout: 0
                    },
                    TxOut {
                        value: 1000,
                        script_pubkey: address_4.script_pubkey()
                    },
                    3
                )
            }
        );
    }

    #[test]
    fn process_100k_blocks() {
        let mut state = State::new(0, Network::Bitcoin, genesis_block(Network::Bitcoin));

        process_chain(&mut state, 100_000);

        let mut total_supply = 0;
        for (_, v, _) in state.utxos.clone().into_set() {
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
            state.get_balance("1PgZsaGjvssNCqHHisshLoCFeUjxPhutTh", 0),
            4000000
        );
        assert_eq!(
            state.get_utxos("1PgZsaGjvssNCqHHisshLoCFeUjxPhutTh", 0),
            maplit::hashset! {
                (
                    OutPoint {
                        txid: Txid::from_str(
                            "1a592a31c79f817ed787b6acbeef29b0f0324179820949d7da6215f0f4870c42",
                        )
                        .unwrap(),
                        vout: 1,
                    },
                    TxOut {
                        value: 4000000,
                        script_pubkey: Address::from_str("1PgZsaGjvssNCqHHisshLoCFeUjxPhutTh")
                            .unwrap()
                            .script_pubkey(),
                    },
                    75361
                )
            }
        );

        // https://blockexplorer.one/bitcoin/mainnet/address/12tGGuawKdkw5NeDEzS3UANhCRa1XggBbK
        assert_eq!(
            state.get_balance("12tGGuawKdkw5NeDEzS3UANhCRa1XggBbK", 0),
            500000000
        );
        assert_eq!(
            state.get_utxos("12tGGuawKdkw5NeDEzS3UANhCRa1XggBbK", 0),
            maplit::hashset! {
                (
                    OutPoint {
                        txid: Txid::from_str(
                            "3371b3978e7285d962fd54656aca6b3191135a1db838b5c689b8a44a7ede6a31",
                        )
                        .unwrap(),
                        vout: 0,
                    },
                    TxOut {
                        value: 500000000,
                        script_pubkey: Address::from_str("12tGGuawKdkw5NeDEzS3UANhCRa1XggBbK")
                            .unwrap()
                            .script_pubkey(),
                    },
                    66184
                )
            }
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
            let block_0 = BlockBuilder::genesis()
                .with_transaction(
                    TransactionBuilder::coinbase()
                        .with_output(&address_1, 1000)
                        .build(),
                )
                .build();

            let state = State::new(1, *network, block_0);

            // Expect an empty UTXO set.
            assert_eq!(state.main_chain_height(), 1);
            assert_eq!(state.get_utxos(&address_1.to_string(), 2), HashSet::new());
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
            state.insert_block(block_1).unwrap();

            // Address 1 should have no UTXOs at zero confirmations.
            assert_eq!(
                state.get_utxos(&address_1.to_string(), 0),
                maplit::hashset! {}
            );
        }
    }
}
