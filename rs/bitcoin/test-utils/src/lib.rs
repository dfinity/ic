use bitcoin::{
    secp256k1::rand::rngs::OsRng, secp256k1::Secp256k1, util::uint::Uint256, Address, Block,
    BlockHash, BlockHeader, KeyPair, Network, OutPoint, PublicKey, Script, Transaction, TxIn,
    TxMerkleNode, TxOut, Witness, XOnlyPublicKey,
};

/// Generates a random P2PKH address.
pub fn random_p2pkh_address(network: Network) -> Address {
    let secp = Secp256k1::new();
    let mut rng = OsRng::new().unwrap();

    Address::p2pkh(&PublicKey::new(secp.generate_keypair(&mut rng).1), network)
}

pub fn random_p2tr_address(network: Network) -> Address {
    let secp = Secp256k1::new();
    let mut rng = OsRng::new().unwrap();
    let key_pair = KeyPair::new(&secp, &mut rng);
    let xonly = XOnlyPublicKey::from_keypair(&key_pair);

    Address::p2tr(&secp, xonly, None, network)
}

pub struct BlockBuilder {
    prev_header: Option<BlockHeader>,
    transactions: Vec<Transaction>,
}

impl BlockBuilder {
    pub fn genesis() -> Self {
        Self {
            prev_header: None,
            transactions: vec![],
        }
    }

    pub fn with_prev_header(prev_header: BlockHeader) -> Self {
        Self {
            prev_header: Some(prev_header),
            transactions: vec![],
        }
    }

    pub fn with_transaction(mut self, transaction: Transaction) -> Self {
        self.transactions.push(transaction);
        self
    }

    pub fn build(self) -> Block {
        let txdata = if self.transactions.is_empty() {
            // Create a random coinbase transaction.
            vec![TransactionBuilder::coinbase().build()]
        } else {
            self.transactions
        };

        let merkle_root =
            bitcoin::util::hash::bitcoin_merkle_root(txdata.iter().map(|tx| tx.txid().as_hash()))
                .unwrap();
        let merkle_root = TxMerkleNode::from_hash(merkle_root);

        let header = match self.prev_header {
            Some(prev_header) => header(&prev_header, merkle_root),
            None => genesis(merkle_root),
        };

        Block { header, txdata }
    }
}

fn genesis(merkle_root: TxMerkleNode) -> BlockHeader {
    let target = Uint256([
        0xffffffffffffffffu64,
        0xffffffffffffffffu64,
        0xffffffffffffffffu64,
        0x7fffffffffffffffu64,
    ]);
    let bits = BlockHeader::compact_target_from_u256(&target);

    let mut header = BlockHeader {
        version: 1,
        time: 0,
        nonce: 0,
        bits,
        merkle_root,
        prev_blockhash: BlockHash::default(),
    };
    solve(&mut header);

    header
}

pub struct TransactionBuilder {
    previous_output: Vec<OutPoint>,
    output: Vec<TxOut>,
}

impl TransactionBuilder {
    pub fn new() -> Self {
        Self {
            previous_output: vec![],
            output: vec![],
        }
    }

    pub fn coinbase() -> Self {
        Self {
            previous_output: vec![OutPoint::null()],
            output: vec![],
        }
    }

    pub fn with_input(mut self, previous_output: OutPoint) -> Self {
        if self.previous_output == vec![OutPoint::null()] {
            panic!("A call `with_input` should not be possible if `coinbase` was called");
        }
        self.previous_output.push(previous_output);
        self
    }

    pub fn with_output(mut self, address: &Address, value: u64) -> Self {
        self.output.push(TxOut {
            value,
            script_pubkey: address.script_pubkey(),
        });
        self
    }

    pub fn build(self) -> Transaction {
        let prev_outputs = if self.previous_output.is_empty() {
            // Default to coinbase if no inputs provided.
            vec![OutPoint::null()]
        } else {
            self.previous_output
        };
        let input = prev_outputs
            .iter()
            .map(|output| TxIn {
                previous_output: *output,
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: Witness::new(),
            })
            .collect();
        let output = if self.output.is_empty() {
            // Use default of 50 BTC.
            vec![TxOut {
                value: 50_0000_0000,
                script_pubkey: random_p2pkh_address(Network::Regtest).script_pubkey(),
            }]
        } else {
            self.output
        };

        Transaction {
            version: 1,
            lock_time: 0,
            input,
            output,
        }
    }
}

impl Default for TransactionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

fn header(prev_header: &BlockHeader, merkle_root: TxMerkleNode) -> BlockHeader {
    let time = prev_header.time + 60 * 10; // 10 minutes.
    let bits = BlockHeader::compact_target_from_u256(&prev_header.target());

    let mut header = BlockHeader {
        version: 1,
        time,
        nonce: 0,
        bits,
        merkle_root,
        prev_blockhash: prev_header.block_hash(),
    };
    solve(&mut header);

    header
}

fn solve(header: &mut BlockHeader) {
    let target = header.target();
    while header.validate_pow(&target).is_err() {
        header.nonce += 1;
    }
}

#[cfg(test)]
mod test {
    mod transaction_builder {
        use crate::{random_p2pkh_address, TransactionBuilder};
        use bitcoin::{Network, OutPoint};

        #[test]
        fn new_build() {
            let tx = TransactionBuilder::new().build();
            assert!(tx.is_coin_base());
            assert_eq!(tx.input.len(), 1);
            assert_eq!(tx.input[0].previous_output, OutPoint::null());
            assert_eq!(tx.output.len(), 1);
            assert_eq!(tx.output[0].value, 50_0000_0000);
        }

        #[test]
        fn coinbase() {
            let tx = TransactionBuilder::coinbase().build();
            assert!(tx.is_coin_base());
            assert_eq!(tx.input.len(), 1);
            assert_eq!(tx.input[0].previous_output, OutPoint::null());
            assert_eq!(tx.output.len(), 1);
            assert_eq!(tx.output[0].value, 50_0000_0000);
        }

        #[test]
        #[should_panic(
            expected = "A call `with_input` should not be possible if `coinbase` was called"
        )]
        fn with_input_panic() {
            let address = random_p2pkh_address(Network::Regtest);
            let coinbase_tx = TransactionBuilder::coinbase()
                .with_output(&address, 1000)
                .build();

            TransactionBuilder::coinbase()
                .with_input(bitcoin::OutPoint::new(coinbase_tx.txid(), 0));
        }

        #[test]
        fn with_output() {
            let address = random_p2pkh_address(Network::Regtest);
            let tx = TransactionBuilder::coinbase()
                .with_output(&address, 1000)
                .build();

            assert!(tx.is_coin_base());
            assert_eq!(tx.input.len(), 1);
            assert_eq!(tx.input[0].previous_output, OutPoint::null());
            assert_eq!(tx.output.len(), 1);
            assert_eq!(tx.output[0].value, 1000);
            assert_eq!(tx.output[0].script_pubkey, address.script_pubkey());
        }

        #[test]
        fn with_output_2() {
            let address_0 = random_p2pkh_address(Network::Regtest);
            let address_1 = random_p2pkh_address(Network::Regtest);
            let tx = TransactionBuilder::coinbase()
                .with_output(&address_0, 1000)
                .with_output(&address_1, 2000)
                .build();

            assert!(tx.is_coin_base());
            assert_eq!(tx.input.len(), 1);
            assert_eq!(tx.input[0].previous_output, OutPoint::null());
            assert_eq!(tx.output.len(), 2);
            assert_eq!(tx.output[0].value, 1000);
            assert_eq!(tx.output[0].script_pubkey, address_0.script_pubkey());
            assert_eq!(tx.output[1].value, 2000);
            assert_eq!(tx.output[1].script_pubkey, address_1.script_pubkey());
        }

        #[test]
        fn with_input() {
            let address = random_p2pkh_address(Network::Regtest);
            let coinbase_tx = TransactionBuilder::coinbase()
                .with_output(&address, 1000)
                .build();

            let tx = TransactionBuilder::new()
                .with_input(bitcoin::OutPoint::new(coinbase_tx.txid(), 0))
                .build();
            assert!(!tx.is_coin_base());
            assert_eq!(tx.input.len(), 1);
            assert_eq!(
                tx.input[0].previous_output,
                bitcoin::OutPoint::new(coinbase_tx.txid(), 0)
            );
            assert_eq!(tx.output.len(), 1);
            assert_eq!(tx.output[0].value, 50_0000_0000);
        }

        #[test]
        fn with_input_2() {
            let address = random_p2pkh_address(Network::Regtest);
            let coinbase_tx_0 = TransactionBuilder::coinbase()
                .with_output(&address, 1000)
                .build();
            let coinbase_tx_1 = TransactionBuilder::coinbase()
                .with_output(&address, 2000)
                .build();

            let tx = TransactionBuilder::new()
                .with_input(bitcoin::OutPoint::new(coinbase_tx_0.txid(), 0))
                .with_input(bitcoin::OutPoint::new(coinbase_tx_1.txid(), 0))
                .build();
            assert!(!tx.is_coin_base());
            assert_eq!(tx.input.len(), 2);
            assert_eq!(
                tx.input[0].previous_output,
                bitcoin::OutPoint::new(coinbase_tx_0.txid(), 0)
            );
            assert_eq!(
                tx.input[1].previous_output,
                bitcoin::OutPoint::new(coinbase_tx_1.txid(), 0)
            );
            assert_eq!(tx.output.len(), 1);
            assert_eq!(tx.output[0].value, 50_0000_0000);
        }
    }
}
