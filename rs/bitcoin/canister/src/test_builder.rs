use bitcoin::{
    secp256k1::rand::rngs::OsRng, secp256k1::Secp256k1, util::uint::Uint256, Address, Block,
    BlockHash, BlockHeader, Network, OutPoint, PublicKey, Script, Transaction, TxIn, TxMerkleNode,
    TxOut,
};

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
            bitcoin::util::hash::bitcoin_merkle_root(txdata.iter().map(|tx| tx.txid().as_hash()));
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
    input: OutPoint,
    output_value: Option<u64>,
    output_address: Option<Address>,
}

impl TransactionBuilder {
    pub fn coinbase() -> Self {
        Self {
            input: OutPoint::null(),
            output_value: None,
            output_address: None,
        }
    }

    pub fn with_input(input: OutPoint) -> Self {
        Self {
            input,
            output_value: None,
            output_address: None,
        }
    }

    pub fn with_output(mut self, address: &Address, value: u64) -> Self {
        self.output_address = Some(address.clone());
        self.output_value = Some(value);
        self
    }

    pub fn build(self) -> Transaction {
        let input = vec![TxIn {
            previous_output: self.input,
            script_sig: Script::new(),
            sequence: 0xffffffff,
            witness: vec![],
        }];

        // Use default of 50 BTC
        let output_value = self.output_value.unwrap_or(50_0000_0000);

        let output_address = match self.output_address {
            Some(address) => address,
            None => {
                // Generate a random address.
                let secp = Secp256k1::new();
                let mut rng = OsRng::new().unwrap();
                Address::p2pkh(
                    &PublicKey::new(secp.generate_keypair(&mut rng).1),
                    Network::Regtest,
                )
            }
        };

        Transaction {
            version: 1,
            lock_time: 0,
            input,
            output: vec![TxOut {
                value: output_value,
                script_pubkey: output_address.script_pubkey(),
            }],
        }
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
