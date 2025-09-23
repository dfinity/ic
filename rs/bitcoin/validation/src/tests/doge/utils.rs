use bitcoin::dogecoin::auxpow::{AuxPow, MERGED_MINING_HEADER};
use bitcoin::hashes::Hash;
use bitcoin::{
    Amount, BlockHash, OutPoint, Script, ScriptBuf, Sequence, Target, Transaction, TxIn,
    TxMerkleNode, TxOut, Witness,
    absolute::LockTime,
    block::{Header as PureHeader, Version},
    dogecoin::Address,
    dogecoin::auxpow::VERSION_AUXPOW,
};
use std::str::FromStr;

const DUMMY_CHAIN_ID: i32 = 42;
pub const DOGECOIN_CHAIN_ID: i32 = 98;
const BASE_VERSION: i32 = 5;
const CHAIN_MERKLE_HEIGHT: usize = 3; // Height of the blockchain Merkle tree used in AuxPow
const CHAIN_MERKLE_NONCE: u32 = 7; // Nonce used to calculate block header indexes into blockchain Merkle tree

/// Mines a block that either matches or doesn't match the difficulty target specified in the header.
pub fn mine_header_to_target(header: &mut PureHeader, should_pass: bool) {
    let target = Target::from_compact(header.bits);
    header.nonce = 0;

    loop {
        let hash = header.block_hash_with_scrypt();
        let hash_target = Target::from_le_bytes(hash.to_byte_array());
        let passes_pow = hash_target <= target;

        if (should_pass && passes_pow) || (!should_pass && !passes_pow) {
            break;
        }

        header.nonce += 1;
        if header.nonce == 0 {
            // Overflow, adjust time and continue
            header.time += 1;
        }
    }
}

pub struct HeaderBuilder {
    version: i32,
    prev_header: Option<PureHeader>,
    merkle_root: TxMerkleNode,
    with_valid_pow: bool,
}

impl Default for HeaderBuilder {
    fn default() -> Self {
        Self {
            version: BASE_VERSION | (DOGECOIN_CHAIN_ID << 16),
            prev_header: None,
            merkle_root: TxMerkleNode::all_zeros(),
            with_valid_pow: true,
        }
    }
}

impl HeaderBuilder {
    pub fn with_prev_header(mut self, prev_header: PureHeader) -> Self {
        self.prev_header = Some(prev_header);
        self
    }

    pub fn with_merkle_root(mut self, merkle_root: TxMerkleNode) -> Self {
        self.merkle_root = merkle_root;
        self
    }

    pub fn with_version(mut self, version: i32) -> Self {
        self.version = version;
        self
    }

    pub fn with_chain_id(mut self, chain_id: i32) -> Self {
        self.version |= chain_id << 16;
        self
    }

    pub fn with_auxpow_bit(mut self, auxpow_bit: bool) -> Self {
        if auxpow_bit {
            self.version |= VERSION_AUXPOW;
        } else {
            self.version &= !VERSION_AUXPOW;
        }
        self
    }

    pub fn with_valid_pow(mut self, valid_pow: bool) -> Self {
        self.with_valid_pow = valid_pow;
        self
    }

    pub fn build(self) -> PureHeader {
        let time = match &self.prev_header {
            Some(header) => header.time + 60,
            None => 0,
        };
        let bits = match &self.prev_header {
            Some(header) => header.bits,
            None => Target::MAX_ATTAINABLE_REGTEST.to_compact_lossy(),
        };

        let mut header = PureHeader {
            version: Version::from_consensus(self.version),
            time,
            nonce: 0,
            bits,
            merkle_root: self.merkle_root,
            prev_blockhash: self
                .prev_header
                .map_or(BlockHash::all_zeros(), |h| h.block_hash()),
        };

        mine_header_to_target(&mut header, self.with_valid_pow);

        header
    }
}

pub struct AuxPowBuilder {
    aux_block_hash: BlockHash,
    merkle_height: usize,
    merkle_nonce: u32,
    chain_id: i32,
    parent_chain_id: i32,
    base_version: i32,
    with_valid_pow: bool,
}

impl AuxPowBuilder {
    pub fn new(aux_block_hash: BlockHash) -> Self {
        Self {
            aux_block_hash,
            merkle_height: CHAIN_MERKLE_HEIGHT,
            merkle_nonce: CHAIN_MERKLE_NONCE,
            chain_id: DOGECOIN_CHAIN_ID,
            parent_chain_id: DUMMY_CHAIN_ID,
            base_version: BASE_VERSION,
            with_valid_pow: true,
        }
    }

    pub fn with_valid_pow(mut self, valid_pow: bool) -> Self {
        self.with_valid_pow = valid_pow;
        self
    }

    pub fn build(self) -> AuxPow {
        let expected_index =
            AuxPow::get_expected_index(self.merkle_nonce, self.chain_id, self.merkle_height);

        let blockchain_branch: Vec<TxMerkleNode> = (0..self.merkle_height)
            .map(|i| TxMerkleNode::from_byte_array([i as u8; 32]))
            .collect();

        let blockchain_merkle_root =
            AuxPow::compute_merkle_root(self.aux_block_hash, &blockchain_branch, expected_index);
        let mut blockchain_merkle_root_le = blockchain_merkle_root.to_byte_array();
        blockchain_merkle_root_le.reverse();

        let mut script_data = Vec::new();
        script_data.extend_from_slice(&MERGED_MINING_HEADER);
        script_data.extend_from_slice(&blockchain_merkle_root_le);
        script_data.extend_from_slice(&(1u32 << self.merkle_height).to_le_bytes());
        script_data.extend_from_slice(&self.merkle_nonce.to_le_bytes());

        let coinbase_tx = TransactionBuilder::new()
            .with_coinbase_script(ScriptBuf::from_bytes(script_data))
            .build();

        let mut parent_block_header = HeaderBuilder::default()
            .with_version(self.base_version)
            .with_chain_id(self.parent_chain_id)
            .with_merkle_root(TxMerkleNode::from_byte_array(
                coinbase_tx.compute_txid().to_byte_array(),
            ))
            .build();

        mine_header_to_target(&mut parent_block_header, self.with_valid_pow);

        AuxPow {
            coinbase_tx,
            parent_hash: BlockHash::all_zeros(),
            coinbase_branch: vec![], // Empty since coinbase is the only tx
            coinbase_index: 0,
            blockchain_branch,
            blockchain_index: expected_index,
            parent_block_header,
        }
    }
}

pub struct TransactionBuilder {
    input: Vec<TxIn>,
    output: Vec<TxOut>,
    lock_time: u32,
}

impl TransactionBuilder {
    pub fn new() -> Self {
        Self {
            input: vec![],
            output: vec![],
            lock_time: 0,
        }
    }

    fn coinbase_input(script_sig: ScriptBuf) -> TxIn {
        TxIn {
            previous_output: OutPoint::null(),
            script_sig,
            sequence: Sequence(0xffffffff),
            witness: Witness::new(),
        }
    }

    pub fn with_coinbase_script(mut self, script_sig: ScriptBuf) -> Self {
        self.input = vec![Self::coinbase_input(script_sig)];
        self
    }

    pub fn build(self) -> Transaction {
        let input = if self.input.is_empty() {
            // Default to coinbase if no inputs provided.
            vec![Self::coinbase_input(Script::new().into())]
        } else {
            self.input
        };
        let output = if self.output.is_empty() {
            // Use default of 50 DOGE.
            vec![TxOut {
                value: Amount::from_sat(50_0000_0000),
                script_pubkey: Address::from_str("mhXcJVuNA48bZsrKq4t21jx1neSqyceqTM")
                    .unwrap()
                    .assume_checked()
                    .script_pubkey(),
            }]
        } else {
            self.output
        };

        Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: LockTime::from_consensus(self.lock_time),
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

#[cfg(test)]
mod test {
    use super::TransactionBuilder;
    use bitcoin::OutPoint;

    #[test]
    fn should_be_coinbase_tx_when_default_new() {
        let tx = TransactionBuilder::new().build();
        assert!(tx.is_coinbase());
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.input[0].previous_output, OutPoint::null());
        assert_eq!(tx.output.len(), 1);
        assert_eq!(tx.output[0].value.to_sat(), 50_0000_0000);
    }
}
