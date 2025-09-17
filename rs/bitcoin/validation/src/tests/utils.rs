use crate::header::HeaderValidator;
use crate::{BlockHeight, HeaderStore};
use bitcoin::block::{Header, Version};
use bitcoin::consensus::deserialize;
use bitcoin::dogecoin::auxpow::AuxPow;
use bitcoin::dogecoin::{
    Header as DogecoinHeader, Network as DogecoinNetwork,
    constants::genesis_block as dogecoin_genesis_block,
};
use bitcoin::hashes::hex::FromHex;
use bitcoin::{BlockHash, CompactTarget, TxMerkleNode};
use csv::{Reader, StringRecord};
use std::collections::HashMap;
use std::str::FromStr;

pub fn deserialize_header(encoded_bytes: &str) -> Header {
    let bytes = Vec::from_hex(encoded_bytes).expect("failed to decoded bytes");
    deserialize(bytes.as_slice()).expect("failed to deserialize")
}

pub fn deserialize_auxpow_header(encoded_bytes: &str) -> DogecoinHeader {
    let bytes = Vec::from_hex(encoded_bytes).expect("failed to decoded bytes");
    deserialize(bytes.as_slice()).expect("failed to deserialize")
}

#[derive(Clone)]
struct StoredHeader {
    header: Header,
    height: BlockHeight,
}

pub struct SimpleHeaderStore {
    headers: HashMap<BlockHash, StoredHeader>,
    height: BlockHeight,
    tip_hash: BlockHash,
    initial_hash: BlockHash,
}

impl SimpleHeaderStore {
    pub fn new(initial_header: Header, height: BlockHeight) -> Self {
        let initial_hash = initial_header.block_hash();
        let tip_hash = initial_header.block_hash();
        let mut headers = HashMap::new();
        headers.insert(
            initial_hash,
            StoredHeader {
                header: initial_header,
                height,
            },
        );

        Self {
            headers,
            height,
            tip_hash,
            initial_hash,
        }
    }

    pub fn add(&mut self, header: Header) {
        let prev = self
            .headers
            .get(&header.prev_blockhash)
            .unwrap_or_else(|| panic!("Previous hash missing for header: {header:?}"));
        let stored_header = StoredHeader {
            header,
            height: prev.height + 1,
        };

        self.height = stored_header.height;
        self.headers.insert(header.block_hash(), stored_header);
        self.tip_hash = header.block_hash();
    }
}

impl HeaderStore for SimpleHeaderStore {
    fn get_header(&self, hash: &BlockHash) -> Option<(Header, BlockHeight)> {
        self.headers
            .get(hash)
            .map(|stored| (stored.header, stored.height))
    }

    fn get_initial_hash(&self) -> BlockHash {
        self.initial_hash
    }

    fn get_height(&self) -> BlockHeight {
        self.height
    }
}

/// Creates a Header from a CSV record with fields: version, prev_blockhash, merkle_root, time, bits, nonce
fn header_from_csv_record(record: &StringRecord) -> Header {
    Header {
        version: Version::from_consensus(i32::from_str_radix(record.get(0).unwrap(), 16).unwrap()),
        prev_blockhash: BlockHash::from_str(record.get(1).unwrap()).unwrap(),
        merkle_root: TxMerkleNode::from_str(record.get(2).unwrap()).unwrap(),
        time: u32::from_str_radix(record.get(3).unwrap(), 16).unwrap(),
        bits: CompactTarget::from_consensus(
            u32::from_str_radix(record.get(4).unwrap(), 16).unwrap(),
        ),
        nonce: u32::from_str_radix(record.get(5).unwrap(), 16).unwrap(),
    }
}

/// Creates an AuxPow from a CSV record with fields: coinbase_tx, parent_hash, coinbase_branch, coinbase_index, blockchain_branch, blockchain_index, parent_block_header
fn auxpow_from_csv_record(record: &StringRecord) -> AuxPow {
    AuxPow {
        coinbase_tx: deserialize(Vec::from_hex(record.get(6).unwrap()).unwrap().as_slice())
            .unwrap(),
        parent_hash: BlockHash::from_str(record.get(7).unwrap()).unwrap(),
        coinbase_branch: deserialize(Vec::from_hex(record.get(8).unwrap()).unwrap().as_slice())
            .unwrap(),
        coinbase_index: i32::from_le_bytes(
            hex::decode(record.get(9).unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
        ),
        blockchain_branch: deserialize(Vec::from_hex(record.get(10).unwrap()).unwrap().as_slice())
            .unwrap(),
        blockchain_index: i32::from_le_bytes(
            hex::decode(record.get(11).unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
        ),
        parent_block_header: deserialize_header(record.get(12).unwrap()),
    }
}

/// This function reads all headers from the specified CSV file and returns them as a `Vec<Header>`.
pub fn get_headers(file: &str) -> Vec<Header> {
    let rdr = Reader::from_path(file);
    assert!(rdr.is_ok(), "Unable to find {file} file");
    let mut rdr = rdr.unwrap();
    let mut headers = vec![];
    for result in rdr.records() {
        let record = result.unwrap();
        let header = header_from_csv_record(&record);
        headers.push(header);
    }
    headers
}

/// This function reads all auxpow headers from the specified CSV file and returns them as a `Vec<Header>`.
pub fn get_auxpow_headers(file: &str) -> Vec<DogecoinHeader> {
    let rdr = Reader::from_path(file);
    assert!(rdr.is_ok(), "Unable to find {file} file");
    let mut rdr = rdr.unwrap();
    let mut headers = vec![];
    for result in rdr.records() {
        let record = result.unwrap();
        let pure_header = header_from_csv_record(&record);
        let aux_pow = pure_header
            .has_auxpow_bit()
            .then(|| auxpow_from_csv_record(&record));
        let header = DogecoinHeader {
            pure_header,
            aux_pow,
        };
        headers.push(header);
    }
    headers
}

pub fn dogecoin_genesis_header(network: &DogecoinNetwork, bits: CompactTarget) -> Header {
    let mut genesis_header = dogecoin_genesis_block(network).header;
    genesis_header.bits = bits;
    genesis_header.pure_header
}

pub fn next_block_header<T: HeaderValidator>(
    validator: &T,
    prev: Header,
    bits: CompactTarget,
) -> Header {
    Header {
        prev_blockhash: prev.block_hash(),
        time: prev.time + validator.pow_target_spacing().as_secs() as u32,
        bits,
        ..prev
    }
}

/// Creates a chain of headers with the given length and
/// proof of work for the first header.
pub fn build_header_chain<T: HeaderValidator>(
    validator: &T,
    genesis_header: Header,
    chain_length: u32,
) -> (SimpleHeaderStore, Header) {
    let pow_limit = validator.pow_limit_bits();
    let h0 = genesis_header;
    let mut store = SimpleHeaderStore::new(h0, 0);
    let mut last_header = h0;

    for _ in 1..chain_length {
        let new_header = next_block_header(validator, last_header, pow_limit);
        store.add(new_header);
        last_header = new_header;
    }

    (store, last_header)
}
