use crate::header::HeaderValidator;
use crate::{BlockHeight, HeaderStore};
use bitcoin::block::Header;
use bitcoin::consensus::deserialize;
use bitcoin::dogecoin::{
    constants::genesis_block as dogecoin_genesis_block, Header as DogecoinHeader,
    Network as DogecoinNetwork,
};
use bitcoin::hashes::hex::FromHex;
use bitcoin::{BlockHash, CompactTarget};
use std::collections::HashMap;

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
            .unwrap_or_else(|| panic!("Previous hash missing for header: {:?}", header));
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
