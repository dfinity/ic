//! Store headers received from p2p network.

use crate::common::{BlockHeight, BlockchainHeader};
use bitcoin::{BlockHash, Work};
use std::collections::HashMap;

/// This struct stores a BlockHeader along with its height in the Bitcoin Blockchain.
#[derive(Debug)]
pub struct HeaderNode<Header> {
    /// This field stores a Bitcoin header.
    pub header: Header,
    /// This field stores the height of a Bitcoin header
    pub height: BlockHeight,
    /// This field stores the work of the Blockchain leading up to this header.
    /// That is, this field is the sum of work of the above header and all its ancestors.
    pub work: Work,
    /// This field contains this node's successor headers.
    pub children: Vec<BlockHash>,
}

pub type HeaderCache<Header> = HashMap<BlockHash, HeaderNode<Header>>;

/// Creates a new cache with a set genesis header determined by the
/// provided network.
pub fn init_cache_with_genesis<Header: BlockchainHeader>(
    genesis_block_header: Header,
) -> HashMap<BlockHash, HeaderNode<Header>> {
    let cached_header = HeaderNode {
        header: genesis_block_header.clone(),
        height: 0,
        work: genesis_block_header.work(),
        children: vec![],
    };
    let mut headers = HashMap::new();
    headers.insert(genesis_block_header.block_hash(), cached_header);
    headers
}
