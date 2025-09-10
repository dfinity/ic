//! Store headers received from p2p network.

use crate::common::{BlockHeight, BlockchainHeader};
use bitcoin::{block::Header as PureHeader, BlockHash, Work};
use ic_btc_validation::ValidateHeaderError;
use std::collections::HashMap;
use std::sync::RwLock;
use thiserror::Error;

/// This struct stores a BlockHeader along with its height in the Bitcoin Blockchain.
#[derive(Clone, Debug)]
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

/// Contains the necessary information about a tip.
#[derive(Clone, Debug)]
pub struct Tip<Header> {
    /// This field stores a Bitcoin header.
    pub header: Header,
    /// This field stores the height of the Bitcoin header stored in the field `header`.
    pub height: BlockHeight,
    /// This field stores the work of the Blockchain leading up to this tip.
    /// That is, this field is the sum of work of the above header and all its ancestors.
    pub work: Work,
}

/// The result when `BlockchainState::add_header(...)` is called.
#[derive(Debug)]
pub enum AddHeaderResult {
    /// This variant is used when the input header is added to the header_cache.
    HeaderAdded(BlockHash),
    /// This variant is used when the input header already exists in the header_cache.
    HeaderAlreadyExists,
}

#[derive(Debug, Error)]
pub enum AddHeaderError {
    /// This variant is used when the input header is invalid
    /// (eg: not of the right format)
    #[error("Received an invalid block header: {0}")]
    InvalidHeader(BlockHash, ValidateHeaderError),
    /// This variant is used when the predecessor of the input header is not part of header_cache.
    #[error("Received a block header where we do not have the previous header in the cache: {0}")]
    PrevHeaderNotCached(BlockHash),
}

pub struct InMemoryHeaderCache<Header> {
    /// The starting point of the blockchain
    genesis: PureHeader,

    /// The cache as a BTreeMap
    cache: HashMap<BlockHash, HeaderNode<Header>>,

    /// This field contains the known tips of the header cache.
    tips: Vec<Tip<Header>>,
}

pub trait HeaderCache: Send + Sync {
    type Header;

    /// Returns the genesis header.
    fn get_genesis(&self) -> PureHeader;

    /// Returns the header for the given block hash.
    fn get_header(&self, hash: &BlockHash) -> Option<HeaderNode<Self::Header>>;

    /// This method adds the input header to the `header_cache`.
    fn add_header(
        &self,
        block_hash: BlockHash,
        header: Self::Header,
    ) -> Result<AddHeaderResult, AddHeaderError>;

    /// This method returns the tip header with the highest cumulative work.
    fn get_active_chain_tip(&self) -> Tip<Self::Header>;

    /// Sort the tips by the total work, return the total number of tips
    fn sort_tips_by_work(&self) -> usize;

    #[cfg(test)]
    /// Return all tips.
    fn get_tips(&self) -> Vec<Tip<Self::Header>>;
}

impl<Header: BlockchainHeader> InMemoryHeaderCache<Header> {
    /// Creates a new cache with a genesis header
    pub fn new(genesis: Header) -> RwLock<Self> {
        let tips = vec![Tip {
            header: genesis.clone(),
            height: 0,
            work: genesis.work(),
        }];
        let cached_header = HeaderNode {
            header: genesis.clone(),
            height: 0,
            work: genesis.work(),
            children: vec![],
        };
        let mut cache = HashMap::new();
        cache.insert(genesis.block_hash(), cached_header);

        RwLock::new(InMemoryHeaderCache {
            genesis: genesis.into_pure_header(),
            cache,
            tips,
        })
    }
}

impl<Header: BlockchainHeader + Send + Sync> HeaderCache for RwLock<InMemoryHeaderCache<Header>> {
    type Header = Header;

    fn get_genesis(&self) -> PureHeader {
        self.read().unwrap().genesis
    }

    fn get_header(&self, hash: &BlockHash) -> Option<HeaderNode<Header>> {
        self.read().unwrap().cache.get(hash).cloned()
    }

    fn add_header(
        &self,
        block_hash: BlockHash,
        header: Header,
    ) -> Result<AddHeaderResult, AddHeaderError> {
        let mut this = self.write().unwrap();
        let parent = this.cache.get_mut(&header.prev_block_hash()).ok_or(
            AddHeaderError::PrevHeaderNotCached(header.prev_block_hash()),
        )?;

        let cached_header = HeaderNode {
            header: header.clone(),
            height: parent.height + 1,
            work: parent.work + header.work(),
            children: vec![],
        };
        parent.children.push(header.block_hash());

        // Update the tip headers.
        // If the previous header already exists in `tips`, then update it with the new tip.
        let prev_hash = header.prev_block_hash();
        let maybe_cached_header_idx = this
            .tips
            .iter()
            .position(|tip| tip.header.block_hash() == prev_hash);
        let tip = Tip {
            header: header.clone(),
            height: cached_header.height,
            work: cached_header.work,
        };

        match maybe_cached_header_idx {
            Some(idx) => {
                this.tips[idx] = tip;
            }
            None => {
                // If the previous header is not a tip, then add the `cached_header` as a tip.
                this.tips.push(tip);
            }
        };

        this.cache.insert(block_hash, cached_header);

        Ok(AddHeaderResult::HeaderAdded(block_hash))
    }

    /// This method returns the tip header with the highest cumulative work.
    fn get_active_chain_tip(&self) -> Tip<Header> {
        // `self.tips` is initialized in the new() method with the initial header.
        // `add_headers` sorts the tips by total work. The zero index will always be
        // the active tip.
        self.read().unwrap().tips[0].clone()
    }

    /// Sort the tips by the total work, return the total number of tips
    fn sort_tips_by_work(&self) -> usize {
        let mut this = self.write().unwrap();
        this.tips.sort_unstable_by(|a, b| b.work.cmp(&a.work));
        this.tips.len()
    }

    #[cfg(test)]
    fn get_tips(&self) -> Vec<Tip<Header>> {
        self.read().unwrap().tips.clone()
    }
}
