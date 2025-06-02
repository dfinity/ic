//! Choose between bitcoin and dogecoin imports.

#![allow(missing_docs)]

pub use dogecoin::block::BlockHeader;
pub type Version = u32;
pub use dogecoin::block::BlockHash;
// pub use dogecoin::blockdata::constants::genesis_block;
pub use bitcoin::absolute;
pub use bitcoin::consensus::{
    deserialize, deserialize_partial, encode, serialize, Decodable, Encodable,
};
pub use bitcoin::hashes::Hash;
pub use bitcoin::io as bitcoin_io;
pub use bitcoin::{Amount, Target, Work};
pub use dogecoin::block::TxMerkleNode;
pub use dogecoin::block::{genesis_block, Block};
pub use dogecoin::network::Network;
pub use dogecoin::p2p::message::{CommandString, NetworkMessage, RawNetworkMessage, MAX_INV_SIZE};
pub use dogecoin::p2p::message_blockdata::{GetHeadersMessage, Inventory};
pub use dogecoin::p2p::message_network::VersionMessage;
pub use dogecoin::p2p::{Address as NetworkAddress, Magic, ServiceFlags};
pub use dogecoin::script::Address;
pub use dogecoin::transaction::Transaction;
pub use dogecoin::transaction::Txid;

pub mod validation {
    pub use ic_btc_validation::ValidateHeaderError;
    pub fn validate_header(
        _network: &super::Network,
        _store: &impl HeaderStore,
        _header: &super::BlockHeader,
    ) -> Result<(), ValidateHeaderError> {
        Ok(())
    }
    pub trait HeaderStore {
        /// Returns the header with the given block hash.
        fn get_header(&self, hash: &super::BlockHash) -> Option<(super::BlockHeader, u32)>;

        /// Returns the initial hash the store starts from.
        fn get_initial_hash(&self) -> super::BlockHash;

        fn get_height(&self) -> u32;
    }
}
