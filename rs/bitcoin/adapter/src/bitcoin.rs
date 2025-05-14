//! Choose between bitcoin and dogecoin imports.

#![allow(missing_docs)]

pub use bitcoin::absolute;
pub use bitcoin::block::Header as BlockHeader;
pub use bitcoin::block::{BlockHash, Version};
pub use bitcoin::blockdata::constants::genesis_block;
pub use bitcoin::blockdata::transaction::Transaction;
pub use bitcoin::consensus::{
    deserialize, deserialize_partial, encode, serialize, Decodable, Encodable,
};
pub use bitcoin::hash_types::Txid;
pub use bitcoin::hashes::Hash;
pub use bitcoin::io as bitcoin_io;
pub use bitcoin::p2p::message::{CommandString, NetworkMessage, RawNetworkMessage, MAX_INV_SIZE};
pub use bitcoin::p2p::message_blockdata::{GetHeadersMessage, Inventory};
pub use bitcoin::p2p::message_network::VersionMessage;
pub use bitcoin::p2p::{Address as NetworkAddress, Magic, ServiceFlags};
pub use bitcoin::{Address, Amount, Block, Network, Target, TxMerkleNode, Work};

pub mod validation {
    pub use ic_btc_validation::{validate_header, HeaderStore, ValidateHeaderError};
}
