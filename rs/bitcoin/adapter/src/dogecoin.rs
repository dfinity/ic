//! Choose between bitcoin and dogecoin imports.

#![allow(missing_docs)]

use nintondo_dogecoin as dogecoin;

pub use dogecoin::absolute;
pub use dogecoin::block::Header as BlockHeader;
pub use dogecoin::block::{BlockHash, Version};
pub use dogecoin::blockdata::constants::genesis_block;
pub use dogecoin::blockdata::transaction::Transaction;
pub use dogecoin::consensus::{
    deserialize, deserialize_partial, encode, serialize, Decodable, Encodable,
};
pub use dogecoin::hash_types::{TxMerkleNode, Txid};
pub use dogecoin::hashes::Hash;
pub use dogecoin::network::constants::ServiceFlags;
pub use dogecoin::network::message::{
    CommandString, NetworkMessage, RawNetworkMessage, MAX_INV_SIZE,
};
pub use dogecoin::network::message_blockdata::{GetHeadersMessage, Inventory};
pub use dogecoin::network::message_network::VersionMessage;
pub use dogecoin::network::{Address as NetworkAddress, Magic};
pub use dogecoin::{Address, Amount, Block, Network, Target, Work};
pub use std::io as bitcoin_io;

pub mod validation {
    pub use ic_btc_validation::{validate_header, HeaderStore, ValidateHeaderError};
}
