//! Choose between bitcoin and dogecoin imports.

#![allow(missing_docs)]

pub use bitcoin::absolute;
pub use bitcoin::block::Header as BlockHeader;
pub use bitcoin::block::{BlockHash, Version};
pub use bitcoin::blockdata::constants::genesis_block;
pub use bitcoin::consensus::{
    deserialize, deserialize_partial, encode, serialize, Decodable, Encodable,
};
pub use bitcoin::hashes::Hash;
pub use bitcoin::io as bitcoin_io;
pub use bitcoin::p2p::message::{CommandString, MAX_INV_SIZE};
pub use bitcoin::p2p::message_blockdata::{GetHeadersMessage, Inventory};
pub use bitcoin::p2p::message_network::VersionMessage;
pub use bitcoin::p2p::{Address as NetworkAddress, Magic, ServiceFlags};
pub use bitcoin::transaction::{Transaction, Txid};
pub use bitcoin::{Address, Amount, Block, Network, Target, TxMerkleNode, Work};

pub type RawNetworkMessage = bitcoin::p2p::message::RawNetworkMessage<Block>;
pub type NetworkMessage = bitcoin::p2p::message::NetworkMessage<Block>;

pub mod validation {
    pub use ic_btc_validation::{validate_header, HeaderStore, ValidateHeaderError};
}

pub fn new_version_message(
    services: ServiceFlags,
    timestamp: i64,
    receiver: NetworkAddress,
    sender: NetworkAddress,
    nonce: u64,
    user_agent: String,
    start_height: i32,
) -> VersionMessage {
    VersionMessage::new(
        services,
        timestamp,
        receiver,
        sender,
        nonce,
        user_agent,
        start_height,
    )
}
