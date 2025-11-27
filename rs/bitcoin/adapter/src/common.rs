use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::p2p::Magic;
use bitcoin::{BlockHash, Work, block::Header as PureHeader};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::{fmt, str::FromStr};

/// This const represents the default version that the adapter will support.
/// This value will be used to filter out Bitcoin nodes that the adapter deems
/// to far behind to interact with.
///
/// 70001 was related back in Feb 2013. It made the last significant change to
/// the version message by adding the `relay` field.
///
/// [Version Handshake](https://en.bitcoin.it/wiki/Version_Handshake)
/// [Protocol Versions](https://developer.bitcoin.org/reference/p2p_networking.html#protocol-versions)
pub const MINIMUM_VERSION_NUMBER: u32 = 70001;

/// This const is used to provide a based buffer size for how many messages can be stashed into the
/// channel. If there are more messages, the sender will end up waiting.
pub const DEFAULT_CHANNEL_BUFFER_SIZE: usize = 64;

/// This field contains the datatype used to store height of a Bitcoin block
pub type BlockHeight = u32;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
/// AdapterNetwork selects between Bitcoin and Dogecoin Network.
///
/// The string representation for mainnet would be either "bitcoin" or "dogecoin".
/// But for non-mainnet networks, they would have a prefix of either "bitcoin:" or "dogecoin:".
///
/// The parsing from string on the other hand favors Bitcoin network in order
/// to maintain backward compatibility. It is only when a string fails to parse
/// as a bitcoin network, it will try to parse as a Dogecoin network (with prefix "dogecoin:").
///
/// # Examples:
///
/// ```rust
/// use ic_btc_adapter::AdapterNetwork;
/// use std::str::FromStr;
///
/// let bitcoin_mainnet = AdapterNetwork::Bitcoin(bitcoin::Network::Bitcoin);
/// let bitcoin_regtest = AdapterNetwork::Bitcoin(bitcoin::Network::Regtest);
/// let dogecoin_mainnet = AdapterNetwork::Dogecoin(bitcoin::dogecoin::Network::Dogecoin);
/// let dogecoin_testnet = AdapterNetwork::Dogecoin(bitcoin::dogecoin::Network::Testnet);
///
/// assert_eq!(bitcoin_mainnet.to_string(), "bitcoin");
/// assert_eq!(bitcoin_regtest.to_string(), "bitcoin:regtest");
/// assert_eq!(dogecoin_mainnet.to_string(), "dogecoin");
/// assert_eq!(dogecoin_testnet.to_string(), "dogecoin:testnet");
/// assert_eq!(AdapterNetwork::from_str("bitcoin"), Ok(bitcoin_mainnet));
/// assert_eq!(AdapterNetwork::from_str("dogecoin"), Ok(dogecoin_mainnet));
/// assert_eq!(AdapterNetwork::from_str("regtest"), Ok(bitcoin_regtest));
/// assert_eq!(AdapterNetwork::from_str("bitcoin:regtest"), Ok(bitcoin_regtest));
/// assert_eq!(AdapterNetwork::from_str("dogecoin:testnet"), Ok(dogecoin_testnet));
/// assert!(matches!(AdapterNetwork::from_str("testnet4"), Ok(AdapterNetwork::Bitcoin(_))));
/// assert!(matches!(AdapterNetwork::from_str("dogecoin:testnet4"), Err(_)));
/// ```
pub enum AdapterNetwork {
    /// Bitcoin network.
    Bitcoin(bitcoin::Network),
    /// Dogecoin network.
    Dogecoin(bitcoin::dogecoin::Network),
}

impl From<bitcoin::Network> for AdapterNetwork {
    fn from(network: bitcoin::Network) -> Self {
        Self::Bitcoin(network)
    }
}

impl From<bitcoin::dogecoin::Network> for AdapterNetwork {
    fn from(network: bitcoin::dogecoin::Network) -> Self {
        Self::Dogecoin(network)
    }
}

impl AdapterNetwork {
    /// Return the network name in a format as explained above.
    pub fn name(&self) -> String {
        match self {
            AdapterNetwork::Bitcoin(bitcoin::Network::Bitcoin) => "bitcoin".to_string(),
            AdapterNetwork::Bitcoin(network) => format!("bitcoin:{network}"),
            AdapterNetwork::Dogecoin(bitcoin::dogecoin::Network::Dogecoin) => {
                "dogecoin".to_string()
            }
            AdapterNetwork::Dogecoin(network) => format!("dogecoin:{network}"),
        }
    }
}

impl fmt::Display for AdapterNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.name(), f)
    }
}

impl FromStr for AdapterNetwork {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // In parsing network names, we give priority to Bitcoin network.
        // So both "testnet" and "bitcoin:testnet" will be parsed as bitcoin::Network::Testnet.
        if let Ok(network) = bitcoin::Network::from_str(s) {
            return Ok(network.into());
        } else if s == "dogecoin" {
            return Ok(bitcoin::dogecoin::Network::Dogecoin.into());
        } else if let Some(s) = s.strip_prefix("dogecoin:") {
            if let Ok(network) = bitcoin::dogecoin::Network::from_str(s) {
                return Ok(network.into());
            }
        } else if let Some(s) = s.strip_prefix("bitcoin:")
            && let Ok(network) = bitcoin::Network::from_str(s)
        {
            return Ok(network.into());
        }
        Err(format!("unknown network name {s}"))
    }
}

impl Serialize for AdapterNetwork {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.name())
    }
}

impl<'de> Deserialize<'de> for AdapterNetwork {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        AdapterNetwork::from_str(&s).map_err(serde::de::Error::custom)
    }
}

/// Trait that implements differences between Bitcoin and Dogecoin networks.
pub trait BlockchainNetwork: Copy + 'static {
    /// Header type.
    type Header: BlockchainHeader + Send + Sync;
    /// Block type.
    type Block: BlockchainBlock<Header = Self::Header>;
    /// P2P protocol version number.
    const P2P_PROTOCOL_VERSION: u32;
    /// Return genesis block header.
    fn genesis_block_header(&self) -> Self::Header;
    /// Helper used to determine if multiple blocks should be returned
    /// in [GetSuccessorsResponse].
    fn are_multiple_blocks_allowed(&self, anchor_height: BlockHeight) -> bool;
    /// Return max blocks bytes.
    fn max_blocks_bytes(&self) -> usize {
        crate::get_successors_handler::MAX_BLOCKS_BYTES
    }
    /// Return max in-flight blocks that is allowed in the adapter state.
    fn max_in_flight_blocks(&self) -> usize {
        crate::get_successors_handler::MAX_IN_FLIGHT_BLOCKS
    }
    /// Return the magic number of this network.
    fn magic(&self) -> Magic;
    /// Return the p2p port used by the given network type.
    fn p2p_port(&self) -> u16;
}

impl BlockchainNetwork for bitcoin::Network {
    type Header = bitcoin::block::Header;
    type Block = bitcoin::Block;
    const P2P_PROTOCOL_VERSION: u32 = bitcoin::p2p::PROTOCOL_VERSION;
    fn genesis_block_header(&self) -> Self::Header {
        bitcoin::blockdata::constants::genesis_block(self).header
    }
    fn are_multiple_blocks_allowed(&self, anchor_height: BlockHeight) -> bool {
        use bitcoin::Network::*;
        match self {
            Bitcoin => {
                anchor_height
                    <= crate::get_successors_handler::BTC_MAINNET_MAX_MULTI_BLOCK_ANCHOR_HEIGHT
            }
            Testnet | Signet | Regtest | Testnet4 => true,
            other => unreachable!("Unsupported Bitcoin network: {:?}", other),
        }
    }
    fn max_blocks_bytes(&self) -> usize {
        match self {
            bitcoin::Network::Testnet4 => crate::get_successors_handler::TESTNET4_MAX_BLOCKS_BYTES,
            _ => crate::get_successors_handler::MAX_BLOCKS_BYTES,
        }
    }
    fn max_in_flight_blocks(&self) -> usize {
        match self {
            bitcoin::Network::Testnet4 => {
                crate::get_successors_handler::TESTNET4_MAX_IN_FLIGHT_BLOCKS
            }
            _ => crate::get_successors_handler::MAX_IN_FLIGHT_BLOCKS,
        }
    }
    fn magic(&self) -> Magic {
        bitcoin::Network::magic(*self)
    }
    fn p2p_port(&self) -> u16 {
        use bitcoin::Network::*;
        match self {
            Bitcoin => 8333,
            Testnet => 18333,
            Testnet4 => 48333,
            _ => 8333,
        }
    }
}

impl BlockchainNetwork for bitcoin::dogecoin::Network {
    type Header = bitcoin::dogecoin::Header;
    type Block = bitcoin::dogecoin::Block;
    const P2P_PROTOCOL_VERSION: u32 = 70015;
    fn genesis_block_header(&self) -> Self::Header {
        bitcoin::dogecoin::constants::genesis_block(self).header
    }
    fn are_multiple_blocks_allowed(&self, anchor_height: BlockHeight) -> bool {
        use bitcoin::dogecoin::Network::*;
        match self {
            Dogecoin => {
                anchor_height
                    <= crate::get_successors_handler::DOGE_MAINNET_MAX_MULTI_BLOCK_ANCHOR_HEIGHT
            }
            Testnet | Regtest => true,
            other => unreachable!("Unsupported Dogecoin network: {:?}", other),
        }
    }
    fn magic(&self) -> Magic {
        bitcoin::dogecoin::Network::magic(*self)
    }
    fn p2p_port(&self) -> u16 {
        use bitcoin::dogecoin::Network::*;
        match self {
            Dogecoin => 22556,
            Testnet => 44556,
            _ => 18444,
        }
    }
}

/// A trait that contains the common methods of both Bitcoin and Dogecoin headers.
pub trait BlockchainHeader: Decodable + Encodable + Clone {
    /// Return block hash.
    fn block_hash(&self) -> BlockHash;
    /// Return previous block hash.
    fn prev_block_hash(&self) -> BlockHash;
    /// Return the total work of the block.
    fn work(&self) -> Work;
    /// Return the 80-byte header.
    fn into_pure_header(self) -> PureHeader;
}

impl BlockchainHeader for bitcoin::block::Header {
    fn block_hash(&self) -> BlockHash {
        self.block_hash()
    }
    fn prev_block_hash(&self) -> BlockHash {
        self.prev_blockhash
    }
    fn work(&self) -> Work {
        self.work()
    }
    fn into_pure_header(self) -> PureHeader {
        self
    }
}

impl BlockchainHeader for bitcoin::dogecoin::Header {
    fn block_hash(&self) -> BlockHash {
        self.pure_header.block_hash()
    }
    fn prev_block_hash(&self) -> BlockHash {
        self.pure_header.prev_blockhash
    }
    fn work(&self) -> Work {
        self.pure_header.work()
    }
    fn into_pure_header(self) -> PureHeader {
        self.pure_header
    }
}

/// A trait that contains the common methods of both Bitcoin and Dogecoin blocks.
pub trait BlockchainBlock: Decodable + Encodable + Clone {
    /// Block Header
    type Header;
    /// Return block hash.
    fn block_hash(&self) -> BlockHash;
    /// Compute merkle root.
    fn compute_merkle_root(&self) -> Option<bitcoin::TxMerkleNode>;
    /// Check if the merkle root in block header matches what is computed.
    fn check_merkle_root(&self) -> bool;
    /// Return the block header.
    fn header(&self) -> &Self::Header;
}

impl BlockchainBlock for bitcoin::Block {
    type Header = bitcoin::block::Header;

    fn block_hash(&self) -> BlockHash {
        bitcoin::Block::block_hash(self)
    }
    fn compute_merkle_root(&self) -> Option<bitcoin::TxMerkleNode> {
        bitcoin::Block::compute_merkle_root(self)
    }
    fn check_merkle_root(&self) -> bool {
        bitcoin::Block::check_merkle_root(self)
    }
    fn header(&self) -> &Self::Header {
        &self.header
    }
}

impl BlockchainBlock for bitcoin::dogecoin::Block {
    type Header = bitcoin::dogecoin::Header;

    fn block_hash(&self) -> BlockHash {
        bitcoin::dogecoin::Block::block_hash(self)
    }
    fn compute_merkle_root(&self) -> Option<bitcoin::TxMerkleNode> {
        bitcoin::dogecoin::Block::compute_merkle_root(self)
    }
    fn check_merkle_root(&self) -> bool {
        bitcoin::dogecoin::Block::check_merkle_root(self)
    }
    fn header(&self) -> &Self::Header {
        &self.header
    }
}

/// A trait for validating block headers in a blockchain network.
pub trait HeaderValidator<Network: BlockchainNetwork> {
    /// The error type returned when validation fails.
    type HeaderError: Debug;

    /// Validate a block header against the rules of the given blockchain network.
    fn validate_header(
        &self,
        network: &Network,
        header: &Network::Header,
    ) -> Result<(), Self::HeaderError>;
}

#[cfg(test)]
pub mod test_common {
    use std::{
        collections::{HashSet, VecDeque},
        net::SocketAddr,
    };

    use bitcoin::{Block, consensus::deserialize};
    use hex::FromHex;

    use crate::{Channel, ChannelError, Command};

    /// This is a hex dump of the first block on the BTC network: 00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048
    pub const BLOCK_1_ENCODED: &str = "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e362990101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000";

    /// This is a hex dump of the first block on the BTC network: 000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd
    pub const BLOCK_2_ENCODED: &str = "010000004860eb18bf1b1620e37e9490fc8a427514416fd75159ab86688e9a8300000000d5fdcc541e25de1c7a5addedf24858b8bb665c9f36ef744ee42c316022c90f9bb0bc6649ffff001d08d2bd610101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d010bffffffff0100f2052a010000004341047211a824f55b505228e4c3d5194c1fcfaa15a456abdf37f9b9d97a4040afc073dee6c89064984f03385237d92167c13e236446b417ab79a0fcae412ae3316b77ac00000000";

    /// This struct is used to capture Commands generated by managers.
    pub struct TestChannel<Header, Block> {
        /// This field holds Commands that are generated by managers.
        received_commands: VecDeque<Command<Header, Block>>,
        /// The connections available for the test to interact with.
        available_connections: Vec<SocketAddr>,
        /// The addresses that disconnect was called on.
        disconnected_addresses: HashSet<SocketAddr>,
    }

    impl<Header, Block> TestChannel<Header, Block> {
        pub fn new(available_connections: Vec<SocketAddr>) -> Self {
            Self {
                received_commands: VecDeque::new(),
                available_connections,
                disconnected_addresses: HashSet::new(),
            }
        }
    }

    impl<Header, Block> TestChannel<Header, Block> {
        pub fn command_count(&self) -> usize {
            self.received_commands.len()
        }

        pub fn pop_front(&mut self) -> Option<Command<Header, Block>> {
            self.received_commands.pop_front()
        }

        pub fn pop_back(&mut self) -> Option<Command<Header, Block>> {
            self.received_commands.pop_back()
        }

        pub fn has_discarded_address(&self, addr: &SocketAddr) -> bool {
            self.disconnected_addresses.contains(addr)
        }
        pub fn add_address(&mut self, addr: SocketAddr) {
            self.available_connections.push(addr);
        }
    }

    impl<Header, Block> Channel<Header, Block> for TestChannel<Header, Block> {
        fn send(&mut self, command: Command<Header, Block>) -> Result<(), ChannelError> {
            self.received_commands.push_back(command);
            Ok(())
        }

        fn available_connections(&self) -> Vec<SocketAddr> {
            self.available_connections
                .iter()
                .filter(|addr| !self.disconnected_addresses.contains(addr))
                .cloned()
                .collect()
        }

        fn discard(&mut self, addr: &SocketAddr) {
            self.disconnected_addresses.insert(*addr);
        }
    }

    pub struct TestState {
        pub block_1: Block,
        pub block_2: Block,
    }

    impl TestState {
        pub fn setup() -> Self {
            let encoded_block_1 =
                Vec::from_hex(BLOCK_1_ENCODED).expect("failed to covert hex to vec");
            let block_1: Block = deserialize(&encoded_block_1).expect("failed to decoded block 1");
            let encoded_block_2 =
                Vec::from_hex(BLOCK_2_ENCODED).expect("failed to covert hex to vec");
            let block_2: Block = deserialize(&encoded_block_2).expect("failed to decoded block 2");

            TestState { block_1, block_2 }
        }
    }
}
