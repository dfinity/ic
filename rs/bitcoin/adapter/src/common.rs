use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::p2p::Magic;
use ic_btc_validation::{HeaderStore, ValidateHeaderError};
use serde::{Deserialize, Serialize};
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
#[allow(missing_docs)]
/// AdapterNetwork selects between bitcoin and dogecoin Network.
///
/// The string representation for mainnet would would be either "bitcoin" or "dogecoin".
/// But for non-mainnet networks, they would have a prefix of either "bitcoin:" or "dogecoin:".
///
/// The parsing from string on the other hand favors bitcoin network in order
/// to maintain backward compatibility. It is only when a string fails to parse
/// as a bitcoin network, it will try to parse as a dogecoin network (with prefix "dogcoin:").
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
    Bitcoin(bitcoin::Network),
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

#[allow(missing_docs)]
impl AdapterNetwork {
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
    pub fn magic(&self) -> Magic {
        match self {
            AdapterNetwork::Bitcoin(network) => network.magic(),
            AdapterNetwork::Dogecoin(network) => network.magic(),
        }
    }
    pub fn genesis_block_header(&self) -> bitcoin::block::Header {
        match self {
            AdapterNetwork::Bitcoin(network) => {
                bitcoin::blockdata::constants::genesis_block(network).header
            }
            AdapterNetwork::Dogecoin(network) => {
                bitcoin::dogecoin::constants::genesis_block(network).header
            }
        }
    }
    pub fn validate_header(
        &self,
        store: &impl HeaderStore,
        header: &bitcoin::block::Header,
    ) -> Result<(), ValidateHeaderError> {
        match self {
            AdapterNetwork::Bitcoin(network) => {
                ic_btc_validation::validate_header(network, store, header)
            }
            AdapterNetwork::Dogecoin(_network) => {
                // TODO: use real dogecoin validation
                Ok(())
            }
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
        // In parsing network names, we give priority to bitcoin network.
        // So both "testnet" and "bitcoin:testnet" will be parsed as bitcoin::Network::Testnet.
        if let Ok(network) = bitcoin::Network::from_str(s) {
            return Ok(network.into());
        } else if s == "dogecoin" {
            return Ok(bitcoin::dogecoin::Network::Dogecoin.into());
        } else if let Some(s) = s.strip_prefix("dogecoin:") {
            if let Ok(network) = bitcoin::dogecoin::Network::from_str(s) {
                return Ok(network.into());
            }
        } else if let Some(s) = s.strip_prefix("bitcoin:") {
            if let Ok(network) = bitcoin::Network::from_str(s) {
                return Ok(network.into());
            }
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

/// A trait that contains the common methods of both Bitcoin and Dogecoin blocks.
#[allow(missing_docs)]
pub trait BlockLike: Decodable + Encodable + Clone {
    fn block_hash(&self) -> bitcoin::BlockHash;
    fn compute_merkle_root(&self) -> Option<bitcoin::TxMerkleNode>;
    fn check_merkle_root(&self) -> bool;
    fn header(&self) -> bitcoin::block::Header;
}

impl BlockLike for bitcoin::Block {
    fn block_hash(&self) -> bitcoin::BlockHash {
        bitcoin::Block::block_hash(self)
    }
    fn compute_merkle_root(&self) -> Option<bitcoin::TxMerkleNode> {
        bitcoin::Block::compute_merkle_root(self)
    }
    fn check_merkle_root(&self) -> bool {
        bitcoin::Block::check_merkle_root(self)
    }
    fn header(&self) -> bitcoin::block::Header {
        self.header
    }
}

impl BlockLike for bitcoin::dogecoin::Block {
    fn block_hash(&self) -> bitcoin::BlockHash {
        bitcoin::dogecoin::Block::block_hash(self)
    }
    fn compute_merkle_root(&self) -> Option<bitcoin::TxMerkleNode> {
        bitcoin::dogecoin::Block::compute_merkle_root(self)
    }
    fn check_merkle_root(&self) -> bool {
        bitcoin::dogecoin::Block::check_merkle_root(self)
    }
    fn header(&self) -> bitcoin::block::Header {
        self.header
    }
}

#[cfg(test)]
pub mod test_common {

    use std::{
        collections::{HashSet, VecDeque},
        net::SocketAddr,
    };

    use bitcoin::{consensus::deserialize, Block};
    use hex::FromHex;

    use crate::{Channel, ChannelError, Command};

    /// This is a hex dump of the first block on the BTC network: 00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048
    pub const BLOCK_1_ENCODED: &str = "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e362990101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000";

    /// This is a hex dump of the first block on the BTC network: 000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd
    pub const BLOCK_2_ENCODED: &str = "010000004860eb18bf1b1620e37e9490fc8a427514416fd75159ab86688e9a8300000000d5fdcc541e25de1c7a5addedf24858b8bb665c9f36ef744ee42c316022c90f9bb0bc6649ffff001d08d2bd610101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d010bffffffff0100f2052a010000004341047211a824f55b505228e4c3d5194c1fcfaa15a456abdf37f9b9d97a4040afc073dee6c89064984f03385237d92167c13e236446b417ab79a0fcae412ae3316b77ac00000000";

    /// This struct is used to capture Commands generated by managers.
    pub struct TestChannel<Network> {
        /// This field holds Commands that are generated by managers.
        received_commands: VecDeque<Command<Network>>,
        /// The connections available for the test to interact with.
        available_connections: Vec<SocketAddr>,
        /// The addresses that disconnect was called on.
        disconnected_addresses: HashSet<SocketAddr>,
    }

    impl<Network> TestChannel<Network> {
        pub fn new(available_connections: Vec<SocketAddr>) -> Self {
            Self {
                received_commands: VecDeque::new(),
                available_connections,
                disconnected_addresses: HashSet::new(),
            }
        }
    }

    impl<Network> TestChannel<Network> {
        pub fn command_count(&self) -> usize {
            self.received_commands.len()
        }

        pub fn pop_front(&mut self) -> Option<Command<Network>> {
            self.received_commands.pop_front()
        }

        pub fn pop_back(&mut self) -> Option<Command<Network>> {
            self.received_commands.pop_back()
        }

        pub fn has_discarded_address(&self, addr: &SocketAddr) -> bool {
            self.disconnected_addresses.contains(addr)
        }
        pub fn add_address(&mut self, addr: SocketAddr) {
            self.available_connections.push(addr);
        }
    }

    impl<Network> Channel<Network> for TestChannel<Network> {
        fn send(&mut self, command: Command<Network>) -> Result<(), ChannelError> {
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
