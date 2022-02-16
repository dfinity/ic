use crate::Config;
use bitcoin::{
    network::{constants::ServiceFlags, Address},
    Network,
};
use rand::{
    prelude::{IteratorRandom, SliceRandom, StdRng},
    SeedableRng,
};
use slog::Logger;
use std::{
    collections::{HashSet, VecDeque},
    net::{SocketAddr, ToSocketAddrs},
};
use thiserror::Error;

/// Starting with version 31402, addresses are prefixed with a timestamp.
/// If no timestamp is present, the addresses should not be relayed to other peers,
/// unless it is indeed confirmed they are up.
pub type AddressTimestamp = u32;

/// This const represents the max amount of addresses that should be sent in an
/// `addr` message.
pub const MAX_ADDR_MESSAGE_SIZE: usize = 1000;

/// This enum is used to address errors found while working with the AddressBook.
#[derive(Debug, Error)]
pub enum AddressBookError {
    /// This variant is used when there are no available addresses.
    /// In practice, this should not occur, but we should still have something
    /// to address the possibility.
    #[error("Could not find an available address.")]
    AddressesDepleted,
    /// This variant is used when there are no available seed addresses to be
    /// found in the seed queue. This occurs due to improper configuration.
    #[error("Could not find any available seed address.")]
    NoSeedAddressesFound,
    /// This variant is used when the address manager receives more than
    /// [MAX_ADDRESSES](crate::addressmanager::MAX_ADDRESSES).
    #[error("Received too many addresses in `addr` message.")]
    TooManyAddresses {
        /// This field contains how many addresses were received.
        received: usize,
        /// This field contains the max amount of addresses that can be received.
        max_amount: usize,
    },
}

/// A convenience wrapper type for addressing results from the AddressBook.
pub type AddressBookResult<T> = Result<T, AddressBookError>;

/// This enum is used to indicate the type of address that is being retrieved from
/// the address book.
#[derive(Debug)]
pub enum AddressEntry {
    /// This variant represents seed addresses. Seed addresses are used to discover
    /// additional nodes on the Bitcoin network.
    Seed(SocketAddr),
    /// This variant represents discovered addresses. These addresses are found
    /// through requested addresses from seed nodes and other discovered nodes.
    Discovered(SocketAddr),
}

impl AddressEntry {
    /// This function is used to access the stored address in the enum.
    pub fn addr(&self) -> &SocketAddr {
        match self {
            AddressEntry::Seed(addr) => addr,
            AddressEntry::Discovered(addr) => addr,
        }
    }
}

/// This struct stores addresses that will be used to create new connections.
/// It also tracks addresses that are in current use to encourage use from
/// non-utilized addresses.
#[cfg_attr(test, derive(Debug))]
pub struct AddressBook {
    /// The DNS seeds provided by the configuration. These are used to build the seed queue.
    dns_seeds: Vec<String>,
    /// The port that should be targeted based on the provided configuration.
    port: u16,
    /// This field contains the addresses that are already in use.
    active_addresses: HashSet<SocketAddr>,
    /// This field contains the addresses that will be used for connections.
    known_addresses: HashSet<SocketAddr>,
    /// This field is used to store an instance of the logger.
    logger: Logger,
    /// The number of addresses needed to be maintained in the address book.
    min_addresses: usize,
    /// The maximum number of addresses that can be stored in the address book.
    max_addresses: usize,
    /// This field contains the addresses that will be used for the address discovery
    /// on initial startup and when the adapter is running low on addresses.
    seed_queue: VecDeque<SocketAddr>,
}

impl AddressBook {
    // TODO: ER-2122: Due to most replica nodes being IPv6 only, the adapter will need an
    // IPv6 only mode.
    /// This function creates a base set of addresses to use based on the
    /// config provided. If no addresses found, a panic will be issued as a connection
    /// cannot be made without an address. If not enough addresses are found to
    /// meet the minimum number of connections, a panic will be issued.
    pub fn new(config: &Config, logger: Logger) -> Self {
        let (min_addresses, max_addresses) = address_limits(config.network);
        let known_addresses: HashSet<SocketAddr> = config.nodes.iter().cloned().collect();
        Self {
            dns_seeds: config.dns_seeds.clone(),
            port: config.port(),
            active_addresses: HashSet::new(),
            known_addresses,
            logger,
            min_addresses,
            max_addresses,
            seed_queue: VecDeque::new(),
        }
    }

    /// This function takes the DNS seeds and creates a new queue of socket addresses to connect to
    /// for the address discovery process.
    fn build_seed_queue(&mut self) {
        let mut rng = StdRng::from_entropy();
        let dns_seeds = self
            .dns_seeds
            .iter()
            .map(|seed| format_addr(seed, self.port));
        let mut addresses = dns_seeds
            .flat_map(|seed| seed.to_socket_addrs().map_or(vec![], |v| v.collect()))
            .collect::<Vec<SocketAddr>>();
        addresses.shuffle(&mut rng);
        self.seed_queue = addresses.into_iter().collect();
    }

    /// This function is used when the adapter idles. It clears out the seed queue and active addresses.
    /// If the address book has seeds, it will also clear the known addresses.
    pub fn clear(&mut self) {
        if self.has_seeds() {
            self.known_addresses = HashSet::new();
        } else {
            self.known_addresses = self
                .known_addresses
                .union(&self.active_addresses)
                .into_iter()
                .cloned()
                .collect();
        }
        self.active_addresses = HashSet::new();
        self.seed_queue = VecDeque::new();
    }

    /// This function is used to determine how many entries are in the address book.
    pub fn size(&self) -> usize {
        self.known_addresses.len()
    }

    /// This function is used to determine if there are enough addresses in the address book
    /// to make a selection.
    pub fn has_enough_addresses(&self) -> bool {
        self.size() >= self.min_addresses
    }

    /// This function is used to determine if the address book has been filled with the maximum
    /// number of addresses.
    pub fn has_max_address(&self) -> bool {
        self.size() >= self.max_addresses
    }

    /// This adds many addresses from a received `addr` message.
    pub fn add_many(
        &mut self,
        sender: &SocketAddr,
        addresses: &[(AddressTimestamp, Address)],
    ) -> AddressBookResult<()> {
        if addresses.len() > MAX_ADDR_MESSAGE_SIZE {
            return Err(AddressBookError::TooManyAddresses {
                received: addresses.len(),
                max_amount: MAX_ADDR_MESSAGE_SIZE,
            });
        }
        let mut added_addresses = 0u32;
        for (_, address) in addresses {
            if self.has_max_address() {
                break;
            }

            if validate_services(&address.services) {
                if let Ok(address) = address.socket_addr() {
                    if *sender == address {
                        continue;
                    }
                    self.add(address);
                    added_addresses = added_addresses.saturating_add(1);
                }
            } else {
                slog::debug!(
                    self.logger,
                    "Address {:?} does not provide the network or network limited services.",
                    address.address
                );
            }
        }

        if added_addresses > 0 {
            slog::info!(
                self.logger,
                "Added {} addresses from {:?}.",
                added_addresses,
                sender
            );
        }

        Ok(())
    }

    /// This adds a new address to the possible sets.
    fn add(&mut self, addr: SocketAddr) {
        if self.active_addresses.contains(&addr) {
            return;
        }

        let added = self.known_addresses.insert(addr);
        if added {
            slog::debug!(
                self.logger,
                "Added {} to the list of known addresses.",
                addr
            );
        }
    }

    /// This function grabs an address randomly from the available addresses pool.
    /// If the available addresses is empty, then an
    /// [AddressBookError::AddressesDepleted](AddressBookError::AddressesDepleted)
    /// error is returned.
    pub fn pop(&mut self) -> AddressBookResult<AddressEntry> {
        let mut rng = StdRng::from_entropy();
        let maybe_address = self.known_addresses.iter().choose(&mut rng).cloned();
        if let Some(addr) = maybe_address {
            self.mark_as_active(&addr);
        }

        maybe_address
            .map(AddressEntry::Discovered)
            .ok_or(AddressBookError::AddressesDepleted)
    }

    /// This function retrieves the next seed address from the seed queue.
    /// If no seeds are found, the seed queue is rebuilt from the DNS seeds.
    pub fn pop_seed(&mut self) -> AddressBookResult<AddressEntry> {
        if self.seed_queue.is_empty() {
            self.build_seed_queue();
        }

        let address = self
            .seed_queue
            .pop_front()
            .ok_or(AddressBookError::NoSeedAddressesFound)?;
        Ok(AddressEntry::Seed(address))
    }

    /// Returns true if the AddressBook has seeds in the queue.
    pub fn has_seeds(&self) -> bool {
        !self.dns_seeds.is_empty()
    }

    /// This function takes a socket address and puts it into the active
    /// addresses set. It also removes the address from the local set, so
    /// the address is used again.
    fn mark_as_active(&mut self, addr: &SocketAddr) {
        self.known_addresses.remove(addr);
        self.active_addresses.insert(*addr);
    }

    /// This function takes a socket address and puts it into the local
    /// addresses set. It also removes the address from the active set, so
    /// the address can be used again.
    pub fn remove_from_active(&mut self, address: &AddressEntry) {
        if let AddressEntry::Discovered(addr) = address {
            self.active_addresses.remove(addr);
            self.known_addresses.insert(*addr);
        }
    }

    /// Completely removes a socket address from the book as long as the book
    /// has seeds. This action is used mainly in the case that an address
    /// performs an action that is not allowed.
    pub fn discard(&mut self, address: &AddressEntry) {
        if let AddressEntry::Discovered(addr) = address {
            if self.has_seeds() {
                self.active_addresses.remove(addr);
                self.known_addresses.remove(addr);
            } else {
                self.remove_from_active(address);
            }
        }
    }
}

/// This function is used to validate service flags . To determine if the address
/// is valid, we check the service flags that have been presented with the
/// address.
///
/// * Network: This node can be asked for full blocks instead of just headers.
/// * Network Limited: BIP-0159: The node is running in pruned mode storing
/// only the most recent 288 blocks. These nodes can still relay blocks from
/// full nodes.
pub fn validate_services(services: &ServiceFlags) -> bool {
    services.has(ServiceFlags::NETWORK | ServiceFlags::NETWORK_LIMITED)
}

/// This is a simple utility function for creating a string that is a valid string
/// for ToSocketAddrs.
fn format_addr(seed: &str, port: u16) -> String {
    format!("{}:{}", seed, port)
}

/// This function is used to get the address limits for the `AddressBook`
/// based on the provided `Network`.
fn address_limits(network: Network) -> (usize, usize) {
    match network {
        Network::Bitcoin => (500, 2000),
        Network::Testnet => (100, 1000),
        Network::Signet => (1, 1),
        Network::Regtest => (1, 1),
    }
}

#[cfg(test)]
mod test {

    use std::str::FromStr;

    use crate::{common::test_common::make_logger, config::test::ConfigBuilder};

    use super::*;

    /// This function tests the address manager basic interactions `mark_as_active`
    /// and `remove_from_active`.
    #[test]
    fn test_address_book_basics() {
        let config = ConfigBuilder::new()
            .with_dns_seeds(vec![String::from("127.0.0.1")])
            .build();
        let mut book = AddressBook::new(&config, make_logger());
        // Check if the address from the known_addresses.json has been loaded.
        let addr = SocketAddr::from_str("127.0.0.1:8333").expect("invalid address");

        assert!(book.known_addresses.is_empty());
        let result = book.pop();
        let err = result.unwrap_err();
        assert!(
            matches!(err, AddressBookError::AddressesDepleted),
            "expected to see a depleted error"
        );

        book.add(addr);
        let result = book.pop();
        assert!(result.is_ok());
        let entry = result.unwrap();
        assert_eq!(entry.addr(), &addr);
    }

    /// This function tests the `AddressManager::validate_address(...)` function to ensure
    /// that the service flags for an address are network and network limited.
    #[test]
    fn test_address_manager_validate_services() {
        let services = ServiceFlags::NETWORK | ServiceFlags::NETWORK_LIMITED;
        assert!(validate_services(&services));

        let services = ServiceFlags::NETWORK;
        assert!(!validate_services(&services));
    }

    /// This function tests the `AddressManager::add_many(...)` function to ensure
    /// addresses that are not valid are skipped while adding the valid addresses.
    #[test]
    fn test_address_manager_add_many() {
        let config = ConfigBuilder::new()
            .with_dns_seeds(vec![String::from("127.0.0.1")])
            .build();
        let mut book = AddressBook::new(&config, make_logger());

        let seed = book.pop_seed().expect("there should be 1 seed");
        let socket_1 = SocketAddr::from_str("127.0.0.1:8444").expect("bad address format");
        let address_1 = Address::new(
            &socket_1,
            ServiceFlags::NETWORK | ServiceFlags::NETWORK_LIMITED,
        );

        let socket_2 = SocketAddr::from_str("127.0.0.1:8555").expect("bad address format");
        let address_2 = Address::new(&socket_2, ServiceFlags::NETWORK_LIMITED);
        let addresses = vec![(0, address_1), (0, address_2)];
        assert_eq!(book.known_addresses.len(), 0);
        book.add_many(seed.addr(), &addresses)
            .expect("should not cause an error");
        assert_eq!(book.known_addresses.len(), 1);
        assert!(book.known_addresses.contains(&socket_1));
        assert!(!book.known_addresses.contains(&socket_2));
    }

    /// This function tests the `AddressBook::discard(...)` function to ensure
    /// the addresses are removed from the pool.
    #[test]
    fn test_discard_address() {
        let config = ConfigBuilder::new()
            .with_dns_seeds(vec![String::from("127.0.0.1"), String::from("192.168.1.1")])
            .build();
        let mut book = AddressBook::new(&config, make_logger());
        let seed = book.pop_seed().expect("there should be 1 seed");
        let socket = SocketAddr::from_str("127.0.0.1:8444").expect("bad address format");
        let address = Address::new(
            &socket,
            ServiceFlags::NETWORK | ServiceFlags::NETWORK_LIMITED,
        );

        let addresses = vec![(0, address)];
        book.add_many(seed.addr(), &addresses)
            .expect("should not cause an error");
        let entry = book.pop().expect("address 1 should be there");
        assert_eq!(book.active_addresses.len(), 1);

        assert_eq!(book.active_addresses.len() + book.known_addresses.len(), 1);
        assert_eq!(book.known_addresses.len(), 0);

        // If there are seed addresses, then toss away the address.
        book.discard(&entry);
        assert_eq!(book.known_addresses.len(), 0);
        assert_eq!(book.active_addresses.len(), 0);

        // If there a no more seeds, then the address is added back into the known addresses pool.
        // Used for connecting to a regtest node.
        book.dns_seeds.clear();
        book.discard(&entry);
        assert_eq!(book.known_addresses.len(), 1);
        assert_eq!(book.active_addresses.len(), 0);
    }

    #[test]
    fn test_discard_address_no_seeds() {
        let config = ConfigBuilder::new()
            .with_network(Network::Regtest)
            .with_nodes(vec![SocketAddr::from_str("127.0.0.1:8333").unwrap()])
            .build();
        let mut book = AddressBook::new(&config, make_logger());
        let entry = book.pop().expect("address from nodes should be there");
        assert_eq!(book.active_addresses.len(), 1);

        assert_eq!(book.active_addresses.len() + book.known_addresses.len(), 1);
        assert_eq!(book.known_addresses.len(), 0);

        book.discard(&entry);
        assert_eq!(book.known_addresses.len(), 1);
        assert_eq!(book.active_addresses.len(), 0);
    }

    /// This function ensures that the [AddressBook::pop_seed](AddressBook::pop_seed) method
    /// gives the next address in queue but also pushes it to the back of the queue.
    #[test]
    fn test_pop_seed() {
        let config = ConfigBuilder::new()
            .with_network(Network::Signet)
            .with_dns_seeds(vec![String::from("127.0.0.1"), String::from("192.168.1.1")])
            .build();
        let mut book = AddressBook::new(&config, make_logger());
        book.pop_seed().expect("there should be 1 seed");
        assert_eq!(book.seed_queue.len(), 1);

        book.pop_seed().expect("there should be 1 seed");
        assert_eq!(book.seed_queue.len(), 0);

        book.pop_seed().expect("pop_seed should rebuild seed queue");
        assert_eq!(book.seed_queue.len(), 1);

        // Remove the remaining seed address and then empty the dns_seeds.
        book.pop_seed().expect("there should be 1 seed");
        book.dns_seeds.clear();
        // `pop_seed` should now cause the AddressBookError::NoSeedAddressesFound error.
        assert!(matches!(
            book.pop_seed(),
            Err(AddressBookError::NoSeedAddressesFound)
        ));
    }

    /// This test exercises `AddressBook::clear(...)` by checking the following:
    /// 1. If there are DNS seeds, the known, active addresses, and seed queue should be emptied.
    /// 2. If there are no DNS seeds, the seed queue and active addresses is emptied.
    #[test]
    fn test_clear() {
        let config = ConfigBuilder::new()
            .with_dns_seeds(vec![String::from("127.0.0.1"), String::from("192.168.1.1")])
            .build();
        let mut book = AddressBook::new(&config, make_logger());
        let seed = book.pop_seed().expect("there should be 1 seed");
        let socket = SocketAddr::from_str("127.0.0.1:8444").expect("bad address format");
        let address = Address::new(
            &socket,
            ServiceFlags::NETWORK | ServiceFlags::NETWORK_LIMITED,
        );

        let addresses = vec![(0, address)];
        book.add_many(seed.addr(), &addresses)
            .expect("should not cause an error");

        book.mark_as_active(&socket);
        assert_eq!(book.known_addresses.len(), 0);
        assert_eq!(book.active_addresses.len(), 1);

        book.clear();
        assert_eq!(book.known_addresses.len(), 0);
        assert_eq!(book.active_addresses.len(), 0);

        book.dns_seeds.clear();
        book.add_many(seed.addr(), &addresses)
            .expect("should not cause an error");

        book.mark_as_active(&socket);
        assert_eq!(book.known_addresses.len(), 0);
        assert_eq!(book.active_addresses.len(), 1);

        book.clear();
        assert_eq!(book.known_addresses.len(), 1);
        assert_eq!(book.active_addresses.len(), 0);
    }
}
