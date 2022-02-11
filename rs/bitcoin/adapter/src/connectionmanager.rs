use std::{
    collections::HashMap,
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bitcoin::network::{
    constants::ServiceFlags,
    message::{CommandString, NetworkMessage},
    message_network::VersionMessage,
    Address,
};
use rand::prelude::*;
use slog::Logger;
use thiserror::Error;
use tokio::{
    sync::mpsc::{channel, Sender},
    sync::mpsc::{unbounded_channel, Receiver},
    task,
};

use crate::{
    addressbook::{
        validate_services, AddressBook, AddressBookError, AddressEntry, AddressTimestamp,
    },
    common::DEFAULT_CHANNEL_BUFFER_SIZE,
    common::*,
    connection::{Connection, ConnectionConfig, ConnectionState, PingState},
    stream::{StreamConfig, StreamEvent, StreamEventKind},
    Channel, ChannelError, Command, Config, ProcessEvent, ProcessEventError,
};

/// This constant represents the amount of time that is allowed for completing a version handshake
/// in seconds. This is useful as some nodes do not respond in an orderly fashion with version
/// information.
const INCOMPLETE_HANDSHAKE_TIMEOUT_SECS: u64 = 5;

/// This constant represents the amount of time that is allowed for a seed to send addresses
/// in seconds. This is useful as some nodes do not respond to `getaddr` or are to slow in
/// responding.
const SEED_ADDR_RETRIEVED_TIMEOUT_SECS: u64 = 5;

/// This enum represents the possible errors that the connection manager may encounter.
#[derive(Debug, Error)]
pub enum ConnectionManagerError {
    /// The connection that was to be used could not be found in the `connections` field.
    #[error("Connection could not be found in the manager.")]
    ConnectionNotFound,
    /// The address manager provided encountered an error while attempting to
    /// look up an available address.
    #[error("Address Book: {0}")]
    AddressBook(AddressBookError),
    #[error("The system time has fallen behind.")]
    SystemTimeIsBehind,
}

/// This type is a simple wrapper for results created by a connection manager.
pub type ConnectionManagerResult<T> = Result<T, ConnectionManagerError>;

/// This struct manages the connection connections that the adapter uses to communicate
/// with Bitcoin nodes.
#[cfg_attr(test, derive(Debug))]
pub struct ConnectionManager {
    /// This field contains the address book.
    address_book: AddressBook,
    /// This field is used to indicate whether or not the connection manager needs to populate the
    /// address book.
    initial_address_discovery: bool,
    /// This field is used to store an instance of the logger.
    logger: Logger,
    /// This field is used to provide the magic value to the raw network message.
    /// The magic number is used to identity the type of Bitcoin network being accessed.
    magic: u32,
    /// This field contains the number of connections the connection manager can manage at one time.
    max_connections: usize,
    /// This field contains the number of connections the connection manager must have in order to send messages.
    min_connections: usize,
    /// The minimum height that nodes should have in order to be a valid
    /// connection.
    min_start_height: BlockHeight,
    /// This field contains connections that have connected are being managed.
    connections: HashMap<SocketAddr, Connection>,
    /// This field determines whether or not we will be using a SOCKS proxy to communicate with
    /// the BTC network.
    socks_proxy: Option<SocketAddr>,
    /// This field is used to receive stream events from the active connection streams.
    stream_event_receiver: Receiver<StreamEvent>,
    /// This field is used to allow new streams to send events back to the connection manager.
    stream_event_sender: Sender<StreamEvent>,
    /// This field is used for the version nonce generation.
    rng: StdRng,
}

impl ConnectionManager {
    /// This function is used to create a new connection manager with a provided config.
    pub fn new(config: &Config, logger: Logger) -> ConnectionManagerResult<Self> {
        let address_book = AddressBook::new(config, logger.clone())
            .map_err(ConnectionManagerError::AddressBook)?;
        let (stream_event_sender, stream_event_receiver) =
            channel::<StreamEvent>(DEFAULT_CHANNEL_BUFFER_SIZE);

        let (min_connections, max_connections) = connection_limits(&address_book);

        Ok(Self {
            initial_address_discovery: !address_book.has_enough_addresses(),
            address_book,
            logger,
            magic: config.network.magic(),
            max_connections,
            min_connections,
            min_start_height: 0,
            connections: HashMap::with_capacity(max_connections),
            rng: StdRng::from_entropy(),
            socks_proxy: config.socks_proxy,
            stream_event_sender,
            stream_event_receiver,
        })
    }

    /// If there is an issue with a misbehaving node, the node is marked as
    /// disconnected and
    pub fn discard(&mut self, address: SocketAddr) {
        if let Ok(conn) = self.get_connection(&address) {
            conn.discard();
        }
    }

    /// This function pulls events off of the connection manager's stream event
    /// receiver and returns it to the caller.
    pub fn receive_stream_event(&mut self) -> Option<StreamEvent> {
        self.stream_event_receiver.try_recv().ok()
    }

    /// This function contains the actions the must occur every time the connection
    /// manager must execute actions.
    pub fn tick<T>(&mut self, handle: fn(StreamConfig) -> T)
    where
        T: Future + Send + 'static,
    {
        if let Err(ConnectionManagerError::AddressBook(err)) = self.manage_connections(handle) {
            slog::error!(self.logger, "{}", err);
        }
    }

    /// This method is used when the adapter is no longer receiving RPC calls from the replica.
    /// Cleans up all active connections.
    pub fn make_idle(&mut self) {
        for conn in self.connections.values_mut() {
            conn.disconnect();
        }
        self.reap_disconnected();
        self.address_book.clear();
    }

    /// This function will remove disconnects and establish new connections.
    fn manage_connections<T>(
        &mut self,
        handle: fn(StreamConfig) -> T,
    ) -> ConnectionManagerResult<()>
    where
        T: Future + Send + 'static,
    {
        self.manage_ping_states();
        self.flag_version_handshake_timeouts();
        self.flag_seed_addr_retrieval_timeouts();
        self.reap_disconnected();
        while self.connections.len() < self.get_max_number_of_connections() {
            self.make_connection(handle)?;
        }
        Ok(())
    }

    /// This function is used to get the max number of connections allowed at a time.
    /// During initial address discovery, the adapter should only make one connection at
    /// a time while discovering addresses from the Bitcoin seed nodes. This is so the
    /// adapter does not overwhelm the network with connections.
    fn get_max_number_of_connections(&self) -> usize {
        if self.initial_address_discovery {
            1
        } else {
            self.max_connections
        }
    }

    /// This function is used to check which connections need to be pinged or
    /// which connections have timed out.
    fn manage_ping_states(&mut self) {
        let mut needs_ping = vec![];
        for conn in self.connections.values_mut() {
            if conn.needs_ping() {
                needs_ping.push(*conn.address_entry().addr());
            }

            if conn.has_ping_timed_out() {
                conn.disconnect();
            }
        }

        for addr in needs_ping {
            slog::info!(self.logger, "Sending ping to {}", addr);
            self.send_ping(&addr).ok();
        }
    }

    /// This function disconnects from nodes that have not completed the version handshake within
    /// the defined limit.
    fn flag_version_handshake_timeouts(&mut self) {
        let now = SystemTime::now();
        for conn in self.connections.values_mut() {
            if let ConnectionState::Connected { timestamp } = *conn.state() {
                let expires_at = timestamp + Duration::from_secs(INCOMPLETE_HANDSHAKE_TIMEOUT_SECS);
                if expires_at <= now {
                    conn.discard();
                }
            }
        }
    }

    /// This function disconnects from seed nodes that have not sent in the addresses within the
    /// defined limit.
    fn flag_seed_addr_retrieval_timeouts(&mut self) {
        let now = SystemTime::now();
        for conn in self.connections.values_mut() {
            if let AddressEntry::Seed(_) = *conn.address_entry() {
                if let ConnectionState::AwaitingAddresses { timestamp } = *conn.state() {
                    let expires_at =
                        timestamp + Duration::from_secs(SEED_ADDR_RETRIEVED_TIMEOUT_SECS);
                    if expires_at <= now {
                        conn.discard();
                    }
                }
            }
        }
    }

    /// This function cleans up connections that are no longer active.
    fn reap_disconnected(&mut self) {
        let mut disconnects = vec![];
        for (addr, conn) in self.connections.iter() {
            match conn.state() {
                ConnectionState::AdapterDiscarded { .. } => {
                    slog::warn!(
                        self.logger,
                        "Adapter discarded connection {}",
                        conn.address_entry().addr(),
                    );
                    self.address_book.discard(conn.address_entry());
                }
                ConnectionState::NodeDisconnected { .. } => {
                    slog::debug!(
                        self.logger,
                        "Node {} disconnected from adapter",
                        conn.address_entry().addr(),
                    );
                    self.address_book.remove_from_active(conn.address_entry());
                }
                _ => {}
            }

            if conn.is_disconnected() {
                disconnects.push(*addr);
            }
        }

        for addr in disconnects {
            self.connections.remove(&addr);
        }
    }

    /// This function creates a new connection with a stream to a BTC node.
    fn make_connection<T>(&mut self, handle: fn(StreamConfig) -> T) -> ConnectionManagerResult<()>
    where
        T: Future + Send + 'static,
    {
        let address_entry_result = if !self.address_book.has_enough_addresses() {
            self.address_book.pop_seed()
        } else {
            self.address_book.pop()
        };
        let address_entry = address_entry_result.map_err(ConnectionManagerError::AddressBook)?;
        let socks_proxy = self.socks_proxy;
        let (writer, network_message_receiver) = unbounded_channel();
        let stream_event_sender = self.stream_event_sender.clone();
        let address = *address_entry.addr();
        let stream_config = StreamConfig {
            address,
            logger: self.logger.clone(),
            magic: self.magic,
            network_message_receiver,
            socks_proxy,
            stream_event_sender,
        };
        let handle = task::spawn(async move {
            handle(stream_config).await;
        });
        let conn = Connection::new(ConnectionConfig {
            address_entry,
            handle,
            writer,
        });
        self.connections.insert(address, conn);
        Ok(())
    }

    /// This function retrieves a connection from the connections pool with a given socket address.
    fn get_connection(&mut self, addr: &SocketAddr) -> ConnectionManagerResult<&mut Connection> {
        match self.connections.get_mut(addr) {
            Some(connection) => Ok(connection),
            None => Err(ConnectionManagerError::ConnectionNotFound),
        }
    }

    // TODO: ER-1493: The adapter should send a version that is more representative of the adapter's
    // current state (block height, the machine's actual address, user agent).
    /// This function is used to send a `version` message to a specified connection.
    fn send_version(&mut self, addr: &SocketAddr) -> ConnectionManagerResult<()> {
        // https://en.bitcoin.it/wiki/Protocol_documentation#version
        let adapter_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
        let services = ServiceFlags::NONE;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ConnectionManagerError::SystemTimeIsBehind)?
            .as_secs();
        // The node address that will be receiving this message
        let receiver = Address::new(addr, ServiceFlags::NETWORK | ServiceFlags::NETWORK_LIMITED);
        // The node address that is sending this message (the adapter itself)
        let sender = Address::new(&adapter_address, ServiceFlags::NONE);
        let nonce: u64 = self.rng.gen();
        let user_agent = String::from("ic-btc-adapter");
        // The height the adapter believes is the tip.
        let start_height: i32 = 0;
        let message = NetworkMessage::Version(VersionMessage::new(
            services,
            timestamp as i64,
            receiver,
            sender,
            nonce,
            user_agent,
            start_height,
        ));

        slog::debug!(self.logger, "Sending version to {}", addr);
        self.send_to(addr, message)
    }

    /// This function is used to send a `verack` message to a specified connection.
    fn send_verack(&mut self, addr: &SocketAddr) -> ConnectionManagerResult<()> {
        slog::debug!(self.logger, "Sending verack to {}", addr);
        self.send_to(addr, NetworkMessage::Verack)
    }

    /// This function is used to send a `getaddr` message to a specified connection.
    fn send_getaddr(&mut self, addr: &SocketAddr) -> ConnectionManagerResult<()> {
        slog::debug!(self.logger, "Sending getaddr to {}", addr);
        self.send_to(addr, NetworkMessage::GetAddr)
    }

    /// This function is used to send a `ping` message to a specified connection.
    fn send_ping(&mut self, addr: &SocketAddr) -> ConnectionManagerResult<()> {
        slog::debug!(self.logger, "Sending ping to {}", addr);
        let nonce = self.rng.gen();
        let conn = self.get_connection(addr)?;
        conn.expect_pong(nonce);
        self.send_to(addr, NetworkMessage::Ping(nonce))
    }

    /// This function is used to respond to a `ping` message with a `pong` to the specified
    /// connection.
    fn send_pong(&mut self, addr: &SocketAddr, nonce: u64) -> ConnectionManagerResult<()> {
        self.send_to(addr, NetworkMessage::Pong(nonce))
    }

    /// This function is used to send a message to a specified connection.
    fn send_to(
        &mut self,
        addr: &SocketAddr,
        network_message: NetworkMessage,
    ) -> ConnectionManagerResult<()> {
        let conn = self.get_connection(addr)?;
        if conn.send(network_message).is_err() {
            conn.disconnect();
        };
        Ok(())
    }

    /// This function checks to see if the connection manager has enough
    /// active connections. Use to control is a message is sent out.
    fn has_enough_active_connections(&self) -> bool {
        self.available_connections().len() >= self.min_connections
    }

    /// This function is used to send a message to all of the connected connections.
    fn send_to_all(&mut self, network_message: NetworkMessage) {
        if !self.has_enough_active_connections() {
            return;
        }

        let available_addrs = self.available_connections();
        for addr in available_addrs {
            self.send_to(&addr, network_message.clone()).ok();
        }
    }

    fn process_version_message(
        &mut self,
        address: &SocketAddr,
        message: &VersionMessage,
    ) -> Result<(), ProcessEventError> {
        slog::info!(self.logger, "Received version from {}", address);
        if !self.validate_received_version(message) {
            slog::warn!(self.logger, "Received an invalid version from {}", address);
            return Err(ProcessEventError::InvalidMessage);
        }
        self.send_verack(address).ok();

        if !self.address_book.has_max_address() {
            self.send_getaddr(address).ok();
        }

        Ok(())
    }

    fn process_verack_message(&mut self, address: &SocketAddr) -> Result<(), ProcessEventError> {
        slog::info!(self.logger, "Received verack from {}", address);
        if let Ok(conn) = self.get_connection(address) {
            match conn.address_entry() {
                AddressEntry::Seed(_) => conn.awaiting_addresses(),
                AddressEntry::Discovered(_) => conn.completed_handshake(),
            };
        }

        slog::info!(
            self.logger,
            "Completed the version handshake with {}",
            address
        );
        Ok(())
    }

    /// This function processes a ping message sent from a connected BTC node.
    fn process_ping_message(
        &mut self,
        address: &SocketAddr,
        nonce: u64,
    ) -> Result<(), ProcessEventError> {
        // If we cannot find the connection, the connection has been cleaned up before the
        // message has been received. It can be skipped.
        slog::debug!(self.logger, "Received ping from {}", address);
        self.send_pong(address, nonce).ok();
        Ok(())
    }

    /// This function processes a received pong message sent from a connected BTC node.
    fn process_pong_message(
        &mut self,
        address: &SocketAddr,
        nonce: u64,
    ) -> Result<(), ProcessEventError> {
        // If we cannot find the connection, the connection has been cleaned up before the
        // message has been received. It can be skipped.
        slog::info!(self.logger, "Received pong from {}", address);
        if let Ok(conn) = self.get_connection(address) {
            let valid_pong = match conn.ping_state() {
                PingState::ExpectingPong {
                    ping_sent_at: _,
                    nonce: ping_nonce,
                } => *ping_nonce == nonce,
                PingState::Idle { last_pong_at: _ } => false,
            };

            if valid_pong {
                conn.idle();
            } else {
                // Received an unexpected or invalid `pong` message.
                // Disconnect from the BTC node.
                conn.disconnect();
            };
        }
        Ok(())
    }

    /// This function processes an `addr` message received from a BTC node.
    /// If too many addresses have been sent, the connection is disconnected,
    /// and the address is discarded.
    fn process_addr_message(
        &mut self,
        address: &SocketAddr,
        addresses: &[(AddressTimestamp, Address)],
    ) -> Result<(), ProcessEventError> {
        let result = self.address_book.add_many(address, addresses);
        if let Err(AddressBookError::TooManyAddresses {
            received,
            max_amount,
        }) = result
        {
            slog::warn!(
                self.logger,
                "Received {} addresses from {} (max: {})",
                received,
                address,
                max_amount
            );
            return Err(ProcessEventError::InvalidMessage);
        }

        if let Ok(conn) = self.get_connection(address) {
            if let AddressEntry::Seed(_) = conn.address_entry() {
                conn.disconnect();
            }
        }

        if self.address_book.has_enough_addresses() {
            self.initial_address_discovery = false;
        }
        Ok(())
    }

    /// This function is used to handle an unknown command from a BTC node.
    fn process_unknown_message(
        &mut self,
        address: &SocketAddr,
        command: &CommandString,
        payload: &[u8],
    ) -> Result<(), ProcessEventError> {
        // If we receive an unknown message from a BTC node, the adapter should log
        // the message for further analysis.
        slog::warn!(
            self.logger,
            "Received an unknown message from {}, command: {}, payload: {}",
            address,
            command,
            hex::encode(payload),
        );
        self.discard(*address);
        Ok(())
    }

    /// This function validates a received version message based on the following criteria:
    ///
    /// * The sender address is advertising the services the adapter is looking for.
    /// * The start height is at least the configured minimum.
    /// * The version is at least the configured minimum.
    /// * The services in the main message match the sender services.
    fn validate_received_version(&self, message: &VersionMessage) -> bool {
        validate_services(&message.services)
            && message.start_height >= self.min_start_height as i32
            && message.version >= MINIMUM_VERSION_NUMBER
    }
}

impl Channel for ConnectionManager {
    fn send(&mut self, command: Command) -> Result<(), ChannelError> {
        let Command { address, message } = command;
        if let Some(addr) = address {
            self.send_to(&addr, message).ok();
        } else {
            self.send_to_all(message);
        }
        Ok(())
    }

    /// This function provides an iterator to the currently available connections.
    fn available_connections(&self) -> Vec<SocketAddr> {
        self.connections
            .iter()
            .filter_map(|(addr, conn)| {
                if let AddressEntry::Seed(_) = conn.address_entry() {
                    return None;
                }

                if conn.is_available() {
                    Some(*addr)
                } else {
                    None
                }
            })
            .collect()
    }
}

impl ProcessEvent for ConnectionManager {
    fn process_event(&mut self, event: &StreamEvent) -> Result<(), ProcessEventError> {
        match &event.kind {
            StreamEventKind::Connected => {
                let result = self.send_version(&event.address);
                if let Ok(conn) = self.get_connection(&event.address) {
                    match result {
                        Ok(_) => {
                            conn.connected();
                            slog::info!(self.logger, "Connected to {}", event.address);
                        }
                        Err(err) => {
                            conn.disconnect();
                            slog::error!(self.logger, "{}", err);
                        }
                    };
                }
                Ok(())
            }
            StreamEventKind::Disconnected => {
                if let Ok(conn) = self.get_connection(&event.address) {
                    conn.disconnect();
                }
                Ok(())
            }
            StreamEventKind::FailedToConnect => {
                self.discard(event.address);
                Ok(())
            }
            StreamEventKind::Message(message) => match message {
                NetworkMessage::Version(version_message) => {
                    self.process_version_message(&event.address, version_message)
                }
                NetworkMessage::Verack => self.process_verack_message(&event.address),
                NetworkMessage::Addr(addresses) => {
                    self.process_addr_message(&event.address, addresses)
                }
                NetworkMessage::Ping(nonce) => self.process_ping_message(&event.address, *nonce),
                NetworkMessage::Pong(nonce) => self.process_pong_message(&event.address, *nonce),
                NetworkMessage::Unknown { command, payload } => {
                    self.process_unknown_message(&event.address, command, payload)
                }
                _ => Ok(()),
            },
        }
    }
}

fn connection_limits(address_book: &AddressBook) -> (usize, usize) {
    if address_book.has_seeds() {
        // Seeds are available.
        (2, 5)
    } else {
        // No seeds are available. Can only connect to nodes explicitly provided.
        (address_book.size(), address_book.size())
    }
}

#[cfg(test)]
mod test {

    use std::str::FromStr;

    use bitcoin::{network::constants::ServiceFlags, Network};

    use crate::{common::test_common::make_logger, config::test::ConfigBuilder};

    use super::*;

    #[test]
    /// This function tests the initialization of the address book.
    fn test_address_book_init() {
        let config = ConfigBuilder::new().with_network(Network::Signet).build();
        let result = ConnectionManager::new(&config, make_logger());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            ConnectionManagerError::AddressBook(AddressBookError::NoAddressesFound)
        ));
    }

    #[test]
    fn validate_received_version_bad_version_number() {
        let socket_1 = SocketAddr::from_str("127.0.0.1:8333").expect("bad address format");
        let socket_2 = SocketAddr::from_str("127.0.0.1:8333").expect("bad address format");
        let services = ServiceFlags::NETWORK | ServiceFlags::NETWORK_LIMITED;
        let receiver = Address::new(&socket_1, services);
        let sender = Address::new(&socket_2, ServiceFlags::NONE);
        let config = ConfigBuilder::new()
            .with_dns_seeds(vec![String::from("127.0.0.1")])
            .build();
        let mut version_message = VersionMessage::new(
            services,
            0,
            receiver,
            sender,
            1,
            String::from("test"),
            60000,
        );
        version_message.version = MINIMUM_VERSION_NUMBER - 1;

        let manager = ConnectionManager::new(&config, make_logger()).expect("invalid init");
        assert!(!manager.validate_received_version(&version_message));
    }

    #[test]
    fn validate_received_version_bad_start_height() {
        let socket_1 = SocketAddr::from_str("127.0.0.1:8333").expect("bad address format");
        let socket_2 = SocketAddr::from_str("127.0.0.1:8333").expect("bad address format");
        let services = ServiceFlags::NETWORK | ServiceFlags::NETWORK_LIMITED;
        let receiver = Address::new(&socket_1, services);
        let sender = Address::new(&socket_2, ServiceFlags::NONE);
        let version_message = VersionMessage::new(
            services,
            0,
            receiver,
            sender,
            1,
            String::from("test"),
            60_000,
        );

        let config = ConfigBuilder::new()
            .with_dns_seeds(vec![String::from("127.0.0.1")])
            .build();
        let mut manager = ConnectionManager::new(&config, make_logger()).expect("invalid init");
        manager.min_start_height = 100_000;

        assert!(!manager.validate_received_version(&version_message));
    }

    #[test]
    fn validate_received_version_service_flags_do_not_match() {
        let socket_1 = SocketAddr::from_str("127.0.0.1:8333").expect("bad address format");
        let socket_2 = SocketAddr::from_str("127.0.0.1:8333").expect("bad address format");
        let services = ServiceFlags::WITNESS;
        let receiver = Address::new(&socket_1, ServiceFlags::NONE);
        let sender = Address::new(&socket_2, ServiceFlags::NONE);
        let version_message = VersionMessage::new(
            services,
            0,
            receiver,
            sender,
            1,
            String::from("test"),
            60_000,
        );

        let config = ConfigBuilder::new()
            .with_dns_seeds(vec![String::from("127.0.0.1")])
            .build();
        let manager = ConnectionManager::new(&config, make_logger()).expect("invalid init");

        assert!(!manager.validate_received_version(&version_message));
    }

    async fn simple_handle(config: StreamConfig) {
        let StreamConfig {
            address,
            mut network_message_receiver,
            stream_event_sender,
            ..
        } = config;

        let adapter_address = SocketAddr::from_str("0.0.0.0:8333").expect("invalid addr");
        let address_2 = SocketAddr::from_str("192.168.1.1:8333").expect("invalid addr");
        let now = SystemTime::now();
        let since_epoch = now
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_secs() as u32;
        let services = ServiceFlags::NETWORK | ServiceFlags::NETWORK_LIMITED;
        let addresses = vec![
            (since_epoch, Address::new(&address, services)),
            (since_epoch, Address::new(&address_2, services)),
        ];

        stream_event_sender
            .send(StreamEvent {
                address,
                kind: StreamEventKind::Connected,
            })
            .await
            .ok();

        loop {
            let maybe_message = network_message_receiver.recv().await;
            if maybe_message.is_none() {
                break; // Something went wrong with the test. Time to escape!
            }
            let message = maybe_message.unwrap();
            match message {
                NetworkMessage::Version(_) => {
                    stream_event_sender
                        .send(StreamEvent {
                            address,
                            kind: StreamEventKind::Message(NetworkMessage::Verack),
                        })
                        .await
                        .ok();
                    stream_event_sender
                        .send(StreamEvent {
                            address,
                            kind: StreamEventKind::Message(NetworkMessage::Version(
                                VersionMessage::new(
                                    services,
                                    since_epoch as i64,
                                    Address::new(&adapter_address, services),
                                    Address::new(&address, services),
                                    0,
                                    String::from("user-agent"),
                                    0,
                                ),
                            )),
                        })
                        .await
                        .ok();
                }
                NetworkMessage::Verack => {}
                NetworkMessage::GetAddr => {
                    stream_event_sender
                        .send(StreamEvent {
                            address,
                            kind: StreamEventKind::Message(NetworkMessage::Addr(addresses.clone())),
                        })
                        .await
                        .ok();
                }
                _ => break,
            }
        }
    }

    /// This test is used to walk through the initial address discovery process.
    #[test]
    fn test_initial_address_discovery_lifecycle() {
        let runtime = tokio::runtime::Runtime::new().expect("runtime err");

        let config = ConfigBuilder::new()
            .with_network(Network::Signet)
            .with_dns_seeds(vec![String::from("127.0.0.1")])
            .build();
        let mut manager = ConnectionManager::new(&config, make_logger()).expect("invalid init");

        let addr = SocketAddr::from_str("127.0.0.1:8333").expect("invalid address");
        assert!(manager.initial_address_discovery);
        assert_eq!(manager.get_max_number_of_connections(), 1);

        runtime.block_on(async {
            manager.tick(simple_handle);
            assert_eq!(manager.connections.len(), 1);
            for i in 0..4u8 {
                let event = manager
                    .stream_event_receiver
                    .recv()
                    .await
                    .expect("connected event should have arrived");
                manager.process_event(&event).ok();
                if i == 3 {
                    // Skipping last tick as this will start a new connection cycle.
                    // At this point, we should be able to see if the seed connection
                    // has been disconnected.
                    continue;
                }
                manager.tick(simple_handle);
            }
        });

        assert_eq!(
            manager.address_book.size(),
            1,
            "Expected to have found the 1 address needed"
        );
        assert!(manager.address_book.has_enough_addresses());
        let conn = manager
            .get_connection(&addr)
            .expect("there should be a seed connection");
        assert!(matches!(
            conn.state(),
            ConnectionState::NodeDisconnected { timestamp: _ }
        ));
        assert_eq!(*conn.address_entry().addr(), addr);
        assert!(!manager.initial_address_discovery);
        assert_eq!(manager.get_max_number_of_connections(), 5);
    }

    #[test]
    fn test_flag_version_handshake_timeouts() {
        let runtime = tokio::runtime::Runtime::new().expect("runtime err");
        let addr = SocketAddr::from_str("127.0.0.1:8333").expect("invalid address");

        let config = ConfigBuilder::new()
            .with_dns_seeds(vec![String::from("127.0.0.1")])
            .build();
        let mut manager = ConnectionManager::new(&config, make_logger()).expect("invalid init");
        let timestamp = SystemTime::now() - Duration::from_secs(60);
        let (writer, _) = unbounded_channel();
        runtime.block_on(async {
            let conn = Connection::new_with_state(
                ConnectionConfig {
                    address_entry: AddressEntry::Discovered(addr),
                    handle: task::spawn(async {}),
                    writer,
                },
                ConnectionState::Connected { timestamp },
            );
            manager.connections.insert(addr, conn);
            manager.flag_version_handshake_timeouts();
            let conn = manager
                .get_connection(&addr)
                .expect("The connection should be there");
            assert!(matches!(
                conn.state(),
                ConnectionState::AdapterDiscarded { .. }
            ));
        });
    }

    /// Tests the `flag_seed_addr_retrieval_timeouts(...)`.
    /// Creates two connections both with the AwaitingAddresses state.
    /// 1 connection has an expired timestamp while the other timestamp is still valid.
    /// `flag_seed_addr_retrieval_timeouts(...)` then flags the expired connection.
    /// `reap_disconnected` is then called to remove the expired connection.
    #[test]
    fn test_flag_seed_addr_retrieval_timeouts() {
        let runtime = tokio::runtime::Runtime::new().expect("runtime err");
        let addr = SocketAddr::from_str("127.0.0.1:8333").expect("invalid address");
        let addr2 = SocketAddr::from_str("192.168.1.1:8333").expect("invalid address");
        let config = ConfigBuilder::new()
            .with_dns_seeds(vec![String::from("127.0.0.1")])
            .build();
        let mut manager = ConnectionManager::new(&config, make_logger()).expect("invalid init");
        let timestamp1 = SystemTime::now() - Duration::from_secs(SEED_ADDR_RETRIEVED_TIMEOUT_SECS);
        let timestamp2 = SystemTime::now() + Duration::from_secs(SEED_ADDR_RETRIEVED_TIMEOUT_SECS);
        let (writer, _) = unbounded_channel();
        runtime.block_on(async {
            let conn = Connection::new_with_state(
                ConnectionConfig {
                    address_entry: AddressEntry::Seed(addr),
                    handle: task::spawn(async {}),
                    writer: writer.clone(),
                },
                ConnectionState::AwaitingAddresses {
                    timestamp: timestamp1,
                },
            );
            manager.connections.insert(addr, conn);
            let conn2 = Connection::new_with_state(
                ConnectionConfig {
                    address_entry: AddressEntry::Seed(addr2),
                    handle: task::spawn(async {}),
                    writer,
                },
                ConnectionState::AwaitingAddresses {
                    timestamp: timestamp2,
                },
            );
            manager.connections.insert(addr2, conn2);
            manager.flag_seed_addr_retrieval_timeouts();
            let conn = manager
                .get_connection(&addr)
                .expect("The connection should be there");
            assert!(matches!(
                conn.state(),
                ConnectionState::AdapterDiscarded { .. }
            ));

            let conn = manager
                .get_connection(&addr2)
                .expect("The connection should be there");
            assert!(matches!(
                conn.state(),
                ConnectionState::AwaitingAddresses { .. }
            ));

            manager.reap_disconnected();
            // Connection 1 has been removed as expected
            let result = manager.get_connection(&addr);
            assert!(result.is_err());
        });
    }

    /// This test ensures that the idle function disconnects all connections and reaps the
    /// connections from the `ConnectionManager.connections` field.
    #[test]
    fn test_make_idle() {
        let runtime = tokio::runtime::Runtime::new().expect("runtime err");
        let addr = SocketAddr::from_str("127.0.0.1:8333").expect("invalid address");
        let addr2 = SocketAddr::from_str("192.168.1.1:8333").expect("invalid address");
        let config = ConfigBuilder::new()
            .with_dns_seeds(vec![String::from("127.0.0.1")])
            .build();
        let mut manager = ConnectionManager::new(&config, make_logger()).expect("invalid init");
        let timestamp1 = SystemTime::now() - Duration::from_secs(SEED_ADDR_RETRIEVED_TIMEOUT_SECS);
        let timestamp2 = SystemTime::now() + Duration::from_secs(SEED_ADDR_RETRIEVED_TIMEOUT_SECS);
        let (writer, _) = unbounded_channel();
        runtime.block_on(async {
            let conn = Connection::new_with_state(
                ConnectionConfig {
                    address_entry: AddressEntry::Seed(addr),
                    handle: task::spawn(async {}),
                    writer: writer.clone(),
                },
                ConnectionState::AwaitingAddresses {
                    timestamp: timestamp1,
                },
            );
            manager.connections.insert(addr, conn);
            let conn2 = Connection::new_with_state(
                ConnectionConfig {
                    address_entry: AddressEntry::Seed(addr2),
                    handle: task::spawn(async {}),
                    writer,
                },
                ConnectionState::HandshakeComplete {
                    timestamp: timestamp2,
                },
            );
            manager.connections.insert(addr2, conn2);

            manager.make_idle();
            assert!(manager.connections.is_empty());
        });
    }
}
