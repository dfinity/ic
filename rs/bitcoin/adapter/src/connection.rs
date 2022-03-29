use crate::addressbook::AddressEntry;
use bitcoin::network::message::NetworkMessage;
use std::time::{Duration, SystemTime};
use thiserror::Error;
use tokio::{sync::mpsc::UnboundedSender, task::JoinHandle};

/// This const represents how often a ping should be sent.
const PING_INTERVAL: Duration = Duration::from_secs(120);
/// This const represents how long the adapter should wait for a pong message.
const PING_TIMEOUT: Duration = Duration::from_secs(30);

/// This enum is used to represent possible errors seen when utilizing
/// the [Connection](crate::connection::Connection) struct.
#[derive(Debug, Error)]
pub enum ConnectionError {
    /// This variant is used to indicate that the stream can no longer be communicated
    /// with. This is likely to due the task ending abruptly due to an unhandled stream
    /// error.
    #[error("Can no longer communicate with stream.")]
    SendToStreamError,
}

/// This type is simply for convenience to wrap the result type with the
/// [ConnectionError](crate::connection::ConnectionError);
pub type ConnectionResult<T> = Result<T, ConnectionError>;

/// This struct is used to initialize a [Connection](crate::connection::Connection).
pub struct ConnectionConfig {
    /// This field contains the address of the connection.
    pub address_entry: AddressEntry,
    /// This field contains the handle to the task that is used for managing the
    /// stream.
    pub handle: JoinHandle<()>,
    /// This field is used to send network messages to the related stream.
    pub writer: UnboundedSender<NetworkMessage>,
}

/// This enum represents the various states that the connection could be in.
#[derive(Debug, Clone)]
pub enum ConnectionState {
    /// This variant represents that the connection has not yet been connected.
    Initializing {
        /// This field represents when the connection state was changed to this value.
        timestamp: SystemTime,
    },
    /// This variant represents that the connection is now connected with the stream.
    Connected {
        /// This field represents when the connection state was changed to this value.
        timestamp: SystemTime,
    },
    /// This variant represents that the version handshake has been completed.
    HandshakeComplete {
        /// This field represents when the connection state was changed to this value.
        timestamp: SystemTime,
    },
    /// This variant represents that the adapter has discarded the connection
    /// due to bad behavior.
    AdapterDiscarded {
        /// This field represents when the connection state was changed to this value.
        timestamp: SystemTime,
    },
    /// This variant represents that the connection has been dropped.
    NodeDisconnected {
        /// This field represents when the connection state was changed to this value.
        timestamp: SystemTime,
    },
    /// The connection has sent a `getaddr` message and is now waiting for a response.
    AwaitingAddresses {
        /// The timestamp when the state change occurred.
        timestamp: SystemTime,
    },
}

/// This enum is used to track the status of wether or not
/// a ping needs to be sent to the connected BTC node.
/// The ping is used to maintain whether or not the connection is stable.
#[derive(Clone, Debug)]
pub enum PingState {
    /// This variant represents that a ping has been sent and the connection is
    /// now expecting a pong message to be received.
    ExpectingPong {
        /// This field is when the ping was sent.
        ping_sent_at: SystemTime,
        /// This field contains the Nonce sent with the initial ping. Pong must contain the nonce.
        nonce: u64,
    },
    /// This variant represents that the connection is not waiting on a pong
    /// message.
    Idle { last_pong_at: SystemTime },
}

/// This struct is used to manage a connection with a Bitcoin node.
#[derive(Debug)]
pub struct Connection {
    /// This field is to store the BTC node address that is accessed by
    /// this connection.
    address_entry: AddressEntry,
    /// This field contains the handle to the task that is used for managing the
    /// stream.
    handle: JoinHandle<()>,
    /// This field is used to track the current state of the connection.
    state: ConnectionState,
    /// This field is used to send network messages to the related stream.
    writer: UnboundedSender<NetworkMessage>,
    /// This field is used to track the current ping status.
    ping_state: PingState,
}

impl Connection {
    /// This function creates a new connection that will be used to manage a
    /// connection to the BTC network.
    pub fn new(config: ConnectionConfig) -> Self {
        let ConnectionConfig {
            address_entry,
            handle,
            writer,
        } = config;

        let timestamp = SystemTime::now();

        Self {
            address_entry,
            handle,
            state: ConnectionState::Initializing { timestamp },
            writer,
            ping_state: PingState::Idle {
                last_pong_at: timestamp,
            },
        }
    }

    /// This function sends a network message to the connected BTC node.
    pub fn send(&mut self, payload: NetworkMessage) -> ConnectionResult<()> {
        self.writer
            .send(payload)
            .map_err(|_| ConnectionError::SendToStreamError)
    }

    /// This function retrieves the address field for public use.
    pub fn address_entry(&self) -> &AddressEntry {
        &self.address_entry
    }

    /// This function used to determine if a connection is a seed address. This is
    /// used to determine if the the service field needs to be validated when looking
    /// at the version.
    pub fn is_seed(&self) -> bool {
        matches!(self.address_entry, AddressEntry::Seed(_))
    }

    /// This function is used to get the current state of the connection.
    pub fn state(&self) -> &ConnectionState {
        &self.state
    }

    /// This function is used to get the current ping state of the connection.
    pub fn ping_state(&self) -> &PingState {
        &self.ping_state
    }

    /// This function is used to set the pong state to [PingState::ExpectingPong](PingState::ExpectingPong).
    pub fn expect_pong(&mut self, nonce: u64) {
        self.ping_state = PingState::ExpectingPong {
            ping_sent_at: SystemTime::now(),
            nonce,
        };
    }

    /// This function is used to update the ping state when a BTC node responds
    /// to the sent `ping` message with the `pong` message.
    pub fn idle(&mut self) {
        self.ping_state = PingState::Idle {
            last_pong_at: SystemTime::now(),
        };
    }

    /// This function is used to set a connection to a connected state,
    /// which is used to monitor the version handshake.
    pub fn connected(&mut self) {
        self.state = ConnectionState::Connected {
            timestamp: SystemTime::now(),
        };
    }

    pub fn completed_handshake(&mut self) {
        self.state = ConnectionState::HandshakeComplete {
            timestamp: SystemTime::now(),
        };
    }

    /// Used to set the connections state to the AwaitingAddresses state.
    pub fn awaiting_addresses(&mut self) {
        self.state = ConnectionState::AwaitingAddresses {
            timestamp: SystemTime::now(),
        };
    }

    /// This function is used to set a connection to a disconnected state,
    /// which will cause the ConnectionManager to clean up this connection.
    pub fn disconnect(&mut self) {
        self.state = ConnectionState::NodeDisconnected {
            timestamp: SystemTime::now(),
        };
        self.handle.abort();
    }

    /// This function is used to set a connection as discarded. The connection
    /// manager will use this to clean up the connection and remove the address
    /// from the address book.
    pub fn discard(&mut self) {
        self.state = ConnectionState::AdapterDiscarded {
            timestamp: SystemTime::now(),
        };
        self.handle.abort();
    }

    /// This function checks to see if the connection is in a disconnected state.
    pub fn is_disconnected(&self) -> bool {
        matches!(
            self.state,
            ConnectionState::NodeDisconnected { timestamp: _ }
        ) || matches!(
            self.state,
            ConnectionState::AdapterDiscarded { timestamp: _ }
        )
    }

    /// This function checks to see if the connection is available to receive messages.
    pub fn is_available(&self) -> bool {
        matches!(
            self.state,
            ConnectionState::HandshakeComplete { timestamp: _ }
        )
    }

    /// This function checks to see if the connection needs to perform a ping.
    pub fn needs_ping(&self) -> bool {
        let needs_ping = match self.ping_state {
            PingState::ExpectingPong {
                ping_sent_at: _,
                nonce: _,
            } => false,
            PingState::Idle {
                last_pong_at: last_ping_at,
            } => match last_ping_at.elapsed() {
                Ok(duration) => duration > PING_INTERVAL,
                // Somehow the connection has a system time from the future.
                // In this case, ping the connection to be on the safe side.
                Err(_) => true,
            },
        };
        needs_ping && self.is_available()
    }

    /// This function checks to see if the connection's ping has timed out.
    pub fn has_ping_timed_out(&self) -> bool {
        let timed_out = match self.ping_state {
            PingState::ExpectingPong {
                ping_sent_at,
                nonce: _,
            } => match ping_sent_at.elapsed() {
                Ok(duration) => duration > PING_TIMEOUT,
                // Somehow the connection has a system time from the future.
                // In this case, the ping should be marked as timed out.
                Err(_) => true,
            },
            PingState::Idle { last_pong_at: _ } => false,
        };
        timed_out && self.is_available()
    }
}

#[cfg(test)]
mod test {

    use std::net::SocketAddr;
    use std::str::FromStr;

    use tokio::{
        runtime::Runtime,
        sync::mpsc::{unbounded_channel, UnboundedReceiver},
    };

    use super::*;

    impl ConnectionState {
        /// This function is used to pull the timestamp from the various states.
        fn get_timestamp(&self) -> &SystemTime {
            match self {
                ConnectionState::Initializing { timestamp } => timestamp,
                ConnectionState::Connected { timestamp } => timestamp,
                ConnectionState::HandshakeComplete { timestamp } => timestamp,
                ConnectionState::AdapterDiscarded { timestamp } => timestamp,
                ConnectionState::NodeDisconnected { timestamp } => timestamp,
                ConnectionState::AwaitingAddresses { timestamp } => timestamp,
            }
        }
    }

    impl Connection {
        /// This function creates a new connection that will be used to manage a
        /// connection to the BTC network.
        pub fn new_with_state(config: ConnectionConfig, state: ConnectionState) -> Self {
            let ConnectionConfig {
                address_entry,
                handle,
                writer,
            } = config;

            let last_pong_at = *state.get_timestamp();

            Self {
                address_entry,
                handle,
                state,
                writer,
                ping_state: PingState::Idle { last_pong_at },
            }
        }
    }

    fn make_connection_and_receiver(
        runtime: &Runtime,
    ) -> (Connection, UnboundedReceiver<NetworkMessage>) {
        let addr = SocketAddr::from_str("127.0.0.1:8333").expect("invalid string");
        let address_entry = AddressEntry::Discovered(addr);
        let handle = runtime.spawn(async {});
        let (writer, reader) = unbounded_channel();
        (
            Connection::new(ConnectionConfig {
                address_entry,
                handle,
                writer,
            }),
            reader,
        )
    }

    #[test]
    fn test_connection_is_disconnected() {
        let runtime = tokio::runtime::Runtime::new().expect("runtime err");
        let (mut conn, _) = make_connection_and_receiver(&runtime);
        assert!(!conn.is_disconnected());
        conn.state = ConnectionState::NodeDisconnected {
            timestamp: SystemTime::now(),
        };
        assert!(conn.is_disconnected());
    }

    #[test]
    fn test_connection_is_available() {
        let runtime = tokio::runtime::Runtime::new().expect("runtime err");
        let (mut conn, _) = make_connection_and_receiver(&runtime);
        assert!(!conn.is_available());
        conn.state = ConnectionState::HandshakeComplete {
            timestamp: SystemTime::now(),
        };
        assert!(conn.is_available());
    }

    #[test]
    fn disconnect() {
        let runtime = tokio::runtime::Runtime::new().expect("runtime err");
        let (mut conn, _) = make_connection_and_receiver(&runtime);
        conn.disconnect();
        assert!(matches!(
            conn.state,
            ConnectionState::NodeDisconnected { timestamp: _ }
        ));
    }
}
