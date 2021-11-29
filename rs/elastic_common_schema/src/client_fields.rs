//! From [Client Fields]:
//!
//! A client is defined as the initiator of a network connection for events
//! regarding sessions, connections, or bidirectional flow records.
//!
//! For TCP events, the client is the initiator of the TCP connection that sends
//! the SYN packet(s). For other protocols, the client is generally the
//! initiator or requestor in the network transaction. Some systems use the term
//! "originator" to refer the client in TCP connections. The client fields
//! describe details about the system acting as the client in the network event.
//! Client fields are usually populated in conjunction with server fields.
//! Client fields are generally not populated for packet-level events.
//!
//! Client / server representations can add semantic context to an exchange,
//! which is helpful to visualize the data in certain situations. If your
//! context falls in that category, you should still ensure that source and
//! destination are filled appropriately.
//!
//! [Client Fields]: https://www.elastic.co/guide/en/ecs/current/ecs-client.html

use std::net::{IpAddr, SocketAddr};

use serde::Serialize;
use slog_derive::SerdeValue;

use crate::Long;
use crate::User;
use crate::{AutonomousSystem, SetTo};
use crate::{Geo, Port};

#[derive(Clone, Debug, Default, Serialize, SerdeValue)]
pub struct Client {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "as")]
    pub autonomous_system: Option<AutonomousSystem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<Long>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geo: Option<Geo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nat: Option<ClientNat>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packets: Option<Long>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<Port>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registered_domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_level_domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<User>,
}

#[derive(Clone, Debug, Default, Serialize, SerdeValue)]
pub struct ClientNat {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<Long>,
}

impl SetTo<IpAddr> for Option<Client> {
    fn set(&mut self, ip: IpAddr) {
        let client = self.get_or_insert(Client::default());
        client.address = Some(ip.to_string());
        client.ip = Some(ip);
        client.port = None;
    }
}

impl SetTo<SocketAddr> for Option<Client> {
    fn set(&mut self, socket_addr: SocketAddr) {
        let client = self.get_or_insert(Client::default());
        client.address = Some(socket_addr.ip().to_string());
        client.ip = Some(socket_addr.ip());
        client.port = Some(socket_addr.port().into());
    }
}

impl SetTo<Port> for Option<Client> {
    fn set(&mut self, port: Port) {
        let client = self.get_or_insert(Client::default());
        client.port = Some(port);
    }
}
