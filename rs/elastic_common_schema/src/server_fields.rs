//! From [Source Fields]:
//!
//! Source fields describe details about the source of a packet/event.
//!
//! Source fields are usually populated in conjunction with destination fields.
//!
//! [Source Fields]: https://www.elastic.co/guide/en/ecs/current/ecs-source.html

use std::net::{IpAddr, SocketAddr};

use serde::Serialize;
use slog_derive::SerdeValue;

use crate::Long;
use crate::User;
use crate::{AutonomousSystem, SetTo};
use crate::{Geo, Port};

#[derive(Clone, Debug, Default, Serialize, SerdeValue)]
pub struct Server {
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
    pub nat: Option<SourceNat>,
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
pub struct SourceNat {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<Long>,
}

impl SetTo<IpAddr> for Option<Server> {
    fn set(&mut self, ip: IpAddr) {
        let server = self.get_or_insert(Server::default());
        server.address = Some(ip.to_string());
        server.ip = Some(ip);
        server.port = None;
    }
}

impl SetTo<SocketAddr> for Option<Server> {
    fn set(&mut self, socket_addr: SocketAddr) {
        let server = self.get_or_insert(Server::default());
        server.address = Some(socket_addr.ip().to_string());
        server.ip = Some(socket_addr.ip());
        server.port = Some(socket_addr.port().into());
    }
}

impl SetTo<Port> for Option<Server> {
    fn set(&mut self, port: Port) {
        let server = self.get_or_insert(Server::default());
        server.port = Some(port);
    }
}
