//! From [Destination Fields]:
//!
//! Destination fields describe details about the source of a packet/event.
//!
//! Destination fields are usually populated in conjunction with source fields.
//!
//! [Source Fields]: https://www.elastic.co/guide/en/ecs/current/ecs-destination.html

use std::net::{IpAddr, SocketAddr};

use serde::Serialize;
use slog_derive::SerdeValue;

use crate::Long;
use crate::{AutonomousSystem, SetTo};
use crate::{Geo, Port};

#[derive(Clone, Debug, Default, Serialize, SerdeValue)]
pub struct Destination {
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "as")]
    autonomous_system: Option<AutonomousSystem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes: Option<Long>,
    #[serde(skip_serializing_if = "Option::is_none")]
    domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    geo: Option<Geo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip: Option<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nat: Option<DestinationNat>,
    #[serde(skip_serializing_if = "Option::is_none")]
    packets: Option<Long>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<Long>,
    #[serde(skip_serializing_if = "Option::is_none")]
    registered_domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    top_level_domain: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, SerdeValue)]
pub struct DestinationNat {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<Long>,
}

impl SetTo<IpAddr> for Option<Destination> {
    fn set(&mut self, ip: IpAddr) {
        let destination = self.get_or_insert(Destination::default());
        destination.address = Some(ip.to_string());
        destination.ip = Some(ip);
        destination.port = None;
    }
}

impl SetTo<SocketAddr> for Option<Destination> {
    fn set(&mut self, socket_addr: SocketAddr) {
        let destination = self.get_or_insert(Destination::default());
        destination.address = Some(socket_addr.ip().to_string());
        destination.ip = Some(socket_addr.ip());
        destination.port = Some(socket_addr.port().into());
    }
}

impl SetTo<Port> for Option<Destination> {
    fn set(&mut self, port: Port) {
        let destination = self.get_or_insert(Destination::default());
        destination.port = Some(port);
    }
}
