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
pub struct Source {
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
    pub nat: Option<ServerNat>,
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
pub struct ServerNat {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<Long>,
}

impl SetTo<IpAddr> for Option<Source> {
    fn set(&mut self, ip: IpAddr) {
        let source = self.get_or_insert(Source::default());
        source.address = Some(ip.to_string());
        source.ip = Some(ip);
        source.port = None;
    }
}

impl SetTo<SocketAddr> for Option<Source> {
    fn set(&mut self, socket_addr: SocketAddr) {
        let source = self.get_or_insert(Source::default());
        source.address = Some(socket_addr.ip().to_string());
        source.ip = Some(socket_addr.ip());
        source.port = Some(socket_addr.port().into());
    }
}

impl SetTo<Port> for Option<Source> {
    fn set(&mut self, port: Port) {
        let source = self.get_or_insert(Source::default());
        source.port = Some(port);
    }
}
