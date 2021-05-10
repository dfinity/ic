use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, path::PathBuf};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Exporter {
    /// Log metrics at `TRACE` level every 30 seconds.
    Log,
    /// Expose Prometheus metrics on the specified address.
    Http(SocketAddr),
    /// Dump metrics to the given file on shutdown.
    File(PathBuf),
}

impl Default for Exporter {
    fn default() -> Self {
        Exporter::Log
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Config {
    pub exporter: Exporter,
    /// Clients X509 certificate used for establishing TLS protocol. The field
    /// is base64 encoded DER certificate.
    pub clients_x509_cert: Option<X509PublicKeyCert>,
}
