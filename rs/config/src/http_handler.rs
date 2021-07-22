use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::{convert::TryFrom, net::SocketAddr};

const DEFAULT_IP_ADDR: &str = "0.0.0.0";

const DEFAULT_PORT: u16 = 8080u16;

#[derive(Debug, Clone, Serialize, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
/// The port configuration. Defaults to using port 8080.
pub enum PortConfig {
    /// Instructs the HTTP handler to use the specified port
    Port(u16),

    /// Instructs the HTTP handler to bind to any open port and report the port
    /// to the specified file.
    /// The port is written in its textual representation, no newline at the
    /// end.
    WritePortTo(PathBuf),
}

/// The external configuration that can be loaded from a configuration file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ExternalConfig {
    // We use "flatten" in order to avoid having to write:
    // ```
    // {
    //   http_handler: {
    //     port: {
    //       port: ...
    //     }
    //   }
    // }
    // ```
    // which is redundant because `port` and `write_port_to` apply only to the port
    /// DEPRECATED: Use `listen_addr` instead.
    ///
    /// Port to listen on.
    ///
    /// ```json5
    /// {
    ///   http_handler: {
    ///     port: 8080
    ///   }
    /// }
    /// ```
    /// or
    /// ```json5
    /// {
    ///   http_handler: {
    ///     write_port_to: "./path/to/file"
    ///   }
    /// }
    /// ```
    #[serde(flatten)]
    pub port: Option<PortConfig>,

    /// IP address and port to listen on
    ///
    /// ```json5
    /// {
    ///   http_handler: {
    ///     listen_addr: "127.0.0.1:8080"
    ///   }
    /// }
    /// ```
    pub listen_addr: Option<SocketAddr>,

    /// An escape hatch to allow API traffic over IPv6 if absolutely
    /// necessary.
    pub allow_ipv6_my_users_have_no_privacy: Option<bool>,

    // The root key is the public key of this Internet Computer instance.
    //
    // If set to `true`, the replica returns the public key of the current
    // subnet in the `/status` endpoint. This is only needed in development
    // instances and tests.
    //
    // In production environments, this should be set to `false` and clients
    // will have an independent trustworthy source for this data.
    //
    // NOTE: Accidentally setting this flag to `true` in production is not a
    //       major security risk for the IC, but developers should not be
    //       tempted to get the IC's root key from this insecure location.
    pub show_root_key_in_status: bool,
    // Clients X509 certificate used for establishing TLS protocol. The field
    // is base64 encoded DER certificate.
    pub clients_x509_cert: Option<String>,
}

impl Default for ExternalConfig {
    fn default() -> Self {
        Self {
            listen_addr: None,
            allow_ipv6_my_users_have_no_privacy: None,
            port: None,
            show_root_key_in_status: true,
            clients_x509_cert: None,
        }
    }
}

/// The internal configuration -- any historical warts from the external
/// configuration are removed. Anything using this struct can trust that it
/// has been validated.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// IP address and port to listen on
    pub listen_addr: SocketAddr,
    /// The path to write the listening port to
    pub port_file_path: Option<PathBuf>,
    /// True if the replica public key is returned from the `/status` endpoint
    pub show_root_key_in_status: bool,
    /// The digital certificate used by TLS.
    pub clients_x509_cert: Option<TlsPublicKeyCert>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::new(
                DEFAULT_IP_ADDR.parse().expect("can't fail"),
                DEFAULT_PORT,
            ),
            port_file_path: None,
            show_root_key_in_status: true,
            clients_x509_cert: None,
        }
    }
}

impl TryFrom<ExternalConfig> for Config {
    type Error = &'static str;

    fn try_from(ec: ExternalConfig) -> Result<Self, Self::Error> {
        let mut config = Config::default();

        config.listen_addr = match (ec.port, ec.listen_addr) {
            (None, Some(listen_addr)) => Ok(listen_addr),
            (Some(port), None) => match port {
                PortConfig::Port(port) => Ok(SocketAddr::new(
                    DEFAULT_IP_ADDR.parse().expect("can't fail"),
                    port,
                )),
                PortConfig::WritePortTo(path) => {
                    config.port_file_path = Some(path);
                    Ok(SocketAddr::new(
                        DEFAULT_IP_ADDR.parse().expect("can't fail"),
                        0,
                    ))
                }
            },
            (None, None) => Err("one of port or listen_addr must be specified"),
            (Some(PortConfig::Port(_)), Some(_)) => Err("both port and listen_addr were specified"),
            (Some(PortConfig::WritePortTo(path)), Some(listen_addr)) => {
                config.port_file_path = Some(path);
                Ok(listen_addr)
            }
        }?;

        config.show_root_key_in_status = ec.show_root_key_in_status;
        if let Some(base64_clients_x509_cert) = ec.clients_x509_cert {
            let base64_decoded_clients_x509_cert = base64::decode(&base64_clients_x509_cert)
                .map_err(|_err| "Could not decode x509 cert from base64 encoding.")?;
            config.clients_x509_cert = Some(
                TlsPublicKeyCert::new_from_der(base64_decoded_clients_x509_cert)
                    .map_err(|_err| "Could not decode x509 cert from DER encoding")?,
            );
        }
        Ok(config)
    }
}

impl TryFrom<Option<ExternalConfig>> for Config {
    type Error = &'static str;

    fn try_from(ec: Option<ExternalConfig>) -> Result<Self, Self::Error> {
        match ec {
            Some(ec) => Self::try_from(ec),
            None => Ok(Self::default()),
        }
    }
}
