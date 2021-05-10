//! Defines `ConnectionEndpoint` as a URL.
use std::{
    convert::TryFrom,
    fmt::Display,
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

use serde::{de, Deserialize, Deserializer, Serialize};
use strum_macros::Display;
use thiserror::Error;
use url::{Host, Url};

use ic_protobuf::registry::node::v1::{
    connection_endpoint::Protocol as pbProtocol, ConnectionEndpoint as pbConnectionEndpoint,
};

#[derive(Debug, Display, Eq, PartialEq)]
pub enum Protocol {
    #[strum(serialize = "http")]
    Http1,
    #[strum(serialize = "https")]
    Http1Tls13,
    #[strum(serialize = "org.dfinity.p2p1")]
    P2p1Tls13,
}

impl From<&pbProtocol> for Protocol {
    fn from(pb: &pbProtocol) -> Self {
        match pb {
            pbProtocol::Unspecified => Protocol::Http1,
            pbProtocol::Http1 => Protocol::Http1,
            pbProtocol::Http1Tls13 => Protocol::Http1Tls13,
            pbProtocol::P2p1Tls13 => Protocol::P2p1Tls13,
        }
    }
}

/// An endpoint is completely defined by a URL.
///
/// Protobuf encoding is proto:registry.node.v1.ConnectionEndpoint.
///
/// An endpoint has at least three pieces of information associated with it:
///  - An IP address
///  - A port
///  - The (application layer) protocol served on that endpoint
///
/// We can use URIs to encode all of the above information in the
/// `ConnectionEndpoint`.
///
/// E.g. for endpoints that use HTTP or HTTPS this would result in:
/// ```text
///    http://w.x.y.z:port
///    https://[w::x::..::y::z]:port
/// ```
///
/// For endpoints that use custom protocols (e.g. P2P), we can define a custom
/// URI scheme as per https://tools.ietf.org/html/rfc7595#section-3.8.
///
/// For example:
/// ```text
///     org.dfinity.p2p1://w.x.y.z:port
/// ```
///
/// Any additional parameters required by the endpoint can be passed
/// in as URI parameters after the "?", e.g.
/// ```text
///    org.dfinity.p2p1://w.x.y.z:port?flow_tag=1234
/// ```
//
// Note: "org.dfinity" can be changed once the Internet Computer has its own domain or set of
// domains.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct ConnectionEndpoint {
    // TODO(O4-44): Might want an EndpointUrl type that wraps the Url and adds
    // specific flags for options we support (e.g., tls_version), and then
    // generates the URL string with the correct parameter values.
    //
    // There's deliberately no access to the internal URL, to prevent changing
    // aspects of it that would make an invalid endpoint.
    url: Url,
}

impl Display for ConnectionEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.url.fmt(f)
    }
}

impl From<ConnectionEndpoint> for String {
    fn from(connection_endpoint: ConnectionEndpoint) -> Self {
        connection_endpoint.to_string()
    }
}

impl From<ConnectionEndpoint> for Url {
    fn from(connection_endpoint: ConnectionEndpoint) -> Self {
        connection_endpoint.url
    }
}

impl From<SocketAddr> for ConnectionEndpoint {
    /// Convert SocketAddr to ConnectionEndpoint by assuming that the protocol
    /// is always "http". This is consistent with how the --nodes flag in
    /// ic-prep handled endpoints.
    // TODO(OR4-49): This should eventually be removed, and we shouldn't be
    // able to create endpoints without a protocol.
    fn from(socket_addr: SocketAddr) -> Self {
        Self {
            url: Url::parse(&format!(
                "http://{}",
                match socket_addr {
                    SocketAddr::V4(sa) => format!("{}", sa),
                    SocketAddr::V6(sa) => format!("{}", sa),
                }
            ))
            .expect("can't fail"),
        }
    }
}

impl From<&ConnectionEndpoint> for SocketAddr {
    fn from(connection_endpoint: &ConnectionEndpoint) -> Self {
        // A valid ConnectionEndpoint always has a known port and can be
        // converted to exactly one SocketAddr.
        connection_endpoint
            .url
            .socket_addrs(|| None)
            .expect("can't fail")[0]
    }
}

impl From<&ConnectionEndpoint> for Protocol {
    fn from(connection_endpoint: &ConnectionEndpoint) -> Self {
        match connection_endpoint.url.scheme() {
            "http" => Protocol::Http1,
            "https" => Protocol::Http1Tls13,
            "org.dfinity.p2p1" => Protocol::P2p1Tls13,
            // Unreachable because everything that constructs a ConnectionEndpoint
            // checks for valid protocols
            _ => unreachable!(),
        }
    }
}

impl TryFrom<Url> for ConnectionEndpoint {
    type Error = ConnectionEndpointTryFromError;

    fn try_from(url: Url) -> Result<Self, Self::Error> {
        let protocol = match url.scheme().as_ref() {
            "http" => Ok(pbProtocol::Http1),
            "https" => Ok(pbProtocol::Http1Tls13),
            // Using 'org.dfinity' as the protocol domain as per https://tools.ietf.org/html/rfc7595#section-3.8.
            // This can be changed once the Internet Computer has its own domain or set of
            // domains.
            "org.dfinity.p2p1" => Ok(pbProtocol::P2p1Tls13),
            scheme => Err(ConnectionEndpointTryFromError::InvalidScheme {
                scheme: scheme.to_string(),
            }),
        }?;

        let (host, host_str) = match url.host() {
            Some(host) => Ok((host, url.host_str().expect("can't fail"))),
            None => Err(ConnectionEndpointTryFromError::MissingHost { url: url.clone() }),
        }?;

        // For the moment the host part should always be an IP address. `uri`
        // can check this, but this only works for "special" URI schemes (see
        // https://url.spec.whatwg.org/#special-scheme).
        //
        // org.dfinity.p2p1 is *not* a special scheme, so the host portion
        // will parse as a domain, not an IP address, but only if it's an IPv4
        // address. If it's an IPv6 address it parses just fine. We need to
        // check it's an IPv4 address ourselves. See also https://github.com/servo/rust-url/issues/606
        match protocol {
            pbProtocol::Http1 | pbProtocol::Http1Tls13 => {
                if let Host::Domain(domain) = host {
                    return Err(ConnectionEndpointTryFromError::HostIsNotIpAddr {
                        url: url.clone(),
                        host: domain.to_string(),
                    });
                };
            }
            pbProtocol::P2p1Tls13 => {
                if let Host::Domain(host_or_ipv4) = host {
                    if host_or_ipv4.parse::<IpAddr>().is_err() {
                        return Err(ConnectionEndpointTryFromError::HostIsNotIpAddr {
                            url: url.clone(),
                            host: host_str.to_string(),
                        });
                    }
                }
            }
            _ => unreachable!(),
        }

        // http/https have default ports, other protocols don't, so if there's
        // no port included then it's an error.
        if url.port_or_known_default().is_none() {
            return Err(ConnectionEndpointTryFromError::MissingPort { url: url.clone() });
        };

        Ok(Self { url })
    }
}

/// Errors that can occur when converting from the protobuf encoding to the
/// `ConnectionEndpoint` type.
#[derive(Error, Debug, Clone, Serialize)]
pub enum ConnectionEndpointTryFromProtoError {
    #[error("invalid scheme for endpoint: {scheme}")]
    InvalidScheme { scheme: String },

    #[error("port does not convert to u16: {port}")]
    InvalidPort { port: String },

    #[error("IP address does not parse: {ip_addr}")]
    InvalidIpAddr { ip_addr: String },

    #[error("final url does not parse: {source}")]
    InvalidUrl {
        source: ConnectionEndpointTryFromStringError,
    },
}

impl TryFrom<pbConnectionEndpoint> for ConnectionEndpoint {
    type Error = ConnectionEndpointTryFromProtoError;

    fn try_from(pb: pbConnectionEndpoint) -> Result<Self, Self::Error> {
        let protocol: &str = match pb.protocol() {
            pbProtocol::Http1 => Ok("http"),
            pbProtocol::Http1Tls13 => Ok("https"),
            pbProtocol::P2p1Tls13 => Ok("org.dfinity.p2p1"),
            // TODO(OR4-49): This should actually return
            // Err(Self::Error::InvalidScheme { scheme: "unspecified".to_string()})
            // if the protocol is unspecified. Assume http until other code that
            // has this assumption is cleaned up.
            pbProtocol::Unspecified => Ok("http"),
        }?;

        let port = u16::try_from(pb.port).map_err(|_| Self::Error::InvalidPort {
            port: pb.port.to_string(),
        })?;

        let socket_addr = SocketAddr::new(
            pb.ip_addr
                .parse::<IpAddr>()
                .map_err(|_| Self::Error::InvalidIpAddr {
                    ip_addr: pb.ip_addr,
                })?,
            port,
        );
        let url_str = format!("{}://{}", protocol, socket_addr);
        let connection_endpoint = url_str
            .parse()
            .map_err(|source| Self::Error::InvalidUrl { source })?;
        Ok(connection_endpoint)
    }
}

/// Errors that can occur when converting from a string to a
/// [`ConnectionEndpoint`].
#[derive(Error, Debug, Clone, Serialize)]
pub enum ConnectionEndpointTryFromStringError {
    #[error("string {url} does not parse as url: {error}")]
    InvalidUrl {
        url: String,
        // url::ParseError does not implement Serialize
        error: String,
    },

    #[error("invalid scheme for endpoint: {scheme}")]
    InvalidScheme { scheme: String },
}

impl FromStr for ConnectionEndpoint {
    type Err = ConnectionEndpointTryFromStringError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Try parsing as a URL first, and if that fails, fall back to parsing
        // as a SocketAddr
        match Url::parse(&s) {
            Ok(url) => {
                // URL was syntactically correct but may be an unsupported
                // protocol
                match url.scheme().as_ref() {
                    "http" => Ok(pbProtocol::Http1),
                    "https" => Ok(pbProtocol::Http1Tls13),
                    "org.dfinity.p2p1" => Ok(pbProtocol::P2p1Tls13),
                    scheme => Err(ConnectionEndpointTryFromStringError::InvalidScheme {
                        scheme: scheme.to_string(),
                    }),
                }?;

                Ok(Self { url })
            }
            Err(source) => match &s.parse::<SocketAddr>() {
                Ok(socket_addr) => Ok(ConnectionEndpoint::from(*socket_addr)),
                // If it failed return an error indicating that it's an invalid
                // URL, as a strong hint that the user should be providing URLs
                // not socket addresses.
                Err(_) => Err(Self::Err::InvalidUrl {
                    url: s.to_string(),
                    error: source.to_string(),
                }),
            },
        }
    }
}

impl<'a> TryFrom<&'a str> for ConnectionEndpoint {
    type Error = <ConnectionEndpoint as FromStr>::Err;
    fn try_from(s: &'a str) -> Result<ConnectionEndpoint, Self::Error> {
        ConnectionEndpoint::from_str(s)
    }
}

// Deserialize using the FromStr implementation. This can't be done with a
// serde attribute on the field, as `from_str` does not have the correct
// signature.
impl<'de> Deserialize<'de> for ConnectionEndpoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        FromStr::from_str(&s).map_err(de::Error::custom)
    }
}

/// Errors that can occur when converting from a URL to a
/// [`ConnectionEndpoint`].
#[derive(Error, Debug)]
pub enum ConnectionEndpointTryFromError {
    #[error("invalid scheme for endpoint: {scheme}")]
    InvalidScheme { scheme: String },

    #[error("endpoint URL does not have a host component: {url}")]
    MissingHost { url: Url },

    #[error("endpoint host component {host} is not an IP address: {url}")]
    HostIsNotIpAddr { url: Url, host: String },

    #[error("endpoint URL does not have a port component: {url}")]
    MissingPort { url: Url },

    #[error("port does not convert to u16: {port}")]
    InvalidPort { port: String },

    #[error("IP address does not parse: {ip_addr}")]
    InvalidIpAddr { ip_addr: String },

    #[error("final url does not parse: {url}: {source}")]
    InvalidUrl {
        url: String,
        source: url::ParseError,
    },
}

impl From<&ConnectionEndpoint> for pbConnectionEndpoint {
    fn from(ce: &ConnectionEndpoint) -> Self {
        let protocol = match ce.url.scheme().as_ref() {
            "http" => pbProtocol::Http1,
            "https" => pbProtocol::Http1Tls13,
            "org.dfinity.p2p1" => pbProtocol::P2p1Tls13,
            _ => panic!("can't fail, protocol is checked when the struct was created"),
        };

        let ip_addr = match ce.url.host() {
            Some(host) => match host {
                Host::Domain(domain) => domain
                    .parse::<IpAddr>()
                    .expect("can't fail, checked when struct was created"),
                Host::Ipv4(ip) => IpAddr::from(ip),
                Host::Ipv6(ip) => IpAddr::from(ip),
            },
            None => unreachable!("can't fail, checked when struct was created"),
        };

        let port = ce
            .url
            .port_or_known_default()
            .expect("can't fail, post was checked when the struct was created");

        pbConnectionEndpoint {
            ip_addr: ip_addr.to_string(),
            port: port as u32,
            protocol: protocol as i32,
        }
    }
}

#[cfg(test)]
mod connection_endpoint_test {
    use super::*;
    use assert_matches::assert_matches;
    use pretty_assertions::assert_eq;

    /// Displaying a ConnectionEndpoint should just show the URL
    #[test]
    fn display_ok() {
        let want = "http://1.2.3.4:8080/";

        let ce = ConnectionEndpoint {
            url: Url::parse(want).unwrap(),
        };

        assert_eq!(ce.to_string(), want);
    }

    /// Converting from a V4 SocketAddr should work, and the protocol should be
    /// `http`
    #[test]
    fn from_socket_addr_v4_ok() {
        let want = "http://1.2.3.4:8080/";
        let socket_addr = "1.2.3.4:8080".parse::<SocketAddr>().unwrap();
        let ce = ConnectionEndpoint::from(socket_addr);
        assert_eq!(ce.to_string(), want);
    }

    /// Converting from a V6 SocketAddr with a port should work, and the
    /// protocol should be `http`
    #[test]
    fn from_socket_addr_v6_ok() {
        let want = "http://[2001:db8::1]:8080/";
        let socket_addr = "[2001:db8::1]:8080".parse::<SocketAddr>().unwrap();
        let ce = ConnectionEndpoint::from(socket_addr);
        assert_eq!(ce.to_string(), want);
    }

    /// Converting from a http Url should work, and should retain the original
    /// protocol
    #[test]
    fn try_from_url_http_ok() {
        let want = "http://1.2.3.4:8080/";
        let url = "http://1.2.3.4:8080".parse::<Url>().unwrap();
        let ce = ConnectionEndpoint::try_from(url).unwrap();
        assert_eq!(ce.to_string(), want);
    }

    /// Converting from a p2p1 Url should work, and should retain the original
    /// protocol
    #[test]
    fn from_url_p2p1_ok() {
        let want = "org.dfinity.p2p1://1.2.3.4:1234";
        let url = "org.dfinity.p2p1://1.2.3.4:1234".parse::<Url>().unwrap();
        let ce = ConnectionEndpoint::try_from(url).unwrap();
        assert_eq!(ce.to_string(), want);
    }

    /// Converting from a p2p1 Url with an unnecessary path should work, and
    /// the path should be retained.
    #[test]
    fn from_url_p2p1_path_ok() {
        let want = "org.dfinity.p2p1://1.2.3.4:1234/can_be_anything";
        let url = "org.dfinity.p2p1://1.2.3.4:1234/can_be_anything"
            .parse::<Url>()
            .unwrap();
        let ce = ConnectionEndpoint::try_from(url).unwrap();
        assert_eq!(ce.to_string(), want);
    }

    /// Converting from a p2p1 Url with an IPv6 address should work.
    #[test]
    fn from_url_p2p1_addr_v6_ok() {
        let want = "org.dfinity.p2p1://[2607:fb58:9005:42:5054:ffff:fe0c:1d05]:4100";
        let url = "org.dfinity.p2p1://[2607:fb58:9005:42:5054:ffff:fe0c:1d05]:4100"
            .parse::<Url>()
            .unwrap();
        let ce = ConnectionEndpoint::try_from(url).unwrap();
        assert_eq!(ce.to_string(), want);
    }

    /// p2p1 URLs *must* include a port number as there is no default port
    #[test]
    fn from_url_p2p1_no_port_fail() {
        let url = "org.dfinity.p2p1://1.2.3.4".parse::<Url>().unwrap();
        assert_matches!(
            ConnectionEndpoint::try_from(url),
            Err(ConnectionEndpointTryFromError::MissingPort { .. })
        );
    }

    /// URL hosts must by IP addresses, not domain names
    #[test]
    fn from_url_domain_fail() {
        let urls: Vec<Url> = vec![
            "http://example.com".parse().unwrap(),
            "org.dfinity.p2p1://example.com:1234".parse().unwrap(),
        ];

        for url in urls.iter() {
            assert_matches!(
                ConnectionEndpoint::try_from(url.clone()),
                Err(ConnectionEndpointTryFromError::HostIsNotIpAddr { .. })
            );
        }
    }

    #[test]
    fn from_url_scheme_fail() {
        // Valid URLs, but invalid schemes for a ConnectionEndpoint
        let urls: Vec<Url> = vec![
            "ftp://127.0.0.1:80".parse().unwrap(),
            "file:///path/to/file".parse().unwrap(),
            "not-a-scheme:///some/thing".parse().unwrap(),
            "data:text/plain,Hello?World#".parse().unwrap(),
        ];

        for url in urls.iter() {
            assert_matches!(
                ConnectionEndpoint::try_from(url.clone()),
                Err(ConnectionEndpointTryFromError::InvalidScheme { .. })
            );
        }
    }
}

#[cfg(test)]
mod pb_connection_endpoint_test {
    use ic_protobuf::registry::node::v1::connection_endpoint::Protocol;

    use super::*;

    use pretty_assertions::assert_eq;

    /// Check that ConnectionEndpoints can roundtrip through a conversion in
    /// and out of a pbConnectionEndpoint.
    #[test]
    fn roundtrip() {
        /// Data for a single test
        struct TestData<'a> {
            /// URL-as-string representation of the endpoint
            source: &'a str,
            /// The pbConnectionEndpoint representation
            pb_connection_endpoint: pbConnectionEndpoint,
        }

        // Collection of valid endpoints, and the pbConnectionEndpoint they
        // should convert to.
        let tests = vec![
            TestData {
                // Basic endpoint, uses the default port
                source: "http://1.2.3.4",
                pb_connection_endpoint: pbConnectionEndpoint {
                    protocol: Protocol::Http1 as i32,
                    ip_addr: "1.2.3.4".to_string(),
                    port: 80,
                },
            },
            TestData {
                // Different port
                source: "http://1.2.3.4:8080",
                pb_connection_endpoint: pbConnectionEndpoint {
                    protocol: Protocol::Http1 as i32,
                    ip_addr: "1.2.3.4".to_string(),
                    port: 8080,
                },
            },
            TestData {
                // HTTPS
                source: "https://1.2.3.4:8080",
                pb_connection_endpoint: pbConnectionEndpoint {
                    protocol: Protocol::Http1Tls13 as i32,
                    ip_addr: "1.2.3.4".to_string(),
                    port: 8080,
                },
            },
            TestData {
                // IPv6. Note that `ip_addr` *is not* expected to be enclosed in
                // `[` and `]`, per https://tools.ietf.org/html/rfc5952#section-4
                source: "http://[2607:fb58:9005:42:5054:ffff:fe0c:1d05]:4100",
                pb_connection_endpoint: pbConnectionEndpoint {
                    protocol: Protocol::Http1 as i32,
                    ip_addr: "2607:fb58:9005:42:5054:ffff:fe0c:1d05".to_string(),
                    port: 4100,
                },
            },
            TestData {
                // p2p, ipv4
                source: "org.dfinity.p2p1://1.2.3.4:4100",
                pb_connection_endpoint: pbConnectionEndpoint {
                    protocol: Protocol::P2p1Tls13 as i32,
                    ip_addr: "1.2.3.4".to_string(),
                    port: 4100,
                },
            },
            TestData {
                // p2p, ipv6. Note that `ip_addr` *is not* expected to be enclosed in
                // `[` and `]`, per https://tools.ietf.org/html/rfc5952#section-4
                source: "org.dfinity.p2p1://[2607:fb58:9005:42:5054:ffff:fe0c:1d05]:4100",
                pb_connection_endpoint: pbConnectionEndpoint {
                    protocol: Protocol::P2p1Tls13 as i32,
                    ip_addr: "2607:fb58:9005:42:5054:ffff:fe0c:1d05".to_string(),
                    port: 4100,
                },
            },
        ];

        for test in tests {
            let connection_endpoint = ConnectionEndpoint::try_from(test.source).unwrap();
            let pb_connection_endpoint = pbConnectionEndpoint::from(&connection_endpoint);

            // Check that proto struct has the correct contents
            assert_eq!(test.pb_connection_endpoint, pb_connection_endpoint);

            // Check that the proto struct can be converted back without error
            let rt_connection_endpoint =
                ConnectionEndpoint::try_from(pb_connection_endpoint).unwrap();

            // Check that the two ConnectionEndpoints are the same
            assert_eq!(connection_endpoint, rt_connection_endpoint);
        }
    }
}
