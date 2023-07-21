//! Defines `ConnectionEndpoint` as a URL.
use std::{
    convert::TryFrom,
    fmt::Display,
    net::{IpAddr, SocketAddr},
};
use thiserror::Error;

use ic_protobuf::registry::node::v1::ConnectionEndpoint as pbConnectionEndpoint;

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
/// URI scheme as per `<https://tools.ietf.org/html/rfc7595#section-3.8>`.
///
/// For example:
/// ```text
///     org.internetcomputer.p2p1://w.x.y.z:port
/// ```
///
/// Any additional parameters required by the endpoint can be passed
/// in as URI parameters after the "?", e.g.
/// ```text
///    org.internetcomputer.p2p1://w.x.y.z:port?flow_tag=1234
/// ```
//
// Note: "org.dfinity" can be changed once the Internet Computer has its own domain or set of
// domains.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ConnectionEndpoint {
    // TODO(O4-44): Might want an EndpointUrl type that wraps the Url and adds
    // specific flags for options we support (e.g., tls_version), and then
    // generates the URL string with the correct parameter values.
    //
    // There's deliberately no access to the internal URL, to prevent changing
    // aspects of it that would make an invalid endpoint.
    socket_addr: SocketAddr,
}

impl Display for ConnectionEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.socket_addr.to_string().fmt(f)
    }
}

impl From<SocketAddr> for ConnectionEndpoint {
    fn from(socket_addr: SocketAddr) -> Self {
        Self { socket_addr }
    }
}

impl From<&ConnectionEndpoint> for SocketAddr {
    fn from(connection_endpoint: &ConnectionEndpoint) -> Self {
        connection_endpoint.socket_addr
    }
}

/// Errors that can occur when converting from the protobuf encoding to the
/// `ConnectionEndpoint` type.
#[derive(Error, Debug, Clone)]
pub enum ConnectionEndpointTryFromProtoError {
    #[error("port does not convert to u16: {port}")]
    InvalidPort { port: String },

    #[error("IP address does not parse: {ip_addr}")]
    InvalidIpAddr { ip_addr: String },
}

impl TryFrom<pbConnectionEndpoint> for ConnectionEndpoint {
    type Error = ConnectionEndpointTryFromProtoError;

    fn try_from(pb: pbConnectionEndpoint) -> Result<Self, Self::Error> {
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
        Ok(ConnectionEndpoint { socket_addr })
    }
}

impl From<&ConnectionEndpoint> for pbConnectionEndpoint {
    fn from(ce: &ConnectionEndpoint) -> Self {
        pbConnectionEndpoint {
            ip_addr: ce.socket_addr.ip().to_string(),
            port: ce.socket_addr.port() as u32,
        }
    }
}

/*
#[cfg(test)]
mod connection_endpoint_test {
    use super::*;
    use assert_matches::assert_matches;
    use pretty_assertions::assert_eq;

    /// Displaying a ConnectionEndpoint should just show the URL
    #[test]
    fn display_ok() {
        let want = "1.2.3.4:8080";

        let ce = ConnectionEndpoint {
            socket_addr: SocketAddr::from_str(want).unwrap(),
        };

        assert_eq!(ce.to_string(), want);
    }

    /// Converting from a V4 SocketAddr should work, and the protocol should be
    /// `http`
    #[test]
    fn from_socket_addr_v4_ok() {
        let want = "1.2.3.4:8080";
        let socket_addr = "1.2.3.4:8080".parse::<SocketAddr>().unwrap();
        let ce = ConnectionEndpoint::from(socket_addr);
        assert_eq!(ce.to_string(), want);
    }

    /// Converting from a V6 SocketAddr with a port should work, and the
    /// protocol should be `http`
    #[test]
    fn from_socket_addr_v6_ok() {
        let want = "[2001:db8::1]:8080";
        let socket_addr = "[2001:db8::1]:8080".parse::<SocketAddr>().unwrap();
        let ce = ConnectionEndpoint::from(socket_addr);
        assert_eq!(ce.to_string(), want);
    }

    /// Converting from a http Url should work, and should retain the original
    /// protocol
    #[test]
    fn try_from_url_http_ok() {
        let want = "1.2.3.4:8080";
        let url = "http://1.2.3.4:8080".parse::<Url>().unwrap();
        let ce = ConnectionEndpoint::try_from(url).unwrap();
        assert_eq!(ce.to_string(), want);
    }

    /// Converting from a p2p1 Url should work, and should retain the original
    /// protocol
    #[test]
    fn from_url_p2p1_ok() {
        let want = "1.2.3.4:1234";
        let url = "org.internetcomputer.p2p1://1.2.3.4:1234"
            .parse::<Url>()
            .unwrap();
        let ce = ConnectionEndpoint::try_from(url).unwrap();
        assert_eq!(ce.to_string(), want);
    }

    /// Converting from a p2p1 Url with an IPv6 address should work.
    #[test]
    fn from_url_p2p1_addr_v6_ok() {
        let want = "[2602:fb2b:100:10:5054:ffff:fe0c:1d05]:4100";
        let url = "org.internetcomputer.p2p1://[2602:fb2b:100:10:5054:ffff:fe0c:1d05]:4100"
            .parse::<Url>()
            .unwrap();
        let ce = ConnectionEndpoint::try_from(url).unwrap();
        assert_eq!(ce.to_string(), want);
    }

    /// p2p1 URLs *must* include a port number as there is no default port
    #[test]
    fn from_url_p2p1_no_port_fail() {
        let url = "org.internetcomputer.p2p1://1.2.3.4"
            .parse::<Url>()
            .unwrap();
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
            "org.internetcomputer.p2p1://example.com:1234"
                .parse()
                .unwrap(),
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
                    ip_addr: "1.2.3.4".to_string(),
                    port: 80,
                },
            },
            TestData {
                // Different port
                source: "http://1.2.3.4:8080",
                pb_connection_endpoint: pbConnectionEndpoint {
                    ip_addr: "1.2.3.4".to_string(),
                    port: 8080,
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
*/
