use super::*;
use std::convert::TryFrom;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;

fn str_node_id(s: &str) -> NodeId {
    NodeId::from(PrincipalId::from_str(s).expect("failed to parse principal id"))
}

#[test]
fn test_parse_auth_from_str() {
    assert_eq!(
        XNetAuthority::from_str("aaaaa-aa.256@1.2.3.4:99").unwrap(),
        XNetAuthority {
            node_id: str_node_id("aaaaa-aa"),
            registry_version: RegistryVersion::new(256),
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 99),
        },
    );
}

#[test]
fn test_parse_auth_from_uri() {
    assert_eq!(
        XNetAuthority::try_from(
            &"http://aaaaa-aa.256@1.2.3.4:99/path/to?stream=1"
                .parse::<Uri>()
                .unwrap()
        )
        .unwrap(),
        XNetAuthority {
            node_id: str_node_id("aaaaa-aa"),
            registry_version: RegistryVersion::new(256),
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 99),
        },
    );
}

#[test]
fn test_auth_display() {
    assert_eq!(
        format!(
            "{}",
            XNetAuthority {
                node_id: str_node_id("aaaaa-aa"),
                registry_version: RegistryVersion::new(256),
                address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 99),
            }
        ),
        "aaaaa-aa.256@1.2.3.4:99".to_string(),
    );
}
