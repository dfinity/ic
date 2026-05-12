use std::net::SocketAddr;

use ic_registry_client_helpers::node::NodeRecord;
use ic_types::{PrincipalId, SubnetId};
use std::str::FromStr;
use url::Url;

pub(crate) fn http_url(n: &NodeRecord) -> Url {
    let c = n.http.as_ref().unwrap();
    // Parse IP address (using IpAddr::parse())
    let ip_addr = c.ip_addr.parse().unwrap();
    Url::parse(
        format!(
            "http://{}",
            SocketAddr::new(ip_addr, u16::try_from(c.port).unwrap())
        )
        .as_str(),
    )
    .unwrap()
}

pub fn subnet_id_from_str(s: &str) -> Result<SubnetId, String> {
    PrincipalId::from_str(s)
        .map_err(|e| format!("Unable to parse subnet_id {e:?}"))
        .map(SubnetId::from)
}
