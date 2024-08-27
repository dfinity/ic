use ic_logger::{warn, ReplicaLogger};
use ic_protobuf::registry::node::v1::ConnectionEndpoint;
use std::net::IpAddr;
use std::str::FromStr;
use url::Url;

pub(crate) fn http_endpoint_to_url(http: &ConnectionEndpoint, log: &ReplicaLogger) -> Option<Url> {
    let host_str = match IpAddr::from_str(&http.ip_addr.clone()) {
        Ok(v) => {
            if v.is_ipv6() {
                format!("[{}]", v)
            } else {
                v.to_string()
            }
        }
        Err(_) => {
            // assume hostname
            http.ip_addr.clone()
        }
    };

    let url = format!("http://{}:{}/", host_str, http.port);
    match Url::parse(&url) {
        Ok(v) => Some(v),
        Err(e) => {
            warn!(log, "Invalid url: {}: {:?}", url, e);
            None
        }
    }
}
