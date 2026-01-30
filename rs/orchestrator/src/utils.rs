use ic_protobuf::registry::node::v1::ConnectionEndpoint;
use std::{net::IpAddr, str::FromStr};
use url::Url;

pub(crate) fn https_endpoint_to_url(http: &ConnectionEndpoint) -> Result<Url, String> {
    let host_str = match IpAddr::from_str(&http.ip_addr.clone()) {
        Ok(v) => {
            if v.is_ipv6() {
                format!("[{v}]")
            } else {
                v.to_string()
            }
        }
        Err(_) => {
            // assume hostname
            http.ip_addr.clone()
        }
    };

    let url = format!("https://{}:{}/", host_str, http.port);
    Url::parse(&url).map_err(|e| format!("Invalid HTTPS endpoint: {url}: {e:?}"))
}
