use ic_crypto_utils_threshold_sig_der::threshold_sig_public_key_to_der;
use ic_interfaces_registry::RegistryClient;
use ic_protobuf::registry::node::v1::ConnectionEndpoint;
use ic_registry_client_helpers::{crypto::CryptoRegistry, subnet::SubnetRegistry};
use ic_types::RegistryVersion;
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

/// The NNS root key, in DER, as recorded in the registry.
pub(crate) fn nns_root_key_der_from_registry(
    registry_client: &dyn RegistryClient,
    version: RegistryVersion,
) -> Result<Vec<u8>, String> {
    let root_subnet_id = registry_client
        .get_root_subnet_id(version)
        .map_err(|err| format!("failed to get the root subnet id: {err}"))?
        .ok_or_else(|| format!("no root subnet id in the registry at version {version}"))?;
    let public_key = registry_client
        .get_threshold_signing_public_key_for_subnet(root_subnet_id, version)
        .map_err(|err| format!("error when retrieving the NNS public key: {err}"))?
        .ok_or_else(|| "NNS public key not set in the registry".to_string())?;

    threshold_sig_public_key_to_der(public_key)
        .map_err(|err| format!("could not DER-encode the NNS public key: {err:?}"))
}
