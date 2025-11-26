use crate::BtcNetwork;
use ic_btc_interface::Txid;
use ic_cdk::management_canister::{
    HttpHeader, HttpMethod, HttpRequestArgs, TransformContext, TransformFunc,
};
use std::cell::RefCell;
use std::fmt;

#[cfg(test)]
mod tests;

/// Return the next Bitcoin API provider for the given `btc_network`.
///
/// Internally it remembers the previously used provider in a thread local
/// state and would iterate through all providers in a round-robin manner.
pub fn next_provider(btc_network: BtcNetwork) -> Provider {
    PREVIOUS_PROVIDER_ID.with(|previous| {
        let provider = (Provider {
            btc_network,
            provider_id: *previous.borrow(),
        })
        .next();
        *previous.borrow_mut() = provider.provider_id;
        provider
    })
}

thread_local! {
    static PREVIOUS_PROVIDER_ID: RefCell<ProviderId> = const { RefCell::new(ProviderId::Btcscan) };
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ProviderId {
    Btcscan,
    Blockstream,
    MempoolSpace,
}

impl fmt::Display for ProviderId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Btcscan => write!(f, "btcscan.org"),
            Self::Blockstream => write!(f, "blockstream.info"),
            Self::MempoolSpace => write!(f, "mempool.space"),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Provider {
    btc_network: BtcNetwork,
    provider_id: ProviderId,
}

impl Provider {
    pub fn btc_network(&self) -> &BtcNetwork {
        &self.btc_network
    }

    pub fn name(&self) -> String {
        match self.btc_network {
            BtcNetwork::Mainnet => self.provider_id.to_string(),
            BtcNetwork::Testnet => "Testnet".to_string(),
            BtcNetwork::Regtest { .. } => "Regtest".to_string(),
        }
    }

    // Return the next provider by cycling through all available providers.
    pub fn next(&self) -> Self {
        let btc_network = &self.btc_network;
        let provider_id = match (btc_network, self.provider_id) {
            (BtcNetwork::Mainnet, ProviderId::Btcscan) => ProviderId::Blockstream,
            (BtcNetwork::Mainnet, ProviderId::Blockstream) => ProviderId::MempoolSpace,
            (BtcNetwork::Mainnet, ProviderId::MempoolSpace) => ProviderId::Btcscan,
            (BtcNetwork::Testnet, ProviderId::Blockstream) => ProviderId::MempoolSpace,
            (BtcNetwork::Testnet, _) => ProviderId::Blockstream,
            (BtcNetwork::Regtest { .. }, _) => return self.clone(),
        };
        Self {
            btc_network: btc_network.clone(),
            provider_id,
        }
    }

    pub fn create_request(
        &self,
        txid: Txid,
        max_response_bytes: u32,
    ) -> Result<HttpRequestArgs, String> {
        match (self.provider_id, &self.btc_network) {
            (_, BtcNetwork::Regtest { json_rpc_url }) => {
                make_post_request(json_rpc_url, txid, max_response_bytes)
            }
            (ProviderId::Blockstream, _) => Ok(make_get_request(
                "blockstream.info",
                &self.btc_network,
                txid,
                max_response_bytes,
            )),
            (ProviderId::MempoolSpace, _) => Ok(make_get_request(
                "mempool.space",
                &self.btc_network,
                txid,
                max_response_bytes,
            )),
            (ProviderId::Btcscan, BtcNetwork::Mainnet) => {
                Ok(btcscan_request(txid, max_response_bytes))
            }
            (provider, btc_network) => {
                panic!("Provider {provider} does not support Bitcoin {btc_network}")
            }
        }
    }
}

fn btcscan_request(txid: Txid, max_response_bytes: u32) -> HttpRequestArgs {
    let host = "btcscan.org";
    let url = format!("https://{host}/api/tx/{txid}/raw");
    let request_headers = vec![HttpHeader {
        name: "User-Agent".to_string(),
        value: "bitcoin_inputs_collector".to_string(),
    }];
    HttpRequestArgs {
        url: url.to_string(),
        method: HttpMethod::GET,
        body: None,
        max_response_bytes: Some(max_response_bytes as u64),
        transform: param_transform(),
        headers: request_headers,
    }
}

fn make_get_request(
    host: &str,
    network: &BtcNetwork,
    txid: Txid,
    max_response_bytes: u32,
) -> HttpRequestArgs {
    let url = match network {
        BtcNetwork::Mainnet => format!("https://{host}/api/tx/{txid}/raw"),
        BtcNetwork::Testnet => format!("https://{host}/testnet/api/tx/{txid}/raw"),
        BtcNetwork::Regtest { .. } => panic!("Request to regtest network requires POST"),
    };
    let request_headers = vec![];
    HttpRequestArgs {
        url: url.to_string(),
        method: HttpMethod::GET,
        body: None,
        max_response_bytes: Some(max_response_bytes as u64),
        transform: param_transform(),
        headers: request_headers,
    }
}

fn make_post_request(
    json_rpc_url: &str,
    txid: Txid,
    max_response_bytes: u32,
) -> Result<HttpRequestArgs, String> {
    let (url, header) = parse_authorization_header_from_url(json_rpc_url)?;
    let body = format!("{{\"method\": \"gettransaction\", \"params\": [\"{txid}\"]}}");
    Ok(HttpRequestArgs {
        url: url.to_string(),
        method: HttpMethod::POST,
        body: Some(body.as_bytes().to_vec()),
        max_response_bytes: Some(max_response_bytes as u64),
        transform: param_transform(),
        headers: vec![header],
    })
}

fn param_transform() -> Option<TransformContext> {
    Some(TransformContext {
        function: TransformFunc(candid::Func {
            principal: ic_cdk::api::canister_self(),
            method: "transform".to_string(),
        }),
        context: vec![],
    })
}

pub(crate) fn parse_authorization_header_from_url(
    json_rpc_url: &str,
) -> Result<(url::Url, HttpHeader), String> {
    let mut url = url::Url::parse(json_rpc_url).map_err(|err| err.to_string())?;
    let username = url.username();
    let password = url.password().unwrap_or_default();
    let authorization = base64::encode(format!(
        "{}:{}",
        url::form_urlencoded::parse(username.as_bytes())
            .next()
            .ok_or("Missing username or error in url_decode".to_string())?
            .0,
        url::form_urlencoded::parse(password.as_bytes())
            .next()
            .ok_or("Missing password or error in url_decode".to_string())?
            .0,
    ));
    url.set_username("")
        .map_err(|()| format!("Invalid JSON RPC URL {json_rpc_url}"))?;
    url.set_password(None)
        .map_err(|()| format!("Invalid JSON RPC URL {json_rpc_url}"))?;
    let header = HttpHeader {
        name: "Authorization".to_string(),
        value: format!("Basic {authorization}"),
    };
    Ok((url, header))
}
