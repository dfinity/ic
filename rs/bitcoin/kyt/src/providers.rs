use crate::BtcNetwork;
use ic_btc_interface::Txid;
use ic_cdk::api::management_canister::http_request::{
    CanisterHttpRequestArgument, HttpHeader, HttpMethod, TransformContext, TransformFunc,
};
use std::cell::RefCell;
use std::fmt;

/// Return the next bitcoin API provider for the given `btc_network`.
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
    static PREVIOUS_PROVIDER_ID: RefCell<ProviderId> = const { RefCell::new(ProviderId::BtcScan) };
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ProviderId {
    BtcScan,
    BlockStream,
    MempoolSpace,
}

impl fmt::Display for ProviderId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::BtcScan => write!(f, "btcscan.org"),
            Self::BlockStream => write!(f, "blockstream.info"),
            Self::MempoolSpace => write!(f, "mempool.space"),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Provider {
    btc_network: BtcNetwork,
    provider_id: ProviderId,
}

impl Provider {
    // Return the next provider by cycling through all available providers.
    pub fn next(&self) -> Self {
        let btc_network = self.btc_network;
        let provider_id = match (self.btc_network, self.provider_id) {
            (BtcNetwork::Mainnet, ProviderId::BtcScan) => ProviderId::BlockStream,
            (BtcNetwork::Mainnet, ProviderId::BlockStream) => ProviderId::MempoolSpace,
            (BtcNetwork::Mainnet, ProviderId::MempoolSpace) => ProviderId::BtcScan,
            (BtcNetwork::Testnet, ProviderId::BlockStream) => ProviderId::MempoolSpace,
            (BtcNetwork::Testnet, _) => ProviderId::BlockStream,
        };
        Self {
            btc_network,
            provider_id,
        }
    }

    pub fn create_request(
        &self,
        txid: Txid,
        max_response_bytes: u32,
    ) -> CanisterHttpRequestArgument {
        match (self.provider_id, self.btc_network) {
            (ProviderId::BlockStream, _) => make_request(
                "blockstream.info",
                self.btc_network,
                txid,
                max_response_bytes,
            ),
            (ProviderId::MempoolSpace, _) => {
                make_request("mempool.space", self.btc_network, txid, max_response_bytes)
            }
            (ProviderId::BtcScan, BtcNetwork::Mainnet) => btcscan_request(txid, max_response_bytes),
            (provider, btc_network) => {
                panic!(
                    "Provider {} does not support bitcoin {}",
                    provider, btc_network
                )
            }
        }
    }
}

fn btcscan_request(txid: Txid, max_response_bytes: u32) -> CanisterHttpRequestArgument {
    let host = "btcscan.org";
    let url = format!("https://{}/api/tx/{}/raw", host, txid);
    let request_headers = vec![
        HttpHeader {
            name: "Host".to_string(),
            value: format!("{host}:443"),
        },
        HttpHeader {
            name: "User-Agent".to_string(),
            value: "bitcoin_inputs_collector".to_string(),
        },
    ];
    CanisterHttpRequestArgument {
        url: url.to_string(),
        method: HttpMethod::GET,
        body: None,
        max_response_bytes: Some(max_response_bytes as u64),
        transform: param_transform(),
        headers: request_headers,
    }
}

fn make_request(
    host: &str,
    network: BtcNetwork,
    txid: Txid,
    max_response_bytes: u32,
) -> CanisterHttpRequestArgument {
    let url = match network {
        BtcNetwork::Mainnet => format!("https://{}/api/tx/{}/raw", host, txid),
        BtcNetwork::Testnet => format!("https://{}/testnet/api/tx/{}/raw", host, txid),
    };
    let request_headers = vec![HttpHeader {
        name: "Host".to_string(),
        value: format!("{host}:443"),
    }];
    CanisterHttpRequestArgument {
        url: url.to_string(),
        method: HttpMethod::GET,
        body: None,
        max_response_bytes: Some(max_response_bytes as u64),
        transform: param_transform(),
        headers: request_headers,
    }
}

fn param_transform() -> Option<TransformContext> {
    Some(TransformContext {
        function: TransformFunc(candid::Func {
            principal: ic_cdk::api::id(),
            method: "transform".to_string(),
        }),
        context: vec![],
    })
}
