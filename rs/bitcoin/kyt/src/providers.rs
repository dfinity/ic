use crate::BtcNetwork;
use ic_btc_interface::Txid;
use ic_cdk::api::management_canister::http_request::{
    CanisterHttpRequestArgument, HttpHeader, HttpMethod, TransformContext, TransformFunc,
};
use std::fmt;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ProviderId {
    BtcScan,
    MempoolSpace,
}

impl fmt::Display for ProviderId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::BtcScan => write!(f, "btcscan.org"),
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
    pub fn new_with_default(btc_network: BtcNetwork) -> Self {
        let provider_id = match btc_network {
            BtcNetwork::Mainnet => ProviderId::BtcScan,
            BtcNetwork::Testnet => ProviderId::MempoolSpace,
        };
        Self {
            btc_network,
            provider_id,
        }
    }
    pub fn next(&self) -> Self {
        let btc_network = self.btc_network;
        let provider_id = match (self.btc_network, self.provider_id) {
            (BtcNetwork::Mainnet, ProviderId::BtcScan) => ProviderId::MempoolSpace,
            (BtcNetwork::Mainnet, ProviderId::MempoolSpace) => ProviderId::BtcScan,
            (BtcNetwork::Testnet, _) => ProviderId::MempoolSpace,
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
        match (self.btc_network, self.provider_id) {
            (BtcNetwork::Mainnet, ProviderId::BtcScan) => {
                mempool_space_request(self.btc_network, txid, max_response_bytes)
            }
            (BtcNetwork::Mainnet, ProviderId::MempoolSpace) => {
                btcscan_request(txid, max_response_bytes)
            }
            (BtcNetwork::Testnet, ProviderId::MempoolSpace) => {
                mempool_space_request(self.btc_network, txid, max_response_bytes)
            }
            (btc_network, provider) => {
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

fn mempool_space_request(
    network: BtcNetwork,
    txid: Txid,
    max_response_bytes: u32,
) -> CanisterHttpRequestArgument {
    let host = "mempool.space";
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
