use crate::BtcNetwork;
use ic_btc_interface::Txid;
use ic_cdk::api::management_canister::http_request::{
    CanisterHttpRequestArgument, HttpHeader, HttpMethod, TransformContext, TransformFunc,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Provider {
    BtcScan,
    MempoolSpace,
}

pub fn create_request(
    btc_network: BtcNetwork,
    txid: Txid,
    previous_provider: Option<Provider>,
    max_response_bytes: u32,
) -> (Provider, CanisterHttpRequestArgument) {
    match (btc_network, previous_provider) {
        (BtcNetwork::Mainnet, None) => btcscan_request(txid, max_response_bytes),
        (BtcNetwork::Mainnet, Some(Provider::BtcScan)) => {
            mempool_space_request(btc_network, txid, max_response_bytes)
        }
        (BtcNetwork::Mainnet, Some(Provider::MempoolSpace)) => {
            btcscan_request(txid, max_response_bytes)
        }
        (BtcNetwork::Testnet, _) => mempool_space_request(btc_network, txid, max_response_bytes),
    }
}

fn btcscan_request(txid: Txid, max_response_bytes: u32) -> (Provider, CanisterHttpRequestArgument) {
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
    (
        Provider::BtcScan,
        CanisterHttpRequestArgument {
            url: url.to_string(),
            method: HttpMethod::GET,
            body: None,
            max_response_bytes: Some(max_response_bytes as u64),
            transform: param_transform(),
            headers: request_headers,
        },
    )
}

fn mempool_space_request(
    network: BtcNetwork,
    txid: Txid,
    max_response_bytes: u32,
) -> (Provider, CanisterHttpRequestArgument) {
    let host = "mempool.space";
    let url = match network {
        BtcNetwork::Mainnet => format!("https://{}/api/tx/{}/raw", host, txid),
        BtcNetwork::Testnet => format!("https://{}/testnet/api/tx/{}/raw", host, txid),
    };
    let request_headers = vec![HttpHeader {
        name: "Host".to_string(),
        value: format!("{host}:443"),
    }];
    (
        Provider::MempoolSpace,
        CanisterHttpRequestArgument {
            url: url.to_string(),
            method: HttpMethod::GET,
            body: None,
            max_response_bytes: Some(max_response_bytes as u64),
            transform: param_transform(),
            headers: request_headers,
        },
    )
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
