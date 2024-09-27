use bitcoin::Network;
use ic_btc_interface::Txid;
use ic_cdk::api::management_canister::http_request::{
    CanisterHttpRequestArgument, HttpHeader, HttpMethod, TransformContext, TransformFunc,
};

pub fn create_requests(
    network: Network,
    txid: Txid,
    max_response_bytes: u32,
) -> CanisterHttpRequestArgument {
    match network {
        Network::Bitcoin => btcscan_request(txid, max_response_bytes),
        Network::Testnet => mempool_space_testnet_request(txid, max_response_bytes),
        _ => panic!("{} network is not supported", network),
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
        transform: Some(TransformContext {
            function: TransformFunc(candid::Func {
                principal: ic_cdk::api::id(),
                method: "transform".to_string(),
            }),
            context: vec![],
        }),
        headers: request_headers,
    }
}

fn mempool_space_testnet_request(
    txid: Txid,
    max_response_bytes: u32,
) -> CanisterHttpRequestArgument {
    let host = "mempool.space";
    let url = format!("https://{}/testnet/api/tx/{}/raw", host, txid);
    let request_headers = vec![HttpHeader {
        name: "Host".to_string(),
        value: format!("{host}:443"),
    }];
    CanisterHttpRequestArgument {
        url: url.to_string(),
        method: HttpMethod::GET,
        body: None,
        max_response_bytes: Some(max_response_bytes as u64),
        transform: Some(TransformContext {
            function: TransformFunc(candid::Func {
                principal: ic_cdk::api::id(),
                method: "transform".to_string(),
            }),
            context: vec![],
        }),
        headers: request_headers,
    }
}
