use crate::RpcApi;
use ic_management_canister_types::HttpHeader;

#[test]
fn should_contain_host_without_sensitive_information() {
    for provider in [
        RpcApi {
            url: "https://eth-mainnet.g.alchemy.com/v2".to_string(),
            headers: None,
        },
        RpcApi {
            url: "https://eth-mainnet.g.alchemy.com/v2/key".to_string(),
            headers: None,
        },
        RpcApi {
            url: "https://eth-mainnet.g.alchemy.com/v2".to_string(),
            headers: Some(vec![HttpHeader {
                name: "authorization".to_string(),
                value: "Bearer key".to_string(),
            }]),
        },
    ] {
        let debug = format!("{:?}", provider);
        assert_eq!(
            debug,
            "RpcApi { host: eth-mainnet.g.alchemy.com, url/headers: *** }"
        );
    }
}
