use crate::result::{ProviderError, RpcError};
use crate::{EthMainnetService, MultiRpcResult, RpcService};

#[test]
fn test_multi_rpc_result_map() {
    let err = RpcError::ProviderError(ProviderError::ProviderNotFound);
    assert_eq!(
        MultiRpcResult::Consistent(Ok(5)).map(|n| n + 1),
        MultiRpcResult::Consistent(Ok(6))
    );
    assert_eq!(
        MultiRpcResult::Consistent(Err(err.clone())).map(|()| unreachable!()),
        MultiRpcResult::Consistent(Err(err.clone()))
    );
    assert_eq!(
        MultiRpcResult::Inconsistent(vec![(
            RpcService::EthMainnet(EthMainnetService::Ankr),
            Ok(5)
        )])
        .map(|n| n + 1),
        MultiRpcResult::Inconsistent(vec![(
            RpcService::EthMainnet(EthMainnetService::Ankr),
            Ok(6)
        )])
    );
    assert_eq!(
        MultiRpcResult::Inconsistent(vec![
            (RpcService::EthMainnet(EthMainnetService::Ankr), Ok(5)),
            (
                RpcService::EthMainnet(EthMainnetService::Cloudflare),
                Ok(10)
            )
        ])
        .map(|n| n + 1),
        MultiRpcResult::Inconsistent(vec![
            (RpcService::EthMainnet(EthMainnetService::Ankr), Ok(6)),
            (
                RpcService::EthMainnet(EthMainnetService::Cloudflare),
                Ok(11)
            )
        ])
    );
    assert_eq!(
        MultiRpcResult::Inconsistent(vec![
            (RpcService::EthMainnet(EthMainnetService::Ankr), Ok(5)),
            (
                RpcService::EthMainnet(EthMainnetService::PublicNode),
                Err(err.clone())
            )
        ])
        .map(|n| n + 1),
        MultiRpcResult::Inconsistent(vec![
            (RpcService::EthMainnet(EthMainnetService::Ankr), Ok(6)),
            (
                RpcService::EthMainnet(EthMainnetService::PublicNode),
                Err(err)
            )
        ])
    );
}
