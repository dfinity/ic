use crate::result::{ProviderError, RpcError};
use crate::{EthMainnetService, MultiRpcResult, RpcService, ValidationError};

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
        MultiRpcResult::Inconsistent(vec![
            (RpcService::EthMainnet(EthMainnetService::Ankr), Ok(5)),
            (RpcService::EthMainnet(EthMainnetService::Ankr), Ok(6))
        ])
        .map(|n| n + 1),
        MultiRpcResult::Inconsistent(vec![
            (RpcService::EthMainnet(EthMainnetService::Ankr), Ok(6)),
            (RpcService::EthMainnet(EthMainnetService::Ankr), Ok(7))
        ])
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
    assert_eq!(
        MultiRpcResult::Inconsistent(vec![(
            RpcService::EthMainnet(EthMainnetService::Ankr),
            Ok(2)
        )])
        .map(|n| n / 2),
        MultiRpcResult::Consistent(Ok(1))
    );
    assert_eq!(
        MultiRpcResult::Inconsistent(vec![
            (RpcService::EthMainnet(EthMainnetService::Ankr), Ok(2)),
            (RpcService::EthMainnet(EthMainnetService::Llama), Ok(3))
        ])
        .map(|n| n / 2),
        MultiRpcResult::Consistent(Ok(1))
    );
    assert_eq!(
        MultiRpcResult::Inconsistent(vec![
            (
                RpcService::EthMainnet(EthMainnetService::Ankr),
                Err(RpcError::ValidationError(ValidationError::Custom(
                    "error message".into()
                )))
            ),
            (
                RpcService::EthMainnet(EthMainnetService::Llama),
                Err(RpcError::ValidationError(ValidationError::Custom(
                    "error message".into()
                )))
            )
        ])
        .and_then(|()| unreachable!()),
        MultiRpcResult::Consistent::<()>(Err(RpcError::ValidationError(ValidationError::Custom(
            "error message".into()
        ))))
    );
}
#[test]
fn test_multi_rpc_result_and_then() {
    let err = RpcError::ProviderError(ProviderError::ProviderNotFound);
    assert_eq!(
        MultiRpcResult::Consistent(Ok(5)).and_then(|n| Ok(n + 1)),
        MultiRpcResult::Consistent(Ok(6))
    );
    assert_eq!(
        MultiRpcResult::Consistent(Err(err.clone())).and_then(|()| unreachable!()),
        MultiRpcResult::Consistent::<()>(Err(err.clone()))
    );
    assert_eq!(
        MultiRpcResult::Inconsistent(vec![
            (RpcService::EthMainnet(EthMainnetService::Ankr), Ok(5)),
            (RpcService::EthMainnet(EthMainnetService::Ankr), Ok(6))
        ])
        .and_then(|n| Ok(n + 1)),
        MultiRpcResult::Inconsistent(vec![
            (RpcService::EthMainnet(EthMainnetService::Ankr), Ok(6)),
            (RpcService::EthMainnet(EthMainnetService::Ankr), Ok(7))
        ])
    );
    assert_eq!(
        MultiRpcResult::Inconsistent(vec![
            (RpcService::EthMainnet(EthMainnetService::Ankr), Ok(5)),
            (
                RpcService::EthMainnet(EthMainnetService::Cloudflare),
                Ok(10)
            )
        ])
        .and_then(|n| Ok(n + 1)),
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
        .and_then(|n| Ok(n + 1)),
        MultiRpcResult::Inconsistent(vec![
            (RpcService::EthMainnet(EthMainnetService::Ankr), Ok(6)),
            (
                RpcService::EthMainnet(EthMainnetService::PublicNode),
                Err(err.clone())
            )
        ])
    );
    assert_eq!(
        MultiRpcResult::Inconsistent(vec![
            (RpcService::EthMainnet(EthMainnetService::Ankr), Ok(1)),
            (RpcService::EthMainnet(EthMainnetService::Llama), Ok(2))
        ])
        .and_then(|n| if n % 2 == 0 { Ok(n) } else { Err(err.clone()) }),
        MultiRpcResult::Inconsistent(vec![
            (
                RpcService::EthMainnet(EthMainnetService::Ankr),
                Err(err.clone())
            ),
            (RpcService::EthMainnet(EthMainnetService::Llama), Ok(2)),
        ])
    );
    assert_eq!(
        MultiRpcResult::Inconsistent(vec![
            (RpcService::EthMainnet(EthMainnetService::Ankr), Ok(1)),
            (RpcService::EthMainnet(EthMainnetService::Llama), Ok(3))
        ])
        .and_then(|n| if n % 2 == 0 { Ok(n) } else { Err(err.clone()) }),
        MultiRpcResult::Consistent(Err(err.clone()))
    );
    assert_eq!(
        MultiRpcResult::Inconsistent(vec![
            (RpcService::EthMainnet(EthMainnetService::Ankr), Ok(2)),
            (RpcService::EthMainnet(EthMainnetService::Llama), Ok(3))
        ])
        .and_then(|n| Ok(n / 2)),
        MultiRpcResult::Consistent(Ok(1))
    );
    assert_eq!(
        MultiRpcResult::Inconsistent(vec![
            (
                RpcService::EthMainnet(EthMainnetService::Ankr),
                Err(RpcError::ValidationError(ValidationError::Custom(
                    "error message".into()
                )))
            ),
            (
                RpcService::EthMainnet(EthMainnetService::Llama),
                Err(RpcError::ValidationError(ValidationError::Custom(
                    "error message".into()
                )))
            )
        ])
        .and_then(|()| unreachable!()),
        MultiRpcResult::Consistent::<()>(Err(RpcError::ValidationError(ValidationError::Custom(
            "error message".into()
        ))))
    );
}
