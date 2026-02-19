use crate::{
    AccessList, AccessListEntry, BlockTag, CallArgs, Hex, Hex20, Hex32, HexByte, Nat256, RpcError,
    TransactionRequest, ValidationError,
};
use alloy_primitives::TxKind;

impl From<alloy_rpc_types::BlockNumberOrTag> for BlockTag {
    fn from(tag: alloy_rpc_types::BlockNumberOrTag) -> Self {
        use alloy_rpc_types::BlockNumberOrTag;
        match tag {
            BlockNumberOrTag::Latest => Self::Latest,
            BlockNumberOrTag::Finalized => Self::Finalized,
            BlockNumberOrTag::Safe => Self::Safe,
            BlockNumberOrTag::Earliest => Self::Earliest,
            BlockNumberOrTag::Pending => Self::Pending,
            BlockNumberOrTag::Number(n) => Self::Number(n.into()),
        }
    }
}

impl TryFrom<BlockTag> for alloy_rpc_types::BlockNumberOrTag {
    type Error = RpcError;

    fn try_from(tag: BlockTag) -> Result<Self, Self::Error> {
        Ok(match tag {
            BlockTag::Latest => Self::Latest,
            BlockTag::Finalized => Self::Finalized,
            BlockTag::Safe => Self::Safe,
            BlockTag::Earliest => Self::Earliest,
            BlockTag::Pending => Self::Pending,
            BlockTag::Number(n) => Self::Number(u64::try_from(n)?),
        })
    }
}

impl TryFrom<alloy_rpc_types::TransactionRequest> for CallArgs {
    type Error = RpcError;

    fn try_from(request: alloy_rpc_types::TransactionRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            transaction: TransactionRequest::try_from(request)?,
            block: None,
        })
    }
}

impl TryFrom<alloy_rpc_types::TransactionRequest> for TransactionRequest {
    type Error = RpcError;

    fn try_from(tx_request: alloy_rpc_types::TransactionRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            tx_type: tx_request.transaction_type.map(HexByte::from),
            nonce: tx_request.nonce.map(Nat256::from),
            to: tx_request.to.and_then(|kind| match kind {
                TxKind::Create => None,
                TxKind::Call(address) => Some(Hex20::from(address)),
            }),
            from: tx_request.from.map(Hex20::from),
            gas: tx_request.gas.map(Nat256::from),
            value: tx_request.value.map(Nat256::from),
            input: tx_request
                .input
                .try_into_unique_input()
                .map_err(|e| RpcError::ValidationError(ValidationError::Custom(e.to_string())))?
                .map(Hex::from),
            gas_price: tx_request.gas_price.map(Nat256::from),
            max_priority_fee_per_gas: tx_request.max_priority_fee_per_gas.map(Nat256::from),
            max_fee_per_gas: tx_request.max_fee_per_gas.map(Nat256::from),
            max_fee_per_blob_gas: tx_request.max_fee_per_blob_gas.map(Nat256::from),
            access_list: tx_request.access_list.map(AccessList::from),
            blob_versioned_hashes: tx_request
                .blob_versioned_hashes
                .map(|hashes| hashes.into_iter().map(Hex32::from).collect()),
            blobs: tx_request
                .sidecar
                .map(|sidecar| sidecar.blobs().iter().map(|b| Hex::from(*b)).collect()),
            chain_id: tx_request.chain_id.map(Nat256::from),
        })
    }
}

impl From<alloy_rpc_types::AccessList> for AccessList {
    fn from(access_list: alloy_rpc_types::AccessList) -> Self {
        Self(
            access_list
                .0
                .into_iter()
                .map(|item| AccessListEntry {
                    address: Hex20::from(item.address),
                    storage_keys: item.storage_keys.into_iter().map(Hex32::from).collect(),
                })
                .collect(),
        )
    }
}

// TODO XC-412: impl From<alloy_rpc_types::Filter> for GetLogsArgs
