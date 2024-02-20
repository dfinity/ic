use super::types::{
    ConstructionMetadataRequestOptions, ConstructionPayloadsRequestMetadata, SignedTransaction,
    UnsignedTransaction,
};
use super::utils::{
    extract_caller_principal_from_rosetta_core_operation, handle_construction_combine,
    handle_construction_hash, handle_construction_payloads, handle_construction_submit,
};
use crate::common::types::Error;
use candid::Principal;
use ic_base_types::{CanisterId, PrincipalId};
use icrc_ledger_agent::{CallMode, Icrc1Agent};
use icrc_ledger_types::icrc1::account::Account;
use rosetta_core::objects::{Amount, Currency, Operation, Signature};
use rosetta_core::response_types::*;
use rosetta_core::{
    convert::principal_id_from_public_key, objects::PublicKey,
    response_types::ConstructionDeriveResponse,
};
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;
use std::time::SystemTime;

pub fn construction_derive(public_key: PublicKey) -> Result<ConstructionDeriveResponse, Error> {
    let principal_id: PrincipalId = principal_id_from_public_key(&public_key)
        .map_err(|err| Error::parsing_unsuccessful(&err))?;
    let account: Account = principal_id.0.into();
    Ok(ConstructionDeriveResponse::new(None, Some(account.into())))
}

pub fn construction_preprocess(
    operations: Vec<Operation>,
) -> Result<ConstructionPreprocessResponse, Error> {
    let mut caller_public_keys = HashSet::new();
    for operation in operations.clone().into_iter() {
        let caller: Account = extract_caller_principal_from_rosetta_core_operation(operation)
            .map_err(|err| Error::processing_construction_failed(&err))?
            .into();
        caller_public_keys.insert(caller);
    }

    Ok(ConstructionPreprocessResponse {
        options: Some(
            ConstructionMetadataRequestOptions {
                suggested_fee: true,
            }
            .try_into()
            .map_err(|err| Error::processing_construction_failed(&err))?,
        ),
        required_public_keys: if caller_public_keys.is_empty() {
            None
        } else {
            Some(
                caller_public_keys
                    .into_iter()
                    .map(|account| account.into())
                    .collect(),
            )
        },
    })
}

pub async fn construction_metadata(
    options: ConstructionMetadataRequestOptions,
    icrc1_agent: Arc<Icrc1Agent>,
    currency: Currency,
) -> Result<ConstructionMetadataResponse, Error> {
    Ok(ConstructionMetadataResponse {
        metadata: serde_json::map::Map::new(),
        suggested_fee: if options.suggested_fee {
            Some(
                icrc1_agent
                    .fee(CallMode::Query)
                    .await
                    .map(|fee| vec![Amount::new(fee.0.to_string(), currency)])
                    .map_err(|err| Error::ledger_communication_unsuccessful(&err))?,
            )
        } else {
            None
        },
    })
}

pub async fn construction_submit(
    signed_transaction: String,
    icrc1_ledger_id: CanisterId,
    icrc1_agent: Arc<Icrc1Agent>,
) -> Result<ConstructionSubmitResponse, Error> {
    let signed_transaction = SignedTransaction::from_str(&signed_transaction)
        .map_err(|err| Error::parsing_unsuccessful(&err))?;

    handle_construction_submit(signed_transaction, icrc1_ledger_id.into(), icrc1_agent)
        .await
        .map_err(|err| Error::processing_construction_failed(&err))
}

pub fn construction_hash(signed_transaction: String) -> Result<ConstructionHashResponse, Error> {
    let signed_transaction = SignedTransaction::from_str(&signed_transaction)
        .map_err(|err| Error::parsing_unsuccessful(&err))?;

    handle_construction_hash(signed_transaction)
        .map_err(|err| Error::processing_construction_failed(&err))
}

pub fn construction_combine(
    unsigned_transaction: String,
    signatures: Vec<Signature>,
) -> Result<ConstructionCombineResponse, Error> {
    let unsigned_transaction = UnsignedTransaction::from_str(&unsigned_transaction)
        .map_err(|err| Error::parsing_unsuccessful(&err))?;

    handle_construction_combine(unsigned_transaction, signatures)
        .map_err(|err| Error::processing_construction_failed(&err))
}

pub fn construction_payloads(
    operations: Vec<Operation>,
    metadata: Option<ConstructionPayloadsRequestMetadata>,
    ledger_id: &Principal,
    public_keys: Vec<PublicKey>,
) -> Result<ConstructionPayloadsResponse, Error> {
    // The interval between each ingress message
    let ingress_interval = ic_constants::MAX_INGRESS_TTL.as_nanos() as u64;

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    let ingress_start = metadata
        .as_ref()
        .and_then(|meta| meta.ingress_start)
        .unwrap_or(now);

    let ingress_end = metadata
        .as_ref()
        .and_then(|meta| meta.ingress_end)
        .unwrap_or(ingress_start + ingress_interval);

    let created_at_time = metadata
        .as_ref()
        .and_then(|meta| meta.created_at_time)
        .unwrap_or(now);

    let memo = metadata
        .as_ref()
        .and_then(|meta| meta.memo.clone())
        .map(|memo| memo.into());

    // TODO: Support longer intervals than a single interval
    if ingress_end != ingress_start + ingress_interval {
        return Err(Error::invalid_metadata(
            &"ingress_end should be after 4 minutes from ingress_start",
        ));
    }

    // TODO: support multiple operations
    if operations.len() != 1 {
        return Err(Error::processing_construction_failed(
            &"Only one operation is supported",
        ));
    }

    // ICRC Rosetta only supports one transaction per request
    // Each transaction has exactly one PublicKey that is associated with the entity making the call to the ledger
    if public_keys.is_empty() {
        return Err(Error::processing_construction_failed(
            &"public_keys should not be empty",
        ));
    }

    if public_keys.len() > 1 {
        return Err(Error::processing_construction_failed(
            &"Only one public key is supported",
        ));
    }

    let sender_public_key = public_keys[0].clone();

    handle_construction_payloads(
        operations[0].clone(),
        created_at_time,
        memo,
        ingress_end,
        *ledger_id,
        sender_public_key,
    )
    .map_err(|err| Error::processing_construction_failed(&err))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_canister_client_sender::{Ed25519KeyPair, Secp256k1KeyPair};
    use proptest::prelude::any;
    use proptest::proptest;
    use rosetta_core::models::RosettaSupportedKeyPair;

    fn call_construction_derive<T: RosettaSupportedKeyPair>(key_pair: &T) {
        let principal_id = key_pair.generate_principal_id().unwrap();
        let public_key = ic_rosetta_test_utils::to_public_key(key_pair);
        let account = Account {
            owner: principal_id.into(),
            subaccount: None,
        };

        let res = construction_derive(public_key);
        assert_eq!(
            res,
            Ok(ConstructionDeriveResponse {
                address: None,
                account_identifier: Some(account.into()),
                metadata: None
            })
        );
    }

    proptest! {
        #[test]
        fn test_construction_derive_ed(seed in any::<u64>()) {
            let key_pair = Ed25519KeyPair::generate_from_u64(seed);
            call_construction_derive(&key_pair);
        }

        #[test]
        fn test_construction_derive_sepc(seed in any::<u64>()) {
            let key_pair = Secp256k1KeyPair::generate_from_u64(seed);
            call_construction_derive(&key_pair);
        }
    }
}
