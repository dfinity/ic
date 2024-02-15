use super::types::{ConstructionMetadataRequestOptions, SignedTransaction, UnsignedTransaction};
use crate::common::types::Error;
use crate::construction_api::utils::handle_construction_combine;
use crate::construction_api::utils::handle_construction_submit;
use ic_base_types::{CanisterId, PrincipalId};
use icrc_ledger_agent::{CallMode, Icrc1Agent};
use icrc_ledger_types::icrc1::account::Account;
use rosetta_core::objects::{Amount, Currency, Signature};
use rosetta_core::response_types::*;
use rosetta_core::{
    convert::principal_id_from_public_key, objects::PublicKey,
    response_types::ConstructionDeriveResponse,
};
use std::str::FromStr;
use std::sync::Arc;

pub fn construction_derive(public_key: PublicKey) -> Result<ConstructionDeriveResponse, Error> {
    let principal_id: PrincipalId = principal_id_from_public_key(&public_key)
        .map_err(|err| Error::parsing_unsuccessful(&err))?;
    let account: Account = principal_id.0.into();
    Ok(ConstructionDeriveResponse::new(None, Some(account.into())))
}

pub fn construction_preprocess() -> Result<ConstructionPreprocessResponse, Error> {
    Ok(ConstructionPreprocessResponse {
        options: Some(
            ConstructionMetadataRequestOptions {
                suggested_fee: true,
            }
            .try_into()
            .map_err(|err| Error::parsing_unsuccessful(&err))?,
        ),
        required_public_keys: None,
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

pub fn construction_combine(
    unsigned_transaction: String,
    signatures: Vec<Signature>,
) -> Result<ConstructionCombineResponse, Error> {
    let unsigned_transaction = UnsignedTransaction::from_str(&unsigned_transaction)
        .map_err(|err| Error::parsing_unsuccessful(&err))?;

    handle_construction_combine(unsigned_transaction, signatures)
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
