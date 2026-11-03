use super::types::{
    ConstructionMetadataRequestOptions, ConstructionPayloadsRequestMetadata, SignedTransaction,
    UnsignedTransaction,
};
use super::utils::{
    extract_caller_principal_from_rosetta_core_operation, handle_construction_combine,
    handle_construction_hash, handle_construction_parse, handle_construction_payloads,
    handle_construction_submit,
};
use crate::common::constants::{INGRESS_INTERVAL_OVERLAP, MAX_INGRESS_WINDOW};
use crate::common::types::Error;
use candid::Principal;
use ic_base_types::{CanisterId, PrincipalId};
use icrc_ledger_agent::{CallMode, Icrc1Agent};
use icrc_ledger_types::icrc1::account::Account;
use num_bigint::BigInt;
use rosetta_core::objects::{Amount, Currency, Operation, Signature};
use rosetta_core::response_types::*;
use rosetta_core::{
    convert::principal_id_from_public_key, objects::PublicKey,
    response_types::ConstructionDeriveResponse,
};
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
    let required_public_keys = if !operations.is_empty() {
        let caller: Account = extract_caller_principal_from_rosetta_core_operation(operations)
            .map_err(|err| Error::processing_construction_failed(&err))?
            .into();
        Some(vec![caller.into()])
    } else {
        None
    };

    Ok(ConstructionPreprocessResponse {
        options: Some(
            ConstructionMetadataRequestOptions {
                suggested_fee: true,
            }
            .try_into()
            .map_err(|err| Error::processing_construction_failed(&err))?,
        ),
        required_public_keys,
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
                    .map(|fee| vec![Amount::new(BigInt::from(fee.0), currency)])
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

/// Validate the caller-provided ingress window before it is expanded into a
/// list of ingress expiries.
///
/// Rejects windows that would make the expiry loop iterate an excessive (or, on
/// arithmetic wraparound, unbounded) number of times. It enforces that:
/// - `ingress_start` is strictly before `ingress_end` (an empty or reversed
///   window would otherwise produce an empty/degenerate set of payloads),
/// - the span `ingress_end - ingress_start` must not exceed 24h, and
/// - `ingress_end` must not be more than 24h in the future, which also rejects
///   the near-`u64::MAX` payloads that would otherwise wrap the loop counter.
fn validate_ingress_window(now: u64, ingress_start: u64, ingress_end: u64) -> Result<(), Error> {
    let max_window = MAX_INGRESS_WINDOW.as_nanos() as u64;
    if ingress_start >= ingress_end {
        return Err(Error::processing_construction_failed(&format!(
            "Ingress start should start before ingress end: Start: {ingress_start}, End: {ingress_end}"
        )));
    }
    if ingress_end.saturating_sub(ingress_start) > max_window {
        return Err(Error::processing_construction_failed(&format!(
            "The ingress window (ingress_end - ingress_start) must not exceed {} hours: Start: {ingress_start}, End: {ingress_end}",
            MAX_INGRESS_WINDOW.as_secs() / 3600
        )));
    }
    if ingress_end.saturating_sub(now) > max_window {
        return Err(Error::processing_construction_failed(&format!(
            "ingress_end must not be more than {} hours in the future: Current time: {now}, End: {ingress_end}",
            MAX_INGRESS_WINDOW.as_secs() / 3600
        )));
    }
    Ok(())
}

pub fn construction_payloads(
    operations: Vec<Operation>,
    metadata: Option<ConstructionPayloadsRequestMetadata>,
    ledger_id: &Principal,
    public_keys: Vec<PublicKey>,
    now: SystemTime,
) -> Result<ConstructionPayloadsResponse, Error> {
    // The interval between each ingress message
    // The permitted drift makes sure that intervals are overlapping and there are no edge cases when trying to submit to the IC
    let ingress_interval: u64 =
        (ic_limits::MAX_INGRESS_TTL - ic_limits::PERMITTED_DRIFT).as_nanos() as u64;

    let now = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    let mut ingress_start = metadata
        .as_ref()
        .and_then(|meta| meta.ingress_start)
        .unwrap_or(now);

    // `ingress_start` originates from optional, caller-controlled metadata, so a
    // near-`u64::MAX` value would overflow this default computation and panic
    // before `validate_ingress_window` runs. Saturate instead: the resulting
    // out-of-range window is then rejected by the validation below.
    let ingress_end = metadata
        .as_ref()
        .and_then(|meta| meta.ingress_end)
        .unwrap_or(ingress_start.saturating_add(ingress_interval));

    let created_at_time = metadata
        .as_ref()
        .and_then(|meta| meta.created_at_time)
        .unwrap_or(now);

    let memo = metadata
        .as_ref()
        .and_then(|meta| meta.memo.clone())
        .map(|memo| memo.into());

    if ingress_end < now + ingress_interval {
        return Err(Error::processing_construction_failed(&format!(
            "Ingress end should be at least one interval from the current time: Current time: {now}, End: {ingress_end}"
        )));
    }

    validate_ingress_window(now, ingress_start, ingress_end)?;

    // Every ingress message sent to the IC has an expiry timestamp until which the signature associated with that message is valid
    // To support a longer overall timeframe than one interval, we can send multiple ingress messages with two signable contents each
    let mut ingress_expiries = vec![];
    while ingress_start < ingress_end {
        ingress_expiries.push(ingress_start + ingress_interval);
        ingress_start +=
            ingress_interval.saturating_sub(INGRESS_INTERVAL_OVERLAP.as_nanos() as u64);
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
        operations,
        created_at_time,
        memo,
        *ledger_id,
        sender_public_key,
        ingress_expiries,
    )
    .map_err(|err| Error::processing_construction_failed(&err))
}

pub fn construction_parse(
    transaction_string: String,
    transaction_is_signed: bool,
    currency: Currency,
) -> Result<ConstructionParseResponse, Error> {
    let (ingress_expiry_start, ingress_expiry_end, envelope_contents) = if transaction_is_signed {
        let signed_transaction = SignedTransaction::from_str(&transaction_string)
            .map_err(|err| Error::parsing_unsuccessful(&err))?;
        (
            signed_transaction.get_lowest_ingress_expiry(),
            signed_transaction.get_highest_ingress_expiry(),
            signed_transaction
                .envelopes
                .into_iter()
                .map(|envelope| envelope.content.into_owned())
                .collect(),
        )
    } else {
        let unsigned_transaction = UnsignedTransaction::from_str(&transaction_string)
            .map_err(|err| Error::parsing_unsuccessful(&err))?;
        (
            unsigned_transaction.get_lowest_ingress_expiry(),
            unsigned_transaction.get_highest_ingress_expiry(),
            unsigned_transaction.envelope_contents,
        )
    };

    handle_construction_parse(
        envelope_contents,
        currency,
        ingress_expiry_start,
        ingress_expiry_end,
        transaction_is_signed,
    )
    .map_err(|err| Error::processing_construction_failed(&err))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::utils::utils::icrc1_operation_to_rosetta_core_operations;
    use crate::construction_api::types::CanisterMethodName;
    use crate::construction_api::utils::build_icrc1_transaction_from_canister_method_args;
    use candid::Encode;
    use ic_agent::Identity;
    use ic_agent::agent::EnvelopeContent;
    use ic_icrc_rosetta_client::RosettaClient;
    use ic_icrc_rosetta_runner::DEFAULT_DECIMAL_PLACES;
    use ic_icrc_rosetta_runner::DEFAULT_TOKEN_SYMBOL;
    use ic_icrc1_test_utils::DEFAULT_TRANSFER_FEE;
    use ic_icrc1_test_utils::KeyPairGenerator;
    use ic_icrc1_test_utils::LedgerEndpointArg;
    use ic_icrc1_test_utils::construction_payloads_request_metadata;
    use ic_icrc1_test_utils::minter_identity;
    use ic_icrc1_test_utils::valid_transactions_strategy;
    use ic_icrc1_tokens_u256::U256;
    use ic_ledger_canister_core::ledger::LedgerTransaction;
    use proptest::prelude::any;
    use proptest::proptest;
    use proptest::strategy::Strategy;
    use proptest::test_runner::Config as TestRunnerConfig;
    use proptest::test_runner::TestRunner;
    use rosetta_core::models::RosettaSupportedKeyPair;
    use rosetta_core::models::{Ed25519KeyPair, Secp256k1KeyPair};

    const NUM_TEST_CASES: u32 = 100;
    const NUM_BLOCKS: usize = 1;

    const HOUR_NANOS: u64 = 60 * 60 * 1_000_000_000;
    // A realistic "now" (~2023) that is well away from the u64 boundary.
    const NOW_NANOS: u64 = 1_700_000_000 * 1_000_000_000;

    // A window whose span exceeds the documented 24h bound would make the loop
    // build a huge list of ingress expiries, so it is rejected before the loop.
    #[test]
    fn oversized_ingress_window_is_rejected() {
        assert!(
            validate_ingress_window(NOW_NANOS, NOW_NANOS, NOW_NANOS + 48 * HOUR_NANOS).is_err()
        );
    }

    // A near-zero start together with a near-`u64::MAX` end spans almost the
    // entire u64 range; that enormous span is rejected (it would otherwise
    // iterate billions of times).
    #[test]
    fn unbounded_ingress_span_is_rejected() {
        assert!(validate_ingress_window(NOW_NANOS, 0, u64::MAX).is_err());
    }

    // A window ending at (near) `u64::MAX` has a small span but an end far in the
    // future; without the future bound the loop counter would wrap past
    // `u64::MAX` and never terminate. The future bound rejects it.
    #[test]
    fn near_u64_max_ingress_window_is_rejected() {
        assert!(
            validate_ingress_window(NOW_NANOS, u64::MAX - 50 * 1_000_000_000, u64::MAX).is_err()
        );
    }

    // Negative control: a realistic window (5 minutes ahead of now) is accepted.
    #[test]
    fn valid_ingress_window_is_accepted() {
        assert!(
            validate_ingress_window(NOW_NANOS, NOW_NANOS, NOW_NANOS + 5 * 60 * 1_000_000_000)
                .is_ok()
        );
    }

    // Boundary: a window of exactly 24h ending exactly 24h from now is accepted,
    // one nanosecond more is rejected.
    #[test]
    fn ingress_window_boundary_is_inclusive() {
        let max = MAX_INGRESS_WINDOW.as_nanos() as u64;
        assert!(validate_ingress_window(NOW_NANOS, NOW_NANOS, NOW_NANOS + max).is_ok());
        assert!(validate_ingress_window(NOW_NANOS, NOW_NANOS, NOW_NANOS + max + 1).is_err());
    }

    #[test]
    fn near_u64_max_ingress_start_is_rejected_without_panic() {
        let metadata = ConstructionPayloadsRequestMetadata {
            memo: None,
            ingress_start: Some(u64::MAX - 10),
            ingress_end: None,
            created_at_time: None,
        };
        let err = construction_payloads(
            vec![],
            Some(metadata),
            &Principal::anonymous(),
            vec![],
            SystemTime::UNIX_EPOCH + std::time::Duration::from_nanos(NOW_NANOS),
        )
        .unwrap_err();
        assert_eq!(
            err.0.message,
            "Processing of the construction request failed."
        );
        assert!(
            err.0
                .description
                .unwrap()
                .contains("ingress_end must not be more than"),
        );
    }

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

    fn assert_parse_response(
        parse_response: ConstructionParseResponse,
        operations: Vec<Operation>,
        metadata: ConstructionPayloadsRequestMetadata,
        now: u64,
    ) {
        let received_metadata =
            ConstructionPayloadsRequestMetadata::try_from(parse_response.metadata).unwrap();

        parse_response.operations.into_iter().for_each(|operation| {
            assert!(
                operations.contains(&operation),
                "{}",
                format!("Operation {operation:?} not found in operations {operations:?}")
            )
        });

        if let Some(created_at_time) = metadata.created_at_time {
            assert_eq!(received_metadata.created_at_time.unwrap(), created_at_time);
        } else {
            assert!(received_metadata.created_at_time.unwrap() >= now);
        }
        assert_eq!(received_metadata.memo, metadata.memo);

        if let Some(ingress_start) = metadata.ingress_start {
            assert_eq!(received_metadata.ingress_start.unwrap(), ingress_start);
        } else {
            assert!(received_metadata.ingress_start.unwrap() >= now);
            assert!(
                received_metadata.ingress_start.unwrap()
                    <= now
                        + (ic_limits::MAX_INGRESS_TTL - ic_limits::PERMITTED_DRIFT).as_nanos()
                            as u64
            );
        }

        if let Some(ingress_end) = metadata.ingress_end {
            // Ingress end should be within an interval from the set ingress_end.
            assert!(received_metadata.ingress_end.unwrap() >= ingress_end);
            assert!(
                received_metadata.ingress_end.unwrap()
                    <= ingress_end
                        + (ic_limits::MAX_INGRESS_TTL - ic_limits::PERMITTED_DRIFT).as_nanos()
                            as u64
            );
        } else {
            // If no ingress_end is set, it should be within an interval from the ingress start time.
            assert!(
                received_metadata.ingress_end.unwrap() >= received_metadata.ingress_start.unwrap()
            );
            assert_eq!(
                received_metadata.ingress_end.unwrap(),
                received_metadata.ingress_start.unwrap()
                    + (ic_limits::MAX_INGRESS_TTL - ic_limits::PERMITTED_DRIFT
                        + INGRESS_INTERVAL_OVERLAP)
                        .as_nanos() as u64
            );
        }
    }

    proptest! {
        #[test]
        fn test_construction_derive_ed(seed in any::<u64>()) {
            let key_pair = Ed25519KeyPair::generate(seed);
            call_construction_derive(&key_pair);
        }

        #[test]
        fn test_construction_derive_sepc(seed in any::<u64>()) {
            let key_pair = Secp256k1KeyPair::generate(seed);
            call_construction_derive(&key_pair);
        }
    }

    #[test]
    fn test_construction_parse() {
        let mut runner = TestRunner::new(TestRunnerConfig {
            max_shrink_iters: 0,
            cases: NUM_TEST_CASES,
            ..Default::default()
        });
        runner
            .run(
                &(
                    valid_transactions_strategy(
                        minter_identity().into(),
                        DEFAULT_TRANSFER_FEE,
                        NUM_BLOCKS,
                        SystemTime::now(),
                    )
                    .no_shrink(),
                    construction_payloads_request_metadata().no_shrink(),
                ),
                |(args_with_caller, construction_payloads_request_metadata)| {
                    for arg_with_caller in args_with_caller.into_iter() {
                        let currency = Currency {
                            symbol: DEFAULT_TOKEN_SYMBOL.to_owned(),
                            decimals: DEFAULT_DECIMAL_PLACES as u32,
                            metadata: None,
                        };
                        let icrc1_transaction: ic_icrc1::Transaction<U256> = arg_with_caller
                            .to_transaction(minter_identity().sender().unwrap().into());
                        let fee = match icrc1_transaction.operation {
                            ic_icrc1::Operation::Transfer { fee, .. } => fee,
                            ic_icrc1::Operation::Approve { fee, .. } => fee,
                            _ => panic!("Invalid operation"),
                        };
                        let rosetta_core_operations = icrc1_operation_to_rosetta_core_operations(
                            icrc1_transaction.clone().operation.into(),
                            currency.clone(),
                            fee.map(|fee| fee.into()),
                        )
                        .unwrap();

                        let ConstructionPreprocessResponse {
                            required_public_keys,
                            ..
                        } = construction_preprocess(rosetta_core_operations.clone()).unwrap();

                        assert_eq!(
                            required_public_keys,
                            Some(vec![
                                icrc_ledger_types::icrc1::account::Account::from(
                                    arg_with_caller.caller.sender().unwrap()
                                )
                                .into()
                            ])
                        );

                        let payloads_metadata: ConstructionPayloadsRequestMetadata =
                            construction_payloads_request_metadata
                                .clone()
                                .try_into()
                                .unwrap();

                        let now = SystemTime::now();

                        let construction_payloads_response = construction_payloads(
                            rosetta_core_operations.clone(),
                            Some(payloads_metadata.clone()),
                            &PrincipalId::new_anonymous().0,
                            vec![(&arg_with_caller.caller).into()],
                            now,
                        );

                        let now = now
                            .duration_since(SystemTime::UNIX_EPOCH)
                            .unwrap()
                            .as_nanos() as u64;
                        let ingress_interval = (ic_limits::MAX_INGRESS_TTL
                            - ic_limits::PERMITTED_DRIFT)
                            .as_nanos() as u64;
                        match (
                            payloads_metadata.ingress_end,
                            payloads_metadata.ingress_start,
                        ) {
                            (Some(ingress_end), Some(ingress_start)) => {
                                if ingress_start >= ingress_end {
                                    assert!(construction_payloads_response.is_err());
                                    continue;
                                }
                                if ingress_end < now + ingress_interval {
                                    assert!(construction_payloads_response.is_err());
                                    continue;
                                }
                            }
                            (Some(ingress_end), _) => {
                                if ingress_end < now + ingress_interval {
                                    assert!(construction_payloads_response.is_err());
                                    continue;
                                }
                            }
                            (_, Some(ingress_start)) => {
                                let ingress_end = ingress_start + ingress_interval;
                                if ingress_end < now + ingress_interval {
                                    assert!(construction_payloads_response.is_err());
                                    continue;
                                }
                            }
                            (_, _) => {}
                        }
                        // Windows wider than the permitted maximum, or with an
                        // ingress_end too far in the future, are rejected before
                        // the loop.
                        let eff_start = payloads_metadata.ingress_start.unwrap_or(now);
                        let eff_end = payloads_metadata
                            .ingress_end
                            .unwrap_or(eff_start + ingress_interval);
                        if validate_ingress_window(now, eff_start, eff_end).is_err() {
                            assert!(construction_payloads_response.is_err());
                            continue;
                        }
                        let construction_parse_response = construction_parse(
                            construction_payloads_response
                                .clone()
                                .unwrap()
                                .unsigned_transaction,
                            false,
                            currency.clone(),
                        )
                        .unwrap();

                        assert_parse_response(
                            construction_parse_response.clone(),
                            rosetta_core_operations.clone(),
                            payloads_metadata,
                            now,
                        );

                        let signatures = RosettaClient::sign_transaction(
                            &arg_with_caller.caller,
                            construction_payloads_response.clone().unwrap(),
                        )
                        .unwrap();

                        let ConstructionCombineResponse { signed_transaction } =
                            construction_combine(
                                construction_payloads_response.unwrap().unsigned_transaction,
                                signatures,
                            )
                            .unwrap();

                        let construction_parse_response =
                            construction_parse(signed_transaction, true, currency.clone()).unwrap();

                        assert_parse_response(
                            construction_parse_response.clone(),
                            rosetta_core_operations,
                            construction_payloads_request_metadata
                                .clone()
                                .try_into()
                                .unwrap(),
                            now,
                        );
                    }
                    Ok(())
                },
            )
            .unwrap();
    }

    #[test]
    fn test_construction_hash() {
        let mut runner = TestRunner::new(TestRunnerConfig {
            max_shrink_iters: 0,
            cases: NUM_TEST_CASES,
            ..Default::default()
        });
        runner
            .run(
                &(valid_transactions_strategy(
                    minter_identity().into(),
                    DEFAULT_TRANSFER_FEE,
                    NUM_BLOCKS,
                    SystemTime::now(),
                )
                .no_shrink(),),
                |(args_with_caller,)| {
                    for arg_with_caller in args_with_caller.into_iter() {
                        let currency = Currency {
                            symbol: DEFAULT_TOKEN_SYMBOL.to_owned(),
                            decimals: DEFAULT_DECIMAL_PLACES as u32,
                            metadata: None,
                        };

                        let ledger_transaction: ic_icrc1::Transaction<U256> = arg_with_caller
                            .to_transaction(minter_identity().sender().unwrap().into());

                        let canister_method_name = match ledger_transaction.operation {
                            ic_icrc1::Operation::Transfer { .. } => {
                                CanisterMethodName::Icrc1Transfer
                            }
                            ic_icrc1::Operation::Approve { .. } => CanisterMethodName::Icrc2Approve,
                            ic_icrc1::Operation::Mint { .. } => CanisterMethodName::Icrc1Transfer,
                            ic_icrc1::Operation::Burn { .. } => CanisterMethodName::Icrc1Transfer,
                            ic_icrc1::Operation::FeeCollector { .. } => {
                                panic!("FeeCollector107 not implemented")
                            }
                            ic_icrc1::Operation::AuthorizedMint { .. }
                            | ic_icrc1::Operation::AuthorizedBurn { .. } => continue,
                        };
                        let args = match arg_with_caller.arg {
                            LedgerEndpointArg::TransferArg(arg) => Encode!(&arg),
                            LedgerEndpointArg::ApproveArg(arg) => Encode!(&arg),
                            LedgerEndpointArg::TransferFromArg(arg) => Encode!(&arg),
                        }
                        .unwrap();

                        let icrc1_transaction = build_icrc1_transaction_from_canister_method_args(
                            &canister_method_name,
                            &arg_with_caller.caller.sender().unwrap(),
                            args,
                        )
                        .unwrap();

                        assert_eq!(
                            icrc1_transaction.hash(),
                            ledger_transaction.clone().hash().as_slice()
                        );

                        let fee = match ledger_transaction.operation {
                            ic_icrc1::Operation::Transfer { fee, .. } => fee,
                            ic_icrc1::Operation::Approve { fee, .. } => fee,
                            _ => panic!("Invalid operation"),
                        };
                        let rosetta_core_operations = icrc1_operation_to_rosetta_core_operations(
                            ledger_transaction.clone().operation.into(),
                            currency.clone(),
                            fee.map(|fee| fee.into()),
                        )
                        .unwrap();

                        let construction_payloads_response = construction_payloads(
                            rosetta_core_operations.clone(),
                            None,
                            &PrincipalId::new_anonymous().0,
                            vec![(&arg_with_caller.caller).into()],
                            SystemTime::now(),
                        );

                        let signatures = RosettaClient::sign_transaction(
                            &arg_with_caller.caller,
                            construction_payloads_response.clone().unwrap(),
                        )
                        .unwrap();

                        let ConstructionCombineResponse { signed_transaction } =
                            construction_combine(
                                construction_payloads_response.unwrap().unsigned_transaction,
                                signatures,
                            )
                            .unwrap();

                        let ConstructionHashResponse {
                            transaction_identifier,
                            ..
                        } = construction_hash(signed_transaction.clone()).unwrap();

                        let signed_transaction =
                            SignedTransaction::from_str(&signed_transaction).unwrap();

                        let ledger_icrc1_transaction =
                            build_icrc1_transaction_from_canister_method_args(
                                &canister_method_name,
                                &arg_with_caller.caller.sender().unwrap(),
                                match signed_transaction
                                    .envelopes
                                    .first()
                                    .unwrap()
                                    .content
                                    .clone()
                                    .into_owned()
                                {
                                    EnvelopeContent::Call { arg, .. } => arg.clone(),
                                    _ => panic!("Invalid envelope content"),
                                },
                            )
                            .unwrap();

                        assert_eq!(
                            hex::decode(transaction_identifier.hash).unwrap(),
                            ledger_icrc1_transaction.hash().to_vec()
                        );
                    }
                    Ok(())
                },
            )
            .unwrap();
    }
}
