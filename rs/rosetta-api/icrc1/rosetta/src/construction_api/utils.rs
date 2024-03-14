use super::types::{
    CanisterMethodName, ConstructionPayloadsRequestMetadata, EnvelopePair, SignedTransaction,
    UnsignedTransaction,
};
use crate::common::utils::utils::{
    icrc1_operation_to_rosetta_core_operations, rosetta_core_operations_to_icrc1_operation,
};
use crate::construction_api::types::ConstructionSubmitResponseMetadata;
use anyhow::{bail, Context};
use candid::{Decode, Encode, Principal};
use ic_agent::agent::{Envelope, EnvelopeContent};
use ic_rosetta_api::models::ConstructionParseResponse;
use icrc_ledger_agent::Icrc1Agent;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::{Memo, TransferArg};
use icrc_ledger_types::icrc2::approve::ApproveArgs;
use icrc_ledger_types::icrc2::transfer_from::TransferFromArgs;
use rosetta_core::objects::{Currency, Operation, PublicKey, Signature, SigningPayload};
use rosetta_core::response_types::ConstructionHashResponse;
use rosetta_core::response_types::{ConstructionCombineResponse, ConstructionPayloadsResponse};
use rosetta_core::{
    identifiers::TransactionIdentifier, response_types::ConstructionSubmitResponse,
};
use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::Arc;

fn build_serialized_bytes<T: serde::Serialize + std::fmt::Debug>(
    object: &T,
) -> anyhow::Result<Vec<u8>> {
    let mut buf = vec![];
    ciborium::ser::into_writer(&object, &mut buf)
        .with_context(|| format!("Failed to serialize object {:?}", object))?;
    Ok(buf)
}

// The Request id is linked to the EnvelopeContent and is the actual content of the request to the IC that needs to be signed to authenticate the caller
fn build_signable_payload(envelope_content: &EnvelopeContent) -> String {
    hex::encode(envelope_content.to_request_id().signable())
}

fn build_envelope_from_signature_and_envelope_content<'a>(
    signature: &Signature,
    envelope_content: EnvelopeContent,
) -> anyhow::Result<Envelope<'a>> {
    let envelope = Envelope {
        content: Cow::Owned(envelope_content),
        sender_pubkey: Some(signature.public_key.get_der_encoding()?),
        sender_sig: Some(hex::decode(&signature.hex_bytes)?),
        sender_delegation: None,
    };
    Ok(envelope)
}

pub async fn handle_construction_submit(
    signed_transaction: SignedTransaction<'_>,
    canister_id: Principal,
    icrc1_agent: Arc<Icrc1Agent>,
    currency: Currency,
) -> anyhow::Result<ConstructionSubmitResponse> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos() as u64;
    let valid_ingress_end: u64 =
        now.saturating_add(ic_constants::MAX_INGRESS_TTL.as_nanos() as u64);

    let lowest_ingress_expiry = signed_transaction.get_lowest_ingress_expiry();
    let highest_ingress_expiry = signed_transaction.get_highest_ingress_expiry();

    // We start at the highest ingress expiry and work our way down to the first ingress expiry that is currently valid
    if let Some(EnvelopePair {
        call_envelope,
        read_state_envelope,
    }) = signed_transaction
        .envelope_pairs
        .into_iter()
        .filter(|envelope_pair| {
            // We need to make sure that the envelope we have currently selected is valid
            // The envelope is valid if it expires within the next INGRESS INTERVAL
            envelope_pair.call_envelope.content.ingress_expiry() <= valid_ingress_end
                && envelope_pair.call_envelope.content.ingress_expiry() >= now
        })
        .max_by_key(|envelope_pair| envelope_pair.call_envelope.content.ingress_expiry())
    {
        // Forward the call envelope to the IC
        let call_envelope_serialized = build_serialized_bytes(&call_envelope)?;
        icrc1_agent
            .agent
            .update_signed(canister_id, call_envelope_serialized)
            .await
            .context("Failed to send EnvelopeContent::Call.")?;

        // Take the request id from the previous call envelope and wait until the IC has processes the content of the call envelope
        let read_state_envelope_serialized = build_serialized_bytes(&read_state_envelope)?;

        let response = icrc1_agent
            .agent
            .wait_signed(
                &call_envelope.content.to_request_id(),
                canister_id,
                read_state_envelope_serialized,
            )
            .await?;

        let transaction_identifier = TransactionIdentifier {
            hash: build_transaction_hash_from_envelope_content(&call_envelope.content)?,
        };

        let rosetta_core_operations: Vec<Operation> = handle_construction_parse(
            vec![call_envelope.content.into_owned()],
            currency,
            lowest_ingress_expiry,
            highest_ingress_expiry,
        )?
        .operations;

        let metadata = ConstructionSubmitResponseMetadata::new(rosetta_core_operations, response)?;

        return Ok(ConstructionSubmitResponse {
            transaction_identifier,
            metadata: Some(metadata.try_into()?),
        });
    }

    bail!("No valid envelopes found in the signed transaction");
}

// Tries to convert a CanisterMethodArg into an icrc1::Transaction
// Fails if the underlying method is not supported by icrc1 ledgers
pub fn build_icrc1_transaction_from_canister_method_args(
    canister_method_name: &CanisterMethodName,
    caller: &Principal,
    candid_bytes: Vec<u8>,
) -> anyhow::Result<crate::common::storage::types::IcrcTransaction> {
    Ok(match canister_method_name {
        CanisterMethodName::Icrc2Approve => {
            let ApproveArgs {
                spender,
                amount,
                from_subaccount,
                fee,
                expected_allowance,
                expires_at,
                memo,
                created_at_time,
            } = Decode!(&candid_bytes, ApproveArgs).with_context(|| {
                format!("Could not decode approve args from: {:?} ", candid_bytes)
            })?;

            let operation = crate::common::storage::types::IcrcOperation::Approve {
                spender,
                amount,
                from: Account {
                    owner: *caller,
                    subaccount: from_subaccount,
                },
                fee,
                expected_allowance,
                expires_at,
            };
            crate::common::storage::types::IcrcTransaction {
                operation,
                memo,
                created_at_time,
            }
        }
        CanisterMethodName::Icrc2TransferFrom => {
            let TransferFromArgs {
                to,
                amount,
                from,
                spender_subaccount,
                fee,
                memo,
                created_at_time,
            } = Decode!(&candid_bytes, TransferFromArgs).with_context(|| {
                format!(
                    "Could not decode transfer from args from: {:?} ",
                    candid_bytes
                )
            })?;

            let operation = crate::common::storage::types::IcrcOperation::Transfer {
                to,
                amount,
                from,
                spender: Some(Account {
                    owner: *caller,
                    subaccount: spender_subaccount,
                }),
                fee,
            };
            crate::common::storage::types::IcrcTransaction {
                operation,
                memo,
                created_at_time,
            }
        }
        CanisterMethodName::Icrc1Transfer => {
            let TransferArg {
                to,
                amount,
                from_subaccount,
                fee,
                memo,
                created_at_time,
            } = Decode!(&candid_bytes, TransferArg).with_context(|| {
                format!("Could not decode transfer args from: {:?} ", candid_bytes)
            })?;

            let operation = crate::common::storage::types::IcrcOperation::Transfer {
                to,
                amount,
                from: Account {
                    owner: *caller,
                    subaccount: from_subaccount,
                },
                spender: None,
                fee,
            };
            crate::common::storage::types::IcrcTransaction {
                operation,
                memo,
                created_at_time,
            }
        }
    })
}

pub fn build_transaction_hash_from_envelope_content(
    envelope_content: &EnvelopeContent,
) -> anyhow::Result<String> {
    // First we can derive the canister method args and the caller of the function from the envelope content
    let canister_method_name = CanisterMethodName::new_from_envelope_content(envelope_content)?;

    let candid_encoded_bytes = match envelope_content {
        EnvelopeContent::Call { arg, .. } => arg.clone(),
        _ => bail!(
            "Wrong EnvelopeContent type, expected EnvelopeContent::Call, got {:?}",
            envelope_content
        ),
    };

    // Then we can derive the icrc1 transaction from the canister method args and the caller
    let icrc1_transaction = build_icrc1_transaction_from_canister_method_args(
        &canister_method_name,
        envelope_content.sender(),
        candid_encoded_bytes,
    )?;

    Ok(format!("{:?}", icrc1_transaction.hash().to_vec()))
}

pub fn build_icrc1_ledger_canister_method_args(
    operation: crate::common::storage::types::IcrcOperation,
    memo: Option<Memo>,
    created_at_time: u64,
) -> anyhow::Result<Vec<u8>> {
    match operation {
        crate::common::storage::types::IcrcOperation::Burn { .. } => {
            bail!("Burn Operation not supported")
        }
        crate::common::storage::types::IcrcOperation::Mint { .. } => {
            bail!("Mint Operation not supported")
        }
        crate::common::storage::types::IcrcOperation::Approve {
            from,
            spender,
            amount,
            expected_allowance,
            expires_at,
            fee,
        } => Encode!(&ApproveArgs {
            from_subaccount: from.subaccount,
            spender,
            amount,
            expected_allowance,
            expires_at,
            fee,
            memo: memo.clone(),
            created_at_time: Some(created_at_time),
        }),
        crate::common::storage::types::IcrcOperation::Transfer {
            from,
            to,
            amount,
            fee,
            spender,
        } => {
            if let Some(spender) = spender {
                Encode!(&TransferFromArgs {
                    spender_subaccount: spender.subaccount,
                    from,
                    to,
                    fee,
                    created_at_time: Some(created_at_time),
                    memo,
                    amount,
                })
            } else {
                Encode!(&TransferArg {
                    from_subaccount: from.subaccount,
                    to,
                    fee,
                    created_at_time: Some(created_at_time),
                    memo,
                    amount,
                })
            }
        }
    }
    .context("Unable to encode canister method args")
}

pub fn extract_caller_principal_from_rosetta_core_operation(
    operations: Vec<rosetta_core::objects::Operation>,
) -> anyhow::Result<Principal> {
    let icrc1_operation = rosetta_core_operations_to_icrc1_operation(operations)?;
    extract_caller_principal_from_icrc1_ledger_operation(&icrc1_operation)
}

/// This function takes in an icrc1 ledger operation and returns the principal that needs to call the icrc1 ledger for the given operation to be successful
fn extract_caller_principal_from_icrc1_ledger_operation(
    operation: &crate::common::storage::types::IcrcOperation,
) -> anyhow::Result<Principal> {
    Ok(match operation {
        crate::common::storage::types::IcrcOperation::Burn { .. } => {
            bail!("Burn Operation not supported")
        }
        crate::common::storage::types::IcrcOperation::Mint { .. } => {
            bail!("Mint Operation not supported")
        }
        crate::common::storage::types::IcrcOperation::Approve { from, .. } => from.owner,
        crate::common::storage::types::IcrcOperation::Transfer { from, spender, .. } => {
            spender.unwrap_or(*from).owner
        }
    })
}

pub fn handle_construction_hash(
    signed_transaction: SignedTransaction,
) -> anyhow::Result<ConstructionHashResponse> {
    if signed_transaction.envelope_pairs.is_empty() {
        bail!("No valid envelopes found in the signed transaction");
    }

    // There are multiple envelopes in the signed transaction, but we only support one icrc1 ledger transaction per signed transaction
    // If there are multiple different icrc1 ledger transactions in the signed transaction, we return an error
    let mut tx_hashes = HashSet::new();
    for envelope_pair in signed_transaction.envelope_pairs {
        let transaction_hash =
            build_transaction_hash_from_envelope_content(&envelope_pair.call_envelope.content)?;
        tx_hashes.insert(transaction_hash);
    }

    // We expect only one icrc1 ledger transaction in the signed transaction
    if tx_hashes.len() > 1 {
        bail!("Only one icrc1 ledger transaction is supported per signed transaction. Found more than one icrc1 ledger transaction.");
    }

    Ok(ConstructionHashResponse {
        transaction_identifier: TransactionIdentifier {
            hash: tx_hashes.into_iter().next().unwrap(),
        },
        metadata: serde_json::map::Map::new(),
    })
}

pub fn handle_construction_combine(
    unsigned_transaction: UnsignedTransaction,
    signatures: Vec<Signature>,
) -> anyhow::Result<ConstructionCombineResponse> {
    if unsigned_transaction.envelope_contents.len() != signatures.len() {
        bail!("Number of signatures does not match number of envelopes");
    }

    let mut request_id_to_signature = std::collections::HashMap::new();
    for signature in &signatures {
        if request_id_to_signature.contains_key(&signature.signing_payload.hex_bytes) {
            bail!("Duplicate request_id found in signatures: {:?}", signature);
        }

        request_id_to_signature.insert(signature.signing_payload.hex_bytes.clone(), signature);
    }

    let mut envelope_pairs = vec![];
    for envelope_content in &unsigned_transaction.envelope_contents {
        if matches!(envelope_content, EnvelopeContent::Call { .. }) {
            let request_id = build_signable_payload(envelope_content);
            let call_signature = request_id_to_signature
                .get(&request_id)
                .context("Failed to find signature for request id")?;

            let read_state_envelope_content = build_read_state_envelope_content(
                envelope_content.sender(),
                envelope_content.ingress_expiry(),
                envelope_content.to_request_id(),
            )?;

            let read_state_signature = request_id_to_signature
                .get(&build_signable_payload(&read_state_envelope_content))
                .context("Failed to find signature for read state request id")?;

            let call_envelope = build_envelope_from_signature_and_envelope_content(
                call_signature,
                (*envelope_content).clone(),
            )?;

            let read_state_envelope = build_envelope_from_signature_and_envelope_content(
                read_state_signature,
                read_state_envelope_content,
            )?;

            envelope_pairs.push(EnvelopePair {
                call_envelope,
                read_state_envelope,
            });
        }
    }

    Ok(ConstructionCombineResponse {
        signed_transaction: hex::encode(serde_cbor::to_vec(&SignedTransaction { envelope_pairs })?),
    })
}

fn build_read_state_envelope_content(
    sender: &Principal,
    ingress_expiry: u64,
    request_id: ic_agent::RequestId,
) -> anyhow::Result<EnvelopeContent> {
    // This code snipped was taken from ic_agent::agent::Agent::read_state_raw
    // The ReadState envelope content is derived from the original EnvelopeContent that contained the Canister Call
    let paths: Vec<Vec<ic_certification::Label>> =
        vec![vec!["request_status".into(), request_id.to_vec().into()]];
    Ok(EnvelopeContent::ReadState {
        sender: *sender,
        paths,
        ingress_expiry,
    })
}

fn build_payloads_from_call_envelope_content(
    call_envelope_content: EnvelopeContent,
    sender_public_key: &PublicKey,
) -> anyhow::Result<(Vec<SigningPayload>, Vec<EnvelopeContent>)> {
    let mut envelope_contents = Vec::new();
    let mut signing_payloads = Vec::new();
    if !matches!(call_envelope_content, EnvelopeContent::Call { .. }) {
        bail!(
            "Wrong EnvelopeContent type, expected EnvelopeContent::Call, got {:?}",
            call_envelope_content
        );
    };

    // This is the payload that needs to be signed for the update call to the Canister on the IC
    let signer_account = Account::from(*call_envelope_content.sender());

    // We also need to sign the read state of the update call to the Canister on the IC
    // When one makes a request to the IC with an EnvelopeContent one first receives an ID for the request back from the IC
    // This ID can be used to continously ask the IC whether there has been any progress to their request that corresponds to that ID
    // If that is the case the IC will respond back with the actual content of the response from the Canister endpoint
    // The ReadState envelope content is derived from the original EnvelopeContent that contained the Canister Call
    let read_state_envelope_content = build_read_state_envelope_content(
        call_envelope_content.sender(),
        call_envelope_content.ingress_expiry(),
        call_envelope_content.to_request_id(),
    )?;

    let call_payload = SigningPayload {
        address: None,
        account_identifier: Some(signer_account.into()),
        hex_bytes: build_signable_payload(&call_envelope_content),
        signature_type: Some(sender_public_key.curve_type.into()),
    };

    let read_state_payload = SigningPayload {
        address: None,
        account_identifier: Some(Account::from(*read_state_envelope_content.sender()).into()),
        hex_bytes: build_signable_payload(&read_state_envelope_content),
        signature_type: Some(sender_public_key.curve_type.into()),
    };

    // For every Canister Call there need to exist two EnvelopContents, one for the acutal content of the Canister Call and the other to read the response of the Canister
    signing_payloads.push(call_payload);
    envelope_contents.push(call_envelope_content);

    signing_payloads.push(read_state_payload);
    envelope_contents.push(read_state_envelope_content);

    Ok((signing_payloads, envelope_contents))
}

pub fn handle_construction_payloads(
    rosetta_core_operations: Vec<Operation>,
    created_at_time: u64,
    memo: Option<Memo>,
    canister_id: Principal,
    sender_public_key: PublicKey,
    ingress_expiries: Vec<u64>,
) -> anyhow::Result<ConstructionPayloadsResponse> {
    // Parse the canister method name from the operation type
    let canister_method_name =
        CanisterMethodName::new_from_rosetta_core_operations(&rosetta_core_operations)?;

    // First we need to convert the generic operations into icrc1 operations
    let icrc1_operation = rosetta_core_operations_to_icrc1_operation(rosetta_core_operations)?;

    let caller = extract_caller_principal_from_icrc1_ledger_operation(&icrc1_operation)?;

    // We can now build the canister method args used to call the icrc1 ledger
    let canister_method_args =
        build_icrc1_ledger_canister_method_args(icrc1_operation, memo, created_at_time)?;

    let mut signing_payloads = Vec::new();
    let mut envelope_contents = Vec::new();
    for (nonce, ingress_expiry) in ingress_expiries.iter().enumerate() {
        // Rosetta will send an envelope containing the update information to a replica
        let envelope_content = EnvelopeContent::Call {
            canister_id,
            method_name: canister_method_name.to_string(),
            arg: canister_method_args.clone(),
            nonce: Some(nonce.to_ne_bytes().to_vec()),
            sender: caller,
            ingress_expiry: *ingress_expiry,
        };

        // For every operation we create a call envelope and a read state envelope
        // For every envelope we create a signing payload
        let (sp, ec) =
            build_payloads_from_call_envelope_content(envelope_content, &sender_public_key)?;

        signing_payloads.extend(sp);
        envelope_contents.extend(ec);
    }

    Ok(ConstructionPayloadsResponse {
        unsigned_transaction: UnsignedTransaction { envelope_contents }.to_string(),
        payloads: signing_payloads,
    })
}

pub fn handle_construction_parse(
    envelope_contents: Vec<EnvelopeContent>,
    currency: Currency,
    ingress_expiry_start: Option<u64>,
    ingress_expiry_end: Option<u64>,
) -> anyhow::Result<ConstructionParseResponse> {
    let mut construction_parse_response = ConstructionParseResponse {
        operations: vec![],
        account_identifier_signers: None,
        metadata: None,
    };

    // Iterate over all Call EnvelopeContents as they are the only ones that contain the information we need to construct the rosetta core operations
    for envelope_content in envelope_contents.into_iter() {
        // First we can derive the canister method args and the caller of the function from the https update
        if let EnvelopeContent::Call { arg, .. } = &envelope_content {
            let canister_method_name =
                CanisterMethodName::new_from_envelope_content(&envelope_content)?;

            // Then we can derive the icrc1 transaction from the canister method args and the caller
            let icrc1_transaction = build_icrc1_transaction_from_canister_method_args(
                &canister_method_name,
                envelope_content.sender(),
                arg.clone(),
            )?;

            let fee = match &icrc1_transaction.operation {
                crate::common::storage::types::IcrcOperation::Transfer { fee, .. } => fee.clone(),
                crate::common::storage::types::IcrcOperation::Approve { fee, .. } => fee.clone(),
                _ => bail!(
                    "Operation type not supported: {:?}",
                    icrc1_transaction.operation
                ),
            };

            // For the response object we need to convert the icrc1 transaction to a rosetta core operation
            let rosetta_core_operations = icrc1_operation_to_rosetta_core_operations(
                icrc1_transaction.operation,
                currency.clone(),
                fee,
            )?;

            // Metadata stays the same for all transactions requested in the same batch.
            construction_parse_response.metadata = Some(
                ConstructionPayloadsRequestMetadata {
                    memo: icrc1_transaction
                        .memo
                        .map(|memo| memo.0.as_slice().to_vec()),
                    created_at_time: icrc1_transaction.created_at_time,
                    // The ingress start is the first ingress expiry set minus the ingress interval
                    ingress_start: ingress_expiry_start.map(|start| {
                        start
                            - (ic_constants::MAX_INGRESS_TTL - ic_constants::PERMITTED_DRIFT)
                                .as_nanos() as u64
                    }),
                    ingress_end: ingress_expiry_end,
                }
                .try_into()?,
            );

            let caller = Account::from(*envelope_content.sender()).into();
            construction_parse_response
                .operations
                .extend(rosetta_core_operations);

            construction_parse_response
                .account_identifier_signers
                .get_or_insert_with(Default::default)
                .push(caller);

            break;
        };
    }

    Ok(construction_parse_response)
}

#[cfg(test)]
mod test {
    use super::*;
    use candid::Nat;
    use ic_agent::Identity;
    use ic_icrc1_test_utils::minter_identity;
    use ic_icrc1_test_utils::valid_transactions_strategy;
    use ic_icrc1_test_utils::LedgerEndpointArg;
    use ic_icrc1_test_utils::DEFAULT_TRANSFER_FEE;
    use proptest::strategy::Strategy;
    use proptest::test_runner::Config as TestRunnerConfig;
    use proptest::test_runner::TestRunner;
    use std::time::SystemTime;

    const NUM_TEST_CASES: u32 = 10;
    const NUM_BLOCKS: usize = 10;

    #[test]
    fn test_transfer_arg_conversion() {
        let mut runner = TestRunner::new(TestRunnerConfig {
            max_shrink_iters: 0,
            cases: NUM_TEST_CASES,
            ..Default::default()
        });

        runner
            .run(
                &(valid_transactions_strategy(
                    Arc::new(minter_identity()),
                    DEFAULT_TRANSFER_FEE,
                    NUM_BLOCKS,
                    SystemTime::now(),
                )
                .no_shrink()),
                |args_with_caller| {
                    for arg_with_caller in args_with_caller.into_iter() {
                        let (canister_method_name, candid_bytes) = match &arg_with_caller.arg {
                            LedgerEndpointArg::TransferArg(args) => {
                                (CanisterMethodName::Icrc1Transfer, Encode!(&args).unwrap())
                            }
                            LedgerEndpointArg::ApproveArg(args) => {
                                (CanisterMethodName::Icrc2Approve, Encode!(&args).unwrap())
                            }
                        };

                        let icrc1_transaction = build_icrc1_transaction_from_canister_method_args(
                            &canister_method_name,
                            &arg_with_caller.caller.sender().unwrap(),
                            candid_bytes,
                        )
                        .unwrap();

                        match arg_with_caller.arg {
                            LedgerEndpointArg::TransferArg(args) => {
                                // ICRC Rosetta only supports transfer and approve operations, no burn or mint
                                match icrc1_transaction.operation {
                                    crate::common::storage::types::IcrcOperation::Transfer {
                                        to,
                                        amount,
                                        from,
                                        fee,
                                        ..
                                    } => {
                                        assert_eq!(to, args.to);
                                        assert_eq!(args.amount, amount);
                                        assert_eq!(
                                            from,
                                            Account {
                                                owner: arg_with_caller.caller.sender().unwrap(),
                                                subaccount: args.from_subaccount
                                            }
                                        );
                                        assert_eq!(fee.map(Nat::from), args.fee);
                                        assert_eq!(args.memo, icrc1_transaction.memo);
                                        assert_eq!(
                                            args.created_at_time,
                                            icrc1_transaction.created_at_time
                                        );
                                    }
                                    _ => panic!("Operation type mismatch"),
                                }
                            }
                            LedgerEndpointArg::ApproveArg(args) => {
                                // ICRC Rosetta only supports transfer and approve operations, no burn or mint
                                match icrc1_transaction.operation {
                                    crate::common::storage::types::IcrcOperation::Approve {
                                        spender,
                                        amount,
                                        from,
                                        fee,
                                        expected_allowance,
                                        expires_at,
                                    } => {
                                        assert_eq!(spender, args.spender);
                                        assert_eq!(amount, args.amount);
                                        assert_eq!(
                                            from,
                                            Account {
                                                owner: arg_with_caller.caller.sender().unwrap(),
                                                subaccount: args.from_subaccount
                                            }
                                        );
                                        assert_eq!(fee.map(Nat::from), args.fee);
                                        assert_eq!(
                                            expected_allowance.map(Nat::from),
                                            args.expected_allowance
                                        );
                                        assert_eq!(expires_at, args.expires_at);
                                        assert_eq!(icrc1_transaction.memo, args.memo);
                                        assert_eq!(
                                            icrc1_transaction.created_at_time,
                                            args.created_at_time
                                        );
                                    }
                                    _ => panic!("Operation type mismatch"),
                                }
                            }
                        }
                    }
                    Ok(())
                },
            )
            .unwrap();
    }
}
