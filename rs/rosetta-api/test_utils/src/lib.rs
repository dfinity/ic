use candid::{Decode, Encode};
use ic_canisters_http_types::{HttpRequest, HttpResponse};
use ic_icrc1_test_utils::KeyPairGenerator;
use ic_rosetta_api::convert::{
    from_hex, from_model_account_identifier, operations_to_requests, to_hex,
    to_model_account_identifier,
};
use ic_rosetta_api::models::amount::{signed_amount, tokens_to_amount};
use ic_rosetta_api::models::operation::OperationType;
use ic_rosetta_api::models::{
    ConstructionCombineResponse, ConstructionParseResponse, ConstructionPayloadsRequestMetadata,
    ConstructionPayloadsResponse, CurveType, PublicKey, Signature, SignatureType,
    SignedTransaction,
};
use ic_rosetta_api::models::{ConstructionSubmitResponse, Error as RosettaError};
use ic_rosetta_api::request::request_result::RequestResult;
use ic_rosetta_api::request::transaction_operation_results::TransactionOperationResults;
use ic_rosetta_api::request::transaction_results::TransactionResults;
use ic_rosetta_api::request::Request;
use ic_rosetta_api::request_types::{
    AddHotKey, ChangeAutoStakeMaturity, Disburse, Follow, ListNeurons, MergeMaturity, NeuronInfo,
    RegisterVote, RemoveHotKey, SetDissolveTimestamp, Spawn, Stake, StakeMaturity, StartDissolve,
    StopDissolve,
};
use ic_rosetta_api::transaction_id::TransactionIdentifier;
use ic_rosetta_api::{convert, errors, errors::ApiError, DEFAULT_TOKEN_SYMBOL};
use ic_state_machine_tests::{StateMachine, WasmResult};
use ic_types::{messages::Blob, time, CanisterId, PrincipalId};
use icp_ledger::{AccountIdentifier, BlockIndex, Operation, Tokens};
use rand::{seq::SliceRandom, thread_rng};
use rosetta_api_serv::RosettaApiHandle;
use rosetta_core::convert::principal_id_from_public_key;
pub use rosetta_core::models::Ed25519KeyPair as EdKeypair;
use rosetta_core::models::RosettaSupportedKeyPair;
use rosetta_core::models::Secp256k1KeyPair;
use serde_bytes::ByteBuf;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

pub mod rosetta_api_serv;

pub fn path_from_env(var: &str) -> PathBuf {
    std::fs::canonicalize(std::env::var(var).unwrap_or_else(|_| panic!("Unable to find {}", var)))
        .unwrap()
}

pub fn to_public_key<T: RosettaSupportedKeyPair>(keypair: &T) -> PublicKey {
    PublicKey {
        hex_bytes: keypair.hex_encode_pk(),
        curve_type: keypair.get_curve_type(),
    }
}

pub fn make_user_ed25519(seed: u64) -> (AccountIdentifier, EdKeypair, PublicKey, PrincipalId) {
    let kp = EdKeypair::generate(seed);
    let pid = kp.generate_principal_id().unwrap();
    let aid: AccountIdentifier = pid.into();
    let pb = to_public_key(&kp);
    (aid, kp, pb, pid)
}

pub fn make_user_ecdsa_secp256k1(
    seed: u64,
) -> (AccountIdentifier, Secp256k1KeyPair, PublicKey, PrincipalId) {
    let kp = Secp256k1KeyPair::generate(seed);
    let pid = kp.generate_principal_id().unwrap();
    let aid: AccountIdentifier = pid.into();
    let pb = to_public_key(&kp);
    (aid, kp, pb, pid)
}

pub struct RequestInfo<T: RosettaSupportedKeyPair> {
    pub request: Request,
    pub sender_keypair: Arc<T>,
}

pub async fn prepare_multiple_txn<T: RosettaSupportedKeyPair>(
    ros: &RosettaApiHandle,
    requests: &[RequestInfo<T>],
    accept_suggested_fee: bool,
    ingress_end: Option<u64>,
    created_at_time: Option<u64>,
) -> Result<(ConstructionPayloadsResponse, Tokens), RosettaError>
where
    Arc<T>: RosettaSupportedKeyPair,
{
    let mut all_ops = Vec::new();
    let mut dry_run_ops = Vec::new();
    let mut all_sender_account_ids = Vec::new();
    let mut all_sender_pks = Vec::new();
    let mut trans_fee_amount = None;
    let token_name = DEFAULT_TOKEN_SYMBOL;

    for request in requests {
        // first ask for the fee
        let mut fee_found = false;
        for o in Request::requests_to_operations(&[request.request.clone()], token_name).unwrap() {
            if o.type_.parse::<OperationType>().unwrap() == OperationType::Fee {
                fee_found = true;
            } else {
                dry_run_ops.push(o.clone());
            }
            all_ops.push(o);
        }

        match request.request.clone() {
            Request::Transfer(Operation::Transfer {
                from, fee, spender, ..
            }) => {
                if spender.is_some() {
                    panic!("TransferFrom operations are not supported here")
                }

                trans_fee_amount = Some(tokens_to_amount(fee, token_name).unwrap());
                all_sender_account_ids.push(to_model_account_identifier(&from));

                // just a sanity check
                assert!(fee_found, "There should be a fee op in operations");
            }
            Request::Stake(Stake { account, .. })
            | Request::StartDissolve(StartDissolve { account, .. })
            | Request::StopDissolve(StopDissolve { account, .. })
            | Request::SetDissolveTimestamp(SetDissolveTimestamp { account, .. })
            | Request::ChangeAutoStakeMaturity(ChangeAutoStakeMaturity { account, .. })
            | Request::AddHotKey(AddHotKey { account, .. })
            | Request::RemoveHotKey(RemoveHotKey { account, .. })
            | Request::Disburse(Disburse { account, .. })
            | Request::Spawn(Spawn { account, .. })
            | Request::RegisterVote(RegisterVote { account, .. })
            | Request::MergeMaturity(MergeMaturity { account, .. })
            | Request::StakeMaturity(StakeMaturity { account, .. })
            | Request::NeuronInfo(NeuronInfo { account, .. })
            | Request::ListNeurons(ListNeurons { account, .. })
            | Request::Follow(Follow { account, .. }) => {
                all_sender_account_ids.push(to_model_account_identifier(&account));
            }
            Request::Transfer(Operation::Burn { .. }) => {
                panic!("Burn operations are supported here")
            }
            Request::Transfer(Operation::Mint { .. }) => {
                panic!("Mint operations are supported here")
            }
            Request::Transfer(Operation::Approve { .. }) => {
                panic!("Approve operations are supported here")
            }
        };

        all_sender_pks.push(to_public_key(&request.sender_keypair));
    }

    all_sender_pks.sort();
    all_sender_pks.dedup();

    all_sender_account_ids.sort_by(compare_accounts);
    all_sender_account_ids.dedup();

    let pre_res = ros.construction_preprocess(dry_run_ops).await.unwrap()?;
    let mut res_keys = pre_res.required_public_keys.clone().unwrap();
    res_keys.sort_by(compare_accounts);
    assert_eq!(
        res_keys, all_sender_account_ids,
        "Preprocess should report that senders' pks are required"
    );

    let metadata_res = ros
        .construction_metadata(
            Some(pre_res.options.try_into().unwrap()),
            Some(all_sender_pks.clone()),
        )
        .await
        .unwrap()?;
    let dry_run_suggested_fee = metadata_res.suggested_fee.map(|mut suggested_fee| {
        assert_eq!(suggested_fee.len(), 1);
        suggested_fee.pop().unwrap()
    });
    let fee_icpts = Tokens::from_e8s(
        dry_run_suggested_fee
            .clone()
            .unwrap_or_else(|| tokens_to_amount(Tokens::default(), token_name).unwrap())
            .value
            .parse()
            .unwrap(),
    );

    if accept_suggested_fee {
        for o in &mut all_ops {
            if o.type_.parse::<OperationType>().unwrap() == OperationType::Fee {
                o.amount = Some(signed_amount(-(fee_icpts.get_e8s() as i128), token_name));
            }
        }
    } else {
        // we assume here that we've got a correct transaction; double check that the
        // fee really is what it should be.
        // Set Dissolve does not have a fee.
        assert_eq!(dry_run_suggested_fee, trans_fee_amount);
    }

    // now try with operations containing the correct fee
    let pre_res = ros
        .construction_preprocess(all_ops.clone())
        .await
        .unwrap()?;
    let mut res_keys = pre_res.required_public_keys.clone().unwrap();
    res_keys.sort_by(compare_accounts);
    assert_eq!(
        res_keys, all_sender_account_ids,
        "Preprocess should report that sender's pk is required"
    );
    let metadata_res = ros
        .construction_metadata(
            Some(pre_res.options.try_into().unwrap()),
            Some(all_sender_pks.clone()),
        )
        .await
        .unwrap()?;
    let suggested_fee = metadata_res.suggested_fee.clone().map(|mut suggested_fee| {
        assert_eq!(suggested_fee.len(), 1);
        suggested_fee.pop().unwrap()
    });

    let metadata = ConstructionPayloadsRequestMetadata::try_from(metadata_res.metadata)?;
    // The fee reported here should be the same as the one we got from dry run
    assert_eq!(suggested_fee, dry_run_suggested_fee);

    ros.construction_payloads(
        Some(ConstructionPayloadsRequestMetadata {
            memo: Some(0),
            ingress_end,
            created_at_time,
            ..metadata
        }),
        all_ops,
        Some(all_sender_pks),
    )
    .await
    .unwrap()
    .map(|resp| (resp, fee_icpts))
}

pub async fn prepare_txn<T: RosettaSupportedKeyPair>(
    ros: &RosettaApiHandle,
    operation: Operation,
    sender_keypair: Arc<T>,
    accept_suggested_fee: bool,
    ingress_end: Option<u64>,
    created_at_time: Option<u64>,
) -> Result<(ConstructionPayloadsResponse, Tokens), RosettaError>
where
    Arc<T>: RosettaSupportedKeyPair,
{
    prepare_multiple_txn(
        ros,
        &[RequestInfo {
            request: Request::Transfer(operation),
            sender_keypair,
        }],
        accept_suggested_fee,
        ingress_end,
        created_at_time,
    )
    .await
}

pub async fn sign_txn<T>(
    ros: &RosettaApiHandle,
    keypairs: &[Arc<T>],
    payloads: ConstructionPayloadsResponse,
) -> Result<ConstructionCombineResponse, RosettaError>
where
    Arc<T>: RosettaSupportedKeyPair,
{
    let mut keypairs_map = HashMap::new();
    for kp in keypairs {
        let pid = principal_id_from_public_key(&to_public_key(kp)).unwrap();
        let acc = AccountIdentifier::from(pid);
        keypairs_map.insert(acc, Arc::clone(kp));
    }

    let mut signatures: Vec<Signature> = payloads
        .payloads
        .into_iter()
        .map(|p| {
            // Note: if we can't find the right key pair, just use the first one. This is
            // necessary for test_wrong_key().
            let keypair = keypairs_map
                .get(
                    &from_model_account_identifier(p.account_identifier.as_ref().unwrap()).unwrap(),
                )
                .cloned()
                .unwrap_or_else(|| Arc::clone(&keypairs[0]));
            let bytes = from_hex(&p.hex_bytes).unwrap();
            let signature_bytes = keypair.sign(&bytes);
            let hex_bytes = to_hex(&signature_bytes);
            Signature {
                signing_payload: p,
                public_key: to_public_key(&keypair),
                signature_type: match keypair.get_curve_type() {
                    CurveType::Edwards25519 => Ok(SignatureType::Ed25519),
                    CurveType::Secp256K1 => Ok(SignatureType::Ecdsa),
                    sig_type => Err(ApiError::InvalidRequest(
                        false,
                        format!("Sginature Type {} not supported byt rosetta", sig_type).into(),
                    )),
                }
                .unwrap(),
                hex_bytes,
            }
        })
        .collect();

    // The order of signatures shouldn't matter.
    let mut rng = thread_rng();
    signatures.shuffle(&mut rng);

    ros.construction_combine(payloads.unsigned_transaction, signatures)
        .await
        .unwrap()
}

// If accept_suggested_fee is false, then Transfer needs to contain a correct
// fee. Otherwise the fee value will be ignored and set to whatever ledger
// canister wants. In such case we don't do checks if the transaction
// created matches the one requested.
pub async fn do_txn<T: RosettaSupportedKeyPair>(
    ros: &RosettaApiHandle,
    sender_keypair: Arc<T>,
    operation: Operation,
    accept_suggested_fee: bool,
    ingress_end: Option<u64>,
    created_at_time: Option<u64>,
) -> Result<
    (
        TransactionIdentifier,
        TransactionResults,
        Tokens, // charged fee
    ),
    RosettaError,
>
where
    Arc<T>: RosettaSupportedKeyPair,
{
    do_multiple_txn(
        ros,
        &[RequestInfo {
            request: Request::Transfer(operation),
            sender_keypair,
        }],
        accept_suggested_fee,
        ingress_end,
        created_at_time,
    )
    .await
}

// the 'internal' version returning TransactionResults.
pub async fn do_multiple_txn<T: RosettaSupportedKeyPair>(
    ros: &RosettaApiHandle,
    requests: &[RequestInfo<T>],
    accept_suggested_fee: bool,
    ingress_end: Option<u64>,
    created_at_time: Option<u64>,
) -> Result<
    (
        TransactionIdentifier,
        TransactionResults,
        Tokens, // charged fee
    ),
    RosettaError,
>
where
    Arc<T>: RosettaSupportedKeyPair,
{
    match do_multiple_txn_submit(
        ros,
        requests,
        accept_suggested_fee,
        ingress_end,
        created_at_time,
    )
    .await
    {
        Ok((submit_res, charged_fee)) => {
            let results = convert::from_transaction_operation_results(
                submit_res.metadata.try_into().unwrap(),
                DEFAULT_TOKEN_SYMBOL,
            )
            .expect("Couldn't convert metadata to TransactionResults");
            if let Some(RequestResult {
                _type: Request::Transfer(_),
                transaction_identifier,
                ..
            }) = results.operations.last()
            {
                assert_eq!(
                    submit_res.transaction_identifier,
                    transaction_identifier.clone().unwrap().into()
                );
            }
            Ok((
                submit_res.transaction_identifier.into(),
                results,
                charged_fee,
            ))
        }
        Err(e) => Err(e),
    }
}

// the 'external' version returning TransactionOperationResults.
pub async fn do_multiple_txn_external<T: RosettaSupportedKeyPair>(
    ros: &RosettaApiHandle,
    requests: &[RequestInfo<T>],
    accept_suggested_fee: bool,
    ingress_end: Option<u64>,
    created_at_time: Option<u64>,
) -> Result<
    (
        TransactionIdentifier,
        TransactionOperationResults,
        Tokens, // charged fee
    ),
    RosettaError,
>
where
    Arc<T>: RosettaSupportedKeyPair,
{
    match do_multiple_txn_submit(
        ros,
        requests,
        accept_suggested_fee,
        ingress_end,
        created_at_time,
    )
    .await
    {
        Ok((submit_res, charged_fee)) => Ok((
            submit_res.transaction_identifier.into(),
            submit_res.metadata.try_into().unwrap(),
            charged_fee,
        )),
        Err(e) => Err(e),
    }
}

async fn do_multiple_txn_submit<T: RosettaSupportedKeyPair>(
    ros: &RosettaApiHandle,
    requests: &[RequestInfo<T>],
    accept_suggested_fee: bool,
    ingress_end: Option<u64>,
    created_at_time: Option<u64>,
) -> Result<
    (
        ConstructionSubmitResponse,
        Tokens, // charged fee
    ),
    RosettaError,
>
where
    Arc<T>: RosettaSupportedKeyPair,
{
    let (payloads, charged_fee) = prepare_multiple_txn(
        ros,
        requests,
        accept_suggested_fee,
        ingress_end,
        created_at_time,
    )
    .await?;

    let parse_res = ros
        .construction_parse(false, payloads.unsigned_transaction.clone())
        .await
        .unwrap()?;

    // Verify consistency between requests and construction parse response.
    fn verify_operations<T: RosettaSupportedKeyPair>(
        requests: &[RequestInfo<T>],
        parse_response: ConstructionParseResponse,
    ) {
        let rs1: Vec<_> = requests.iter().map(|r| r.request.clone()).collect();
        let rs2 = operations_to_requests(&parse_response.operations, false, DEFAULT_TOKEN_SYMBOL)
            .unwrap();
        assert_eq!(rs1, rs2, "Requests differs: {:?} vs {:?}", rs1, rs2);
    }

    if !accept_suggested_fee {
        verify_operations(requests, parse_res);
    }

    // check that we got enough unsigned messages
    if let Some(ingress_end) = ingress_end {
        let ingress_start = time::current_time().as_nanos_since_unix_epoch();
        let intervals = (ingress_end - ingress_start) / 120_000_000_000;
        assert!(payloads.payloads.len() as u64 + 2 >= intervals * 2);
    }

    let keypairs: Vec<_> = requests
        .iter()
        .map(|t| t.sender_keypair.to_owned())
        .collect();

    let signed = sign_txn(ros, &keypairs, payloads).await?;

    let parse_res = ros
        .construction_parse(true, signed.signed_transaction.clone())
        .await
        .unwrap()?;

    if !accept_suggested_fee {
        verify_operations(requests, parse_res);
    }
    let hash_res = ros
        .construction_hash(signed.signed_transaction.clone())
        .await
        .unwrap()?;

    let submit_res = ros
        .construction_submit(
            SignedTransaction::from_str(&signed.signed_transaction.clone()).unwrap(),
        )
        .await
        .unwrap()?;

    assert_eq!(
        hash_res.transaction_identifier,
        submit_res.transaction_identifier
    );

    // check idempotency
    let submit_res2 = ros
        .construction_submit(
            SignedTransaction::from_str(&signed.signed_transaction.clone()).unwrap(),
        )
        .await
        .unwrap()?;
    assert_eq!(submit_res, submit_res2);

    let mut txn = SignedTransaction::from_str(&signed.signed_transaction).unwrap();
    for (_, request) in txn.requests.iter_mut() {
        *request = vec![request.last().unwrap().clone()];
    }

    let submit_res3 = ros
        .construction_submit(SignedTransaction::from_str(&signed.signed_transaction).unwrap())
        .await
        .unwrap()?;
    assert_eq!(submit_res, submit_res3);

    Ok((submit_res, charged_fee))
}

pub async fn send_icpts<T: RosettaSupportedKeyPair>(
    ros: &RosettaApiHandle,
    keypair: Arc<T>,
    dst: AccountIdentifier,
    amount: Tokens,
) -> Result<
    (
        TransactionIdentifier,
        Option<BlockIndex>,
        Tokens, // charged fee
    ),
    RosettaError,
>
where
    Arc<T>: RosettaSupportedKeyPair,
{
    send_icpts_with_window(ros, keypair, dst, amount, None, None).await
}

pub async fn send_icpts_with_window<T: RosettaSupportedKeyPair>(
    ros: &RosettaApiHandle,
    keypair: Arc<T>,
    dst: AccountIdentifier,
    amount: Tokens,
    ingress_end: Option<u64>,
    created_at_time: Option<u64>,
) -> Result<
    (
        TransactionIdentifier,
        Option<BlockIndex>,
        Tokens, // charged fee
    ),
    RosettaError,
>
where
    Arc<T>: RosettaSupportedKeyPair,
{
    let public_key_der = EdKeypair::der_encode_pk(keypair.get_pb_key()).unwrap();

    let from: AccountIdentifier = PrincipalId::new_self_authenticating(&public_key_der).into();

    let t = Operation::Transfer {
        from,
        to: dst,
        spender: None,
        amount,
        fee: Tokens::ZERO,
    };

    do_txn(ros, keypair, t, true, ingress_end, created_at_time)
        .await
        .and_then(|(_, results, fee)| {
            if let Some(RequestResult {
                _type: Request::Transfer(Operation::Transfer { .. }),
                transaction_identifier,
                block_index,
                ..
            }) = results.operations.last()
            {
                Ok((
                    transaction_identifier
                        .clone()
                        .expect("Transfers must return a real transaction identifier"),
                    *block_index,
                    fee,
                ))
            } else {
                Err(errors::convert_to_error(
                    &convert::transaction_results_to_api_error(results, DEFAULT_TOKEN_SYMBOL),
                ))
            }
        })
}

pub fn assert_ic_error(err: &RosettaError, code: u32, ic_http_status: u64, text: &str) {
    let err = if let ApiError::OperationsErrors(results, _) =
        errors::convert_to_api_error(err.clone(), DEFAULT_TOKEN_SYMBOL)
    {
        errors::convert_to_error(&results.error().unwrap().clone())
    } else {
        err.clone()
    };

    assert_eq!(err.0.code, code);
    let details = err.0.details.as_ref().unwrap();
    assert_eq!(
        details.get("ic_http_status").unwrap().as_u64().unwrap(),
        ic_http_status
    );
    assert!(
        details
            .get("error_message")
            .unwrap()
            .as_str()
            .unwrap()
            .contains(text),
        "Expected error message to contain '{}' but got: '{}'",
        text,
        details.get("error_message").unwrap().as_str().unwrap()
    );
}

pub fn assert_canister_error(err: &RosettaError, code: u32, text: &str) {
    let err = if let ApiError::OperationsErrors(results, _) =
        errors::convert_to_api_error(err.clone(), DEFAULT_TOKEN_SYMBOL)
    {
        errors::convert_to_error(&results.error().unwrap().clone())
    } else {
        err.clone()
    };

    assert_eq!(
        err.0.code, code,
        "rosetta error {:?} does not have code: {}",
        err, code
    );
    let details = err.0.details.as_ref().unwrap();
    assert!(
        details
            .get("error_message")
            .unwrap()
            .as_str()
            .unwrap()
            .contains(text),
        "rosetta error {:?} does not contain '{}'",
        err,
        text
    );
}

pub fn store_threshold_sig_pk<P: AsRef<Path>>(pk: &Blob, path: P) {
    let mut bytes = vec![];
    bytes.extend_from_slice(b"-----BEGIN PUBLIC KEY-----\r\n");
    for chunk in base64::encode(&pk[..]).as_bytes().chunks(64) {
        bytes.extend_from_slice(chunk);
        bytes.extend_from_slice(b"\r\n");
    }
    bytes.extend_from_slice(b"-----END PUBLIC KEY-----\r\n");

    let path = path.as_ref();
    std::fs::write(path, bytes)
        .unwrap_or_else(|e| panic!("failed to store public key to {}: {}", path.display(), e));
}

fn compare_accounts(
    x: &ic_rosetta_api::models::AccountIdentifier,
    y: &ic_rosetta_api::models::AccountIdentifier,
) -> std::cmp::Ordering {
    let xx = (&x.address, x.sub_account.as_ref().map(|s| &s.address));
    let yy = (&y.address, y.sub_account.as_ref().map(|s| &s.address));
    xx.cmp(&yy)
}

/// Tests that `http_request` endpoint of a given canister rejects overly large HTTP requests
/// (exceeding the candid decoding quota of 10,000, corresponding to roughly 10 KB of decoded data).
pub fn test_http_request_decoding_quota(env: &StateMachine, canister_id: CanisterId) {
    // The anonymous end-user sends a small HTTP request. This should succeed.
    let http_request = HttpRequest {
        method: "GET".to_string(),
        url: "/metrics".to_string(),
        headers: vec![],
        body: ByteBuf::from(vec![42; 1_000]),
    };
    let http_request_bytes = Encode!(&http_request).unwrap();
    let response = match env
        .execute_ingress(canister_id, "http_request", http_request_bytes)
        .unwrap()
    {
        WasmResult::Reply(bytes) => Decode!(&bytes, HttpResponse).unwrap(),
        WasmResult::Reject(reason) => panic!("Unexpected reject: {}", reason),
    };
    assert_eq!(response.status_code, 200);

    // The anonymous end-user sends a large HTTP request. This should be rejected.
    let mut large_http_request = http_request;
    large_http_request.body = ByteBuf::from(vec![42; 1_000_000]);
    let large_http_request_bytes = Encode!(&large_http_request).unwrap();
    let err = env
        .execute_ingress(canister_id, "http_request", large_http_request_bytes)
        .unwrap_err();
    assert!(
        err.description().contains("Deserialization Failed")
            || err
                .description()
                .contains("Decoding cost exceeds the limit")
    );
}

#[test]
fn test_keypair_encoding() {
    //Create keypairs of each type
    let kp_ed_keypair = EdKeypair::generate(100);
    let kp_secp256k1_key_pair = Secp256k1KeyPair::generate(200);

    //Testing the functions of RosettaSupportedKeypair for EdKeypair
    assert_eq!(kp_ed_keypair.get_curve_type(), CurveType::Edwards25519);
    let pid = kp_ed_keypair.generate_principal_id().unwrap();
    //RosettaSupportedKeyPairs supports two encoding types: HEX and DER.
    let pk_hex_encoded = kp_ed_keypair.hex_encode_pk();
    let pk_decoded = EdKeypair::hex_decode_pk(&pk_hex_encoded).unwrap();
    assert_eq!(pk_decoded, kp_ed_keypair.get_pb_key());
    let pk_der_encoded = EdKeypair::der_encode_pk(kp_ed_keypair.get_pb_key()).unwrap();
    let pk_decoded = EdKeypair::der_decode_pk(pk_der_encoded).unwrap();
    assert_eq!(pk_decoded, kp_ed_keypair.get_pb_key());
    //See if the principal id is recoverable from the hex encoded public key
    assert_eq!(EdKeypair::get_principal_id(&pk_hex_encoded).unwrap(), pid);

    //Test the function to make new users of specific key type. Given the same seed the results should be the same
    let (aid_b, _kp_b, pb_b, pid_b) = make_user_ed25519(100);
    assert_eq!(aid_b, pid.into());
    assert_eq!(pb_b, to_public_key(&kp_ed_keypair));
    assert_eq!(
        kp_ed_keypair.get_pb_key(),
        from_hex(&pb_b.hex_bytes).unwrap()
    );
    assert_eq!(pid_b, pid);

    //Testing the functions of RosettaSupportedKeypair for Secp256k1KeyPair
    assert_eq!(kp_secp256k1_key_pair.get_curve_type(), CurveType::Secp256K1);
    let pid = kp_secp256k1_key_pair.generate_principal_id().unwrap();
    //RosettaSupportedKeyPairs supports two encoding types: HEX and DER.
    let pk_hex_encoded = kp_secp256k1_key_pair.hex_encode_pk();
    let pk_decoded = Secp256k1KeyPair::hex_decode_pk(&pk_hex_encoded).unwrap();
    assert_eq!(pk_decoded, kp_secp256k1_key_pair.get_pb_key());
    let pk_der_encoded =
        Secp256k1KeyPair::der_encode_pk(kp_secp256k1_key_pair.get_pb_key()).unwrap();
    let pk_decoded = Secp256k1KeyPair::der_decode_pk(pk_der_encoded).unwrap();
    assert_eq!(pk_decoded, kp_secp256k1_key_pair.get_pb_key());
    //See if the principal id is recoverable from the hex encoded public key
    assert_eq!(
        Secp256k1KeyPair::get_principal_id(&pk_hex_encoded).unwrap(),
        pid
    );

    //Test the function to make new users of specific key type. Given the same seed the results should be the same
    let (aid_b, _kp_b, pb_b, pid_b) = make_user_ecdsa_secp256k1(200);
    assert_eq!(aid_b, pid.into());
    assert_eq!(pb_b, to_public_key(&kp_secp256k1_key_pair));
    assert_eq!(
        kp_secp256k1_key_pair.get_pb_key(),
        from_hex(&pb_b.hex_bytes).unwrap()
    );
    assert_eq!(pid_b, pid);
}
