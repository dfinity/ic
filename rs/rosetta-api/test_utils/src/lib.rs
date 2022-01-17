use ic_rosetta_api::convert::{
    amount_, from_hex, from_model_account_identifier, from_operations, from_public_key,
    principal_id_from_public_key, signed_amount, to_hex, to_model_account_identifier,
};

use ic_rosetta_api::models::Error as RosettaError;
use ic_rosetta_api::models::{
    ConstructionCombineResponse, ConstructionPayloadsRequestMetadata, ConstructionPayloadsResponse,
    CurveType, PublicKey, Signature, SignatureType,
};
use ic_rosetta_api::request_types::{
    AddHotKey, Disburse, MergeMaturity, Request, RequestResult, SetDissolveTimestamp, Spawn, Stake,
    StartDissolve, StopDissolve, TransactionResults,
};
use ic_rosetta_api::transaction_id::TransactionIdentifier;
use ic_rosetta_api::{convert, errors, errors::ApiError, DEFAULT_TOKEN_NAME};
use ic_types::{messages::Blob, time, PrincipalId};

use ledger_canister::{AccountIdentifier, BlockHeight, Operation, Tokens};

pub use ed25519_dalek::Keypair as EdKeypair;
use log::debug;
use rand::{rngs::StdRng, seq::SliceRandom, thread_rng, SeedableRng};
use std::collections::HashMap;
use std::sync::Arc;

pub mod rosetta_api_serv;
pub mod sample_data;

use rosetta_api_serv::RosettaApiHandle;
use std::path::Path;

pub fn to_public_key(keypair: &EdKeypair) -> PublicKey {
    PublicKey {
        hex_bytes: to_hex(&keypair.public.to_bytes()),
        curve_type: CurveType::Edwards25519,
    }
}

pub fn make_user(seed: u64) -> (AccountIdentifier, EdKeypair, PublicKey, PrincipalId) {
    let mut rng = StdRng::seed_from_u64(seed);
    let keypair = EdKeypair::generate(&mut rng);

    let public_key = to_public_key(&keypair);

    let public_key_der =
        ic_canister_client::ed25519_public_key_to_der(keypair.public.to_bytes().to_vec());

    assert_eq!(
        from_public_key(&public_key).unwrap(),
        keypair.public.to_bytes()
    );

    let pid = PrincipalId::new_self_authenticating(&public_key_der);
    let user_id: AccountIdentifier = pid.into();

    debug!("[test] created user {}", user_id);

    (user_id, keypair, public_key, pid)
}

pub fn acc_id(seed: u64) -> AccountIdentifier {
    let mut rng = StdRng::seed_from_u64(seed);
    let keypair = EdKeypair::generate(&mut rng);
    let public_key_der =
        ic_canister_client::ed25519_public_key_to_der(keypair.public.to_bytes().to_vec());

    PrincipalId::new_self_authenticating(&public_key_der).into()
}

pub struct RequestInfo {
    pub request: Request,
    pub sender_keypair: Arc<EdKeypair>,
}

pub async fn prepare_multiple_txn(
    ros: &RosettaApiHandle,
    requests: &[RequestInfo],
    accept_suggested_fee: bool,
    ingress_end: Option<u64>,
    created_at_time: Option<u64>,
) -> Result<(ConstructionPayloadsResponse, Tokens), RosettaError> {
    let mut all_ops = Vec::new();
    let mut dry_run_ops = Vec::new();
    let mut all_sender_account_ids = Vec::new();
    let mut all_sender_pks = Vec::new();
    let mut trans_fee_amount = None;
    let token_name = DEFAULT_TOKEN_NAME;

    for request in requests {
        // first ask for the fee
        let mut fee_found = false;
        for o in Request::requests_to_operations(&[request.request.clone()], token_name).unwrap() {
            if o._type == "FEE" {
                fee_found = true;
            } else {
                dry_run_ops.push(o.clone());
            }
            all_ops.push(o);
        }

        match request.request.clone() {
            Request::Transfer(Operation::Transfer { from, fee, .. }) => {
                trans_fee_amount = Some(amount_(fee, token_name).unwrap());
                all_sender_account_ids.push(to_model_account_identifier(&from));

                // just a sanity check
                assert!(fee_found, "There should be a fee op in operations");
            }
            Request::Stake(Stake { account, .. })
            | Request::StartDissolve(StartDissolve { account, .. })
            | Request::StopDissolve(StopDissolve { account, .. })
            | Request::SetDissolveTimestamp(SetDissolveTimestamp { account, .. })
            | Request::AddHotKey(AddHotKey { account, .. })
            | Request::Disburse(Disburse { account, .. })
            | Request::Spawn(Spawn { account, .. })
            | Request::MergeMaturity(MergeMaturity { account, .. }) => {
                all_sender_account_ids.push(to_model_account_identifier(&account));
            }
            Request::Transfer(Operation::Burn { .. }) => {
                panic!("Burn operations are supported here")
            }
            Request::Transfer(Operation::Mint { .. }) => {
                panic!("Mint operations are supported here")
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
        .construction_metadata(pre_res.options, Some(all_sender_pks.clone()))
        .await
        .unwrap()?;
    let dry_run_suggested_fee = metadata_res.suggested_fee.map(|mut suggested_fee| {
        assert_eq!(suggested_fee.len(), 1);
        suggested_fee.pop().unwrap()
    });
    let fee_icpts = Tokens::from_e8s(
        dry_run_suggested_fee
            .clone()
            .unwrap_or_else(|| amount_(Tokens::default(), token_name).unwrap())
            .value
            .parse()
            .unwrap(),
    );

    if accept_suggested_fee {
        for o in &mut all_ops {
            if o._type == "FEE" {
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
        .construction_metadata(pre_res.options, Some(all_sender_pks.clone()))
        .await
        .unwrap()?;
    let suggested_fee = metadata_res.suggested_fee.clone().map(|mut suggested_fee| {
        assert_eq!(suggested_fee.len(), 1);
        suggested_fee.pop().unwrap()
    });

    // The fee reported here should be the same as the one we got from dry run
    assert_eq!(suggested_fee, dry_run_suggested_fee);

    ros.construction_payloads(
        Some(ConstructionPayloadsRequestMetadata {
            memo: Some(0),
            ingress_end,
            created_at_time,
            ..metadata_res.metadata
        }),
        all_ops,
        Some(all_sender_pks),
    )
    .await
    .unwrap()
    .map(|resp| (resp, fee_icpts))
}

pub async fn prepare_txn(
    ros: &RosettaApiHandle,
    operation: Operation,
    sender_keypair: Arc<EdKeypair>,
    accept_suggested_fee: bool,
    ingress_end: Option<u64>,
    created_at_time: Option<u64>,
) -> Result<(ConstructionPayloadsResponse, Tokens), RosettaError> {
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

pub async fn sign_txn(
    ros: &RosettaApiHandle,
    keypairs: &[Arc<EdKeypair>],
    payloads: ConstructionPayloadsResponse,
) -> Result<ConstructionCombineResponse, RosettaError> {
    use ed25519_dalek::Signer;

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
                .map(|x| Arc::clone(x))
                .unwrap_or_else(|| Arc::clone(&keypairs[0]));
            let bytes = from_hex(&p.hex_bytes).unwrap();
            let signature_bytes = keypair.sign(&bytes).to_bytes();
            let hex_bytes = to_hex(&signature_bytes);
            Signature {
                signing_payload: p,
                public_key: to_public_key(&keypair),
                signature_type: SignatureType::Ed25519,
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
pub async fn do_txn(
    ros: &RosettaApiHandle,
    sender_keypair: Arc<EdKeypair>,
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
> {
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

pub async fn do_multiple_txn(
    ros: &RosettaApiHandle,
    requests: &[RequestInfo],
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
> {
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

    if !accept_suggested_fee {
        let rs: Vec<_> = requests.iter().map(|r| r.request.clone()).collect();
        assert_eq!(
            rs,
            from_operations(&parse_res.operations, false, DEFAULT_TOKEN_NAME).unwrap()
        );
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
        let rs: Vec<_> = requests.iter().map(|r| r.request.clone()).collect();
        assert_eq!(
            rs,
            from_operations(&parse_res.operations, false, DEFAULT_TOKEN_NAME).unwrap()
        );
    }

    let hash_res = ros
        .construction_hash(signed.signed_transaction.clone())
        .await
        .unwrap()?;

    let submit_res = ros
        .construction_submit(signed.signed_transaction().unwrap())
        .await
        .unwrap()?;

    assert_eq!(
        hash_res.transaction_identifier,
        submit_res.transaction_identifier
    );

    // check idempotency
    let submit_res2 = ros
        .construction_submit(signed.signed_transaction().unwrap())
        .await
        .unwrap()?;
    assert_eq!(submit_res, submit_res2);

    let mut txn = signed.signed_transaction().unwrap();
    for (_, request) in txn.iter_mut() {
        *request = vec![request.last().unwrap().clone()];
    }

    let submit_res3 = ros
        .construction_submit(signed.signed_transaction().unwrap())
        .await
        .unwrap()?;
    assert_eq!(submit_res, submit_res3);

    let results =
        convert::from_transaction_operation_results(submit_res.metadata, DEFAULT_TOKEN_NAME)
            .expect("Couldn't convert metadata to TransactionResults");

    if let Some(RequestResult {
        _type: Request::Transfer(_),
        transaction_identifier,
        ..
    }) = results.operations.last()
    {
        assert_eq!(
            submit_res.transaction_identifier,
            transaction_identifier.clone().unwrap()
        );
    }

    Ok((submit_res.transaction_identifier, results, charged_fee))
}

pub async fn send_icpts(
    ros: &RosettaApiHandle,
    keypair: Arc<EdKeypair>,
    dst: AccountIdentifier,
    amount: Tokens,
) -> Result<
    (
        TransactionIdentifier,
        Option<BlockHeight>,
        Tokens, // charged fee
    ),
    RosettaError,
> {
    send_icpts_with_window(ros, keypair, dst, amount, None, None).await
}

pub async fn send_icpts_with_window(
    ros: &RosettaApiHandle,
    keypair: Arc<EdKeypair>,
    dst: AccountIdentifier,
    amount: Tokens,
    ingress_end: Option<u64>,
    created_at_time: Option<u64>,
) -> Result<
    (
        TransactionIdentifier,
        Option<BlockHeight>,
        Tokens, // charged fee
    ),
    RosettaError,
> {
    let public_key_der =
        ic_canister_client::ed25519_public_key_to_der(keypair.public.to_bytes().to_vec());

    let from: AccountIdentifier = PrincipalId::new_self_authenticating(&public_key_der).into();

    let t = Operation::Transfer {
        from,
        to: dst,
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
                    &convert::transaction_results_to_api_error(results, DEFAULT_TOKEN_NAME),
                ))
            }
        })
}

pub fn assert_ic_error(err: &RosettaError, code: u32, ic_http_status: u64, text: &str) {
    let err = if let ApiError::OperationsErrors(results, _) =
        errors::convert_to_api_error(err.clone(), DEFAULT_TOKEN_NAME)
    {
        errors::convert_to_error(&results.error().unwrap().clone())
    } else {
        err.clone()
    };

    assert_eq!(err.code, code);
    let details = err.details.as_ref().unwrap();
    assert_eq!(
        details.get("ic_http_status").unwrap().as_u64().unwrap(),
        ic_http_status
    );
    assert!(details
        .get("error_message")
        .unwrap()
        .as_str()
        .unwrap()
        .contains(text));
}

pub fn assert_canister_error(err: &RosettaError, code: u32, text: &str) {
    let err = if let ApiError::OperationsErrors(results, _) =
        errors::convert_to_api_error(err.clone(), DEFAULT_TOKEN_NAME)
    {
        errors::convert_to_error(&results.error().unwrap().clone())
    } else {
        err.clone()
    };

    assert_eq!(
        err.code, code,
        "rosetta error {:?} does not have code: {}",
        err, code
    );
    let details = err.details.as_ref().unwrap();
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
