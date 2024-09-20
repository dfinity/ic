use super::governance_client::GovernanceClient;
use crate::rosetta_tests::{
    ledger_client::LedgerClient,
    lib::convert::{neuron_account_from_public_key, neuron_subaccount_bytes_from_public_key},
    rosetta_client::RosettaApiClient,
};
use candid::Principal;
use ic_icrc1_test_utils::KeyPairGenerator;
use ic_ledger_core::{block::BlockIndex, Tokens};
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance_api::pb::v1::{neuron::DissolveState, Neuron};
use ic_rosetta_api::{
    convert,
    convert::{
        from_hex, from_model_account_identifier, operations_to_requests, to_hex,
        to_model_account_identifier,
    },
    errors,
    errors::ApiError,
    models::{
        amount::{signed_amount, tokens_to_amount},
        operation::OperationType,
        ConstructionCombineResponse, ConstructionParseResponse,
        ConstructionPayloadsRequestMetadata, ConstructionPayloadsResponse,
        ConstructionSubmitResponse, CurveType, Error, Error as RosettaError, PublicKey, Signature,
        SignatureType, SignedTransaction,
    },
    request::{
        request_result::RequestResult, transaction_operation_results::TransactionOperationResults,
        transaction_results::TransactionResults, Request,
    },
    request_types::{
        AddHotKey, ChangeAutoStakeMaturity, Disburse, Follow, ListNeurons, MergeMaturity,
        NeuronInfo, RegisterVote, RemoveHotKey, SetDissolveTimestamp, Spawn, Stake, StakeMaturity,
        StartDissolve, StopDissolve,
    },
    transaction_id::TransactionIdentifier,
    DEFAULT_TOKEN_SYMBOL,
};
use ic_rosetta_test_utils::{EdKeypair, RequestInfo};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_types::{time, PrincipalId};
use icp_ledger::{AccountIdentifier, Operation};
use rand::{rngs::StdRng, seq::SliceRandom, thread_rng, SeedableRng};
use rosetta_core::{
    convert::principal_id_from_public_key,
    models::{RosettaSupportedKeyPair, Secp256k1KeyPair},
    objects::ObjectMap,
};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    str::FromStr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub(crate) fn make_user(seed: u64) -> (AccountIdentifier, EdKeypair, PublicKey, PrincipalId) {
    make_user_ed25519(seed)
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

pub fn to_public_key<T: RosettaSupportedKeyPair>(keypair: &T) -> PublicKey {
    PublicKey {
        hex_bytes: keypair.hex_encode_pk(),
        curve_type: keypair.get_curve_type(),
    }
}

pub(crate) fn one_day_from_now_nanos() -> u64 {
    (ic_types::time::current_time() + Duration::from_secs(24 * 60 * 60)).as_nanos_since_unix_epoch()
}

pub(crate) fn hex2addr(a: &str) -> AccountIdentifier {
    AccountIdentifier::from_hex(a).unwrap()
}

// If accept_suggested_fee is false, then Transfer needs to contain a correct
// fee. Otherwise the fee value will be ignored and set to whatever ledger
// canister wants. In such case we don't do checks if the transaction
// created matches the one requested.
pub async fn do_txn<T: RosettaSupportedKeyPair>(
    ros: &RosettaApiClient,
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
    Error,
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
    ros: &RosettaApiClient,
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
    ros: &RosettaApiClient,
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
    ros: &RosettaApiClient,
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
        .construction_submit(SignedTransaction::from_str(&signed.signed_transaction).unwrap())
        .await
        .unwrap()?;

    assert_eq!(
        hash_res.transaction_identifier,
        submit_res.transaction_identifier
    );

    // check idempotency
    let submit_res2 = ros
        .construction_submit(SignedTransaction::from_str(&signed.signed_transaction).unwrap())
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

pub async fn prepare_multiple_txn<T: RosettaSupportedKeyPair>(
    ros: &RosettaApiClient,
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
                trans_fee_amount = Some(tokens_to_amount(fee, token_name).unwrap());
                all_sender_account_ids.push(to_model_account_identifier(&from));

                // just a sanity check
                assert!(fee_found, "There should be a fee op in operations");

                if spender.is_some() {
                    panic!("TransferFrom operations are not supported here")
                }
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
                panic!("Burn operations are not supported here")
            }
            Request::Transfer(Operation::Mint { .. }) => {
                panic!("Mint operations are not supported here")
            }
            Request::Transfer(Operation::Approve { .. }) => {
                panic!("Approve operations are not supported here")
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

    // The fee reported here should be the same as the one we got from dry run
    assert_eq!(suggested_fee, dry_run_suggested_fee);
    let metadata = ConstructionPayloadsRequestMetadata::try_from(metadata_res.metadata)?;
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
    ros: &RosettaApiClient,
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
    ros: &RosettaApiClient,
    keypairs: &[Arc<T>],
    payloads: ConstructionPayloadsResponse,
) -> Result<ConstructionCombineResponse, RosettaError>
where
    Arc<T>: RosettaSupportedKeyPair,
{
    let mut keypairs_map = HashMap::new();
    for kp in keypairs {
        let pid = principal_id_from_public_key(&to_public_key(kp)).unwrap();
        let acc = icp_ledger::account_identifier::AccountIdentifier::from(pid);
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

pub async fn check_balance(
    client: &RosettaApiClient,
    ledger_client: &LedgerClient,
    acc: &AccountIdentifier,
    expected_balance: Tokens,
) {
    let balance = Tokens::from_e8s(
        client
            .account_balance(*acc)
            .await
            .expect("Error while querying account balance")
            .expect("Cannot get account balance")
            .balances[0]
            .value
            .parse()
            .unwrap(),
    );

    assert_eq!(expected_balance, balance);
    let acc_ledger = acc;
    let balance_from_ledger = ledger_client.get_account_balance(*acc_ledger).await;
    assert_eq!(balance_from_ledger, balance);
}

fn compare_accounts(
    x: &ic_rosetta_api::models::AccountIdentifier,
    y: &ic_rosetta_api::models::AccountIdentifier,
) -> std::cmp::Ordering {
    let xx = (&x.address, x.sub_account.as_ref().map(|s| &s.address));
    let yy = (&y.address, y.sub_account.as_ref().map(|s| &s.address));
    xx.cmp(&yy)
}

/// Create a ledger client connecting to the same ledger as the provided Rosetta client.
pub fn create_ledger_client(env: &TestEnv, client: &RosettaApiClient) -> LedgerClient {
    let ledger_canister_id = client.get_ledger_canister_id();
    let ledger_principal = Principal::from(ledger_canister_id.get());
    LedgerClient::new(env, ledger_principal)
}

pub fn create_governance_client(env: &TestEnv, client: &RosettaApiClient) -> GovernanceClient {
    let governance_canister_id = client.get_governance_canister_id();
    let governance_principal = Principal::from(governance_canister_id.get());
    GovernanceClient::new(env, governance_principal)
}

pub fn create_custom_neuron(
    id: u64,
    neuron_setup: impl FnOnce(&mut Neuron),
    ledger_balances: &mut HashMap<AccountIdentifier, Tokens>,
    kp: &EdKeypair,
) -> NeuronDetails {
    let neuron_subaccount_identifier = rand::random();
    let pid = kp.generate_principal_id().unwrap();
    let aid: AccountIdentifier = pid.into();
    let pb = to_public_key(kp);
    let created_timestamp_seconds = (SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
        - Duration::from_secs(60 * 60 * 24 * 365))
    .as_secs();
    let mut neuron = Neuron {
        id: Some(NeuronId { id }),
        account: neuron_subaccount_bytes_from_public_key(&pb, neuron_subaccount_identifier)
            .unwrap()
            .to_vec(),
        controller: Some(pid),
        created_timestamp_seconds,
        aging_since_timestamp_seconds: u64::MAX,
        dissolve_state: Some(DissolveState::WhenDissolvedTimestampSeconds(0)),
        cached_neuron_stake_e8s: Tokens::new(10, 0).unwrap().get_e8s(),
        kyc_verified: true,
        ..Default::default()
    };

    // Apply neuron customization here (setup function).
    neuron_setup(&mut neuron);

    let neuron_account =
        neuron_account_from_public_key(&GOVERNANCE_CANISTER_ID, &pb, neuron_subaccount_identifier)
            .unwrap();
    let neuron_account = from_model_account_identifier(&neuron_account).unwrap();
    // Add the neuron balance to the ledger.
    ledger_balances.insert(
        neuron_account,
        Tokens::from_e8s(neuron.cached_neuron_stake_e8s),
    );

    // Create neuron info.
    NeuronDetails {
        account_id: aid,
        key_pair: kp.clone(),
        public_key: pb,
        principal_id: pid,
        neuron_subaccount_identifier,
        neuron,
        neuron_account,
    }
}

pub fn create_neuron(
    seed: u64,
    neuron_setup: impl FnOnce(&mut Neuron),
    ledger_balances: &mut HashMap<AccountIdentifier, Tokens>,
) -> NeuronDetails {
    let neuron_subaccount_identifier = rand::random();
    let (account_id, key_pair, public_key, principal_id) = make_user(seed);
    let created_timestamp_seconds = (SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
        - Duration::from_secs(60 * 60 * 24 * 365))
    .as_secs();
    let mut neuron = Neuron {
        id: Some(NeuronId { id: seed }),
        account: neuron_subaccount_bytes_from_public_key(&public_key, neuron_subaccount_identifier)
            .unwrap()
            .to_vec(),
        controller: Some(principal_id),
        created_timestamp_seconds,
        aging_since_timestamp_seconds: u64::MAX,
        dissolve_state: Some(DissolveState::WhenDissolvedTimestampSeconds(0)),
        cached_neuron_stake_e8s: Tokens::new(10, 0).unwrap().get_e8s(),
        kyc_verified: true,
        ..Default::default()
    };

    // Apply neuron customization here (setup function).
    neuron_setup(&mut neuron);

    let neuron_account = neuron_account_from_public_key(
        &GOVERNANCE_CANISTER_ID,
        &public_key,
        neuron_subaccount_identifier,
    )
    .unwrap();
    let neuron_account = from_model_account_identifier(&neuron_account).unwrap();
    // Add the neuron balance to the ledger.
    ledger_balances.insert(
        neuron_account,
        Tokens::from_e8s(neuron.cached_neuron_stake_e8s),
    );

    // Create neuron info.
    NeuronDetails {
        account_id,
        key_pair,
        public_key,
        principal_id,
        neuron_subaccount_identifier,
        neuron,
        neuron_account,
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct NeuronDetails {
    pub(crate) account_id: AccountIdentifier,
    pub(crate) key_pair: EdKeypair,
    pub(crate) public_key: PublicKey,
    pub(crate) principal_id: PrincipalId,
    pub(crate) neuron_subaccount_identifier: u64,
    pub(crate) neuron: Neuron,
    pub(crate) neuron_account: AccountIdentifier,
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

pub fn acc_id(seed: u64) -> AccountIdentifier {
    let mut rng = StdRng::seed_from_u64(seed);
    let keypair = ic_canister_client_sender::Ed25519KeyPair::generate(&mut rng);
    let public_key_der =
        ic_canister_client_sender::ed25519_public_key_to_der(keypair.public_key.to_vec());
    PrincipalId::new_self_authenticating(&public_key_der).into()
}

pub async fn raw_construction(ros: &RosettaApiClient, operation: &str, req: Value) -> ObjectMap {
    let req = req.to_string();
    let res = &ros
        .raw_construction_endpoint(operation, req.as_bytes())
        .await
        .unwrap();
    let output: ObjectMap = serde_json::from_slice(&res.0).unwrap();
    assert!(
        res.1.is_success(),
        "Result of {} should be a success, got: {:?}",
        operation,
        output
    );
    output
}

pub fn sign(payload: &Value, keypair: &Arc<EdKeypair>) -> Value {
    let hex_bytes: &str = payload.get("hex_bytes").unwrap().as_str().unwrap();
    let bytes = from_hex(hex_bytes).unwrap();
    let signature_bytes = keypair.sign(&bytes);
    let hex_bytes = to_hex(&signature_bytes);
    json!(hex_bytes)
}

pub async fn send_icpts<T: RosettaSupportedKeyPair>(
    ros: &RosettaApiClient,
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
    ros: &RosettaApiClient,
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
    let public_key_der = ic_canister_client_sender::ed25519_public_key_to_der(keypair.get_pb_key());

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
