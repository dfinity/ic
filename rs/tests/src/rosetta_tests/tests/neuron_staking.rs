use crate::rosetta_tests::ledger_client::LedgerClient;
use crate::rosetta_tests::lib::{
    assert_canister_error, check_balance, create_ledger_client, do_multiple_txn, make_user_ed25519,
    one_day_from_now_nanos, raw_construction, sign, to_public_key,
};
use crate::rosetta_tests::rosetta_client::RosettaApiClient;
use crate::rosetta_tests::setup::setup;
use crate::rosetta_tests::test_neurons::TestNeurons;
use assert_json_diff::{assert_json_eq, assert_json_include};
use ic_ledger_core::tokens::{CheckedAdd, CheckedSub};
use ic_ledger_core::Tokens;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_rosetta_api::convert::{from_model_account_identifier, neuron_account_from_public_key};
use ic_rosetta_api::models::seconds::Seconds;
use ic_rosetta_api::models::NeuronInfoResponse;
use ic_rosetta_api::models::NeuronState;
use ic_rosetta_api::request::Request;
use ic_rosetta_api::request_types::{SetDissolveTimestamp, Stake, StartDissolve, StopDissolve};
use ic_rosetta_test_utils::{EdKeypair, RequestInfo};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::util::block_on;
use icp_ledger::{AccountIdentifier, Operation, DEFAULT_TRANSFER_FEE};
use serde_json::{json, Value};
use slog::info;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::UNIX_EPOCH;

const PORT: u32 = 8103;
const VM_NAME: &str = "rosetta-neuron-staking";

pub fn test(env: TestEnv) {
    let logger = env.logger();

    let mut ledger_balances = HashMap::new();
    let (acc, _, _, _) = make_user_ed25519(101);
    ledger_balances.insert(acc, Tokens::new(1000, 0).unwrap());

    // Create neurons.
    let one_year_from_now = 60 * 60 * 24 * 365
        + std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    let neurons = TestNeurons::new(2000, &mut ledger_balances);

    // Create Rosetta and ledger clients.
    let neurons = neurons.get_neurons();
    let client = setup(&env, PORT, VM_NAME, Some(ledger_balances), Some(neurons));
    let ledger_client = create_ledger_client(&env, &client);

    block_on(async {
        info!(logger, "Test staking");
        let _ = test_staking(&client).await;
        info!(logger, "Test staking (raw JSON)");
        let _ = test_staking_raw(&client).await;
        info!(logger, "Test staking failure");
        test_staking_failure(&client).await;
        info!(logger, "Test staking flow");
        test_staking_flow(&client, &ledger_client, Seconds(one_year_from_now)).await;
        info!(logger, "Test staking flow two transactions");
        test_staking_flow_two_txns(&client, &ledger_client, Seconds(one_year_from_now)).await;
    });
}

async fn test_staking(client: &RosettaApiClient) -> (AccountIdentifier, Arc<EdKeypair>) {
    let (acc, kp_b, _pk_b, _pid_b) = make_user_ed25519(101);
    let key_pair = Arc::new(kp_b);

    let (dst_acc, dst_acc_kp, dst_acc_pk, _pid) = make_user_ed25519(1300);
    let dst_acc_kp = Arc::new(dst_acc_kp);
    let neuron_index = 2;

    let staked_amount = Tokens::new(10, 0).unwrap();

    // Could use /construction/derive for this.
    let neuron_account =
        neuron_account_from_public_key(&GOVERNANCE_CANISTER_ID, &dst_acc_pk, neuron_index).unwrap();
    let neuron_account = from_model_account_identifier(&neuron_account).unwrap();

    let (_tid, results, _fee) = do_multiple_txn(
        client,
        &[
            RequestInfo {
                request: Request::Transfer(Operation::Transfer {
                    from: acc,
                    to: dst_acc,
                    spender: None,
                    amount: staked_amount.checked_add(&DEFAULT_TRANSFER_FEE).unwrap(),
                    fee: DEFAULT_TRANSFER_FEE,
                }),
                sender_keypair: Arc::clone(&key_pair),
            },
            RequestInfo {
                request: Request::Transfer(Operation::Transfer {
                    from: dst_acc,
                    to: neuron_account,
                    spender: None,
                    amount: staked_amount,
                    fee: DEFAULT_TRANSFER_FEE,
                }),
                sender_keypair: Arc::clone(&dst_acc_kp),
            },
            RequestInfo {
                request: Request::Stake(Stake {
                    account: dst_acc,
                    neuron_index,
                }),
                sender_keypair: Arc::clone(&dst_acc_kp),
            },
        ],
        false,
        Some(one_day_from_now_nanos()),
        None,
    )
    .await
    .unwrap();

    let neuron_id = results.operations.last().unwrap().neuron_id;
    assert!(
        neuron_id.is_some(),
        "NeuronId should have been returned here"
    );

    // Block height is the last block observed.
    // In this case the transfer to neuron_account.
    assert!(results.last_block_index().is_some());

    let neuron_info: NeuronInfoResponse = client
        .account_balance_neuron(neuron_account, neuron_id, None, false)
        .await
        .unwrap()
        .unwrap()
        .metadata
        .try_into()
        .unwrap();
    assert_eq!(neuron_info.state, NeuronState::Dissolved);

    let neuron_info: NeuronInfoResponse = client
        .account_balance_neuron(
            neuron_account,
            None,
            Some((dst_acc_pk.clone(), neuron_index)),
            false,
        )
        .await
        .unwrap()
        .unwrap()
        .metadata
        .try_into()
        .unwrap();
    assert_eq!(neuron_info.state, NeuronState::Dissolved);

    let neuron_info: NeuronInfoResponse = client
        .account_balance_neuron(neuron_account, None, Some((dst_acc_pk, neuron_index)), true)
        .await
        .unwrap()
        .unwrap()
        .metadata
        .try_into()
        .unwrap();
    assert_eq!(neuron_info.state, NeuronState::Dissolved);

    // Return staked account.
    (dst_acc, dst_acc_kp)
}

async fn test_staking_failure(client: &RosettaApiClient) {
    let (acc, kp_b, _pk_b, _pid_b) = make_user_ed25519(101);
    let key_pair = Arc::new(kp_b);

    let (dst_acc, dst_acc_kp, dst_acc_pk, _pid) = make_user_ed25519(1301);
    let dst_acc_kp = Arc::new(dst_acc_kp);
    let neuron_index = 2;

    // This is just below the minimum (NetworkEconomics.neuron_minimum_stake_e8s).
    let staked_amount = Tokens::new(1, 0)
        .unwrap()
        .checked_sub(&Tokens::from_e8s(1))
        .unwrap();

    // Could use /construction/derive for this.
    let neuron_account =
        neuron_account_from_public_key(&GOVERNANCE_CANISTER_ID, &dst_acc_pk, neuron_index).unwrap();
    let neuron_account = from_model_account_identifier(&neuron_account).unwrap();

    let err = do_multiple_txn(
        client,
        &[
            RequestInfo {
                request: Request::Transfer(Operation::Transfer {
                    from: acc,
                    to: dst_acc,
                    spender: None,
                    amount: staked_amount.checked_add(&DEFAULT_TRANSFER_FEE).unwrap(),
                    fee: DEFAULT_TRANSFER_FEE,
                }),
                sender_keypair: Arc::clone(&key_pair),
            },
            RequestInfo {
                request: Request::Transfer(Operation::Transfer {
                    from: dst_acc,
                    to: neuron_account,
                    spender: None,
                    amount: staked_amount,
                    fee: DEFAULT_TRANSFER_FEE,
                }),
                sender_keypair: Arc::clone(&dst_acc_kp),
            },
            RequestInfo {
                request: Request::Stake(Stake {
                    account: dst_acc,
                    neuron_index,
                }),
                sender_keypair: Arc::clone(&dst_acc_kp),
            },
        ],
        false,
        Some(one_day_from_now_nanos()),
        None,
    )
    .await
    .unwrap_err();

    assert_canister_error(
        &err,
        750,
        "Could not claim neuron: InsufficientFunds: Account does not have enough funds to stake a neuron",
    );
}

async fn test_staking_raw(client: &RosettaApiClient) -> (AccountIdentifier, Arc<EdKeypair>) {
    let (acc, kp_b, _pk_b, _pid_b) = make_user_ed25519(101);
    let key_pair = Arc::new(kp_b);

    let (dst_acc, dst_acc_kp, dst_acc_pk, _pid) = make_user_ed25519(1300);
    let dst_acc_kp = Arc::new(dst_acc_kp);
    let neuron_index = 2;

    // Could use /construction/derive for this.
    let neuron_account =
        neuron_account_from_public_key(&GOVERNANCE_CANISTER_ID, &dst_acc_pk, neuron_index).unwrap();
    let neuron_account = from_model_account_identifier(&neuron_account).unwrap();

    // Key pairs as Json.
    let pk1 = serde_json::to_value(to_public_key(&key_pair)).unwrap();
    let pk2 = serde_json::to_value(to_public_key(&dst_acc_kp)).unwrap();

    // Call /construction/derive.
    let req_derive = json!({
        "network_identifier": &client.network_id(),
        "public_key": pk1,
        "metadata": {
            "account_type": "ledger"
        }
    });
    let res_derive = raw_construction(client, "derive", req_derive).await;
    let address = res_derive
        .get("account_identifier")
        .unwrap()
        .get("address")
        .unwrap();
    assert_eq!(&acc.to_hex(), address); // 52bef...

    // acc => 52bef...
    // dest_acc => 1e31da...
    // neuron_account => 79ec2...

    // Call /construction/preprocess
    let operations = json!([
        {
            "operation_identifier": {
                "index": 0
            },
            "type": "TRANSACTION",
            "account": {
                "address": &acc
            },
            "amount": {
                "value": "-1000010000",
                "currency": {
                    "symbol": "ICP",
                    "decimals": 8
                }
            },
        },
        {
            "operation_identifier": {
                "index": 1
            },
            "type": "TRANSACTION",
            "account": {
                "address": &dst_acc
            },
            "amount": {
                "value": "1000010000",
                "currency": {
                    "symbol": "ICP",
                    "decimals": 8
                }
            },
        },
        {
            "operation_identifier": {
                "index": 2
            },
            "type": "FEE",
            "account": {
                "address": &acc
            },
            "amount": {
                "value": "-10000",
                "currency": {
                    "symbol": "ICP",
                    "decimals": 8
                }
            },
        },
        {
            "operation_identifier": {
                "index": 3
            },
            "type": "TRANSACTION",
            "account": {
                "address": &dst_acc
            },
            "amount": {
                "value": "-1000000000",
                "currency": {
                    "symbol": "ICP",
                    "decimals": 8
                }
            },
        },
        {
            "operation_identifier": {
                "index": 4
            },
            "type": "TRANSACTION",
            "account": {
                "address": &neuron_account
            },
            "amount": {
                "value": "1000000000",
                "currency": {
                    "symbol": "ICP",
                    "decimals": 8
                }
            },
        },
        {
            "operation_identifier": {
                "index": 5
            },
            "type": "FEE",
            "account": {
                "address": &dst_acc
            },
            "amount": {
                "value": "-10000",
                "currency": {
                    "symbol": "ICP",
                    "decimals": 8
                }
            },
        },
        {
            "operation_identifier": {
                "index": 6
            },
            "type": "STAKE",
            "account": {
                "address": &dst_acc
            },
            "metadata": {
                "neuron_index": &neuron_index
            }
        }
    ]);
    let req_preprocess = json!({
        "network_identifier": &client.network_id(),
        "operations": operations,
        "metadata": {},
    });
    let res_preprocess = raw_construction(client, "preprocess", req_preprocess).await;
    let options = res_preprocess.get("options");
    assert_json_eq!(
        json!({
            "request_types": [
                "TRANSACTION",
                "TRANSACTION",
                {"STAKE": {"neuron_index": 2}}
            ]
        }),
        options.unwrap()
    );

    // Call /construction/metadata
    let req_metadata = json!({
        "network_identifier": &client.network_id(),
        "options": options,
        "public_keys": [pk1]
    });
    let res_metadata = raw_construction(client, "metadata", req_metadata).await;
    assert_json_eq!(
        json!([
            {
                "currency": {"symbol": "ICP", "decimals": 8},
                "value": format!("{}", DEFAULT_TRANSFER_FEE.get_e8s())
            }
        ]),
        res_metadata.get("suggested_fee").unwrap()
    );
    // NB: metadata response will have to be added to payloads request.

    // Call /construction/payloads
    let req_payloads = json!({
        "network_identifier": &client.network_id(),
        "operations": operations,
        "metadata": res_metadata,
        "public_keys": [pk1,pk2]
    });
    let res_payloads = raw_construction(client, "payloads", req_payloads).await;
    let unsigned_transaction: &Value = res_payloads.get("unsigned_transaction").unwrap();
    let payloads = res_payloads.get("payloads").unwrap();
    let payloads = payloads.as_array().unwrap();
    assert_eq!(6, payloads.len(), "Expecting 6 payloads (3x2).");

    // Call /construction/parse (unsigned).
    let req_parse = json!({
        "network_identifier": &client.network_id(),
        "signed": false,
        "transaction": &unsigned_transaction
    });
    let _res_parse = raw_construction(client, "parse", req_parse).await;

    // Call /construction/combine.
    let signatures = json!([
        {
            "signing_payload": payloads[0],
            "public_key": pk1,
            "signature_type": "ed25519",
            "hex_bytes": sign(&payloads[0], &key_pair)
        },{
            "signing_payload": payloads[1],
            "public_key": pk1,
            "signature_type": "ed25519",
            "hex_bytes": sign(&payloads[1], &key_pair)
        },{
            "signing_payload": payloads[2],
            "public_key": pk2,
            "signature_type": "ed25519",
            "hex_bytes": sign(&payloads[2], &dst_acc_kp)
        },{
            "signing_payload": payloads[3],
            "public_key": pk2,
            "signature_type": "ed25519",
            "hex_bytes": sign(&payloads[3], &dst_acc_kp)
        },{
            "signing_payload": payloads[4],
            "public_key": pk2,
            "signature_type": "ed25519",
            "hex_bytes": sign(&payloads[4], &dst_acc_kp)
        },{
            "signing_payload": payloads[5],
            "public_key": pk2,
            "signature_type": "ed25519",
            "hex_bytes": sign(&payloads[5], &dst_acc_kp)
        },
    ]);

    let req_combine = json!({
        "network_identifier": &client.network_id(),
        "unsigned_transaction": &unsigned_transaction,
        "signatures": signatures
    });
    let res_combine = raw_construction(client, "combine", req_combine).await;

    // Call /construction/parse (signed).
    let signed_transaction: &Value = res_combine.get("signed_transaction").unwrap();
    let req_parse = json!({
        "network_identifier": &client.network_id(),
        "signed": true,
        "transaction": &signed_transaction
    });
    let _res_parse = raw_construction(client, "parse", req_parse).await;

    // Call /construction/hash.
    let req_hash = json!({
        "network_identifier": &client.network_id(),
        "signed_transaction": &signed_transaction
    });
    let _res_hash = raw_construction(client, "hash", req_hash).await;

    // Call /construction/submit.
    let req_submit = json!({
        "network_identifier": &client.network_id(),
        "signed_transaction": &signed_transaction
    });
    let res_submit = raw_construction(client, "submit", req_submit).await;

    // Check proper state after staking.
    let operations = res_submit
        .get("metadata")
        .unwrap()
        .get("operations")
        .unwrap()
        .as_array()
        .unwrap();
    assert_eq!(
        7,
        operations.len(),
        "Expecting 7 operations for the staking transactions."
    );
    for op in operations.iter() {
        assert_eq!(
            op.get("status").unwrap(),
            "COMPLETED",
            "Operation didn't complete."
        );
    }
    assert_json_include!(
        actual: &operations[0],
        expected: json!({
            "amount": {"currency": {"decimals": 8, "symbol": "ICP"}, "value": "-1000010000"},
            "operation_identifier": {"index": 0},
            "status": "COMPLETED",
            "type": "TRANSACTION"
        })
    );

    let last_neuron_id = operations
        .last()
        .unwrap()
        .get("metadata")
        .expect("Expecting metadata in response")
        .get("neuron_id");
    assert!(
        last_neuron_id.is_some(),
        "NeuronId should have been returned here"
    );
    let neuron_id = last_neuron_id.unwrap().as_u64();

    // Block height is the last block observed.
    // In this case the transfer to neuron_account.
    let last_block_idx = operations
        .iter()
        .rev()
        .find_map(|r| r.get("metadata").and_then(|r| r.get("block_index")));
    assert!(last_block_idx.is_some());

    let neuron_info: NeuronInfoResponse = client
        .account_balance_neuron(neuron_account, neuron_id, None, false)
        .await
        .unwrap()
        .unwrap()
        .metadata
        .try_into()
        .unwrap();
    assert_eq!(neuron_info.state, NeuronState::Dissolved);

    // Return staked account.
    (dst_acc, dst_acc_kp)
}

async fn test_staking_flow(
    client: &RosettaApiClient,
    ledger_client: &LedgerClient,
    timestamp: Seconds,
) {
    let (test_account, kp_b, _pk_b, _pid_b) = make_user_ed25519(101);
    let test_key_pair = Arc::new(kp_b);

    let (_, tip_idx) = ledger_client.get_tip().await;
    let balance_before = ledger_client.get_account_balance(test_account).await;
    let (dst_acc, dst_acc_kp, dst_acc_pk, _pid) = make_user_ed25519(1400);
    let dst_acc_kp = Arc::new(dst_acc_kp);

    let staked_amount = Tokens::new(1, 0).unwrap();

    let neuron_index = 1;
    // Could use /neuron/derive for this.
    let neuron_account =
        neuron_account_from_public_key(&GOVERNANCE_CANISTER_ID, &dst_acc_pk, neuron_index).unwrap();
    let neuron_account = from_model_account_identifier(&neuron_account).unwrap();

    let (_tid, res, _fee) = do_multiple_txn(
        client,
        &[
            RequestInfo {
                request: Request::Transfer(Operation::Transfer {
                    from: test_account,
                    to: dst_acc,
                    spender: None,
                    amount: staked_amount.checked_add(&DEFAULT_TRANSFER_FEE).unwrap(),
                    fee: DEFAULT_TRANSFER_FEE,
                }),
                sender_keypair: Arc::clone(&test_key_pair),
            },
            RequestInfo {
                request: Request::Transfer(Operation::Transfer {
                    from: dst_acc,
                    to: neuron_account,
                    spender: None,
                    amount: staked_amount,
                    fee: DEFAULT_TRANSFER_FEE,
                }),
                sender_keypair: Arc::clone(&dst_acc_kp),
            },
            RequestInfo {
                request: Request::Stake(Stake {
                    account: dst_acc,
                    neuron_index,
                }),
                sender_keypair: Arc::clone(&dst_acc_kp),
            },
            RequestInfo {
                request: Request::SetDissolveTimestamp(SetDissolveTimestamp {
                    account: dst_acc,
                    neuron_index,
                    timestamp,
                }),
                sender_keypair: Arc::clone(&dst_acc_kp),
            },
            RequestInfo {
                request: Request::StartDissolve(StartDissolve {
                    account: dst_acc,
                    neuron_index,
                }),
                sender_keypair: Arc::clone(&dst_acc_kp),
            },
            RequestInfo {
                request: Request::StopDissolve(StopDissolve {
                    account: dst_acc,
                    neuron_index,
                }),
                sender_keypair: Arc::clone(&dst_acc_kp),
            },
        ],
        false,
        None,
        None,
    )
    .await
    .unwrap();

    let expected_idx = tip_idx + 2;

    if let Some(h) = res.last_block_index() {
        assert_eq!(h, expected_idx);
    }
    let _ = client.wait_for_block_at(expected_idx).await.unwrap();

    check_balance(
        client,
        ledger_client,
        &test_account,
        balance_before
            .checked_sub(&staked_amount)
            .unwrap()
            .checked_sub(&DEFAULT_TRANSFER_FEE)
            .unwrap()
            .checked_sub(&DEFAULT_TRANSFER_FEE)
            .unwrap(),
    )
    .await;
}

async fn test_staking_flow_two_txns(
    client: &RosettaApiClient,
    ledger_client: &LedgerClient,
    timestamp: Seconds,
) {
    let (test_account, kp_b, _pk_b, _pid_b) = make_user_ed25519(101);
    let test_key_pair = Arc::new(kp_b);

    let (_, tip_idx) = ledger_client.get_tip().await;
    let balance_before = ledger_client.get_account_balance(test_account).await;

    let (dst_acc, dst_acc_kp, dst_acc_pk, _pid) = make_user_ed25519(1401);
    let dst_acc_kp = Arc::new(dst_acc_kp);

    let staked_amount = Tokens::new(1, 0).unwrap();
    let neuron_index = 1;

    // Could use /neuron/derive for this.
    let neuron_account =
        neuron_account_from_public_key(&GOVERNANCE_CANISTER_ID, &dst_acc_pk, neuron_index).unwrap();
    let neuron_account = from_model_account_identifier(&neuron_account).unwrap();

    let (_tid, _bh, _fee) = do_multiple_txn(
        client,
        &[
            RequestInfo {
                request: Request::Transfer(Operation::Transfer {
                    from: test_account,
                    to: dst_acc,
                    spender: None,
                    amount: staked_amount.checked_add(&DEFAULT_TRANSFER_FEE).unwrap(),
                    fee: DEFAULT_TRANSFER_FEE,
                }),
                sender_keypair: Arc::clone(&test_key_pair),
            },
            RequestInfo {
                request: Request::Transfer(Operation::Transfer {
                    from: dst_acc,
                    to: neuron_account,
                    spender: None,
                    amount: staked_amount,
                    fee: DEFAULT_TRANSFER_FEE,
                }),
                sender_keypair: Arc::clone(&dst_acc_kp),
            },
        ],
        false,
        None,
        None,
    )
    .await
    .unwrap();

    let (_tid, res, _fee) = do_multiple_txn(
        client,
        &[
            RequestInfo {
                request: Request::Stake(Stake {
                    account: dst_acc,
                    neuron_index,
                }),
                sender_keypair: Arc::clone(&dst_acc_kp),
            },
            RequestInfo {
                request: Request::SetDissolveTimestamp(SetDissolveTimestamp {
                    account: dst_acc,
                    neuron_index,
                    timestamp,
                }),
                sender_keypair: Arc::clone(&dst_acc_kp),
            },
            RequestInfo {
                request: Request::StartDissolve(StartDissolve {
                    account: dst_acc,
                    neuron_index,
                }),
                sender_keypair: Arc::clone(&dst_acc_kp),
            },
            RequestInfo {
                request: Request::StopDissolve(StopDissolve {
                    account: dst_acc,
                    neuron_index,
                }),
                sender_keypair: Arc::clone(&dst_acc_kp),
            },
        ],
        false,
        None,
        None,
    )
    .await
    .unwrap();

    let expected_idx = tip_idx + 2;

    if let Some(h) = res.last_block_index() {
        assert_eq!(h, expected_idx);
    }
    let _ = client.wait_for_block_at(expected_idx).await.unwrap();

    check_balance(
        client,
        ledger_client,
        &test_account,
        balance_before
            .checked_sub(&staked_amount)
            .unwrap()
            .checked_sub(&DEFAULT_TRANSFER_FEE)
            .unwrap()
            .checked_sub(&DEFAULT_TRANSFER_FEE)
            .unwrap(),
    )
    .await;
}
