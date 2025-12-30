use anyhow::Result;
use assert_json_diff::assert_json_eq;
use ic_rosetta_api::{
    request::{Request, request_result::RequestResult},
    request_types::{AddHotKey, Follow, PublicKeyOrPrincipal},
};
use ic_rosetta_test_utils::{EdKeypair, RequestInfo};
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_system_test_driver::{driver::test_env::TestEnv, util::block_on};
use rosetta_test_lib::{
    ledger_client::LedgerClient,
    rosetta_client::RosettaApiClient,
    setup::{ROSETTA_TESTS_OVERALL_TIMEOUT, ROSETTA_TESTS_PER_TEST_TIMEOUT, setup},
    test_neurons::TestNeurons,
    utils::{
        NeuronDetails, create_ledger_client, do_multiple_txn, do_multiple_txn_external,
        make_user_ed25519, one_day_from_now_nanos, raw_construction, sign, to_public_key,
    },
};
use serde_json::{Value, json};
use std::{collections::HashMap, sync::Arc};

const PORT: u32 = 8108;
const VM_NAME: &str = "neuron-follow";
const NUM_NEURONS_TO_FOLLOW: usize = 16;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(group_setup)
        .with_overall_timeout(ROSETTA_TESTS_OVERALL_TIMEOUT)
        .with_timeout_per_test(ROSETTA_TESTS_PER_TEST_TIMEOUT)
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}

fn group_setup(_env: TestEnv) {}

pub fn test(env: TestEnv) {
    let _logger = env.logger();

    let mut ledger_balances = HashMap::new();

    // Create neurons.
    let mut neurons = TestNeurons::new(2000, &mut ledger_balances);

    let neuron1 = neurons.create(|neuron| {
        neuron.maturity_e8s_equivalent = 300_000_000;
    });
    let neuron2 = neurons.create(|neuron| {
        neuron.maturity_e8s_equivalent = 300_000_000;
    });
    let neuron3 = neurons.create(|neuron| {
        neuron.maturity_e8s_equivalent = 300_000_000;
    });
    let neuron4 = neurons.create(|neuron| {
        neuron.maturity_e8s_equivalent = 300_000_000;
    });
    let mut neurons_to_follow = vec![];
    for _ in 0..NUM_NEURONS_TO_FOLLOW {
        let n = neurons.create(|neuron| {
            neuron.maturity_e8s_equivalent = 100_000_000;
        });
        neurons_to_follow.push(n);
    }

    // Create Rosetta and ledger clients.
    let neurons = neurons.get_neurons();
    let client = setup(&env, PORT, VM_NAME, Some(ledger_balances), Some(neurons));
    let ledger_client = create_ledger_client(&env, &client);

    block_on(async {
        test_follow(&client, &ledger_client, &neuron1, &neurons_to_follow).await;
        test_follow_with_hotkey(&client, &ledger_client, &neuron2, &neurons_to_follow).await;
        test_follow_with_hotkey_raw(&client, &ledger_client, &neuron3, &neurons_to_follow).await;
        test_follow_too_many(&client, &ledger_client, &neuron4, &neurons_to_follow).await;
    });
}

async fn test_follow(
    ros: &RosettaApiClient,
    _ledger: &LedgerClient,
    neuron_info: &NeuronDetails,
    neurons_to_follow: &[NeuronDetails],
) {
    // IDs of neurons to follow (f1 and f2).
    let f1 = neurons_to_follow.first().unwrap().neuron.id.unwrap().id;
    let f2 = neurons_to_follow.get(1).unwrap().neuron.id.unwrap().id;

    let acc = neuron_info.account_id;
    let neuron_index = neuron_info.neuron_subaccount_identifier;
    let key_pair: Arc<EdKeypair> = neuron_info.key_pair.clone().into();
    let _expected_type = "FOLLOW".to_string();
    let res = do_multiple_txn_external(
        ros,
        &[RequestInfo {
            request: Request::Follow(Follow {
                account: acc,
                topic: 0, // 0 is "Unspecified" topic.
                followees: vec![f1, f2],
                controller: None,
                neuron_index,
            }),
            sender_keypair: Arc::clone(&key_pair),
        }],
        false,
        Some(one_day_from_now_nanos()),
        None,
    )
    .await
    .map(|(tx_id, results, _)| {
        assert!(!tx_id.is_transfer());
        assert!(matches!(
            results
                .operations
                .first()
                .expect("Expected one follow operation."),
            ic_rosetta_api::models::Operation {
                type_: _expected_type,
                ..
            }
        ));
        results
    })
    .expect("Failed to follow");

    assert_eq!(1, res.operations.len());
    let status = res
        .operations
        .first()
        .unwrap()
        .status
        .as_ref()
        .expect("Status expected");
    assert_eq!(status, "COMPLETED");
}

async fn test_follow_with_hotkey(
    ros: &RosettaApiClient,
    _ledger: &LedgerClient,
    neuron_info: &NeuronDetails,
    neurons_to_follow: &[NeuronDetails],
) {
    // IDs of neurons to follow (f1 and f2).
    let f1 = neurons_to_follow.first().unwrap().neuron.id.unwrap().id;
    let f2 = neurons_to_follow.get(1).unwrap().neuron.id.unwrap().id;

    let acc = neuron_info.account_id;
    let neuron_index = neuron_info.neuron_subaccount_identifier;
    let neuron_controller = neuron_info.principal_id;
    let key_pair: Arc<EdKeypair> = neuron_info.key_pair.clone().into();

    // Add hotkey.
    let (hotkey_acc, hotkey_keypair, hotkey_pk, _) = make_user_ed25519(5010);
    do_multiple_txn(
        ros,
        &[RequestInfo {
            request: Request::AddHotKey(AddHotKey {
                account: acc,
                neuron_index,
                key: PublicKeyOrPrincipal::PublicKey(hotkey_pk),
            }),
            sender_keypair: Arc::clone(&key_pair),
        }],
        false,
        Some(one_day_from_now_nanos()),
        None,
    )
    .await
    .map(|(tx_id, results, _)| {
        assert!(!tx_id.is_transfer());
        assert!(matches!(
            results.operations.first().unwrap(),
            RequestResult {
                _type: Request::AddHotKey(_),
                ..
            }
        ));
    })
    .expect("Error while adding hotkey.");
    let hotkey_keypair: Arc<EdKeypair> = hotkey_keypair.into();
    println!("Added hotkey for neuron management");

    // Follow.
    let _expected_type = "FOLLOW".to_string();
    let res = do_multiple_txn_external(
        ros,
        &[RequestInfo {
            request: Request::Follow(Follow {
                account: hotkey_acc,
                topic: 0, // 0 is "Unspecified" topic.
                followees: vec![f1, f2],
                controller: Some(neuron_controller),
                neuron_index,
            }),
            sender_keypair: Arc::clone(&hotkey_keypair),
        }],
        false,
        Some(one_day_from_now_nanos()),
        None,
    )
    .await
    .map(|(tx_id, results, _)| {
        assert!(!tx_id.is_transfer());
        assert!(matches!(
            results
                .operations
                .first()
                .expect("Expected one follow operation."),
            ic_rosetta_api::models::Operation {
                type_: _expected_type,
                ..
            }
        ));
        results
    })
    .expect("Failed to follow");

    assert_eq!(1, res.operations.len());
    let status = res
        .operations
        .first()
        .unwrap()
        .status
        .as_ref()
        .expect("Status expected");
    assert_eq!(status, "COMPLETED");
}

async fn test_follow_with_hotkey_raw(
    ros: &RosettaApiClient,
    _ledger: &LedgerClient,
    neuron_info: &NeuronDetails,
    neurons_to_follow: &[NeuronDetails],
) {
    // IDs of neurons to follow (f1, f2, and f3).
    let f1 = neurons_to_follow.first().unwrap().neuron.id.unwrap().id;
    let f2 = neurons_to_follow.get(1).unwrap().neuron.id.unwrap().id;
    let f3 = neurons_to_follow.get(2).unwrap().neuron.id.unwrap().id;

    let acc = neuron_info.account_id;
    let neuron_index = neuron_info.neuron_subaccount_identifier;
    let neuron_controller = neuron_info.principal_id;
    let key_pair: Arc<EdKeypair> = neuron_info.key_pair.clone().into();

    // Add hotkey.
    let (hotkey_acc, hotkey_keypair, hotkey_pk, _) = make_user_ed25519(5010);
    do_multiple_txn(
        ros,
        &[RequestInfo {
            request: Request::AddHotKey(AddHotKey {
                account: acc,
                neuron_index,
                key: PublicKeyOrPrincipal::PublicKey(hotkey_pk),
            }),
            sender_keypair: Arc::clone(&key_pair),
        }],
        false,
        Some(one_day_from_now_nanos()),
        None,
    )
    .await
    .map(|(tx_id, results, _)| {
        assert!(!tx_id.is_transfer());
        assert!(matches!(
            results.operations.first().unwrap(),
            RequestResult {
                _type: Request::AddHotKey(_),
                ..
            }
        ));
    })
    .expect("Error while adding hotkey.");
    let hotkey_keypair: Arc<EdKeypair> = hotkey_keypair.into();
    println!("Added hotkey for neuron management");

    //
    // Follow (raw calls).
    //

    // Key pairs as Json.
    let _pk_org = serde_json::to_value(to_public_key(&key_pair)).unwrap();
    let pk_hotkey = serde_json::to_value(to_public_key(&hotkey_keypair)).unwrap();

    // Call /construction/derive.
    println!("Calling /construction/derive");
    let req_derive = json!({
        "network_identifier": &ros.network_id(),
        "public_key": pk_hotkey,
        "metadata": {
            "account_type": "ledger"
        }
    });
    let _res_derive = raw_construction(ros, "derive", req_derive).await;

    // Call /construction/preprocess
    // Test using public key instead of controller principal id.
    // (this is the red/green test for ROSETTA1-247).
    println!("Calling /construction/preprocess");
    let operations = json!([
        {
            "operation_identifier": {
                "index": 0
            },
            "type": "FOLLOW",
            "account": {
                "address": &hotkey_acc
            },
            "metadata": {
                "topic": 0,
                "followees": [
                    f1,
                    f2
                ],
                "controller": {
                    "public_key": neuron_info.public_key
                },
                "neuron_index": &neuron_index
            }
        },
        {
            "operation_identifier": {
                "index": 1
            },
            "type": "FOLLOW",
            "account": {
                "address": &hotkey_acc
            },
            "metadata": {
                "topic": 5,
                "followees": [
                    f3,
                ],
                "controller": {
                    "principal": neuron_controller
                },
                "neuron_index": &neuron_index
            }
        }
    ]);
    let req_preprocess = json!({
        "network_identifier": &ros.network_id(),
        "operations": operations,
        "metadata": {},
    });
    let res_preprocess = raw_construction(ros, "preprocess", req_preprocess).await;
    let options = res_preprocess.get("options");
    assert_json_eq!(
        json!({
            "request_types": [
                {
                    "FOLLOW": {
                        "controller": {
                            "principal": neuron_controller
                        },
                        "neuron_index": &neuron_index
                    }
                },
                {
                    "FOLLOW": {
                        "controller": {
                            "principal": neuron_controller
                        },
                        "neuron_index": &neuron_index
                    }
                }
            ]
        }),
        options.unwrap()
    );

    // Call /construction/metadata
    println!("Calling /construction/metadata");
    let req_metadata = json!({
        "network_identifier": &ros.network_id(),
        "options": options,
        "public_keys": [pk_hotkey]
    });
    let res_metadata = raw_construction(ros, "metadata", req_metadata).await;
    // NB: metadata response will have to be added to payloads request.

    // Call /construction/payloads
    println!("Calling /construction/payloads");
    let req_payloads = json!({
        "network_identifier": &ros.network_id(),
        "operations": operations,
        "metadata": res_metadata,
        "public_keys": [pk_hotkey]
    });
    let res_payloads = raw_construction(ros, "payloads", req_payloads).await;
    let unsigned_transaction: &Value = res_payloads.get("unsigned_transaction").unwrap();
    let payloads = res_payloads.get("payloads").unwrap();
    let payloads = payloads.as_array().unwrap();
    assert_eq!(4, payloads.len(), "Expecting 4 payloads.");

    // Call /construction/parse (unsigned).
    println!("Calling /construction/parse (unsigned)");
    let req_parse = json!({
        "network_identifier": &ros.network_id(),
        "signed": false,
        "transaction": &unsigned_transaction
    });
    let _res_parse = raw_construction(ros, "parse", req_parse).await;

    // Call /construction/combine.
    // NB: we always have to sign ingress and read payloads.
    println!("Calling /construction/combine");
    let signatures = json!([
        {
            "signing_payload": payloads[0],
            "public_key": pk_hotkey,
            "signature_type": "ed25519",
            "hex_bytes": sign(&payloads[0], &hotkey_keypair)
        },
        {
            "signing_payload": payloads[1],
            "public_key": pk_hotkey,
            "signature_type": "ed25519",
            "hex_bytes": sign(&payloads[1], &hotkey_keypair)
        },
        {
            "signing_payload": payloads[2],
            "public_key": pk_hotkey,
            "signature_type": "ed25519",
            "hex_bytes": sign(&payloads[2], &hotkey_keypair)
        },
        {
            "signing_payload": payloads[3],
            "public_key": pk_hotkey,
            "signature_type": "ed25519",
            "hex_bytes": sign(&payloads[3], &hotkey_keypair)
        }
    ]);
    let req_combine = json!({
        "network_identifier": &ros.network_id(),
        "unsigned_transaction": &unsigned_transaction,
        "signatures": signatures
    });
    let res_combine = raw_construction(ros, "combine", req_combine).await;

    // Call /construction/parse (signed).
    println!("Calling /construction/parse (signed)");
    let signed_transaction: &Value = res_combine.get("signed_transaction").unwrap();
    let req_parse = json!({
        "network_identifier": &ros.network_id(),
        "signed": true,
        "transaction": &signed_transaction
    });
    let _res_parse = raw_construction(ros, "parse", req_parse).await;

    // Call /construction/hash.
    println!("Calling /construction/hash");
    let req_hash = json!({
        "network_identifier": &ros.network_id(),
        "signed_transaction": &signed_transaction
    });
    let _res_hash = raw_construction(ros, "hash", req_hash).await;

    // Call /construction/submit.
    let req_submit = json!({
        "network_identifier": &ros.network_id(),
        "signed_transaction": &signed_transaction
    });
    let res_submit = raw_construction(ros, "submit", req_submit).await;

    // Check submit results.
    let operations = res_submit
        .get("metadata")
        .unwrap()
        .get("operations")
        .unwrap()
        .as_array()
        .unwrap();
    assert_eq!(
        2,
        operations.len(),
        "Expecting 2 operations for the FOLLOW transaction."
    );
    for op in operations.iter() {
        assert_eq!(
            op.get("status").unwrap(),
            "COMPLETED",
            "Operation didn't complete."
        );
    }
}

/// Test adding too many followees (max allowed by governance is 15).
async fn test_follow_too_many(
    ros: &RosettaApiClient,
    _ledger: &LedgerClient,
    neuron_info: &NeuronDetails,
    neurons_to_follow: &[NeuronDetails],
) {
    let acc = neuron_info.account_id;
    let neuron_index = neuron_info.neuron_subaccount_identifier;
    let key_pair: Arc<EdKeypair> = neuron_info.key_pair.clone().into();
    let _expected_type = "FOLLOW".to_string();
    let followees: Vec<u64> = neurons_to_follow
        .iter()
        .take(NUM_NEURONS_TO_FOLLOW)
        .map(|n| n.neuron.id.unwrap().id)
        .collect();
    let res = do_multiple_txn_external(
        ros,
        &[RequestInfo {
            request: Request::Follow(Follow {
                account: acc,
                topic: 0, // 0 is "Unspecified" topic.
                followees,
                controller: None,
                neuron_index,
            }),
            sender_keypair: Arc::clone(&key_pair),
        }],
        false,
        Some(one_day_from_now_nanos()),
        None,
    )
    .await;
    assert!(
        res.is_err(),
        "Expecting an error while following too many neurons (16 followed while limit is 15)."
    );
    let res = res.unwrap_err();
    assert_eq!(res.0.code, 770);
    assert_eq!(res.0.message, "Operation failed");
}
