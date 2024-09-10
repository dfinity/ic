use crate::rosetta_tests::{
    ledger_client::LedgerClient,
    lib::{
        create_ledger_client, do_multiple_txn, do_multiple_txn_external, make_user_ed25519,
        one_day_from_now_nanos, raw_construction, sign, to_public_key, NeuronDetails,
    },
    rosetta_client::RosettaApiClient,
    setup::setup,
    test_neurons::TestNeurons,
};
use assert_json_diff::assert_json_eq;
use ic_base_types::PrincipalId;
use ic_ledger_core::Tokens;
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_governance_api::pb::v1::neuron::{DissolveState, Followees};
use ic_rosetta_api::{
    models::operation::OperationType,
    request::{request_result::RequestResult, Request},
    request_types::{AddHotKey, NeuronInfo, PublicKeyOrPrincipal},
};
use ic_rosetta_test_utils::{EdKeypair, RequestInfo};
use ic_system_test_driver::{driver::test_env::TestEnv, util::block_on};
use rosetta_core::objects::ObjectMap;
use serde_json::{json, Value};
use std::{collections::HashMap, sync::Arc};

const PORT: u32 = 8107;
const VM_NAME: &str = "neuron-info";

pub fn test(env: TestEnv) {
    let _logger = env.logger();

    let mut ledger_balances = HashMap::new();
    let (acc, _, _, _) = make_user_ed25519(101);
    ledger_balances.insert(acc, Tokens::new(1000, 0).unwrap());

    // Create neurons.
    let mut neurons = TestNeurons::new(2000, &mut ledger_balances);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let neuron1 = neurons.create(|neuron| {
        neuron.dissolve_state = Some(DissolveState::DissolveDelaySeconds(2 * 365 * 24 * 60 * 60));
        neuron.aging_since_timestamp_seconds = now;
        neuron.maturity_e8s_equivalent = 345_000_000;
        neuron.kyc_verified = true;
        neuron.followees = HashMap::from([
            (
                0,
                Followees {
                    followees: vec![
                        NeuronId { id: 12 },
                        NeuronId { id: 34 },
                        NeuronId { id: 56 },
                    ],
                },
            ),
            (
                6,
                Followees {
                    followees: vec![NeuronId { id: 33 }],
                },
            ),
        ]);
    });
    let neuron2 = neurons.create(|neuron| {
        neuron.dissolve_state = Some(
            ic_nns_governance_api::pb::v1::neuron::DissolveState::DissolveDelaySeconds(
                3 * 365 * 24 * 60 * 60,
            ),
        );
        neuron.aging_since_timestamp_seconds = now;
        neuron.maturity_e8s_equivalent = 678_000_000;
        neuron.kyc_verified = true;
        neuron.followees = HashMap::from([
            (
                0,
                Followees {
                    followees: vec![
                        NeuronId { id: 123 },
                        NeuronId { id: 345 },
                        NeuronId { id: 567 },
                    ],
                },
            ),
            (
                7,
                Followees {
                    followees: vec![NeuronId { id: 333 }],
                },
            ),
        ]);
    });
    let neuron3 = neurons.create(|neuron| {
        neuron.dissolve_state = Some(
            ic_nns_governance_api::pb::v1::neuron::DissolveState::DissolveDelaySeconds(
                3 * 365 * 24 * 60 * 60,
            ),
        );
        neuron.aging_since_timestamp_seconds = now;
        neuron.maturity_e8s_equivalent = 679_000_000;
        neuron.kyc_verified = true;
        neuron.followees = HashMap::from([
            (
                0,
                Followees {
                    followees: vec![NeuronId { id: 111 }, NeuronId { id: 222 }],
                },
            ),
            (
                8,
                Followees {
                    followees: vec![NeuronId { id: 555 }, NeuronId { id: 666 }],
                },
            ),
        ]);
    });

    // Create Rosetta and ledger clients.
    let neurons = neurons.get_neurons();
    let client = setup(&env, PORT, VM_NAME, Some(ledger_balances), Some(neurons));
    let ledger_client = create_ledger_client(&env, &client);

    block_on(async {
        test_neuron_info(&client, &ledger_client, &neuron1).await;
        test_neuron_info_with_hotkey(&client, &ledger_client, &neuron2).await;
        test_neuron_info_with_hotkey_raw(&client, &ledger_client, &neuron3).await;
    });
}

async fn test_neuron_info(
    ros: &RosettaApiClient,
    _ledger: &LedgerClient,
    neuron_info: &NeuronDetails,
) {
    let acc = neuron_info.account_id;
    let neuron_index = neuron_info.neuron_subaccount_identifier;
    let key_pair: Arc<EdKeypair> = neuron_info.key_pair.clone().into();
    let _expected_type = "NEURON_INFO".to_string();
    let res = do_multiple_txn_external(
        ros,
        &[RequestInfo {
            request: Request::NeuronInfo(NeuronInfo {
                account: acc,
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
                .expect("Expected one neuron info operation."),
            ic_rosetta_api::models::Operation {
                type_: _expected_type,
                ..
            }
        ));
        results
    })
    .expect("Failed to retrieve neuron info");

    assert_eq!(1, res.operations.len());
    let metadata: &ObjectMap = res
        .operations
        .first()
        .unwrap()
        .metadata
        .as_ref()
        .expect("No metadata found.");
    let maturity = metadata
        .get("maturity_e8s_equivalent")
        .expect("Maturity expected")
        .as_u64()
        .unwrap();
    let kyc = metadata.get("kyc_verified").expect("KYC status expected");
    assert_eq!(345_000_000, maturity);
    assert!(kyc.as_bool().unwrap());
    assert_eq!(
        "NOT_DISSOLVING",
        metadata
            .get("state")
            .expect("State expected")
            .as_str()
            .unwrap()
    );
    let followees = metadata.get("followees").expect("Expected followees");
    assert_eq!(
        json!({
            "0": [12, 34, 56],
            "6": [33],
        }),
        *followees
    );
    let hotkeys = metadata.get("hotkeys").expect("Expected hotkeys");
    assert_eq!(json!([]), *hotkeys);
}

async fn test_neuron_info_with_hotkey(
    ros: &RosettaApiClient,
    _ledger: &LedgerClient,
    neuron_info: &NeuronDetails,
) {
    let key_pair: Arc<EdKeypair> = neuron_info.key_pair.clone().into();
    let acc = neuron_info.account_id;
    let neuron_index = neuron_info.neuron_subaccount_identifier;
    let neuron_controller = neuron_info.principal_id;

    // Add hotkey.
    let (hotkey_acc, hotkey_keypair, hotkey_pk, _) = make_user_ed25519(5000);
    do_multiple_txn(
        ros,
        &[RequestInfo {
            request: Request::AddHotKey(AddHotKey {
                account: acc,
                neuron_index,
                key: PublicKeyOrPrincipal::PublicKey(hotkey_pk.clone()),
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

    // Test neuron info operation using the hotkey.
    let res = do_multiple_txn_external(
        ros,
        &[RequestInfo {
            request: Request::NeuronInfo(NeuronInfo {
                account: hotkey_acc,
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
        assert_eq!(
            results.operations.len(),
            1,
            "Expecting exactly one operation."
        );
        assert_eq!(
            ic_rosetta_api::models::operation::OperationType::NeuronInfo,
            results.operations[0]
                .type_
                .parse::<OperationType>()
                .unwrap(),
            "Expecting one neuron info operation."
        );
        results
    })
    .expect("Failed to retrieve neuron info with hotkey");

    assert_eq!(1, res.operations.len());
    let metadata: &ObjectMap = res
        .operations
        .first()
        .unwrap()
        .metadata
        .as_ref()
        .expect("No metadata found.");
    let maturity = metadata
        .get("maturity_e8s_equivalent")
        .expect("Maturity expected");
    let kyc = metadata.get("kyc_verified").expect("KYC status expected");
    assert_eq!(678_000_000, maturity.as_u64().unwrap());
    assert!(kyc.as_bool().unwrap());
    assert_eq!(
        "NOT_DISSOLVING",
        metadata
            .get("state")
            .expect("State expected")
            .as_str()
            .unwrap()
    );

    let followees = metadata.get("followees").expect("Expected followees");
    assert_eq!(
        json!({
            "0": [123, 345, 567],
            "7": [333],
        }),
        *followees
    );
    let hotkeys = metadata.get("hotkeys").expect("Expected hotkeys");
    let hotkey_pid = PrincipalId::try_from(&PublicKeyOrPrincipal::PublicKey(hotkey_pk)).unwrap();
    assert_eq!(json!([hotkey_pid]), *hotkeys);
}

async fn test_neuron_info_with_hotkey_raw(
    ros: &RosettaApiClient,
    _ledger: &LedgerClient,
    neuron_info: &NeuronDetails,
) {
    let key_pair: Arc<EdKeypair> = neuron_info.key_pair.clone().into();
    let acc = neuron_info.account_id;
    let neuron_index = neuron_info.neuron_subaccount_identifier;
    let neuron_controller = neuron_info.principal_id;

    // Add hotkey.
    let (hotkey_acc, hotkey_keypair, hotkey_pk, _) = make_user_ed25519(5000);
    do_multiple_txn(
        ros,
        &[RequestInfo {
            request: Request::AddHotKey(AddHotKey {
                account: acc,
                neuron_index,
                key: PublicKeyOrPrincipal::PublicKey(hotkey_pk.clone()),
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
    // Neuron info (raw calls).
    //

    // Key pairs as Json.
    let _pk_org = serde_json::to_value(to_public_key(&key_pair)).unwrap();
    let pk_hotkey = serde_json::to_value(to_public_key(&hotkey_keypair)).unwrap();

    // Call /construction/derive.
    let req_derive = json!({
        "network_identifier": &ros.network_id(),
        "public_key": pk_hotkey,
        "metadata": {
            "account_type": "ledger"
        }
    });
    let _res_derive = raw_construction(ros, "derive", req_derive).await;

    // Call /construction/preprocess
    // Test both public_key and principal for identifying controller.
    let operations = json!([
        {
            "operation_identifier": {
                "index": 0
            },
            "type": "NEURON_INFO",
            "account": {
                "address": &hotkey_acc
            },
            "metadata": {
                "controller": {
                    "public_key": neuron_info.public_key,
                },
                "neuron_index": &neuron_index
            }
        },
        {
            "operation_identifier": {
                "index": 1
            },
            "type": "NEURON_INFO",
            "account": {
                "address": &hotkey_acc
            },
            "metadata": {
                "controller": {
                    "principal": neuron_controller,
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
                    "NEURON_INFO": {
                        "controller": {
                            "principal": neuron_controller
                        },
                        "neuron_index": &neuron_index
                    }
                },
                {
                    "NEURON_INFO": {
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
    let req_metadata = json!({
        "network_identifier": &ros.network_id(),
        "options": options,
        "public_keys": [pk_hotkey]
    });
    let res_metadata = raw_construction(ros, "metadata", req_metadata).await;
    // NB: metadata response will have to be added to payloads request.

    // Call /construction/payloads
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
    let req_parse = json!({
        "network_identifier": &ros.network_id(),
        "signed": false,
        "transaction": &unsigned_transaction
    });
    let _res_parse = raw_construction(ros, "parse", req_parse).await;

    // Call /construction/combine.
    // NB: we always have to sign ingress and read payloads.
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
    let signed_transaction: &Value = res_combine.get("signed_transaction").unwrap();
    let req_parse = json!({
        "network_identifier": &ros.network_id(),
        "signed": true,
        "transaction": &signed_transaction
    });
    let _res_parse = raw_construction(ros, "parse", req_parse).await;

    // Call /construction/hash.
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
        "Expecting 2 operations for the NEURON_INFO transaction."
    );
    for op in operations.iter() {
        assert_eq!(
            op.get("status").unwrap(),
            "COMPLETED",
            "Operation didn't complete."
        );
        assert_eq!(
            op.get("type").unwrap(),
            "NEURON_INFO",
            "Operation should be NEURON_INFO."
        );
    }
    assert_eq!(2, operations.len());
    let metadata = operations
        .first()
        .unwrap()
        .get("metadata")
        .expect("No metadata found.");
    let maturity = metadata
        .get("maturity_e8s_equivalent")
        .expect("Maturity expected");
    let kyc = metadata.get("kyc_verified").expect("KYC status expected");
    assert_eq!(679_000_000, maturity.as_u64().unwrap());
    assert!(kyc.as_bool().unwrap());
    assert_eq!(
        "NOT_DISSOLVING",
        metadata
            .get("state")
            .expect("State expected")
            .as_str()
            .unwrap()
    );
    let followees = metadata.get("followees").expect("Expected followees");
    assert_eq!(
        json!({
            "0": [111, 222],
            "8": [555, 666],
        }),
        *followees
    );
    let hotkeys = metadata.get("hotkeys").expect("Expected hotkeys");
    let hotkey_pid = PrincipalId::try_from(&PublicKeyOrPrincipal::PublicKey(hotkey_pk)).unwrap();
    assert_eq!(json!([hotkey_pid]), *hotkeys);
}
