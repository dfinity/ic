use crate::rosetta_tests::lib::{
    acc_id, assert_ic_error, create_ledger_client, create_neuron, do_multiple_txn, make_user,
    make_user_ed25519, one_day_from_now_nanos, prepare_txn, sign_txn, NeuronDetails,
};
use crate::rosetta_tests::rosetta_client::RosettaApiClient;
use crate::rosetta_tests::setup::{setup, TRANSFER_FEE};
use ic_ledger_core::Tokens;
use ic_rosetta_api::models::SignedTransaction;
use ic_rosetta_api::request::request_result::RequestResult;
use ic_rosetta_api::request::Request;
use ic_rosetta_api::request_types::{AddHotKey, PublicKeyOrPrincipal, RemoveHotKey, Status};
use ic_rosetta_test_utils::{EdKeypair, RequestInfo};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::util::block_on;
use icp_ledger::Operation;
use slog::Logger;
use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

const PORT: u32 = 8105;
const VM_NAME: &str = "rosetta-neuron-hotkey";

pub fn test(env: TestEnv) {
    let logger = env.logger();

    // Create initial ledger balances.
    let mut ledger_balances = HashMap::new();

    // Create neurons.
    let neuron1 = create_neuron(2001, |_| {}, &mut ledger_balances);
    let neuron2 = create_neuron(2002, |_| {}, &mut ledger_balances);
    let mut neurons = BTreeMap::new();
    neurons.insert(neuron1.neuron.id.unwrap().id, neuron1.neuron.clone());
    neurons.insert(neuron2.neuron.id.unwrap().id, neuron2.neuron.clone());

    // Create Rosetta and ledger clients.
    let client = setup(&env, PORT, VM_NAME, Some(ledger_balances), Some(neurons));
    let _ledger_client = create_ledger_client(&env, &client);

    block_on(async {
        test_add_hotkey(&client, &neuron1, &logger)
            .await
            .expect("add_hotkey test failed");
        test_remove_hotkey(&client, &neuron2, &logger).await;
        test_wrong_key(&client, &logger).await;
    });
}

async fn test_add_hotkey(
    ros: &RosettaApiClient,
    neuron_info: &NeuronDetails,
    _logger: &Logger,
) -> Result<(), ic_rosetta_api::models::Error> {
    let _neuron = &neuron_info.neuron;
    let acc = neuron_info.account_id;
    let key_pair = Arc::new(neuron_info.key_pair.clone());
    let neuron_index = neuron_info.neuron_subaccount_identifier;

    let (_, _, pk, pid) = make_user(1400);

    let r = do_multiple_txn(
        ros,
        &[RequestInfo {
            request: Request::AddHotKey(AddHotKey {
                account: acc,
                neuron_index,
                key: PublicKeyOrPrincipal::PublicKey(pk),
            }),
            sender_keypair: Arc::clone(&key_pair),
        }],
        false,
        Some(
            (ic_types::time::current_time() + Duration::from_secs(24 * 60 * 60))
                .as_nanos_since_unix_epoch(),
        ),
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
    });

    do_multiple_txn(
        ros,
        &[RequestInfo {
            request: Request::AddHotKey(AddHotKey {
                account: acc,
                neuron_index,
                key: PublicKeyOrPrincipal::Principal(pid),
            }),
            sender_keypair: Arc::clone(&key_pair),
        }],
        false,
        None,
        Some(
            (ic_types::time::current_time() + Duration::from_secs(24 * 60 * 60))
                .as_nanos_since_unix_epoch(),
        ),
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
    .unwrap_or_else(|e| panic!("{:?}", e));
    r
}

async fn test_remove_hotkey(
    ros: &RosettaApiClient,
    neuron_details: &NeuronDetails,
    _logger: &Logger,
) {
    let key_pair: Arc<EdKeypair> = neuron_details.key_pair.clone().into();
    let account = neuron_details.account_id;
    let neuron_index = neuron_details.neuron_subaccount_identifier;
    let _neuron_controller = neuron_details.principal_id;

    // Add hot key.
    let (_hotkey_acc, hotkey_keypair, hotkey_pk, _) = make_user(6000);
    do_multiple_txn(
        ros,
        &[RequestInfo {
            request: Request::AddHotKey(AddHotKey {
                account,
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
                status: Status::Completed,
                ..
            }
        ));
    })
    .expect("Error while adding hotkey.");
    let _hotkey_keypair: Arc<EdKeypair> = hotkey_keypair.into();
    println!("Added hotkey for neuron management");

    // Remove hot key (success)
    do_multiple_txn(
        ros,
        &[RequestInfo {
            request: Request::RemoveHotKey(RemoveHotKey {
                account: neuron_details.account_id,
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
                _type: Request::RemoveHotKey(_),
                status: Status::Completed,
                ..
            }
        ));
    })
    .expect("Error while removing hotkey.");
    println!("Removed hotkey successfully");

    // Remove hot key again (error expected)
    let res = do_multiple_txn(
        ros,
        &[RequestInfo {
            request: Request::RemoveHotKey(RemoveHotKey {
                account: neuron_details.account_id,
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
                _type: Request::RemoveHotKey(_),
                status: Status::Failed(_),
                ..
            }
        ));
    });
    assert!(
        res.is_err(),
        "Expecting an error while removing twice the hotkey."
    );
    let res = res.unwrap_err();
    assert_eq!(res.0.code, 770);
    assert_eq!(res.0.message, "Operation failed");
}

// Sign a transaction with wrong key and check if it gets rejected
async fn test_wrong_key(ros: &RosettaApiClient, _logger: &Logger) {
    let (acc_a, kp_a, _pk_a, _pid_a) = make_user_ed25519(100);
    let key_pair = Arc::new(kp_a);
    let (_acc, wrong_kp, _wrong_pk, _pid) = make_user_ed25519(1052);
    let t = Operation::Transfer {
        from: acc_a,
        to: acc_id(1051),
        spender: None,
        amount: Tokens::from_e8s(100),
        fee: Tokens::from_e8s(TRANSFER_FEE),
    };

    let (payloads, _fee) = prepare_txn(ros, t, key_pair, false, None, None)
        .await
        .unwrap();

    let signed = SignedTransaction::from_str(
        &sign_txn(ros, &[Arc::new(wrong_kp)], payloads)
            .await
            .unwrap()
            .signed_transaction,
    )
    .unwrap();
    let err = ros.construction_submit(signed).await.unwrap().unwrap_err();
    assert_ic_error(&err, 740, 403, "does not match the public key");
}
