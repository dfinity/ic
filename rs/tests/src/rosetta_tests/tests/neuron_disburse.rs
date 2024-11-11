use crate::rosetta_tests::{
    ledger_client::LedgerClient,
    lib::{
        check_balance, create_ledger_client, do_multiple_txn, make_user_ed25519,
        one_day_from_now_nanos, sign_txn, to_public_key, NeuronDetails,
    },
    rosetta_client::RosettaApiClient,
    setup::setup,
    test_neurons::TestNeurons,
};
use ic_ledger_core::{
    tokens::{CheckedAdd, CheckedSub},
    Tokens,
};
use ic_nns_governance_api::pb::v1::{neuron::DissolveState, Neuron};
use ic_rosetta_api::{
    models::{ConstructionPayloadsResponse, SignedTransaction},
    request::{
        request_result::RequestResult, transaction_operation_results::TransactionOperationResults,
        Request,
    },
    request_types::{Disburse, Status},
};
use ic_rosetta_test_utils::RequestInfo;
use ic_system_test_driver::{driver::test_env::TestEnv, util::block_on};
use icp_ledger::{AccountIdentifier, DEFAULT_TRANSFER_FEE};
use rosetta_core::objects::ObjectMap;
use serde_json::json;
use slog::Logger;
use std::{collections::HashMap, str::FromStr, sync::Arc, time::UNIX_EPOCH};

const PORT: u32 = 8104;
const VM_NAME: &str = "neuron-disburse";

pub fn test(env: TestEnv) {
    let logger = env.logger();

    let mut ledger_balances = HashMap::new();

    // Create neurons.
    let neuron_setup = |neuron: &mut Neuron| {
        neuron.dissolve_state = Some(DissolveState::WhenDissolvedTimestampSeconds(0))
    };

    let one_year_from_now = 60 * 60 * 24 * 365
        + std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

    let mut neurons = TestNeurons::new(2000, &mut ledger_balances);

    let neuron1 = neurons.create(neuron_setup);
    let neuron2 = neurons.create(neuron_setup);
    let neuron3 = neurons.create(neuron_setup);
    let neuron4 = neurons.create(|neuron| {
        neuron.dissolve_state = Some(DissolveState::WhenDissolvedTimestampSeconds(
            one_year_from_now,
        ))
    });
    let neuron5 = neurons.create(neuron_setup);
    let neuron6 = neurons.create(neuron_setup);
    let neuron7 = neurons.create(neuron_setup);

    // Create Rosetta and ledger clients.
    let neurons = neurons.get_neurons();
    let client = setup(&env, PORT, VM_NAME, Some(ledger_balances), Some(neurons));
    let ledger_client = create_ledger_client(&env, &client);

    block_on(async {
        test_disburse_raw(&client, &ledger_client, &neuron1, None, None, &logger)
            .await
            .expect("Failed test raw disburse");

        test_disburse(&client, &ledger_client, &neuron2, None, None)
            .await
            .expect("Failed test disburse");

        // Disburse to custom recipient.
        let (recipient, _, _, _) = make_user_ed25519(102);
        test_disburse(&client, &ledger_client, &neuron3, None, Some(recipient))
            .await
            .expect("Failed test disburse to custom recipient");

        // Disburse before neuron is dissolved (fail expected).
        test_disburse(&client, &ledger_client, &neuron4, None, Some(recipient))
            .await
            .unwrap_err();

        // Disburse an amount.
        test_disburse(
            &client,
            &ledger_client,
            &neuron5,
            Some(Tokens::new(5, 0).unwrap()),
            None,
        )
        .await
        .expect("Failed test disburse an amount");

        // Disburse full stake.
        test_disburse(
            &client,
            &ledger_client,
            &neuron6,
            Some(Tokens::new(10, 0).unwrap()),
            None,
        )
        .await
        .expect("Failed test disburse full stake");

        // Disburse more than staked amount.
        test_disburse(
            &client,
            &ledger_client,
            &neuron7,
            Some(Tokens::new(11, 0).unwrap()),
            None,
        )
        .await
        .unwrap_err()
    });
}

#[allow(clippy::too_many_arguments)]
async fn test_disburse(
    ros: &RosettaApiClient,
    ledger_client: &LedgerClient,
    neuron_info: &NeuronDetails,
    amount: Option<Tokens>,
    recipient: Option<AccountIdentifier>,
) -> Result<(), ic_rosetta_api::models::Error> {
    let neuron = &neuron_info.neuron;
    let acc = neuron_info.account_id;
    let key_pair = Arc::new(neuron_info.key_pair.clone());
    let neuron_index = neuron_info.neuron_subaccount_identifier;

    let pre_disburse = ledger_client.get_account_balance(acc).await;
    let (_, tip_idx) = ledger_client.get_tip().await;

    let res = do_multiple_txn(
        ros,
        &[RequestInfo {
            request: Request::Disburse(Disburse {
                account: acc,
                amount,
                recipient,
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
            results.operations.first().unwrap(),
            RequestResult {
                _type: Request::Disburse(_),
                status: Status::Completed,
                ..
            }
        ));
        results
    })?;

    let amount = amount.unwrap_or_else(|| Tokens::from_e8s(neuron.cached_neuron_stake_e8s));

    let expected_idx = tip_idx + 1;

    if let Some(h) = res.last_block_index() {
        assert_eq!(h, expected_idx);
    }
    let _ = ros.wait_for_block_at(expected_idx).await.unwrap();

    // governance assumes the default fee for disburse and that's why this check uses the
    // DEFAULT_TRANSFER_FEE.
    check_balance(
        ros,
        ledger_client,
        &recipient.unwrap_or(acc),
        pre_disburse
            .checked_add(&amount)
            .unwrap()
            .checked_sub(&DEFAULT_TRANSFER_FEE)
            .unwrap(),
    )
    .await;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn test_disburse_raw(
    ros: &RosettaApiClient,
    ledger_client: &LedgerClient,
    neuron_info: &NeuronDetails,
    amount: Option<Tokens>,
    recipient: Option<AccountIdentifier>,
    _logger: &Logger,
) -> Result<(), ic_rosetta_api::models::Error> {
    let neuron = &neuron_info.neuron;
    let acc = neuron_info.account_id;
    let key_pair = Arc::new(neuron_info.key_pair.clone());
    let neuron_index = neuron_info.neuron_subaccount_identifier;

    let pre_disburse = ledger_client.get_account_balance(acc).await;
    let (_, tip_idx) = ledger_client.get_tip().await;
    let req = json!({
        "network_identifier": &ros.network_id(),
        "operations": [
            {
                "operation_identifier": {
                    "index": 0
                },
                "type": "DISBURSE",
                "account": {
                    "address": &acc
                },
                "metadata": {
                    "neuron_index": &neuron_index
                }
            }
        ]
    });
    let req = req.to_string();

    let metadata: ObjectMap = serde_json::from_slice(
        &ros.raw_construction_endpoint("metadata", req.as_bytes())
            .await
            .unwrap()
            .0,
    )
    .unwrap();

    let mut req: ObjectMap = serde_json::from_str(&req).unwrap();
    req.insert("metadata".to_string(), metadata.into());
    req.insert(
        "public_keys".to_string(),
        serde_json::to_value(vec![to_public_key(&key_pair)]).unwrap(),
    );

    let payloads: ConstructionPayloadsResponse = serde_json::from_slice(
        &ros.raw_construction_endpoint("payloads", &serde_json::to_vec_pretty(&req).unwrap())
            .await
            .unwrap()
            .0,
    )
    .unwrap();

    let signed = sign_txn(ros, &[key_pair.clone()], payloads).await.unwrap();

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

    for op in TransactionOperationResults::try_from(submit_res.metadata)
        .unwrap()
        .operations
        .iter()
    {
        assert_eq!(
            op.status.as_ref().expect("Expecting status to be set."),
            "COMPLETED",
            "Operation didn't complete."
        );
    }

    let amount = amount.unwrap_or_else(|| Tokens::from_e8s(neuron.cached_neuron_stake_e8s));
    let expected_idx = tip_idx + 1;
    let _ = ros.wait_for_block_at(expected_idx).await.unwrap();

    // governance assumes the default fee for disburse and that's why this check uses the
    // DEFAULT_TRANSFER_FEE.
    check_balance(
        ros,
        ledger_client,
        &recipient.unwrap_or(acc),
        pre_disburse
            .checked_add(&amount)
            .unwrap()
            .checked_sub(&DEFAULT_TRANSFER_FEE)
            .unwrap(),
    )
    .await;
    Ok(())
}
