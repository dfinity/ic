use crate::rosetta_tests::{
    ledger_client::LedgerClient,
    lib::{
        check_balance, create_ledger_client, do_multiple_txn, one_day_from_now_nanos, NeuronDetails,
    },
    rosetta_client::RosettaApiClient,
    setup::setup,
    test_neurons::TestNeurons,
};
use ic_ledger_core::Tokens;
use ic_nns_governance_api::pb::v1::Neuron;
use ic_rosetta_api::{
    models::EdKeypair,
    request::{request_result::RequestResult, Request},
    request_types::{ChangeAutoStakeMaturity, StakeMaturity, Status},
};
use ic_rosetta_test_utils::RequestInfo;
use ic_system_test_driver::{driver::test_env::TestEnv, util::block_on};
use icp_ledger::AccountIdentifier;
use std::{collections::HashMap, sync::Arc};

const PORT: u32 = 8109;
const VM_NAME: &str = "neuron-maturity";

pub fn test(env: TestEnv) {
    let _logger = env.logger();

    let mut ledger_balances = HashMap::new();

    // Create neurons.
    let mut neurons = TestNeurons::new(2000, &mut ledger_balances);
    let neuron_setup = |neuron: &mut Neuron| {
        neuron.maturity_e8s_equivalent = 420_000_000;
    };
    let neuron1 = neurons.create(neuron_setup);
    let neuron2 = neurons.create(neuron_setup);
    let neuron3 = neurons.create(neuron_setup);
    let neuron4 = neurons.create(neuron_setup);

    // Create Rosetta and ledger clients.
    let neurons = neurons.get_neurons();
    let client = setup(&env, PORT, VM_NAME, Some(ledger_balances), Some(neurons));
    let ledger_client = create_ledger_client(&env, &client);

    block_on(async {
        test_stake_maturity_all(&client, &ledger_client, &neuron1).await;
        test_stake_maturity_partial(&client, &ledger_client, &neuron2).await;
        test_stake_maturity_invalid(&client, &neuron3).await;
        test_change_auto_stake_maturity(
            &client,
            neuron4.account_id,
            Arc::new(neuron4.key_pair.clone()),
            true,
            neuron4.neuron_subaccount_identifier,
        )
        .await;
        test_change_auto_stake_maturity(
            &client,
            neuron4.account_id,
            Arc::new(neuron4.key_pair).clone(),
            false,
            neuron4.neuron_subaccount_identifier,
        )
        .await;
    });
}

async fn test_stake_maturity_all(
    ros: &RosettaApiClient,
    ledger: &LedgerClient,
    neuron_info: &NeuronDetails,
) {
    test_stake_maturity(ros, ledger, neuron_info, None).await;
}

async fn test_stake_maturity_partial(
    ros: &RosettaApiClient,
    ledger: &LedgerClient,
    neuron_info: &NeuronDetails,
) {
    test_stake_maturity(ros, ledger, neuron_info, Some(14)).await;
}

async fn test_stake_maturity(
    ros: &RosettaApiClient,
    ledger: &LedgerClient,
    neuron_info: &NeuronDetails,
    percent: Option<u32>,
) {
    let (_, tip_idx) = ledger.get_tip().await;

    let acc = neuron_info.account_id;
    let neuron_index = neuron_info.neuron_subaccount_identifier;
    let key_pair: Arc<EdKeypair> = neuron_info.key_pair.clone().into();

    let neuron_acc = neuron_info.neuron_account;
    let balance_before = ledger.get_account_balance(neuron_acc).await;
    assert_ne!(
        balance_before.get_e8s(),
        0,
        "Neuron balance shouldn't be 0."
    );

    let res = do_multiple_txn(
        ros,
        &[RequestInfo {
            request: Request::StakeMaturity(StakeMaturity {
                account: acc,
                percentage_to_stake: Some(percent.unwrap_or(100)),
                neuron_index,
            }),
            sender_keypair: Arc::clone(&key_pair),
        }],
        true,
        Some(one_day_from_now_nanos()),
        None,
    )
    .await
    .map(|(tx_id, results, _)| {
        assert!(!tx_id.is_transfer());
        assert!(matches!(
            results.operations.first().unwrap(),
            RequestResult {
                _type: Request::StakeMaturity(_),
                status: Status::Completed,
                ..
            }
        ));
        results
    })
    .expect("failed to stake neuron maturity");

    // Check stake maturity results.
    // We expect no transaction to happen, as staking *does not* mint new tokens.
    let expected_idx = tip_idx;
    if let Some(h) = res.last_block_index() {
        assert_eq!(h, expected_idx);
    }
    // Wait for Rosetta sync.
    ros.wait_for_tip_sync(expected_idx).await.unwrap();
    let balance_after = ledger.get_account_balance(neuron_acc).await;

    assert_eq!(
        balance_before.get_e8s(),
        balance_after.get_e8s(),
        "Neuron balance should have not increased after stake_maturity."
    );

    // We should get the same results with Rosetta call (step not required though).
    check_balance(
        ros,
        ledger,
        &neuron_acc,
        Tokens::from_e8s(balance_before.get_e8s()),
    )
    .await;
}

async fn test_stake_maturity_invalid(ros: &RosettaApiClient, neuron_info: &NeuronDetails) {
    let acc = neuron_info.account_id;
    let neuron_index = neuron_info.neuron_subaccount_identifier;
    let key_pair: Arc<EdKeypair> = neuron_info.key_pair.clone().into();

    let res = do_multiple_txn(
        ros,
        &[RequestInfo {
            request: Request::StakeMaturity(StakeMaturity {
                account: acc,
                percentage_to_stake: Some(104),
                neuron_index,
            }),
            sender_keypair: Arc::clone(&key_pair),
        }],
        true,
        Some(one_day_from_now_nanos()),
        None,
    )
    .await;

    assert!(
        res.is_err(),
        "Error expected while trying to stake neuron maturity with an invalid percentage"
    );
}

async fn test_change_auto_stake_maturity(
    ros: &RosettaApiClient,
    acc: AccountIdentifier,
    key_pair: Arc<EdKeypair>,
    requested_setting_for_auto_stake_maturity: bool,
    neuron_index: u64,
) {
    change_auto_stake_maturity(
        ros,
        acc,
        key_pair,
        requested_setting_for_auto_stake_maturity,
        neuron_index,
    )
    .await
    .unwrap();
}

async fn change_auto_stake_maturity(
    ros: &RosettaApiClient,
    acc: AccountIdentifier,
    key_pair: Arc<EdKeypair>,
    requested_setting_for_auto_stake_maturity: bool,
    neuron_index: u64,
) -> Result<(), ic_rosetta_api::models::Error> {
    do_multiple_txn(
        ros,
        &[RequestInfo {
            request: Request::ChangeAutoStakeMaturity(ChangeAutoStakeMaturity {
                account: acc,
                neuron_index,
                requested_setting_for_auto_stake_maturity,
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
                _type: Request::ChangeAutoStakeMaturity(ChangeAutoStakeMaturity { .. }),
                status: Status::Completed,
                ..
            }
        ));
    })
}
