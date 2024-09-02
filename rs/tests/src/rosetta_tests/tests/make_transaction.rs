use crate::rosetta_tests::ledger_client::LedgerClient;
use crate::rosetta_tests::lib::{
    acc_id, assert_canister_error, check_balance, create_ledger_client, do_multiple_txn, do_txn,
    hex2addr, make_user, make_user_ecdsa_secp256k1, make_user_ed25519, one_day_from_now_nanos,
    send_icpts, send_icpts_with_window,
};
use crate::rosetta_tests::rosetta_client::RosettaApiClient;
use crate::rosetta_tests::setup::{setup, TRANSFER_FEE};
use ic_ledger_core::tokens::{CheckedAdd, CheckedSub};
use ic_ledger_core::Tokens;
use ic_rosetta_api::models::EdKeypair;
use ic_rosetta_api::request::Request;
use ic_rosetta_test_utils::RequestInfo;
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::util::block_on;
use icp_ledger::{AccountIdentifier, Operation};
use lazy_static::lazy_static;
use rosetta_core::models::RosettaSupportedKeyPair;
use slog::{debug, info, Logger};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

const PORT: u32 = 8102;
const VM_NAME: &str = "rosetta-make-transaction";

lazy_static! {
    static ref FEE: Tokens = Tokens::from_e8s(10_000);
}

pub fn test(env: TestEnv) {
    let logger = env.logger();

    // Accounts for test and initial ledger balances.
    let mut ledger_balances = HashMap::new();

    let (acc_a, kp_a, _pk_a, _pid_a) = make_user(100);
    let kp_a = Arc::new(kp_a);
    let (acc_b, kp_b, _pk_b, _pid_b) = make_user(101);
    let kp_b = Arc::new(kp_b);
    let (acc_secp256k1, kp_secp256k1, _pk_secp256k1, _pid_secp256k1) =
        make_user_ecdsa_secp256k1(200);
    let kp_secp256k1 = Arc::new(kp_secp256k1);
    let acc1 = hex2addr("35548ec29e9d85305850e87a2d2642fe7214ff4bb36334070deafc3345c3b127");
    let acc2 = hex2addr("42a3eb61d549dc9fe6429ce2361ec60a569b8befe43eb15a3fc5c88516711bc5");
    let acc3 = hex2addr("eaf407f7fa3770edb621ce920f6c83cefb63df333044d1cdcd2a300ceb85cb1c");
    let acc4 = hex2addr("ba5b33d11f93033ba45b0a0136d4f7f6310ee482cfb1cfebdb4cea55f4aeda17");
    let acc5 = hex2addr("776ab0ef12a63f5b1bd605f202b1b5cefeaf5791c0241c773fc8e76a6c4a8b40");
    let acc6 = hex2addr("88bf52d6380bf2ed7b5fd4010afd145dc351cbf386def9b9be017bbeb640a919");
    let acc7 = hex2addr("92c9c807da64528240f65ec29b58c839bf2374e9c1c38b7661da65fd8710124e");
    ledger_balances.insert(acc1, Tokens::from_e8s(100_000_000_001));
    ledger_balances.insert(acc2, Tokens::from_e8s(100_000_000_002));
    ledger_balances.insert(acc3, Tokens::from_e8s(100_000_000_003));
    ledger_balances.insert(acc4, Tokens::from_e8s(100_000_000_004));
    ledger_balances.insert(acc5, Tokens::from_e8s(100_000_000_005));
    ledger_balances.insert(acc6, Tokens::from_e8s(100_000_000_006));
    ledger_balances.insert(acc7, Tokens::from_e8s(100_000_000_007));
    ledger_balances.insert(acc_a, Tokens::from_e8s(200_000_000_000));
    ledger_balances.insert(acc_b, Tokens::new(1000, 0).unwrap());
    ledger_balances.insert(acc_secp256k1, Tokens::from_e8s(200_000_000_000));

    let client = setup(&env, PORT, VM_NAME, Some(ledger_balances), None);
    let ledger_client = create_ledger_client(&env, &client);

    block_on(async {
        // Verify proper balance on ledger.
        let balance = ledger_client.get_account_balance(acc1).await;
        assert_eq!(balance, Tokens::from_e8s(100_000_000_001));

        // Wait for tip synchronization.
        let (_, tip_idx) = ledger_client.get_tip().await;
        let _res = client.wait_for_tip_sync(tip_idx).await;

        // Verify initial balance (should have been initialized in setup).
        let acc = acc_a;
        let balance = ledger_client.get_account_balance(acc).await;
        assert_eq!(
            balance,
            Tokens::from_e8s(200_000_000_000),
            "Invalid balance returned by ledger"
        );
        debug!(&logger, "Sync ok for ledger, checking Rosetta result...");
        let balance = Tokens::from_e8s(
            client
                .account_balance(acc_a)
                .await
                .unwrap()
                .unwrap()
                .balances[0]
                .value
                .parse()
                .unwrap(),
        );
        assert_eq!(
            balance,
            Tokens::from_e8s(200_000_000_000),
            "Invalid balance returned by Rosetta"
        );

        test_make_transaction(&client, &ledger_client, acc_a, Arc::clone(&kp_a), &logger).await;
        //Test make transaction with secp256k1 keypair.
        test_make_transaction(
            &client,
            &ledger_client,
            acc_secp256k1,
            Arc::clone(&kp_secp256k1),
            &logger,
        )
        .await;

        // Some more advanced tests
        info!(logger, "Test no funds");
        test_no_funds(&client, Arc::clone(&kp_a)).await;
        info!(logger, "Test configurable ingress window");
        test_ingress_window(&client, Arc::clone(&kp_a)).await;
        info!(logger, "Test multiple transfers");
        test_multiple_transfers(&client, &ledger_client, acc_b, Arc::clone(&kp_b)).await;
        info!(logger, "Test multiple transfers (fail)");
        test_multiple_transfers_fail(&client, &ledger_client, acc_b, Arc::clone(&kp_b)).await;
    });
}

/// Make a transaction through Rosetta API and verify that it landed on the blockchain.
async fn test_make_transaction<T: RosettaSupportedKeyPair>(
    client: &RosettaApiClient,
    ledger_client: &LedgerClient,
    acc: AccountIdentifier,
    key_pair: Arc<T>,
    logger: &Logger,
) where
    Arc<T>: RosettaSupportedKeyPair,
{
    info!(logger, "Test make transaction");
    let acc_ledger = acc;
    let src_balance_before = ledger_client.get_account_balance(acc_ledger).await;
    let (dst_acc, _kp, _pk, _pid) = make_user(1050);
    let dst_balance_before = Tokens::from_e8s(
        client
            .account_balance(dst_acc)
            .await
            .expect("Error while communicating with Rosetta.")
            .expect("Rosetta error")
            .balances[0]
            .value
            .parse()
            .unwrap(),
    );

    let tip_idx = client
        .network_status()
        .await
        .unwrap()
        .unwrap()
        .current_block_identifier
        .index;
    let expected_idx = tip_idx + 1;

    let from = acc;
    let to = dst_acc;
    let amount = Tokens::from_e8s(1000);
    let fee = Tokens::from_e8s(TRANSFER_FEE);
    let t = Operation::Transfer {
        from,
        to,
        spender: None,
        amount,
        fee,
    };
    let (tid, results, _fee) = do_txn(
        client,
        key_pair,
        t.clone(),
        false,
        Some(one_day_from_now_nanos()),
        None,
    )
    .await
    .expect("Error during transfer operation.");

    if let Some(h) = results.last_block_index() {
        assert_eq!(h, expected_idx);
    }
    let block = client.wait_for_block_at(expected_idx).await.unwrap();
    assert_eq!(block.transactions.len(), 1);

    let t = block.transactions.first().unwrap();
    assert_eq!(t.transaction_identifier, tid.into());

    check_balance(
        client,
        ledger_client,
        &acc,
        src_balance_before
            .checked_sub(&amount)
            .unwrap()
            .checked_sub(&fee)
            .unwrap(),
    )
    .await;

    check_balance(
        client,
        ledger_client,
        &dst_acc,
        dst_balance_before.checked_add(&amount).unwrap(),
    )
    .await;
}

async fn test_no_funds(ros: &RosettaApiClient, funding_key_pair: Arc<EdKeypair>) {
    let (acc1, keypair1, _, _) = make_user_ed25519(9275456);
    let keypair1 = Arc::new(keypair1);
    let acc2 = acc_id(598620493);

    // charge up user1
    let (_, bh, _) = send_icpts(
        ros,
        funding_key_pair,
        acc1,
        Tokens::from_e8s(10_000).checked_add(&FEE).unwrap(),
    )
    .await
    .unwrap();
    ros.wait_for_tip_sync(bh.unwrap()).await.unwrap();

    // Transfer some funds from user1 to user2
    let (_, bh, _) = send_icpts(ros, Arc::clone(&keypair1), acc2, Tokens::from_e8s(1000))
        .await
        .unwrap();
    ros.wait_for_tip_sync(bh.unwrap()).await.unwrap();

    // Try to transfer more. This should fail with an error from the canister.
    let err = send_icpts(ros, keypair1, acc2, Tokens::from_e8s(10_000))
        .await
        .unwrap_err();
    assert_canister_error(&err, 750, "account doesn't have enough funds");

    // and now try to make a transfer from an empty account
    let (_, empty_acc_kp, _, _) = make_user_ed25519(434561);
    let err = send_icpts(ros, Arc::new(empty_acc_kp), acc2, Tokens::from_e8s(100))
        .await
        .unwrap_err();
    assert_canister_error(&err, 750, "account doesn't have enough funds");
}

async fn test_ingress_window(ros: &RosettaApiClient, funding_key_pair: Arc<EdKeypair>) {
    let (acc1, _keypair1, _, _) = make_user_ed25519(42);

    let now = ic_types::time::current_time();
    let expiry = now + Duration::from_secs(24 * 60 * 60);

    // charge up user1
    let (_, bh, _) = send_icpts_with_window(
        ros,
        Arc::clone(&funding_key_pair),
        acc1,
        Tokens::from_e8s(10_000),
        Some(expiry.as_nanos_since_unix_epoch()),
        Some(now.as_nanos_since_unix_epoch()),
    )
    .await
    .unwrap();
    ros.wait_for_tip_sync(bh.unwrap()).await.unwrap();

    // do the same transaction again; this should be rejected
    // note that we pass the same created_at value to get the same
    // transaction
    let err = send_icpts_with_window(
        ros,
        funding_key_pair,
        acc1,
        Tokens::from_e8s(10_000),
        None,
        Some(now.as_nanos_since_unix_epoch()),
    )
    .await
    .unwrap_err();
    assert_canister_error(&err, 750, "transaction is a duplicate");
}

/// Test doing multiple transfers in a single submit call
async fn test_multiple_transfers(
    ros: &RosettaApiClient,
    ledger: &LedgerClient,
    acc: AccountIdentifier,
    key_pair: Arc<EdKeypair>,
) {
    let (dst_acc1, dst_acc1_kp, _pk, _pid) = make_user_ed25519(1100);
    let (dst_acc2, dst_acc2_kp, _pk, _pid) = make_user_ed25519(1101);
    let (dst_acc3, _kp, _pk, _pid) = make_user_ed25519(1102);

    let amount1 = Tokens::new(3, 0).unwrap();
    let amount2 = Tokens::new(2, 0).unwrap();
    let amount3 = Tokens::new(1, 0).unwrap();

    let tip_idx = ros
        .network_status()
        .await
        .unwrap()
        .unwrap()
        .current_block_identifier
        .index;
    let expected_idx = tip_idx + 3;

    let (tid, results, _fee) = do_multiple_txn(
        ros,
        &[
            RequestInfo {
                request: Request::Transfer(Operation::Transfer {
                    from: acc,
                    to: dst_acc1,
                    spender: None,
                    amount: amount1,
                    fee: *FEE,
                }),
                sender_keypair: Arc::clone(&key_pair),
            },
            RequestInfo {
                request: Request::Transfer(Operation::Transfer {
                    from: dst_acc1,
                    to: dst_acc2,
                    spender: None,
                    amount: amount2,
                    fee: *FEE,
                }),
                sender_keypair: Arc::new(dst_acc1_kp),
            },
            RequestInfo {
                request: Request::Transfer(Operation::Transfer {
                    from: dst_acc2,
                    to: dst_acc3,
                    spender: None,
                    amount: amount3,
                    fee: *FEE,
                }),
                sender_keypair: Arc::new(dst_acc2_kp),
            },
        ],
        false,
        Some(one_day_from_now_nanos()),
        None,
    )
    .await
    .unwrap();

    if let Some(h) = results.last_block_index() {
        assert_eq!(h, expected_idx);
    }
    let block = ros.wait_for_block_at(expected_idx).await.unwrap();
    assert_eq!(block.transactions.len(), 1);

    let t = block.transactions.first().unwrap();
    assert_eq!(t.transaction_identifier, tid.into());

    check_balance(
        ros,
        ledger,
        &dst_acc1,
        amount1
            .checked_sub(&amount2)
            .unwrap()
            .checked_sub(&FEE)
            .unwrap(),
    )
    .await;
    check_balance(
        ros,
        ledger,
        &dst_acc2,
        amount2
            .checked_sub(&amount3)
            .unwrap()
            .checked_sub(&FEE)
            .unwrap(),
    )
    .await;
    check_balance(ros, ledger, &dst_acc3, amount3).await;
}

/// Test part of a multiple transfer failing. This is not atomic.
async fn test_multiple_transfers_fail(
    ros: &RosettaApiClient,
    ledger: &LedgerClient,
    acc: AccountIdentifier,
    key_pair: Arc<EdKeypair>,
) {
    let (dst_acc1, dst_acc1_kp, _pk, _pid) = make_user_ed25519(1200);
    let (dst_acc2, dst_acc2_kp, _pk, _pid) = make_user_ed25519(1201);
    let (dst_acc3, _kp, _pk, _pid) = make_user_ed25519(1202);

    let amount1 = Tokens::new(3, 0).unwrap();
    let amount2 = Tokens::new(2, 0).unwrap();
    let amount3 = Tokens::new(100_000, 0).unwrap();

    let tip_idx = ros
        .network_status()
        .await
        .unwrap()
        .unwrap()
        .current_block_identifier
        .index;
    let expected_idx = tip_idx + 1;

    let err = do_multiple_txn(
        ros,
        &[
            RequestInfo {
                request: Request::Transfer(Operation::Transfer {
                    from: acc,
                    to: dst_acc1,
                    spender: None,
                    amount: amount1,
                    fee: *FEE,
                }),
                sender_keypair: Arc::clone(&key_pair),
            },
            RequestInfo {
                request: Request::Transfer(Operation::Transfer {
                    from: acc,
                    to: dst_acc3,
                    spender: None,
                    amount: amount3,
                    fee: *FEE,
                }),
                sender_keypair: Arc::new(dst_acc2_kp),
            },
            RequestInfo {
                request: Request::Transfer(Operation::Transfer {
                    from: dst_acc1,
                    to: dst_acc2,
                    spender: None,
                    amount: amount2,
                    fee: *FEE,
                }),
                sender_keypair: Arc::new(dst_acc1_kp),
            },
        ],
        false,
        Some(one_day_from_now_nanos()),
        None,
    )
    .await
    .unwrap_err();
    assert_canister_error(&err, 750, "debit account doesn't have enough funds");

    let block = ros.wait_for_block_at(expected_idx).await.unwrap();
    assert_eq!(block.transactions.len(), 1);

    check_balance(ros, ledger, &dst_acc1, amount1).await;
    check_balance(ros, ledger, &dst_acc2, Tokens::ZERO).await;
    check_balance(ros, ledger, &dst_acc3, Tokens::ZERO).await;
}
