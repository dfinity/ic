use crate::address::Address;
use crate::eth_rpc::{Hash, Quantity};
use crate::lifecycle::EthereumNetwork;
use crate::numeric::{BlockNumber, LedgerBurnIndex, TransactionNonce, Wei};
use crate::transactions::{create_transaction, EthTransactions, EthWithdrawalRequest};
use crate::tx::{
    AccessList, ConfirmedEip1559Transaction, Eip1559Signature, Eip1559TransactionRequest,
    SignedEip1559TransactionRequest, TransactionPrice,
};

mod eth_transactions {
    use crate::numeric::{LedgerBurnIndex, TransactionNonce};
    use crate::transactions::tests::withdrawal_request_with_index;
    use crate::transactions::EthTransactions;

    mod record_withdrawal_request {
        use super::*;
        use crate::transactions::tests::{
            confirmed_transaction, create_and_record_transaction, expect_panic_with_message,
            sign_transaction, transaction_price,
        };

        #[test]
        fn should_record_withdrawal_request() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let index = LedgerBurnIndex::new(15);
            let withdrawal_request = withdrawal_request_with_index(index);

            transactions.record_withdrawal_request(withdrawal_request.clone());

            assert_eq!(
                transactions.withdrawal_requests_batch(5),
                vec![withdrawal_request]
            );
        }

        #[test]
        fn should_fail_recording_withdrawal_request_when_duplicate_ledger_burn_index() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let index = LedgerBurnIndex::new(15);
            let withdrawal_request = withdrawal_request_with_index(index);
            transactions.record_withdrawal_request(withdrawal_request.clone());

            expect_panic_with_message(
                || transactions.record_withdrawal_request(withdrawal_request.clone()),
                "duplicate ledger burn index",
            );

            let created_tx = create_and_record_transaction(
                &mut transactions,
                withdrawal_request.clone(),
                transaction_price(),
            );
            expect_panic_with_message(
                || transactions.record_withdrawal_request(withdrawal_request.clone()),
                "duplicate ledger burn index",
            );

            let sent_tx = sign_transaction(created_tx);
            transactions.record_sent_transaction(sent_tx.clone());
            expect_panic_with_message(
                || transactions.record_withdrawal_request(withdrawal_request.clone()),
                "duplicate ledger burn index",
            );

            transactions.record_finalized_transaction(confirmed_transaction(sent_tx));
            expect_panic_with_message(
                || transactions.record_withdrawal_request(withdrawal_request.clone()),
                "duplicate ledger burn index",
            );
        }
    }

    mod withdrawal_requests_batch {
        use super::*;
        use proptest::proptest;

        #[test]
        fn should_be_empty_when_no_withdrawal_requests() {
            let transactions = EthTransactions::new(TransactionNonce::ZERO);
            assert_eq!(transactions.withdrawal_requests_batch(5), vec![]);
        }

        #[test]
        fn should_retrieve_the_first_withdrawal_requests() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            for i in 0..5 {
                let withdrawal_request = withdrawal_request_with_index(LedgerBurnIndex::new(i));
                transactions.record_withdrawal_request(withdrawal_request);
            }

            let requests = transactions.withdrawal_requests_batch(0);
            assert_eq!(requests, vec![]);

            let requests = transactions.withdrawal_requests_batch(1);
            assert_eq!(
                requests,
                vec![withdrawal_request_with_index(LedgerBurnIndex::new(0)),]
            );

            let requests = transactions.withdrawal_requests_batch(2);
            assert_eq!(
                requests,
                vec![
                    withdrawal_request_with_index(LedgerBurnIndex::new(0)),
                    withdrawal_request_with_index(LedgerBurnIndex::new(1)),
                ]
            );
        }

        proptest! {
            #[test]
            fn should_retrieve_all_withdrawal_requests_in_order(batch_size in 3..100_usize) {
                let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
                for i in 0..3 {
                    let withdrawal_request = withdrawal_request_with_index(LedgerBurnIndex::new(i));
                        transactions.record_withdrawal_request(withdrawal_request);
                }

                let requests = transactions.withdrawal_requests_batch(batch_size);

                assert_eq!(
                    requests,
                    vec![
                        withdrawal_request_with_index(LedgerBurnIndex::new(0)),
                        withdrawal_request_with_index(LedgerBurnIndex::new(1)),
                        withdrawal_request_with_index(LedgerBurnIndex::new(2)),
                    ]
                );
            }
        }
    }

    mod reschedule_withdrawal_request {
        use crate::numeric::{LedgerBurnIndex, TransactionNonce};
        use crate::transactions::tests::eth_transactions::withdrawal_request_with_index;
        use crate::transactions::EthTransactions;

        #[test]
        fn should_reschedule_withdrawal_request() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let first_request = withdrawal_request_with_index(LedgerBurnIndex::new(15));
            let second_request = withdrawal_request_with_index(LedgerBurnIndex::new(16));
            let third_request = withdrawal_request_with_index(LedgerBurnIndex::new(17));
            transactions.record_withdrawal_request(first_request.clone());
            transactions.record_withdrawal_request(second_request.clone());
            transactions.record_withdrawal_request(third_request.clone());

            // 3 -> 2 -> 1
            assert_eq!(
                transactions.withdrawal_requests_batch(5),
                vec![
                    first_request.clone(),
                    second_request.clone(),
                    third_request.clone()
                ]
            );

            transactions.reschedule_withdrawal_request(first_request.clone());
            // 1 -> 3 -> 2
            assert_eq!(
                transactions.withdrawal_requests_batch(5),
                vec![
                    second_request.clone(),
                    third_request.clone(),
                    first_request.clone()
                ]
            );

            transactions.reschedule_withdrawal_request(second_request.clone());
            // 2 -> 1 -> 3
            assert_eq!(
                transactions.withdrawal_requests_batch(5),
                vec![
                    third_request.clone(),
                    first_request.clone(),
                    second_request.clone()
                ]
            );

            transactions.reschedule_withdrawal_request(third_request.clone());
            // 3 -> 2 -> 1
            assert_eq!(
                transactions.withdrawal_requests_batch(5),
                vec![first_request, second_request, third_request]
            );
        }
    }

    mod record_created_transaction {
        use crate::address::Address;
        use crate::lifecycle::EthereumNetwork;
        use crate::numeric::{LedgerBurnIndex, TransactionNonce};
        use crate::transactions::tests::{
            create_and_record_transaction, expect_panic_with_message, transaction_price,
            withdrawal_request_with_index,
        };
        use crate::transactions::{create_transaction, EthTransactions};
        use crate::tx::Eip1559TransactionRequest;
        use proptest::prelude::any;
        use proptest::{prop_assert_ne, proptest};

        #[test]
        fn should_fail_when_withdrawal_request_not_found() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let withdrawal_request = withdrawal_request_with_index(LedgerBurnIndex::new(15));
            let tx = create_transaction(
                &withdrawal_request,
                TransactionNonce::ZERO,
                transaction_price(),
                EthereumNetwork::Sepolia,
            )
            .unwrap();

            expect_panic_with_message(
                || transactions.record_created_transaction(withdrawal_request, tx),
                "withdrawal request not found",
            );
        }

        #[test]
        fn should_fail_when_mismatch_with_withdrawal_request() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let withdrawal_request = withdrawal_request_with_index(LedgerBurnIndex::new(15));
            transactions.record_withdrawal_request(withdrawal_request.clone());
            let correct_tx = create_transaction(
                &withdrawal_request,
                TransactionNonce::ZERO,
                transaction_price(),
                EthereumNetwork::Sepolia,
            )
            .unwrap();

            let tx_with_wrong_destination = Eip1559TransactionRequest {
                destination: Address::ZERO,
                ..correct_tx.clone()
            };
            assert_ne!(correct_tx, tx_with_wrong_destination);
            expect_panic_with_message(
                || {
                    transactions.record_created_transaction(
                        withdrawal_request.clone(),
                        tx_with_wrong_destination,
                    )
                },
                "destination mismatch",
            );

            let tx_with_wrong_amount = Eip1559TransactionRequest {
                amount: withdrawal_request
                    .withdrawal_amount
                    .checked_increment()
                    .unwrap(),
                ..correct_tx.clone()
            };
            assert_ne!(correct_tx, tx_with_wrong_amount);
            expect_panic_with_message(
                || {
                    transactions
                        .record_created_transaction(withdrawal_request, tx_with_wrong_amount)
                },
                "amount deducted from transaction fees",
            );
        }

        proptest! {
            #[test]
            fn should_fail_when_nonce_wrong(current_nonce in any::<u64>(), nonce_drift in 1..=u64::MAX) {
                let current_nonce = TransactionNonce::from(current_nonce);
                let wrong_nonce = current_nonce.checked_add(TransactionNonce::from(nonce_drift)).unwrap();
                prop_assert_ne!(current_nonce, wrong_nonce);
                let mut transactions = EthTransactions::new(current_nonce);
                let withdrawal_request = withdrawal_request_with_index(LedgerBurnIndex::new(15));
                transactions.record_withdrawal_request(withdrawal_request.clone());
                let tx_with_wrong_nonce = create_transaction(
                    &withdrawal_request,
                    wrong_nonce,
                    transaction_price(),
                    EthereumNetwork::Sepolia,
                )
                .unwrap();

                expect_panic_with_message(
                    || transactions.record_created_transaction(withdrawal_request, tx_with_wrong_nonce),
                    "nonce mismatch",
                );
            }
        }

        #[test]
        fn should_create_and_record_transaction() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let transaction_price = transaction_price();
            for i in 0..100_u64 {
                let ledger_burn_index = LedgerBurnIndex::new(15 + i);
                let withdrawal_request = withdrawal_request_with_index(ledger_burn_index);
                transactions.record_withdrawal_request(withdrawal_request.clone());
                let expected_tx_amount = withdrawal_request
                    .withdrawal_amount
                    .checked_sub(transaction_price.max_transaction_fee())
                    .unwrap();

                let created_tx = create_and_record_transaction(
                    &mut transactions,
                    withdrawal_request.clone(),
                    transaction_price.clone(),
                );

                assert_eq!(
                    created_tx,
                    Eip1559TransactionRequest {
                        chain_id: EthereumNetwork::Sepolia.chain_id(),
                        nonce: TransactionNonce::from(i),
                        max_priority_fee_per_gas: transaction_price.max_priority_fee_per_gas,
                        max_fee_per_gas: transaction_price.max_fee_per_gas,
                        gas_limit: transaction_price.gas_limit,
                        destination: withdrawal_request.destination,
                        amount: expected_tx_amount,
                        data: vec![],
                        access_list: Default::default(),
                    }
                );
                assert_eq!(transactions.next_nonce, TransactionNonce::from(i + 1));
            }
        }

        #[test]
        fn should_consume_withdrawal_request_when_creating_transaction() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let withdrawal_request = withdrawal_request_with_index(LedgerBurnIndex::new(15));
            transactions.record_withdrawal_request(withdrawal_request.clone());

            let _created_tx = create_and_record_transaction(
                &mut transactions,
                withdrawal_request,
                transaction_price(),
            );

            assert_eq!(transactions.withdrawal_requests_batch(1), vec![]);
        }
    }

    mod record_sent_transaction {
        use super::*;
        use crate::map::MultiKeyMap;
        use crate::numeric::Wei;
        use crate::transactions::tests::{
            create_and_record_transaction, expect_panic_with_message, sign_transaction,
            signed_transaction_with_nonce, transaction_price,
        };
        use std::iter;

        #[test]
        #[should_panic(expected = "missing created transaction")]
        fn should_fail_when_created_transaction_not_found() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            transactions
                .record_sent_transaction(signed_transaction_with_nonce(TransactionNonce::ZERO));
        }

        #[test]
        fn should_record_first_sent_transaction() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let ledger_burn_index = LedgerBurnIndex::new(15);
            let withdrawal_request = withdrawal_request_with_index(ledger_burn_index);
            transactions.record_withdrawal_request(withdrawal_request.clone());
            let created_tx = create_and_record_transaction(
                &mut transactions,
                withdrawal_request,
                transaction_price(),
            );
            let signed_tx = sign_transaction(created_tx);

            transactions.record_sent_transaction(signed_tx.clone());

            assert_eq!(transactions.created_transactions_iter().next(), None);
            assert_eq!(
                transactions.sent_tx,
                MultiKeyMap::from_iter(vec![(
                    TransactionNonce::ZERO,
                    ledger_burn_index,
                    vec![signed_tx]
                )])
            );
        }

        #[test]
        fn should_fail_when_first_sent_transaction_does_not_match_created_transaction() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let ledger_burn_index = LedgerBurnIndex::new(15);
            let withdrawal_request = withdrawal_request_with_index(ledger_burn_index);
            transactions.record_withdrawal_request(withdrawal_request.clone());
            let created_tx = create_and_record_transaction(
                &mut transactions,
                withdrawal_request,
                transaction_price(),
            );
            //TODO FI-933: turn this into a proptest to generate an arbitrary transaction
            let wrong_signed_tx = {
                let mut wrong_transaction = created_tx.clone();
                wrong_transaction.max_priority_fee_per_gas = wrong_transaction
                    .max_priority_fee_per_gas
                    .checked_add(Wei::ONE)
                    .unwrap();
                assert_ne!(wrong_transaction, created_tx);
                sign_transaction(wrong_transaction)
            };

            expect_panic_with_message(
                || transactions.record_sent_transaction(wrong_signed_tx.clone()),
                "mismatch between sent transaction and created transaction",
            );
        }

        #[test]
        fn should_add_multiple_sent_transactions_for_same_nonce_with_different_fees() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let ledger_burn_index = LedgerBurnIndex::new(15);
            let withdrawal_request = withdrawal_request_with_index(ledger_burn_index);
            transactions.record_withdrawal_request(withdrawal_request.clone());
            let created_tx = create_and_record_transaction(
                &mut transactions,
                withdrawal_request,
                transaction_price(),
            );

            let transaction_with_increasing_fees: Vec<_> = iter::repeat(created_tx)
                .take(10)
                .enumerate()
                .map(|(index, mut tx)| {
                    tx.max_priority_fee_per_gas = tx
                        .max_priority_fee_per_gas
                        .checked_add(Wei::from(index as u8))
                        .unwrap();
                    tx.amount = tx.amount.checked_sub(Wei::from(index as u8)).unwrap();
                    sign_transaction(tx)
                })
                .collect();

            for (index, transaction) in transaction_with_increasing_fees.iter().enumerate() {
                transactions.record_sent_transaction(transaction.clone());
                assert_eq!(transactions.created_transactions_iter().next(), None);
                assert_eq!(
                    transactions.sent_tx,
                    MultiKeyMap::from_iter(vec![(
                        TransactionNonce::ZERO,
                        ledger_burn_index,
                        transaction_with_increasing_fees[0..=index].to_vec()
                    )])
                );
            }
        }

        #[test]
        fn should_fail_to_add_sent_transaction_when_mismatch_with_already_sent() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let ledger_burn_index = LedgerBurnIndex::new(15);
            let withdrawal_request = withdrawal_request_with_index(ledger_burn_index);
            transactions.record_withdrawal_request(withdrawal_request.clone());
            let created_tx = create_and_record_transaction(
                &mut transactions,
                withdrawal_request,
                transaction_price(),
            );
            let signed_tx = sign_transaction(created_tx.clone());
            transactions.record_sent_transaction(signed_tx.clone());

            let wrong_resent_tx = {
                let mut wrong_transaction = created_tx.clone();
                wrong_transaction.data = vec![0x01];
                assert_ne!(wrong_transaction, created_tx);
                sign_transaction(wrong_transaction)
            };

            expect_panic_with_message(
                || transactions.record_sent_transaction(wrong_resent_tx.clone()),
                "mismatch between last sent transaction",
            );
        }
    }

    mod record_finalized_transaction {
        use crate::numeric::{LedgerBurnIndex, TransactionNonce};
        use crate::transactions::tests::{
            confirmed_transaction, create_and_record_transaction, dummy_signature,
            expect_panic_with_message, sign_transaction, transaction_price,
            withdrawal_request_with_index,
        };
        use crate::transactions::EthTransactions;
        use crate::tx::SignedEip1559TransactionRequest;

        #[test]
        fn should_fail_when_sent_transaction_not_found() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let ledger_burn_index = LedgerBurnIndex::new(15);
            let withdrawal_request = withdrawal_request_with_index(ledger_burn_index);
            transactions.record_withdrawal_request(withdrawal_request.clone());
            let created_tx = create_and_record_transaction(
                &mut transactions,
                withdrawal_request,
                transaction_price(),
            );
            let signed_tx =
                SignedEip1559TransactionRequest::from((created_tx.clone(), dummy_signature()));
            transactions.record_sent_transaction(signed_tx.clone());

            let confirmed_tx_with_wrong_nonce = {
                let mut wrong_transaction = created_tx.clone();
                wrong_transaction.nonce = wrong_transaction.nonce.checked_increment().unwrap();
                assert_ne!(wrong_transaction, created_tx);
                confirmed_transaction(sign_transaction(wrong_transaction))
            };

            expect_panic_with_message(
                || transactions.record_finalized_transaction(confirmed_tx_with_wrong_nonce),
                "missing sent transaction",
            );

            let confirmed_tx_with_wrong_signature = {
                let mut wrong_signature = dummy_signature();
                wrong_signature.signature_y_parity = true;
                confirmed_transaction(SignedEip1559TransactionRequest::from((
                    created_tx,
                    wrong_signature,
                )))
            };

            expect_panic_with_message(
                || transactions.record_finalized_transaction(confirmed_tx_with_wrong_signature),
                "mismatch between sent transactions and the confirmed transaction",
            );
        }

        #[test]
        fn should_record_finalized_transaction() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let ledger_burn_index = LedgerBurnIndex::new(15);
            let withdrawal_request = withdrawal_request_with_index(ledger_burn_index);
            transactions.record_withdrawal_request(withdrawal_request.clone());
            let created_tx = create_and_record_transaction(
                &mut transactions,
                withdrawal_request,
                transaction_price(),
            );
            let signed_tx = sign_transaction(created_tx);
            transactions.record_sent_transaction(signed_tx.clone());

            let confirmed_transaction = confirmed_transaction(signed_tx);
            transactions.record_finalized_transaction(confirmed_transaction.clone());

            assert_eq!(
                transactions
                    .finalized_transactions_iter()
                    .collect::<Vec<_>>(),
                vec![(
                    &TransactionNonce::ZERO,
                    &ledger_burn_index,
                    &confirmed_transaction
                )]
            );
            assert_eq!(transactions.sent_transactions_iter().next(), None);
        }
    }

    mod transaction_status {
        use crate::endpoints::{EthTransaction, RetrieveEthStatus};
        use crate::numeric::{LedgerBurnIndex, TransactionNonce};
        use crate::transactions::tests::{
            confirmed_transaction, create_and_record_transaction, sign_transaction,
            transaction_price, withdrawal_request_with_index,
        };
        use crate::transactions::EthTransactions;

        #[test]
        fn should_withdrawal_flow_succeed_with_correct_status() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let ledger_burn_index = LedgerBurnIndex::new(15);
            let withdrawal_request = withdrawal_request_with_index(ledger_burn_index);

            assert_eq!(
                transactions.transaction_status(&ledger_burn_index),
                RetrieveEthStatus::NotFound
            );
            transactions.record_withdrawal_request(withdrawal_request.clone());
            assert_eq!(
                transactions.transaction_status(&ledger_burn_index),
                RetrieveEthStatus::Pending
            );

            let created_tx = create_and_record_transaction(
                &mut transactions,
                withdrawal_request,
                transaction_price(),
            );
            assert_eq!(
                transactions.transaction_status(&ledger_burn_index),
                RetrieveEthStatus::TxCreated
            );

            let signed_tx = sign_transaction(created_tx);
            transactions.record_sent_transaction(signed_tx.clone());
            let eth_transaction = EthTransaction {
                transaction_hash: signed_tx.hash().to_string(),
            };
            assert_eq!(
                transactions.transaction_status(&ledger_burn_index),
                RetrieveEthStatus::TxSent(eth_transaction.clone())
            );

            transactions.record_finalized_transaction(confirmed_transaction(signed_tx));
            assert_eq!(
                transactions.transaction_status(&ledger_burn_index),
                RetrieveEthStatus::TxConfirmed(eth_transaction)
            );
        }
    }
}

mod eth_withdrawal_request {
    use crate::numeric::LedgerBurnIndex;
    use crate::transactions::tests::withdrawal_request_with_index;

    #[test]
    fn should_have_readable_debug_representation() {
        let request = withdrawal_request_with_index(LedgerBurnIndex::new(131));
        let expected_debug = "EthWithdrawalRequest { withdrawal_amount: 1_100_000_000_000_000, destination: 0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34, ledger_burn_index: 131 }";
        assert_eq!(format!("{:?}", request), expected_debug);
    }
}

mod create_transaction {
    use crate::lifecycle::EthereumNetwork;
    use crate::numeric::{LedgerBurnIndex, TransactionNonce, Wei};
    use crate::transactions::tests::{transaction_price, withdrawal_request_with_index};
    use crate::transactions::{create_transaction, CreateTransactionError, EthWithdrawalRequest};
    use crate::tx::{AccessList, Eip1559TransactionRequest};
    use proptest::prelude::any;
    use proptest::{prop_assert_eq, proptest};

    proptest! {
        #[test]
        fn should_fail_when_amount_does_not_cover_transaction_fees(withdrawal_amount in any::<u64>()) {
            let transaction_price = transaction_price();
            let max_transaction_fee = transaction_price.max_transaction_fee();
            let insufficient_amount = Wei::from(withdrawal_amount % (max_transaction_fee.as_f64() as u64));
            let ledger_burn_index = LedgerBurnIndex::new(15);
            let withdrawal_request = EthWithdrawalRequest {
                withdrawal_amount: insufficient_amount,
                ..withdrawal_request_with_index(ledger_burn_index)
            };

            let result = create_transaction(
                &withdrawal_request,
                TransactionNonce::TWO,
                transaction_price,
                EthereumNetwork::Sepolia,
            );

            prop_assert_eq!(
                result,
                Err(CreateTransactionError::InsufficientAmount {
                    ledger_burn_index,
                    withdrawal_amount: withdrawal_request.withdrawal_amount,
                    max_transaction_fee,
                })
            )
        }
    }

    proptest! {
        #[test]
        fn should_create_transaction(withdrawal_amount in 31_500_001_050_000_u64..=u64::MAX) {
            let transaction_price = transaction_price();
            let max_transaction_fee = transaction_price.max_transaction_fee();
            let ledger_burn_index = LedgerBurnIndex::new(15);
            let withdrawal_amount = Wei::from(withdrawal_amount);
            let withdrawal_request = EthWithdrawalRequest {
                withdrawal_amount,
                ..withdrawal_request_with_index(ledger_burn_index)
            };
            prop_assert_eq!(
                max_transaction_fee,
                Wei::from(31_500_001_050_000_u64)
            );

            let result = create_transaction(
                &withdrawal_request,
                TransactionNonce::TWO,
                transaction_price.clone(),
                EthereumNetwork::Sepolia,
            );

            prop_assert_eq!(result, Ok(Eip1559TransactionRequest {
                chain_id: EthereumNetwork::Sepolia.chain_id(),
                nonce: TransactionNonce::TWO,
                max_priority_fee_per_gas: transaction_price.max_priority_fee_per_gas,
                max_fee_per_gas: transaction_price.max_fee_per_gas,
                gas_limit: transaction_price.gas_limit,
                destination: withdrawal_request.destination,
                amount: withdrawal_amount.checked_sub(max_transaction_fee).unwrap(),
                data: vec![],
                access_list: AccessList::new()
            }))
        }
    }
}

fn expect_panic_with_message<F: FnOnce() -> R, R: std::fmt::Debug>(f: F, expected_message: &str) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    let error = result.unwrap_err();
    let panic_message = {
        if let Some(s) = error.downcast_ref::<String>() {
            s.to_string()
        } else if let Some(s) = error.downcast_ref::<&str>() {
            s.to_string()
        } else {
            format!("{:?}", error)
        }
    };
    assert!(
        panic_message.contains(expected_message),
        "Expected panic message to contain: {}, but got: {}",
        expected_message,
        panic_message
    );
}

fn withdrawal_request_with_index(ledger_burn_index: LedgerBurnIndex) -> EthWithdrawalRequest {
    use std::str::FromStr;
    EthWithdrawalRequest {
        ledger_burn_index,
        destination: Address::from_str("0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34").unwrap(),
        withdrawal_amount: Wei::new(1_100_000_000_000_000),
    }
}

fn signed_transaction_with_nonce(nonce: TransactionNonce) -> SignedEip1559TransactionRequest {
    SignedEip1559TransactionRequest::from((
        eip_1559_transaction_request_with_nonce(nonce),
        dummy_signature(),
    ))
}

fn eip_1559_transaction_request_with_nonce(nonce: TransactionNonce) -> Eip1559TransactionRequest {
    use std::str::FromStr;
    const SEPOLIA_TEST_CHAIN_ID: u64 = 11155111;
    Eip1559TransactionRequest {
        chain_id: SEPOLIA_TEST_CHAIN_ID,
        nonce,
        max_priority_fee_per_gas: Wei::new(0x59682f00),
        max_fee_per_gas: Wei::new(0x598653cd),
        gas_limit: Quantity::new(56_511),
        destination: Address::from_str("0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34").unwrap(),
        amount: Wei::new(1_000_000_000_000_000),
        data: hex::decode(
            "b214faa51d882d15b09f8e81e29606305f5fefc5eff3e2309620a3557ecae39d62020000",
        )
        .unwrap(),
        access_list: AccessList::new(),
    }
}

fn transaction_price() -> TransactionPrice {
    TransactionPrice {
        max_fee_per_gas: Wei::new(0x59682f32),
        max_priority_fee_per_gas: Wei::new(0x59682f00),
        gas_limit: Quantity::new(21_000),
    }
}

fn create_and_record_transaction(
    transactions: &mut EthTransactions,
    withdrawal_request: EthWithdrawalRequest,
    transaction_price: TransactionPrice,
) -> Eip1559TransactionRequest {
    let burn_index = withdrawal_request.ledger_burn_index;
    let tx = create_transaction(
        &withdrawal_request,
        transactions.next_transaction_nonce(),
        transaction_price,
        EthereumNetwork::Sepolia,
    )
    .expect("failed to create transaction");
    transactions.record_created_transaction(withdrawal_request, tx);
    transactions
        .created_tx
        .get_alt(&burn_index)
        .unwrap()
        .clone()
}

fn confirmed_transaction(
    signed_tx: SignedEip1559TransactionRequest,
) -> ConfirmedEip1559Transaction {
    use std::str::FromStr;
    ConfirmedEip1559Transaction::new(
        signed_tx,
        Hash::from_str("0xce67a85c9fb8bc50213815c32814c159fd75160acf7cb8631e8e7b7cf7f1d472")
            .unwrap(),
        BlockNumber::new(4190269),
    )
}

fn sign_transaction(transaction: Eip1559TransactionRequest) -> SignedEip1559TransactionRequest {
    SignedEip1559TransactionRequest::from((transaction, dummy_signature()))
}

fn dummy_signature() -> Eip1559Signature {
    Eip1559Signature {
        signature_y_parity: false,
        r: Default::default(),
        s: Default::default(),
    }
}
