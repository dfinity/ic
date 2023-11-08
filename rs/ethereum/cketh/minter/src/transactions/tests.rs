use crate::address::Address;
use crate::eth_rpc::{Hash, Quantity};
use crate::eth_rpc_client::responses::TransactionReceipt;
use crate::lifecycle::EvmNetwork;
use crate::numeric::{BlockNumber, LedgerBurnIndex, TransactionNonce, Wei};
use crate::transactions::{
    create_transaction, EthTransactions, EthWithdrawalRequest, ResubmitTransaction,
};
use crate::tx::{
    AccessList, Eip1559Signature, Eip1559TransactionRequest, SignedEip1559TransactionRequest,
    TransactionPrice,
};

mod eth_transactions {
    use crate::numeric::{LedgerBurnIndex, TransactionNonce};
    use crate::transactions::tests::withdrawal_request_with_index;
    use crate::transactions::EthTransactions;

    mod record_withdrawal_request {
        use super::*;
        use crate::transactions::tests::{
            create_and_record_signed_transaction, create_and_record_transaction,
            expect_panic_with_message, transaction_price, transaction_receipt,
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

            let signed_tx = create_and_record_signed_transaction(&mut transactions, created_tx);
            expect_panic_with_message(
                || transactions.record_withdrawal_request(withdrawal_request.clone()),
                "duplicate ledger burn index",
            );

            transactions.record_sent_transaction(signed_tx.clone());
            expect_panic_with_message(
                || transactions.record_withdrawal_request(withdrawal_request.clone()),
                "duplicate ledger burn index",
            );

            transactions.record_finalized_transaction(index, transaction_receipt(&signed_tx));
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
        use crate::lifecycle::EvmNetwork;
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
                EvmNetwork::Sepolia,
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
                EvmNetwork::Sepolia,
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
                    EvmNetwork::Sepolia,
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
                        chain_id: EvmNetwork::Sepolia.chain_id(),
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

    mod record_signed_transaction {
        use super::super::arbitrary::arb_signed_eip_1559_transaction_request_with_nonce;
        use crate::numeric::{LedgerBurnIndex, TransactionNonce};
        use crate::transactions::tests::{
            create_and_record_transaction, create_and_record_withdrawal_request,
            expect_panic_with_message, sign_transaction, signed_transaction_with_nonce,
            transaction_price,
        };
        use crate::transactions::EthTransactions;
        use proptest::{prop_assume, proptest};

        #[test]
        #[should_panic(expected = "missing created transaction")]
        fn should_fail_when_created_transaction_not_found() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            transactions
                .record_signed_transaction(signed_transaction_with_nonce(TransactionNonce::ZERO));
        }

        #[test]
        fn should_record_signed_transactions() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            for i in 0..100 {
                let ledger_burn_index = LedgerBurnIndex::new(15 + i);
                let withdrawal_request =
                    create_and_record_withdrawal_request(&mut transactions, ledger_burn_index);
                let created_tx = create_and_record_transaction(
                    &mut transactions,
                    withdrawal_request,
                    transaction_price(),
                );
                let signed_tx = sign_transaction(created_tx);

                transactions.record_signed_transaction(signed_tx.clone());

                assert_eq!(transactions.created_transactions_iter().next(), None);
                assert_eq!(
                    transactions.signed_tx.get_alt(&ledger_burn_index),
                    Some(&signed_tx)
                );
            }
        }

        proptest! {
            #[test]
            fn should_fail_when_signed_transaction_does_not_match_created_transaction(
                bad_tx in arb_signed_eip_1559_transaction_request_with_nonce(TransactionNonce::ZERO)
            ) {
                let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
                let ledger_burn_index = LedgerBurnIndex::new(15);
                let withdrawal_request =
                    create_and_record_withdrawal_request(&mut transactions, ledger_burn_index);
                let created_tx = create_and_record_transaction(
                    &mut transactions,
                    withdrawal_request,
                    transaction_price(),
                );
                prop_assume!(bad_tx.transaction() != &created_tx);

                expect_panic_with_message(
                    || transactions.record_signed_transaction(bad_tx),
                    "mismatch",
                );
            }
        }

        #[test]
        fn should_fail_to_re_sign_without_resubmit() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let ledger_burn_index = LedgerBurnIndex::new(15);
            let withdrawal_request =
                create_and_record_withdrawal_request(&mut transactions, ledger_burn_index);
            let created_tx = create_and_record_transaction(
                &mut transactions,
                withdrawal_request,
                transaction_price(),
            );
            let signed_tx = sign_transaction(created_tx);
            transactions.record_signed_transaction(signed_tx.clone());

            expect_panic_with_message(
                || transactions.record_signed_transaction(signed_tx),
                "missing created transaction",
            );
        }
    }

    mod record_sent_transaction {
        use super::super::arbitrary::arb_signed_eip_1559_transaction_request_with_nonce;
        use super::*;
        use crate::map::MultiKeyMap;
        use crate::transactions::tests::{
            create_and_record_signed_transaction, create_and_record_transaction,
            create_and_record_withdrawal_request, expect_panic_with_message,
            signed_transaction_with_nonce, transaction_price,
        };
        use proptest::{prop_assume, proptest};

        #[test]
        #[should_panic(expected = "missing signed transaction")]
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
            let signed_tx = create_and_record_signed_transaction(&mut transactions, created_tx);

            transactions.record_sent_transaction(signed_tx.clone());

            assert_eq!(transactions.created_transactions_iter().next(), None);
            assert_eq!(transactions.signed_transactions_iter().next(), None);
            assert_eq!(
                transactions.sent_tx,
                MultiKeyMap::from_iter(vec![(
                    TransactionNonce::ZERO,
                    ledger_burn_index,
                    vec![signed_tx]
                )])
            );
        }

        proptest! {
            #[test]
            fn should_fail_when_first_sent_transaction_does_not_match_signed_transaction(
                wrong_signed_tx in arb_signed_eip_1559_transaction_request_with_nonce(TransactionNonce::ZERO)
            ) {
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
                create_and_record_signed_transaction(&mut transactions, created_tx.clone());
                prop_assume!(signed_tx != wrong_signed_tx);

                expect_panic_with_message(
                    || transactions.record_sent_transaction(wrong_signed_tx.clone()),
                    "mismatch between sent transaction and signed transaction",
                );
            }
        }

        #[test]
        fn should_fail_to_resend_without_resubmit() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let ledger_burn_index = LedgerBurnIndex::new(15);
            let withdrawal_request =
                create_and_record_withdrawal_request(&mut transactions, ledger_burn_index);
            let created_tx = create_and_record_transaction(
                &mut transactions,
                withdrawal_request,
                transaction_price(),
            );
            let signed_tx = create_and_record_signed_transaction(&mut transactions, created_tx);
            transactions.record_sent_transaction(signed_tx.clone());

            expect_panic_with_message(
                || transactions.record_sent_transaction(signed_tx),
                "missing signed transaction",
            );
        }
    }

    mod create_resubmit_transactions {
        use crate::eth_rpc::Quantity;
        use crate::numeric::{LedgerBurnIndex, TransactionCount, TransactionNonce, Wei};
        use crate::transactions::tests::{
            create_and_record_signed_transaction, create_and_record_transaction,
            create_and_record_withdrawal_request, transaction_price, withdrawal_request_with_index,
        };
        use crate::transactions::{EthTransactions, ResubmitTransaction, ResubmitTransactionError};
        use crate::tx::{Eip1559TransactionRequest, TransactionPrice};

        #[test]
        fn should_be_empty_when_no_sent_transactions() {
            let transactions = EthTransactions::new(TransactionNonce::ZERO);
            let resubmitted_txs = transactions
                .create_resubmit_transactions(TransactionCount::ZERO, transaction_price());

            assert_eq!(resubmitted_txs, vec![]);
        }

        #[test]
        fn should_be_empty_when_all_sent_transactions_already_mined() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let initial_price = transaction_price();
            let higher_new_price = TransactionPrice {
                max_fee_per_gas: initial_price.max_fee_per_gas.checked_increment().unwrap(),
                ..initial_price
            };
            for num_tx in 0..100_u64 {
                let withdrawal_request =
                    withdrawal_request_with_index(LedgerBurnIndex::new(15 + num_tx));
                transactions.record_withdrawal_request(withdrawal_request.clone());
                let created_tx = create_and_record_transaction(
                    &mut transactions,
                    withdrawal_request,
                    initial_price.clone(),
                );
                let signed_tx = create_and_record_signed_transaction(&mut transactions, created_tx);
                transactions.record_sent_transaction(signed_tx);

                let resubmitted_txs = transactions.create_resubmit_transactions(
                    TransactionCount::from(num_tx + 1),
                    higher_new_price.clone(),
                );

                assert_eq!(resubmitted_txs, vec![]);
            }
        }

        #[test]
        fn should_resubmit_sent_transactions_as_is_when_new_price_not_higher() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let initial_price = transaction_price();
            let mut sent_transactions = Vec::with_capacity(100);
            for num_tx in 0..100_u64 {
                let withdrawal_request = create_and_record_withdrawal_request(
                    &mut transactions,
                    LedgerBurnIndex::new(15 + num_tx),
                );
                let created_tx = create_and_record_transaction(
                    &mut transactions,
                    withdrawal_request,
                    initial_price.clone(),
                );
                let signed_tx = create_and_record_signed_transaction(&mut transactions, created_tx);
                transactions.record_sent_transaction(signed_tx.clone());
                sent_transactions.push(signed_tx);
            }

            let resubmitted_txs = transactions
                .create_resubmit_transactions(TransactionCount::from(10_u8), initial_price.clone());

            //transactions with nonces 0..10 (exclusive) were mined
            assert_eq!(
                resubmitted_txs,
                sent_transactions[10..]
                    .iter()
                    .map(|tx| Ok::<ResubmitTransaction, ResubmitTransactionError>(
                        ResubmitTransaction::ToSend(tx.clone())
                    ))
                    .collect::<Vec<_>>()
            );
        }

        #[test]
        fn should_resubmit_transaction_with_updated_price() {
            let price_at_tx_creation = TransactionPrice {
                gas_limit: Quantity::new(21_000),
                max_fee_per_gas: Wei::from(11_u8),
                max_priority_fee_per_gas: Wei::from(21_u8),
            };
            let tests = vec![
                ParameterizedTest {
                    price_at_tx_creation: price_at_tx_creation.clone(),
                    price_at_tx_resubmission: TransactionPrice {
                        max_fee_per_gas: price_at_tx_creation
                            .max_fee_per_gas
                            .checked_increment()
                            .unwrap(),
                        ..price_at_tx_creation.clone()
                    },
                    resubmitted_tx_max_fee_per_gas: Wei::from(13_u8), //10% increase of 11 rounded up
                    resubmitted_tx_max_priority_fee_per_gas: Wei::from(24_u8), //10% increase of 21 rounded up
                    resubmitted_tx_amount_deduction: Wei::from(2 * 21_000_u32), //The increase in max_fee_per_gas is 2, so with a gas limit of 21_000, the amount should be decreased by 42_000
                },
                ParameterizedTest {
                    price_at_tx_creation: price_at_tx_creation.clone(),
                    price_at_tx_resubmission: TransactionPrice {
                        max_fee_per_gas: price_at_tx_creation
                            .max_fee_per_gas
                            .checked_mul(2_u8)
                            .unwrap(),
                        ..price_at_tx_creation.clone()
                    },
                    resubmitted_tx_max_fee_per_gas: Wei::from(22_u8), //new price because higher than 10% bump
                    resubmitted_tx_max_priority_fee_per_gas: Wei::from(24_u8), //10% increase of 21 rounded up
                    resubmitted_tx_amount_deduction: Wei::from(11 * 21_000_u32),
                },
                ParameterizedTest {
                    price_at_tx_creation: price_at_tx_creation.clone(),
                    price_at_tx_resubmission: TransactionPrice {
                        max_fee_per_gas: price_at_tx_creation
                            .max_fee_per_gas
                            .checked_mul(2_u8)
                            .unwrap(),
                        max_priority_fee_per_gas: price_at_tx_creation
                            .max_priority_fee_per_gas
                            .checked_mul(2_u8)
                            .unwrap(),
                        ..price_at_tx_creation.clone()
                    },
                    resubmitted_tx_max_fee_per_gas: Wei::from(22_u8), //new price because higher than 10% bump
                    resubmitted_tx_max_priority_fee_per_gas: Wei::from(42_u8), //new price because higher than 10% bump
                    resubmitted_tx_amount_deduction: Wei::from(11 * 21_000_u32),
                },
            ];

            for test in tests {
                let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
                let ledger_burn_index = LedgerBurnIndex::new(15);
                let withdrawal_request = withdrawal_request_with_index(ledger_burn_index);
                transactions.record_withdrawal_request(withdrawal_request.clone());
                let initial_tx = create_and_record_transaction(
                    &mut transactions,
                    withdrawal_request,
                    test.price_at_tx_creation.clone(),
                );
                let signed_tx =
                    create_and_record_signed_transaction(&mut transactions, initial_tx.clone());
                transactions.record_sent_transaction(signed_tx);

                let resubmitted_txs = transactions.create_resubmit_transactions(
                    TransactionCount::ZERO,
                    test.price_at_tx_resubmission.clone(),
                );

                let expected_resubmitted_tx = Eip1559TransactionRequest {
                    max_fee_per_gas: test.resubmitted_tx_max_fee_per_gas,
                    max_priority_fee_per_gas: test.resubmitted_tx_max_priority_fee_per_gas,
                    amount: initial_tx
                        .amount
                        .checked_sub(test.resubmitted_tx_amount_deduction)
                        .unwrap(),
                    ..initial_tx
                };
                assert_eq!(
                    resubmitted_txs,
                    vec![Ok(ResubmitTransaction::ToSign(expected_resubmitted_tx))]
                );
            }
        }

        #[test]
        fn should_resubmit_multiple_transactions() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let initial_price = TransactionPrice {
                gas_limit: Quantity::new(21_000),
                max_fee_per_gas: Wei::from(11_u8),
                max_priority_fee_per_gas: Wei::from(21_u8),
            };
            for num_tx in 0..100_u64 {
                let withdrawal_request = create_and_record_withdrawal_request(
                    &mut transactions,
                    LedgerBurnIndex::new(15 + num_tx),
                );
                let created_tx = create_and_record_transaction(
                    &mut transactions,
                    withdrawal_request,
                    initial_price.clone(),
                );
                let signed_tx = create_and_record_signed_transaction(&mut transactions, created_tx);
                transactions.record_sent_transaction(signed_tx);
            }
            let higher_price = TransactionPrice {
                max_fee_per_gas: initial_price.max_fee_per_gas.checked_increment().unwrap(),
                ..initial_price
            };

            let resubmitted_txs = transactions
                .create_resubmit_transactions(TransactionCount::from(30_u8), higher_price.clone());
            assert_eq!(resubmitted_txs.len(), 70);
            for (i, resubmitted_tx) in resubmitted_txs
                .into_iter()
                .map(|res| res.unwrap())
                .enumerate()
            {
                let initial_transaction = transactions
                    .sent_tx
                    .get_alt(&LedgerBurnIndex::new(15 + i as u64))
                    .unwrap()[0]
                    .transaction();
                assert_eq!(
                    resubmitted_tx,
                    ResubmitTransaction::ToSign(Eip1559TransactionRequest {
                        nonce: TransactionNonce::from(30_u8 + i as u8),
                        max_fee_per_gas: Wei::from(13_u8),
                        max_priority_fee_per_gas: Wei::from(24_u8),
                        amount: initial_transaction
                            .amount
                            .checked_sub(Wei::from(2 * 21_000_u32))
                            .unwrap(),
                        ..initial_transaction.clone()
                    })
                );
            }
        }

        struct ParameterizedTest {
            price_at_tx_creation: TransactionPrice,
            price_at_tx_resubmission: TransactionPrice,
            resubmitted_tx_max_fee_per_gas: Wei,
            resubmitted_tx_max_priority_fee_per_gas: Wei,
            resubmitted_tx_amount_deduction: Wei,
        }
    }

    mod record_resubmit_transaction {
        use super::super::arbitrary::arb_signed_eip_1559_transaction_request_with_nonce;
        use crate::eth_rpc::Quantity;
        use crate::map::MultiKeyMap;
        use crate::numeric::{LedgerBurnIndex, TransactionCount, TransactionNonce, Wei};
        use crate::transactions::tests::{
            create_and_record_signed_transaction, create_and_record_transaction,
            create_and_record_withdrawal_request, expect_panic_with_message, sign_transaction,
            transaction_price,
        };
        use crate::transactions::{EthTransactions, ResubmitTransaction};
        use crate::tx::{Eip1559TransactionRequest, TransactionPrice};
        use proptest::{prop_assume, proptest};
        use std::iter;

        #[test]
        fn should_fail_when_no_sent_tx() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let withdrawal_request =
                create_and_record_withdrawal_request(&mut transactions, LedgerBurnIndex::new(15));
            let created_tx = create_and_record_transaction(
                &mut transactions,
                withdrawal_request,
                transaction_price(),
            );

            expect_panic_with_message(
                || {
                    transactions
                        .record_resubmit_transaction(ResubmitTransaction::ToSign(created_tx))
                },
                "sent transaction not found",
            );
        }

        #[test]
        fn should_add_multiple_sent_transactions_for_same_nonce_with_different_fees() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let ledger_burn_index = LedgerBurnIndex::new(15);
            let withdrawal_request =
                create_and_record_withdrawal_request(&mut transactions, ledger_burn_index);
            let created_tx = create_and_record_transaction(
                &mut transactions,
                withdrawal_request,
                transaction_price(),
            );
            let first_sent_tx =
                create_and_record_signed_transaction(&mut transactions, created_tx.clone());
            transactions.record_sent_transaction(first_sent_tx.clone());

            let transaction_with_increasing_fees: Vec<_> = iter::repeat(created_tx)
                .take(10)
                .enumerate()
                .map(|(index, mut tx)| {
                    tx.max_priority_fee_per_gas = tx
                        .max_priority_fee_per_gas
                        .checked_add(Wei::from(index as u8))
                        .unwrap();
                    tx.amount = tx.amount.checked_sub(Wei::from(index as u8)).unwrap();
                    tx
                })
                .collect();

            for (index, transaction) in transaction_with_increasing_fees.iter().enumerate() {
                transactions
                    .record_resubmit_transaction(ResubmitTransaction::ToSign(transaction.clone()));
                let signed_tx = sign_transaction(transaction.clone());
                transactions.record_signed_transaction(signed_tx.clone());
                transactions.record_sent_transaction(signed_tx);
                assert_eq!(transactions.created_transactions_iter().next(), None);
                assert_eq!(
                    transactions.sent_tx,
                    MultiKeyMap::from_iter(vec![(
                        TransactionNonce::ZERO,
                        ledger_burn_index,
                        vec![first_sent_tx.clone()]
                            .into_iter()
                            .chain(
                                transaction_with_increasing_fees[0..=index]
                                    .iter()
                                    .map(|tx| sign_transaction(tx.clone()))
                            )
                            .collect()
                    )])
                );
            }
        }

        proptest! {
            #[test]
            fn should_fail_when_mismatch_with_already_sent(
                wrong_resent_tx in arb_signed_eip_1559_transaction_request_with_nonce(TransactionNonce::ZERO)
            ) {
                let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
                let ledger_burn_index = LedgerBurnIndex::new(15);
                let withdrawal_request =
                    create_and_record_withdrawal_request(&mut transactions, ledger_burn_index);
                let created_tx = create_and_record_transaction(
                    &mut transactions,
                    withdrawal_request,
                    transaction_price(),
                );
                let signed_tx =
                    create_and_record_signed_transaction(&mut transactions, created_tx.clone());
                transactions.record_sent_transaction(signed_tx.clone());
                prop_assume!(signed_tx != wrong_resent_tx);

                expect_panic_with_message(
                    || {
                        transactions
                            .record_resubmit_transaction(ResubmitTransaction::ToSend(wrong_resent_tx))
                    },
                    "mismatch between last sent transaction",
                );
            }
        }

        #[test]
        fn should_replace_existing_resubmitted_transaction() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let initial_price = TransactionPrice {
                gas_limit: Quantity::new(21_000),
                max_fee_per_gas: Wei::from(11_u8),
                max_priority_fee_per_gas: Wei::from(21_u8),
            };
            let resubmit_price_1 = TransactionPrice {
                max_fee_per_gas: initial_price.max_fee_per_gas.checked_increment().unwrap(),
                ..initial_price
            };
            let ledger_burn_index = LedgerBurnIndex::new(15);
            let withdrawal_request =
                create_and_record_withdrawal_request(&mut transactions, ledger_burn_index);
            let created_tx = create_and_record_transaction(
                &mut transactions,
                withdrawal_request,
                initial_price.clone(),
            );
            let signed_tx =
                create_and_record_signed_transaction(&mut transactions, created_tx.clone());
            transactions.record_sent_transaction(signed_tx);

            let resubmitted_txs_1 = transactions
                .create_resubmit_transactions(TransactionCount::ZERO, resubmit_price_1.clone());
            let resubmitted_tx1 = Eip1559TransactionRequest {
                max_fee_per_gas: Wei::from(13_u8),
                max_priority_fee_per_gas: Wei::from(24_u8),
                amount: created_tx
                    .amount
                    .checked_sub(Wei::from(2 * 21_000_u32))
                    .unwrap(),
                ..created_tx.clone()
            };
            let expected_resubmitted_tx1 = ResubmitTransaction::ToSign(resubmitted_tx1.clone());
            assert_eq!(
                resubmitted_txs_1,
                vec![Ok(expected_resubmitted_tx1.clone())]
            );
            transactions.record_resubmit_transaction(expected_resubmitted_tx1);
            assert_eq!(
                transactions.created_transactions_iter().collect::<Vec<_>>(),
                vec![(
                    &TransactionNonce::ZERO,
                    &ledger_burn_index,
                    &resubmitted_tx1
                )]
            );

            let resubmit_price_2 = TransactionPrice {
                max_fee_per_gas: initial_price.max_fee_per_gas.checked_mul(2_u8).unwrap(),
                ..resubmit_price_1
            };
            let resubmitted_txs_2 =
                transactions.create_resubmit_transactions(TransactionCount::ZERO, resubmit_price_2);
            let resubmitted_tx2 = Eip1559TransactionRequest {
                max_fee_per_gas: Wei::from(22_u8),
                max_priority_fee_per_gas: Wei::from(24_u8),
                amount: created_tx
                    .amount
                    .checked_sub(Wei::from(11 * 21_000_u32))
                    .unwrap(),
                ..created_tx
            };
            let expected_resubmitted_tx2 = ResubmitTransaction::ToSign(resubmitted_tx2.clone());
            assert_eq!(
                resubmitted_txs_2,
                vec![Ok(expected_resubmitted_tx2.clone())]
            );
            transactions.record_resubmit_transaction(expected_resubmitted_tx2);
            assert_eq!(
                transactions.created_transactions_iter().collect::<Vec<_>>(),
                vec![(
                    &TransactionNonce::ZERO,
                    &ledger_burn_index,
                    &resubmitted_tx2
                )]
            );
        }
    }

    mod sent_transactions_to_finalize {
        use super::super::{
            arbitrary::arb_checked_amount_of, create_and_record_transaction,
            create_and_record_withdrawal_request, transaction_price,
        };
        use crate::numeric::{TransactionCount, TransactionNonce};
        use crate::transactions::tests::{
            create_and_record_signed_transaction, resubmit_transaction_with_bumped_price,
            resubmit_transaction_with_same_price,
        };
        use crate::transactions::{EthTransactions, LedgerBurnIndex};
        use crate::tx::SignedEip1559TransactionRequest;
        use proptest::proptest;
        use std::collections::BTreeMap;

        proptest! {
            #[test]
            fn should_be_empty_when_no_transaction_to_finalize(finalized_tx_count in arb_checked_amount_of()) {
                let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
                assert_eq!(
                    transactions.sent_transactions_to_finalize(&finalized_tx_count),
                    BTreeMap::default()
                );

                let ledger_burn_index = LedgerBurnIndex::new(15);
                let withdrawal_request = create_and_record_withdrawal_request(
                    &mut transactions,
                    ledger_burn_index
                );
                assert_eq!(
                    transactions.sent_transactions_to_finalize(&finalized_tx_count),
                    BTreeMap::default()
                );

                let created_tx = create_and_record_transaction(
                    &mut transactions,
                    withdrawal_request,
                    transaction_price(),
                );
                assert_eq!(
                    transactions.sent_transactions_to_finalize(&finalized_tx_count),
                    BTreeMap::default()
                );

                let _signed_tx = create_and_record_signed_transaction(&mut transactions, created_tx);
                assert_eq!(
                    transactions.sent_transactions_to_finalize(&finalized_tx_count),
                    BTreeMap::default()
                );
            }
        }

        #[test]
        fn should_contain_transactions_to_finalize() {
            fn send_transaction(
                transactions: &mut EthTransactions,
                ledger_burn_index: LedgerBurnIndex,
            ) -> SignedEip1559TransactionRequest {
                let withdrawal_request =
                    create_and_record_withdrawal_request(transactions, ledger_burn_index);
                let created_tx = create_and_record_transaction(
                    transactions,
                    withdrawal_request,
                    transaction_price(),
                );
                let signed_tx =
                    create_and_record_signed_transaction(transactions, created_tx.clone());
                transactions.record_sent_transaction(signed_tx.clone());
                signed_tx
            }

            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);

            let withdrawal_id_15 = LedgerBurnIndex::new(15);
            let sent_tx_0_0 = send_transaction(&mut transactions, withdrawal_id_15);
            assert_eq!(sent_tx_0_0.nonce(), TransactionNonce::ZERO);
            let sent_tx_0_1 = resubmit_transaction_with_bumped_price(
                &mut transactions,
                sent_tx_0_0.transaction().clone(),
            );
            let sent_tx_0_2 =
                resubmit_transaction_with_same_price(&mut transactions, sent_tx_0_1.clone());
            let hashes_0: BTreeMap<_, _> = vec![sent_tx_0_0, sent_tx_0_1, sent_tx_0_2]
                .iter()
                .map(|tx| (tx.hash(), withdrawal_id_15))
                .collect();

            let withdrawal_id_16 = LedgerBurnIndex::new(16);
            let sent_tx_1_0 = send_transaction(&mut transactions, withdrawal_id_16);
            assert_eq!(sent_tx_1_0.nonce(), TransactionNonce::ONE);
            let sent_tx_1_1 = resubmit_transaction_with_bumped_price(
                &mut transactions,
                sent_tx_1_0.transaction().clone(),
            );
            let sent_tx_1_2 = resubmit_transaction_with_bumped_price(
                &mut transactions,
                sent_tx_1_1.transaction().clone(),
            );
            let sent_tx_1_3 =
                resubmit_transaction_with_same_price(&mut transactions, sent_tx_1_2.clone());
            let hashes_1: BTreeMap<_, _> = vec![sent_tx_1_0, sent_tx_1_1, sent_tx_1_2, sent_tx_1_3]
                .iter()
                .map(|tx| (tx.hash(), withdrawal_id_16))
                .collect();

            let signed_tx = send_transaction(&mut transactions, LedgerBurnIndex::new(17));
            assert_eq!(signed_tx.nonce(), TransactionNonce::TWO);

            let res = transactions.sent_transactions_to_finalize(&TransactionCount::ZERO);
            assert_eq!(res, BTreeMap::default());

            let res = transactions.sent_transactions_to_finalize(&TransactionCount::ONE);
            assert_eq!(res, hashes_0);

            let res = transactions.sent_transactions_to_finalize(&TransactionCount::TWO);
            assert_eq!(
                res,
                hashes_0.into_iter().chain(hashes_1.into_iter()).collect()
            );
        }
    }

    mod record_finalized_transaction {
        use crate::map::MultiKeyMap;
        use crate::numeric::{LedgerBurnIndex, TransactionNonce};
        use crate::transactions::tests::{
            create_and_record_signed_transaction, create_and_record_transaction,
            create_and_record_withdrawal_request, dummy_signature, expect_panic_with_message,
            transaction_price, transaction_receipt, withdrawal_request_with_index,
        };
        use crate::transactions::{EthTransactions, ResubmitTransaction};
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
                create_and_record_signed_transaction(&mut transactions, created_tx.clone());

            transactions.record_sent_transaction(signed_tx.clone());

            expect_panic_with_message(
                || {
                    transactions.record_finalized_transaction(
                        LedgerBurnIndex::new(16),
                        transaction_receipt(&signed_tx),
                    )
                },
                "missing sent transaction",
            );

            let receipt_with_wrong_hash = {
                let mut wrong_signature = dummy_signature();
                wrong_signature.signature_y_parity = true;
                transaction_receipt(&SignedEip1559TransactionRequest::from((
                    created_tx,
                    wrong_signature,
                )))
            };

            expect_panic_with_message(
                || {
                    transactions
                        .record_finalized_transaction(ledger_burn_index, receipt_with_wrong_hash)
                },
                "no transaction matching receipt",
            );
        }

        #[test]
        fn should_record_finalized_transaction() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let ledger_burn_index = LedgerBurnIndex::new(15);
            let withdrawal_request =
                create_and_record_withdrawal_request(&mut transactions, ledger_burn_index);
            let created_tx = create_and_record_transaction(
                &mut transactions,
                withdrawal_request,
                transaction_price(),
            );
            let signed_tx = create_and_record_signed_transaction(&mut transactions, created_tx);
            transactions.record_sent_transaction(signed_tx.clone());

            let receipt = transaction_receipt(&signed_tx);
            transactions.record_finalized_transaction(ledger_burn_index, receipt.clone());

            assert_eq!(
                transactions
                    .finalized_transactions_iter()
                    .collect::<Vec<_>>(),
                vec![(
                    &TransactionNonce::ZERO,
                    &ledger_burn_index,
                    &signed_tx.try_finalize(receipt).unwrap()
                )]
            );
            assert_eq!(transactions.created_transactions_iter().next(), None);
            assert_eq!(transactions.signed_transactions_iter().next(), None);
            assert_eq!(transactions.sent_transactions_iter().next(), None);
        }

        #[test]
        fn should_clean_up_failed_resubmitted_transactions_when_finalizing() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let ledger_burn_index = LedgerBurnIndex::new(15);
            let withdrawal_request =
                create_and_record_withdrawal_request(&mut transactions, ledger_burn_index);
            let created_tx = create_and_record_transaction(
                &mut transactions,
                withdrawal_request,
                transaction_price(),
            );
            let signed_tx =
                create_and_record_signed_transaction(&mut transactions, created_tx.clone());
            transactions.record_sent_transaction(signed_tx.clone());
            transactions
                .record_resubmit_transaction(ResubmitTransaction::ToSend(signed_tx.clone()));
            transactions.record_sent_transaction(signed_tx.clone());
            assert_eq!(
                transactions
                    .sent_tx
                    .get(&TransactionNonce::ZERO)
                    .unwrap()
                    .len(),
                2
            );
            transactions
                .record_resubmit_transaction(ResubmitTransaction::ToSend(signed_tx.clone()));
            assert!(transactions.signed_tx.contains_alt(&ledger_burn_index));
            transactions
                .record_resubmit_transaction(ResubmitTransaction::ToSign(created_tx.clone()));
            assert!(transactions.created_tx.contains_alt(&ledger_burn_index));

            let receipt = transaction_receipt(&signed_tx);
            transactions.record_finalized_transaction(ledger_burn_index, receipt.clone());

            assert_eq!(
                transactions.finalized_tx,
                MultiKeyMap::from_iter(vec![(
                    TransactionNonce::ZERO,
                    ledger_burn_index,
                    signed_tx.try_finalize(receipt).unwrap()
                )])
            );
            assert_eq!(transactions.created_transactions_iter().next(), None);
            assert_eq!(transactions.signed_transactions_iter().next(), None);
            assert_eq!(transactions.sent_transactions_iter().next(), None);
        }
    }

    mod transaction_status {
        use crate::endpoints::{EthTransaction, RetrieveEthStatus};
        use crate::numeric::{LedgerBurnIndex, TransactionNonce};
        use crate::transactions::tests::{
            create_and_record_transaction, sign_transaction, transaction_price,
            transaction_receipt, withdrawal_request_with_index,
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
            let eth_transaction = EthTransaction {
                transaction_hash: signed_tx.hash().to_string(),
            };
            transactions.record_signed_transaction(signed_tx.clone());
            assert_eq!(
                transactions.transaction_status(&ledger_burn_index),
                RetrieveEthStatus::TxSigned(eth_transaction.clone())
            );

            transactions.record_sent_transaction(signed_tx.clone());
            assert_eq!(
                transactions.transaction_status(&ledger_burn_index),
                RetrieveEthStatus::TxSent(eth_transaction.clone())
            );

            transactions
                .record_finalized_transaction(ledger_burn_index, transaction_receipt(&signed_tx));
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
    use crate::lifecycle::EvmNetwork;
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
                EvmNetwork::Sepolia,
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
                EvmNetwork::Sepolia,
            );

            prop_assert_eq!(result, Ok(Eip1559TransactionRequest {
                chain_id: EvmNetwork::Sepolia.chain_id(),
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

mod withdrawal_flow {
    use super::arbitrary::{
        arb_checked_amount_of, arb_non_overflowing_transaction_price, arb_withdrawal_request,
    };
    use crate::lifecycle::init::InitArg;
    use crate::numeric::{wei_from_milli_ether, LedgerBurnIndex, TransactionNonce};
    use crate::state::{mutate_state, read_state, State, STATE};
    use crate::storage::{decode_state, encode_state};
    use crate::transactions::tests::{
        create_and_record_signed_transaction, create_and_record_transaction,
        create_and_record_withdrawal_request, sign_transaction, transaction_price,
        transaction_receipt,
    };
    use crate::transactions::{create_transaction, EthTransactions, EvmNetwork};
    use candid::Principal;
    use proptest::proptest;
    use std::cell::RefCell;

    #[test]
    fn should_not_panic() {
        let transactions = EthTransactions::new(TransactionNonce::ZERO);
        //required because proptest closure cannot take mutable args.
        let wrapped_txs = RefCell::new(transactions);

        proptest!(|(request in arb_withdrawal_request())| {
            wrapped_txs.borrow_mut().record_withdrawal_request(request)
        });

        proptest!(|(transaction_price in arb_non_overflowing_transaction_price(), transaction_count in arb_checked_amount_of())| {
            let resubmit_txs = wrapped_txs.borrow().create_resubmit_transactions(transaction_count, transaction_price.clone());
            for resubmit_tx in resubmit_txs.into_iter().flatten() {
                wrapped_txs.borrow_mut().record_resubmit_transaction(resubmit_tx);
            }

            let withdrawal_requests = wrapped_txs.borrow().withdrawal_requests_batch(5);
            for request in withdrawal_requests {
                let nonce = wrapped_txs.borrow().next_transaction_nonce();
                if let Ok(created_tx) = create_transaction(
                    &request,
                    nonce,
                    transaction_price.clone(),
                    EvmNetwork::Sepolia,
                ){
                    wrapped_txs.borrow_mut().record_created_transaction(request, created_tx);
                }
            }

            let created_txs: Vec<_> = wrapped_txs.borrow().created_transactions_iter().map(|(_nonce, _ledger_burn_index, tx)| tx)
            .cloned()
            .collect();
            for created_tx in created_txs {
                wrapped_txs.borrow_mut().record_signed_transaction(sign_transaction(created_tx));
            }

            let sent_txs: Vec<_> =  wrapped_txs.borrow().signed_transactions_iter().map(|(_nonce, _ledger_burn_index, tx)| tx)
            .cloned()
            .collect();
            for sent_tx in sent_txs {
                wrapped_txs.borrow_mut().record_sent_transaction(sent_tx);
            }
        });
    }

    #[test]
    fn should_encode_decode_state() {
        use crate::state::STATE;
        STATE.with(|s| {
            *s.borrow_mut() = Some(
                State::try_from(InitArg {
                    ethereum_network: Default::default(),
                    ecdsa_key_name: "test_key_1".to_string(),
                    ethereum_contract_address: None,
                    ledger_id: Principal::from_text("apia6-jaaaa-aaaar-qabma-cai")
                        .expect("BUG: invalid principal"),
                    ethereum_block_height: Default::default(),
                    minimum_withdrawal_amount: wei_from_milli_ether(10).into(),
                    next_transaction_nonce: Default::default(),
                })
                .expect("init args should be valid"),
            );
        });

        check_encode_decode_state_roundtrip();

        let ledger_burn_index = LedgerBurnIndex::new(15);
        let withdrawal_request = mutate_state(|s| {
            create_and_record_withdrawal_request(&mut s.eth_transactions, ledger_burn_index)
        });
        check_encode_decode_state_roundtrip();

        let created_tx = mutate_state(|s| {
            create_and_record_transaction(
                &mut s.eth_transactions,
                withdrawal_request,
                transaction_price(),
            )
        });
        check_encode_decode_state_roundtrip();

        let signed_tx = mutate_state(|s| {
            create_and_record_signed_transaction(&mut s.eth_transactions, created_tx)
        });
        check_encode_decode_state_roundtrip();

        mutate_state(|s| {
            s.eth_transactions
                .record_sent_transaction(signed_tx.clone())
        });
        check_encode_decode_state_roundtrip();

        let receipt = transaction_receipt(&signed_tx);
        mutate_state(|s| {
            s.eth_transactions
                .record_finalized_transaction(ledger_burn_index, receipt)
        });
        println!("Encode/Decode finalized TX");
        check_encode_decode_state_roundtrip();
    }

    fn check_encode_decode_state_roundtrip() {
        let before_state = read_state(|s| s.clone());

        read_state(|s| encode_state(s));
        STATE.with(|cell| {
            *cell.borrow_mut() = Some(decode_state());
        });

        let after_state = read_state(|s| s.clone());
        assert_eq!(before_state, after_state);
    }
}

mod arbitrary {
    use crate::address::Address;
    use crate::checked_amount::CheckedAmountOf;
    use crate::eth_rpc::Quantity;
    use crate::numeric::{TransactionNonce, Wei};
    use crate::transactions::EthWithdrawalRequest;
    use crate::tx::{
        AccessList, AccessListItem, Eip1559Signature, Eip1559TransactionRequest,
        SignedEip1559TransactionRequest, StorageKey, TransactionPrice,
    };
    use phantom_newtype::Id;
    use proptest::strategy::Strategy;

    pub fn arb_checked_amount_of<Unit>() -> impl Strategy<Value = CheckedAmountOf<Unit>> {
        use proptest::arbitrary::any;
        use proptest::array::uniform32;
        uniform32(any::<u8>()).prop_map(CheckedAmountOf::from_be_bytes)
    }

    fn arb_u64_id<Entity>() -> impl Strategy<Value = Id<Entity, u64>> {
        use proptest::arbitrary::any;
        any::<u64>().prop_map(Id::from)
    }

    fn arb_u256() -> impl Strategy<Value = ethnum::u256> {
        use proptest::arbitrary::any;
        use proptest::array::uniform32;
        uniform32(any::<u8>()).prop_map(ethnum::u256::from_be_bytes)
    }

    fn arb_address() -> impl Strategy<Value = Address> {
        use proptest::arbitrary::any;
        use proptest::array::uniform20;
        uniform20(any::<u8>()).prop_map(|bytes| Address::new(bytes))
    }

    pub fn arb_withdrawal_request() -> impl Strategy<Value = EthWithdrawalRequest> {
        (arb_checked_amount_of(), arb_address(), arb_u64_id()).prop_map(
            |(withdrawal_amount, destination, ledger_burn_index)| EthWithdrawalRequest {
                withdrawal_amount,
                destination,
                ledger_burn_index,
            },
        )
    }

    pub fn arb_non_overflowing_transaction_price() -> impl Strategy<Value = TransactionPrice> {
        use proptest::arbitrary::any;
        (any::<u128>(), any::<u128>(), any::<u128>()).prop_map(
            |(gas_limit, max_priority_fee_per_gas, max_fee_per_gas)| {
                let price = TransactionPrice {
                    gas_limit: Quantity::new(gas_limit),
                    max_fee_per_gas: Wei::new(max_fee_per_gas),
                    max_priority_fee_per_gas: Wei::new(max_priority_fee_per_gas),
                };
                let _does_not_panic = price.max_transaction_fee();
                price
            },
        )
    }

    fn arb_storage_key() -> impl Strategy<Value = StorageKey> {
        use proptest::arbitrary::any;
        use proptest::array::uniform32;
        uniform32(any::<u8>()).prop_map(StorageKey)
    }

    fn arb_access_list_item() -> impl Strategy<Value = AccessListItem> {
        use proptest::collection::vec;
        (arb_address(), vec(arb_storage_key(), 0..100)).prop_map(|(address, storage_keys)| {
            AccessListItem {
                address,
                storage_keys,
            }
        })
    }

    fn arb_access_list() -> impl Strategy<Value = AccessList> {
        use proptest::collection::vec;
        vec(arb_access_list_item(), 0..100).prop_map(AccessList)
    }

    pub fn arb_eip_1559_transaction_request() -> impl Strategy<Value = Eip1559TransactionRequest> {
        use proptest::arbitrary::any;
        use proptest::collection::vec;
        (
            any::<u64>(),
            arb_checked_amount_of(),
            arb_non_overflowing_transaction_price(),
            arb_address(),
            arb_checked_amount_of(),
            vec(any::<u8>(), 0..100),
            arb_access_list(),
        )
            .prop_map(
                |(chain_id, nonce, transaction_price, destination, amount, data, access_list)| {
                    Eip1559TransactionRequest {
                        chain_id,
                        nonce,
                        max_priority_fee_per_gas: transaction_price.max_priority_fee_per_gas,
                        max_fee_per_gas: transaction_price.max_fee_per_gas,
                        gas_limit: transaction_price.gas_limit,
                        destination,
                        amount,
                        data,
                        access_list,
                    }
                },
            )
    }

    fn arb_eip_1559_signature() -> impl Strategy<Value = Eip1559Signature> {
        use proptest::arbitrary::any;
        (any::<bool>(), arb_u256(), arb_u256()).prop_map(|(signature_y_parity, r, s)| {
            Eip1559Signature {
                signature_y_parity,
                r,
                s,
            }
        })
    }

    pub fn arb_signed_eip_1559_transaction_request_with_nonce(
        nonce: TransactionNonce,
    ) -> impl Strategy<Value = SignedEip1559TransactionRequest> {
        (arb_eip_1559_transaction_request(), arb_eip_1559_signature()).prop_map(
            move |(mut tx, sig)| {
                tx.nonce = nonce;
                SignedEip1559TransactionRequest::from((tx, sig))
            },
        )
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

fn create_and_record_withdrawal_request(
    transactions: &mut EthTransactions,
    ledger_burn_index: LedgerBurnIndex,
) -> EthWithdrawalRequest {
    let request = withdrawal_request_with_index(ledger_burn_index);
    transactions.record_withdrawal_request(request.clone());
    request
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
        EvmNetwork::Sepolia,
    )
    .expect("failed to create transaction");
    transactions.record_created_transaction(withdrawal_request, tx);
    transactions
        .created_tx
        .get_alt(&burn_index)
        .unwrap()
        .clone()
}

fn create_and_record_signed_transaction(
    transactions: &mut EthTransactions,
    created_tx: Eip1559TransactionRequest,
) -> SignedEip1559TransactionRequest {
    let signed_tx = sign_transaction(created_tx);
    transactions.record_signed_transaction(signed_tx.clone());
    signed_tx
}

fn resubmit_transaction_with_bumped_price(
    transactions: &mut EthTransactions,
    created_tx: Eip1559TransactionRequest,
) -> SignedEip1559TransactionRequest {
    let bumped_price = created_tx.transaction_price().increase_by_10_percent();
    let new_tx = Eip1559TransactionRequest {
        max_fee_per_gas: bumped_price.max_fee_per_gas,
        max_priority_fee_per_gas: bumped_price.max_priority_fee_per_gas,
        gas_limit: bumped_price.gas_limit,
        ..created_tx
    };
    transactions.record_resubmit_transaction(ResubmitTransaction::ToSign(new_tx.clone()));
    let signed_tx = sign_transaction(new_tx);
    transactions.record_signed_transaction(signed_tx.clone());
    transactions.record_sent_transaction(signed_tx.clone());
    signed_tx
}

fn resubmit_transaction_with_same_price(
    transactions: &mut EthTransactions,
    signed_tx: SignedEip1559TransactionRequest,
) -> SignedEip1559TransactionRequest {
    let resubmit_tx = ResubmitTransaction::ToSend(signed_tx.clone());
    transactions.record_resubmit_transaction(resubmit_tx.clone());
    transactions.record_sent_transaction(signed_tx.clone());
    signed_tx
}

fn transaction_receipt(signed_tx: &SignedEip1559TransactionRequest) -> TransactionReceipt {
    use crate::eth_rpc_client::responses::TransactionStatus;
    use std::str::FromStr;
    TransactionReceipt {
        block_hash: Hash::from_str(
            "0xce67a85c9fb8bc50213815c32814c159fd75160acf7cb8631e8e7b7cf7f1d472",
        )
        .unwrap(),
        block_number: BlockNumber::new(4190269),
        effective_gas_price: signed_tx.transaction().max_fee_per_gas,
        gas_used: signed_tx.transaction().gas_limit,
        status: TransactionStatus::Success,
        transaction_hash: signed_tx.hash(),
    }
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
