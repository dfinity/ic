use crate::eth_rpc::Hash;
use crate::eth_rpc_client::responses::{TransactionReceipt, TransactionStatus};
use crate::lifecycle::EthereumNetwork;
use crate::numeric::{
    BlockNumber, Erc20Value, GasAmount, LedgerBurnIndex, TransactionNonce, Wei, WeiPerGas,
};
use crate::state::transactions::{
    create_transaction, Erc20WithdrawalRequest, EthTransactions, EthWithdrawalRequest, Subaccount,
    WithdrawalRequest,
};
use crate::tx::{
    AccessList, Eip1559Signature, Eip1559TransactionRequest, SignedEip1559TransactionRequest,
    TransactionPrice, TransactionPriceEstimate,
};
use crate::withdraw::{estimate_gas_limit, CKETH_WITHDRAWAL_TRANSACTION_GAS_LIMIT};
use ic_ethereum_types::Address;

const DEFAULT_WITHDRAWAL_AMOUNT: u128 = 1_100_000_000_000_000;
const DEFAULT_PRINCIPAL: &str = "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae";
const DEFAULT_SUBACCOUNT: [u8; 32] = [0x11; 32];
const DEFAULT_RECIPIENT_ADDRESS: &str = "0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34";
const DEFAULT_CREATED_AT: u64 = 1699527697000000000;

const DEFAULT_MAX_TRANSACTION_FEE: u128 = 30_000_000_000_000_000;
const DEFAULT_ERC20_CONTRACT_ADDRESS: &str = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";

mod eth_transactions {
    use crate::numeric::{LedgerBurnIndex, TransactionNonce};
    use crate::state::transactions::tests::cketh_withdrawal_request_with_index;
    use crate::state::transactions::tests::only_eth_withdrawals;
    use crate::state::transactions::{EthTransactions, TransactionStatus};

    mod record_withdrawal_request {
        use super::*;
        use crate::state::transactions::tests::{
            ckerc20_withdrawal_request_with_index, create_and_record_signed_transaction,
            create_and_record_transaction, gas_fee_estimate, transaction_receipt,
        };
        use crate::state::transactions::WithdrawalRequest;
        use crate::test_fixtures::expect_panic_with_message;

        #[test]
        fn should_record_withdrawal_request() {
            fn test<R: Into<WithdrawalRequest> + Clone>(withdrawal_request: R) {
                let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
                transactions.record_withdrawal_request(withdrawal_request.clone());

                assert_eq!(
                    transactions.withdrawal_requests_batch(5),
                    vec![withdrawal_request.into()]
                );
            }

            test(cketh_withdrawal_request_with_index(LedgerBurnIndex::new(
                15,
            )));
            test(ckerc20_withdrawal_request_with_index(
                LedgerBurnIndex::new(15),
                LedgerBurnIndex::new(1),
            ));
        }

        #[test]
        fn should_fail_recording_withdrawal_request_when_duplicate_ledger_burn_index() {
            fn test<R: Into<WithdrawalRequest> + Clone, S: Into<WithdrawalRequest> + Clone>(
                withdrawal_request: R,
                duplicate_index: S,
            ) {
                let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
                transactions.record_withdrawal_request(withdrawal_request.clone());

                expect_panic_with_message(
                    || transactions.record_withdrawal_request(duplicate_index.clone()),
                    "duplicate ckETH ledger burn index",
                );

                let created_tx = create_and_record_transaction(
                    &mut transactions,
                    withdrawal_request.clone(),
                    gas_fee_estimate(),
                );
                expect_panic_with_message(
                    || transactions.record_withdrawal_request(duplicate_index.clone()),
                    "duplicate ckETH ledger burn index",
                );

                let signed_tx = create_and_record_signed_transaction(&mut transactions, created_tx);
                expect_panic_with_message(
                    || transactions.record_withdrawal_request(duplicate_index.clone()),
                    "duplicate ckETH ledger burn index",
                );

                transactions.record_finalized_transaction(
                    withdrawal_request.into().cketh_ledger_burn_index(),
                    transaction_receipt(&signed_tx, TransactionStatus::Success),
                );
                expect_panic_with_message(
                    || transactions.record_withdrawal_request(duplicate_index.clone()),
                    "duplicate ckETH ledger burn index",
                );
            }

            let cketh_burn_index = LedgerBurnIndex::new(15);
            let ckerc20_burn_index = LedgerBurnIndex::new(1);
            test(
                cketh_withdrawal_request_with_index(cketh_burn_index),
                cketh_withdrawal_request_with_index(cketh_burn_index),
            );
            test(
                cketh_withdrawal_request_with_index(cketh_burn_index),
                ckerc20_withdrawal_request_with_index(cketh_burn_index, ckerc20_burn_index),
            );
            test(
                ckerc20_withdrawal_request_with_index(cketh_burn_index, ckerc20_burn_index),
                cketh_withdrawal_request_with_index(cketh_burn_index),
            );
            test(
                ckerc20_withdrawal_request_with_index(cketh_burn_index, ckerc20_burn_index),
                ckerc20_withdrawal_request_with_index(cketh_burn_index, ckerc20_burn_index),
            );
        }
    }

    mod withdrawal_requests_batch {
        use super::*;
        use crate::state::transactions::tests::{
            create_and_record_signed_transaction, create_and_record_transaction,
            create_and_record_withdrawal_request, gas_fee_estimate,
        };
        use crate::state::transactions::EthWithdrawalRequest;
        use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
        use proptest::proptest;
        use rand::Rng;

        #[test]
        fn should_be_empty_when_no_withdrawal_requests() {
            let transactions = EthTransactions::new(TransactionNonce::ZERO);
            assert_eq!(transactions.withdrawal_requests_batch(5), vec![]);
        }

        #[test]
        fn should_retrieve_the_first_withdrawal_requests() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            for i in 0..5 {
                let withdrawal_request =
                    cketh_withdrawal_request_with_index(LedgerBurnIndex::new(i));
                transactions.record_withdrawal_request(withdrawal_request);
            }

            let requests = transactions.withdrawal_requests_batch(0);
            assert_eq!(requests, vec![]);

            let requests = transactions.withdrawal_requests_batch(1);
            assert_eq!(
                only_eth_withdrawals(requests),
                vec![cketh_withdrawal_request_with_index(LedgerBurnIndex::new(0))]
            );

            let requests = transactions.withdrawal_requests_batch(2);
            assert_eq!(
                only_eth_withdrawals(requests),
                vec![
                    cketh_withdrawal_request_with_index(LedgerBurnIndex::new(0)),
                    cketh_withdrawal_request_with_index(LedgerBurnIndex::new(1)),
                ]
            );
        }

        proptest! {
            #[test]
            fn should_retrieve_all_withdrawal_requests_in_order(batch_size in 3..100_usize) {
                let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
                for i in 0..3 {
                    let withdrawal_request = cketh_withdrawal_request_with_index(LedgerBurnIndex::new(i));
                        transactions.record_withdrawal_request(withdrawal_request);
                }

                let requests = transactions.withdrawal_requests_batch(batch_size);

                assert_eq!(
                    only_eth_withdrawals(requests),
                    vec![
                        cketh_withdrawal_request_with_index(LedgerBurnIndex::new(0)),
                        cketh_withdrawal_request_with_index(LedgerBurnIndex::new(1)),
                        cketh_withdrawal_request_with_index(LedgerBurnIndex::new(2)),
                    ]
                );
            }
        }

        #[test]
        fn should_limit_batch_size_when_too_many_pending_transactions() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let mut rng = reproducible_rng();
            for i in 0..997 {
                let withdrawal_request = create_and_record_withdrawal_request(
                    &mut transactions,
                    LedgerBurnIndex::new(i),
                );
                create_and_record_pending_transaction(
                    &mut transactions,
                    withdrawal_request,
                    rng.gen(),
                );
            }
            for i in 997..1000 {
                create_and_record_withdrawal_request(&mut transactions, LedgerBurnIndex::new(i));
            }

            assert_eq!(
                only_eth_withdrawals(transactions.withdrawal_requests_batch(3)),
                vec![
                    cketh_withdrawal_request_with_index(LedgerBurnIndex::new(997)),
                    cketh_withdrawal_request_with_index(LedgerBurnIndex::new(998)),
                    cketh_withdrawal_request_with_index(LedgerBurnIndex::new(999)),
                ]
            );

            create_and_record_pending_transaction(
                &mut transactions,
                cketh_withdrawal_request_with_index(LedgerBurnIndex::new(997)),
                rng.gen(),
            );
            assert_eq!(
                only_eth_withdrawals(transactions.withdrawal_requests_batch(3)),
                vec![
                    cketh_withdrawal_request_with_index(LedgerBurnIndex::new(998)),
                    cketh_withdrawal_request_with_index(LedgerBurnIndex::new(999)),
                ]
            );

            create_and_record_pending_transaction(
                &mut transactions,
                cketh_withdrawal_request_with_index(LedgerBurnIndex::new(998)),
                rng.gen(),
            );
            assert_eq!(
                only_eth_withdrawals(transactions.withdrawal_requests_batch(3)),
                vec![cketh_withdrawal_request_with_index(LedgerBurnIndex::new(
                    999
                ))]
            );

            create_and_record_pending_transaction(
                &mut transactions,
                cketh_withdrawal_request_with_index(LedgerBurnIndex::new(999)),
                rng.gen(),
            );
            assert_eq!(transactions.withdrawal_requests_batch(3), vec![]);
        }

        fn create_and_record_pending_transaction(
            transactions: &mut EthTransactions,
            withdrawal_request: EthWithdrawalRequest,
            to_sign: bool,
        ) {
            let tx =
                create_and_record_transaction(transactions, withdrawal_request, gas_fee_estimate());
            if to_sign {
                create_and_record_signed_transaction(transactions, tx);
            }
        }
    }

    mod reschedule_withdrawal_request {
        use crate::numeric::{LedgerBurnIndex, TransactionNonce};
        use crate::state::transactions::tests::eth_transactions::cketh_withdrawal_request_with_index;
        use crate::state::transactions::tests::only_eth_withdrawals;
        use crate::state::transactions::EthTransactions;

        #[test]
        fn should_reschedule_withdrawal_request() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let first_request = cketh_withdrawal_request_with_index(LedgerBurnIndex::new(15));
            let second_request = cketh_withdrawal_request_with_index(LedgerBurnIndex::new(16));
            let third_request = cketh_withdrawal_request_with_index(LedgerBurnIndex::new(17));
            transactions.record_withdrawal_request(first_request.clone());
            transactions.record_withdrawal_request(second_request.clone());
            transactions.record_withdrawal_request(third_request.clone());

            // 3 -> 2 -> 1
            assert_eq!(
                only_eth_withdrawals(transactions.withdrawal_requests_batch(5)),
                vec![
                    first_request.clone(),
                    second_request.clone(),
                    third_request.clone(),
                ]
            );

            transactions.reschedule_withdrawal_request(first_request.clone());
            // 1 -> 3 -> 2
            assert_eq!(
                only_eth_withdrawals(transactions.withdrawal_requests_batch(5)),
                vec![
                    second_request.clone(),
                    third_request.clone(),
                    first_request.clone(),
                ]
            );

            transactions.reschedule_withdrawal_request(second_request.clone());
            // 2 -> 1 -> 3
            assert_eq!(
                only_eth_withdrawals(transactions.withdrawal_requests_batch(5)),
                vec![
                    third_request.clone(),
                    first_request.clone(),
                    second_request.clone(),
                ]
            );

            transactions.reschedule_withdrawal_request(third_request.clone());
            // 3 -> 2 -> 1
            assert_eq!(
                only_eth_withdrawals(transactions.withdrawal_requests_batch(5)),
                vec![first_request, second_request, third_request]
            );
        }
    }

    mod record_created_transaction {
        use crate::lifecycle::EthereumNetwork;
        use crate::numeric::{LedgerBurnIndex, TransactionNonce};
        use crate::state::transactions::tests::{
            cketh_withdrawal_request_with_index, cketh_withdrawal_tx_fee,
            create_and_record_transaction, gas_fee_estimate,
        };
        use crate::state::transactions::{create_transaction, EthTransactions};
        use crate::test_fixtures::expect_panic_with_message;
        use crate::tx::Eip1559TransactionRequest;
        use crate::withdraw::CKETH_WITHDRAWAL_TRANSACTION_GAS_LIMIT;
        use ic_ethereum_types::Address;
        use proptest::prelude::any;
        use proptest::{prop_assert_ne, proptest};

        #[test]
        fn should_fail_when_withdrawal_request_not_found() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let withdrawal_request = cketh_withdrawal_request_with_index(LedgerBurnIndex::new(15));
            let tx = create_transaction(
                &withdrawal_request.clone().into(),
                TransactionNonce::ZERO,
                cketh_withdrawal_tx_fee(),
                EthereumNetwork::Sepolia,
            )
            .unwrap();

            expect_panic_with_message(
                || {
                    transactions
                        .record_created_transaction(withdrawal_request.ledger_burn_index, tx)
                },
                "withdrawal request 15 not found",
            );
        }

        #[test]
        fn should_fail_when_mismatch_with_withdrawal_request() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let withdrawal_request = cketh_withdrawal_request_with_index(LedgerBurnIndex::new(15));
            transactions.record_withdrawal_request(withdrawal_request.clone());
            let correct_tx = create_transaction(
                &withdrawal_request.clone().into(),
                TransactionNonce::ZERO,
                cketh_withdrawal_tx_fee(),
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
                        withdrawal_request.ledger_burn_index,
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
                    transactions.record_created_transaction(
                        withdrawal_request.ledger_burn_index,
                        tx_with_wrong_amount,
                    )
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
                let withdrawal_request = cketh_withdrawal_request_with_index(LedgerBurnIndex::new(15));
                transactions.record_withdrawal_request(withdrawal_request.clone());
                let tx_with_wrong_nonce = create_transaction(
                    &withdrawal_request.clone().into(),
                    wrong_nonce,
                    cketh_withdrawal_tx_fee(),
                    EthereumNetwork::Sepolia,
                )
                .unwrap();

                expect_panic_with_message(
                    || transactions.record_created_transaction(withdrawal_request.ledger_burn_index, tx_with_wrong_nonce),
                    "nonce mismatch",
                );
            }
        }

        #[test]
        fn should_create_and_record_transaction() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let transaction_price = gas_fee_estimate();
            for i in 0..100_u64 {
                let ledger_burn_index = LedgerBurnIndex::new(15 + i);
                let withdrawal_request = cketh_withdrawal_request_with_index(ledger_burn_index);
                transactions.record_withdrawal_request(withdrawal_request.clone());
                let expected_tx_amount = withdrawal_request
                    .withdrawal_amount
                    .checked_sub(
                        transaction_price
                            .clone()
                            .to_price(CKETH_WITHDRAWAL_TRANSACTION_GAS_LIMIT)
                            .max_transaction_fee(),
                    )
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
                        gas_limit: CKETH_WITHDRAWAL_TRANSACTION_GAS_LIMIT,
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
            let withdrawal_request = cketh_withdrawal_request_with_index(LedgerBurnIndex::new(15));
            transactions.record_withdrawal_request(withdrawal_request.clone());

            let _created_tx = create_and_record_transaction(
                &mut transactions,
                withdrawal_request,
                gas_fee_estimate(),
            );

            assert_eq!(transactions.withdrawal_requests_batch(1), vec![]);
        }
    }

    mod record_signed_transaction {
        use super::super::arbitrary::arb_signed_eip_1559_transaction_request_with_nonce;
        use crate::numeric::{LedgerBurnIndex, TransactionNonce};
        use crate::state::transactions::tests::{
            create_and_record_transaction, create_and_record_withdrawal_request, gas_fee_estimate,
            sign_transaction, signed_transaction_with_nonce,
        };
        use crate::state::transactions::EthTransactions;
        use crate::test_fixtures::expect_panic_with_message;
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
                    gas_fee_estimate(),
                );
                let signed_tx = sign_transaction(created_tx);

                transactions.record_signed_transaction(signed_tx.clone());

                assert_eq!(transactions.transactions_to_sign_iter().next(), None);
                assert_eq!(
                    transactions.sent_tx.get_alt(&ledger_burn_index),
                    Some(&vec![signed_tx])
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
                    gas_fee_estimate(),
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
                gas_fee_estimate(),
            );
            let signed_tx = sign_transaction(created_tx);
            transactions.record_signed_transaction(signed_tx.clone());

            expect_panic_with_message(
                || transactions.record_signed_transaction(signed_tx),
                "missing created transaction",
            );
        }
    }

    mod create_resubmit_transactions {
        use crate::numeric::{LedgerBurnIndex, TransactionCount, TransactionNonce, Wei, WeiPerGas};
        use crate::state::transactions::tests::{
            cketh_withdrawal_request_with_index, create_and_record_signed_transaction,
            create_and_record_transaction, create_and_record_withdrawal_request, gas_fee_estimate,
        };
        use crate::state::transactions::EthTransactions;
        use crate::tx::{Eip1559TransactionRequest, TransactionPriceEstimate};

        #[test]
        fn should_be_empty_when_no_sent_transactions() {
            let transactions = EthTransactions::new(TransactionNonce::ZERO);
            let resubmitted_txs = transactions
                .create_resubmit_transactions(TransactionCount::ZERO, gas_fee_estimate());

            assert_eq!(resubmitted_txs, vec![]);
        }

        #[test]
        fn should_be_empty_when_all_sent_transactions_already_mined() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let initial_price = gas_fee_estimate();
            let higher_new_price = TransactionPriceEstimate {
                max_fee_per_gas: initial_price.max_fee_per_gas.checked_increment().unwrap(),
                ..initial_price
            };
            for num_tx in 0..100_u64 {
                let withdrawal_request =
                    cketh_withdrawal_request_with_index(LedgerBurnIndex::new(15 + num_tx));
                transactions.record_withdrawal_request(withdrawal_request.clone());
                let created_tx = create_and_record_transaction(
                    &mut transactions,
                    withdrawal_request,
                    initial_price.clone(),
                );
                let _signed_tx =
                    create_and_record_signed_transaction(&mut transactions, created_tx);

                let resubmitted_txs = transactions.create_resubmit_transactions(
                    TransactionCount::from(num_tx + 1),
                    higher_new_price.clone(),
                );

                assert_eq!(resubmitted_txs, vec![]);
            }
        }

        #[test]
        fn should_be_empty_when_new_price_not_higher() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let initial_price = gas_fee_estimate();
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
                let _signed_tx =
                    create_and_record_signed_transaction(&mut transactions, created_tx);
            }

            let resubmitted_txs = transactions
                .create_resubmit_transactions(TransactionCount::from(10_u8), initial_price.clone());

            assert_eq!(resubmitted_txs, vec![]);
        }

        #[test]
        fn should_resubmit_transaction_with_updated_price() {
            let price_at_tx_creation = TransactionPriceEstimate {
                max_fee_per_gas: WeiPerGas::from(11_u8),
                max_priority_fee_per_gas: WeiPerGas::from(21_u8),
            };
            let tests = vec![
                ParameterizedTest {
                    price_at_tx_creation: price_at_tx_creation.clone(),
                    price_at_tx_resubmission: TransactionPriceEstimate {
                        max_fee_per_gas: price_at_tx_creation
                            .max_fee_per_gas
                            .checked_increment()
                            .unwrap(),
                        ..price_at_tx_creation.clone()
                    },
                    resubmitted_tx_max_fee_per_gas: WeiPerGas::from(13_u8), //10% increase of 11 rounded up
                    resubmitted_tx_max_priority_fee_per_gas: WeiPerGas::from(24_u8), //10% increase of 21 rounded up
                    resubmitted_tx_amount_deduction: Wei::from(2 * 21_000_u32), //The increase in max_fee_per_gas is 2, so with a gas limit of 21_000, the amount should be decreased by 42_000
                },
                ParameterizedTest {
                    price_at_tx_creation: price_at_tx_creation.clone(),
                    price_at_tx_resubmission: TransactionPriceEstimate {
                        max_fee_per_gas: price_at_tx_creation
                            .max_fee_per_gas
                            .checked_mul(2_u8)
                            .unwrap(),
                        ..price_at_tx_creation.clone()
                    },
                    resubmitted_tx_max_fee_per_gas: WeiPerGas::from(22_u8), //new price because higher than 10% bump
                    resubmitted_tx_max_priority_fee_per_gas: WeiPerGas::from(24_u8), //10% increase of 21 rounded up
                    resubmitted_tx_amount_deduction: Wei::from(11 * 21_000_u32),
                },
                ParameterizedTest {
                    price_at_tx_creation: price_at_tx_creation.clone(),
                    price_at_tx_resubmission: TransactionPriceEstimate {
                        max_fee_per_gas: price_at_tx_creation
                            .max_fee_per_gas
                            .checked_mul(2_u8)
                            .unwrap(),
                        max_priority_fee_per_gas: price_at_tx_creation
                            .max_priority_fee_per_gas
                            .checked_mul(2_u8)
                            .unwrap(),
                    },
                    resubmitted_tx_max_fee_per_gas: WeiPerGas::from(22_u8), //new price because higher than 10% bump
                    resubmitted_tx_max_priority_fee_per_gas: WeiPerGas::from(42_u8), //new price because higher than 10% bump
                    resubmitted_tx_amount_deduction: Wei::from(11 * 21_000_u32),
                },
            ];

            for test in tests {
                let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
                let ledger_burn_index = LedgerBurnIndex::new(15);
                let withdrawal_request = cketh_withdrawal_request_with_index(ledger_burn_index);
                transactions.record_withdrawal_request(withdrawal_request.clone());
                let initial_tx = create_and_record_transaction(
                    &mut transactions,
                    withdrawal_request,
                    test.price_at_tx_creation.clone(),
                );
                let _signed_tx =
                    create_and_record_signed_transaction(&mut transactions, initial_tx.clone());

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
                    vec![Ok((ledger_burn_index, expected_resubmitted_tx))]
                );
            }
        }

        #[test]
        fn should_resubmit_multiple_transactions() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let initial_price = TransactionPriceEstimate {
                max_fee_per_gas: WeiPerGas::from(11_u8),
                max_priority_fee_per_gas: WeiPerGas::from(21_u8),
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
                let _signed_tx =
                    create_and_record_signed_transaction(&mut transactions, created_tx);
            }
            let higher_price = TransactionPriceEstimate {
                max_fee_per_gas: initial_price.max_fee_per_gas.checked_increment().unwrap(),
                ..initial_price
            };

            let resubmitted_txs = transactions
                .create_resubmit_transactions(TransactionCount::from(30_u8), higher_price.clone());
            assert_eq!(resubmitted_txs.len(), 70);
            for (i, (withdrawal_id, resubmitted_tx)) in resubmitted_txs
                .into_iter()
                .map(|res| res.unwrap())
                .enumerate()
            {
                let initial_transaction =
                    transactions.sent_tx.get_alt(&withdrawal_id).unwrap()[0].transaction();
                assert_eq!(
                    resubmitted_tx,
                    Eip1559TransactionRequest {
                        nonce: TransactionNonce::from(30_u8 + i as u8),
                        max_fee_per_gas: WeiPerGas::from(13_u8),
                        max_priority_fee_per_gas: WeiPerGas::from(24_u8),
                        amount: initial_transaction
                            .amount
                            .checked_sub(Wei::from(2 * 21_000_u32))
                            .unwrap(),
                        ..initial_transaction.clone()
                    }
                );
            }
        }

        struct ParameterizedTest {
            price_at_tx_creation: TransactionPriceEstimate,
            price_at_tx_resubmission: TransactionPriceEstimate,
            resubmitted_tx_max_fee_per_gas: WeiPerGas,
            resubmitted_tx_max_priority_fee_per_gas: WeiPerGas,
            resubmitted_tx_amount_deduction: Wei,
        }
    }

    mod record_resubmit_transaction {
        use super::super::arbitrary::arb_signed_eip_1559_transaction_request_with_nonce;
        use crate::map::MultiKeyMap;
        use crate::numeric::{LedgerBurnIndex, TransactionCount, TransactionNonce, Wei, WeiPerGas};
        use crate::state::transactions::tests::{
            create_and_record_signed_transaction, create_and_record_transaction,
            create_and_record_withdrawal_request, gas_fee_estimate, sign_transaction,
        };
        use crate::state::transactions::{equal_ignoring_fee_and_amount, EthTransactions};
        use crate::test_fixtures::expect_panic_with_message;
        use crate::tx::{Eip1559TransactionRequest, TransactionPriceEstimate};
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
                gas_fee_estimate(),
            );

            expect_panic_with_message(
                || transactions.record_resubmit_transaction(created_tx),
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
                gas_fee_estimate(),
            );
            let first_sent_tx =
                create_and_record_signed_transaction(&mut transactions, created_tx.clone());

            let transaction_with_increasing_fees: Vec<_> = iter::repeat(created_tx)
                .take(10)
                .enumerate()
                .map(|(index, mut tx)| {
                    tx.max_priority_fee_per_gas = tx
                        .max_priority_fee_per_gas
                        .checked_add(WeiPerGas::from(index as u8))
                        .unwrap();
                    tx.amount = tx.amount.checked_sub(Wei::from(index as u8)).unwrap();
                    tx
                })
                .collect();

            for (index, transaction) in transaction_with_increasing_fees.iter().enumerate() {
                transactions.record_resubmit_transaction(transaction.clone());
                let signed_tx = sign_transaction(transaction.clone());
                transactions.record_signed_transaction(signed_tx.clone());
                assert_eq!(transactions.transactions_to_sign_iter().next(), None);
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
                    gas_fee_estimate(),
                );
                let _signed_tx =
                    create_and_record_signed_transaction(&mut transactions, created_tx.clone());
                prop_assume!(!equal_ignoring_fee_and_amount(&created_tx, wrong_resent_tx.transaction()));

                expect_panic_with_message(
                    || {
                        transactions
                            .record_resubmit_transaction(wrong_resent_tx.transaction().clone())
                    },
                    "mismatch between last sent transaction",
                );
            }
        }

        #[test]
        fn should_replace_existing_resubmitted_transaction() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let initial_price = TransactionPriceEstimate {
                max_fee_per_gas: WeiPerGas::from(11_u8),
                max_priority_fee_per_gas: WeiPerGas::from(21_u8),
            };
            let resubmit_price_1 = TransactionPriceEstimate {
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
            let _signed_tx =
                create_and_record_signed_transaction(&mut transactions, created_tx.clone());

            let resubmitted_txs_1 = transactions
                .create_resubmit_transactions(TransactionCount::ZERO, resubmit_price_1.clone());
            let resubmitted_tx1 = Eip1559TransactionRequest {
                max_fee_per_gas: WeiPerGas::from(13_u8),
                max_priority_fee_per_gas: WeiPerGas::from(24_u8),
                amount: created_tx
                    .amount
                    .checked_sub(Wei::from(2 * 21_000_u32))
                    .unwrap(),
                ..created_tx.clone()
            };
            let expected_resubmitted_tx1 = resubmitted_tx1.clone();
            assert_eq!(
                resubmitted_txs_1,
                vec![Ok((ledger_burn_index, expected_resubmitted_tx1.clone()))]
            );
            transactions.record_resubmit_transaction(expected_resubmitted_tx1);
            assert_eq!(
                transactions.transactions_to_sign_iter().collect::<Vec<_>>(),
                vec![(
                    &TransactionNonce::ZERO,
                    &ledger_burn_index,
                    &resubmitted_tx1
                )]
            );

            let resubmit_price_2 = TransactionPriceEstimate {
                max_fee_per_gas: initial_price.max_fee_per_gas.checked_mul(2_u8).unwrap(),
                ..resubmit_price_1
            };
            let resubmitted_txs_2 =
                transactions.create_resubmit_transactions(TransactionCount::ZERO, resubmit_price_2);
            let resubmitted_tx2 = Eip1559TransactionRequest {
                max_fee_per_gas: WeiPerGas::from(22_u8),
                max_priority_fee_per_gas: WeiPerGas::from(24_u8),
                amount: created_tx
                    .amount
                    .checked_sub(Wei::from(11 * 21_000_u32))
                    .unwrap(),
                ..created_tx
            };
            let expected_resubmitted_tx2 = resubmitted_tx2.clone();
            assert_eq!(
                resubmitted_txs_2,
                vec![Ok((ledger_burn_index, expected_resubmitted_tx2.clone()))]
            );
            transactions.record_resubmit_transaction(expected_resubmitted_tx2);
            assert_eq!(
                transactions.transactions_to_sign_iter().collect::<Vec<_>>(),
                vec![(
                    &TransactionNonce::ZERO,
                    &ledger_burn_index,
                    &resubmitted_tx2
                )]
            );
        }
    }

    mod transactions_to_send_batch {
        use crate::numeric::{LedgerBurnIndex, TransactionCount, TransactionNonce};
        use crate::state::transactions::tests::arbitrary::arb_checked_amount_of;
        use crate::state::transactions::tests::{
            create_and_record_signed_transaction, create_and_record_transaction,
            create_and_record_withdrawal_request, gas_fee_estimate,
            resubmit_transaction_with_bumped_price,
        };
        use crate::state::transactions::EthTransactions;
        use proptest::proptest;

        proptest! {
            #[test]
            fn should_be_empty_when_no_transactions_to_send(latest_tx_count in arb_checked_amount_of()) {
                let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
                assert_transactions_to_send_iter_is_empty(&transactions, latest_tx_count);

                let ledger_burn_index = LedgerBurnIndex::new(15);
                let withdrawal_request =
                    create_and_record_withdrawal_request(&mut transactions, ledger_burn_index);
                assert_transactions_to_send_iter_is_empty(&transactions, latest_tx_count);

                let _created_tx = create_and_record_transaction(
                    &mut transactions,
                    withdrawal_request,
                    gas_fee_estimate(),
                );
                assert_transactions_to_send_iter_is_empty(&transactions, latest_tx_count);
            }
        }

        #[test]
        fn should_contain_only_last_transactions() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let first_ledger_burn_index = LedgerBurnIndex::new(15);
            let first_withdrawal_request =
                create_and_record_withdrawal_request(&mut transactions, first_ledger_burn_index);
            let first_created_tx = create_and_record_transaction(
                &mut transactions,
                first_withdrawal_request,
                gas_fee_estimate(),
            );
            let first_tx =
                create_and_record_signed_transaction(&mut transactions, first_created_tx.clone());
            let last_first_tx =
                resubmit_transaction_with_bumped_price(&mut transactions, first_created_tx.clone());

            let second_ledger_burn_index = LedgerBurnIndex::new(16);
            let second_withdrawal_request =
                create_and_record_withdrawal_request(&mut transactions, second_ledger_burn_index);
            let second_created_tx = create_and_record_transaction(
                &mut transactions,
                second_withdrawal_request,
                gas_fee_estimate(),
            );
            let second_tx =
                create_and_record_signed_transaction(&mut transactions, second_created_tx.clone());
            assert_eq!(
                vec![
                    (
                        &TransactionNonce::ZERO,
                        &first_ledger_burn_index,
                        &vec![first_tx, last_first_tx.clone()]
                    ),
                    (
                        &TransactionNonce::ONE,
                        &second_ledger_burn_index,
                        &vec![second_tx.clone()]
                    ),
                ],
                transactions.sent_transactions_iter().collect::<Vec<_>>()
            );

            assert_eq!(
                transactions.transactions_to_send_batch(TransactionCount::ZERO, usize::MAX),
                vec![last_first_tx, second_tx.clone()]
            );

            assert_eq!(
                transactions.transactions_to_send_batch(TransactionCount::ONE, usize::MAX),
                vec![second_tx]
            );

            assert_transactions_to_send_iter_is_empty(&transactions, TransactionCount::TWO);
        }

        fn assert_transactions_to_send_iter_is_empty(
            transactions: &EthTransactions,
            latest_tx_count: TransactionCount,
        ) {
            assert_eq!(
                transactions.transactions_to_send_batch(latest_tx_count, usize::MAX),
                vec![]
            );
        }
    }

    mod sent_transactions_to_finalize {
        use super::super::{
            arbitrary::arb_checked_amount_of, create_and_record_transaction,
            create_and_record_withdrawal_request, gas_fee_estimate,
        };
        use crate::numeric::{TransactionCount, TransactionNonce};
        use crate::state::transactions::tests::{
            create_and_record_signed_transaction, resubmit_transaction_with_bumped_price,
        };
        use crate::state::transactions::{EthTransactions, LedgerBurnIndex};
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

                let _created_tx = create_and_record_transaction(
                    &mut transactions,
                    withdrawal_request,
                    gas_fee_estimate(),
                );
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
                    gas_fee_estimate(),
                );
                create_and_record_signed_transaction(transactions, created_tx.clone())
            }

            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);

            let withdrawal_id_15 = LedgerBurnIndex::new(15);
            let sent_tx_0_0 = send_transaction(&mut transactions, withdrawal_id_15);
            assert_eq!(sent_tx_0_0.nonce(), TransactionNonce::ZERO);
            let sent_tx_0_1 = resubmit_transaction_with_bumped_price(
                &mut transactions,
                sent_tx_0_0.transaction().clone(),
            );
            let hashes_0: BTreeMap<_, _> = vec![sent_tx_0_0, sent_tx_0_1]
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
            let hashes_1: BTreeMap<_, _> = vec![sent_tx_1_0, sent_tx_1_1, sent_tx_1_2]
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
        use crate::numeric::{LedgerBurnIndex, TransactionNonce, Wei};
        use crate::state::transactions::tests::{
            cketh_withdrawal_request_with_index, create_and_record_signed_transaction,
            create_and_record_transaction, create_and_record_withdrawal_request, dummy_signature,
            gas_fee_estimate, transaction_receipt, DEFAULT_CREATED_AT, DEFAULT_PRINCIPAL,
            DEFAULT_RECIPIENT_ADDRESS, DEFAULT_SUBACCOUNT, DEFAULT_WITHDRAWAL_AMOUNT,
        };
        use crate::state::transactions::{
            Address, EthTransactions, EthWithdrawalRequest, ReimbursementRequest, Subaccount,
            TransactionStatus,
        };
        use crate::test_fixtures::expect_panic_with_message;
        use crate::tx::SignedEip1559TransactionRequest;
        use std::str::FromStr;

        #[test]
        fn should_fail_when_sent_transaction_not_found() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let ledger_burn_index = LedgerBurnIndex::new(15);
            let withdrawal_request = cketh_withdrawal_request_with_index(ledger_burn_index);
            transactions.record_withdrawal_request(withdrawal_request.clone());
            let created_tx = create_and_record_transaction(
                &mut transactions,
                withdrawal_request,
                gas_fee_estimate(),
            );
            let signed_tx =
                create_and_record_signed_transaction(&mut transactions, created_tx.clone());

            expect_panic_with_message(
                || {
                    transactions.record_finalized_transaction(
                        LedgerBurnIndex::new(16),
                        transaction_receipt(&signed_tx, TransactionStatus::Success),
                    )
                },
                "missing sent transaction",
            );

            let receipt_with_wrong_hash = {
                let mut wrong_signature = dummy_signature();
                wrong_signature.signature_y_parity = true;
                transaction_receipt(
                    &SignedEip1559TransactionRequest::from((created_tx, wrong_signature)),
                    TransactionStatus::Success,
                )
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
        fn should_record_finalized_transaction_and_not_reimburse() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let ledger_burn_index = LedgerBurnIndex::new(15);
            let withdrawal_request =
                create_and_record_withdrawal_request(&mut transactions, ledger_burn_index);
            let created_tx = create_and_record_transaction(
                &mut transactions,
                withdrawal_request,
                gas_fee_estimate(),
            );
            let signed_tx = create_and_record_signed_transaction(&mut transactions, created_tx);
            let maybe_reimburse_request = transactions
                .maybe_reimburse
                .get(&ledger_burn_index)
                .expect("maybe reimburse request not found");
            assert_eq!(
                maybe_reimburse_request,
                &EthWithdrawalRequest {
                    withdrawal_amount: Wei::new(DEFAULT_WITHDRAWAL_AMOUNT),
                    destination: Address::from_str(DEFAULT_RECIPIENT_ADDRESS).unwrap(),
                    ledger_burn_index,
                    from: candid::Principal::from_str(DEFAULT_PRINCIPAL,).unwrap(),
                    from_subaccount: Some(Subaccount(DEFAULT_SUBACCOUNT)),
                    created_at: Some(DEFAULT_CREATED_AT),
                }
                .into()
            );
            assert!(!transactions.maybe_reimburse.is_empty());

            let receipt = transaction_receipt(&signed_tx, TransactionStatus::Success);
            transactions.record_finalized_transaction(ledger_burn_index, receipt.clone());

            assert!(transactions.maybe_reimburse.is_empty());
            assert!(transactions.reimbursement_requests.is_empty());
        }

        #[test]
        fn should_record_finalized_transaction_and_reimburse() {
            use crate::numeric::Wei;
            use crate::state::transactions::Subaccount;

            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let ledger_burn_index = LedgerBurnIndex::new(15);
            let withdrawal_request =
                create_and_record_withdrawal_request(&mut transactions, ledger_burn_index);
            let created_tx = create_and_record_transaction(
                &mut transactions,
                withdrawal_request,
                gas_fee_estimate(),
            );
            let signed_tx = create_and_record_signed_transaction(&mut transactions, created_tx);
            let maybe_reimburse_request = transactions
                .maybe_reimburse
                .get(&ledger_burn_index)
                .expect("maybe reimburse request not found");
            assert_eq!(
                maybe_reimburse_request,
                &EthWithdrawalRequest {
                    withdrawal_amount: Wei::new(DEFAULT_WITHDRAWAL_AMOUNT),
                    destination: Address::from_str(DEFAULT_RECIPIENT_ADDRESS).unwrap(),
                    ledger_burn_index,
                    from: candid::Principal::from_str(DEFAULT_PRINCIPAL).unwrap(),
                    from_subaccount: Some(Subaccount(DEFAULT_SUBACCOUNT)),
                    created_at: Some(DEFAULT_CREATED_AT),
                }
                .into()
            );

            let receipt = transaction_receipt(&signed_tx, TransactionStatus::Failure);
            transactions.record_finalized_transaction(ledger_burn_index, receipt.clone());

            let finalized_transaction = transactions
                .finalized_tx
                .get_alt(&ledger_burn_index)
                .expect("finalized tx not found");

            assert!(transactions.maybe_reimburse.is_empty());
            let reimbursement_request = transactions
                .reimbursement_requests
                .get(&ledger_burn_index)
                .expect("reimbursement request not found");
            assert_eq!(
                reimbursement_request,
                &ReimbursementRequest {
                    transaction_hash: Some(receipt.transaction_hash),
                    withdrawal_id: ledger_burn_index,
                    to: candid::Principal::from_str(DEFAULT_PRINCIPAL).unwrap(),
                    to_subaccount: Some(Subaccount(DEFAULT_SUBACCOUNT)),
                    reimbursed_amount: *finalized_transaction.transaction_amount(),
                }
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
                gas_fee_estimate(),
            );
            let signed_tx = create_and_record_signed_transaction(&mut transactions, created_tx);

            let receipt = transaction_receipt(&signed_tx, TransactionStatus::Success);
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
            assert_eq!(transactions.transactions_to_sign_iter().next(), None);
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
                gas_fee_estimate(),
            );
            let signed_tx =
                create_and_record_signed_transaction(&mut transactions, created_tx.clone());
            transactions.record_resubmit_transaction(created_tx.clone());
            assert!(transactions.created_tx.contains_alt(&ledger_burn_index));

            let receipt = transaction_receipt(&signed_tx, TransactionStatus::Success);
            transactions.record_finalized_transaction(ledger_burn_index, receipt.clone());

            assert_eq!(
                transactions.finalized_tx,
                MultiKeyMap::from_iter(vec![(
                    TransactionNonce::ZERO,
                    ledger_burn_index,
                    signed_tx.try_finalize(receipt).unwrap()
                )])
            );
            assert_eq!(transactions.transactions_to_sign_iter().next(), None);
            assert_eq!(transactions.sent_transactions_iter().next(), None);
        }
    }

    mod transaction_status {
        use crate::endpoints::{EthTransaction, RetrieveEthStatus, TxFinalizedStatus};
        use crate::numeric::{LedgerBurnIndex, LedgerMintIndex, TransactionNonce, Wei};
        use crate::state::transactions::tests::DEFAULT_WITHDRAWAL_AMOUNT;
        use crate::state::transactions::tests::{
            cketh_withdrawal_request_with_index, create_and_record_transaction, gas_fee_estimate,
            sign_transaction, transaction_receipt,
        };
        use crate::state::transactions::{EthTransactions, TransactionStatus};

        #[test]
        fn should_withdrawal_flow_succeed_with_correct_status() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let ledger_burn_index = LedgerBurnIndex::new(15);
            let withdrawal_request = cketh_withdrawal_request_with_index(ledger_burn_index);

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
                gas_fee_estimate(),
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
                RetrieveEthStatus::TxSent(eth_transaction.clone())
            );

            transactions.record_finalized_transaction(
                ledger_burn_index,
                transaction_receipt(&signed_tx, TransactionStatus::Success),
            );
            assert_eq!(
                transactions.transaction_status(&ledger_burn_index),
                RetrieveEthStatus::TxFinalized(TxFinalizedStatus::Success(eth_transaction))
            );
        }

        #[test]
        fn should_withdrawal_flow_succeed_with_reimbursed_status() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let ledger_burn_index = LedgerBurnIndex::new(15);
            let withdrawal_request = cketh_withdrawal_request_with_index(ledger_burn_index);

            transactions.record_withdrawal_request(withdrawal_request.clone());

            let created_tx = create_and_record_transaction(
                &mut transactions,
                withdrawal_request,
                gas_fee_estimate(),
            );

            let signed_tx = sign_transaction(created_tx);
            let eth_transaction = EthTransaction {
                transaction_hash: signed_tx.hash().to_string(),
            };
            transactions.record_signed_transaction(signed_tx.clone());

            transactions.record_finalized_transaction(
                ledger_burn_index,
                transaction_receipt(&signed_tx, TransactionStatus::Failure),
            );
            assert_eq!(
                transactions.transaction_status(&ledger_burn_index),
                RetrieveEthStatus::TxFinalized(TxFinalizedStatus::PendingReimbursement(
                    eth_transaction.clone()
                ))
            );

            transactions
                .record_finalized_reimbursement(ledger_burn_index, LedgerMintIndex::new(16));

            let finalized_transaction = transactions
                .finalized_tx
                .get_alt(&ledger_burn_index)
                .expect("finalized tx not found");

            let effective_fee_paid = finalized_transaction.effective_transaction_fee();

            assert_eq!(
                transactions.transaction_status(&ledger_burn_index),
                RetrieveEthStatus::TxFinalized(TxFinalizedStatus::Reimbursed {
                    reimbursed_in_block: candid::Nat::from(16_u8),
                    transaction_hash: signed_tx.hash().to_string(),
                    reimbursed_amount: Wei::new(DEFAULT_WITHDRAWAL_AMOUNT)
                        .checked_sub(effective_fee_paid)
                        .unwrap()
                        .into(),
                })
            );
        }
    }
}

mod oldest_incomplete_withdrawal_timestamp {
    use super::*;

    #[test]
    fn should_return_none_when_no_requests() {
        let transactions = EthTransactions::new(TransactionNonce::ZERO);
        assert_eq!(None, transactions.oldest_incomplete_withdrawal_timestamp());
    }

    #[test]
    fn should_return_created_at_of_one_request() {
        let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
        let withdrawal_request = cketh_withdrawal_request_with_index(LedgerBurnIndex::new(15));
        transactions.record_withdrawal_request(withdrawal_request.clone());

        assert_eq!(
            transactions.oldest_incomplete_withdrawal_timestamp(),
            withdrawal_request.created_at,
        );
    }

    #[test]
    fn should_return_the_min_of_two_requests() {
        let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
        transactions.record_withdrawal_request(EthWithdrawalRequest {
            created_at: Some(10),
            ..cketh_withdrawal_request_with_index(LedgerBurnIndex::new(15))
        });
        transactions.record_withdrawal_request(EthWithdrawalRequest {
            created_at: Some(20),
            ..cketh_withdrawal_request_with_index(LedgerBurnIndex::new(16))
        });

        assert_eq!(
            transactions.oldest_incomplete_withdrawal_timestamp(),
            Some(10),
        );
    }

    #[test]
    fn should_work_for_requests_with_transactions() {
        let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
        let withdrawal_request = cketh_withdrawal_request_with_index(LedgerBurnIndex::new(15));
        transactions.record_withdrawal_request(withdrawal_request.clone());
        create_and_record_transaction(&mut transactions, withdrawal_request, gas_fee_estimate());

        assert_eq!(
            transactions.oldest_incomplete_withdrawal_timestamp(),
            Some(DEFAULT_CREATED_AT),
        );
    }

    #[test]
    fn should_return_the_min_of_requests_in_all_states() {
        let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
        let first_request = EthWithdrawalRequest {
            created_at: Some(10),
            ..cketh_withdrawal_request_with_index(LedgerBurnIndex::new(15))
        };
        transactions.record_withdrawal_request(first_request.clone());
        transactions.record_withdrawal_request(EthWithdrawalRequest {
            created_at: Some(20),
            ..cketh_withdrawal_request_with_index(LedgerBurnIndex::new(16))
        });
        create_and_record_transaction(&mut transactions, first_request, gas_fee_estimate());

        assert_eq!(
            transactions.oldest_incomplete_withdrawal_timestamp(),
            Some(10),
        );
    }

    #[test]
    fn should_ignore_finalized_requests() {
        let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
        let index = LedgerBurnIndex::new(15);
        let withdrawal_request = cketh_withdrawal_request_with_index(index);
        transactions.record_withdrawal_request(withdrawal_request.clone());
        let created_tx = create_and_record_transaction(
            &mut transactions,
            withdrawal_request,
            gas_fee_estimate(),
        );
        let signed_tx = create_and_record_signed_transaction(&mut transactions, created_tx);
        transactions.record_finalized_transaction(
            index,
            transaction_receipt(&signed_tx, TransactionStatus::Success),
        );

        assert_eq!(transactions.oldest_incomplete_withdrawal_timestamp(), None);
    }
}

mod eth_withdrawal_request {
    use crate::numeric::LedgerBurnIndex;
    use crate::state::transactions::tests::cketh_withdrawal_request_with_index;

    #[test]
    fn should_have_readable_debug_representation() {
        let request = cketh_withdrawal_request_with_index(LedgerBurnIndex::new(131));
        let expected_debug = "EthWithdrawalRequest { withdrawal_amount: 1_100_000_000_000_000, destination: 0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34, ledger_burn_index: 131, from: k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae, from_subaccount: Some(1111111111111111111111111111111111111111111111111111111111111111), created_at: Some(1699527697000000000) }";
        assert_eq!(format!("{:?}", request), expected_debug);
    }
}

mod erc_20_withdrawal_request {
    use crate::numeric::LedgerBurnIndex;
    use crate::state::transactions::tests::ckerc20_withdrawal_request_with_index;

    #[test]
    fn should_have_readable_debug_representation() {
        let request = ckerc20_withdrawal_request_with_index(
            LedgerBurnIndex::new(131),
            LedgerBurnIndex::new(2),
        );
        let expected_debug = "Erc20WithdrawalRequest { max_transaction_fee: 30_000_000_000_000_000, withdrawal_amount: 1_100_000_000_000_000, erc20_contract_address: 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48, destination: 0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34, cketh_ledger_burn_index: 131, ckerc20_ledger_burn_index: 2, from: k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae, from_subaccount: Some(1111111111111111111111111111111111111111111111111111111111111111), created_at: 1699527697000000000 }";
        assert_eq!(format!("{:?}", request), expected_debug);
    }
}

mod create_transaction {
    use crate::lifecycle::EthereumNetwork;
    use crate::numeric::{
        Erc20Value, GasAmount, LedgerBurnIndex, TransactionNonce, Wei, WeiPerGas,
    };
    use crate::state::transactions::tests::{
        ckerc20_withdrawal_request_with_index, cketh_withdrawal_request_with_index,
        cketh_withdrawal_tx_fee,
    };
    use crate::state::transactions::{
        create_transaction, CreateTransactionError, Erc20WithdrawalRequest, EthWithdrawalRequest,
    };
    use crate::tx::TransactionPrice;
    use crate::tx::{AccessList, Eip1559TransactionRequest};
    use crate::withdraw::CKETH_WITHDRAWAL_TRANSACTION_GAS_LIMIT;
    use proptest::prelude::any;
    use proptest::{prop_assert_eq, proptest};

    proptest! {
        #[test]
        fn should_fail_when_amount_does_not_cover_transaction_fees(withdrawal_amount in any::<u64>()) {
            let transaction_price = cketh_withdrawal_tx_fee();
            let actual_max_transaction_fee = transaction_price.max_transaction_fee();
            let insufficient_amount = Wei::from(withdrawal_amount % (actual_max_transaction_fee.as_f64() as u64));
            let cketh_ledger_burn_index = LedgerBurnIndex::new(15);

            let cketh_withdrawal_request = EthWithdrawalRequest {
                withdrawal_amount: insufficient_amount,
                ..cketh_withdrawal_request_with_index(cketh_ledger_burn_index)
            };
            let result = create_transaction(
                &cketh_withdrawal_request.clone().into(),
                TransactionNonce::TWO,
                transaction_price.clone(),
                EthereumNetwork::Sepolia,
            );
            prop_assert_eq!(
                result,
                Err(CreateTransactionError::InsufficientTransactionFee {
                    cketh_ledger_burn_index,
                    allowed_max_transaction_fee: cketh_withdrawal_request.withdrawal_amount,
                    actual_max_transaction_fee,
                })
            );

            let ckerc20_withdrawal_request = Erc20WithdrawalRequest {
                max_transaction_fee: insufficient_amount,
                ..ckerc20_withdrawal_request_with_index(cketh_ledger_burn_index, LedgerBurnIndex::new(2))
            };
            let result = create_transaction(
                &ckerc20_withdrawal_request.clone().into(),
                TransactionNonce::TWO,
                transaction_price,
                EthereumNetwork::Sepolia,
            );
            prop_assert_eq!(
                result,
                Err(CreateTransactionError::InsufficientTransactionFee {
                    cketh_ledger_burn_index,
                    allowed_max_transaction_fee: ckerc20_withdrawal_request.max_transaction_fee,
                    actual_max_transaction_fee,
                })
            )
        }
    }

    proptest! {
        #[test]
        fn should_create_transaction(withdrawal_amount in 31_500_001_050_000_u64..=u64::MAX) {
            let transaction_price = cketh_withdrawal_tx_fee();
            let max_transaction_fee = transaction_price.max_transaction_fee();
            let ledger_burn_index = LedgerBurnIndex::new(15);
            let withdrawal_amount = Wei::from(withdrawal_amount);
            let withdrawal_request = EthWithdrawalRequest {
                withdrawal_amount,
                ..cketh_withdrawal_request_with_index(ledger_burn_index)
            };
            prop_assert_eq!(
                max_transaction_fee,
                Wei::from(31_500_001_050_000_u64)
            );

            let result = create_transaction(
                &withdrawal_request.clone().into(),
                TransactionNonce::TWO,
                transaction_price.clone(),
                EthereumNetwork::Sepolia,
            );

            prop_assert_eq!(result, Ok(Eip1559TransactionRequest {
                chain_id: EthereumNetwork::Sepolia.chain_id(),
                nonce: TransactionNonce::TWO,
                max_priority_fee_per_gas: transaction_price.max_priority_fee_per_gas,
                max_fee_per_gas: transaction_price.max_fee_per_gas,
                gas_limit: CKETH_WITHDRAWAL_TRANSACTION_GAS_LIMIT,
                destination: withdrawal_request.destination,
                amount: withdrawal_amount.checked_sub(max_transaction_fee).unwrap(),
                data: vec![],
                access_list: AccessList::new()
            }))
        }
    }

    proptest! {
        #[test]
        fn should_create_ckerc20_withdrawal_transaction(max_transaction_fee in 4_938_808_337_538_008_808_u128..=u128::MAX) {
            // Example of a USDC transfer
            // https://etherscan.io/tx/0x295846b122356aebb2d426ffdc2510c2f5eecbf5fc359fb24bba8a7ab5fa8616
            let transaction_price = TransactionPrice {
                gas_limit: GasAmount::from(0x93348_u64),
                max_fee_per_gas: WeiPerGas::from(0x77320769855_u64),
                max_priority_fee_per_gas: WeiPerGas::from(0x50000000_u64),
            };
            prop_assert_eq!(
                transaction_price.max_transaction_fee(),
                Wei::from(4_938_808_337_538_008_808_u128)
            );
            let cketh_ledger_burn_index = LedgerBurnIndex::new(15);
            let ckerc20_ledger_burn_index = LedgerBurnIndex::new(2);
            let withdrawal_request = Erc20WithdrawalRequest {
                max_transaction_fee: Wei::from(max_transaction_fee),
                withdrawal_amount: Erc20Value::from(0x204123f_u64), //33.821247 USDC
                destination: "0x6b9353bf4f90abdb218979b7596fafc3c6c6ac64"
                    .parse()
                    .unwrap(),
                erc20_contract_address: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
                    .parse()
                    .unwrap(),
                ..ckerc20_withdrawal_request_with_index(
                    cketh_ledger_burn_index,
                    ckerc20_ledger_burn_index,
                )
            };

            let result = create_transaction(
                &withdrawal_request.clone().into(),
                TransactionNonce::from(0x57_u32),
                transaction_price.clone(),
                EthereumNetwork::Mainnet,
            );

            prop_assert_eq!(result, Ok(Eip1559TransactionRequest {
                    chain_id: EthereumNetwork::Mainnet.chain_id(),
                    nonce: TransactionNonce::from(0x57_u32),
                    max_priority_fee_per_gas: transaction_price.max_priority_fee_per_gas,
                    max_fee_per_gas: transaction_price.max_fee_per_gas,
                    gas_limit: transaction_price.gas_limit,
                    destination: withdrawal_request.erc20_contract_address,
                    amount: Wei::ZERO,
                    data: hex::decode("a9059cbb0000000000000000000000006b9353bf4f90abdb218979b7596fafc3c6c6ac64000000000000000000000000000000000000000000000000000000000204123f").unwrap(),
                    access_list: AccessList::new()
                }))
        }
    }
}

mod withdrawal_flow {
    use super::arbitrary::{arb_checked_amount_of, arb_gas_fee_estimate, arb_withdrawal_request};
    use crate::numeric::TransactionNonce;
    use crate::state::transactions::tests::sign_transaction;
    use crate::state::transactions::{create_transaction, EthTransactions, EthereumNetwork};
    use crate::withdraw::estimate_gas_limit;
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

        proptest!(|(gas_fee_estimate in arb_gas_fee_estimate(), transaction_count in arb_checked_amount_of())| {
            let resubmit_txs = wrapped_txs.borrow().create_resubmit_transactions(transaction_count, gas_fee_estimate.clone());
            for (_withdrawal_id, resubmit_tx) in resubmit_txs.into_iter().flatten() {
                wrapped_txs.borrow_mut().record_resubmit_transaction(resubmit_tx);
            }

            let withdrawal_requests = wrapped_txs.borrow().withdrawal_requests_batch(5);
            for request in withdrawal_requests {
                let nonce = wrapped_txs.borrow().next_transaction_nonce();
                if let Ok(created_tx) = create_transaction(
                    &request,
                    nonce,
                    gas_fee_estimate.clone().to_price(estimate_gas_limit(&request)),
                    EthereumNetwork::Sepolia,
                ){
                    wrapped_txs.borrow_mut().record_created_transaction(request.cketh_ledger_burn_index(), created_tx);
                }
            }

            let created_txs: Vec<_> = wrapped_txs.borrow().transactions_to_sign_iter().map(|(_nonce, _ledger_burn_index, tx)| tx)
            .cloned()
            .collect();
            for created_tx in created_txs {
                wrapped_txs.borrow_mut().record_signed_transaction(sign_transaction(created_tx));
            }
        });
    }
}

pub mod arbitrary {
    use crate::checked_amount::CheckedAmountOf;
    use crate::numeric::{GasAmount, TransactionNonce, WeiPerGas};
    use crate::state::transactions::{EthWithdrawalRequest, Subaccount};
    use crate::tx::{
        AccessList, AccessListItem, Eip1559Signature, Eip1559TransactionRequest,
        SignedEip1559TransactionRequest, StorageKey, TransactionPrice, TransactionPriceEstimate,
    };
    use candid::Principal;
    use ic_ethereum_types::Address;
    use phantom_newtype::Id;
    use proptest::arbitrary::any;
    use proptest::array::{uniform20, uniform32};
    use proptest::collection::vec as pvec;
    use proptest::strategy::Strategy;

    pub fn arb_checked_amount_of<Unit>() -> impl Strategy<Value = CheckedAmountOf<Unit>> {
        uniform32(any::<u8>()).prop_map(CheckedAmountOf::from_be_bytes)
    }

    fn arb_u64_id<Entity>() -> impl Strategy<Value = Id<Entity, u64>> {
        any::<u64>().prop_map(Id::from)
    }

    fn arb_u256() -> impl Strategy<Value = ethnum::u256> {
        uniform32(any::<u8>()).prop_map(ethnum::u256::from_be_bytes)
    }

    fn arb_address() -> impl Strategy<Value = Address> {
        uniform20(any::<u8>()).prop_map(Address::new)
    }

    fn arb_principal() -> impl Strategy<Value = Principal> {
        pvec(any::<u8>(), 0..=29).prop_map(|bytes| Principal::from_slice(&bytes))
    }

    fn arb_subaccount() -> impl Strategy<Value = Subaccount> {
        uniform32(any::<u8>()).prop_map(Subaccount)
    }

    pub fn arb_withdrawal_request() -> impl Strategy<Value = EthWithdrawalRequest> {
        (
            arb_checked_amount_of(),
            arb_address(),
            arb_u64_id(),
            arb_principal(),
            proptest::option::of(arb_subaccount()),
            proptest::option::of(any::<u64>()),
        )
            .prop_map(
                |(
                    withdrawal_amount,
                    destination,
                    ledger_burn_index,
                    from,
                    from_subaccount,
                    created_at,
                )| {
                    EthWithdrawalRequest {
                        withdrawal_amount,
                        destination,
                        ledger_burn_index,
                        from,
                        from_subaccount,
                        created_at,
                    }
                },
            )
    }

    pub fn arb_non_overflowing_transaction_price() -> impl Strategy<Value = TransactionPrice> {
        (any::<u128>(), arb_gas_fee_estimate()).prop_map(|(gas_limit, gas_fee)| {
            let price = gas_fee.to_price(GasAmount::new(gas_limit));
            let _does_not_panic = price.max_transaction_fee();
            price
        })
    }

    pub fn arb_gas_fee_estimate() -> impl Strategy<Value = TransactionPriceEstimate> {
        (any::<u128>(), any::<u128>()).prop_map(|(max_priority_fee_per_gas, max_fee_per_gas)| {
            TransactionPriceEstimate {
                max_fee_per_gas: WeiPerGas::new(max_fee_per_gas),
                max_priority_fee_per_gas: WeiPerGas::new(max_priority_fee_per_gas),
            }
        })
    }

    fn arb_storage_key() -> impl Strategy<Value = StorageKey> {
        uniform32(any::<u8>()).prop_map(StorageKey)
    }

    fn arb_access_list_item() -> impl Strategy<Value = AccessListItem> {
        (arb_address(), pvec(arb_storage_key(), 0..100)).prop_map(|(address, storage_keys)| {
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
        (
            any::<u64>(),
            arb_checked_amount_of(),
            arb_non_overflowing_transaction_price(),
            arb_address(),
            arb_checked_amount_of(),
            pvec(any::<u8>(), 0..100),
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

fn cketh_withdrawal_request_with_index(ledger_burn_index: LedgerBurnIndex) -> EthWithdrawalRequest {
    use std::str::FromStr;
    EthWithdrawalRequest {
        ledger_burn_index,
        destination: Address::from_str(DEFAULT_RECIPIENT_ADDRESS).unwrap(),
        withdrawal_amount: Wei::new(DEFAULT_WITHDRAWAL_AMOUNT),
        from: candid::Principal::from_str(DEFAULT_PRINCIPAL).unwrap(),
        from_subaccount: Some(Subaccount(DEFAULT_SUBACCOUNT)),
        created_at: Some(DEFAULT_CREATED_AT),
    }
}

fn only_eth_withdrawals<T: IntoIterator<Item = WithdrawalRequest>>(
    withdrawal_requests: T,
) -> Vec<EthWithdrawalRequest> {
    withdrawal_requests
        .into_iter()
        .filter_map(|request| match request {
            WithdrawalRequest::CkEth(request) => Some(request),
            _ => None,
        })
        .collect()
}

fn ckerc20_withdrawal_request_with_index(
    cketh_ledger_burn_index: LedgerBurnIndex,
    ckerc20_ledger_burn_index: LedgerBurnIndex,
) -> Erc20WithdrawalRequest {
    use std::str::FromStr;
    Erc20WithdrawalRequest {
        max_transaction_fee: Wei::new(DEFAULT_MAX_TRANSACTION_FEE),
        destination: Address::from_str(DEFAULT_RECIPIENT_ADDRESS).unwrap(),
        cketh_ledger_burn_index,
        erc20_contract_address: DEFAULT_ERC20_CONTRACT_ADDRESS.parse().unwrap(),
        ckerc20_ledger_burn_index,
        withdrawal_amount: Erc20Value::new(DEFAULT_WITHDRAWAL_AMOUNT),
        from: candid::Principal::from_str(DEFAULT_PRINCIPAL).unwrap(),
        from_subaccount: Some(Subaccount(DEFAULT_SUBACCOUNT)),
        created_at: DEFAULT_CREATED_AT,
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
        max_priority_fee_per_gas: WeiPerGas::new(0x59682f00),
        max_fee_per_gas: WeiPerGas::new(0x598653cd),
        gas_limit: GasAmount::new(56_511),
        destination: Address::from_str("0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34").unwrap(),
        amount: Wei::new(1_000_000_000_000_000),
        data: hex::decode(
            "b214faa51d882d15b09f8e81e29606305f5fefc5eff3e2309620a3557ecae39d62020000",
        )
        .unwrap(),
        access_list: AccessList::new(),
    }
}

fn gas_fee_estimate() -> TransactionPriceEstimate {
    TransactionPriceEstimate {
        max_fee_per_gas: WeiPerGas::new(0x59682f32),
        max_priority_fee_per_gas: WeiPerGas::new(0x59682f00),
    }
}

fn cketh_withdrawal_tx_fee() -> TransactionPrice {
    gas_fee_estimate().to_price(CKETH_WITHDRAWAL_TRANSACTION_GAS_LIMIT)
}

fn create_and_record_withdrawal_request(
    transactions: &mut EthTransactions,
    ledger_burn_index: LedgerBurnIndex,
) -> EthWithdrawalRequest {
    let request = cketh_withdrawal_request_with_index(ledger_burn_index);
    transactions.record_withdrawal_request(request.clone());
    request
}

fn create_and_record_transaction<R: Into<WithdrawalRequest>>(
    transactions: &mut EthTransactions,
    withdrawal_request: R,
    gas_fee_estimate: TransactionPriceEstimate,
) -> Eip1559TransactionRequest {
    let withdrawal_request = withdrawal_request.into();
    let burn_index = withdrawal_request.cketh_ledger_burn_index();
    let tx = create_transaction(
        &withdrawal_request,
        transactions.next_transaction_nonce(),
        gas_fee_estimate.to_price(estimate_gas_limit(&withdrawal_request)),
        EthereumNetwork::Sepolia,
    )
    .expect("failed to create transaction");
    transactions.record_created_transaction(withdrawal_request.cketh_ledger_burn_index(), tx);
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
    transactions.record_resubmit_transaction(new_tx.clone());
    let signed_tx = sign_transaction(new_tx);
    transactions.record_signed_transaction(signed_tx.clone());
    signed_tx
}

fn transaction_receipt(
    signed_tx: &SignedEip1559TransactionRequest,
    status: TransactionStatus,
) -> TransactionReceipt {
    use std::str::FromStr;
    TransactionReceipt {
        block_hash: Hash::from_str(
            "0xce67a85c9fb8bc50213815c32814c159fd75160acf7cb8631e8e7b7cf7f1d472",
        )
        .unwrap(),
        block_number: BlockNumber::new(4190269),
        effective_gas_price: signed_tx.transaction().max_fee_per_gas,
        gas_used: signed_tx.transaction().gas_limit,
        status,
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
