use crate::checked_amount::CheckedAmountOf;
use crate::eth_logs::LedgerSubaccount;
use crate::eth_rpc::Hash;
use crate::eth_rpc_client::responses::{TransactionReceipt, TransactionStatus};
use crate::lifecycle::EthereumNetwork;
use crate::numeric::{
    BlockNumber, Erc20Value, GasAmount, LedgerBurnIndex, TransactionNonce, Wei, WeiPerGas,
};
use crate::state::transactions::{
    Erc20WithdrawalRequest, EthTransactions, EthWithdrawalRequest, WithdrawalRequest,
    create_transaction,
};
use crate::tx::{
    AccessList, Eip1559Signature, Eip1559TransactionRequest, GasFeeEstimate,
    SignedEip1559TransactionRequest,
};
use crate::withdraw::estimate_gas_limit;
use ic_ethereum_types::Address;
use rand::Rng;

const DEFAULT_WITHDRAWAL_AMOUNT: u128 = 1_100_000_000_000_000;
const DEFAULT_PRINCIPAL: &str = "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae";
const DEFAULT_SUBACCOUNT: [u8; 32] = [0x11; 32];
const DEFAULT_RECIPIENT_ADDRESS: &str = "0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34";
const DEFAULT_CREATED_AT: u64 = 1699527697000000000;

const DEFAULT_MAX_TRANSACTION_FEE: u128 = 30_000_000_000_000_000;
const DEFAULT_CKERC20_MAX_FEE_PER_GAS: WeiPerGas =
    WeiPerGas::new(DEFAULT_MAX_TRANSACTION_FEE / 65_000_u128);
const DEFAULT_ERC20_CONTRACT_ADDRESS: &str = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
const DEFAULT_CKERC20_LEDGER_ID: &str = "sa4so-piaaa-aaaar-qacnq-cai";

mod eth_transactions {
    use crate::endpoints::{EthTransaction, RetrieveEthStatus};
    use crate::numeric::{LedgerBurnIndex, TransactionNonce};
    use crate::state::transactions::tests::{
        cketh_withdrawal_request_with_index, create_and_record_transaction, gas_fee_estimate,
        sign_transaction, transaction_receipt,
    };
    use crate::state::transactions::{EthTransactions, TransactionStatus, WithdrawalRequest};

    mod record_withdrawal_request {
        use super::*;
        use crate::state::transactions::WithdrawalRequest;
        use crate::state::transactions::tests::{
            ckerc20_withdrawal_request_with_index, create_and_record_signed_transaction,
            create_and_record_transaction, gas_fee_estimate, transaction_receipt,
        };
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
        use crate::state::transactions::WithdrawalRequest;
        use crate::state::transactions::tests::{
            create_and_record_ck_withdrawal_requests, create_and_record_signed_transaction,
            create_and_record_transaction, gas_fee_estimate,
        };
        use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
        use proptest::{prop_assert_eq, proptest};
        use rand::Rng;

        #[test]
        fn should_be_empty_when_no_withdrawal_requests() {
            let transactions = EthTransactions::new(TransactionNonce::ZERO);
            assert_eq!(transactions.withdrawal_requests_batch(5), vec![]);
        }

        #[test]
        fn should_retrieve_the_first_withdrawal_requests() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let mut rng = reproducible_rng();
            let withdrawal_requests: [WithdrawalRequest; 5] =
                create_and_record_ck_withdrawal_requests(&mut transactions, &mut rng);

            let requests = transactions.withdrawal_requests_batch(0);
            assert_eq!(requests, vec![]);

            let requests = transactions.withdrawal_requests_batch(1);
            assert_eq!(requests.as_slice(), &withdrawal_requests[0..=0]);

            let requests = transactions.withdrawal_requests_batch(2);
            assert_eq!(&requests, &withdrawal_requests[0..=1]);
        }

        proptest! {
            #[test]
            fn should_retrieve_all_withdrawal_requests_in_order(batch_size in 3..100_usize) {
                let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
                let mut rng = reproducible_rng();
                let withdrawal_requests: [WithdrawalRequest; 3] =
                    create_and_record_ck_withdrawal_requests(&mut transactions, &mut rng);

                let requests = transactions.withdrawal_requests_batch(batch_size);

                prop_assert_eq!(requests, withdrawal_requests);
            }
        }

        #[test]
        fn should_limit_batch_size_when_too_many_pending_transactions() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let mut rng = reproducible_rng();
            let withdrawal_requests: [WithdrawalRequest; 1000] =
                create_and_record_ck_withdrawal_requests(&mut transactions, &mut rng);
            withdrawal_requests
                .iter()
                .take(997)
                .for_each(|withdrawal_request| {
                    create_and_record_pending_transaction(
                        &mut transactions,
                        withdrawal_request.clone(),
                        rng.r#gen(),
                    )
                });

            assert_eq!(
                transactions.withdrawal_requests_batch(3).as_slice(),
                &withdrawal_requests[997..=999]
            );

            create_and_record_pending_transaction(
                &mut transactions,
                withdrawal_requests[997].clone(),
                rng.r#gen(),
            );
            assert_eq!(
                transactions.withdrawal_requests_batch(3).as_slice(),
                &withdrawal_requests[998..=999]
            );

            create_and_record_pending_transaction(
                &mut transactions,
                withdrawal_requests[998].clone(),
                rng.r#gen(),
            );
            assert_eq!(
                transactions.withdrawal_requests_batch(3).as_slice(),
                &withdrawal_requests[999..=999]
            );

            create_and_record_pending_transaction(
                &mut transactions,
                withdrawal_requests[999].clone(),
                rng.r#gen(),
            );
            assert_eq!(transactions.withdrawal_requests_batch(3), vec![]);
        }

        fn create_and_record_pending_transaction<R: Into<WithdrawalRequest>>(
            transactions: &mut EthTransactions,
            withdrawal_request: R,
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
        use crate::numeric::TransactionNonce;
        use crate::state::transactions::EthTransactions;
        use crate::state::transactions::tests::create_and_record_ck_withdrawal_requests;
        use ic_crypto_test_utils_reproducible_rng::reproducible_rng;

        #[test]
        fn should_reschedule_withdrawal_request() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let mut rng = reproducible_rng();
            let [first_request, second_request, third_request] =
                create_and_record_ck_withdrawal_requests(&mut transactions, &mut rng);
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
                    first_request.clone(),
                ]
            );

            transactions.reschedule_withdrawal_request(second_request.clone());
            // 2 -> 1 -> 3
            assert_eq!(
                transactions.withdrawal_requests_batch(5),
                vec![
                    third_request.clone(),
                    first_request.clone(),
                    second_request.clone(),
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
        use crate::lifecycle::EthereumNetwork;
        use crate::numeric::{LedgerBurnIndex, TransactionNonce, Wei};
        use crate::state::transactions::Erc20Value;
        use crate::state::transactions::tests::{
            DEFAULT_CKERC20_MAX_FEE_PER_GAS, ckerc20_withdrawal_request_with_index,
            cketh_withdrawal_request_with_index, create_and_record_ck_withdrawal_requests,
            create_and_record_transaction, create_ck_withdrawal_requests, gas_fee_estimate,
        };
        use crate::state::transactions::{EthTransactions, create_transaction};
        use crate::test_fixtures::expect_panic_with_message;
        use crate::tx::Eip1559TransactionRequest;
        use crate::withdraw::{
            CKERC20_WITHDRAWAL_TRANSACTION_GAS_LIMIT, CKETH_WITHDRAWAL_TRANSACTION_GAS_LIMIT,
            estimate_gas_limit,
        };
        use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
        use ic_ethereum_types::Address;
        use proptest::prelude::any;
        use proptest::{prop_assert_ne, proptest};

        #[test]
        fn should_fail_when_withdrawal_request_not_found() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let mut rng = reproducible_rng();
            let [withdrawal_request] = create_ck_withdrawal_requests(&mut rng);
            let tx = create_transaction(
                &withdrawal_request.clone(),
                TransactionNonce::ZERO,
                gas_fee_estimate(),
                estimate_gas_limit(&withdrawal_request),
                EthereumNetwork::Sepolia,
            )
            .unwrap();

            let burn_index = withdrawal_request.cketh_ledger_burn_index();
            expect_panic_with_message(
                || transactions.record_created_transaction(burn_index, tx),
                &format!("withdrawal request {burn_index} not found"),
            );
        }

        #[test]
        fn should_fail_when_mismatch_with_cketh_withdrawal_request() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let withdrawal_request = cketh_withdrawal_request_with_index(LedgerBurnIndex::new(15));
            transactions.record_withdrawal_request(withdrawal_request.clone());
            let correct_tx = create_transaction(
                &withdrawal_request.clone().into(),
                TransactionNonce::ZERO,
                gas_fee_estimate(),
                estimate_gas_limit(&withdrawal_request.clone().into()),
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

        #[test]
        fn should_fail_when_mismatch_with_ckerc20_withdrawal_request() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let withdrawal_request = ckerc20_withdrawal_request_with_index(
                LedgerBurnIndex::new(3),
                LedgerBurnIndex::new(7),
            );
            transactions.record_withdrawal_request(withdrawal_request.clone());
            let correct_tx = create_transaction(
                &withdrawal_request.clone().into(),
                TransactionNonce::ZERO,
                gas_fee_estimate(),
                estimate_gas_limit(&withdrawal_request.clone().into()),
                EthereumNetwork::Sepolia,
            )
            .unwrap();
            let tx_mixing_payee_address_with_erc20_address = Eip1559TransactionRequest {
                destination: withdrawal_request.destination,
                ..correct_tx.clone()
            };
            assert_ne!(correct_tx, tx_mixing_payee_address_with_erc20_address);
            expect_panic_with_message(
                || {
                    transactions.record_created_transaction(
                        withdrawal_request.cketh_ledger_burn_index,
                        tx_mixing_payee_address_with_erc20_address,
                    )
                },
                "destination mismatch",
            );

            let tx_with_wrong_amount = Eip1559TransactionRequest {
                amount: Wei::ONE,
                ..correct_tx.clone()
            };
            assert_ne!(correct_tx, tx_with_wrong_amount);
            expect_panic_with_message(
                || {
                    transactions.record_created_transaction(
                        withdrawal_request.cketh_ledger_burn_index,
                        tx_with_wrong_amount,
                    )
                },
                "amount should be zero",
            );
        }

        proptest! {
            #[test]
            fn should_fail_when_nonce_wrong(current_nonce in any::<u64>(), nonce_drift in 1..=u64::MAX) {
                let current_nonce = TransactionNonce::from(current_nonce);
                let wrong_nonce = current_nonce.checked_add(TransactionNonce::from(nonce_drift)).unwrap();
                prop_assert_ne!(current_nonce, wrong_nonce);
                let mut transactions = EthTransactions::new(current_nonce);
                let mut rng = reproducible_rng();
                let [withdrawal_request] = create_and_record_ck_withdrawal_requests(&mut transactions, &mut rng);
                let tx_with_wrong_nonce = create_transaction(
                    &withdrawal_request.clone(),
                    wrong_nonce,
                    gas_fee_estimate(),
                    CKETH_WITHDRAWAL_TRANSACTION_GAS_LIMIT,
                    EthereumNetwork::Sepolia,
                )
                .unwrap();

                expect_panic_with_message(
                    || transactions.record_created_transaction(withdrawal_request.cketh_ledger_burn_index(), tx_with_wrong_nonce),
                    "nonce mismatch",
                );
            }
        }

        #[test]
        fn should_create_and_record_cketh_transaction() {
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
                        max_fee_per_gas: transaction_price.estimate_max_fee_per_gas(),
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
        fn should_create_and_record_ckerc20_transactions() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let gas_fee_estimate = gas_fee_estimate();
            for i in 0..100_u64 {
                let cketh_ledger_burn_index = LedgerBurnIndex::new(3 * i);
                let ckerc20_ledger_burn_index = LedgerBurnIndex::new(7 * i);
                let withdrawal_request = ckerc20_withdrawal_request_with_index(
                    cketh_ledger_burn_index,
                    ckerc20_ledger_burn_index,
                );
                transactions.record_withdrawal_request(withdrawal_request.clone());
                let created_tx = create_and_record_transaction(
                    &mut transactions,
                    withdrawal_request.clone(),
                    gas_fee_estimate.clone(),
                );

                assert_eq!(
                    created_tx,
                    Eip1559TransactionRequest {
                        chain_id: EthereumNetwork::Sepolia.chain_id(),
                        nonce: TransactionNonce::from(i),
                        max_priority_fee_per_gas: gas_fee_estimate.max_priority_fee_per_gas,
                        max_fee_per_gas: DEFAULT_CKERC20_MAX_FEE_PER_GAS,
                        gas_limit: CKERC20_WITHDRAWAL_TRANSACTION_GAS_LIMIT,
                        destination: withdrawal_request.erc20_contract_address,
                        amount: Wei::ZERO,
                        data: erc20_transfer_data(
                            &withdrawal_request.destination,
                            &withdrawal_request.withdrawal_amount,
                        ),
                        access_list: Default::default(),
                    }
                );
                assert_eq!(transactions.next_nonce, TransactionNonce::from(i + 1));
            }
        }

        #[allow(deprecated)]
        fn erc20_transfer_data(
            expected_address: &Address,
            expected_amount: &Erc20Value,
        ) -> Vec<u8> {
            use crate::state::transactions::ERC_20_TRANSFER_FUNCTION_SELECTOR;
            use ethers_core::abi::{Param, ParamType, Token};

            let erc20_transfer = ethers_core::abi::Function {
                name: "transfer".to_string(),
                inputs: vec![
                    Param {
                        name: "_to".to_string(),
                        kind: ParamType::Address,
                        internal_type: None,
                    },
                    Param {
                        name: "_value".to_string(),
                        kind: ParamType::Uint(256),
                        internal_type: None,
                    },
                ],
                outputs: vec![Param {
                    name: "success".to_string(),
                    kind: ParamType::Bool,
                    internal_type: None,
                }],
                constant: None,
                state_mutability: ethers_core::abi::StateMutability::NonPayable,
            };
            assert_eq!(
                erc20_transfer.short_signature(),
                ERC_20_TRANSFER_FUNCTION_SELECTOR
            );
            erc20_transfer
                .encode_input(&[
                    Token::Address(expected_address.to_string().parse().unwrap()),
                    Token::Uint(expected_amount.to_be_bytes().into()),
                ])
                .expect("failed to encode transfer data")
        }

        #[test]
        fn should_consume_withdrawal_request_when_creating_transaction() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let mut rng = reproducible_rng();
            let [withdrawal_request] =
                create_and_record_ck_withdrawal_requests(&mut transactions, &mut rng);

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
        use crate::numeric::TransactionNonce;
        use crate::state::transactions::tests::{
            create_and_record_ck_withdrawal_requests, create_and_record_transaction,
            gas_fee_estimate, sign_transaction, signed_transaction_with_nonce,
        };
        use crate::state::transactions::{EthTransactions, WithdrawalRequest};
        use crate::test_fixtures::expect_panic_with_message;
        use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
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
            let mut rng = reproducible_rng();
            let withdrawal_requests: [WithdrawalRequest; 100] =
                create_and_record_ck_withdrawal_requests(&mut transactions, &mut rng);
            for withdrawal_request in withdrawal_requests {
                let cketh_ledger_burn_index = withdrawal_request.cketh_ledger_burn_index();
                let created_tx = create_and_record_transaction(
                    &mut transactions,
                    withdrawal_request,
                    gas_fee_estimate(),
                );
                let signed_tx = sign_transaction(created_tx);

                transactions.record_signed_transaction(signed_tx.clone());

                assert_eq!(transactions.transactions_to_sign_iter().next(), None);
                assert_eq!(
                    transactions
                        .sent_tx
                        .get_alt(&cketh_ledger_burn_index)
                        .map(|txs| txs.iter().map(|tx| tx.as_ref()).collect()),
                    Some(vec![&signed_tx])
                );
            }
        }

        proptest! {
            #[test]
            fn should_fail_when_signed_transaction_does_not_match_created_transaction(
                bad_tx in arb_signed_eip_1559_transaction_request_with_nonce(TransactionNonce::ZERO)
            ) {
                let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
                let mut rng = reproducible_rng();
                let [withdrawal_request] =
                    create_and_record_ck_withdrawal_requests(&mut transactions, &mut rng);
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
            let mut rng = reproducible_rng();
            let [withdrawal_request] =
                create_and_record_ck_withdrawal_requests(&mut transactions, &mut rng);
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
            DEFAULT_CKERC20_MAX_FEE_PER_GAS, DEFAULT_MAX_TRANSACTION_FEE,
            cketh_withdrawal_request_with_index, create_and_record_ck_withdrawal_requests,
            create_and_record_ckerc20_withdrawal_requests,
            create_and_record_cketh_withdrawal_requests, create_and_record_signed_transaction,
            create_and_record_transaction, double_and_increment, gas_fee_estimate,
        };
        use crate::state::transactions::{
            EthTransactions, ResubmitTransactionError, WithdrawalRequest,
        };
        use crate::tx::{Eip1559TransactionRequest, GasFeeEstimate};
        use ic_crypto_test_utils_reproducible_rng::reproducible_rng;

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
            let mut rng = reproducible_rng();
            let withdrawal_requests: [WithdrawalRequest; 100] =
                create_and_record_ck_withdrawal_requests(&mut transactions, &mut rng);
            let initial_price = gas_fee_estimate();
            let higher_new_price = GasFeeEstimate {
                max_priority_fee_per_gas: initial_price
                    .max_priority_fee_per_gas
                    .checked_increment()
                    .unwrap(),
                ..initial_price
            };
            for (num_tx, withdrawal_request) in withdrawal_requests.into_iter().enumerate() {
                let created_tx = create_and_record_transaction(
                    &mut transactions,
                    withdrawal_request,
                    initial_price.clone(),
                );
                let _signed_tx =
                    create_and_record_signed_transaction(&mut transactions, created_tx);

                let resubmitted_txs = transactions.create_resubmit_transactions(
                    TransactionCount::from((num_tx as u64) + 1),
                    higher_new_price.clone(),
                );

                assert_eq!(resubmitted_txs, vec![]);
            }
        }

        #[test]
        fn should_be_empty_when_initial_max_fee_per_gas_covers_new_fee() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let mut rng = reproducible_rng();
            let withdrawal_requests: [WithdrawalRequest; 100] =
                create_and_record_ck_withdrawal_requests(&mut transactions, &mut rng);
            let initial_price = GasFeeEstimate {
                base_fee_per_gas: WeiPerGas::from(10_u8),
                max_priority_fee_per_gas: WeiPerGas::from(2_u8),
            };
            for withdrawal_request in withdrawal_requests {
                let created_tx = create_and_record_transaction(
                    &mut transactions,
                    withdrawal_request,
                    initial_price.clone(),
                );
                let _signed_tx =
                    create_and_record_signed_transaction(&mut transactions, created_tx);
            }

            let mut updated_prices: Vec<_> = (0_u8..=20)
                .map(|base_fee_per_gas_next_block| GasFeeEstimate {
                    base_fee_per_gas: WeiPerGas::from(base_fee_per_gas_next_block),
                    ..initial_price.clone()
                })
                .collect();
            updated_prices.extend(
                (0_u8..=21).map(|base_fee_per_gas_next_block| GasFeeEstimate {
                    base_fee_per_gas: WeiPerGas::from(base_fee_per_gas_next_block),
                    max_priority_fee_per_gas: WeiPerGas::from(1_u8),
                }),
            );
            updated_prices.extend(
                (0_u8..=22).map(|base_fee_per_gas_next_block| GasFeeEstimate {
                    base_fee_per_gas: WeiPerGas::from(base_fee_per_gas_next_block),
                    max_priority_fee_per_gas: WeiPerGas::from(0_u8),
                }),
            );

            for updated_price in updated_prices {
                let resubmitted_txs = transactions
                    .create_resubmit_transactions(TransactionCount::from(10_u8), updated_price);
                assert_eq!(resubmitted_txs, vec![]);
            }
        }

        #[test]
        fn should_resubmit_cketh_transaction_with_updated_price() {
            let price_at_tx_creation = GasFeeEstimate {
                base_fee_per_gas: WeiPerGas::from(10_u8),
                max_priority_fee_per_gas: WeiPerGas::from(2_u8),
            };
            let max_fee_per_gas_at_tx_creation = 2 * 10 + 2;
            let tests = vec![
                //max_priority_fee_per_gas increased
                ParameterizedTest {
                    price_at_tx_creation: price_at_tx_creation.clone(),
                    price_at_tx_resubmission: GasFeeEstimate {
                        max_priority_fee_per_gas: price_at_tx_creation
                            .max_priority_fee_per_gas
                            .checked_increment()
                            .unwrap(),
                        ..price_at_tx_creation.clone()
                    },
                    resubmitted_tx_max_fee_per_gas: price_at_tx_creation
                        .clone()
                        .estimate_max_fee_per_gas(),
                    resubmitted_tx_max_priority_fee_per_gas: WeiPerGas::from(3_u8),
                    resubmitted_cketh_tx_amount_deduction: Wei::ZERO,
                },
                //base_fee_per_gas_next_block increased
                ParameterizedTest {
                    price_at_tx_creation: price_at_tx_creation.clone(),
                    price_at_tx_resubmission: GasFeeEstimate {
                        base_fee_per_gas: price_at_tx_creation
                            .base_fee_per_gas
                            .checked_mul(2_u8)
                            .and_then(|fee| fee.checked_increment())
                            .unwrap(),
                        ..price_at_tx_creation.clone()
                    },
                    resubmitted_tx_max_fee_per_gas: WeiPerGas::from(24_u8), // (2 * 10 + 1) + 3
                    resubmitted_tx_max_priority_fee_per_gas: WeiPerGas::from(3_u8), //10% increase of 2 rounded up
                    resubmitted_cketh_tx_amount_deduction: Wei::from(
                        (24 - max_fee_per_gas_at_tx_creation) * 21_000_u32,
                    ),
                },
                // max_priority_fee_per_gas and base_fee_per_gas_next_block increased
                ParameterizedTest {
                    price_at_tx_creation: price_at_tx_creation.clone(),
                    price_at_tx_resubmission: GasFeeEstimate {
                        base_fee_per_gas: price_at_tx_creation
                            .base_fee_per_gas
                            .checked_mul(2_u8)
                            .and_then(|fee| fee.checked_increment())
                            .unwrap(),
                        max_priority_fee_per_gas: price_at_tx_creation
                            .max_priority_fee_per_gas
                            .checked_mul(2_u8)
                            .unwrap(),
                    },
                    resubmitted_tx_max_fee_per_gas: WeiPerGas::from(25_u8), //(2 * 10 + 1) + 4
                    resubmitted_tx_max_priority_fee_per_gas: WeiPerGas::from(4_u8), //max_priority_fee_per_gas at tx_resubmission because higher than 10% bump of max_priority_fee_per_gas at tx_creation
                    resubmitted_cketh_tx_amount_deduction: Wei::from(
                        (25 - max_fee_per_gas_at_tx_creation) * 21_000_u32,
                    ),
                },
            ];

            fn check_resubmit_tx<R: Into<WithdrawalRequest>>(
                test: &ParameterizedTest,
                withdrawal_request: R,
            ) {
                let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
                let withdrawal_request = withdrawal_request.into();
                let cketh_ledger_burn_index = withdrawal_request.cketh_ledger_burn_index();
                transactions.record_withdrawal_request(withdrawal_request.clone());
                let initial_tx = create_and_record_transaction(
                    &mut transactions,
                    withdrawal_request.clone(),
                    test.price_at_tx_creation.clone(),
                );
                let _signed_tx =
                    create_and_record_signed_transaction(&mut transactions, initial_tx.clone());

                let resubmitted_txs = transactions.create_resubmit_transactions(
                    TransactionCount::ZERO,
                    test.price_at_tx_resubmission.clone(),
                );
                let expected_resubmitted_tx_amount = match withdrawal_request {
                    WithdrawalRequest::CkEth(_) => initial_tx
                        .amount
                        .checked_sub(test.resubmitted_cketh_tx_amount_deduction)
                        .unwrap(),
                    WithdrawalRequest::CkErc20(_) => initial_tx.amount,
                };
                let expected_resubmitted_tx = Eip1559TransactionRequest {
                    max_fee_per_gas: test.resubmitted_tx_max_fee_per_gas,
                    max_priority_fee_per_gas: test.resubmitted_tx_max_priority_fee_per_gas,
                    amount: expected_resubmitted_tx_amount,
                    ..initial_tx
                };
                assert_eq!(
                    resubmitted_txs,
                    vec![Ok((cketh_ledger_burn_index, expected_resubmitted_tx))]
                );
            }

            for test in &tests {
                let cketh_ledger_burn_index = LedgerBurnIndex::new(15);
                check_resubmit_tx(
                    test,
                    cketh_withdrawal_request_with_index(cketh_ledger_burn_index),
                );
            }
        }

        #[test]
        fn should_resubmit_multiple_cketh_transactions() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let withdrawal_requests: [WithdrawalRequest; 100] =
                create_and_record_cketh_withdrawal_requests(&mut transactions);
            let initial_price = GasFeeEstimate {
                base_fee_per_gas: WeiPerGas::from(10_u8),
                max_priority_fee_per_gas: WeiPerGas::from(2_u8),
            };
            for withdrawal_request in &withdrawal_requests {
                let created_tx = create_and_record_transaction(
                    &mut transactions,
                    withdrawal_request.clone(),
                    initial_price.clone(),
                );
                let _signed_tx =
                    create_and_record_signed_transaction(&mut transactions, created_tx);
            }
            let higher_price = GasFeeEstimate {
                base_fee_per_gas: double_and_increment(initial_price.base_fee_per_gas),
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
                let initial_transaction = transactions.sent_tx.get_alt(&withdrawal_id).unwrap()[0]
                    .as_ref()
                    .transaction();
                let expected_amount = initial_transaction
                    .amount
                    .checked_sub(Wei::from(2 * 21_000_u32))
                    .unwrap();
                assert_eq!(
                    resubmitted_tx,
                    Eip1559TransactionRequest {
                        nonce: TransactionNonce::from(30_u8 + i as u8),
                        max_fee_per_gas: WeiPerGas::from(24_u8), // (2 * 10 + 1) + 3
                        max_priority_fee_per_gas: WeiPerGas::from(3_u8),
                        amount: expected_amount,
                        ..initial_transaction.clone()
                    }
                );
            }
        }

        #[test]
        fn should_not_resubmit_ckerc20_transactions_unless_max_priority_fee_increases() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let withdrawal_requests: [WithdrawalRequest; 100] =
                create_and_record_ckerc20_withdrawal_requests(&mut transactions);
            let initial_price = GasFeeEstimate {
                base_fee_per_gas: WeiPerGas::from(10_u8),
                max_priority_fee_per_gas: WeiPerGas::from(2_u8),
            };
            for withdrawal_request in &withdrawal_requests {
                let created_tx = create_and_record_transaction(
                    &mut transactions,
                    withdrawal_request.clone(),
                    initial_price.clone(),
                );
                let _signed_tx =
                    create_and_record_signed_transaction(&mut transactions, created_tx);
            }

            let higher_base_fee_per_gas_price = GasFeeEstimate {
                base_fee_per_gas: double_and_increment(initial_price.base_fee_per_gas),
                ..initial_price
            };
            let resubmitted_txs = transactions.create_resubmit_transactions(
                TransactionCount::from(30_u8),
                higher_base_fee_per_gas_price.clone(),
            );
            assert_eq!(resubmitted_txs, vec![]);

            let higher_max_priority_fee_per_gas_price = GasFeeEstimate {
                max_priority_fee_per_gas: initial_price
                    .max_priority_fee_per_gas
                    .checked_increment()
                    .unwrap(),
                ..initial_price
            };
            let resubmitted_txs = transactions.create_resubmit_transactions(
                TransactionCount::from(30_u8),
                higher_max_priority_fee_per_gas_price.clone(),
            );
            assert_eq!(resubmitted_txs.len(), 70);
            for (i, (withdrawal_id, resubmitted_tx)) in resubmitted_txs
                .into_iter()
                .map(|res| res.unwrap())
                .enumerate()
            {
                let initial_transaction = transactions.sent_tx.get_alt(&withdrawal_id).unwrap()[0]
                    .as_ref()
                    .transaction();
                assert_eq!(
                    resubmitted_tx,
                    Eip1559TransactionRequest {
                        nonce: TransactionNonce::from(30_u8 + i as u8),
                        max_priority_fee_per_gas: WeiPerGas::from(3_u8),
                        ..initial_transaction.clone()
                    }
                );
            }

            let too_high_price = GasFeeEstimate {
                base_fee_per_gas: DEFAULT_CKERC20_MAX_FEE_PER_GAS,
                max_priority_fee_per_gas: WeiPerGas::ONE,
            };
            let resubmitted_txs = transactions.create_resubmit_transactions(
                TransactionCount::from(30_u8),
                too_high_price.clone(),
            );
            assert_eq!(
                resubmitted_txs,
                vec![Err(ResubmitTransactionError::InsufficientTransactionFee {
                    ledger_burn_index: 93_u64.into(),
                    transaction_nonce: 30_u8.into(),
                    allowed_max_transaction_fee: DEFAULT_MAX_TRANSACTION_FEE.into(),
                    max_transaction_fee: 30_000_000_000_165_000_u128.into(),
                })]
            );
        }

        struct ParameterizedTest {
            price_at_tx_creation: GasFeeEstimate,
            price_at_tx_resubmission: GasFeeEstimate,
            resubmitted_tx_max_fee_per_gas: WeiPerGas,
            resubmitted_tx_max_priority_fee_per_gas: WeiPerGas,
            resubmitted_cketh_tx_amount_deduction: Wei,
        }
    }

    mod record_resubmit_transaction {
        use super::super::arbitrary::arb_signed_eip_1559_transaction_request_with_nonce;
        use crate::map::MultiKeyMap;
        use crate::numeric::{LedgerBurnIndex, TransactionCount, TransactionNonce, Wei, WeiPerGas};
        use crate::state::transactions::tests::{
            ckerc20_withdrawal_request_with_index, cketh_withdrawal_request_with_index,
            create_and_record_ck_withdrawal_requests, create_and_record_signed_transaction,
            create_and_record_transaction, gas_fee_estimate, sign_transaction,
        };
        use crate::state::transactions::{
            EthTransactions, WithdrawalRequest, equal_ignoring_fee_and_amount,
        };
        use crate::test_fixtures::expect_panic_with_message;
        use crate::tx::{Eip1559TransactionRequest, GasFeeEstimate};
        use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
        use proptest::{prop_assume, proptest};

        #[test]
        fn should_fail_when_no_sent_tx() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let mut rng = reproducible_rng();
            let [withdrawal_request] =
                create_and_record_ck_withdrawal_requests(&mut transactions, &mut rng);
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
            fn test<
                R: Into<WithdrawalRequest>,
                F: FnOnce(Eip1559TransactionRequest) -> Vec<Eip1559TransactionRequest>,
            >(
                withdrawal_request: R,
                create_transactions_with_increasing_fees: F,
            ) {
                let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
                let withdrawal_request = withdrawal_request.into();
                let cketh_ledger_burn_index = withdrawal_request.cketh_ledger_burn_index();
                transactions.record_withdrawal_request(withdrawal_request.clone());
                let created_tx = create_and_record_transaction(
                    &mut transactions,
                    withdrawal_request,
                    gas_fee_estimate(),
                );
                let first_sent_tx =
                    create_and_record_signed_transaction(&mut transactions, created_tx.clone());
                let transaction_with_increasing_fees =
                    create_transactions_with_increasing_fees(created_tx);

                for (index, transaction) in transaction_with_increasing_fees.iter().enumerate() {
                    transactions.record_resubmit_transaction(transaction.clone());
                    let signed_tx = sign_transaction(transaction.clone());
                    transactions.record_signed_transaction(signed_tx.clone());
                    assert_eq!(transactions.transactions_to_sign_iter().next(), None);
                    let sent_txs: Vec<_> = vec![first_sent_tx.clone()]
                        .into_iter()
                        .chain(
                            transaction_with_increasing_fees[0..=index]
                                .iter()
                                .map(|tx| sign_transaction(tx.clone())),
                        )
                        .collect();
                    assert_eq!(
                        MultiKeyMap::from_iter(transactions.sent_transactions_iter()),
                        MultiKeyMap::from_iter(vec![(
                            &TransactionNonce::ZERO,
                            &cketh_ledger_burn_index,
                            sent_txs.iter().collect()
                        )])
                    );
                }
            }

            let cketh_ledger_burn_index = LedgerBurnIndex::new(15);
            let ckerc20_ledger_burn_index = LedgerBurnIndex::new(7);
            test(
                cketh_withdrawal_request_with_index(cketh_ledger_burn_index),
                |created_tx| {
                    std::iter::repeat_n(created_tx, 10)
                        .enumerate()
                        .map(|(index, mut tx)| {
                            tx.max_priority_fee_per_gas = tx
                                .max_priority_fee_per_gas
                                .checked_add(WeiPerGas::from(index as u8))
                                .unwrap();
                            tx.amount = tx.amount.checked_sub(Wei::from(index as u8)).unwrap();
                            tx
                        })
                        .collect()
                },
            );
            test(
                ckerc20_withdrawal_request_with_index(
                    cketh_ledger_burn_index,
                    ckerc20_ledger_burn_index,
                ),
                |created_tx| {
                    std::iter::repeat_n(created_tx, 10)
                        .enumerate()
                        .map(|(index, mut tx)| {
                            tx.max_priority_fee_per_gas = tx
                                .max_priority_fee_per_gas
                                .checked_add(WeiPerGas::from(index as u8))
                                .unwrap();
                            tx
                        })
                        .collect()
                },
            );
        }

        proptest! {
            #[test]
            fn should_fail_when_mismatch_with_already_sent(
                wrong_resent_tx in arb_signed_eip_1559_transaction_request_with_nonce(TransactionNonce::ZERO)
            ) {
                let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
                let mut rng = reproducible_rng();
                let [withdrawal_request] =
                    create_and_record_ck_withdrawal_requests(&mut transactions, &mut rng);
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
            fn test<R: Into<WithdrawalRequest>>(withdrawal_request: R) {
                let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
                let initial_price = GasFeeEstimate {
                    base_fee_per_gas: WeiPerGas::from(10_u8),
                    max_priority_fee_per_gas: WeiPerGas::from(2_u8),
                };
                let resubmit_price_1 = GasFeeEstimate {
                    max_priority_fee_per_gas: WeiPerGas::from(3_u8),
                    ..initial_price
                };
                let withdrawal_request = withdrawal_request.into();
                let cketh_ledger_burn_index = withdrawal_request.cketh_ledger_burn_index();
                transactions.record_withdrawal_request(withdrawal_request.clone());
                let created_tx = create_and_record_transaction(
                    &mut transactions,
                    withdrawal_request.clone(),
                    initial_price.clone(),
                );
                let _signed_tx =
                    create_and_record_signed_transaction(&mut transactions, created_tx.clone());

                let resubmitted_txs_1 = transactions
                    .create_resubmit_transactions(TransactionCount::ZERO, resubmit_price_1.clone());
                let resubmitted_tx1 = Eip1559TransactionRequest {
                    max_fee_per_gas: created_tx.max_fee_per_gas,
                    max_priority_fee_per_gas: WeiPerGas::from(3_u8),
                    ..created_tx.clone()
                };
                let expected_resubmitted_tx1 = resubmitted_tx1.clone();
                assert_eq!(
                    resubmitted_txs_1,
                    vec![Ok((
                        cketh_ledger_burn_index,
                        expected_resubmitted_tx1.clone()
                    ))]
                );
                transactions.record_resubmit_transaction(expected_resubmitted_tx1);
                assert_eq!(
                    transactions.transactions_to_sign_iter().collect::<Vec<_>>(),
                    vec![(
                        &TransactionNonce::ZERO,
                        &cketh_ledger_burn_index,
                        &resubmitted_tx1
                    )]
                );

                let resubmit_price_2 = GasFeeEstimate {
                    max_priority_fee_per_gas: WeiPerGas::from(4_u8),
                    ..resubmit_price_1
                };
                let resubmitted_txs_2 = transactions
                    .create_resubmit_transactions(TransactionCount::ZERO, resubmit_price_2.clone());
                let resubmitted_tx2 = Eip1559TransactionRequest {
                    max_fee_per_gas: created_tx.max_fee_per_gas,
                    max_priority_fee_per_gas: resubmit_price_2.max_priority_fee_per_gas,
                    ..created_tx
                };
                let expected_resubmitted_tx2 = resubmitted_tx2.clone();
                assert_eq!(
                    resubmitted_txs_2,
                    vec![Ok((
                        cketh_ledger_burn_index,
                        expected_resubmitted_tx2.clone()
                    ))]
                );
                transactions.record_resubmit_transaction(expected_resubmitted_tx2);
                assert_eq!(
                    transactions.transactions_to_sign_iter().collect::<Vec<_>>(),
                    vec![(
                        &TransactionNonce::ZERO,
                        &cketh_ledger_burn_index,
                        &resubmitted_tx2
                    )]
                );
            }

            let cketh_ledger_burn_index = LedgerBurnIndex::new(15);
            let ckerc20_ledger_burn_index = LedgerBurnIndex::new(7);
            test(cketh_withdrawal_request_with_index(cketh_ledger_burn_index));
            test(ckerc20_withdrawal_request_with_index(
                cketh_ledger_burn_index,
                ckerc20_ledger_burn_index,
            ));
        }
    }

    mod transactions_to_send_batch {
        use crate::numeric::{TransactionCount, TransactionNonce};
        use crate::state::transactions::EthTransactions;
        use crate::state::transactions::tests::arbitrary::arb_checked_amount_of;
        use crate::state::transactions::tests::{
            create_and_record_ck_withdrawal_requests, create_and_record_signed_transaction,
            create_and_record_transaction, gas_fee_estimate,
            resubmit_transaction_with_bumped_price,
        };
        use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
        use proptest::proptest;

        proptest! {
            #[test]
            fn should_be_empty_when_no_transactions_to_send(latest_tx_count in arb_checked_amount_of()) {
                let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
                let mut rng = reproducible_rng();
                assert_transactions_to_send_iter_is_empty(&transactions, latest_tx_count);

                let [withdrawal_request] =
                    create_and_record_ck_withdrawal_requests(&mut transactions, &mut rng);
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
            let mut rng = reproducible_rng();
            let [first_withdrawal_request, second_withdrawal_request] =
                create_and_record_ck_withdrawal_requests(&mut transactions, &mut rng);
            let first_created_tx = create_and_record_transaction(
                &mut transactions,
                first_withdrawal_request.clone(),
                gas_fee_estimate(),
            );
            let first_tx =
                create_and_record_signed_transaction(&mut transactions, first_created_tx.clone());
            let last_first_tx =
                resubmit_transaction_with_bumped_price(&mut transactions, first_created_tx.clone());

            let second_created_tx = create_and_record_transaction(
                &mut transactions,
                second_withdrawal_request.clone(),
                gas_fee_estimate(),
            );
            let second_tx =
                create_and_record_signed_transaction(&mut transactions, second_created_tx.clone());
            assert_eq!(
                vec![
                    (
                        &TransactionNonce::ZERO,
                        &first_withdrawal_request.cketh_ledger_burn_index(),
                        vec![&first_tx, &last_first_tx]
                    ),
                    (
                        &TransactionNonce::ONE,
                        &second_withdrawal_request.cketh_ledger_burn_index(),
                        vec![&second_tx]
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
            arbitrary::arb_checked_amount_of, create_and_record_transaction, gas_fee_estimate,
        };
        use crate::numeric::{TransactionCount, TransactionNonce};
        use crate::state::transactions::tests::{
            create_and_record_ck_withdrawal_requests, create_and_record_signed_transaction,
            resubmit_transaction_with_bumped_price,
        };
        use crate::state::transactions::{EthTransactions, WithdrawalRequest};
        use crate::tx::SignedEip1559TransactionRequest;
        use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
        use proptest::proptest;
        use std::collections::BTreeMap;

        proptest! {
            #[test]
            fn should_be_empty_when_no_transaction_to_finalize(finalized_tx_count in arb_checked_amount_of()) {
                let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
                let mut rng = reproducible_rng();
                assert_eq!(
                    transactions.sent_transactions_to_finalize(&finalized_tx_count),
                    BTreeMap::default()
                );

                let [withdrawal_request] = create_and_record_ck_withdrawal_requests(
                    &mut transactions,
                    &mut rng
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
                withdrawal_request: WithdrawalRequest,
            ) -> SignedEip1559TransactionRequest {
                let created_tx = create_and_record_transaction(
                    transactions,
                    withdrawal_request,
                    gas_fee_estimate(),
                );
                create_and_record_signed_transaction(transactions, created_tx.clone())
            }

            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let mut rng = reproducible_rng();
            let [first_withdrawal, second_withdrawal, third_withdrawal] =
                create_and_record_ck_withdrawal_requests(&mut transactions, &mut rng);
            let first_cketh_ledger_burn_index = first_withdrawal.cketh_ledger_burn_index();
            let second_cketh_ledger_burn_index = second_withdrawal.cketh_ledger_burn_index();

            let sent_tx_0_0 = send_transaction(&mut transactions, first_withdrawal);
            assert_eq!(sent_tx_0_0.nonce(), TransactionNonce::ZERO);
            let sent_tx_0_1 = resubmit_transaction_with_bumped_price(
                &mut transactions,
                sent_tx_0_0.transaction().clone(),
            );
            let hashes_0: BTreeMap<_, _> = vec![sent_tx_0_0, sent_tx_0_1]
                .iter()
                .map(|tx| (tx.hash(), first_cketh_ledger_burn_index))
                .collect();

            let sent_tx_1_0 = send_transaction(&mut transactions, second_withdrawal);
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
                .map(|tx| (tx.hash(), second_cketh_ledger_burn_index))
                .collect();

            let signed_tx = send_transaction(&mut transactions, third_withdrawal);
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
        use crate::eth_rpc_client::responses::TransactionReceipt;
        use crate::map::MultiKeyMap;
        use crate::numeric::{GasAmount, LedgerBurnIndex, TransactionNonce, Wei, WeiPerGas};
        use crate::state::transactions::tests::{
            ckerc20_withdrawal_request_with_index, cketh_withdrawal_request_with_index,
            create_and_record_ck_withdrawal_requests, create_and_record_signed_transaction,
            create_and_record_transaction, dummy_signature, gas_fee_estimate, transaction_receipt,
        };
        use crate::state::transactions::{
            Erc20WithdrawalRequest, EthTransactions, ReimbursementIndex, ReimbursementRequest,
            TransactionStatus, WithdrawalRequest,
        };
        use crate::test_fixtures::expect_panic_with_message;
        use crate::tx::{GasFeeEstimate, SignedEip1559TransactionRequest};
        use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
        use maplit::{btreemap, btreeset};

        #[test]
        fn should_fail_when_sent_transaction_not_found() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let mut rng = reproducible_rng();
            let [withdrawal_request] =
                create_and_record_ck_withdrawal_requests(&mut transactions, &mut rng);
            let cketh_ledger_burn_index = withdrawal_request.cketh_ledger_burn_index();
            let created_tx = create_and_record_transaction(
                &mut transactions,
                withdrawal_request,
                gas_fee_estimate(),
            );
            let signed_tx =
                create_and_record_signed_transaction(&mut transactions, created_tx.clone());

            let wrong_index = LedgerBurnIndex::from(cketh_ledger_burn_index.get() + 1);
            expect_panic_with_message(
                || {
                    transactions.record_finalized_transaction(
                        wrong_index,
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
                    transactions.record_finalized_transaction(
                        cketh_ledger_burn_index,
                        receipt_with_wrong_hash,
                    )
                },
                "no transaction matching receipt",
            );
        }

        #[test]
        fn should_record_cketh_finalized_transaction_and_not_reimburse() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let cketh_ledger_burn_index = LedgerBurnIndex::new(15);
            let withdrawal_request: WithdrawalRequest =
                cketh_withdrawal_request_with_index(cketh_ledger_burn_index).into();
            transactions.record_withdrawal_request(withdrawal_request.clone());
            let created_tx = create_and_record_transaction(
                &mut transactions,
                withdrawal_request.clone(),
                gas_fee_estimate(),
            );
            let signed_tx = create_and_record_signed_transaction(&mut transactions, created_tx);
            let maybe_reimburse_request = transactions
                .maybe_reimburse_requests_iter()
                .find(|r| r.cketh_ledger_burn_index() == cketh_ledger_burn_index)
                .expect("maybe reimburse request not found");
            assert_eq!(maybe_reimburse_request, &withdrawal_request);
            assert!(!transactions.maybe_reimburse.is_empty());

            let receipt = transaction_receipt(&signed_tx, TransactionStatus::Success);
            transactions.record_finalized_transaction(cketh_ledger_burn_index, receipt.clone());

            assert!(transactions.maybe_reimburse.is_empty());
            assert!(transactions.reimbursement_requests.is_empty());
        }

        #[test]
        fn should_not_reimburse_unused_transaction_fee_when_ckerc20_withdrawal_successful() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let cketh_ledger_burn_index = LedgerBurnIndex::new(7);
            let ckerc20_ledger_burn_index = LedgerBurnIndex::new(7);
            let withdrawal_request = ckerc20_withdrawal_request_with_index(
                cketh_ledger_burn_index,
                ckerc20_ledger_burn_index,
            );
            transactions.record_withdrawal_request(withdrawal_request.clone());
            let created_tx = create_and_record_transaction(
                &mut transactions,
                withdrawal_request.clone(),
                gas_fee_estimate(),
            );
            let signed_tx = create_and_record_signed_transaction(&mut transactions, created_tx);
            let receipt = TransactionReceipt {
                gas_used: GasAmount::from(40_000_u32),
                effective_gas_price: WeiPerGas::from(100_u16),
                ..transaction_receipt(&signed_tx, TransactionStatus::Success)
            };
            assert_eq!(
                receipt.effective_transaction_fee(),
                Wei::from(4_000_000_u32)
            );
            transactions.record_finalized_transaction(cketh_ledger_burn_index, receipt.clone());

            assert_eq!(transactions.maybe_reimburse, btreeset! {});
            assert_eq!(transactions.reimbursement_requests, btreemap! {});
        }

        #[test]
        fn should_not_reimburse_when_ckerc20_witdrawal_used_up_transaction_fee() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let cketh_ledger_burn_index = LedgerBurnIndex::new(7);
            let ckerc20_ledger_burn_index = LedgerBurnIndex::new(7);
            let withdrawal_request = Erc20WithdrawalRequest {
                max_transaction_fee: Wei::from(32_500_000_000_000_000_u128),
                ..ckerc20_withdrawal_request_with_index(
                    cketh_ledger_burn_index,
                    ckerc20_ledger_burn_index,
                )
            };
            transactions.record_withdrawal_request(withdrawal_request.clone());
            let created_tx = create_and_record_transaction(
                &mut transactions,
                withdrawal_request.clone(),
                GasFeeEstimate {
                    base_fee_per_gas: WeiPerGas::from(250_000_000_000_u128),
                    max_priority_fee_per_gas: WeiPerGas::ZERO,
                },
            );
            let signed_tx = create_and_record_signed_transaction(&mut transactions, created_tx);
            let receipt = TransactionReceipt {
                gas_used: GasAmount::from(65_000_u32),
                effective_gas_price: WeiPerGas::from(500_000_000_000_u128),
                ..transaction_receipt(&signed_tx, TransactionStatus::Success)
            };
            assert_eq!(
                receipt.effective_transaction_fee(),
                withdrawal_request.max_transaction_fee
            );
            transactions.record_finalized_transaction(cketh_ledger_burn_index, receipt.clone());

            assert_eq!(transactions.maybe_reimburse, btreeset! {});
            assert_eq!(transactions.reimbursement_requests, btreemap! {});
        }

        #[test]
        fn should_reimburse_tokens_when_ckerc20_withdrawal_fails() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let cketh_ledger_burn_index = LedgerBurnIndex::new(7);
            let ckerc20_ledger_burn_index = LedgerBurnIndex::new(7);
            let withdrawal_request = ckerc20_withdrawal_request_with_index(
                cketh_ledger_burn_index,
                ckerc20_ledger_burn_index,
            );
            transactions.record_withdrawal_request(withdrawal_request.clone());
            let created_tx = create_and_record_transaction(
                &mut transactions,
                withdrawal_request.clone(),
                gas_fee_estimate(),
            );
            let signed_tx = create_and_record_signed_transaction(&mut transactions, created_tx);
            let receipt = TransactionReceipt {
                gas_used: GasAmount::from(40_000_u32),
                effective_gas_price: WeiPerGas::from(100_u16),
                ..transaction_receipt(&signed_tx, TransactionStatus::Failure)
            };
            assert_eq!(
                receipt.effective_transaction_fee(),
                Wei::from(4_000_000_u32)
            );
            transactions.record_finalized_transaction(cketh_ledger_burn_index, receipt.clone());
            let expected_ckerc20_reimbursed_amount = withdrawal_request.withdrawal_amount;

            assert_eq!(transactions.maybe_reimburse, btreeset! {});
            assert_eq!(
                transactions.reimbursement_requests,
                btreemap! {
                    ReimbursementIndex::CkErc20 {
                        cketh_ledger_burn_index,
                        ledger_id: withdrawal_request.ckerc20_ledger_id,
                        ckerc20_ledger_burn_index } =>
                    ReimbursementRequest {
                        ledger_burn_index: cketh_ledger_burn_index,
                        reimbursed_amount: expected_ckerc20_reimbursed_amount.change_units(),
                        to: withdrawal_request.from,
                        to_subaccount: withdrawal_request.from_subaccount,
                        transaction_hash: Some(receipt.transaction_hash),
                    }
                }
            );
        }

        #[test]
        fn should_record_finalized_transaction_and_reimburse_unused_tx_fee_when_cketh_withdrawal_fails()
         {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let withdrawal_request = cketh_withdrawal_request_with_index(LedgerBurnIndex::new(15));
            transactions.record_withdrawal_request(withdrawal_request.clone());
            let cketh_ledger_burn_index = withdrawal_request.ledger_burn_index;
            let created_tx = create_and_record_transaction(
                &mut transactions,
                withdrawal_request.clone(),
                gas_fee_estimate(),
            );
            let signed_tx = create_and_record_signed_transaction(&mut transactions, created_tx);
            let maybe_reimburse_request = transactions
                .maybe_reimburse_requests_iter()
                .find(|r| r.cketh_ledger_burn_index() == cketh_ledger_burn_index)
                .expect("maybe reimburse request not found");
            assert_eq!(maybe_reimburse_request, &withdrawal_request.clone().into());

            let receipt = transaction_receipt(&signed_tx, TransactionStatus::Failure);
            transactions.record_finalized_transaction(cketh_ledger_burn_index, receipt.clone());

            let finalized_transaction = transactions
                .get_finalized_transaction(&cketh_ledger_burn_index)
                .expect("finalized tx not found");

            assert!(transactions.maybe_reimburse.is_empty());
            let cketh_reimbursement_index = ReimbursementIndex::CkEth {
                ledger_burn_index: cketh_ledger_burn_index,
            };
            let reimbursement_request = transactions
                .reimbursement_requests
                .get(&cketh_reimbursement_index)
                .expect("reimbursement request not found");
            let effective_fee_paid = finalized_transaction.effective_transaction_fee();
            assert_eq!(
                reimbursement_request,
                &ReimbursementRequest {
                    transaction_hash: Some(receipt.transaction_hash),
                    ledger_burn_index: cketh_ledger_burn_index,
                    to: withdrawal_request.from,
                    to_subaccount: withdrawal_request.from_subaccount,
                    reimbursed_amount: withdrawal_request
                        .withdrawal_amount
                        .checked_sub(effective_fee_paid)
                        .unwrap()
                        .change_units()
                }
            );
        }

        #[test]
        fn should_record_finalized_transaction() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let mut rng = reproducible_rng();
            let [withdrawal_request] =
                create_and_record_ck_withdrawal_requests(&mut transactions, &mut rng);
            let cketh_ledger_burn_index = withdrawal_request.cketh_ledger_burn_index();
            let created_tx = create_and_record_transaction(
                &mut transactions,
                withdrawal_request,
                gas_fee_estimate(),
            );
            let signed_tx = create_and_record_signed_transaction(&mut transactions, created_tx);

            let receipt = transaction_receipt(&signed_tx, TransactionStatus::Success);
            transactions.record_finalized_transaction(cketh_ledger_burn_index, receipt.clone());

            assert_eq!(
                transactions
                    .finalized_transactions_iter()
                    .collect::<Vec<_>>(),
                vec![(
                    &TransactionNonce::ZERO,
                    &cketh_ledger_burn_index,
                    &signed_tx.try_finalize(receipt).unwrap()
                )]
            );
            assert_eq!(transactions.transactions_to_sign_iter().next(), None);
            assert_eq!(transactions.sent_transactions_iter().next(), None);
        }

        #[test]
        fn should_clean_up_failed_resubmitted_transactions_when_finalizing() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let mut rng = reproducible_rng();
            let [withdrawal_request] =
                create_and_record_ck_withdrawal_requests(&mut transactions, &mut rng);
            let cketh_ledger_burn_index = withdrawal_request.cketh_ledger_burn_index();
            let created_tx = create_and_record_transaction(
                &mut transactions,
                withdrawal_request,
                gas_fee_estimate(),
            );
            let signed_tx =
                create_and_record_signed_transaction(&mut transactions, created_tx.clone());
            transactions.record_resubmit_transaction(created_tx.clone());
            assert!(
                transactions
                    .created_tx
                    .contains_alt(&cketh_ledger_burn_index)
            );

            let receipt = transaction_receipt(&signed_tx, TransactionStatus::Success);
            transactions.record_finalized_transaction(cketh_ledger_burn_index, receipt.clone());

            assert_eq!(
                transactions.finalized_tx,
                MultiKeyMap::from_iter(vec![(
                    TransactionNonce::ZERO,
                    cketh_ledger_burn_index,
                    signed_tx.try_finalize(receipt).unwrap()
                )])
            );
            assert_eq!(transactions.transactions_to_sign_iter().next(), None);
            assert_eq!(transactions.sent_transactions_iter().next(), None);
        }
    }

    mod record_quarantined_reimbursement {
        use crate::eth_rpc_client::responses::TransactionStatus;
        use crate::numeric::TransactionNonce;
        use crate::state::transactions::tests::create_ck_withdrawal_requests;
        use crate::state::transactions::tests::eth_transactions::withdrawal_flow;
        use crate::state::transactions::{EthTransactions, ReimbursedError, ReimbursementIndex};
        use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
        use maplit::{btreemap, btreeset};

        #[test]
        fn should_quarantine_reimbursement() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let mut rng = reproducible_rng();
            let [withdrawal_request] = create_ck_withdrawal_requests(&mut rng);
            let reimbursement_index = ReimbursementIndex::from(&withdrawal_request);
            let _eth_transaction = withdrawal_flow(
                &mut transactions,
                withdrawal_request,
                TransactionStatus::Failure,
            );

            transactions.record_quarantined_reimbursement(reimbursement_index.clone());

            assert_eq!(transactions.maybe_reimburse, btreeset! {});
            assert_eq!(transactions.reimbursement_requests, btreemap! {});
            assert_eq!(
                transactions.reimbursed,
                btreemap! {
                    reimbursement_index => Err(ReimbursedError::Quarantined)
                }
            )
        }
    }

    mod transaction_status {
        use crate::endpoints::{RetrieveEthStatus, TxFinalizedStatus};
        use crate::eth_logs::LedgerSubaccount;
        use crate::numeric::{LedgerBurnIndex, LedgerMintIndex, TransactionNonce};
        use crate::state::transactions::tests::{
            ckerc20_withdrawal_request_with_index, cketh_withdrawal_request_with_index,
            create_ck_withdrawal_requests, eth_transactions::withdrawal_flow,
        };
        use crate::state::transactions::{
            EthTransactions, ReimbursementIndex, TransactionStatus, WithdrawalRequest,
            WithdrawalSearchParameter, WithdrawalStatus,
        };
        use ic_crypto_test_utils_reproducible_rng::reproducible_rng;

        pub fn assert_withdrawal_status(
            transactions: &EthTransactions,
            request: &WithdrawalRequest,
            withdrawal_status: Vec<WithdrawalStatus>,
        ) {
            let result = withdrawal_status
                .iter()
                .map(|status| (request, status.clone()))
                .collect::<Vec<_>>();

            assert_eq!(
                transactions
                    .withdrawal_status(&WithdrawalSearchParameter::ByWithdrawalId(
                        request.cketh_ledger_burn_index()
                    ))
                    .into_iter()
                    .map(|(r, s, _)| (r, s))
                    .collect::<Vec<_>>(),
                result
            );

            assert_eq!(
                transactions
                    .withdrawal_status(&WithdrawalSearchParameter::ByRecipient(request.payee()))
                    .into_iter()
                    .map(|(r, s, _)| (r, s))
                    .collect::<Vec<_>>(),
                result
            );

            assert_eq!(
                transactions
                    .withdrawal_status(&WithdrawalSearchParameter::BySenderAccount(
                        icrc_ledger_types::icrc1::account::Account {
                            owner: request.from(),
                            subaccount: request
                                .from_subaccount()
                                .cloned()
                                .map(LedgerSubaccount::to_bytes)
                        }
                    ))
                    .into_iter()
                    .map(|(r, s, _)| (r, s))
                    .collect::<Vec<_>>(),
                result
            );
        }

        #[test]
        fn should_have_finalized_success_status() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let mut rng = reproducible_rng();
            let [withdrawal_request] = create_ck_withdrawal_requests(&mut rng);
            let cketh_ledger_burn_index = withdrawal_request.cketh_ledger_burn_index();

            let receipt = withdrawal_flow(
                &mut transactions,
                withdrawal_request.clone(),
                TransactionStatus::Success,
            );

            let success = TxFinalizedStatus::Success {
                transaction_hash: receipt.transaction_hash.to_string(),
                effective_transaction_fee: Some(receipt.effective_transaction_fee().into()),
            };
            assert_eq!(
                transactions.transaction_status(&cketh_ledger_burn_index),
                RetrieveEthStatus::TxFinalized(success.clone())
            );
            assert_withdrawal_status(
                &transactions,
                &withdrawal_request,
                vec![WithdrawalStatus::TxFinalized(success)],
            );
        }

        #[test]
        fn should_have_finalized_reimbursed_status_for_cketh_withdrawal() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let withdrawal_request = cketh_withdrawal_request_with_index(LedgerBurnIndex::new(15));
            let cketh_ledger_burn_index = withdrawal_request.ledger_burn_index;
            let receipt = withdrawal_flow(
                &mut transactions,
                withdrawal_request.clone(),
                TransactionStatus::Failure,
            );

            let pending_reimbursedment = TxFinalizedStatus::PendingReimbursement((&receipt).into());
            assert_eq!(
                transactions.transaction_status(&cketh_ledger_burn_index),
                RetrieveEthStatus::TxFinalized(pending_reimbursedment.clone())
            );
            assert_withdrawal_status(
                &transactions,
                &withdrawal_request.clone().into(),
                vec![WithdrawalStatus::TxFinalized(pending_reimbursedment)],
            );

            let cketh_reimbursement_index = ReimbursementIndex::CkEth {
                ledger_burn_index: cketh_ledger_burn_index,
            };
            transactions.record_finalized_reimbursement(
                cketh_reimbursement_index,
                LedgerMintIndex::new(16),
            );

            let finalized_transaction = transactions
                .get_finalized_transaction(&cketh_ledger_burn_index)
                .expect("finalized tx not found");
            let effective_fee_paid = finalized_transaction.effective_transaction_fee();

            let reimbursed = TxFinalizedStatus::Reimbursed {
                reimbursed_in_block: candid::Nat::from(16_u8),
                transaction_hash: receipt.transaction_hash.to_string(),
                reimbursed_amount: withdrawal_request
                    .withdrawal_amount
                    .checked_sub(effective_fee_paid)
                    .unwrap()
                    .into(),
            };
            assert_eq!(
                transactions.transaction_status(&cketh_ledger_burn_index),
                RetrieveEthStatus::TxFinalized(reimbursed.clone())
            );
            assert_withdrawal_status(
                &transactions,
                &withdrawal_request.clone().into(),
                vec![WithdrawalStatus::TxFinalized(reimbursed)],
            );
        }

        #[test]
        fn should_have_finalized_reimbursed_status_for_ckerc20_withdrawal() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let withdrawal_request = ckerc20_withdrawal_request_with_index(
                LedgerBurnIndex::new(15),
                LedgerBurnIndex::new(7),
            );
            let cketh_ledger_burn_index = withdrawal_request.cketh_ledger_burn_index;
            let receipt = withdrawal_flow(
                &mut transactions,
                withdrawal_request.clone(),
                TransactionStatus::Failure,
            );

            let pending_reimbursement = TxFinalizedStatus::PendingReimbursement((&receipt).into());
            assert_eq!(
                transactions.transaction_status(&cketh_ledger_burn_index),
                RetrieveEthStatus::TxFinalized(pending_reimbursement.clone())
            );
            assert_withdrawal_status(
                &transactions,
                &withdrawal_request.clone().into(),
                vec![WithdrawalStatus::TxFinalized(pending_reimbursement)],
            );

            let ckerc20_reimbursement_index = ReimbursementIndex::CkErc20 {
                cketh_ledger_burn_index: withdrawal_request.cketh_ledger_burn_index,
                ledger_id: withdrawal_request.ckerc20_ledger_id,
                ckerc20_ledger_burn_index: withdrawal_request.ckerc20_ledger_burn_index,
            };
            transactions.record_finalized_reimbursement(
                ckerc20_reimbursement_index,
                LedgerMintIndex::new(16),
            );

            let reimbursed = TxFinalizedStatus::Reimbursed {
                reimbursed_in_block: candid::Nat::from(16_u8),
                transaction_hash: receipt.transaction_hash.to_string(),
                reimbursed_amount: withdrawal_request.withdrawal_amount.into(),
            };
            assert_eq!(
                transactions.transaction_status(&cketh_ledger_burn_index),
                RetrieveEthStatus::TxFinalized(reimbursed.clone())
            );
            assert_withdrawal_status(
                &transactions,
                &withdrawal_request.clone().into(),
                vec![WithdrawalStatus::TxFinalized(reimbursed)],
            );
        }

        #[test]
        fn should_have_status_pending_reimbursement_for_quarantined_reimbursement() {
            let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
            let mut rng = reproducible_rng();
            let [withdrawal_request] = create_ck_withdrawal_requests(&mut rng);
            let reimbursement_index = ReimbursementIndex::from(&withdrawal_request);
            let receipt = withdrawal_flow(
                &mut transactions,
                withdrawal_request,
                TransactionStatus::Failure,
            );
            transactions.record_quarantined_reimbursement(reimbursement_index.clone());

            assert_eq!(
                transactions.transaction_status(&reimbursement_index.withdrawal_id()),
                RetrieveEthStatus::TxFinalized(TxFinalizedStatus::PendingReimbursement(
                    (&receipt).into()
                ))
            );
        }
    }

    pub fn withdrawal_flow<T: Into<WithdrawalRequest>>(
        transactions: &mut EthTransactions,
        withdrawal_request: T,
        status: TransactionStatus,
    ) -> super::TransactionReceipt {
        use crate::state::transactions::WithdrawalStatus;
        use transaction_status::assert_withdrawal_status;

        let withdrawal_request = withdrawal_request.into();
        let cketh_ledger_burn_index = withdrawal_request.cketh_ledger_burn_index();

        assert_eq!(
            transactions.transaction_status(&cketh_ledger_burn_index),
            RetrieveEthStatus::NotFound
        );
        assert_withdrawal_status(transactions, &withdrawal_request.clone(), vec![]);
        transactions.record_withdrawal_request(withdrawal_request.clone());
        assert_eq!(
            transactions.transaction_status(&cketh_ledger_burn_index),
            RetrieveEthStatus::Pending
        );
        assert_withdrawal_status(
            transactions,
            &withdrawal_request.clone(),
            vec![WithdrawalStatus::Pending],
        );

        let created_tx = create_and_record_transaction(
            transactions,
            withdrawal_request.clone(),
            gas_fee_estimate(),
        );
        assert_eq!(
            transactions.transaction_status(&cketh_ledger_burn_index),
            RetrieveEthStatus::TxCreated
        );
        assert_withdrawal_status(
            transactions,
            &withdrawal_request.clone(),
            vec![WithdrawalStatus::TxCreated],
        );

        let signed_tx = sign_transaction(created_tx);
        let eth_transaction = EthTransaction {
            transaction_hash: signed_tx.hash().to_string(),
        };
        transactions.record_signed_transaction(signed_tx.clone());
        assert_eq!(
            transactions.transaction_status(&cketh_ledger_burn_index),
            RetrieveEthStatus::TxSent(eth_transaction.clone())
        );
        assert_withdrawal_status(
            transactions,
            &withdrawal_request.clone(),
            vec![WithdrawalStatus::TxSent(eth_transaction.clone())],
        );

        let receipt = transaction_receipt(&signed_tx, status);
        transactions.record_finalized_transaction(cketh_ledger_burn_index, receipt.clone());
        receipt
    }
}

mod oldest_incomplete_withdrawal_timestamp {
    use super::*;
    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;

    #[test]
    fn should_return_none_when_no_requests() {
        let transactions = EthTransactions::new(TransactionNonce::ZERO);
        assert_eq!(None, transactions.oldest_incomplete_withdrawal_timestamp());
    }

    #[test]
    fn should_return_created_at_of_one_request() {
        let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
        let mut rng = reproducible_rng();
        let [withdrawal_request] =
            create_and_record_ck_withdrawal_requests(&mut transactions, &mut rng);

        assert_eq!(
            transactions.oldest_incomplete_withdrawal_timestamp(),
            withdrawal_request.created_at(),
        );
    }

    #[test]
    fn should_return_the_min_of_two_requests() {
        let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
        let mut rng = reproducible_rng();
        let [mut first_request, mut second_request] = create_ck_withdrawal_requests(&mut rng);
        set_created_at(&mut first_request, 10);
        set_created_at(&mut second_request, 20);
        transactions.record_withdrawal_request(first_request);
        transactions.record_withdrawal_request(second_request);

        assert_eq!(
            transactions.oldest_incomplete_withdrawal_timestamp(),
            Some(10),
        );
    }

    #[test]
    fn should_work_for_requests_with_transactions() {
        let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
        let mut rng = reproducible_rng();
        let [withdrawal_request] =
            create_and_record_ck_withdrawal_requests(&mut transactions, &mut rng);
        create_and_record_transaction(
            &mut transactions,
            withdrawal_request.clone(),
            gas_fee_estimate(),
        );

        assert_eq!(
            transactions.oldest_incomplete_withdrawal_timestamp(),
            withdrawal_request.created_at(),
        );
    }

    #[test]
    fn should_return_the_min_of_requests_in_all_states() {
        let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
        let mut rng = reproducible_rng();
        let [mut first_request, mut second_request] = create_ck_withdrawal_requests(&mut rng);
        set_created_at(&mut first_request, 10);
        set_created_at(&mut second_request, 20);

        transactions.record_withdrawal_request(first_request.clone());
        transactions.record_withdrawal_request(second_request.clone());
        create_and_record_transaction(&mut transactions, first_request, gas_fee_estimate());

        assert_eq!(
            transactions.oldest_incomplete_withdrawal_timestamp(),
            Some(10),
        );
    }

    #[test]
    fn should_ignore_finalized_requests() {
        let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
        let mut rng = reproducible_rng();
        let [withdrawal_request] =
            create_and_record_ck_withdrawal_requests(&mut transactions, &mut rng);
        let cketh_ledger_burn_index = withdrawal_request.cketh_ledger_burn_index();
        let created_tx = create_and_record_transaction(
            &mut transactions,
            withdrawal_request,
            gas_fee_estimate(),
        );
        let signed_tx = create_and_record_signed_transaction(&mut transactions, created_tx);
        transactions.record_finalized_transaction(
            cketh_ledger_burn_index,
            transaction_receipt(&signed_tx, TransactionStatus::Success),
        );

        assert_eq!(transactions.oldest_incomplete_withdrawal_timestamp(), None);
    }

    fn set_created_at(withdrawal_request: &mut WithdrawalRequest, created_at: u64) {
        match withdrawal_request {
            WithdrawalRequest::CkEth(request) => request.created_at = Some(created_at),
            WithdrawalRequest::CkErc20(request) => request.created_at = created_at,
        }
    }
}

mod eth_withdrawal_request {
    use crate::numeric::LedgerBurnIndex;
    use crate::state::transactions::tests::cketh_withdrawal_request_with_index;

    #[test]
    fn should_have_readable_debug_representation() {
        let request = cketh_withdrawal_request_with_index(LedgerBurnIndex::new(131));
        let expected_debug = "EthWithdrawalRequest { withdrawal_amount: 1_100_000_000_000_000, destination: 0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34, ledger_burn_index: 131, from: k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae, from_subaccount: Some(1111111111111111111111111111111111111111111111111111111111111111), created_at: Some(1699527697000000000) }";
        assert_eq!(format!("{request:?}"), expected_debug);
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
        let expected_debug = "Erc20WithdrawalRequest { max_transaction_fee: 30_000_000_000_000_000, withdrawal_amount: 1_100_000_000_000_000, erc20_contract_address: 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48, destination: 0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34, cketh_ledger_burn_index: 131, ckerc20_ledger_id: sa4so-piaaa-aaaar-qacnq-cai, ckerc20_ledger_burn_index: 2, from: k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae, from_subaccount: Some(1111111111111111111111111111111111111111111111111111111111111111), created_at: 1699527697000000000 }";
        assert_eq!(format!("{request:?}"), expected_debug);
    }
}

mod create_transaction {
    use crate::lifecycle::EthereumNetwork;
    use crate::numeric::{
        Erc20Value, GasAmount, LedgerBurnIndex, TransactionNonce, Wei, WeiPerGas,
    };
    use crate::state::transactions::tests::arbitrary::{arb_address, arb_checked_amount_of};
    use crate::state::transactions::tests::{
        ckerc20_withdrawal_request_with_index, cketh_withdrawal_request_with_index,
        gas_fee_estimate,
    };
    use crate::state::transactions::{
        CreateTransactionError, Erc20WithdrawalRequest, EthWithdrawalRequest, TransactionCallData,
        create_transaction,
    };
    use crate::tx::GasFeeEstimate;
    use crate::tx::{AccessList, Eip1559TransactionRequest};
    use crate::withdraw::CKETH_WITHDRAWAL_TRANSACTION_GAS_LIMIT;
    use proptest::collection::vec as pvec;
    use proptest::prelude::any;
    use proptest::{prop_assert, prop_assert_eq, proptest};

    proptest! {
        #[test]
        fn should_fail_when_amount_does_not_cover_transaction_fees(withdrawal_amount in any::<u64>()) {
            let gas_fee = gas_fee_estimate();
            let gas_limit = CKETH_WITHDRAWAL_TRANSACTION_GAS_LIMIT;
            let transaction_price = gas_fee.clone().to_price(gas_limit);
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
                gas_fee.clone(),
                gas_limit,
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

            let actual_min_max_transaction_fee = gas_fee.min_max_fee_per_gas().transaction_cost(gas_limit).unwrap();
            let insufficient_amount = Wei::from(withdrawal_amount % (actual_min_max_transaction_fee.as_f64() as u64));
            let ckerc20_withdrawal_request = Erc20WithdrawalRequest {
                max_transaction_fee: insufficient_amount,
                ..ckerc20_withdrawal_request_with_index(cketh_ledger_burn_index, LedgerBurnIndex::new(2))
            };
            let result = create_transaction(
                &ckerc20_withdrawal_request.clone().into(),
                TransactionNonce::TWO,
                gas_fee,
                gas_limit,
                EthereumNetwork::Sepolia,
            );
            prop_assert_eq!(
                result,
                Err(CreateTransactionError::InsufficientTransactionFee {
                    cketh_ledger_burn_index,
                    allowed_max_transaction_fee: ckerc20_withdrawal_request.max_transaction_fee,
                    actual_max_transaction_fee: actual_min_max_transaction_fee,
                })
            )
        }
    }

    proptest! {
        #[test]
        fn should_create_transaction(withdrawal_amount in 31_500_001_050_000_u64..=u64::MAX) {
            let gas_fee = gas_fee_estimate();
            let gas_limit = CKETH_WITHDRAWAL_TRANSACTION_GAS_LIMIT;
            let transaction_price = gas_fee.clone().to_price(gas_limit);
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
                gas_fee,
                gas_limit,
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
        fn should_create_ckerc20_withdrawal_transaction(max_transaction_fee in 4_652_229_101_896_296_u128..=u128::MAX) {
            // Example of a USDC transfer
            // https://etherscan.io/tx/0x295846b122356aebb2d426ffdc2510c2f5eecbf5fc359fb24bba8a7ab5fa8616
            let gas_fee = GasFeeEstimate {
                base_fee_per_gas: WeiPerGas::from(0xb9790a88a_u64),
                max_priority_fee_per_gas:  WeiPerGas::from(0x2faf080_u64)
            };
            let gas_limit = GasAmount::from(0x16ca4_u64);
            let min_tx_fee = gas_fee.min_max_fee_per_gas().transaction_cost(gas_limit).unwrap();
            prop_assert_eq!(
                min_tx_fee,
                Wei::from(4_652_229_101_896_296_u128)
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
                gas_fee.clone(),
                gas_limit,
                EthereumNetwork::Mainnet,
            ).unwrap();
            let tx_max_fee_per_gas = result.max_fee_per_gas;
            let max_tx_fee = tx_max_fee_per_gas.transaction_cost(gas_limit).unwrap();

            prop_assert!(min_tx_fee <= max_tx_fee && max_tx_fee <= withdrawal_request.max_transaction_fee);

            prop_assert_eq!(result, Eip1559TransactionRequest {
                    chain_id: EthereumNetwork::Mainnet.chain_id(),
                    nonce: TransactionNonce::from(0x57_u32),
                    max_priority_fee_per_gas: gas_fee.max_priority_fee_per_gas,
                    max_fee_per_gas: tx_max_fee_per_gas,
                    gas_limit,
                    destination: withdrawal_request.erc20_contract_address,
                    amount: Wei::ZERO,
                    data: hex::decode("a9059cbb0000000000000000000000006b9353bf4f90abdb218979b7596fafc3c6c6ac64000000000000000000000000000000000000000000000000000000000204123f").unwrap(),
                    access_list: AccessList::new()
            })
        }
    }

    proptest! {
         #[test]
         fn should_encode_decode_transaction_call_data(to in arb_address(), value in arb_checked_amount_of()) {
             let erc20_transfer = TransactionCallData::Erc20Transfer { to, value };
             let decoded_data = TransactionCallData::decode(erc20_transfer.encode()).unwrap();
             prop_assert_eq!(decoded_data, erc20_transfer);
         }

         #[test]
         fn should_not_panic_when_decoding_transaction_call_data(data_with_expected_length in pvec(any::<u8>(), 68), arb_data in pvec(any::<u8>(), 0..1000)) {
             let _decoded_data = TransactionCallData::decode(data_with_expected_length);
             let _decoded_data = TransactionCallData::decode(arb_data);
         }

    }
}

mod withdrawal_flow {
    use super::arbitrary::{arb_checked_amount_of, arb_gas_fee_estimate, arb_withdrawal_request};
    use crate::numeric::TransactionNonce;
    use crate::state::transactions::tests::sign_transaction;
    use crate::state::transactions::{EthTransactions, EthereumNetwork, create_transaction};
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
                    gas_fee_estimate.clone(),
                    estimate_gas_limit(&request),
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
    use crate::state::transactions::{
        Erc20WithdrawalRequest, EthWithdrawalRequest, WithdrawalRequest,
    };
    use crate::test_fixtures::arb::arb_ledger_subaccount;
    use crate::tx::{
        AccessList, AccessListItem, Eip1559Signature, Eip1559TransactionRequest, GasFeeEstimate,
        SignedEip1559TransactionRequest, StorageKey, TransactionPrice,
    };
    use candid::Principal;
    use ic_ethereum_types::Address;
    use phantom_newtype::Id;
    use proptest::arbitrary::any;
    use proptest::array::{uniform20, uniform32};
    use proptest::collection::vec as pvec;
    use proptest::prelude::BoxedStrategy;
    use proptest::prop_oneof;
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

    pub fn arb_address() -> impl Strategy<Value = Address> {
        uniform20(any::<u8>()).prop_map(Address::new)
    }

    fn arb_principal() -> impl Strategy<Value = Principal> {
        pvec(any::<u8>(), 0..=29).prop_map(|bytes| Principal::from_slice(&bytes))
    }

    pub fn arb_withdrawal_request() -> BoxedStrategy<WithdrawalRequest> {
        prop_oneof![
            arb_cketh_withdrawal_request().prop_map(|req| req.into()),
            arb_ckerc20_withdrawal_request().prop_map(|req| req.into()),
        ]
        .boxed()
    }

    fn arb_cketh_withdrawal_request() -> impl Strategy<Value = EthWithdrawalRequest> {
        (
            arb_checked_amount_of(),
            arb_address(),
            arb_u64_id(),
            arb_principal(),
            arb_ledger_subaccount(),
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

    fn arb_ckerc20_withdrawal_request() -> impl Strategy<Value = Erc20WithdrawalRequest> {
        (
            arb_checked_amount_of(),
            arb_checked_amount_of(),
            arb_address(),
            arb_u64_id(),
            arb_address(),
            arb_principal(),
            arb_u64_id(),
            arb_principal(),
            arb_ledger_subaccount(),
            any::<u64>(),
        )
            .prop_map(
                |(
                    max_transaction_fee,
                    withdrawal_amount,
                    destination,
                    cketh_ledger_burn_index,
                    erc20_contract_address,
                    ckerc20_ledger_id,
                    ckerc20_ledger_burn_index,
                    from,
                    from_subaccount,
                    created_at,
                )| {
                    Erc20WithdrawalRequest {
                        max_transaction_fee,
                        withdrawal_amount,
                        destination,
                        cketh_ledger_burn_index,
                        erc20_contract_address,
                        ckerc20_ledger_id,
                        ckerc20_ledger_burn_index,
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

    pub fn arb_gas_fee_estimate() -> impl Strategy<Value = GasFeeEstimate> {
        (any::<u128>(), any::<u128>()).prop_map(
            |(base_fee_per_gas_next_block, max_priority_fee_per_gas)| GasFeeEstimate {
                base_fee_per_gas: WeiPerGas::new(base_fee_per_gas_next_block),
                max_priority_fee_per_gas: WeiPerGas::new(max_priority_fee_per_gas),
            },
        )
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
        from_subaccount: LedgerSubaccount::from_bytes(DEFAULT_SUBACCOUNT),
        created_at: Some(DEFAULT_CREATED_AT),
    }
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
        ckerc20_ledger_id: candid::Principal::from_str(DEFAULT_CKERC20_LEDGER_ID).unwrap(),
        ckerc20_ledger_burn_index,
        withdrawal_amount: Erc20Value::new(DEFAULT_WITHDRAWAL_AMOUNT),
        from: candid::Principal::from_str(DEFAULT_PRINCIPAL).unwrap(),
        from_subaccount: LedgerSubaccount::from_bytes(DEFAULT_SUBACCOUNT),
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

fn gas_fee_estimate() -> GasFeeEstimate {
    GasFeeEstimate {
        base_fee_per_gas: WeiPerGas::from(25_u8),
        max_priority_fee_per_gas: WeiPerGas::new(0x59682f00),
    }
}

/// Create a mix of ckETH and ckERC20 withdrawal requests and record them.
fn create_and_record_ck_withdrawal_requests<const N: usize, R: Rng>(
    transactions: &mut EthTransactions,
    rng: &mut R,
) -> [WithdrawalRequest; N] {
    let requests = create_ck_withdrawal_requests(rng);
    for request in &requests {
        transactions.record_withdrawal_request(request.clone());
    }
    requests
}

/// Create ckETH withdrawal requests and record them.
fn create_and_record_cketh_withdrawal_requests<const N: usize>(
    transactions: &mut EthTransactions,
) -> [WithdrawalRequest; N] {
    let requests = create_cketh_withdrawal_requests();
    for request in &requests {
        transactions.record_withdrawal_request(request.clone());
    }
    requests
}

/// Create ckERC20 withdrawal requests and record them.
fn create_and_record_ckerc20_withdrawal_requests<const N: usize>(
    transactions: &mut EthTransactions,
) -> [WithdrawalRequest; N] {
    let requests = create_ckerc20_withdrawal_requests();
    for request in &requests {
        transactions.record_withdrawal_request(request.clone());
    }
    requests
}

/// Create a mix of ckETH and ckERC20 withdrawal requests.
fn create_ck_withdrawal_requests<const N: usize, R: Rng>(rng: &mut R) -> [WithdrawalRequest; N] {
    let mut requests = Vec::with_capacity(N);
    let mut is_cketh_withdrawals: [bool; N] = [false; N];
    rng.fill(&mut is_cketh_withdrawals[..]);
    for (i, is_cketh_withdrawal) in is_cketh_withdrawals.into_iter().enumerate() {
        let cketh_ledger_burn_index = LedgerBurnIndex::from(3 * (i as u64));
        let request: WithdrawalRequest = if is_cketh_withdrawal {
            cketh_withdrawal_request_with_index(cketh_ledger_burn_index).into()
        } else {
            let ckerc20_ledger_burn_index = LedgerBurnIndex::from(7 * (i as u64));
            ckerc20_withdrawal_request_with_index(
                cketh_ledger_burn_index,
                ckerc20_ledger_burn_index,
            )
            .into()
        };
        requests.push(request.clone());
    }
    requests.try_into().unwrap()
}

/// Create ckETH withdrawal requests.
fn create_cketh_withdrawal_requests<const N: usize>() -> [WithdrawalRequest; N] {
    let mut requests = Vec::with_capacity(N);
    for i in 1..=N as u64 {
        let cketh_ledger_burn_index = LedgerBurnIndex::from(3 * i);
        let request = cketh_withdrawal_request_with_index(cketh_ledger_burn_index).into();
        requests.push(request);
    }
    requests.try_into().unwrap()
}

/// Create ckERC20 withdrawal requests.
fn create_ckerc20_withdrawal_requests<const N: usize>() -> [WithdrawalRequest; N] {
    let mut requests = Vec::with_capacity(N);
    for i in 1..=N as u64 {
        let cketh_ledger_burn_index = LedgerBurnIndex::from(3 * i);
        let ckerc20_ledger_burn_index = LedgerBurnIndex::from(7 * i);
        let request = ckerc20_withdrawal_request_with_index(
            cketh_ledger_burn_index,
            ckerc20_ledger_burn_index,
        )
        .into();
        requests.push(request);
    }
    requests.try_into().unwrap()
}

fn create_and_record_transaction<R: Into<WithdrawalRequest>>(
    transactions: &mut EthTransactions,
    withdrawal_request: R,
    gas_fee_estimate: GasFeeEstimate,
) -> Eip1559TransactionRequest {
    let withdrawal_request = withdrawal_request.into();
    let burn_index = withdrawal_request.cketh_ledger_burn_index();
    let tx = create_transaction(
        &withdrawal_request,
        transactions.next_transaction_nonce(),
        gas_fee_estimate,
        estimate_gas_limit(&withdrawal_request),
        EthereumNetwork::Sepolia,
    )
    .expect("failed to create transaction");
    transactions.record_created_transaction(withdrawal_request.cketh_ledger_burn_index(), tx);
    transactions
        .created_tx
        .get_alt(&burn_index)
        .unwrap()
        .as_ref()
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
    let initial_price = created_tx.transaction_price();
    let new_tx = Eip1559TransactionRequest {
        max_fee_per_gas: increase_by_10_percent(initial_price.max_fee_per_gas),
        max_priority_fee_per_gas: increase_by_10_percent(initial_price.max_priority_fee_per_gas),
        gas_limit: initial_price.gas_limit,
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

fn double_and_increment<T>(amount: CheckedAmountOf<T>) -> CheckedAmountOf<T> {
    amount
        .checked_mul(2_u8)
        .and_then(|f| f.checked_increment())
        .unwrap()
}

pub fn increase_by_10_percent<T>(amount: CheckedAmountOf<T>) -> CheckedAmountOf<T> {
    amount
        .checked_add(
            amount
                .checked_div_ceil(10_u8)
                .expect("BUG: must be Some() because divisor is non-zero"),
        )
        .unwrap_or(CheckedAmountOf::MAX)
}
