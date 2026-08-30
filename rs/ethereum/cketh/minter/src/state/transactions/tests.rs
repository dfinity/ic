use crate::checked_amount::CheckedAmountOf;
use crate::eth_logs::LedgerSubaccount;
use crate::eth_rpc::Hash;
use crate::eth_rpc_client::responses::{TransactionReceipt, TransactionStatus};
use crate::lifecycle::EthereumNetwork;
use crate::numeric::{
    BlockNumber, Erc20Value, GasAmount, LedgerBurnIndex, TransactionNonce, Wei, WeiPerGas,
};
use crate::state::transactions::{
    Erc20WithdrawalRequest, EthWithdrawalRequest, MinterTransactionPipeline, PipelineRequest,
    WithdrawalRequest, WithdrawalTransactions,
};
use crate::tx::{
    AccessList, Eip1559TransactionRequest, GasFeeEstimate, SignableTransaction, Signed,
    SignedEip1559TransactionRequest, TransactionSignature,
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

mod withdrawal_transactions {
    use crate::endpoints::{EthTransaction, RetrieveEthStatus};
    use crate::numeric::{LedgerBurnIndex, TransactionNonce};
    use crate::state::transactions::tests::{
        cketh_withdrawal_request_with_index, create_and_record_transaction, gas_fee_estimate,
        sign_transaction, transaction_receipt,
    };
    use crate::state::transactions::{
        TransactionStatus, WithdrawalRequest, WithdrawalTransactions,
    };

    mod record_request {
        use super::*;
        use crate::state::transactions::WithdrawalRequest;
        use crate::state::transactions::tests::{
            ckerc20_withdrawal_request_with_index, create_and_record_signed_transaction,
            create_and_record_transaction, gas_fee_estimate, transaction_receipt,
        };
        use crate::test_fixtures::expect_panic_with_message;

        #[test]
        fn should_record_request() {
            fn test<R: Into<WithdrawalRequest> + Clone>(withdrawal_request: R) {
                let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
                transactions.record_request(withdrawal_request.clone());

                assert_eq!(
                    transactions.requests_batch(5),
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
                let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
                transactions.record_request(withdrawal_request.clone());

                expect_panic_with_message(
                    || transactions.record_request(duplicate_index.clone()),
                    "duplicate transaction id",
                );

                let created_tx = create_and_record_transaction(
                    &mut transactions,
                    withdrawal_request.clone(),
                    gas_fee_estimate(),
                );
                expect_panic_with_message(
                    || transactions.record_request(duplicate_index.clone()),
                    "duplicate transaction id",
                );

                let signed_tx = create_and_record_signed_transaction(&mut transactions, created_tx);
                expect_panic_with_message(
                    || transactions.record_request(duplicate_index.clone()),
                    "duplicate transaction id",
                );

                transactions.record_finalized_transaction(
                    withdrawal_request.into().cketh_ledger_burn_index(),
                    transaction_receipt(&signed_tx, TransactionStatus::Success),
                );
                expect_panic_with_message(
                    || transactions.record_request(duplicate_index.clone()),
                    "duplicate transaction id",
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

    mod requests_batch {
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
            let transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
            assert_eq!(transactions.requests_batch(5), vec![]);
        }

        #[test]
        fn should_retrieve_the_first_withdrawal_requests() {
            let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
            let mut rng = reproducible_rng();
            let withdrawal_requests: [WithdrawalRequest; 5] =
                create_and_record_ck_withdrawal_requests(&mut transactions, &mut rng);

            let requests = transactions.requests_batch(0);
            assert_eq!(requests, vec![]);

            let requests = transactions.requests_batch(1);
            assert_eq!(requests.as_slice(), &withdrawal_requests[0..=0]);

            let requests = transactions.requests_batch(2);
            assert_eq!(&requests, &withdrawal_requests[0..=1]);
        }

        proptest! {
            #[test]
            fn should_retrieve_all_withdrawal_requests_in_order(batch_size in 3..100_usize) {
                let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
                let mut rng = reproducible_rng();
                let withdrawal_requests: [WithdrawalRequest; 3] =
                    create_and_record_ck_withdrawal_requests(&mut transactions, &mut rng);

                let requests = transactions.requests_batch(batch_size);

                prop_assert_eq!(requests, withdrawal_requests);
            }
        }

        #[test]
        fn should_limit_batch_size_when_too_many_pending_transactions() {
            let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
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
                transactions.requests_batch(3).as_slice(),
                &withdrawal_requests[997..=999]
            );

            create_and_record_pending_transaction(
                &mut transactions,
                withdrawal_requests[997].clone(),
                rng.r#gen(),
            );
            assert_eq!(
                transactions.requests_batch(3).as_slice(),
                &withdrawal_requests[998..=999]
            );

            create_and_record_pending_transaction(
                &mut transactions,
                withdrawal_requests[998].clone(),
                rng.r#gen(),
            );
            assert_eq!(
                transactions.requests_batch(3).as_slice(),
                &withdrawal_requests[999..=999]
            );

            create_and_record_pending_transaction(
                &mut transactions,
                withdrawal_requests[999].clone(),
                rng.r#gen(),
            );
            assert_eq!(transactions.requests_batch(3), vec![]);
        }

        fn create_and_record_pending_transaction<R: Into<WithdrawalRequest>>(
            transactions: &mut WithdrawalTransactions,
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

    mod reschedule_request {
        use crate::numeric::TransactionNonce;
        use crate::state::transactions::WithdrawalTransactions;
        use crate::state::transactions::tests::create_and_record_ck_withdrawal_requests;
        use ic_crypto_test_utils_reproducible_rng::reproducible_rng;

        #[test]
        fn should_reschedule_withdrawal_request() {
            let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
            let mut rng = reproducible_rng();
            let [first_request, second_request, third_request] =
                create_and_record_ck_withdrawal_requests(&mut transactions, &mut rng);
            // 3 -> 2 -> 1
            assert_eq!(
                transactions.requests_batch(5),
                vec![
                    first_request.clone(),
                    second_request.clone(),
                    third_request.clone()
                ]
            );

            transactions.reschedule_request(first_request.cketh_ledger_burn_index());
            // 1 -> 3 -> 2
            assert_eq!(
                transactions.requests_batch(5),
                vec![
                    second_request.clone(),
                    third_request.clone(),
                    first_request.clone(),
                ]
            );

            transactions.reschedule_request(second_request.cketh_ledger_burn_index());
            // 2 -> 1 -> 3
            assert_eq!(
                transactions.requests_batch(5),
                vec![
                    third_request.clone(),
                    first_request.clone(),
                    second_request.clone(),
                ]
            );

            transactions.reschedule_request(third_request.cketh_ledger_burn_index());
            // 3 -> 2 -> 1
            assert_eq!(
                transactions.requests_batch(5),
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
        use crate::state::transactions::{
            PipelineRequest, WithdrawalRequest, WithdrawalTransactions,
        };
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
            let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
            let mut rng = reproducible_rng();
            let [withdrawal_request] = create_ck_withdrawal_requests(&mut rng);
            let tx = withdrawal_request
                .clone()
                .create_transaction(
                    TransactionNonce::ZERO,
                    gas_fee_estimate(),
                    estimate_gas_limit(&withdrawal_request),
                    EthereumNetwork::Sepolia,
                )
                .unwrap();

            let burn_index = withdrawal_request.cketh_ledger_burn_index();
            expect_panic_with_message(
                || transactions.record_created_transaction(burn_index, tx),
                &format!("request {burn_index} not found"),
            );
        }

        #[test]
        fn should_fail_when_mismatch_with_cketh_withdrawal_request() {
            let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
            let withdrawal_request = cketh_withdrawal_request_with_index(LedgerBurnIndex::new(15));
            transactions.record_request(withdrawal_request.clone());
            let pipeline_request: WithdrawalRequest = withdrawal_request.clone().into();
            let correct_tx = pipeline_request
                .create_transaction(
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
            let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
            let withdrawal_request = ckerc20_withdrawal_request_with_index(
                LedgerBurnIndex::new(3),
                LedgerBurnIndex::new(7),
            );
            transactions.record_request(withdrawal_request.clone());
            let pipeline_request: WithdrawalRequest = withdrawal_request.clone().into();
            let correct_tx = pipeline_request
                .create_transaction(
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
                let mut transactions = WithdrawalTransactions::new(current_nonce);
                let mut rng = reproducible_rng();
                let [withdrawal_request] = create_and_record_ck_withdrawal_requests(&mut transactions, &mut rng);
                let tx_with_wrong_nonce = withdrawal_request.clone().create_transaction(
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
            let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
            let transaction_price = gas_fee_estimate();
            for i in 0..100_u64 {
                let ledger_burn_index = LedgerBurnIndex::new(15 + i);
                let withdrawal_request = cketh_withdrawal_request_with_index(ledger_burn_index);
                transactions.record_request(withdrawal_request.clone());
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
                assert_eq!(
                    transactions.next_transaction_nonce(),
                    TransactionNonce::from(i + 1)
                );
            }
        }

        #[test]
        fn should_create_and_record_ckerc20_transactions() {
            let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
            let gas_fee_estimate = gas_fee_estimate();
            for i in 0..100_u64 {
                let cketh_ledger_burn_index = LedgerBurnIndex::new(3 * i);
                let ckerc20_ledger_burn_index = LedgerBurnIndex::new(7 * i);
                let withdrawal_request = ckerc20_withdrawal_request_with_index(
                    cketh_ledger_burn_index,
                    ckerc20_ledger_burn_index,
                );
                transactions.record_request(withdrawal_request.clone());
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
                assert_eq!(
                    transactions.next_transaction_nonce(),
                    TransactionNonce::from(i + 1)
                );
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
            let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
            let mut rng = reproducible_rng();
            let [withdrawal_request] =
                create_and_record_ck_withdrawal_requests(&mut transactions, &mut rng);

            let _created_tx = create_and_record_transaction(
                &mut transactions,
                withdrawal_request,
                gas_fee_estimate(),
            );

            assert_eq!(transactions.requests_batch(1), vec![]);
        }
    }

    mod record_signed_transaction {
        use super::super::arbitrary::arb_signed_eip_1559_transaction_request_with_nonce;
        use crate::numeric::TransactionNonce;
        use crate::state::transactions::tests::{
            create_and_record_ck_withdrawal_requests, create_and_record_transaction,
            gas_fee_estimate, sent_transactions, sign_transaction, signed_transaction_with_nonce,
        };
        use crate::state::transactions::{WithdrawalRequest, WithdrawalTransactions};
        use crate::test_fixtures::expect_panic_with_message;
        use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
        use proptest::{prop_assume, proptest};

        #[test]
        #[should_panic(expected = "missing created transaction")]
        fn should_fail_when_created_transaction_not_found() {
            let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
            transactions
                .record_signed_transaction(signed_transaction_with_nonce(TransactionNonce::ZERO));
        }

        #[test]
        fn should_record_signed_transactions() {
            let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
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
                    sent_transactions(&transactions, &cketh_ledger_burn_index),
                    Some(vec![&signed_tx])
                );
            }
        }

        proptest! {
            #[test]
            fn should_fail_when_signed_transaction_does_not_match_created_transaction(
                bad_tx in arb_signed_eip_1559_transaction_request_with_nonce(TransactionNonce::ZERO)
            ) {
                let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
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
            let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
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
            create_and_record_transaction, double_and_increment, first_sent_transaction,
            gas_fee_estimate,
        };
        use crate::state::transactions::{
            ResubmitTransactionError, WithdrawalRequest, WithdrawalTransactions,
        };
        use crate::tx::{Eip1559TransactionRequest, GasFeeEstimate};
        use ic_crypto_test_utils_reproducible_rng::reproducible_rng;

        #[test]
        fn should_be_empty_when_no_sent_transactions() {
            let transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
            let resubmitted_txs = transactions
                .create_resubmit_transactions(TransactionCount::ZERO, gas_fee_estimate());

            assert_eq!(resubmitted_txs, vec![]);
        }

        #[test]
        fn should_be_empty_when_all_sent_transactions_already_mined() {
            let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
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
            let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
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
                let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
                let withdrawal_request = withdrawal_request.into();
                let cketh_ledger_burn_index = withdrawal_request.cketh_ledger_burn_index();
                transactions.record_request(withdrawal_request.clone());
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
                    WithdrawalRequest::CkEth(_) | WithdrawalRequest::SweeperFunding(_) => {
                        initial_tx
                            .amount
                            .checked_sub(test.resubmitted_cketh_tx_amount_deduction)
                            .unwrap()
                    }
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
            let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
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
                let initial_transaction = first_sent_transaction(&transactions, &withdrawal_id);
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
            let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
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
                let initial_transaction = first_sent_transaction(&transactions, &withdrawal_id);
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
                    id: 93_u64.into(),
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
            WithdrawalRequest, WithdrawalTransactions, equal_ignoring_fee_and_amount,
        };
        use crate::test_fixtures::expect_panic_with_message;
        use crate::tx::{Eip1559TransactionRequest, GasFeeEstimate};
        use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
        use proptest::{prop_assume, proptest};

        #[test]
        fn should_fail_when_no_sent_tx() {
            let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
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
                let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
                let withdrawal_request = withdrawal_request.into();
                let cketh_ledger_burn_index = withdrawal_request.cketh_ledger_burn_index();
                transactions.record_request(withdrawal_request.clone());
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
                let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
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
                let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
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
                transactions.record_request(withdrawal_request.clone());
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
        use crate::state::transactions::WithdrawalTransactions;
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
                let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
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
            let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
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
            transactions: &WithdrawalTransactions,
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
        use crate::state::transactions::{WithdrawalRequest, WithdrawalTransactions};
        use crate::tx::SignedEip1559TransactionRequest;
        use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
        use proptest::proptest;
        use std::collections::BTreeMap;

        proptest! {
            #[test]
            fn should_be_empty_when_no_transaction_to_finalize(finalized_tx_count in arb_checked_amount_of()) {
                let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
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
                transactions: &mut WithdrawalTransactions,
                withdrawal_request: WithdrawalRequest,
            ) -> SignedEip1559TransactionRequest {
                let created_tx = create_and_record_transaction(
                    transactions,
                    withdrawal_request,
                    gas_fee_estimate(),
                );
                create_and_record_signed_transaction(transactions, created_tx.clone())
            }

            let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
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
            let hashes_0: BTreeMap<_, _> = [sent_tx_0_0, sent_tx_0_1]
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
            let hashes_1: BTreeMap<_, _> = [sent_tx_1_0, sent_tx_1_1, sent_tx_1_2]
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
        use crate::endpoints::RetrieveEthStatus;
        use crate::eth_rpc_client::responses::TransactionReceipt;
        use crate::numeric::{GasAmount, LedgerBurnIndex, TransactionNonce, Wei, WeiPerGas};
        use crate::state::transactions::tests::{
            ckerc20_withdrawal_request_with_index, cketh_withdrawal_request_with_index,
            create_and_record_ck_withdrawal_requests, create_and_record_signed_transaction,
            create_and_record_transaction, dummy_signature, gas_fee_estimate, transaction_receipt,
        };
        use crate::state::transactions::{
            Erc20WithdrawalRequest, ReimbursementIndex, ReimbursementRequest, TransactionStatus,
            WithdrawalRequest, WithdrawalTransactions,
        };
        use crate::test_fixtures::expect_panic_with_message;
        use crate::tx::{GasFeeEstimate, SignedEip1559TransactionRequest};
        use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
        use maplit::{btreemap, btreeset};

        #[test]
        fn should_fail_when_sent_transaction_not_found() {
            let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
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
            let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
            let cketh_ledger_burn_index = LedgerBurnIndex::new(15);
            let withdrawal_request: WithdrawalRequest =
                cketh_withdrawal_request_with_index(cketh_ledger_burn_index).into();
            transactions.record_request(withdrawal_request.clone());
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
            let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
            let cketh_ledger_burn_index = LedgerBurnIndex::new(7);
            let ckerc20_ledger_burn_index = LedgerBurnIndex::new(7);
            let withdrawal_request = ckerc20_withdrawal_request_with_index(
                cketh_ledger_burn_index,
                ckerc20_ledger_burn_index,
            );
            transactions.record_request(withdrawal_request.clone());
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
            let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
            let cketh_ledger_burn_index = LedgerBurnIndex::new(7);
            let ckerc20_ledger_burn_index = LedgerBurnIndex::new(7);
            let withdrawal_request = Erc20WithdrawalRequest {
                max_transaction_fee: Wei::from(32_500_000_000_000_000_u128),
                ..ckerc20_withdrawal_request_with_index(
                    cketh_ledger_burn_index,
                    ckerc20_ledger_burn_index,
                )
            };
            transactions.record_request(withdrawal_request.clone());
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
            let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
            let cketh_ledger_burn_index = LedgerBurnIndex::new(7);
            let ckerc20_ledger_burn_index = LedgerBurnIndex::new(7);
            let withdrawal_request = ckerc20_withdrawal_request_with_index(
                cketh_ledger_burn_index,
                ckerc20_ledger_burn_index,
            );
            transactions.record_request(withdrawal_request.clone());
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
            let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
            let withdrawal_request = cketh_withdrawal_request_with_index(LedgerBurnIndex::new(15));
            transactions.record_request(withdrawal_request.clone());
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
            let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
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
            let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
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
            assert_eq!(
                transactions.transaction_status(&cketh_ledger_burn_index),
                RetrieveEthStatus::TxCreated
            );

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
    }

    mod record_quarantined_reimbursement {
        use crate::eth_rpc_client::responses::TransactionStatus;
        use crate::numeric::TransactionNonce;
        use crate::state::transactions::tests::create_ck_withdrawal_requests;
        use crate::state::transactions::tests::withdrawal_transactions::withdrawal_flow;
        use crate::state::transactions::{
            ReimbursedError, ReimbursementIndex, WithdrawalTransactions,
        };
        use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
        use maplit::{btreemap, btreeset};

        #[test]
        fn should_quarantine_reimbursement() {
            let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
            let mut rng = reproducible_rng();
            let [withdrawal_request] = create_ck_withdrawal_requests(&mut rng);
            let reimbursement_index = ReimbursementIndex::try_from(&withdrawal_request)
                .expect("BUG: create_ck_withdrawal_requests only builds user withdrawals");
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
            create_ck_withdrawal_requests, withdrawal_transactions::withdrawal_flow,
        };
        use crate::state::transactions::{
            ReimbursementIndex, TransactionStatus, WithdrawalRequest, WithdrawalSearchParameter,
            WithdrawalStatus, WithdrawalTransactions,
        };
        use ic_crypto_test_utils_reproducible_rng::reproducible_rng;

        pub fn assert_withdrawal_status(
            transactions: &WithdrawalTransactions,
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
            let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
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
            let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
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
            let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
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
            let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
            let mut rng = reproducible_rng();
            let [withdrawal_request] = create_ck_withdrawal_requests(&mut rng);
            let reimbursement_index = ReimbursementIndex::try_from(&withdrawal_request)
                .expect("BUG: create_ck_withdrawal_requests only builds user withdrawals");
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
        transactions: &mut WithdrawalTransactions,
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
        transactions.record_request(withdrawal_request.clone());
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

    mod sweeper_funding {
        use super::withdrawal_flow;
        use super::*;
        use crate::eth_logs::LedgerSubaccount;
        use crate::lifecycle::EthereumNetwork;
        use crate::numeric::TransactionCount;
        use crate::numeric::{Wei, WeiPerGas};
        use crate::state::transactions::ResubmitTransactionError;
        use crate::state::transactions::tests::{
            DEFAULT_CREATED_AT, DEFAULT_PRINCIPAL, DEFAULT_WITHDRAWAL_AMOUNT,
            ckerc20_withdrawal_request_with_index, create_and_record_signed_transaction,
        };
        use crate::state::transactions::{
            CreateTransactionError, EthWithdrawalRequest, NotReimbursable, PipelineRequest,
            ReimbursementIndex,
        };
        use crate::tx::GasFeeEstimate;
        use crate::withdraw::CKETH_WITHDRAWAL_TRANSACTION_GAS_LIMIT;
        use assert_matches::assert_matches;
        use ic_ethereum_types::Address;
        use maplit::{btreemap, btreeset};
        use std::str::FromStr;

        fn sweeper_funding_payload() -> EthWithdrawalRequest {
            EthWithdrawalRequest {
                withdrawal_amount: Wei::new(DEFAULT_WITHDRAWAL_AMOUNT),
                destination: Address::new([0x53; 20]),
                ledger_burn_index: LedgerBurnIndex::new(15),
                from: candid::Principal::from_str(DEFAULT_PRINCIPAL).unwrap(),
                from_subaccount: LedgerSubaccount::from_bytes(crate::CKETH_FEE_SUBACCOUNT),
                created_at: Some(DEFAULT_CREATED_AT),
            }
        }

        fn sweeper_funding_request() -> WithdrawalRequest {
            WithdrawalRequest::SweeperFunding(sweeper_funding_payload())
        }

        #[test]
        fn should_not_be_reimbursable() {
            let request = sweeper_funding_request();

            assert!(!request.is_reimbursable());
            assert_eq!(
                ReimbursementIndex::try_from(&request),
                Err(NotReimbursable),
                "a funding request must not yield a reimbursement index"
            );
        }

        #[test]
        fn should_report_the_outstanding_funding_until_its_transaction_finalizes() {
            let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
            let funding = sweeper_funding_payload();

            transactions.record_request(sweeper_funding_request());
            assert_eq!(
                transactions.outstanding_sweeper_funding(),
                Some(&funding),
                "a queued funding is outstanding"
            );

            let created_tx = create_and_record_transaction(
                &mut transactions,
                sweeper_funding_request(),
                gas_fee_estimate(),
            );
            assert_eq!(
                transactions.outstanding_sweeper_funding(),
                Some(&funding),
                "a funding whose transaction is waiting to be signed is outstanding"
            );

            let signed_tx = create_and_record_signed_transaction(&mut transactions, created_tx);
            assert_eq!(
                transactions.outstanding_sweeper_funding(),
                Some(&funding),
                "a funding whose transaction was sent is outstanding until it finalizes"
            );

            transactions.record_finalized_transaction(
                funding.ledger_burn_index,
                transaction_receipt(&signed_tx, TransactionStatus::Success),
            );
            assert_eq!(
                transactions.outstanding_sweeper_funding(),
                None,
                "a finalized funding is no longer outstanding, however long it stays among the \
                 processed requests"
            );
        }

        #[test]
        fn should_not_report_a_user_withdrawal_as_an_outstanding_funding() {
            let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
            let cketh = cketh_withdrawal_request_with_index(LedgerBurnIndex::new(15));

            transactions.record_request(cketh.clone());
            transactions.record_request(ckerc20_withdrawal_request_with_index(
                LedgerBurnIndex::new(16),
                LedgerBurnIndex::new(17),
            ));
            assert_eq!(transactions.outstanding_sweeper_funding(), None);

            let created_tx =
                create_and_record_transaction(&mut transactions, cketh, gas_fee_estimate());
            create_and_record_signed_transaction(&mut transactions, created_tx);

            assert_eq!(
                transactions.outstanding_sweeper_funding(),
                None,
                "only a funding is a funding, at whatever stage the others are"
            );
        }

        #[test]
        fn should_never_enter_maybe_reimburse() {
            let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
            let funding = sweeper_funding_request();

            transactions.record_request(funding.clone());
            let created_tx = create_and_record_transaction(
                &mut transactions,
                funding.clone(),
                gas_fee_estimate(),
            );
            create_and_record_signed_transaction(&mut transactions, created_tx);

            assert_eq!(
                transactions.maybe_reimburse,
                btreeset! {},
                "funding must not be tracked for reimbursement"
            );
        }

        #[test]
        fn should_not_reimburse_a_failed_funding() {
            for status in [TransactionStatus::Success, TransactionStatus::Failure] {
                let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);

                let _receipt =
                    withdrawal_flow(&mut transactions, sweeper_funding_request(), status);

                assert_eq!(transactions.maybe_reimburse, btreeset! {});
                assert_eq!(
                    transactions.reimbursement_requests,
                    btreemap! {},
                    "a {status:?} funding must not create a reimbursement request"
                );
                assert_eq!(transactions.reimbursed, btreemap! {});
            }
        }

        #[test]
        fn should_still_reimburse_a_failed_user_withdrawal() {
            let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);

            let _receipt = withdrawal_flow(
                &mut transactions,
                cketh_withdrawal_request_with_index(LedgerBurnIndex::new(15)),
                TransactionStatus::Failure,
            );

            assert_eq!(
                transactions.reimbursement_requests.len(),
                1,
                "a failed user withdrawal must still be reimbursed"
            );
        }

        #[test]
        fn should_deduct_the_transaction_fee_from_the_funded_amount() {
            let funding = sweeper_funding_payload();
            let gas_fee = gas_fee_estimate();
            let expected_fee = gas_fee
                .clone()
                .to_price(CKETH_WITHDRAWAL_TRANSACTION_GAS_LIMIT)
                .max_transaction_fee();

            let tx = WithdrawalRequest::SweeperFunding(funding.clone())
                .create_transaction(
                    TransactionNonce::ZERO,
                    gas_fee,
                    CKETH_WITHDRAWAL_TRANSACTION_GAS_LIMIT,
                    EthereumNetwork::Mainnet,
                )
                .expect("the funded amount must cover the fee");

            assert_eq!(tx.destination, funding.destination);
            assert_eq!(
                tx.amount,
                funding
                    .withdrawal_amount
                    .checked_sub(expected_fee)
                    .expect("test setup: the fee must fit inside the funded amount"),
                "the ETH delivered is the burn minus the fee, so total spend never exceeds the burn"
            );
            assert!(tx.data.is_empty(), "funding is a plain value transfer");
        }

        #[test]
        fn should_fail_to_create_a_transaction_when_the_fee_exceeds_the_funded_amount() {
            let funding = EthWithdrawalRequest {
                withdrawal_amount: Wei::new(1),
                ..sweeper_funding_payload()
            };
            let expected_index = funding.ledger_burn_index;

            assert_matches!(
                WithdrawalRequest::SweeperFunding(funding).create_transaction(
                    TransactionNonce::ZERO,
                    gas_fee_estimate(),
                    CKETH_WITHDRAWAL_TRANSACTION_GAS_LIMIT,
                    EthereumNetwork::Mainnet,
                ),
                Err(CreateTransactionError::InsufficientTransactionFee {
                    cketh_ledger_burn_index,
                    allowed_max_transaction_fee,
                    ..
                }) if cketh_ledger_burn_index == expected_index
                    && allowed_max_transaction_fee == Wei::new(1)
            );
        }

        #[test]
        fn should_cap_resubmission_at_the_funded_amount() {
            let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
            let funding = sweeper_funding_payload();
            let request = WithdrawalRequest::SweeperFunding(funding.clone());
            transactions.record_request(request.clone());
            let created_tx =
                create_and_record_transaction(&mut transactions, request, gas_fee_estimate());
            create_and_record_signed_transaction(&mut transactions, created_tx);

            let spiked_fee = GasFeeEstimate {
                base_fee_per_gas: WeiPerGas::from(10_000_000_000_000_u64),
                ..gas_fee_estimate()
            };
            let resubmitted =
                transactions.create_resubmit_transactions(TransactionCount::ZERO, spiked_fee);

            assert_matches!(
                resubmitted.first().expect("BUG: nothing to resubmit"),
                Err(ResubmitTransactionError::InsufficientTransactionFee {
                    allowed_max_transaction_fee,
                    max_transaction_fee,
                    ..
                }) if *allowed_max_transaction_fee == funding.withdrawal_amount
                    && *max_transaction_fee > funding.withdrawal_amount
            );
        }

        #[test]
        fn should_use_the_plain_transfer_gas_limit() {
            let request = sweeper_funding_request();

            assert_eq!(
                crate::withdraw::estimate_gas_limit(&request),
                crate::withdraw::CKETH_WITHDRAWAL_TRANSACTION_GAS_LIMIT,
            );
        }
    }
}

mod oldest_incomplete_request_timestamp {
    use super::*;
    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;

    #[test]
    fn should_return_none_when_no_requests() {
        let transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
        assert_eq!(None, transactions.oldest_incomplete_request_timestamp());
    }

    #[test]
    fn should_return_created_at_of_one_request() {
        let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
        let mut rng = reproducible_rng();
        let [withdrawal_request] =
            create_and_record_ck_withdrawal_requests(&mut transactions, &mut rng);

        assert_eq!(
            transactions.oldest_incomplete_request_timestamp(),
            withdrawal_request.created_at(),
        );
    }

    #[test]
    fn should_return_the_min_of_two_requests() {
        let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
        let mut rng = reproducible_rng();
        let [mut first_request, mut second_request] = create_ck_withdrawal_requests(&mut rng);
        set_created_at(&mut first_request, 10);
        set_created_at(&mut second_request, 20);
        transactions.record_request(first_request);
        transactions.record_request(second_request);

        assert_eq!(transactions.oldest_incomplete_request_timestamp(), Some(10),);
    }

    #[test]
    fn should_work_for_requests_with_transactions() {
        let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
        let mut rng = reproducible_rng();
        let [withdrawal_request] =
            create_and_record_ck_withdrawal_requests(&mut transactions, &mut rng);
        create_and_record_transaction(
            &mut transactions,
            withdrawal_request.clone(),
            gas_fee_estimate(),
        );

        assert_eq!(
            transactions.oldest_incomplete_request_timestamp(),
            withdrawal_request.created_at(),
        );
    }

    #[test]
    fn should_return_the_min_of_requests_in_all_states() {
        let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
        let mut rng = reproducible_rng();
        let [mut first_request, mut second_request] = create_ck_withdrawal_requests(&mut rng);
        set_created_at(&mut first_request, 10);
        set_created_at(&mut second_request, 20);

        transactions.record_request(first_request.clone());
        transactions.record_request(second_request.clone());
        create_and_record_transaction(&mut transactions, first_request, gas_fee_estimate());

        assert_eq!(transactions.oldest_incomplete_request_timestamp(), Some(10),);
    }

    #[test]
    fn should_ignore_finalized_requests() {
        let mut transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
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

        assert_eq!(transactions.oldest_incomplete_request_timestamp(), None);
    }

    fn set_created_at(withdrawal_request: &mut WithdrawalRequest, created_at: u64) {
        match withdrawal_request {
            WithdrawalRequest::CkEth(request) | WithdrawalRequest::SweeperFunding(request) => {
                request.created_at = Some(created_at)
            }
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
        CreateTransactionError, Erc20WithdrawalRequest, EthWithdrawalRequest, PipelineRequest,
        TransactionCallData, WithdrawalRequest,
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
            let pipeline_request: WithdrawalRequest = cketh_withdrawal_request.clone().into();
            let result = pipeline_request.create_transaction(
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
            let pipeline_request: WithdrawalRequest = ckerc20_withdrawal_request.clone().into();
            let result = pipeline_request.create_transaction(
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

            let pipeline_request: WithdrawalRequest = withdrawal_request.clone().into();
            let result = pipeline_request.create_transaction(
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

            let pipeline_request: WithdrawalRequest = withdrawal_request.clone().into();
            let result = pipeline_request.create_transaction(
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
    use crate::lifecycle::EthereumNetwork;
    use crate::numeric::TransactionNonce;
    use crate::state::transactions::tests::sign_transaction;
    use crate::state::transactions::{PipelineRequest, WithdrawalTransactions};
    use crate::withdraw::estimate_gas_limit;
    use proptest::proptest;
    use std::cell::RefCell;

    #[test]
    fn should_not_panic() {
        let transactions = WithdrawalTransactions::new(TransactionNonce::ZERO);
        //required because proptest closure cannot take mutable args.
        let wrapped_txs = RefCell::new(transactions);

        proptest!(|(request in arb_withdrawal_request())| {
            wrapped_txs.borrow_mut().record_request(request)
        });

        proptest!(|(gas_fee_estimate in arb_gas_fee_estimate(), transaction_count in arb_checked_amount_of())| {
            let resubmit_txs = wrapped_txs.borrow().create_resubmit_transactions(transaction_count, gas_fee_estimate.clone());
            for (_withdrawal_id, resubmit_tx) in resubmit_txs.into_iter().flatten() {
                wrapped_txs.borrow_mut().record_resubmit_transaction(resubmit_tx);
            }

            let withdrawal_requests = wrapped_txs.borrow().requests_batch(5);
            for request in withdrawal_requests {
                let nonce = wrapped_txs.borrow().next_transaction_nonce();
                if let Ok(created_tx) = request.create_transaction(
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
        AccessList, AccessListItem, Eip1559TransactionRequest, GasFeeEstimate,
        SignedEip1559TransactionRequest, StorageKey, TransactionPrice, TransactionSignature,
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

    fn arb_eip_1559_signature() -> impl Strategy<Value = TransactionSignature> {
        (any::<bool>(), arb_u256(), arb_u256()).prop_map(|(signature_y_parity, r, s)| {
            TransactionSignature {
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

mod sweep_lane {
    use super::{gas_fee_estimate, sign_transaction, transaction_receipt};
    use crate::deposit_address::DepositAddress;
    use crate::eth_rpc_client::responses::TransactionStatus;
    use crate::lifecycle::EthereumNetwork;
    use crate::numeric::GasAmount;
    use crate::numeric::{TransactionCount, TransactionNonce, Wei, WeiPerGas};
    use crate::state::transactions::{
        AuthorizedSweepItem, CreateSweepTransactionError, PipelineRequest,
        ResubmitTransactionError, SweepId, SweepRequest, TransactionPipeline, sweep_gas_limit,
    };

    const SWEEP_TRANSACTION_GAS_LIMIT: GasAmount = GasAmount::new(100_000);
    use crate::sweeper_contract::SweepItem;
    use crate::tx::{
        DelegatingSweep, Eip1559TransactionRequest, Eip7702TransactionRequest, GasFeeEstimate,
        SignableTransaction, SignedAuthorization, SweepTransaction, TransactionSignature,
    };
    use assert_matches::assert_matches;
    use candid::Principal;
    use ethnum::u256;
    use ic_ethereum_types::Address;
    use icrc_ledger_types::icrc1::account::Account;

    const EIP1559_TX_ID: u8 = 2;
    const SET_CODE_TX_ID: u8 = 4;

    /// A sweep of two deposit addresses, both already delegated to the sweeper contract and so
    /// carrying no authorization.
    fn sweep_request(id: u64) -> SweepRequest {
        SweepRequest {
            id: SweepId(id),
            destination: Address::new([id as u8; 20]),
            token: Address::new([0xc0; 20]),
            items: vec![sweep_item(1, None), sweep_item(2, None)],
            max_transaction_fee: Wei::from(1_000_000_000_000_000_u64),
            created_at: 1_620_328_630_000_000_000,
        }
    }

    /// A sweep of two deposit addresses that are not yet delegated to the sweeper contract.
    fn delegating_sweep_request(id: u64) -> SweepRequest {
        SweepRequest {
            items: vec![
                sweep_item(1, Some(authorization(1))),
                sweep_item(2, Some(authorization(2))),
            ],
            ..sweep_request(id)
        }
    }

    fn sweep_item(seed: u8, authorization: Option<SignedAuthorization>) -> AuthorizedSweepItem {
        AuthorizedSweepItem {
            item: SweepItem {
                deposit: DepositAddress::new(Address::new([seed; 20])),
                account: Account {
                    owner: Principal::management_canister(),
                    subaccount: Some([seed; 32]),
                },
                attestation: TransactionSignature {
                    signature_y_parity: false,
                    r: u256::from(seed),
                    s: u256::from(seed),
                },
            },
            authorization,
        }
    }

    fn authorization(seed: u8) -> SignedAuthorization {
        SignedAuthorization {
            chain_id: EthereumNetwork::Sepolia.chain_id(),
            delegate: Address::new([0xde; 20]),
            nonce: TransactionNonce::ZERO,
            y_parity: false,
            r: u256::from(seed),
            s: u256::from(seed),
        }
    }

    fn sweeper_pipeline() -> TransactionPipeline<SweepRequest> {
        TransactionPipeline::new(TransactionNonce::ZERO)
    }

    fn higher_gas_fee_estimate() -> GasFeeEstimate {
        let estimate = gas_fee_estimate();
        GasFeeEstimate {
            base_fee_per_gas: estimate.base_fee_per_gas.checked_mul(2_u8).unwrap(),
            max_priority_fee_per_gas: estimate.max_priority_fee_per_gas.checked_mul(2_u8).unwrap(),
        }
    }

    fn create_and_record_sweep_tx(
        pipeline: &mut TransactionPipeline<SweepRequest>,
        request: SweepRequest,
    ) -> SweepTransaction {
        let id = request.id;
        let tx = request
            .create_transaction(
                pipeline.next_transaction_nonce(),
                gas_fee_estimate(),
                SWEEP_TRANSACTION_GAS_LIMIT,
                EthereumNetwork::Sepolia,
            )
            .expect("BUG: the fixture allowance covers the fixture fee");
        pipeline.record_created_transaction(id, tx);
        pipeline.created_tx.get_alt(&id).unwrap().as_ref().clone()
    }

    #[test]
    fn should_scale_the_sweep_gas_limit_with_the_distinct_addresses_walked() {
        const MEASURED_TEN_DEPOSIT_SWEEP_GAS: u128 = 609_431;

        let items_for = |addresses: u8| -> Vec<AuthorizedSweepItem> {
            (1..=addresses).map(|seed| sweep_item(seed, None)).collect()
        };

        assert_eq!(sweep_gas_limit(&items_for(1)), GasAmount::new(225_000));
        assert_eq!(sweep_gas_limit(&items_for(10)), GasAmount::new(1_710_000));
        assert!(sweep_gas_limit(&items_for(10)) > GasAmount::new(MEASURED_TEN_DEPOSIT_SWEEP_GAS));

        let one_address_ten_times: Vec<_> = (0..10).map(|_| sweep_item(1, None)).collect();
        assert_eq!(
            sweep_gas_limit(&one_address_ten_times),
            sweep_gas_limit(&items_for(1))
        );
    }

    #[test]
    fn should_price_and_create_a_sweep_transaction_with_the_same_gas_limit() {
        let request = delegating_sweep_request(1);
        let transaction = request
            .create_transaction(
                TransactionNonce::ZERO,
                gas_fee_estimate(),
                request.gas_limit(),
                EthereumNetwork::Sepolia,
            )
            .expect("BUG: the fixture allowance covers the fixture fee");

        assert_eq!(request.gas_limit(), sweep_gas_limit(&request.items));
        assert_eq!(transaction.gas_limit(), sweep_gas_limit(&request.items));
    }

    #[test]
    fn should_create_a_sweep_transaction_on_the_lane_own_nonce() {
        let mut pipeline = sweeper_pipeline();
        pipeline.record_request(sweep_request(0));
        assert_eq!(pipeline.next_transaction_nonce(), TransactionNonce::ZERO);

        let tx = create_and_record_sweep_tx(&mut pipeline, sweep_request(0));

        assert_eq!(tx.nonce(), TransactionNonce::ZERO);
        assert_eq!(
            pipeline.next_transaction_nonce(),
            TransactionNonce::from(1_u64)
        );
        assert_eq!(tx.destination(), &sweep_request(0).destination);
        assert_eq!(tx.amount(), &Wei::ZERO);
        assert_eq!(tx.data(), sweep_request(0).call_data());
    }

    #[test]
    fn should_sweep_with_the_transaction_type_the_delegations_to_install_call_for() {
        struct Case {
            scenario: &'static str,
            items: Vec<AuthorizedSweepItem>,
            expected_transaction_type: u8,
        }

        for case in [
            Case {
                scenario: "every swept address already delegated",
                items: vec![sweep_item(1, None), sweep_item(2, None)],
                expected_transaction_type: EIP1559_TX_ID,
            },
            Case {
                scenario: "one swept address still to delegate",
                items: vec![sweep_item(1, Some(authorization(1))), sweep_item(2, None)],
                expected_transaction_type: SET_CODE_TX_ID,
            },
            Case {
                scenario: "two swept addresses still to delegate",
                items: vec![
                    sweep_item(1, Some(authorization(1))),
                    sweep_item(2, Some(authorization(2))),
                ],
                expected_transaction_type: SET_CODE_TX_ID,
            },
        ] {
            let context = case.scenario;
            let request = SweepRequest {
                items: case.items,
                ..sweep_request(0)
            };
            let mut pipeline = sweeper_pipeline();
            pipeline.record_request(request.clone());

            let tx = create_and_record_sweep_tx(&mut pipeline, request.clone());

            assert_eq!(
                tx.transaction_type(),
                case.expected_transaction_type,
                "{context}"
            );
            assert_eq!(
                tx.authorizations(),
                request.authorizations().as_slice(),
                "{context}"
            );
            assert_eq!(tx.destination(), &request.destination, "{context}");
            assert_eq!(tx.amount(), &Wei::ZERO, "{context}");
            assert_eq!(tx.data(), request.call_data(), "{context}");
            assert_eq!(tx.nonce(), TransactionNonce::ZERO, "{context}");
        }
    }

    #[test]
    fn should_keep_the_delegations_when_bumping_the_fee() {
        let mut pipeline = sweeper_pipeline();
        let request = delegating_sweep_request(0);
        pipeline.record_request(request.clone());
        let created = create_and_record_sweep_tx(&mut pipeline, request.clone());
        pipeline.record_signed_transaction(sign_transaction(created.clone()));

        let resubmitted = pipeline
            .create_resubmit_transactions(TransactionCount::ZERO, higher_gas_fee_estimate());

        let [Ok((id, bumped))] = resubmitted.as_slice() else {
            panic!("BUG: expected exactly one transaction to resubmit, got {resubmitted:?}");
        };
        assert_eq!(id, &SweepId(0));
        assert_eq!(bumped.transaction_type(), SET_CODE_TX_ID);
        assert_eq!(bumped.authorizations(), request.authorizations().as_slice());
        assert!(bumped.max_priority_fee_per_gas() > created.max_priority_fee_per_gas());
        assert_eq!(bumped.max_fee_per_gas(), created.max_fee_per_gas());
    }

    #[test]
    fn should_finalize_a_sweep() {
        let mut pipeline = sweeper_pipeline();
        pipeline.record_request(sweep_request(0));
        let created = create_and_record_sweep_tx(&mut pipeline, sweep_request(0));
        let signed = sign_transaction(created);
        pipeline.record_signed_transaction(signed.clone());

        let receipt = transaction_receipt(&signed, TransactionStatus::Success);
        let finalized = pipeline.record_finalized_transaction(SweepId(0), &receipt);

        assert_eq!(finalized.transaction_hash(), &signed.hash());
        assert!(pipeline.get_finalized_transaction(&SweepId(0)).is_some());
    }

    #[test]
    fn should_finalize_a_sweep_that_installed_delegations() {
        let mut pipeline = sweeper_pipeline();
        pipeline.record_request(delegating_sweep_request(0));
        let created = create_and_record_sweep_tx(&mut pipeline, delegating_sweep_request(0));
        let signed = sign_transaction(created);
        pipeline.record_signed_transaction(signed.clone());

        let receipt = transaction_receipt(&signed, TransactionStatus::Success);
        let finalized = pipeline.record_finalized_transaction(SweepId(0), &receipt);

        assert_eq!(finalized.transaction_hash(), &signed.hash());
        assert_eq!(
            finalized.transaction().authorizations(),
            delegating_sweep_request(0).authorizations().as_slice()
        );
    }

    #[test]
    fn should_advance_the_nonce_across_two_sweeps() {
        let mut pipeline = sweeper_pipeline();
        pipeline.record_request(sweep_request(0));
        pipeline.record_request(sweep_request(1));

        let first = create_and_record_sweep_tx(&mut pipeline, sweep_request(0));
        let second = create_and_record_sweep_tx(&mut pipeline, sweep_request(1));

        assert_eq!(first.nonce(), TransactionNonce::ZERO);
        assert_eq!(second.nonce(), TransactionNonce::from(1_u64));
        assert_eq!(
            pipeline.next_transaction_nonce(),
            TransactionNonce::from(2_u64)
        );
    }

    #[test]
    #[should_panic(expected = "sweep transaction should carry the request's call data")]
    fn should_trap_when_the_created_transaction_carries_other_call_data() {
        let mut pipeline = sweeper_pipeline();
        pipeline.record_request(sweep_request(0));
        let SweepTransaction::Eip1559(tx) = created_sweep_transaction(&pipeline, sweep_request(0))
        else {
            panic!("BUG: a sweep with no delegations to install is an EIP-1559 transaction");
        };

        pipeline.record_created_transaction(
            SweepId(0),
            SweepTransaction::new(
                Eip1559TransactionRequest {
                    data: vec![0xff],
                    ..tx
                },
                vec![],
            ),
        );
    }

    #[test]
    #[should_panic(expected = "sweep transaction should install exactly the request's delegations")]
    fn should_trap_when_the_created_transaction_installs_other_delegations() {
        let mut pipeline = sweeper_pipeline();
        let request = delegating_sweep_request(0);
        pipeline.record_request(request.clone());
        let SweepTransaction::Eip7702(tx) = created_sweep_transaction(&pipeline, request) else {
            panic!("BUG: a sweep with delegations to install is an EIP-7702 transaction");
        };

        pipeline.record_created_transaction(
            SweepId(0),
            SweepTransaction::Eip7702(
                DelegatingSweep::new(Eip7702TransactionRequest {
                    authorization_list: vec![authorization(3)],
                    ..tx.transaction().clone()
                })
                .unwrap(),
            ),
        );
    }

    /// The transaction `request` creates on `pipeline`'s next nonce, without recording it.
    fn created_sweep_transaction(
        pipeline: &TransactionPipeline<SweepRequest>,
        request: SweepRequest,
    ) -> SweepTransaction {
        request
            .create_transaction(
                pipeline.next_transaction_nonce(),
                gas_fee_estimate(),
                SWEEP_TRANSACTION_GAS_LIMIT,
                EthereumNetwork::Sepolia,
            )
            .expect("BUG: the fixture allowance covers the fixture fee")
    }

    #[test]
    fn should_allocate_the_whole_fee_allowance_to_a_sweep_transaction() {
        let request = sweep_request(0);
        let pipeline = sweeper_pipeline();

        let SweepTransaction::Eip1559(tx) = created_sweep_transaction(&pipeline, request.clone())
        else {
            panic!("BUG: a sweep with no delegations to install is an EIP-1559 transaction");
        };

        assert_eq!(
            tx.max_fee_per_gas
                .transaction_cost(SWEEP_TRANSACTION_GAS_LIMIT),
            Some(request.max_transaction_fee)
        );
        assert_eq!(
            tx.max_priority_fee_per_gas,
            gas_fee_estimate().max_priority_fee_per_gas
        );
    }

    #[test]
    fn should_refuse_to_create_a_sweep_the_allowance_cannot_pay_for() {
        let request = sweep_request(0);
        let spiked_fee = GasFeeEstimate {
            base_fee_per_gas: WeiPerGas::from(10_000_000_000_000_u64),
            ..gas_fee_estimate()
        };

        let created = request.create_transaction(
            TransactionNonce::ZERO,
            spiked_fee,
            SWEEP_TRANSACTION_GAS_LIMIT,
            EthereumNetwork::Sepolia,
        );

        assert_matches!(
            created,
            Err(CreateSweepTransactionError::InsufficientTransactionFee {
                id,
                allowed_max_transaction_fee,
                actual_max_transaction_fee,
            }) if id == request.id
                && allowed_max_transaction_fee == request.max_transaction_fee
                && actual_max_transaction_fee > request.max_transaction_fee
        );
    }

    #[test]
    fn should_refuse_to_create_a_sweep_whose_allowance_the_priority_fee_alone_exceeds() {
        let request = SweepRequest {
            max_transaction_fee: Wei::from(100_000_u64),
            ..sweep_request(0)
        };
        assert!(
            gas_fee_estimate().max_priority_fee_per_gas
                > request
                    .max_transaction_fee
                    .into_wei_per_gas(SWEEP_TRANSACTION_GAS_LIMIT)
                    .unwrap()
        );

        let created = request.create_transaction(
            TransactionNonce::ZERO,
            gas_fee_estimate(),
            SWEEP_TRANSACTION_GAS_LIMIT,
            EthereumNetwork::Sepolia,
        );

        assert_matches!(
            created,
            Err(CreateSweepTransactionError::InsufficientTransactionFee { .. })
        );
    }

    #[test]
    fn should_refuse_to_resubmit_a_sweep_beyond_its_fee_allowance() {
        let mut pipeline = sweeper_pipeline();
        pipeline.record_request(sweep_request(0));
        let created = create_and_record_sweep_tx(&mut pipeline, sweep_request(0));
        pipeline.record_signed_transaction(sign_transaction(created));

        let spiked_fee = GasFeeEstimate {
            base_fee_per_gas: WeiPerGas::from(10_000_000_000_000_u64),
            ..gas_fee_estimate()
        };
        let resubmitted = pipeline.create_resubmit_transactions(TransactionCount::ZERO, spiked_fee);

        assert_matches!(
            resubmitted.first().expect("BUG: nothing to resubmit"),
            Err(ResubmitTransactionError::InsufficientTransactionFee {
                id,
                allowed_max_transaction_fee,
                max_transaction_fee,
                ..
            }) if *id == SweepId(0)
                && *allowed_max_transaction_fee == sweep_request(0).max_transaction_fee
                && *max_transaction_fee > sweep_request(0).max_transaction_fee
        );
    }

    #[test]
    #[should_panic(expected = "duplicate transaction id")]
    fn should_trap_on_a_duplicate_sweep_id() {
        let mut pipeline = sweeper_pipeline();
        pipeline.record_request(sweep_request(7));
        pipeline.record_request(sweep_request(7));
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
    transactions: &mut WithdrawalTransactions,
    rng: &mut R,
) -> [WithdrawalRequest; N] {
    let requests = create_ck_withdrawal_requests(rng);
    for request in &requests {
        transactions.record_request(request.clone());
    }
    requests
}

/// Create ckETH withdrawal requests and record them.
fn create_and_record_cketh_withdrawal_requests<const N: usize>(
    transactions: &mut WithdrawalTransactions,
) -> [WithdrawalRequest; N] {
    let requests = create_cketh_withdrawal_requests();
    for request in &requests {
        transactions.record_request(request.clone());
    }
    requests
}

/// Create ckERC20 withdrawal requests and record them.
fn create_and_record_ckerc20_withdrawal_requests<const N: usize>(
    transactions: &mut WithdrawalTransactions,
) -> [WithdrawalRequest; N] {
    let requests = create_ckerc20_withdrawal_requests();
    for request in &requests {
        transactions.record_request(request.clone());
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
    transactions: &mut WithdrawalTransactions,
    withdrawal_request: R,
    gas_fee_estimate: GasFeeEstimate,
) -> Eip1559TransactionRequest {
    let withdrawal_request = withdrawal_request.into();
    let tx = withdrawal_request
        .create_transaction(
            transactions.next_transaction_nonce(),
            gas_fee_estimate,
            estimate_gas_limit(&withdrawal_request),
            EthereumNetwork::Sepolia,
        )
        .expect("failed to create transaction");
    let burn_index = withdrawal_request.cketh_ledger_burn_index();
    transactions.record_created_transaction(burn_index, tx.clone());
    tx
}

fn sent_transactions<'a>(
    transactions: &'a WithdrawalTransactions,
    burn_index: &LedgerBurnIndex,
) -> Option<Vec<&'a SignedEip1559TransactionRequest>> {
    transactions
        .sent_transactions_iter()
        .find(|(_nonce, index, _txs)| *index == burn_index)
        .map(|(_nonce, _index, txs)| txs)
}

fn first_sent_transaction<'a>(
    transactions: &'a WithdrawalTransactions,
    burn_index: &LedgerBurnIndex,
) -> &'a Eip1559TransactionRequest {
    sent_transactions(transactions, burn_index).expect("BUG: no sent transaction")[0].transaction()
}

fn create_and_record_signed_transaction(
    transactions: &mut WithdrawalTransactions,
    created_tx: Eip1559TransactionRequest,
) -> SignedEip1559TransactionRequest {
    let signed_tx = sign_transaction(created_tx);
    transactions.record_signed_transaction(signed_tx.clone());
    signed_tx
}

fn resubmit_transaction_with_bumped_price(
    transactions: &mut WithdrawalTransactions,
    created_tx: Eip1559TransactionRequest,
) -> SignedEip1559TransactionRequest {
    use crate::tx::SignableTransaction;
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

fn transaction_receipt<T: SignableTransaction>(
    signed_tx: &Signed<T>,
    status: TransactionStatus,
) -> TransactionReceipt {
    use std::str::FromStr;
    TransactionReceipt {
        block_hash: Hash::from_str(
            "0xce67a85c9fb8bc50213815c32814c159fd75160acf7cb8631e8e7b7cf7f1d472",
        )
        .unwrap(),
        block_number: BlockNumber::new(4190269),
        effective_gas_price: signed_tx.transaction().max_fee_per_gas(),
        gas_used: signed_tx.transaction().gas_limit(),
        status,
        transaction_hash: signed_tx.hash(),
    }
}

fn sign_transaction<T: SignableTransaction>(transaction: T) -> Signed<T> {
    Signed::from((transaction, dummy_signature()))
}

fn dummy_signature() -> TransactionSignature {
    TransactionSignature {
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

use crate::map::MultiKeyMap;
use crate::state::transactions::{ReimbursedResult, ReimbursementIndex, ReimbursementRequest};
use crate::tx::{FinalizedEip1559Transaction, SignedTransactionRequest, TransactionRequest};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Assembles a [`WithdrawalTransactions`] field by field, so a test can build a state the public
/// API would take many steps to reach — then clone the builder and vary one field to check what
/// that field alone changes.
#[derive(Clone)]
pub(in crate::state) struct WithdrawalTransactionsBuilder {
    pending_requests: VecDeque<WithdrawalRequest>,
    processed_requests: BTreeMap<LedgerBurnIndex, WithdrawalRequest>,
    created_tx: MultiKeyMap<TransactionNonce, LedgerBurnIndex, TransactionRequest>,
    sent_tx: MultiKeyMap<TransactionNonce, LedgerBurnIndex, Vec<SignedTransactionRequest>>,
    finalized_tx: MultiKeyMap<TransactionNonce, LedgerBurnIndex, FinalizedEip1559Transaction>,
    next_nonce: TransactionNonce,
    maybe_reimburse: BTreeSet<LedgerBurnIndex>,
    reimbursement_requests: BTreeMap<ReimbursementIndex, ReimbursementRequest>,
    reimbursed: BTreeMap<ReimbursementIndex, ReimbursedResult>,
}

impl Default for WithdrawalTransactionsBuilder {
    fn default() -> Self {
        Self {
            pending_requests: Default::default(),
            processed_requests: Default::default(),
            created_tx: Default::default(),
            sent_tx: Default::default(),
            finalized_tx: Default::default(),
            next_nonce: TransactionNonce::ZERO,
            maybe_reimburse: Default::default(),
            reimbursement_requests: Default::default(),
            reimbursed: Default::default(),
        }
    }
}

impl WithdrawalTransactionsBuilder {
    pub(in crate::state) fn with_pending_requests(
        mut self,
        pending_requests: VecDeque<WithdrawalRequest>,
    ) -> Self {
        self.pending_requests = pending_requests;
        self
    }

    pub(in crate::state) fn with_processed_requests(
        mut self,
        processed_requests: BTreeMap<LedgerBurnIndex, WithdrawalRequest>,
    ) -> Self {
        self.processed_requests = processed_requests;
        self
    }

    pub(in crate::state) fn with_created_tx(
        mut self,
        created_tx: MultiKeyMap<TransactionNonce, LedgerBurnIndex, TransactionRequest>,
    ) -> Self {
        self.created_tx = created_tx;
        self
    }

    pub(in crate::state) fn with_sent_tx(
        mut self,
        sent_tx: MultiKeyMap<TransactionNonce, LedgerBurnIndex, Vec<SignedTransactionRequest>>,
    ) -> Self {
        self.sent_tx = sent_tx;
        self
    }

    pub(in crate::state) fn with_finalized_tx(
        mut self,
        finalized_tx: MultiKeyMap<TransactionNonce, LedgerBurnIndex, FinalizedEip1559Transaction>,
    ) -> Self {
        self.finalized_tx = finalized_tx;
        self
    }

    pub(in crate::state) fn with_next_nonce(mut self, next_nonce: TransactionNonce) -> Self {
        self.next_nonce = next_nonce;
        self
    }

    pub(in crate::state) fn with_maybe_reimburse(
        mut self,
        maybe_reimburse: BTreeSet<LedgerBurnIndex>,
    ) -> Self {
        self.maybe_reimburse = maybe_reimburse;
        self
    }

    pub(in crate::state) fn with_reimbursement_requests(
        mut self,
        reimbursement_requests: BTreeMap<ReimbursementIndex, ReimbursementRequest>,
    ) -> Self {
        self.reimbursement_requests = reimbursement_requests;
        self
    }

    pub(in crate::state) fn with_reimbursed(
        mut self,
        reimbursed: BTreeMap<ReimbursementIndex, ReimbursedResult>,
    ) -> Self {
        self.reimbursed = reimbursed;
        self
    }

    pub(in crate::state) fn build(self) -> WithdrawalTransactions {
        WithdrawalTransactions {
            pipeline: MinterTransactionPipeline {
                pending_requests: self.pending_requests,
                processed_requests: self.processed_requests,
                created_tx: self.created_tx,
                sent_tx: self.sent_tx,
                finalized_tx: self.finalized_tx,
                next_nonce: self.next_nonce,
            },
            maybe_reimburse: self.maybe_reimburse,
            reimbursement_requests: self.reimbursement_requests,
            reimbursed: self.reimbursed,
        }
    }
}
