use crate::address::Address;
use crate::eth_rpc::Quantity;
use crate::numeric::{TransactionNonce, Wei};
use crate::tx::Eip1559TransactionRequest;

mod pending_eth_transactions_insert {
    use crate::numeric::{LedgerBurnIndex, TransactionNonce};
    use crate::transactions::tests::eip_1559_transaction_request_with_nonce;
    use crate::transactions::PendingEthTransactions;
    use assert_matches::assert_matches;

    #[test]
    fn should_insert_transaction_with_incrementing_nonce() {
        let nonce_tx_1 = TransactionNonce::from(10);
        let mut transactions = PendingEthTransactions::new(nonce_tx_1);

        assert_eq!(
            transactions.insert(
                LedgerBurnIndex(0),
                eip_1559_transaction_request_with_nonce(nonce_tx_1)
            ),
            Ok(())
        );
        assert_eq!(
            transactions.next_nonce,
            nonce_tx_1.checked_increment().unwrap()
        );

        let nonce_tx_2 = TransactionNonce::from(11);
        assert_eq!(
            transactions.insert(
                LedgerBurnIndex(1),
                eip_1559_transaction_request_with_nonce(nonce_tx_2)
            ),
            Ok(())
        );
        assert_eq!(
            transactions.next_nonce,
            nonce_tx_2.checked_increment().unwrap()
        );
    }

    #[test]
    fn should_fail_when_duplicate_ledger_burn_index() {
        let mut transactions = PendingEthTransactions::new(TransactionNonce::from(1));
        let duplicate_index = LedgerBurnIndex(10);
        assert_eq!(
            transactions.insert(
                duplicate_index,
                eip_1559_transaction_request_with_nonce(TransactionNonce::from(1))
            ),
            Ok(())
        );
        assert_eq!(
            transactions.insert(
                LedgerBurnIndex(20),
                eip_1559_transaction_request_with_nonce(TransactionNonce::from(2))
            ),
            Ok(())
        );

        let result = transactions.insert(
            duplicate_index,
            eip_1559_transaction_request_with_nonce(TransactionNonce::from(3)),
        );

        assert_matches!(result, Err(msg) if msg.contains("burn index"));
    }

    #[test]
    fn should_fail_when_nonce_out_of_order() {
        let mut transactions = PendingEthTransactions::new(TransactionNonce::from(0));

        for nonce in 0..=3 {
            assert_eq!(
                transactions.insert(
                    LedgerBurnIndex(10 + nonce),
                    eip_1559_transaction_request_with_nonce(TransactionNonce::from(nonce))
                ),
                Ok(())
            );
        }

        let result_with_skipped_nonce = transactions.insert(
            LedgerBurnIndex(20),
            eip_1559_transaction_request_with_nonce(TransactionNonce::from(5)),
        );
        assert_matches!(result_with_skipped_nonce, Err(msg) if msg.contains("nonce"));

        let result_with_duplicate_nonce = transactions.insert(
            LedgerBurnIndex(20),
            eip_1559_transaction_request_with_nonce(TransactionNonce::from(3)),
        );
        assert_matches!(result_with_duplicate_nonce, Err(msg) if msg.contains("nonce"));
    }

    #[test]
    fn should_keep_next_nonce_value_when_transaction_removed() {
        let mut transactions = PendingEthTransactions::new(TransactionNonce::from(0));

        for nonce in 0..=3 {
            assert_eq!(
                transactions.insert(
                    LedgerBurnIndex(10 + nonce),
                    eip_1559_transaction_request_with_nonce(TransactionNonce::from(nonce))
                ),
                Ok(())
            );
        }

        assert_eq!(transactions.next_nonce, TransactionNonce::from(4));
        //TODO: FI-867 use public method to remove finalized transactions
        transactions.by_burn_index.remove(&LedgerBurnIndex(13));
        assert_eq!(transactions.next_nonce, TransactionNonce::from(4));
    }
}

mod transactions_to_sign {
    use crate::numeric::{LedgerBurnIndex, TransactionNonce};
    use crate::transactions::tests::eip_1559_transaction_request_with_nonce;
    use crate::transactions::PendingEthTransactions;
    use crate::tx::Eip1559TransactionRequest;

    #[test]
    fn should_be_empty_when_no_transactions() {
        let transactions = PendingEthTransactions::new(TransactionNonce::from(0));
        assert_eq!(
            transactions.transactions_to_sign(),
            Vec::<&Eip1559TransactionRequest>::new()
        );
    }

    #[test]
    fn should_sort_transactions_by_nonce_value() {
        let mut transactions = PendingEthTransactions::new(TransactionNonce::from(10));
        let tx_1 = eip_1559_transaction_request_with_nonce(TransactionNonce::from(10));
        let tx_2 = eip_1559_transaction_request_with_nonce(TransactionNonce::from(11));
        let tx_3 = eip_1559_transaction_request_with_nonce(TransactionNonce::from(12));
        assert_eq!(
            transactions.insert(LedgerBurnIndex(100), tx_1.clone()),
            Ok(())
        );
        assert_eq!(
            transactions.insert(LedgerBurnIndex(10), tx_2.clone()),
            Ok(())
        );
        assert_eq!(
            transactions.insert(LedgerBurnIndex(1000), tx_3.clone()),
            Ok(())
        );

        let to_sign = transactions.transactions_to_sign();

        assert_eq!(to_sign, vec![&tx_1, &tx_2, &tx_3]);
    }
}

mod find_by_burn_index {
    use crate::numeric::{LedgerBurnIndex, TransactionNonce};
    use crate::transactions::tests::eip_1559_transaction_request_with_nonce;
    use crate::transactions::{PendingEthTransaction, PendingEthTransactions};

    #[test]
    fn should_return_none_when_empty() {
        let transactions = PendingEthTransactions::new(TransactionNonce::from(0));
        assert_eq!(transactions.find_by_burn_index(LedgerBurnIndex(0)), None);
    }

    #[test]
    fn should_find_transaction() {
        let mut transactions = PendingEthTransactions::new(TransactionNonce::from(1));
        let (index_1, tx_1) = (
            LedgerBurnIndex(10),
            eip_1559_transaction_request_with_nonce(TransactionNonce::from(1)),
        );
        let (index_2, tx_2) = (
            LedgerBurnIndex(20),
            eip_1559_transaction_request_with_nonce(TransactionNonce::from(2)),
        );
        assert_eq!(transactions.insert(index_1, tx_1.clone()), Ok(()));
        assert_eq!(transactions.insert(index_2, tx_2.clone()), Ok(()));

        let found_tx = transactions.find_by_burn_index(index_1);

        assert_eq!(found_tx, Some(&PendingEthTransaction::NotSigned(tx_1)));
    }

    #[test]
    fn should_not_find_transaction_with_wrong_index() {
        let mut transactions = PendingEthTransactions::new(TransactionNonce::from(0));
        let index = 10;
        assert_eq!(
            transactions.insert(
                LedgerBurnIndex(index),
                eip_1559_transaction_request_with_nonce(TransactionNonce::from(0))
            ),
            Ok(())
        );

        assert_eq!(
            transactions.find_by_burn_index(LedgerBurnIndex(index + 1)),
            None
        );
    }
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
        access_list: vec![],
    }
}
