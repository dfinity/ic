use crate::address::Address;
use crate::eth_rpc::{Hash, Quantity};
use crate::numeric::{BlockNumber, LedgerBurnIndex, TransactionNonce, Wei};
use crate::transactions::EthWithdrawalRequest;
use crate::tx::{
    AccessList, ConfirmedEip1559Transaction, Eip1559Signature, Eip1559TransactionRequest,
    SignedEip1559TransactionRequest,
};

mod eth_transactions {
    use crate::endpoints::{EthTransaction, RetrieveEthStatus};
    use crate::numeric::{LedgerBurnIndex, TransactionNonce};
    use crate::transactions::tests::{
        confirmed_transaction, dummy_signature, eip_1559_transaction_request_with_nonce,
        expect_panic_with_message, withdrawal_request_with_index,
    };
    use crate::transactions::EthTransactions;
    use crate::tx::SignedEip1559TransactionRequest;

    #[test]
    fn should_withdrawal_flow_succeed_with_correct_status() {
        let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
        let index = LedgerBurnIndex::new(15);

        assert_eq!(
            transactions.transaction_status(&index),
            RetrieveEthStatus::NotFound
        );
        let withdrawal_request = withdrawal_request_with_index(index);
        transactions.record_withdrawal_request(withdrawal_request.clone());
        assert_eq!(
            transactions.transaction_status(&index),
            RetrieveEthStatus::Pending
        );

        let tx = eip_1559_transaction_request_with_nonce(TransactionNonce::ZERO);
        transactions.record_created_transaction(withdrawal_request, tx.clone());
        assert_eq!(
            transactions.transaction_status(&index),
            RetrieveEthStatus::TxCreated
        );

        let signed_tx = SignedEip1559TransactionRequest::from((tx, dummy_signature()));
        let expected_hash = EthTransaction {
            transaction_hash: "0xbe3a7b0639afd4b7883f0303abcf6133140c7c1d9f574028e17d9efc8c27e0c4"
                .to_string(),
        };
        transactions.record_signed_transaction(signed_tx.clone());
        assert_eq!(
            transactions.transaction_status(&index),
            RetrieveEthStatus::TxSigned(expected_hash.clone())
        );

        transactions.record_sent_transaction(signed_tx.clone());
        assert_eq!(
            transactions.transaction_status(&index),
            RetrieveEthStatus::TxSent(expected_hash.clone())
        );

        let confirmed_tx = confirmed_transaction(signed_tx);
        transactions.record_confirmed_transaction(confirmed_tx);
        assert_eq!(
            transactions.transaction_status(&index),
            RetrieveEthStatus::TxConfirmed(expected_hash)
        );
    }

    #[test]
    fn should_panic_when_trying_to_record_transaction_if_one_already_pending() {
        let mut transactions = EthTransactions::new(TransactionNonce::ZERO);
        let index = LedgerBurnIndex::new(15);
        let first_request = withdrawal_request_with_index(index);
        transactions.record_withdrawal_request(first_request.clone());
        let second_request = withdrawal_request_with_index(LedgerBurnIndex::new(16));
        transactions.record_withdrawal_request(second_request.clone());
        let first_tx = eip_1559_transaction_request_with_nonce(TransactionNonce::ZERO);
        transactions.record_created_transaction(first_request, first_tx.clone());

        let second_tx = eip_1559_transaction_request_with_nonce(
            TransactionNonce::ZERO.checked_increment().unwrap(),
        );
        expect_panic_with_message(
            || transactions.record_created_transaction(second_request, second_tx),
            "pending transaction already exists",
        );
    }

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
            transactions.maybe_process_new_transaction(),
            Some(first_request.clone())
        );

        transactions.reschedule_withdrawal_request(first_request.clone());
        // 1 -> 3 -> 2
        assert_eq!(
            transactions.maybe_process_new_transaction(),
            Some(second_request.clone())
        );

        transactions.reschedule_withdrawal_request(second_request);
        // 2 -> 1 -> 3
        assert_eq!(
            transactions.maybe_process_new_transaction(),
            Some(third_request.clone())
        );

        transactions.reschedule_withdrawal_request(third_request);
        // 3 -> 2 -> 1
        assert_eq!(
            transactions.maybe_process_new_transaction(),
            Some(first_request)
        );
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

fn expect_panic_with_message<F: FnOnce() -> R, R: std::fmt::Debug>(f: F, expected_message: &str) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    let panic_message = *result.unwrap_err().downcast_ref::<&str>().unwrap();
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

fn dummy_signature() -> Eip1559Signature {
    Eip1559Signature {
        signature_y_parity: false,
        r: Default::default(),
        s: Default::default(),
    }
}
