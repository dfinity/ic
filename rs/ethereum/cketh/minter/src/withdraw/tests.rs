use crate::eth_rpc::Hash;
use crate::eth_rpc_client::MultiCallError;
use crate::numeric::LedgerBurnIndex;
use crate::state::receipt_fetch::{
    INITIAL_RECEIPT_FETCH_WINDOW, ROUNDS_SINCE_CHAIN_READ_BEFORE_SKIPPING,
};
use crate::state::transactions::WithdrawalRequest;
use crate::state::{mutate_state, read_state};
use crate::test_fixtures::{init_state, initial_state, mock, stub_rpc_client};
use crate::withdraw::{ReceiptLookup, collect_finalized_receipts, fetch_receipts_for_round};
use evm_rpc_types::{
    Hex20, Hex32, Hex256, HexByte, Nat256, TransactionReceipt as EvmTransactionReceipt,
};
use ic_canister_runtime::IcError;
use ic_ethereum_types::Address;
use std::collections::BTreeMap;

mod collect {
    use super::*;

    #[test]
    fn should_return_nothing_for_an_empty_round() {
        let (receipts, outcome) = collect_finalized_receipts::<LedgerBurnIndex>(vec![]);

        assert_eq!(receipts, BTreeMap::new());
        assert_eq!(outcome.lookups(), 0);
    }

    #[test]
    fn should_finalize_the_ids_that_answered_and_leave_the_others_pending() {
        let (receipts, outcome) = collect_finalized_receipts(vec![
            ReceiptLookup {
                hash: hash(1),
                id: id(1),
                result: Ok(Some(receipt(hash(1)))),
            },
            ReceiptLookup {
                hash: hash(2),
                id: id(2),
                result: Err(failed_lookup()),
            },
            ReceiptLookup {
                hash: hash(3),
                id: id(3),
                result: Ok(Some(receipt(hash(3)))),
            },
        ]);

        assert_eq!(
            receipts,
            BTreeMap::from([(id(1), receipt(hash(1))), (id(3), receipt(hash(3)))])
        );
        assert_eq!(outcome.receipts(), 2);
        assert_eq!(outcome.failures(), 1);
        assert!(!outcome.is_abandoned());
    }

    #[test]
    fn should_finalize_a_resubmitted_id_on_the_variant_that_was_mined() {
        let (receipts, outcome) = collect_finalized_receipts(vec![
            ReceiptLookup {
                hash: hash(1),
                id: id(1),
                result: Ok(None),
            },
            ReceiptLookup {
                hash: hash(2),
                id: id(1),
                result: Ok(Some(receipt(hash(2)))),
            },
            ReceiptLookup {
                hash: hash(3),
                id: id(1),
                result: Err(failed_lookup()),
            },
        ]);

        assert_eq!(receipts, BTreeMap::from([(id(1), receipt(hash(2)))]));
        assert_eq!(outcome.receipts(), 1);
        assert_eq!(outcome.not_mined(), 1);
        assert_eq!(outcome.failures(), 1);
    }

    #[test]
    fn should_leave_an_id_pending_without_trapping_when_none_of_its_transactions_was_mined() {
        let (receipts, outcome) = collect_finalized_receipts(vec![
            ReceiptLookup {
                hash: hash(1),
                id: id(1),
                result: Ok(None),
            },
            ReceiptLookup {
                hash: hash(2),
                id: id(1),
                result: Ok(None),
            },
            ReceiptLookup {
                hash: hash(3),
                id: id(2),
                result: Ok(Some(receipt(hash(3)))),
            },
        ]);

        assert_eq!(receipts, BTreeMap::from([(id(2), receipt(hash(3)))]));
        assert_eq!(outcome.not_mined(), 2);
        assert_eq!(outcome.failures(), 0);
    }

    #[test]
    fn should_abandon_the_round_but_count_every_lookup_on_two_receipts_for_the_same_id() {
        let (receipts, outcome) = collect_finalized_receipts(vec![
            ReceiptLookup {
                hash: hash(1),
                id: id(1),
                result: Ok(Some(receipt(hash(1)))),
            },
            ReceiptLookup {
                hash: hash(2),
                id: id(1),
                result: Ok(Some(receipt(hash(2)))),
            },
            ReceiptLookup {
                hash: hash(3),
                id: id(2),
                result: Ok(Some(receipt(hash(3)))),
            },
            ReceiptLookup {
                hash: hash(4),
                id: id(3),
                result: Ok(None),
            },
            ReceiptLookup {
                hash: hash(5),
                id: id(4),
                result: Err(failed_lookup()),
            },
        ]);

        assert_eq!(receipts, BTreeMap::new());
        assert!(outcome.is_abandoned());
        assert_eq!(outcome.receipts(), 3);
        assert_eq!(outcome.not_mined(), 1);
        assert_eq!(outcome.failures(), 1);
        assert_eq!(outcome.lookups(), 5);
    }
}

mod round {
    use super::*;

    #[tokio::test]
    async fn should_skip_a_round_rather_than_read_the_chain_again() {
        init_state(initial_state());
        mutate_state(|s| {
            for _ in 0..=ROUNDS_SINCE_CHAIN_READ_BEFORE_SKIPPING {
                s.withdrawal_transactions
                    .pipeline_mut()
                    .receipt_fetch_mut()
                    .record_round_without_chain_read();
            }
        });

        let rounds_before = read_state(|s| {
            s.withdrawal_transactions
                .pipeline()
                .receipt_fetch()
                .rounds_since_chain_read()
        });

        let receipts = fetch_receipts_for_round::<WithdrawalRequest, _>(
            Address::new([0_u8; 20]),
            &no_rpc_runtime(),
        )
        .await;

        assert_eq!(receipts, BTreeMap::new());
        assert_eq!(
            read_state(|s| s
                .withdrawal_transactions
                .pipeline()
                .receipt_fetch()
                .rounds_since_chain_read()),
            rounds_before + 1,
            "a skipped round is one more round that read nothing"
        );
        assert_eq!(
            read_state(|s| s
                .automatic_deposits
                .sweeper_pipeline()
                .receipt_fetch()
                .rounds_since_chain_read()),
            0,
            "one pipeline skipping rounds must not touch the other"
        );
    }

    #[tokio::test]
    async fn should_count_a_round_whose_chain_read_failed() {
        init_state(initial_state());
        let mut runtime = mock::MockCanisterRuntime::new();
        runtime
            .expect_evm_rpc_client()
            .times(1)
            .return_once(|| stub_rpc_client(vec![Err(IcError::CallPerformFailed)]));

        let receipts =
            fetch_receipts_for_round::<WithdrawalRequest, _>(Address::new([0_u8; 20]), &runtime)
                .await;

        assert_eq!(receipts, BTreeMap::new());
        assert_eq!(
            read_state(|s| s
                .withdrawal_transactions
                .pipeline()
                .receipt_fetch()
                .rounds_since_chain_read()),
            1,
            "a round that could not read the chain is what starts the skipping"
        );
        assert_eq!(
            read_state(|s| s
                .withdrawal_transactions
                .pipeline()
                .receipt_fetch()
                .window()),
            INITIAL_RECEIPT_FETCH_WINDOW,
            "a round that never reached its lookups says nothing about the providers"
        );
    }
}

fn no_rpc_runtime() -> mock::MockCanisterRuntime {
    let mut runtime = mock::MockCanisterRuntime::new();
    runtime.expect_evm_rpc_client().never();
    runtime
}

fn failed_lookup() -> MultiCallError<Option<EvmTransactionReceipt>> {
    MultiCallError::from_client_error(IcError::CallPerformFailed)
}

fn id(id: u8) -> LedgerBurnIndex {
    LedgerBurnIndex::new(id as u64)
}

fn hash(seed: u8) -> Hash {
    Hash([seed; 32])
}

fn receipt(transaction_hash: Hash) -> EvmTransactionReceipt {
    EvmTransactionReceipt {
        block_hash: Hex32::from([0x11_u8; 32]),
        block_number: Nat256::from(0x4132ec_u64),
        effective_gas_price: Nat256::from(0xfefbee3e_u64),
        gas_used: Nat256::from(0x5208_u64),
        cumulative_gas_used: Nat256::from(0x8b2e10_u64),
        status: Some(Nat256::from(1_u8)),
        root: None,
        transaction_hash: Hex32::from(transaction_hash.0),
        contract_address: None,
        from: Hex20::from([0x17_u8; 20]),
        logs: vec![],
        logs_bloom: Hex256::from([0_u8; 256]),
        to: Some(Hex20::from([0xdd_u8; 20])),
        transaction_index: Nat256::from(0x32_u8),
        tx_type: HexByte::from(0x02_u8),
    }
}
