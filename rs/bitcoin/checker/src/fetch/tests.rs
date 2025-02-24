use super::*;
use crate::{providers::Provider, CheckTransactionIrrecoverableError};
use bitcoin::{
    absolute::LockTime, address::Address, hashes::Hash, transaction::Version, Amount, OutPoint,
    PubkeyHash, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use ic_btc_checker::{
    blocklist, BtcNetwork, CheckMode, CHECK_TRANSACTION_CYCLES_REQUIRED,
    CHECK_TRANSACTION_CYCLES_SERVICE_FEE,
};
use ic_cdk::api::call::RejectionCode;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::str::FromStr;

// A mock environment that provides simulated `get_tx` implementation, with
// mock states and transactions used for testing purpose.
struct MockEnv {
    high_load: bool,
    calls: RefCell<VecDeque<(Txid, u32)>>,
    replies: RefCell<VecDeque<Result<Transaction, HttpGetTxError>>>,
    available_cycles: RefCell<u128>,
    accepted_cycles: RefCell<u128>,
    called_provider: RefCell<Option<Provider>>,
}

const TEST_SUBNET_NODES: u16 = 13;

impl FetchEnv for MockEnv {
    type FetchGuard = ();

    fn new_fetch_guard(&self, _txid: Txid) -> Result<Self::FetchGuard, FetchGuardError> {
        if self.high_load {
            Err(FetchGuardError::NoCapacity)
        } else {
            Ok(())
        }
    }

    fn config(&self) -> Config {
        Config::new_and_validate(BtcNetwork::Mainnet, CheckMode::Normal, TEST_SUBNET_NODES).unwrap()
    }

    async fn http_get_tx(
        &self,
        provider: &Provider,
        txid: Txid,
        max_response_bytes: u32,
    ) -> Result<Transaction, HttpGetTxError> {
        self.calls
            .borrow_mut()
            .push_back((txid, max_response_bytes));
        *self.called_provider.borrow_mut() = Some(provider.clone());
        self.replies
            .borrow_mut()
            .pop_front()
            .unwrap_or(Err(HttpGetTxError::Rejected {
                code: RejectionCode::SysTransient,
                message: "no more reply".to_string(),
            }))
    }
    fn cycles_accept(&self, cycles: u128) -> u128 {
        let mut available = self.available_cycles.borrow_mut();
        let mut accepted = self.accepted_cycles.borrow_mut();
        let cycles = cycles.min(*available);
        *accepted += cycles;
        *available -= cycles;
        cycles
    }
}

impl MockEnv {
    fn new(available_cycles: u128) -> Self {
        Self {
            high_load: false,
            calls: RefCell::new(VecDeque::new()),
            replies: RefCell::new(VecDeque::new()),
            available_cycles: RefCell::new(available_cycles),
            accepted_cycles: RefCell::new(0),
            called_provider: RefCell::new(None),
        }
    }
    fn assert_get_tx_call(&self, txid: Txid, max_response_bytes: u32) {
        assert_eq!(
            self.calls.borrow_mut().pop_front(),
            Some((txid, max_response_bytes))
        )
    }
    fn assert_no_more_get_tx_call(&self) {
        assert_eq!(self.calls.borrow_mut().pop_front(), None)
    }
    fn expect_get_tx_with_reply(&self, reply: Result<Transaction, HttpGetTxError>) {
        self.replies.borrow_mut().push_back(reply)
    }
    fn refill_cycles(&self, cycles: u128) {
        *self.available_cycles.borrow_mut() = cycles;
    }
    fn cycles_accepted(&self) -> u128 {
        *self.accepted_cycles.borrow()
    }
    fn cycles_available(&self) -> u128 {
        *self.available_cycles.borrow()
    }
}

fn mock_txid(v: u8) -> Txid {
    Txid::from([v; 32])
}

fn mock_transaction() -> Transaction {
    Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: Vec::new(),
        output: Vec::new(),
    }
}

fn mock_transaction_with_outputs(num_outputs: usize) -> Transaction {
    let mut tx = mock_transaction();
    let output = (0..num_outputs)
        .map(|i| TxOut {
            value: Amount::ONE_SAT,
            script_pubkey: ScriptBuf::new_p2pkh(&PubkeyHash::from_slice(&[i as u8; 20]).unwrap()),
        })
        .collect();
    tx.output = output;
    tx
}

fn mock_transaction_with_output_but_no_address(num_outputs: usize) -> Transaction {
    let mut tx = mock_transaction();
    // This vout was taken from a regtest transaction. It is equivalent to
    // "OP_RETURN aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9"
    let vout = [
        0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed, 0xe2, 0xf6, 0x1c, 0x3f, 0x71, 0xd1, 0xde, 0xfd, 0x3f,
        0xa9, 0x99, 0xdf, 0xa3, 0x69, 0x53, 0x75, 0x5c, 0x69, 0x06, 0x89, 0x79, 0x99, 0x62, 0xb4,
        0x8b, 0xeb, 0xd8, 0x36, 0x97, 0x4e, 0x8c, 0xf9,
    ];
    let output = (0..num_outputs)
        .map(|_| TxOut {
            value: Amount::ONE_SAT,
            script_pubkey: ScriptBuf::from_bytes(vout.clone().to_vec()),
        })
        .collect();
    tx.output = output;
    tx
}

fn mock_transaction_with_inputs(input_txids: Vec<(Txid, u32)>) -> Transaction {
    let mut tx = mock_transaction();
    let input = input_txids
        .into_iter()
        .enumerate()
        .map(|(i, (txid, vout))| TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_slice(txid.as_ref()).unwrap(),
                vout,
            },
            script_sig: ScriptBuf::from_bytes(vec![i as u8; 32]),
            sequence: Sequence::ZERO,
            witness: Witness::new(),
        })
        .collect();
    tx.input = input;
    tx
}

#[tokio::test]
async fn test_mock_env() {
    // Test cycle mock functions
    let env = MockEnv::new(CHECK_TRANSACTION_CYCLES_REQUIRED);
    let provider = providers::next_provider(env.config().btc_network());
    assert_eq!(
        env.cycles_accept(CHECK_TRANSACTION_CYCLES_SERVICE_FEE),
        CHECK_TRANSACTION_CYCLES_SERVICE_FEE
    );
    let available = env.cycles_available();
    assert_eq!(
        available,
        CHECK_TRANSACTION_CYCLES_REQUIRED - CHECK_TRANSACTION_CYCLES_SERVICE_FEE
    );
    assert_eq!(
        env.cycles_accept(CHECK_TRANSACTION_CYCLES_REQUIRED),
        available
    );

    // Test get_tx mock function
    let env = MockEnv::new(0);
    let txid = mock_txid(0);
    env.expect_get_tx_with_reply(Ok(mock_transaction()));
    let result = env
        .http_get_tx(&provider, txid, INITIAL_MAX_RESPONSE_BYTES)
        .await;
    assert!(result.is_ok());
    env.assert_get_tx_call(txid, INITIAL_MAX_RESPONSE_BYTES);
    env.assert_no_more_get_tx_call();
}

#[test]
fn test_try_fetch_tx() {
    let mut env = MockEnv::new(CHECK_TRANSACTION_CYCLES_REQUIRED);
    let txid_0 = mock_txid(0);
    let txid_1 = mock_txid(1);
    let txid_2 = mock_txid(2);
    let from_tx = |tx: &bitcoin::Transaction| {
        TransactionCheckData::from_transaction(&env.config().btc_network(), tx.clone()).unwrap()
    };

    // case Fetched
    let fetched_0 = FetchTxStatus::Fetched(FetchedTx {
        tx: from_tx(&mock_transaction()),
        input_addresses: vec![None],
    });
    state::set_fetch_status(txid_0, fetched_0.clone());
    assert!(matches!(
        env.try_fetch_tx(txid_0),
        TryFetchResult::Fetched(_)
    ));

    // case Pending
    state::set_fetch_status(txid_1, FetchTxStatus::PendingOutcall);
    assert!(matches!(env.try_fetch_tx(txid_1), TryFetchResult::Pending));

    // case HighLoad
    env.high_load = true;
    assert!(matches!(env.try_fetch_tx(txid_2), TryFetchResult::HighLoad));
    env.high_load = false;

    // case NotEnoughCycles
    assert!(matches!(
        MockEnv::new(0).try_fetch_tx(txid_2),
        TryFetchResult::NotEnoughCycles
    ));

    // case ToFetch
    let available = env.cycles_available();
    assert!(state::get_fetch_status(txid_2).is_none());
    assert!(matches!(
        env.try_fetch_tx(mock_txid(2)),
        TryFetchResult::ToFetch(_)
    ));
    assert_eq!(
        env.cycles_available(),
        available - get_tx_cycle_cost(INITIAL_MAX_RESPONSE_BYTES, TEST_SUBNET_NODES)
    );
}

#[tokio::test]
async fn test_fetch_tx() {
    let env = MockEnv::new(CHECK_TRANSACTION_CYCLES_REQUIRED);
    let provider = providers::next_provider(env.config().btc_network());
    let txid_0 = mock_txid(0);
    let txid_1 = mock_txid(1);
    let txid_2 = mock_txid(2);
    let from_tx = |tx: &bitcoin::Transaction| {
        TransactionCheckData::from_transaction(&env.config().btc_network(), tx.clone()).unwrap()
    };

    // case Fetched
    let tx_0 = mock_transaction_with_inputs(vec![(txid_1, 0), (txid_2, 1)]);

    env.expect_get_tx_with_reply(Ok(tx_0.clone()));
    let result = env
        .fetch_tx((), provider.clone(), txid_0, INITIAL_MAX_RESPONSE_BYTES)
        .await;
    assert!(matches!(result, Ok(FetchResult::Fetched(_))));
    assert!(matches!(
        state::get_fetch_status(txid_0),
        Some(FetchTxStatus::Fetched(_))
    ));
    if let Ok(FetchResult::Fetched(fetched)) = result {
        assert_eq!(fetched.tx, from_tx(&tx_0));
        assert_eq!(fetched.input_addresses, vec![None, None]);
    } else {
        unreachable!()
    }

    // case RetryWithBiggerBuffer
    env.expect_get_tx_with_reply(Err(HttpGetTxError::ResponseTooLarge));
    let result = env
        .fetch_tx((), provider.clone(), txid_1, INITIAL_MAX_RESPONSE_BYTES)
        .await;
    assert!(matches!(result, Ok(FetchResult::RetryWithBiggerBuffer)));
    assert!(matches!(
                state::get_fetch_status(txid_1),
                Some(FetchTxStatus::PendingRetry { max_response_bytes }) if max_response_bytes == RETRY_MAX_RESPONSE_BYTES));

    // case Err
    env.expect_get_tx_with_reply(Err(HttpGetTxError::TxEncoding(
        "failed to decode tx".to_string(),
    )));
    let result = env
        .fetch_tx((), provider.clone(), txid_2, INITIAL_MAX_RESPONSE_BYTES)
        .await;
    assert!(matches!(
        result,
        Ok(FetchResult::Error(HttpGetTxError::TxEncoding(_)))
    ));
    assert!(matches!(
        state::get_fetch_status(txid_2),
        Some(FetchTxStatus::Error(FetchTxStatusError {
            error: HttpGetTxError::TxEncoding(_),
            ..
        }))
    ));
}

#[tokio::test]
async fn test_check_fetched() {
    let mut env = MockEnv::new(CHECK_TRANSACTION_CYCLES_REQUIRED);
    let good_address = Address::from_str("12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S")
        .unwrap()
        .assume_checked();
    let bad_address = Address::from_str(blocklist::BTC_ADDRESS_BLOCKLIST[0])
        .unwrap()
        .assume_checked();

    let txid_0 = mock_txid(0);
    let txid_1 = mock_txid(1);
    let txid_2 = mock_txid(2);
    let tx_0 = mock_transaction_with_inputs(vec![(txid_1, 0), (txid_2, 1)]);
    let tx_1 = mock_transaction_with_outputs(1);
    let tx_2 = mock_transaction_with_outputs(2);
    let network = env.config().btc_network();
    let from_tx = |tx: &bitcoin::Transaction| {
        TransactionCheckData::from_transaction(&network, tx.clone()).unwrap()
    };

    // case Passed
    let fetched = FetchedTx {
        tx: from_tx(&tx_0),
        input_addresses: vec![Some(good_address.clone())],
    };
    state::set_fetch_status(txid_0, FetchTxStatus::Fetched(fetched.clone()));
    assert!(matches!(
        env.check_fetched(txid_0, &fetched).await,
        CheckTransactionResponse::Passed
    ));
    // Check accepted cycles
    assert_eq!(env.cycles_accepted(), 0);

    // case Failed
    let fetched = FetchedTx {
        tx: from_tx(&tx_0),
        input_addresses: vec![Some(good_address.clone()), Some(bad_address)],
    };
    state::set_fetch_status(txid_0, FetchTxStatus::Fetched(fetched.clone()));
    assert!(matches!(
        env.check_fetched(txid_0, &fetched).await,
        CheckTransactionResponse::Failed(_)
    ));
    // Check accepted cycle
    assert_eq!(env.cycles_accepted(), 0);

    // case HighLoad
    env.high_load = true;
    let fetched = FetchedTx {
        tx: from_tx(&tx_0),
        input_addresses: vec![Some(good_address), None],
    };
    state::set_fetch_status(txid_0, FetchTxStatus::Fetched(fetched.clone()));
    assert!(matches!(
        env.check_fetched(txid_0, &fetched).await,
        CheckTransactionResponse::Unknown(CheckTransactionStatus::Retriable(
            CheckTransactionRetriable::HighLoad
        ))
    ));
    // Check accepted cycle
    assert_eq!(env.cycles_accepted(), 0);
    env.high_load = false;

    // case NotEnoughCycles
    let env = MockEnv::new(get_tx_cycle_cost(INITIAL_MAX_RESPONSE_BYTES, TEST_SUBNET_NODES) / 2);
    assert!(matches!(
        env.check_fetched(txid_0, &fetched).await,
        CheckTransactionResponse::Unknown(CheckTransactionStatus::NotEnoughCycles)
    ));
    // Check available cycles: we deduct all remaining cycles even when they are not enough
    assert_eq!(env.cycles_available(), 0);

    // case Pending: need 2 inputs, but only able to get 1 for now
    let env =
        MockEnv::new(get_tx_cycle_cost(INITIAL_MAX_RESPONSE_BYTES, TEST_SUBNET_NODES) * 3 / 2);
    let fetched = FetchedTx {
        tx: from_tx(&tx_0),
        input_addresses: vec![None, None],
    };
    state::set_fetch_status(txid_0, FetchTxStatus::Fetched(fetched.clone()));
    env.expect_get_tx_with_reply(Ok(tx_1.clone()));
    assert!(matches!(
        env.check_fetched(txid_0, &fetched).await,
        CheckTransactionResponse::Unknown(CheckTransactionStatus::Retriable(
            CheckTransactionRetriable::Pending
        ))
    ));
    // Check remaining cycle: we deduct all remaining cycles when they are not enough
    assert_eq!(env.cycles_available(), 0);
    // Continue to get another one, should pass
    env.refill_cycles(get_tx_cycle_cost(
        INITIAL_MAX_RESPONSE_BYTES,
        TEST_SUBNET_NODES,
    ));
    env.expect_get_tx_with_reply(Ok(tx_2.clone()));
    assert!(matches!(
        env.check_fetched(txid_0, &fetched).await,
        CheckTransactionResponse::Passed
    ));
    // Check remaining cycle
    assert_eq!(env.cycles_available(), 0);

    // case Passed: need 2 inputs, and getting both
    let env = MockEnv::new(CHECK_TRANSACTION_CYCLES_REQUIRED);
    let fetched = FetchedTx {
        tx: from_tx(&tx_0),
        input_addresses: vec![None, None],
    };
    state::set_fetch_status(txid_0, FetchTxStatus::Fetched(fetched.clone()));
    state::clear_fetch_status(txid_1);
    state::clear_fetch_status(txid_2);
    env.expect_get_tx_with_reply(Ok(tx_1.clone()));
    env.expect_get_tx_with_reply(Ok(tx_2.clone()));
    assert!(matches!(
        env.check_fetched(txid_0, &fetched).await,
        CheckTransactionResponse::Passed
    ));
    // Check remaining cycle
    assert_eq!(
        env.cycles_available(),
        CHECK_TRANSACTION_CYCLES_REQUIRED
            - get_tx_cycle_cost(INITIAL_MAX_RESPONSE_BYTES, TEST_SUBNET_NODES) * 2
    );

    // case Passed: need 2 inputs, and 1 already exists in cache.
    let env = MockEnv::new(CHECK_TRANSACTION_CYCLES_REQUIRED);
    let fetched = FetchedTx {
        tx: from_tx(&tx_0),
        input_addresses: vec![None, None],
    };
    state::set_fetch_status(txid_0, FetchTxStatus::Fetched(fetched.clone()));
    state::set_fetch_status(
        txid_1,
        FetchTxStatus::Fetched(FetchedTx {
            tx: from_tx(&tx_1),
            input_addresses: vec![],
        }),
    );
    state::clear_fetch_status(txid_2);
    env.expect_get_tx_with_reply(Ok(tx_2.clone()));
    assert!(matches!(
        env.check_fetched(txid_0, &fetched).await,
        CheckTransactionResponse::Passed
    ));
    // Check remaining cycle
    assert_eq!(
        env.cycles_available(),
        CHECK_TRANSACTION_CYCLES_REQUIRED
            - get_tx_cycle_cost(INITIAL_MAX_RESPONSE_BYTES, TEST_SUBNET_NODES)
    );

    // case Pending: need 2 input, but 1 of them gives RetryWithBiggerBuffer error.
    let env = MockEnv::new(CHECK_TRANSACTION_CYCLES_REQUIRED);
    let fetched = FetchedTx {
        tx: from_tx(&tx_0),
        input_addresses: vec![None, None],
    };
    state::set_fetch_status(txid_0, FetchTxStatus::Fetched(fetched.clone()));
    state::clear_fetch_status(txid_1);
    state::clear_fetch_status(txid_2);
    env.expect_get_tx_with_reply(Ok(tx_1.clone()));
    env.expect_get_tx_with_reply(Err(HttpGetTxError::ResponseTooLarge));
    assert!(matches!(
        env.check_fetched(txid_0, &fetched).await,
        CheckTransactionResponse::Unknown(CheckTransactionStatus::Retriable(
            CheckTransactionRetriable::Pending
        ))
    ));
    // Try again with bigger buffer, should Pass
    env.expect_get_tx_with_reply(Ok(tx_2.clone()));
    assert!(matches!(
        env.check_fetched(txid_0, &fetched).await,
        CheckTransactionResponse::Passed
    ));
    // Check remaining cycle
    assert_eq!(
        env.cycles_available(),
        CHECK_TRANSACTION_CYCLES_REQUIRED
            - get_tx_cycle_cost(INITIAL_MAX_RESPONSE_BYTES, TEST_SUBNET_NODES) * 2
            - get_tx_cycle_cost(RETRY_MAX_RESPONSE_BYTES, TEST_SUBNET_NODES)
    );

    // case Error: need 2 input, but 1 of them keeps giving RetryWithBiggerBuffer error.
    let env = MockEnv::new(CHECK_TRANSACTION_CYCLES_REQUIRED);
    let fetched = FetchedTx {
        tx: from_tx(&tx_0),
        input_addresses: vec![None, None],
    };
    state::set_fetch_status(txid_0, FetchTxStatus::Fetched(fetched.clone()));
    state::clear_fetch_status(txid_1);
    state::clear_fetch_status(txid_2);
    env.expect_get_tx_with_reply(Ok(tx_1.clone()));
    env.expect_get_tx_with_reply(Err(HttpGetTxError::ResponseTooLarge));
    assert!(matches!(
        env.check_fetched(txid_0, &fetched).await,
        CheckTransactionResponse::Unknown(CheckTransactionStatus::Retriable(
            CheckTransactionRetriable::Pending
        ))
    ));
    // Try again with bigger buffer, still fails
    env.expect_get_tx_with_reply(Err(HttpGetTxError::ResponseTooLarge));
    assert!(matches!(
            env.check_fetched(txid_0, &fetched).await,
            CheckTransactionResponse::Unknown(CheckTransactionStatus::Error(
                CheckTransactionIrrecoverableError::ResponseTooLarge { txid }
            )) if txid_2.as_ref() == txid));
    // Check remaining cycle
    assert_eq!(
        env.cycles_available(),
        CHECK_TRANSACTION_CYCLES_REQUIRED
            - get_tx_cycle_cost(INITIAL_MAX_RESPONSE_BYTES, TEST_SUBNET_NODES) * 2
            - get_tx_cycle_cost(RETRY_MAX_RESPONSE_BYTES, TEST_SUBNET_NODES)
    );

    // case HttpGetTxError can be retried.
    let remaining_cycles = env.cycles_available();
    let provider = providers::next_provider(env.config().btc_network());
    state::set_fetch_status(
        txid_2,
        FetchTxStatus::Error(FetchTxStatusError {
            provider: provider.clone(),
            max_response_bytes: RETRY_MAX_RESPONSE_BYTES,
            error: HttpGetTxError::Rejected {
                code: RejectionCode::SysTransient,
                message: "no more reply".to_string(),
            },
        }),
    );
    env.expect_get_tx_with_reply(Ok(tx_2.clone()));
    assert!(matches!(
        env.check_fetched(txid_0, &fetched).await,
        CheckTransactionResponse::Passed
    ));
    // check if provider has been rotated
    assert!(*env.called_provider.borrow() == Some(provider.next()));
    // Check remaining cycle. The cost should match RETRY_MAX_RESPONSE_BYTES
    assert_eq!(
        env.cycles_available(),
        remaining_cycles - get_tx_cycle_cost(RETRY_MAX_RESPONSE_BYTES, TEST_SUBNET_NODES)
    );

    // case Error: "Tx .. vout .. has no address ...". It should never happen
    // unless blockdata is corrupted.
    let env = MockEnv::new(CHECK_TRANSACTION_CYCLES_REQUIRED);
    let fetched = FetchedTx {
        tx: from_tx(&tx_0),
        input_addresses: vec![None, None],
    };
    state::set_fetch_status(txid_0, FetchTxStatus::Fetched(fetched.clone()));
    state::clear_fetch_status(txid_1);
    state::clear_fetch_status(txid_2);
    env.expect_get_tx_with_reply(Ok(tx_1.clone()));
    env.expect_get_tx_with_reply(Ok(mock_transaction_with_output_but_no_address(2)));
    assert!(matches!(
        env.check_fetched(txid_0, &fetched).await,
        CheckTransactionResponse::Unknown(CheckTransactionStatus::Error(
            CheckTransactionIrrecoverableError::InvalidTransaction(err)
        )) if err.contains("has no address")
    ));
}
