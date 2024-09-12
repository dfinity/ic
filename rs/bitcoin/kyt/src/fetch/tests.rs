use super::*;
use crate::blocklist;
use bitcoin::{
    absolute::LockTime, hashes::Hash, transaction::Version, Amount, OutPoint, PubkeyHash,
    ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use ic_cdk::api::call::RejectionCode;
use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::str::FromStr;

struct MockState {
    statuses: RefCell<BTreeMap<Txid, FetchTxStatus>>,
    high_load: bool,
}

impl FetchState for MockState {
    type FetchGuard = ();
    fn new_fetch_guard(&self, _txid: Txid) -> Result<Self::FetchGuard, FetchGuardError> {
        if self.high_load {
            Err(FetchGuardError::NoCapacity)
        } else {
            Ok(())
        }
    }
    fn get_fetch_status(&self, txid: Txid) -> Option<FetchTxStatus> {
        self.statuses.borrow().get(&txid).cloned()
    }
    fn set_fetch_status(&self, txid: Txid, status: FetchTxStatus) {
        self.statuses.borrow_mut().insert(txid, status);
    }
    fn set_fetched_address(&self, txid: Txid, index: usize, address: Address) {
        self.statuses.borrow_mut().entry(txid).and_modify(|status| {
            if let FetchTxStatus::Fetched(fetched) = status {
                fetched.input_addresses[index] = Some(address);
            };
        });
    }
}

impl MockState {
    fn new() -> Self {
        Self {
            statuses: RefCell::new(BTreeMap::default()),
            high_load: false,
        }
    }
}

// A mock environment that provides simulated `get_tx` implementation, with
// mock states and transactions used for testing purpose.
struct MockEnv {
    calls: RefCell<VecDeque<(Txid, u32)>>,
    replies: RefCell<VecDeque<Result<Transaction, GetTxError>>>,
    available_cycles: RefCell<u128>,
    accepted_cycles: RefCell<u128>,
}

impl FetchEnv for MockEnv {
    async fn get_tx(&self, txid: Txid, buffer_size: u32) -> Result<Transaction, GetTxError> {
        self.calls.borrow_mut().push_back((txid, buffer_size));
        self.replies
            .borrow_mut()
            .pop_front()
            .unwrap_or(Err(GetTxError::Rejected {
                code: RejectionCode::from(0),
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
    fn cycles_available(&self) -> u128 {
        *self.available_cycles.borrow()
    }
}

impl MockEnv {
    fn new(available_cycles: u128) -> Self {
        Self {
            calls: RefCell::new(VecDeque::new()),
            replies: RefCell::new(VecDeque::new()),
            available_cycles: RefCell::new(available_cycles),
            accepted_cycles: RefCell::new(0),
        }
    }
    fn assert_get_tx_call(&self, txid: Txid, buffer_size: u32) {
        assert_eq!(
            self.calls.borrow_mut().pop_front(),
            Some((txid, buffer_size))
        )
    }
    fn assert_no_more_get_tx_call(&self) {
        assert_eq!(self.calls.borrow_mut().pop_front(), None)
    }
    fn expect_get_tx_with_reply(&self, reply: Result<Transaction, GetTxError>) {
        self.replies.borrow_mut().push_back(reply)
    }
    fn refill_cycles(&self, cycles: u128) {
        *self.available_cycles.borrow_mut() = cycles;
    }
    fn cycles_accepted(&self) -> u128 {
        *self.accepted_cycles.borrow()
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
    let result = env.get_tx(txid, INITIAL_BUFFER_SIZE).await;
    assert!(result.is_ok());
    env.assert_get_tx_call(txid, INITIAL_BUFFER_SIZE);
    env.assert_no_more_get_tx_call();
}

#[test]
fn test_try_fetch_tx() {
    let mut state = MockState::new();
    let env = MockEnv::new(CHECK_TRANSACTION_CYCLES_REQUIRED);
    let txid_0 = mock_txid(0);
    let txid_1 = mock_txid(1);

    // case Fetched
    let fetched_0 = FetchTxStatus::Fetched(FetchedTx {
        tx: mock_transaction(),
        input_addresses: vec![None],
    });
    state.set_fetch_status(txid_0, fetched_0.clone());
    assert!(matches!(
        env.try_fetch_tx(&state, txid_0),
        TryFetchResult::Fetched(_)
    ));

    // case Pending
    state.set_fetch_status(txid_1, FetchTxStatus::PendingOutcall);
    assert!(matches!(
        env.try_fetch_tx(&state, txid_1),
        TryFetchResult::Pending
    ));

    // case HighLoad
    state.high_load = true;
    assert!(matches!(
        env.try_fetch_tx(&state, mock_txid(2)),
        TryFetchResult::HighLoad
    ));
    state.high_load = false;

    // case NotEnoughCycles
    assert!(matches!(
        MockEnv::new(0).try_fetch_tx(&state, mock_txid(2)),
        TryFetchResult::NotEnoughCycles
    ));

    // case ToFetch
    let available = env.cycles_available();
    assert!(matches!(
        env.try_fetch_tx(&state, mock_txid(2)),
        TryFetchResult::ToFetch(_)
    ));
    assert_eq!(
        env.cycles_available(),
        available - get_tx_cycle_cost(INITIAL_BUFFER_SIZE)
    );
}

#[tokio::test]
async fn test_fetch_tx() {
    let state = MockState::new();
    let env = MockEnv::new(CHECK_TRANSACTION_CYCLES_REQUIRED);
    let txid_0 = mock_txid(0);
    let txid_1 = mock_txid(1);
    let txid_2 = mock_txid(2);

    // case Fetched
    let tx_0 = mock_transaction_with_inputs(vec![(txid_1, 0), (txid_2, 1)]);

    env.expect_get_tx_with_reply(Ok(tx_0.clone()));
    let result = env.fetch_tx(&state, (), txid_0, INITIAL_BUFFER_SIZE).await;
    assert!(matches!(result, Ok(FetchResult::Fetched(_))));
    assert!(matches!(
        state.get_fetch_status(txid_0),
        Some(FetchTxStatus::Fetched(_))
    ));
    if let Ok(FetchResult::Fetched(fetched)) = result {
        assert_eq!(fetched.tx, tx_0);
        assert_eq!(fetched.input_addresses, vec![None, None]);
    } else {
        unreachable!()
    }

    // case RetryWithBiggerBuffer
    env.expect_get_tx_with_reply(Err(GetTxError::ResponseTooLarge));
    let result = env.fetch_tx(&state, (), txid_1, INITIAL_BUFFER_SIZE).await;
    assert!(matches!(result, Ok(FetchResult::RetryWithBiggerBuffer)));
    assert!(matches!(
                state.get_fetch_status(txid_1),
                Some(FetchTxStatus::PendingRetry { buffer_size }) if buffer_size == RETRY_BUFFER_SIZE));

    // case Err
    env.expect_get_tx_with_reply(Err(GetTxError::TxEncoding(
        "failed to decode tx".to_string(),
    )));
    let result = env.fetch_tx(&state, (), txid_2, INITIAL_BUFFER_SIZE).await;
    assert!(matches!(
        result,
        Ok(FetchResult::Error(GetTxError::TxEncoding(_)))
    ));
    assert!(matches!(
        state.get_fetch_status(txid_2),
        Some(FetchTxStatus::Error(GetTxError::TxEncoding(_)))
    ));
}

#[tokio::test]
async fn test_check_fetched() {
    let state = MockState::new();
    let env = MockEnv::new(CHECK_TRANSACTION_CYCLES_REQUIRED);
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

    // case Passed
    let fetched = FetchedTx {
        tx: tx_0.clone(),
        input_addresses: vec![Some(good_address.clone())],
    };
    state.set_fetch_status(txid_0, FetchTxStatus::Fetched(fetched.clone()));
    assert!(matches!(
        env.check_fetched(&state, txid_0, &fetched).await,
        Ok(CheckTransactionResponse::Passed)
    ));
    // Check accepted cycles
    assert_eq!(env.cycles_accepted(), 0);

    // case Failed
    let fetched = FetchedTx {
        tx: tx_0.clone(),
        input_addresses: vec![Some(good_address.clone()), Some(bad_address)],
    };
    state.set_fetch_status(txid_0, FetchTxStatus::Fetched(fetched.clone()));
    assert!(matches!(
        env.check_fetched(&state, txid_0, &fetched).await,
        Ok(CheckTransactionResponse::Failed)
    ));
    // Check accepted cycle
    assert_eq!(env.cycles_accepted(), 0);

    // case HighLoad
    let mut state = MockState::new();
    state.high_load = true;
    let fetched = FetchedTx {
        tx: tx_0.clone(),
        input_addresses: vec![Some(good_address), None],
    };
    state.set_fetch_status(txid_0, FetchTxStatus::Fetched(fetched.clone()));
    assert!(matches!(
        env.check_fetched(&state, txid_0, &fetched).await,
        Ok(CheckTransactionResponse::HighLoad)
    ));
    // Check accepted cycle
    assert_eq!(env.cycles_accepted(), 0);

    // case NotEnoughCycles
    let state = MockState::new();
    let env = MockEnv::new(get_tx_cycle_cost(INITIAL_BUFFER_SIZE) / 2);
    assert!(matches!(
        env.check_fetched(&state, txid_0, &fetched).await,
        Ok(CheckTransactionResponse::NotEnoughCycles)
    ));
    // Check available cycles: we deduct all remaining cycles even when they are not enough
    assert_eq!(env.cycles_available(), 0);

    // case Pending: need 2 inputs, but only able to get 1 for now
    let state = MockState::new();
    let env = MockEnv::new(get_tx_cycle_cost(INITIAL_BUFFER_SIZE) * 3 / 2);
    let fetched = FetchedTx {
        tx: tx_0.clone(),
        input_addresses: vec![None, None],
    };
    state.set_fetch_status(txid_0, FetchTxStatus::Fetched(fetched.clone()));
    env.expect_get_tx_with_reply(Ok(tx_1.clone()));
    assert!(matches!(
        dbg!(env.check_fetched(&state, txid_0, &fetched).await),
        Ok(CheckTransactionResponse::Pending)
    ));
    // Check remaining cycle: we deduct all remaining cycles when they are not enough
    assert_eq!(env.cycles_available(), 0);
    // Continue to get another one, should pass
    env.refill_cycles(get_tx_cycle_cost(INITIAL_BUFFER_SIZE));
    env.expect_get_tx_with_reply(Ok(tx_2.clone()));
    assert!(matches!(
        env.check_fetched(&state, txid_0, &fetched).await,
        Ok(CheckTransactionResponse::Passed)
    ));
    // Check remaining cycle
    assert_eq!(env.cycles_available(), 0);

    // case Passed: need 2 inputs, and getting both
    let state = MockState::new();
    let env = MockEnv::new(CHECK_TRANSACTION_CYCLES_REQUIRED);
    let fetched = FetchedTx {
        tx: tx_0.clone(),
        input_addresses: vec![None, None],
    };
    state.set_fetch_status(txid_0, FetchTxStatus::Fetched(fetched.clone()));
    env.expect_get_tx_with_reply(Ok(tx_1.clone()));
    env.expect_get_tx_with_reply(Ok(tx_2.clone()));
    assert!(matches!(
        env.check_fetched(&state, txid_0, &fetched).await,
        Ok(CheckTransactionResponse::Passed)
    ));
    // Check remaining cycle
    assert_eq!(
        env.cycles_available(),
        CHECK_TRANSACTION_CYCLES_REQUIRED - get_tx_cycle_cost(INITIAL_BUFFER_SIZE) * 2
    );

    // case Passed: need 2 inputs, and 1 already exists in cache.
    let state = MockState::new();
    let env = MockEnv::new(CHECK_TRANSACTION_CYCLES_REQUIRED);
    let fetched = FetchedTx {
        tx: tx_0.clone(),
        input_addresses: vec![None, None],
    };
    state.set_fetch_status(txid_0, FetchTxStatus::Fetched(fetched.clone()));
    state.set_fetch_status(
        txid_1,
        FetchTxStatus::Fetched(FetchedTx {
            tx: tx_1.clone(),
            input_addresses: vec![],
        }),
    );
    env.expect_get_tx_with_reply(Ok(tx_2.clone()));
    assert!(matches!(
        env.check_fetched(&state, txid_0, &fetched).await,
        Ok(CheckTransactionResponse::Passed)
    ));
    // Check remaining cycle
    assert_eq!(
        env.cycles_available(),
        CHECK_TRANSACTION_CYCLES_REQUIRED - get_tx_cycle_cost(INITIAL_BUFFER_SIZE)
    );

    // case Pending: need 2 input, but 1 of them gives RetryWithBiggerBuffer error.
    let state = MockState::new();
    let env = MockEnv::new(CHECK_TRANSACTION_CYCLES_REQUIRED);
    let fetched = FetchedTx {
        tx: tx_0.clone(),
        input_addresses: vec![None, None],
    };
    state.set_fetch_status(txid_0, FetchTxStatus::Fetched(fetched.clone()));
    env.expect_get_tx_with_reply(Ok(tx_1.clone()));
    env.expect_get_tx_with_reply(Err(GetTxError::ResponseTooLarge));
    assert!(matches!(
        env.check_fetched(&state, txid_0, &fetched).await,
        Ok(CheckTransactionResponse::Pending)
    ));
    // Try again with bigger buffer, should Pass
    env.expect_get_tx_with_reply(Ok(tx_2.clone()));
    assert!(matches!(
        env.check_fetched(&state, txid_0, &fetched).await,
        Ok(CheckTransactionResponse::Passed)
    ));
    // Check remaining cycle
    assert_eq!(
        env.cycles_available(),
        CHECK_TRANSACTION_CYCLES_REQUIRED
            - get_tx_cycle_cost(INITIAL_BUFFER_SIZE) * 2
            - get_tx_cycle_cost(RETRY_BUFFER_SIZE)
    );

    // case Error: need 2 input, but 1 of them keeps giving RetryWithBiggerBuffer error.
    let state = MockState::new();
    let env = MockEnv::new(CHECK_TRANSACTION_CYCLES_REQUIRED);
    let fetched = FetchedTx {
        tx: tx_0.clone(),
        input_addresses: vec![None, None],
    };
    state.set_fetch_status(txid_0, FetchTxStatus::Fetched(fetched.clone()));
    env.expect_get_tx_with_reply(Ok(tx_1.clone()));
    env.expect_get_tx_with_reply(Err(GetTxError::ResponseTooLarge));
    assert!(matches!(
        env.check_fetched(&state, txid_0, &fetched).await,
        Ok(CheckTransactionResponse::Pending)
    ));
    // Try again with bigger buffer, still fails
    env.expect_get_tx_with_reply(Err(GetTxError::ResponseTooLarge));
    assert!(matches!(
            env.check_fetched(&state, txid_0, &fetched).await,
            Err(CheckTransactionError::ResponseTooLarge { txid }) if txid_2.as_ref() == txid));
    // Check remaining cycle
    assert_eq!(
        env.cycles_available(),
        CHECK_TRANSACTION_CYCLES_REQUIRED
            - get_tx_cycle_cost(INITIAL_BUFFER_SIZE) * 2
            - get_tx_cycle_cost(RETRY_BUFFER_SIZE)
    );
}
