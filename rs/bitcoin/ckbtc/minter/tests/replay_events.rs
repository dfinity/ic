//! To refresh the stored events on disk, call the tests as follows
//! ```
//! bazel test --spawn_strategy=standalone //rs/bitcoin/ckbtc/minter:ckbtc_minter_replay_events_tests  --test_env=RETRIEVE_MINTER_EVENTS=true --test_arg "should_replay_events_for_mainnet" --test_timeout 900
//! ```
//! The parameter `spawn_strategy=standalone` is needed, because the events will be fetched from the running canister and the default sandbox doesn't allow it.
//! The parameter `test_env=RETRIEVE_MINTER_EVENTS=true` is needed to enable the fetching of the events.

use candid::{CandidType, Deserialize, Principal};
use ic_agent::Agent;
use ic_btc_interface::{OutPoint, Utxo};
use ic_ckbtc_minter::address::BitcoinAddress;
use ic_ckbtc_minter::fees::BitcoinFeeEstimator;
use ic_ckbtc_minter::reimbursement::InvalidTransactionError;
use ic_ckbtc_minter::state::CkBtcMinterState;
use ic_ckbtc_minter::state::eventlog::{Event, EventType, replay};
use ic_ckbtc_minter::state::invariants::{CheckInvariants, CheckInvariantsImpl};
use ic_ckbtc_minter::{
    BuildTxError, ECDSAPublicKey, MIN_RELAY_FEE_PER_VBYTE, MIN_RESUBMISSION_DELAY, Network,
    build_unsigned_transaction_from_inputs, process_maybe_finalized_transactions,
    resubmit_transactions, state, tx,
};
use icrc_ledger_types::icrc1::account::Account;
use maplit::btreeset;
use std::cell::RefCell;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, LazyLock, RwLock};

pub mod mock {
    use crate::CkBtcMinterState;
    use async_trait::async_trait;
    use candid::Principal;
    use ic_btc_checker::CheckTransactionResponse;
    use ic_btc_interface::Utxo;
    use ic_ckbtc_minter::address::BitcoinAddress;
    use ic_ckbtc_minter::fees::BitcoinFeeEstimator;
    use ic_ckbtc_minter::management::CallError;
    use ic_ckbtc_minter::updates::retrieve_btc::BtcAddressCheckStatus;
    use ic_ckbtc_minter::updates::update_balance::UpdateBalanceError;
    use ic_ckbtc_minter::{
        CanisterRuntime, GetCurrentFeePercentilesRequest, GetUtxosRequest, GetUtxosResponse,
        Network, tx,
    };
    use icrc_ledger_types::icrc1::account::Account;
    use icrc_ledger_types::icrc1::transfer::Memo;
    use mockall::mock;
    use std::time::Duration;

    mock! {
        #[derive(Debug)]
        pub CanisterRuntime {}

        #[async_trait]
        impl CanisterRuntime for CanisterRuntime {
            type Estimator = BitcoinFeeEstimator;
            fn caller(&self) -> Principal;
            fn id(&self) -> Principal;
            fn time(&self) -> u64;
            fn global_timer_set(&self, timestamp: u64);
            fn parse_address(&self, address: &str, network: Network) -> Result<BitcoinAddress, String>;
            fn block_time(&self, network: Network) -> Duration;
            fn derive_user_address(&self, state: &CkBtcMinterState, account: &Account) -> String;
            fn derive_minter_address(&self, state: &CkBtcMinterState) -> BitcoinAddress;
            fn derive_minter_address_str(&self, state: &CkBtcMinterState) -> String;
            fn refresh_fee_percentiles_frequency(&self) -> Duration;
            fn fee_estimator(&self, state: &CkBtcMinterState) -> BitcoinFeeEstimator;
            async fn get_current_fee_percentiles(&self, request: &GetCurrentFeePercentilesRequest) -> Result<Vec<u64>, CallError>;
            async fn get_utxos(&self, request: &GetUtxosRequest) -> Result<GetUtxosResponse, CallError>;
            async fn check_transaction(&self, btc_checker_principal: Option<Principal>, utxo: &Utxo, cycle_payment: u128, ) -> Result<CheckTransactionResponse, CallError>;
            async fn mint_ckbtc(&self, amount: u64, to: Account, memo: Memo) -> Result<u64, UpdateBalanceError>;
            async fn sign_with_ecdsa(&self, key_name: String, derivation_path: Vec<Vec<u8>>, message_hash: [u8; 32]) -> Result<Vec<u8>, CallError>;
            async fn send_transaction(&self, transaction: &tx::SignedTransaction, network: Network) -> Result<(), CallError>;
            async fn check_address( &self, btc_checker_principal: Option<Principal>, address: String, ) -> Result<BtcAddressCheckStatus, CallError>;
        }
    }
}

const FAKE_SEC1_SIG: [u8; 64] = [
    0x8A, 0x2F, 0x47, 0x1B, 0x9C, 0xF4, 0x31, 0x6E, 0xA3, 0x55, 0x17, 0xD1, 0x4A, 0xF2, 0x66, 0xCD,
    0x9B, 0x7E, 0xC2, 0x6D, 0x48, 0x1C, 0x3E, 0xA7, 0xFA, 0x1D, 0x22, 0x4B, 0x8E, 0x5F, 0x72, 0x81,
    0x6E, 0x19, 0xC4, 0xF8, 0x92, 0x57, 0x01, 0x3A, 0x5C, 0xAA, 0xDE, 0x12, 0x8B, 0x64, 0x9E, 0xC1,
    0x7D, 0xF5, 0x93, 0x54, 0x21, 0x0E, 0x8A, 0xC6, 0x3B, 0x1D, 0x4A, 0x2C, 0x77, 0x98, 0xF0, 0xEB,
];

pub fn mock_ecdsa_public_key() -> ECDSAPublicKey {
    const PUBLIC_KEY: [u8; 33] = [
        3, 148, 123, 81, 208, 34, 99, 144, 214, 13, 193, 18, 89, 94, 30, 185, 101, 191, 164, 124,
        208, 174, 236, 190, 3, 16, 230, 196, 9, 252, 191, 110, 127,
    ];
    const CHAIN_CODE: [u8; 32] = [
        75, 34, 9, 207, 130, 169, 36, 138, 73, 80, 39, 225, 249, 154, 160, 111, 145, 197, 192, 53,
        148, 5, 62, 21, 47, 232, 104, 195, 249, 32, 160, 189,
    ];
    ECDSAPublicKey {
        public_key: PUBLIC_KEY.to_vec(),
        chain_code: CHAIN_CODE.to_vec(),
    }
}

static MAINNET_EVENTS: LazyLock<GetEventsResult> = LazyLock::new(|| Mainnet.deserialize());
static MAINNET_STATE: LazyLock<CkBtcMinterState> = LazyLock::new(|| {
    replay::<SkipCheckInvariantsImpl>(MAINNET_EVENTS.events.iter().cloned())
        .expect("Failed to replay events")
});
static TESTNET_EVENTS: LazyLock<GetEventsResult> = LazyLock::new(|| Testnet.deserialize());

#[tokio::test]
async fn should_replay_events_for_mainnet() {
    Mainnet.retrieve_and_store_events_if_env().await;

    let state = &MAINNET_STATE;
    state
        .check_invariants()
        .expect("Failed to check invariants");

    assert_eq!(state.btc_network, Network::Mainnet);
    assert_eq!(state.get_total_btc_managed(), 40_431_602_885);
}

#[tokio::test]
async fn should_have_not_many_transactions_with_many_used_utxos() {
    let mut txs_by_used_utxos: BTreeMap<_, Vec<String>> = BTreeMap::new();
    for event in MAINNET_EVENTS.events.iter().cloned() {
        // Note: this does not consider resubmitted transactions (event `ReplacedBtcTransaction`)
        // which use the same UTXOs set as the replaced transaction.
        if let EventType::SentBtcTransaction { utxos, txid, .. } = event.payload {
            txs_by_used_utxos
                .entry(std::cmp::Reverse(utxos.len()))
                .and_modify(|txs| txs.push(txid.to_string()))
                .or_insert(vec![txid.to_string()]);
        }
    }

    let mut iter = txs_by_used_utxos.into_iter();

    assert_eq!(
        iter.next(),
        Some((
            Reverse(1799),
            vec!["87ebf46e400a39e5ec22b28515056a3ce55187dba9669de8300160ac08f64c30".to_string()]
        ))
    );

    let (second_biggest_num_utxos, tx_ids) = iter.next().unwrap();
    assert!(
        second_biggest_num_utxos.0 <= 1_000,
        "Expected exactly one non-standard transaction, while all other transactions {tx_ids:?} must use at most 1_000 UTXOs"
    );
}

#[tokio::test]
async fn should_not_resubmit_tx_87ebf46e400a39e5ec22b28515056a3ce55187dba9669de8300160ac08f64c30() {
    Mainnet.retrieve_and_store_events_if_env().await;

    let mut state = MAINNET_STATE.clone();

    assert_eq!(state.btc_network, Network::Mainnet);
    assert_eq!(state.get_total_btc_managed(), 40_431_602_885);

    let txid = "87ebf46e400a39e5ec22b28515056a3ce55187dba9669de8300160ac08f64c30";

    let stuck_tx = {
        let txs: Vec<_> = state
            .stuck_transactions
            .iter()
            .filter(|tx| tx.txid.to_string() == txid)
            .collect();
        assert_eq!(txs.len(), 1);
        txs[0].clone()
    };

    assert_eq!(stuck_tx.submitted_at, 1_755_022_419_795_766_424);
    assert_eq!(stuck_tx.requests.len(), 43);
    assert_eq!(
        stuck_tx.requests.iter().map(|req| req.amount).sum::<u64>(),
        3_316_317_017_u64 //33 BTC!
    );
    assert_eq!(stuck_tx.used_utxos.len(), 1_799);
    assert_eq!(stuck_tx.fee_per_vbyte, Some(7_486));

    let principals: BTreeSet<_> = stuck_tx
        .requests
        .iter()
        .map(|req| req.reimbursement_account.unwrap())
        .map(|account| account.owner)
        .collect();
    assert_eq!(
        principals,
        btreeset! {Principal::from_text("ztwhb-qiaaa-aaaaj-azw7a-cai").unwrap()}
    );

    assert_eq!(state.replacement_txid.len(), 1);
    let resubmitted_txid = *state.replacement_txid.get(&stuck_tx.txid).unwrap();
    let resubmitted_tx = {
        let txs: Vec<_> = state
            .submitted_transactions
            .iter()
            .filter(|tx| tx.txid == resubmitted_txid)
            .collect();
        assert_eq!(txs.len(), 1);
        txs[0].clone()
    };
    assert_eq!(
        resubmitted_tx.txid.to_string(),
        "5ae2d26e623113e416a59892b4268d641ebc45be2954c5953136948a256da847"
    );
    assert_eq!(resubmitted_tx.submitted_at, 1_755_116_484_667_101_556);

    assert_eq!(stuck_tx.used_utxos, resubmitted_tx.used_utxos);
    assert_eq!(
        stuck_tx.fee_per_vbyte.unwrap() + MIN_RELAY_FEE_PER_VBYTE,
        resubmitted_tx.fee_per_vbyte.unwrap()
    );
    assert_eq!(stuck_tx.requests, resubmitted_tx.requests);

    let outputs = resubmitted_tx
        .requests
        .iter()
        .map(|req| (req.address.clone(), req.amount))
        .collect();
    let input_utxos = &resubmitted_tx.used_utxos;
    let main_address = BitcoinAddress::parse(
        "bc1q0jrxz4jh59t5qsu7l0y59kpfdmgjcq60wlee3h",
        Network::Mainnet,
    )
    .unwrap();
    let tx_fee_per_vbyte = resubmitted_tx.fee_per_vbyte.unwrap();
    let fee_estimator = BitcoinFeeEstimator::from_state(&state);
    let build_tx_error = build_unsigned_transaction_from_inputs(
        input_utxos,
        outputs,
        main_address.clone(),
        tx_fee_per_vbyte,
        &fee_estimator,
    )
    .unwrap_err();

    assert_eq!(
        build_tx_error,
        BuildTxError::InvalidTransaction(InvalidTransactionError::TooManyInputs {
            num_inputs: 1799,
            max_num_inputs: 1000
        })
    );

    // Check if a cancellation tx will be sent
    let min_amount = 50_000;
    let mut transactions = BTreeMap::new();
    transactions.insert(resubmitted_txid, resubmitted_tx.clone());
    let replaced = RefCell::new(vec![]);
    let transactions_sent: Arc<RwLock<Vec<tx::SignedTransaction>>> = Arc::new(RwLock::new(vec![]));
    let mut now = resubmitted_tx.submitted_at + MIN_RESUBMISSION_DELAY.as_nanos() as u64;
    let mut runtime = mock::MockCanisterRuntime::new();
    runtime.expect_time().return_const(now);
    runtime
        .expect_sign_with_ecdsa()
        .return_const(Ok(FAKE_SEC1_SIG.to_vec()));
    let sent_clone = transactions_sent.clone();
    runtime.expect_send_transaction().returning(move |tx, _| {
        let mut arr = sent_clone.write().unwrap();
        arr.push(tx.clone());
        Ok(())
    });
    let fee_estimator = BitcoinFeeEstimator::from_state(&state);
    resubmit_transactions(
        "mock_key",
        10,
        main_address,
        mock_ecdsa_public_key(),
        Network::Mainnet,
        min_amount,
        transactions,
        |_| {
            Some(Account {
                owner: Principal::anonymous(),
                subaccount: None,
            })
        },
        |old_txid, new_tx, reason| replaced.borrow_mut().push((old_txid, new_tx, reason)),
        &runtime,
        &fee_estimator,
    )
    .await;
    let replaced = replaced.borrow();
    assert_eq!(replaced.len(), 1);
    assert_eq!(replaced[0].0, resubmitted_txid);
    let cancellation_tx = replaced[0].1.clone();
    let replaced_reason = replaced[0].2.clone();
    let cancellation_txid = cancellation_tx.txid;
    assert_eq!(cancellation_tx.used_utxos.len(), 1);
    let used_utxo = cancellation_tx.used_utxos[0].clone();
    let sent = transactions_sent.read().unwrap();
    assert_eq!(sent.len(), 1);
    let signed_tx = sent[0].clone();
    assert_eq!(signed_tx.inputs.len(), 1);
    assert_eq!(&used_utxo.outpoint, &signed_tx.inputs[0].previous_output);

    // Trigger the replacement in state
    state::audit::replace_transaction(
        &mut state,
        resubmitted_txid,
        cancellation_tx.clone(),
        replaced_reason,
        &runtime,
    );
    assert!(
        !state
            .submitted_transactions
            .iter()
            .any(|tx| tx.txid == resubmitted_txid)
    );
    assert!(
        state
            .submitted_transactions
            .iter()
            .any(|tx| tx.txid == cancellation_txid)
    );
    assert!(
        state
            .stuck_transactions
            .iter()
            .any(|tx| tx.txid == resubmitted_txid)
    );

    // Check if transaction is canceled once cancellation tx is finalized.
    now += MIN_RESUBMISSION_DELAY.as_nanos() as u64;
    let main_account = Account {
        owner: Principal::from_text("mqygn-kiaaa-aaaar-qaadq-cai").unwrap(),
        subaccount: None,
    };
    let mut runtime = mock::MockCanisterRuntime::new();
    runtime.expect_time().return_const(now);
    let mut maybe_finalized_transactions = vec![(cancellation_txid, cancellation_tx)]
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    let mock_height = 910109u32;
    let new_utxos = signed_tx
        .outputs
        .iter()
        .enumerate()
        .map(|(i, out)| Utxo {
            outpoint: OutPoint {
                txid: cancellation_txid,
                vout: i as u32,
            },
            value: out.value,
            height: mock_height,
        })
        .collect::<Vec<_>>();
    process_maybe_finalized_transactions(
        &mut state,
        &mut maybe_finalized_transactions,
        new_utxos,
        main_account,
        &runtime,
    );
    assert!(
        !state
            .stuck_transactions
            .iter()
            .any(|tx| tx.txid == stuck_tx.txid)
    );
    assert!(
        !state
            .stuck_transactions
            .iter()
            .any(|tx| tx.txid == resubmitted_txid)
    );
    assert!(
        !state
            .submitted_transactions
            .iter()
            .any(|tx| tx.txid == cancellation_txid)
    );
    assert!(maybe_finalized_transactions.is_empty());
    assert!(!state.available_utxos.contains(&used_utxo));
    assert!(
        resubmitted_tx
            .used_utxos
            .iter()
            .all(|utxo| utxo == &used_utxo || state.available_utxos.contains(utxo))
    );
}

#[tokio::test]
async fn should_replay_events_for_testnet() {
    Testnet.retrieve_and_store_events_if_env().await;

    let state = replay::<SkipCheckInvariantsImpl>(TESTNET_EVENTS.events.iter().cloned())
        .expect("Failed to replay events");
    state
        .check_invariants()
        .expect("Failed to check invariants");

    assert_eq!(state.btc_network, Network::Testnet);
    assert_eq!(state.get_total_btc_managed(), 24_902_022_759);
}

// This test is ignored because it takes too long to run,
// roughly 50 minutes. It's useful to run it locally when
// updating mainnet_events.gz or testnet_events.gz.
// bazel test //rs/bitcoin/ckbtc/minter:ckbtc_minter_replay_events_tests --test_arg="should_replay_events_and_check_invariants" --test_arg=--ignored
#[test]
#[ignore]
fn should_replay_events_and_check_invariants() {
    fn test(events: &GetEventsResult) {
        println!("Replaying {} events", events.total_event_count);
        let _state = replay::<CheckInvariantsImpl>(events.events.iter().cloned())
            .expect("Failed to replay events");
    }
    test(&MAINNET_EVENTS);
    test(&TESTNET_EVENTS);
}

// Due to an initial bug, there were a lot of useless events.
// Those have been "removed" with [#3424](https://github.com/dfinity/ic/pull/3434),
// meaning that events have been migrated to a new stable memory region and those useless events
// have been filtered out during the migration.
// That means that those useless events still exist in the initial stable memory region and this test is to prevent
// any regression.
#[tokio::test]
async fn should_not_have_useless_events() {
    fn assert_useless_events_is_empty(events: &GetEventsResult) {
        let mut count = 0;
        for event in &events.events {
            match &event.payload {
                EventType::ReceivedUtxos { utxos, .. } if utxos.is_empty() => {
                    count += 1;
                }
                _ => {}
            }
        }
        assert_eq!(count, 0);
    }

    assert_useless_events_is_empty(&MAINNET_EVENTS);
    assert_useless_events_is_empty(&TESTNET_EVENTS);
}

#[derive(Debug)]
struct Mainnet;

#[derive(Debug)]
struct Testnet;

trait GetEventsFile {
    async fn retrieve_and_store_events_if_env(&self) {
        if std::env::var("RETRIEVE_MINTER_EVENTS").map(|s| s.parse().ok().unwrap_or_default())
            == Ok(true)
        {
            self.retrieve_and_store_events().await;
        }
    }

    async fn get_events(
        &self,
        agent: &Agent,
        minter_id: &Principal,
        start: u64,
        length: u64,
    ) -> Vec<Event> {
        use candid::{Decode, Encode};
        use ic_ckbtc_minter::state::eventlog::GetEventsArg;

        let arg = GetEventsArg { start, length };

        let raw_result = agent
            .update(minter_id, "get_events")
            .with_arg(Encode!(&arg).unwrap())
            .call_and_wait()
            .await
            .expect("Failed to call get_events");
        Decode!(&raw_result, Vec<Event>).unwrap()
    }

    async fn retrieve_and_store_events(&self) {
        use candid::Encode;
        use flate2::Compression;
        use flate2::bufread::GzEncoder;
        use ic_agent::{Agent, identity::AnonymousIdentity};
        use std::fs::File;
        use std::io::{BufReader, BufWriter, Read, Write};

        let agent = Agent::builder()
            .with_url("https://icp0.io")
            .with_identity(AnonymousIdentity)
            .build()
            .expect("Failed to create agent");

        const MAX_EVENTS_PER_QUERY: u64 = 2000;
        let mut events = Vec::new();
        loop {
            let fetched_events = self
                .get_events(
                    &agent,
                    &self.minter_canister_id(),
                    events.len() as u64,
                    MAX_EVENTS_PER_QUERY,
                )
                .await;
            if fetched_events.is_empty() {
                break;
            }
            events.extend(fetched_events);
        }
        let total_event_count = events.len() as u64;

        let encoded_all_events = Encode!(&GetEventsResult {
            events,
            total_event_count
        })
        .unwrap();
        let mut gz = GzEncoder::new(
            BufReader::new(encoded_all_events.as_slice()),
            Compression::best(),
        );
        let mut compressed_buffer = Vec::new();
        gz.read_to_end(&mut compressed_buffer)
            .expect("BUG: failed to compress events");
        let mut compressed_file = BufWriter::new(File::create(self.path_to_events_file()).unwrap());
        compressed_file
            .write_all(&compressed_buffer)
            .expect("BUG: failed to write events");
    }

    fn minter_canister_id(&self) -> Principal;

    fn path_to_events_file(&self) -> PathBuf {
        let mut path = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
        path.push(format!("test_resources/{}", self.file_name()));
        path
    }

    fn file_name(&self) -> &str;

    fn deserialize(&self) -> GetEventsResult {
        use candid::Decode;
        use flate2::read::GzDecoder;
        use std::fs::File;
        use std::io::Read;

        let file = File::open(self.path_to_events_file()).unwrap();
        let mut gz = GzDecoder::new(file);
        let mut decompressed_buffer = Vec::new();
        gz.read_to_end(&mut decompressed_buffer)
            .expect("BUG: failed to decompress events");
        Decode!(&decompressed_buffer, GetEventsResult).expect("Failed to decode events")
    }
}

impl GetEventsFile for Mainnet {
    fn minter_canister_id(&self) -> Principal {
        Principal::from_text("mqygn-kiaaa-aaaar-qaadq-cai").unwrap()
    }
    fn file_name(&self) -> &str {
        "mainnet_events.gz"
    }
}

impl GetEventsFile for Testnet {
    fn minter_canister_id(&self) -> Principal {
        Principal::from_text("ml52i-qqaaa-aaaar-qaaba-cai").unwrap()
    }
    fn file_name(&self) -> &str {
        "testnet_events.gz"
    }
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct GetEventsResult {
    pub events: Vec<Event>,
    pub total_event_count: u64,
}

/// This struct is used to skip the check invariants when replaying the events
/// because it otherwise takes too long.
///
/// This is because invariants are checked upon `ReceivedUtxos` events and
/// each check is linear over the state size, meaning overall complexity is quadratic
/// with the number of `ReceivedUtxos` events.
pub enum SkipCheckInvariantsImpl {}

impl CheckInvariants for SkipCheckInvariantsImpl {
    fn check_invariants(_state: &CkBtcMinterState) -> Result<(), String> {
        Ok(())
    }
}
