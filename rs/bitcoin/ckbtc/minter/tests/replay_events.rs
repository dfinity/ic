//! To refresh the stored events on disk, call the tests as follows
//! ```
//! bazel test --spawn_strategy=standalone //rs/bitcoin/ckbtc/minter:ckbtc_minter_replay_events_tests  --test_env=RETRIEVE_MINTER_EVENTS=true --test_arg "should_replay_events_for_mainnet" --test_timeout 900
//! ```
//! The parameter `spawn_strategy=standalone` is needed, because the events will be fetched from the running canister and the default sandbox doesn't allow it.
//! The parameter `test_env=RETRIEVE_MINTER_EVENTS=true` is needed to enable the fetching of the events.

use candid::{CandidType, Deserialize, Principal};
use ic_agent::Agent;
use ic_btc_interface::Txid;
use ic_ckbtc_minter::address::BitcoinAddress;
use ic_ckbtc_minter::state::eventlog::{replay, Event, EventType};
use ic_ckbtc_minter::state::invariants::{CheckInvariants, CheckInvariantsImpl};
use ic_ckbtc_minter::state::CkBtcMinterState;
use ic_ckbtc_minter::{
    build_unsigned_transaction_from_inputs, resubmit_transactions, BuildTxError, ECDSAPublicKey,
    Network,
};
use icrc_ledger_types::icrc1::account::Account;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, RwLock};

pub mod mock {
    use async_trait::async_trait;
    use candid::Principal;
    use ic_btc_checker::CheckTransactionResponse;
    use ic_btc_interface::Utxo;
    use ic_ckbtc_minter::management::CallError;
    use ic_ckbtc_minter::updates::update_balance::UpdateBalanceError;
    use ic_ckbtc_minter::{tx, CanisterRuntime, GetUtxosRequest, GetUtxosResponse, Network};
    use ic_management_canister_types_private::DerivationPath;
    use icrc_ledger_types::icrc1::account::Account;
    use icrc_ledger_types::icrc1::transfer::Memo;
    use mockall::mock;

    mock! {
        #[derive(Debug)]
        pub CanisterRuntime {}

        #[async_trait]
        impl CanisterRuntime for CanisterRuntime {
            fn caller(&self) -> Principal;
            fn id(&self) -> Principal;
            fn time(&self) -> u64;
            fn global_timer_set(&self, timestamp: u64);
            async fn bitcoin_get_utxos(&self, request: GetUtxosRequest) -> Result<GetUtxosResponse, CallError>;
            async fn check_transaction(&self, btc_checker_principal: Principal, utxo: &Utxo, cycle_payment: u128, ) -> Result<CheckTransactionResponse, CallError>;
            async fn mint_ckbtc(&self, amount: u64, to: Account, memo: Memo) -> Result<u64, UpdateBalanceError>;
            async fn sign_with_ecdsa(&self, key_name: String, derivation_path: DerivationPath, message_hash: [u8; 32]) -> Result<Vec<u8>, CallError>;
            async fn send_transaction(&self, transaction: &tx::SignedTransaction, network: Network) -> Result<(), CallError>;
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

fn assert_useless_events_is_empty(events: impl Iterator<Item = Event>) {
    let mut count = 0;
    for event in events {
        match &event.payload {
            EventType::ReceivedUtxos { utxos, .. } if utxos.is_empty() => {
                count += 1;
            }
            _ => {}
        }
    }
    assert_eq!(count, 0);
}

async fn should_migrate_events_for(file: impl GetEventsFile) -> CkBtcMinterState {
    use ic_ckbtc_minter::storage::{decode_event, encode_event, migrate_events};
    use ic_stable_structures::{
        log::Log as StableLog,
        memory_manager::{MemoryId, MemoryManager},
        DefaultMemoryImpl,
    };

    file.retrieve_and_store_events_if_env().await;

    let mgr = MemoryManager::init(DefaultMemoryImpl::default());
    let old_events = StableLog::new(mgr.get(MemoryId::new(0)), mgr.get(MemoryId::new(1)));
    let new_events = StableLog::new(mgr.get(MemoryId::new(2)), mgr.get(MemoryId::new(3)));
    let events = file.deserialize().events;
    events.iter().for_each(|event| {
        old_events.append(&encode_event(event)).unwrap();
    });
    let removed = migrate_events(&old_events, &new_events);
    assert!(removed > 0);
    assert!(!new_events.is_empty());
    assert_eq!(new_events.len() + removed, old_events.len());
    assert_useless_events_is_empty(new_events.iter().map(|bytes| decode_event(&bytes)));

    let state =
        replay::<SkipCheckInvariantsImpl>(new_events.iter().map(|bytes| decode_event(&bytes)))
            .expect("Failed to replay events");
    state
        .check_invariants()
        .expect("Failed to check invariants");

    state
}

#[tokio::test]
async fn should_migrate_events_for_testnet() {
    let state = should_migrate_events_for(Testnet).await;
    assert_eq!(state.btc_network, Network::Testnet);
    assert_eq!(state.get_total_btc_managed(), 16_578_205_978);
}

#[tokio::test]
async fn should_replay_events_for_mainnet() {
    Mainnet.retrieve_and_store_events_if_env().await;

    let state = replay::<SkipCheckInvariantsImpl>(Mainnet.deserialize().events.into_iter())
        .expect("Failed to replay events");
    state
        .check_invariants()
        .expect("Failed to check invariants");

    assert_eq!(state.btc_network, Network::Mainnet);
    assert_eq!(state.get_total_btc_managed(), 43_332_249_778);
}

#[tokio::test]
async fn should_not_resubmit_tx_87ebf46e400a39e5ec22b28515056a3ce55187dba9669de8300160ac08f64c30() {
    Mainnet.retrieve_and_store_events_if_env().await;

    let state = replay::<SkipCheckInvariantsImpl>(Mainnet.deserialize().events.into_iter())
        .expect("Failed to replay events");

    assert_eq!(state.btc_network, Network::Mainnet);
    assert_eq!(state.get_total_btc_managed(), 43_332_249_778);

    let tx_id = "87ebf46e400a39e5ec22b28515056a3ce55187dba9669de8300160ac08f64c30";

    let submitted_tx = {
        let mut txs: Vec<_> = state
            .submitted_transactions
            .iter()
            .filter(|tx| tx.txid.to_string() == tx_id)
            .collect();
        assert_eq!(txs.len(), 1);
        txs.pop().unwrap()
    };

    assert_eq!(submitted_tx.requests.len(), 43);
    assert_eq!(
        submitted_tx
            .requests
            .iter()
            .map(|req| req.amount)
            .sum::<u64>(),
        3_316_317_017_u64 //33 BTC!
    );
    assert_eq!(submitted_tx.used_utxos.len(), 1_799);
    assert_eq!(submitted_tx.fee_per_vbyte, Some(7_486));

    let outputs = submitted_tx
        .requests
        .iter()
        .map(|req| (req.address.clone(), req.amount))
        .collect();
    let input_utxos = &submitted_tx.used_utxos;
    let main_address = BitcoinAddress::parse(
        "bc1q0jrxz4jh59t5qsu7l0y59kpfdmgjcq60wlee3h",
        Network::Mainnet,
    )
    .unwrap();
    let tx_fee_per_vbyte = submitted_tx.fee_per_vbyte.unwrap();
    let build_tx_error = build_unsigned_transaction_from_inputs(
        input_utxos,
        outputs,
        main_address.clone(),
        tx_fee_per_vbyte,
    )
    .unwrap_err();

    assert_eq!(
        build_tx_error,
        BuildTxError::TooManyInputs {
            num_inputs: 1799,
            max_num_inputs: 1000
        }
    );

    let tx_id = Txid::from_str(tx_id).unwrap();
    let min_amount = 50_000;
    let mut transactions = BTreeMap::new();
    transactions.insert(tx_id, submitted_tx.clone());
    let mut runtime = mock::MockCanisterRuntime::new();
    let replaced = RefCell::new(vec![]);
    let transactions_sent: Arc<RwLock<Vec<Vec<u8>>>> = Arc::new(RwLock::new(vec![]));
    runtime.expect_time().return_const(0u64);
    runtime
        .expect_sign_with_ecdsa()
        .return_const(Ok(FAKE_SEC1_SIG.to_vec()));
    let sent_clone = transactions_sent.clone();
    runtime.expect_send_transaction().returning(move |tx, _| {
        let mut arr = sent_clone.write().unwrap();
        arr.push(tx.serialize());
        Ok(())
    });
    resubmit_transactions(
        "mock_key",
        123,
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
        |old_txid, new_tx| replaced.borrow_mut().push((old_txid, new_tx)),
        &runtime,
    )
    .await;
    let replaced = replaced.borrow();
    assert_eq!(replaced.len(), 1);
    assert_eq!(replaced[0].0, tx_id);
    let sent = transactions_sent.read().unwrap();
    assert_eq!(sent.len(), 1);
}

#[tokio::test]
async fn should_replay_events_for_testnet() {
    Testnet.retrieve_and_store_events_if_env().await;

    let state = replay::<SkipCheckInvariantsImpl>(Testnet.deserialize().events.into_iter())
        .expect("Failed to replay events");
    state
        .check_invariants()
        .expect("Failed to check invariants");

    assert_eq!(state.btc_network, Network::Testnet);
    assert_eq!(state.get_total_btc_managed(), 16_578_205_978);
}

// This test is ignored because it takes too long to run,
// roughly 50 minutes. It's useful to run it locally when
// updating mainnet_events.gz or testnet_events.gz.
// bazel test //rs/bitcoin/ckbtc/minter:ckbtc_minter_replay_events_tests --test_arg="should_replay_events_and_check_invariants" --test_arg=--ignored
#[test]
#[ignore]
fn should_replay_events_and_check_invariants() {
    fn test(file: impl GetEventsFile + std::fmt::Debug) {
        let events = file.deserialize();
        println!("Replaying {} {:?} events", events.total_event_count, file);
        let _state = replay::<CheckInvariantsImpl>(events.events.into_iter())
            .expect("Failed to replay events");
    }
    test(Mainnet);
    test(Testnet);
}

// It's not clear why those events are here in the first place
// but this test ensures that the number of such events doesn't grow.
#[tokio::test]
async fn should_not_grow_number_of_useless_events() {
    fn test(file: impl GetEventsFile) -> (u64, Vec<usize>) {
        let events = file.deserialize();
        let received_utxo_to_minter_with_empty_utxos = EventType::ReceivedUtxos {
            mint_txid: None,
            to_account: file.minter_canister_id().into(),
            utxos: vec![],
        };

        let useless_events_indexes =
            assert_useless_events_eq(&events.events, &received_utxo_to_minter_with_empty_utxos);
        (events.total_event_count, useless_events_indexes)
    }

    let (total_event_count, useless_events_indexes) = test(Mainnet);
    assert_eq!(total_event_count, 551_739);
    assert_eq!(useless_events_indexes.len(), 0);

    let (total_event_count, useless_events_indexes) = test(Testnet);
    assert_eq!(total_event_count, 46_815);
    assert_eq!(useless_events_indexes.len(), 4_044);
    assert_eq!(useless_events_indexes.last(), Some(&4_614_usize));

    fn assert_useless_events_eq(
        events: &[Event],
        expected_useless_event: &EventType,
    ) -> Vec<usize> {
        let mut indexes = Vec::new();
        for (index, event) in events.iter().enumerate() {
            match &event.payload {
                EventType::ReceivedUtxos { utxos, .. } if utxos.is_empty() => {
                    assert_eq!(&event.payload, expected_useless_event);
                    indexes.push(index);
                }
                _ => {}
            }
        }
        indexes
    }
}

#[derive(Debug)]
struct Mainnet;

#[derive(Debug)]
struct Testnet;

trait GetEventsFile {
    // TODO (XC-261):
    // These associated types are meant to deal with the the type difference in existing
    // event logs between mainnet (with timestamps) and testnet (without timestamps)
    // when we deserialize them for processing. This difference will go away once
    // we re-deploy the testnet canister. These types (and the GetEventsFile trait)
    // should be consolidated by then.
    type EventType: CandidType + for<'a> Deserialize<'a> + Into<Event>;
    type ResultType: CandidType + for<'a> Deserialize<'a> + Into<GetEventsResult>;

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
        Decode!(&raw_result, Vec<Self::EventType>)
            .unwrap()
            .into_iter()
            .map(|x| x.into())
            .collect()
    }

    async fn retrieve_and_store_events(&self) {
        use candid::Encode;
        use flate2::bufread::GzEncoder;
        use flate2::Compression;
        use ic_agent::{identity::AnonymousIdentity, Agent};
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
        Decode!(&decompressed_buffer, Self::ResultType)
            .expect("Failed to decode events")
            .into()
    }
}

impl GetEventsFile for Mainnet {
    type EventType = Event;
    type ResultType = GetEventsResult;
    fn minter_canister_id(&self) -> Principal {
        Principal::from_text("mqygn-kiaaa-aaaar-qaadq-cai").unwrap()
    }
    fn file_name(&self) -> &str {
        "mainnet_events.gz"
    }
}

impl GetEventsFile for Testnet {
    type EventType = EventType;
    type ResultType = GetEventsWithoutTimestampsResult;
    fn minter_canister_id(&self) -> Principal {
        Principal::from_text("ml52i-qqaaa-aaaar-qaaba-cai").unwrap()
    }
    fn file_name(&self) -> &str {
        "testnet_events.gz"
    }
}

// TODO XC-261: Remove
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct GetEventsWithoutTimestampsResult {
    pub events: Vec<EventType>,
    pub total_event_count: u64,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct GetEventsResult {
    pub events: Vec<Event>,
    pub total_event_count: u64,
}

// TODO XC-261: Remove
impl From<GetEventsWithoutTimestampsResult> for GetEventsResult {
    fn from(value: GetEventsWithoutTimestampsResult) -> Self {
        Self {
            events: value.events.into_iter().map(Event::from).collect(),
            total_event_count: value.total_event_count,
        }
    }
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
