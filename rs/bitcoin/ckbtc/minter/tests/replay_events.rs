//! To refresh the stored events on disk, call the tests as follows
//! ```
//! bazel test --spawn_strategy=standalone //rs/bitcoin/ckbtc/minter:ckbtc_minter_replay_events_tests  --test_env=RETRIEVE_MINTER_EVENTS=true --test_arg "should_replay_events_for_mainnet" --test_timeout 900
//! ```
//! The parameter `spawn_strategy=standalone` is needed, because the events will be fetched from the running canister and the default sandbox doesn't allow it.
//! The parameter `test_env=RETRIEVE_MINTER_EVENTS=true` is needed to enable the fetching of the events.

use candid::{CandidType, Deserialize, Principal};
use ic_agent::Agent;
use ic_ckbtc_minter::state::eventlog::{replay, Event, EventType};
use ic_ckbtc_minter::state::invariants::{CheckInvariants, CheckInvariantsImpl};
use ic_ckbtc_minter::state::CkBtcMinterState;
use ic_ckbtc_minter::Network;
use std::path::PathBuf;

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
async fn should_migrate_events_for_mainnet() {
    let state = should_migrate_events_for(Mainnet).await;
    assert_eq!(state.btc_network, Network::Mainnet);
    assert_eq!(state.get_total_btc_managed(), 20_209_150_152);
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
    assert_eq!(state.get_total_btc_managed(), 20_209_150_152);
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
    assert_eq!(total_event_count, 443_137);
    assert_eq!(useless_events_indexes.len(), 409_141);
    assert_eq!(useless_events_indexes.last(), Some(&411_301_usize));

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
