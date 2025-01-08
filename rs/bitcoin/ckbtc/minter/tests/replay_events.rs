use candid::{CandidType, Deserialize, Principal};
use ic_agent::Agent;
use ic_ckbtc_minter::state::eventlog::{replay, Event, EventType};
use ic_ckbtc_minter::state::invariants::{CheckInvariants, CheckInvariantsImpl};
use ic_ckbtc_minter::state::{CkBtcMinterState, Network};
use std::path::PathBuf;

#[tokio::test]
async fn should_replay_events_for_mainnet() {
    GetEventsFile::Mainnet
        .retrieve_and_store_events_if_env()
        .await;

    let state =
        replay::<SkipCheckInvariantsImpl>(GetEventsFile::Mainnet.deserialize().events.into_iter())
            .expect("Failed to replay events");
    state
        .check_invariants()
        .expect("Failed to check invariants");

    assert_eq!(state.btc_network, Network::Mainnet);
    assert_eq!(state.get_total_btc_managed(), 21_723_786_340);
}

#[tokio::test]
async fn should_replay_events_for_testnet() {
    GetEventsFile::Testnet
        .retrieve_and_store_events_if_env()
        .await;

    let state =
        replay::<SkipCheckInvariantsImpl>(GetEventsFile::Testnet.deserialize().events.into_iter())
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
    for file in [GetEventsFile::Mainnet, GetEventsFile::Testnet] {
        let events = file.deserialize();
        println!("Replaying {} {:?} events", events.total_event_count, file);
        let _state = replay::<CheckInvariantsImpl>(events.events.into_iter())
            .expect("Failed to replay events");
    }
}

// It's not clear why those events are here in the first place
// but this test ensures that the number of such events doesn't grow.
#[tokio::test]
async fn should_not_grow_number_of_useless_events() {
    for file in [GetEventsFile::Mainnet, GetEventsFile::Testnet] {
        let events = file.deserialize();
        let received_utxo_to_minter_with_empty_utxos = EventType::ReceivedUtxos {
            mint_txid: None,
            to_account: file.minter_canister_id().into(),
            utxos: vec![],
        };

        let useless_events_indexes =
            assert_useless_events_eq(&events.events, &received_utxo_to_minter_with_empty_utxos);

        match file {
            GetEventsFile::Mainnet => {
                assert_eq!(events.total_event_count, 432_050);
                assert_eq!(useless_events_indexes.len(), 409_141);
                assert_eq!(useless_events_indexes.last(), Some(&411_301_usize));
            }
            GetEventsFile::Testnet => {
                assert_eq!(events.total_event_count, 46_815);
                assert_eq!(useless_events_indexes.len(), 4_044);
                assert_eq!(useless_events_indexes.last(), Some(&4_614_usize));
            }
        }
    }

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
enum GetEventsFile {
    Mainnet,
    Testnet,
}

impl GetEventsFile {
    /// To refresh the stored events on disk, call the tests as follows
    /// ```
    /// bazel test --spawn_strategy=standalone //rs/bitcoin/ckbtc/minter:ckbtc_minter_replay_events_tests  --test_env=RETRIEVE_MINTER_EVENTS=true --test_arg "should_replay_events_for_mainnet" --test_timeout 900
    /// ```
    /// The parameter `spawn_strategy=standalone` is needed, because the events will be fetched from the running canister and the default sandbox doesn't allow it.
    /// The parameter `test_env=RETRIEVE_MINTER_EVENTS=true` is needed to enable the fetching of the events.
    async fn retrieve_and_store_events_if_env(&self) {
        if std::env::var("RETRIEVE_MINTER_EVENTS").map(|s| s.parse().ok().unwrap_or_default())
            == Ok(true)
        {
            self.retrieve_and_store_events().await;
        }
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
            let fetched_events = get_events(
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

    fn minter_canister_id(&self) -> Principal {
        match self {
            GetEventsFile::Mainnet => Principal::from_text("mqygn-kiaaa-aaaar-qaadq-cai").unwrap(),
            GetEventsFile::Testnet => Principal::from_text("ml52i-qqaaa-aaaar-qaaba-cai").unwrap(),
        }
    }

    fn path_to_events_file(&self) -> PathBuf {
        let mut path = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
        path.push(format!("test_resources/{}", self.file_name()));
        path
    }

    fn file_name(&self) -> &str {
        match self {
            GetEventsFile::Mainnet => "mainnet_events.gz",
            GetEventsFile::Testnet => "testnet_events.gz",
        }
    }

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
        // TODO XC-261 The logic here assumes the compressed events in the file still use the
        //  'old' Candid interface (i.e. a vector of `EventTypes`). Once the deployed minter
        //  canister on mainnet/testnet return a result with the new interface, the explicit
        //  conversion from `EventType` to `Event` must be removed.
        Decode!(&decompressed_buffer, GetEventTypesResult)
            .expect("Failed to decode events")
            .into()
    }
}

async fn get_events(agent: &Agent, minter_id: &Principal, start: u64, length: u64) -> Vec<Event> {
    use candid::{Decode, Encode};
    use ic_ckbtc_minter::state::eventlog::GetEventsArg;

    let arg = GetEventsArg { start, length };

    let raw_result = agent
        .update(minter_id, "get_events")
        .with_arg(Encode!(&arg).unwrap())
        .call_and_wait()
        .await
        .expect("Failed to call get_events");
    // TODO XC-261 The logic here assumes the result we get from the minter canister `get_events`
    //  endpoint still uses the 'old' Candid interface (i.e. a vector of `EventTypes`). Once the
    //  deployed minter canisters on mainnet/testnet return a result with the new interface, the
    //  explicit conversion from `EventType` to `Event` must be removed.
    Decode!(&raw_result, Vec<EventType>)
        .unwrap()
        .into_iter()
        .map(Event::from)
        .collect()
}

// TODO XC-261: Remove
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct GetEventTypesResult {
    pub events: Vec<EventType>,
    pub total_event_count: u64,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct GetEventsResult {
    pub events: Vec<Event>,
    pub total_event_count: u64,
}

// TODO XC-261: Remove
impl From<GetEventTypesResult> for GetEventsResult {
    fn from(value: GetEventTypesResult) -> Self {
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
