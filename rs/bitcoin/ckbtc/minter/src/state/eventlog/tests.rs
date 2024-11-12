use crate::state::eventlog::{replay, Event};
use crate::Network;
use candid::{CandidType, Deserialize, Principal};
use ic_agent::Agent;
use std::path::PathBuf;

#[tokio::test]
async fn should_replay_events_for_mainnet() {
    GetEventsFile::Mainnet
        .retrieve_and_store_events_if_env()
        .await;

    let state = replay(GetEventsFile::Mainnet.deserialize()).expect("Failed to replay events");

    assert_eq!(state.btc_network, Network::Mainnet);
    assert_eq!(state.get_total_btc_managed(), 22_330_465_791);
}

#[tokio::test]
async fn should_replay_events_for_testnet() {
    GetEventsFile::Testnet
        .retrieve_and_store_events_if_env()
        .await;

    let state = replay(GetEventsFile::Testnet.deserialize()).expect("Failed to replay events");

    assert_eq!(state.btc_network, Network::Testnet);
    assert_eq!(state.get_total_btc_managed(), 16_578_205_978);
}

enum GetEventsFile {
    Mainnet,
    Testnet,
}

impl GetEventsFile {
    /// To refresh the stored events on disk, call the tests as follows
    /// ```
    /// bazel test --spawn_strategy=standalone //rs/bitcoin/ckbtc/minter:ckbtc_minter_lib_unit_tests  --test_env=RETRIEVE_MINTER_EVENTS=true --test_arg "should_replay_events_for_mainnet" --test_timeout 900
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
        use candid::{CandidType, Decode, Encode};
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

    fn deserialize(&self) -> impl Iterator<Item = Event> {
        use candid::Decode;
        use flate2::read::GzDecoder;
        use std::fs::File;
        use std::io::Read;

        let file = File::open(self.path_to_events_file()).unwrap();
        let mut gz = GzDecoder::new(file);
        let mut decompressed_buffer = Vec::new();
        gz.read_to_end(&mut decompressed_buffer)
            .expect("BUG: failed to decompress events");
        let events =
            Decode!(&decompressed_buffer, GetEventsResult).expect("Failed to decode events");
        let total_event_count = events.total_event_count;
        events
            .events
            .into_iter()
            .enumerate()
            .map(move |(index, event)| {
                println!("Replaying event {index}/{total_event_count}: {:?}", event);
                event
            })
    }
}

async fn get_events(agent: &Agent, minter_id: &Principal, start: u64, length: u64) -> Vec<Event> {
    use crate::state::eventlog::GetEventsArg;
    use candid::{Decode, Encode};

    let arg = GetEventsArg { start, length };

    let raw_result = agent
        .update(minter_id, "get_events")
        .with_arg(Encode!(&arg).unwrap())
        .call_and_wait()
        .await
        .expect("Failed to call get_events");
    Decode!(&raw_result, Vec<Event>).unwrap()
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct GetEventsResult {
    pub events: Vec<Event>,
    pub total_event_count: u64,
}
