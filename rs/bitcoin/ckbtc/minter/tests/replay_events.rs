//! To refresh the stored events on disk, call the tests as follows
//! ```
//! bazel test --spawn_strategy=standalone //rs/bitcoin/ckbtc/minter:ckbtc_minter_replay_events_tests  --test_env=RETRIEVE_MINTER_EVENTS=true --test_arg "should_replay_events_for_mainnet" --test_timeout 900
//! ```
//! The parameter `spawn_strategy=standalone` is needed, because the events will be fetched from the running canister and the default sandbox doesn't allow it.
//! The parameter `test_env=RETRIEVE_MINTER_EVENTS=true` is needed to enable the fetching of the events.

use candid::{CandidType, Deserialize, Principal};
use ic_agent::Agent;
use ic_ckbtc_minter::address::BitcoinAddress;
use ic_ckbtc_minter::state::eventlog::{replay, Event, EventType};
use ic_ckbtc_minter::state::invariants::{CheckInvariants, CheckInvariantsImpl};
use ic_ckbtc_minter::state::CkBtcMinterState;
use ic_ckbtc_minter::{
    build_unsigned_transaction_from_inputs, sign_transaction, ECDSAPublicKey, Network,
    SignTransactionError,
};
use std::collections::BTreeMap;
use std::path::PathBuf;

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
    let (unsigned_tx, _change_output) = build_unsigned_transaction_from_inputs(
        input_utxos,
        outputs,
        main_address.clone(),
        tx_fee_per_vbyte,
    )
    .unwrap();

    let sign_tx_error = sign_transaction(
        "does not matter".to_string(),
        &ECDSAPublicKey {
            public_key: vec![],
            chain_code: vec![],
        },
        &BTreeMap::default(),
        unsigned_tx,
    )
    .await
    .unwrap_err();
    assert_eq!(
        sign_tx_error,
        SignTransactionError::TooManyInputs {
            num_inputs: 1799,
            max_num_inputs: 1000
        }
    )
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
    assert_eq!(state.get_total_btc_managed(), 24_902_022_759);
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

// Due to an initial bug, there were a lot of useless events.
// Those have been "removed" with [#3424](https://github.com/dfinity/ic/pull/3434),
// meaning that events have been migrated to a new stable memory region and those useless events
// have been filtered out during the migration.
// That means that those useless events still exist in the initial stable memory region and this test is to prevent
// any regression.
#[tokio::test]
async fn should_not_have_useless_events() {
    fn assert_useless_events_is_empty(file: impl GetEventsFile) {
        let events = file.deserialize();
        let mut count = 0;
        for event in events.events {
            match &event.payload {
                EventType::ReceivedUtxos { utxos, .. } if utxos.is_empty() => {
                    count += 1;
                }
                _ => {}
            }
        }
        assert_eq!(count, 0);
    }

    assert_useless_events_is_empty(Mainnet);
    assert_useless_events_is_empty(Testnet);
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
        Decode!(&decompressed_buffer, GetEventsResult)
            .expect("Failed to decode events")
            .into()
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
