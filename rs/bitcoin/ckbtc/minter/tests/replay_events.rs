//! To refresh the stored events on disk, call the tests as follows
//! ```
//! bazel test --spawn_strategy=standalone //rs/bitcoin/ckbtc/minter:ckbtc_minter_replay_events_tests  --test_env=RETRIEVE_MINTER_EVENTS=true --test_arg "should_replay_events_for_mainnet" --test_timeout 900
//! ```
//! The parameter `spawn_strategy=standalone` is needed, because the events will be fetched from the running canister and the default sandbox doesn't allow it.
//! The parameter `test_env=RETRIEVE_MINTER_EVENTS=true` is needed to enable the fetching of the events.

use candid::{CandidType, Deserialize, Principal};
use ic_agent::Agent;
use ic_ckbtc_minter::state::CkBtcMinterState;
use ic_ckbtc_minter::state::eventlog::{
    CkBtcEventLogger, CkBtcMinterEvent, EventLogger, EventType,
};
use ic_ckbtc_minter::state::invariants::{CheckInvariants, CheckInvariantsImpl};
use ic_ckbtc_minter::{ECDSAPublicKey, Network};
use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::LazyLock;

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
        Network, state::eventlog::CkBtcEventLogger, tx,
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
            type EventLogger = CkBtcEventLogger;
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
            fn event_logger(&self) -> CkBtcEventLogger;
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
    CkBtcEventLogger
        .replay::<SkipCheckInvariantsImpl>(MAINNET_EVENTS.events.iter().cloned())
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
async fn should_replay_events_for_testnet() {
    Testnet.retrieve_and_store_events_if_env().await;

    let state = CkBtcEventLogger
        .replay::<SkipCheckInvariantsImpl>(TESTNET_EVENTS.events.iter().cloned())
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
        let _state = CkBtcEventLogger
            .replay::<CheckInvariantsImpl>(events.events.iter().cloned())
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
    ) -> Vec<CkBtcMinterEvent> {
        use candid::{Decode, Encode};
        use ic_ckbtc_minter::state::eventlog::GetEventsArg;

        let arg = GetEventsArg { start, length };

        let raw_result = agent
            .update(minter_id, "get_events")
            .with_arg(Encode!(&arg).unwrap())
            .call_and_wait()
            .await
            .expect("Failed to call get_events");
        Decode!(&raw_result, Vec<CkBtcMinterEvent>).unwrap()
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
    pub events: Vec<CkBtcMinterEvent>,
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
