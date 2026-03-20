//! To refresh the stored events on disk, call the tests as follows
//! ```
//! bazel test --spawn_strategy=standalone //rs/bitcoin/ckbtc/minter:ckbtc_minter_replay_events_tests  --test_env=RETRIEVE_MINTER_EVENTS=true --test_arg "should_replay_events_for_mainnet" --test_timeout 900
//! ```
//! The parameter `spawn_strategy=standalone` is needed, because the events will be fetched from the running canister and the default sandbox doesn't allow it.
//! The parameter `test_env=RETRIEVE_MINTER_EVENTS=true` is needed to enable the fetching of the events.

use candid::{CandidType, Deserialize, Principal};
use ic_agent::Agent;
use ic_btc_interface::OutPoint;
use ic_ckbtc_minter::address::BitcoinAddress;
use ic_ckbtc_minter::fees::BitcoinFeeEstimator;
use ic_ckbtc_minter::state::eventlog::{
    CkBtcEventLogger, CkBtcMinterEvent, EventLogger, EventType,
};
use ic_ckbtc_minter::state::invariants::{CheckInvariants, CheckInvariantsImpl};
use ic_ckbtc_minter::state::{CkBtcMinterState, LedgerMintIndex};
use ic_ckbtc_minter::tx::FeeRate;
use ic_ckbtc_minter::{ECDSAPublicKey, Network, build_unsigned_transaction};
use maplit::{btreemap, btreeset};
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
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
        CanisterRuntime, ECDSAPublicKey, GetCurrentFeePercentilesRequest, GetUtxosRequest,
        GetUtxosResponse, Network, state::eventlog::CkBtcEventLogger, tx::FeeRate,
        tx::SignedRawTransaction, tx::UnsignedTransaction,
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
            async fn get_current_fee_percentiles(&self, request: &GetCurrentFeePercentilesRequest) -> Result<Vec<FeeRate>, CallError>;
            async fn get_utxos(&self, request: &GetUtxosRequest) -> Result<GetUtxosResponse, CallError>;
            async fn check_transaction(&self, btc_checker_principal: Option<Principal>, utxo: &Utxo, cycle_payment: u128, ) -> Result<CheckTransactionResponse, CallError>;
            async fn mint_ckbtc(&self, amount: u64, to: Account, memo: Memo) -> Result<u64, UpdateBalanceError>;
            async fn sign_with_ecdsa(&self, key_name: String, derivation_path: Vec<Vec<u8>>, message_hash: [u8; 32]) -> Result<Vec<u8>, CallError>;
            async fn sign_transaction( &self, key_name: String, ecdsa_public_key: ECDSAPublicKey, unsigned_tx: UnsignedTransaction, accounts: Vec<Account>) -> Result<SignedRawTransaction, CallError>;
            async fn send_raw_transaction(&self, transaction: Vec<u8>, network: Network) -> Result<(), CallError>;
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
async fn should_replay_events_and_retain_pending_requests() {
    Mainnet.retrieve_and_store_events_if_env().await;

    let state = &MAINNET_STATE;
    state
        .check_invariants()
        .expect("Failed to check invariants");

    println!(
        "pending retrieve_btc_request = {:?}",
        state.pending_retrieve_btc_requests
    );

    let block_indices = state
        .pending_retrieve_btc_requests
        .iter()
        .map(|request| request.block_index)
        .collect::<BTreeSet<_>>();
    // 1st stuck retrieve_btc transits to pending
    assert!(block_indices.contains(&3459007));
    assert!(block_indices.contains(&3459009));
    assert!(block_indices.contains(&3459013));
    // 2st stuck retrieve_btc transits to pending
    assert!(block_indices.contains(&3489347));
    assert!(block_indices.contains(&3489353));
}

#[test]
fn should_be_able_to_send_fresh_transaction() {
    let mut state = MAINNET_STATE.clone();

    state
        .check_invariants()
        .expect("Failed to check invariants");

    let pending_withdrawals: BTreeSet<_> = state
        .pending_retrieve_btc_requests
        .iter()
        .map(|req| req.block_index)
        .collect();
    assert_eq!(
        pending_withdrawals.len(),
        state.pending_retrieve_btc_requests.len()
    );
    assert_eq!(pending_withdrawals.len(), 6);
    let stuck_withdrawals = btreeset! { 3459007_u64, 3459009, 3459013, 3489347, 3489353 };
    assert!(stuck_withdrawals.is_subset(&pending_withdrawals));

    let batch = state.build_batch(100);
    assert_eq!(
        batch
            .iter()
            .map(|req| req.block_index)
            .collect::<BTreeSet<_>>(),
        pending_withdrawals
    );
    println!("{batch:?}");

    let outputs: Vec<_> = batch
        .iter()
        .map(|req| (req.address.clone(), req.amount))
        .collect();

    let main_address = BitcoinAddress::parse(
        "bc1q0jrxz4jh59t5qsu7l0y59kpfdmgjcq60wlee3h",
        Network::Mainnet,
    )
    .unwrap();
    let max_num_inputs_in_transaction = 1000;
    let fee_millisatoshi_per_vbyte = FeeRate::from_millis_per_byte(1_500);
    let fee_estimator = BitcoinFeeEstimator::from_state(&state);
    let (unsigned_tx, change_output, total_fee, utxos) = build_unsigned_transaction(
        &mut state.available_utxos,
        outputs,
        &main_address,
        max_num_inputs_in_transaction,
        fee_millisatoshi_per_vbyte,
        &fee_estimator,
    )
    .unwrap();

    println!("tx: {unsigned_tx:?}");
    println!("change_output: {change_output:?}");
    println!("total_fee: {total_fee:?}");
    println!("utxos: {utxos:?}");

    let input_outpoints: Vec<_> = unsigned_tx
        .inputs
        .iter()
        .map(|input| &input.previous_output)
        .map(|outpoint| format!("{}:{}", outpoint.txid, outpoint.vout))
        .collect();
    assert_eq!(
        input_outpoints,
        vec![
            "68c6e98741cee0ceca94c9e34b93fac64a1ad70c0fc134aa22936d321f3432f3:4",
            "9114688b68c51906adbc44b09896a259ffccc5e3e974906afe7a2444cfa62a28:0",
            "b1a328a6ef7c92df7c92dca15b345b1d66cfe5c7b7637fe82a69aef1b211ad36:0",
            "3895d99d362f362993c2137dafb92c99887b36fbbb1a81f7f2f11cad974e11e4:1",
            "ed307192ef1e09c51d6276357ddb31f65fdbcb502c5047a6d8d68443eb5c06a4:21",
            "76e17e2941e80e8d25e01abce53b87f2cb1c12f9d86d0578ccf3e67426b17b2e:0",
            "f3ad7d7befd989a4724ced75a8eed451aeee6ecf4f161b0bd59071e52545fe79:1"
        ]
    );

    assert!(!input_outpoints.contains(
        &"91bb46443799335076fbcd117f2295c7499d02dd3a59c22a531d31591114b303:5".to_string()
    ));
    assert!(!input_outpoints.contains(
        &"8942e5ef0d4ace158a4fddd5153d320701bd13370ff8fecef13795cdd8ff1dc5:1".to_string()
    ));
}

#[tokio::test]
async fn should_replay_events_for_mainnet() {
    Mainnet.retrieve_and_store_events_if_env().await;

    let state = &MAINNET_STATE;
    state
        .check_invariants()
        .expect("Failed to check invariants");

    assert_eq!(state.btc_network, Network::Mainnet);
    assert_eq!(state.get_total_btc_managed(), 28_608_213_637);
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
    assert_eq!(state.get_total_btc_managed(), 24_885_679_983);
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

#[test]
fn should_have_exactly_2_double_mint_events_and_not_more() {
    fn test(
        retrieved_events: &GetEventsResult,
        double_mints: BTreeMap<OutPoint, [LedgerMintIndex; 2]>,
    ) {
        let double_mints_by_index: BTreeMap<_, _> = double_mints
            .iter()
            // the second index is the double mint
            .map(|(outpoint, indexes)| (indexes[1], outpoint))
            .collect();

        let minted_utxos: Vec<_> = retrieved_events
            .events
            .iter()
            .filter_map(|event| match &event.payload {
                EventType::ReceivedUtxos {
                    mint_txid, utxos, ..
                } => {
                    if let Some(mint) = mint_txid
                        && double_mints_by_index.contains_key(mint)
                    {
                        assert_eq!(utxos.len(), 1);
                        assert_eq!(&utxos[0].outpoint, double_mints_by_index[mint]);
                        None
                    } else {
                        Some(utxos)
                    }
                }
                _ => None,
            })
            .flatten()
            .collect();

        let unique_outpoints: BTreeSet<_> =
            minted_utxos.iter().map(|utxo| &utxo.outpoint).collect();

        assert_eq!(minted_utxos.len(), unique_outpoints.len());
    }

    fn outpoint(out: &str) -> OutPoint {
        let (txid, vout) = out.split_once(":").unwrap();
        OutPoint {
            txid: txid.parse().unwrap(),
            vout: vout.parse().unwrap(),
        }
    }

    // Obviously double mints should never occur.
    // This was due to a bug, see
    // https://forum.dfinity.org/t/proposal-140929-to-upgrade-the-ckbtc-minter/65401/3
    // for details.
    let double_mints = btreemap! {
        outpoint("91bb46443799335076fbcd117f2295c7499d02dd3a59c22a531d31591114b303:5") => [3_458_934, 3_458_990],
        outpoint("8942e5ef0d4ace158a4fddd5153d320701bd13370ff8fecef13795cdd8ff1dc5:1") => [3_489_107, 3_489_297]
    };
    test(&MAINNET_EVENTS, double_mints);
    test(&TESTNET_EVENTS, BTreeMap::default());
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
