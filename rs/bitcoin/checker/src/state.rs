use crate::{
    BtcNetwork, CheckMode,
    providers::{Provider, parse_authorization_header_from_url},
};
use bitcoin::{Address, Transaction};
use ic_btc_interface::Txid;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{Cell, DefaultMemoryImpl, Storable, storable::Bound};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::fmt;

#[cfg(test)]
mod tests;

/// Error returned by calling `http_get_tx`.
#[derive(Debug, Clone)]
pub enum HttpGetTxError {
    TxEncoding(String),
    TxidMismatch { expected: Txid, decoded: Txid },
    ResponseTooLarge,
    Rejected { code: u32, message: String },
    CallPerformFailed,
}

impl fmt::Display for HttpGetTxError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use HttpGetTxError::*;
        match self {
            TxEncoding(s) => write!(f, "TxEncoding: {s}"),
            TxidMismatch { expected, decoded } => {
                write!(f, "TxidMismatch: expected {expected} but decoded {decoded}")
            }
            ResponseTooLarge => write!(f, "ResponseTooLarge"),
            Rejected { code, message } => write!(f, "Rejected: code {code:?}, {message}"),
            CallPerformFailed => write!(f, "CallPerformedFailed"),
        }
    }
}

/// We store in state the `FetchStatus` for every `Txid` we fetch.
/// It transitions from `PendingOutcall` to any one of the three
/// possible outcomes: `PendingRetry`, `Error`, or `Fetched`.
#[derive(Debug, Clone)]
pub enum FetchTxStatus {
    PendingOutcall,
    PendingRetry { max_response_bytes: u32 },
    Error(FetchTxStatusError),
    Fetched(FetchedTx),
}

#[derive(Debug, Clone)]
pub struct FetchTxStatusError {
    pub provider: Provider,
    pub max_response_bytes: u32,
    pub error: HttpGetTxError,
}

/// Once the transaction data is successfully fetched, we create
/// a list of `input_addresses` (matching the number of inputs)
/// that is initialized as `None`. Once a corresponding input
/// transaction is fetched (see function `check_fetched`), its
/// input address will be computed and filled in.
#[derive(Clone, Debug)]
pub struct FetchedTx {
    pub tx: TransactionCheckData,
    pub input_addresses: Vec<Option<Address>>,
}

/// Instead of storing the full transaction data, we only
/// store relevant bits, including inputs (which are previous
/// outputs) and output addresses.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TransactionCheckData {
    pub inputs: Vec<PreviousOutput>,
    pub outputs: Vec<Option<Address>>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PreviousOutput {
    pub txid: Txid,
    pub vout: u32,
}

impl TransactionCheckData {
    pub fn from_transaction(
        btc_network: &BtcNetwork,
        tx: Transaction,
    ) -> Result<Self, bitcoin::address::FromScriptError> {
        let inputs = tx
            .input
            .iter()
            .map(|input| PreviousOutput {
                txid: Txid::from(*(input.previous_output.txid.as_ref() as &[u8; 32])),
                vout: input.previous_output.vout,
            })
            .collect();
        let mut outputs = Vec::new();
        for output in tx.output.iter() {
            // Some outputs do not have addresses. These outputs will never be
            // inputs of other transactions, so it is okay to treat them as `None`.
            outputs.push(
                Address::from_script(
                    &output.script_pubkey,
                    bitcoin::Network::from(btc_network.clone()),
                )
                .ok(),
            )
        }
        Ok(Self { inputs, outputs })
    }
}

// Max number of concurrent http outcalls.
const MAX_CONCURRENT: u32 = 50;

// Max number of entries in the cache is set to 10_000. Since the average transaction size
// is about 400 bytes, the estimated memory usage of the cache is in the order of 10s of MBs.
const MAX_FETCH_TX_ENTRIES: usize = 10_000;

// The internal state includes:
// 1. Outcall capacity, a semaphore limiting max concurrent outcalls.
// 2. fetch transaction status, indexed by transaction id.
//
// TODO(XC-191): persist canister state
thread_local! {
    pub(crate) static OUTCALL_CAPACITY: RefCell<u32> = const { RefCell::new(MAX_CONCURRENT) };
    pub(crate) static FETCH_TX_CACHE: RefCell<FetchTxCache<FetchTxStatus>> = RefCell::new(
        FetchTxCache::new(MAX_FETCH_TX_ENTRIES)
    );
}

// Time in nanoseconds since the epoch (1970-01-01).
pub(crate) type Timestamp = u64;

pub(crate) struct FetchTxCache<T> {
    max_entries: usize,
    status: BTreeMap<Txid, T>,
    created: VecDeque<(Txid, Timestamp)>,
}

impl<T> FetchTxCache<T> {
    fn new(max_entries: usize) -> Self {
        assert!(max_entries > 0);
        Self {
            max_entries,
            status: BTreeMap::new(),
            created: VecDeque::new(),
        }
    }

    fn get_status(&self, txid: Txid) -> Option<&T> {
        self.status.get(&txid)
    }

    // Set the status of a txid with a timestamp. If the txid does not
    // already have a status, a new status entry is created and associated
    // with the given the timestamp.
    //
    // This function may also remove and return the oldest entry if we
    // exceeds the `max_entries` settings.
    fn set_status_with(
        &mut self,
        txid: Txid,
        status: T,
        now: Timestamp,
    ) -> Option<(Txid, Timestamp, T)> {
        if self.status.insert(txid, status).is_none() {
            // This is a new entry, record its created time.
            self.created.push_back((txid, now));
            assert_eq!(self.status.len(), self.created.len());
            // Purge the oldest entry when we exceed max_entries.
            if self.created.len() > self.max_entries {
                let removed = self.created.pop_front().and_then(|(txid, timestamp)| {
                    self.status
                        .remove(&txid)
                        .map(|status| (txid, timestamp, status))
                });
                assert_eq!(self.status.len(), self.created.len());
                assert!(self.created.len() <= self.max_entries);
                return removed;
            }
        }
        None
    }

    fn clear_status(&mut self, txid: Txid) {
        let _ = self.status.remove(&txid);
        self.created.retain(|(id, _)| *id != txid);
    }

    pub(crate) fn iter(&self) -> impl DoubleEndedIterator<Item = (Txid, Timestamp, &T)> + '_ {
        self.created
            .iter()
            .map(|(txid, timestamp)| (*txid, *timestamp, self.status.get(txid).unwrap()))
    }
}

pub fn get_fetch_status(txid: Txid) -> Option<FetchTxStatus> {
    FETCH_TX_CACHE.with(|cache| cache.borrow().get_status(txid).cloned())
}

// Mock the time when running tests.
#[cfg(test)]
fn time() -> u64 {
    0
}

#[cfg(not(test))]
fn time() -> u64 {
    ic_cdk::api::time()
}

pub fn set_fetch_status(txid: Txid, status: FetchTxStatus) {
    let _ = FETCH_TX_CACHE.with(|cache| cache.borrow_mut().set_status_with(txid, status, time()));
}

pub fn clear_fetch_status(txid: Txid) {
    FETCH_TX_CACHE.with(|cache| cache.borrow_mut().clear_status(txid))
}

/// Set the address at the given `index` in the `Fetched` status of the given `txid`.
/// Pre-condition: the status of `txid` is `Fetched`, and `index` is within bounds.
pub fn set_fetched_address(txid: Txid, index: usize, address: Address) {
    FETCH_TX_CACHE.with(|s| {
        s.borrow_mut().status.entry(txid).and_modify(|status| {
            if let FetchTxStatus::Fetched(fetched) = status {
                fetched.input_addresses[index] = Some(address);
            };
        });
    })
}

#[derive(Eq, PartialEq, Debug)]
pub struct FetchGuard(Txid);

#[derive(Debug)]
pub enum FetchGuardError {
    NoCapacity,
}

impl FetchGuard {
    pub fn new(txid: Txid) -> Result<Self, FetchGuardError> {
        let guard = OUTCALL_CAPACITY.with(|capacity| {
            let mut capacity = capacity.borrow_mut();
            if *capacity > 0 {
                *capacity -= 1;
                Ok(FetchGuard(txid))
            } else {
                Err(FetchGuardError::NoCapacity)
            }
        })?;
        set_fetch_status(txid, FetchTxStatus::PendingOutcall);
        Ok(guard)
    }
}

impl Drop for FetchGuard {
    fn drop(&mut self) {
        OUTCALL_CAPACITY.with(|capacity| {
            let mut capacity = capacity.borrow_mut();
            *capacity += 1;
        });
        let txid = self.0;
        if let Some(FetchTxStatus::PendingOutcall) = get_fetch_status(txid) {
            // Only clear the status when it is still `PendingOutcall`
            clear_fetch_status(txid);
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct Config {
    btc_network: BtcNetwork,
    pub check_mode: CheckMode,
    #[serde(default = "default_num_subnet_nodes")]
    pub num_subnet_nodes: u16,
}

fn default_num_subnet_nodes() -> u16 {
    34
}

impl Config {
    pub fn new_and_validate(
        btc_network: BtcNetwork,
        check_mode: CheckMode,
        num_subnet_nodes: u16,
    ) -> Result<Self, String> {
        if let BtcNetwork::Regtest { json_rpc_url } = &btc_network {
            let _ = parse_authorization_header_from_url(json_rpc_url)?;
        }
        Ok(Self {
            btc_network,
            check_mode,
            num_subnet_nodes,
        })
    }

    pub fn btc_network(&self) -> BtcNetwork {
        self.btc_network.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum ConfigState {
    Uninitialized,
    Initialized(Config),
}

impl Storable for ConfigState {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        let mut buf = vec![];
        ciborium::ser::into_writer(self, &mut buf).expect("failed to encode ConfigState");
        Cow::Owned(buf)
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        ciborium::de::from_reader(bytes.as_ref()).unwrap_or_else(|e| {
            panic!(
                "failed to decode ConfigState bytes {:?}: {}",
                bytes.as_ref(),
                e
            )
        })
    }

    const BOUND: Bound = Bound::Unbounded;
}

type StableMemory = VirtualMemory<DefaultMemoryImpl>;

const CONFIG_MEMORY_ID: MemoryId = MemoryId::new(0);

// Configuration is stored in stable memory.
thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> = RefCell::new(
            MemoryManager::init(DefaultMemoryImpl::default())
    );
    static CONFIG: RefCell<Cell<ConfigState, StableMemory>> = RefCell::new(
        Cell::init(config_memory(), ConfigState::Uninitialized).expect("failed to initialize stable cell for config")
    );
}

fn config_memory() -> StableMemory {
    MEMORY_MANAGER.with(|m| m.borrow().get(CONFIG_MEMORY_ID))
}

pub fn set_config(config: Config) {
    CONFIG
        .with(|c| c.borrow_mut().set(ConfigState::Initialized(config)))
        .expect("failed to set config");
}

pub fn get_config() -> Config {
    match CONFIG.with(|c| c.borrow().get().clone()) {
        ConfigState::Uninitialized => panic!("config is uninitialized"),
        ConfigState::Initialized(config) => config,
    }
}
