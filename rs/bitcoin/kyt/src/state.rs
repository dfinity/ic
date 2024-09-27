use crate::types::InitArg;
use bitcoin::{Address, Network, Transaction};
use candid::{decode_args, encode_args};
use ic_btc_interface::{Network as BtcNetwork, Txid};
use ic_cdk::api::call::RejectionCode;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{storable::Bound, Cell, DefaultMemoryImpl, Storable};
use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::BTreeMap;

#[cfg(test)]
mod tests;

/// Error returned by calling `http_get_tx`.
#[derive(Debug, Clone)]
pub enum HttpGetTxError {
    TxEncoding(String),
    TxidMismatch {
        expected: Txid,
        decoded: Txid,
    },
    ResponseTooLarge,
    Rejected {
        code: RejectionCode,
        message: String,
    },
}

/// We store in state the `FetchStatus` for every `Txid` we fetch.
/// It transitions from `PendingOutcall` to any one of the three
/// possible outcomes: `PendingRetry`, `Error`, or `Fetched`.
#[derive(Debug, Clone)]
pub enum FetchTxStatus {
    PendingOutcall,
    PendingRetry { max_response_bytes: u32 },
    Error(HttpGetTxError),
    Fetched(FetchedTx),
}

/// Once the transaction data is successfully fetched, we create
/// a list of `input_addresses` (matching the number of inputs)
/// that is initialized as `None`. Once a corresponding input
/// transaction is fetched (see function `check_fetched`), its
/// input address will be computed and filled in.
#[derive(Clone, Debug)]
pub struct FetchedTx {
    pub tx: Transaction,
    pub input_addresses: Vec<Option<Address>>,
}

// Max number of concurrent http outcalls.
const MAX_CONCURRENT: u32 = 50;

#[derive(Clone, Debug)]
pub struct Config {
    pub network: Network,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            network: Network::Bitcoin,
        }
    }
}

impl From<InitArg> for Config {
    fn from(arg: InitArg) -> Self {
        let network = match arg.network {
            BtcNetwork::Mainnet => Network::Bitcoin,
            BtcNetwork::Testnet => Network::Testnet,
            BtcNetwork::Regtest => Network::Regtest,
        };
        Self { network }
    }
}

impl From<&Config> for InitArg {
    fn from(arg: &Config) -> Self {
        let network = match arg.network {
            Network::Bitcoin => BtcNetwork::Mainnet,
            Network::Testnet => BtcNetwork::Testnet,
            Network::Regtest => BtcNetwork::Regtest,
            _ => panic!("unsupported network type: Signet"),
        };
        Self { network }
    }
}

impl Storable for Config {
    fn to_bytes(&self) -> Cow<[u8]> {
        let buf = encode_args((InitArg::from(self),)).expect("fail to encode config");
        Cow::Owned(buf)
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        let (config,): (InitArg,) =
            decode_args(bytes.as_ref()).expect("failed to decode config bytes");
        config.into()
    }

    const BOUND: Bound = Bound::Unbounded;
}

type StableMemory = VirtualMemory<DefaultMemoryImpl>;

const CONFIG_MEMORY_ID: MemoryId = MemoryId::new(0);

// The internal KYT state includes:
// 1. Configurations.
// 2. Outcall capacity, a semaphore limiting max concurrent outcalls.
// 3. fetch transaction status, indexed by transaction id.
//
// TODO(XC-191): persist canister state
thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> = RefCell::new(
            MemoryManager::init(DefaultMemoryImpl::default())
    );
    static CONFIG: RefCell<Cell<Config, StableMemory>> = RefCell::new(
        Cell::init(config_memory(), Config::default()).expect("failed to initialize stable cell for state")
    );
    static OUTCALL_CAPACITY: RefCell<u32> = const { RefCell::new(MAX_CONCURRENT) };
    static FETCH_TX_STATUS: RefCell<BTreeMap<Txid, FetchTxStatus>> = RefCell::new(BTreeMap::default());
}

#[allow(dead_code)]
fn config_memory() -> StableMemory {
    MEMORY_MANAGER.with(|m| m.borrow().get(CONFIG_MEMORY_ID))
}

pub fn set_config(config: Config) {
    CONFIG
        .with(|c| c.borrow_mut().set(config))
        .expect("failed to set config");
}

pub fn get_config() -> Config {
    CONFIG.with(|c| c.borrow().get().clone())
}

pub fn get_fetch_status(txid: Txid) -> Option<FetchTxStatus> {
    FETCH_TX_STATUS.with(|s| s.borrow().get(&txid).cloned())
}

pub fn set_fetch_status(txid: Txid, status: FetchTxStatus) {
    FETCH_TX_STATUS.with(|s| {
        let _ = s.borrow_mut().insert(txid, status);
    })
}

pub fn clear_fetch_status(txid: Txid) {
    FETCH_TX_STATUS.with(|s| {
        let _ = s.borrow_mut().remove(&txid);
    })
}

/// Set the address at the given `index` in the `Fetched` status of the given `txid`.
/// Pre-condition: the status of `txid` is `Fetched`, and `index` is within bounds.
pub fn set_fetched_address(txid: Txid, index: usize, address: Address) {
    FETCH_TX_STATUS.with(|s| {
        s.borrow_mut().entry(txid).and_modify(|status| {
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
