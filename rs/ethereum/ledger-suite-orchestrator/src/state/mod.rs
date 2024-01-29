#[cfg(test)]
mod tests;

use crate::candid::InitArg;
use crate::scheduler::{Erc20Contract, Task, Tasks};
use candid::Principal;
use ic_cdk::trap;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{Cell, DefaultMemoryImpl, Storable};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_bytes::ByteBuf;
use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::marker::PhantomData;

const STATE_MEMORY_ID: MemoryId = MemoryId::new(0);
const WASM_HASH_LENGTH: usize = 32;

thread_local! {
     static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> = RefCell::new(
        MemoryManager::init(DefaultMemoryImpl::default())
    );

    //TODO: more refined stable memory structure, right now we just dump everything into a single Cell
    pub static STATE: RefCell<Cell<ConfigState, VirtualMemory<DefaultMemoryImpl>>> = RefCell::new(Cell::init(
    MEMORY_MANAGER.with(|m| m.borrow().get(STATE_MEMORY_ID)), ConfigState::default())
    .expect("failed to initialize stable cell for state"));
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct Wasm {
    #[serde(with = "serde_bytes")]
    binary: Vec<u8>,
    hash: WasmHash,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
#[serde(try_from = "serde_bytes::ByteBuf", into = "serde_bytes::ByteBuf")]
pub struct WasmHash([u8; WASM_HASH_LENGTH]);

impl TryFrom<ByteBuf> for WasmHash {
    type Error = String;

    fn try_from(value: ByteBuf) -> Result<Self, Self::Error> {
        Ok(WasmHash(value.to_vec().try_into().map_err(
            |e: Vec<u8>| format!("expected {} bytes, but got {}", WASM_HASH_LENGTH, e.len()),
        )?))
    }
}

impl From<WasmHash> for ByteBuf {
    fn from(value: WasmHash) -> Self {
        ByteBuf::from(value.0.to_vec())
    }
}

impl From<[u8; WASM_HASH_LENGTH]> for WasmHash {
    fn from(value: [u8; WASM_HASH_LENGTH]) -> Self {
        Self(value)
    }
}

impl Wasm {
    pub fn new(binary: Vec<u8>) -> Self {
        let hash = WasmHash::from(ic_crypto_sha2::Sha256::hash(binary.as_slice()));
        Self { binary, hash }
    }

    pub fn to_bytes(self) -> Vec<u8> {
        self.binary
    }

    pub fn hash(&self) -> &WasmHash {
        &self.hash
    }
}

impl From<Vec<u8>> for Wasm {
    fn from(v: Vec<u8>) -> Self {
        Self::new(v)
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Default)]
pub struct ManagedCanisters {
    canisters: BTreeMap<Erc20Contract, Canisters>,
}

#[derive(Default, Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct Canisters {
    pub ledger: Option<LedgerCanister>,
    pub index: Option<IndexCanister>,
    pub archives: Vec<Principal>,
}

impl Canisters {
    pub fn ledger_canister_id(&self) -> Option<&Principal> {
        self.ledger.as_ref().map(LedgerCanister::canister_id)
    }

    pub fn index_canister_id(&self) -> Option<&Principal> {
        self.index.as_ref().map(IndexCanister::canister_id)
    }

    pub fn archive_canister_ids(&self) -> &[Principal] {
        &self.archives
    }
}

#[derive(Debug)]
pub struct Canister<T> {
    status: ManagedCanisterStatus,
    marker: PhantomData<T>,
}

impl<T> Clone for Canister<T> {
    fn clone(&self) -> Self {
        Self::new(self.status.clone())
    }
}

impl<T> PartialEq for Canister<T> {
    fn eq(&self, other: &Self) -> bool {
        self.status.eq(&other.status)
    }
}

impl<T> Canister<T> {
    pub fn new(status: ManagedCanisterStatus) -> Self {
        Self {
            status,
            marker: PhantomData,
        }
    }

    pub fn canister_id(&self) -> &Principal {
        self.status.canister_id()
    }
}

impl<T> Serialize for Canister<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.status.serialize(serializer)
    }
}

impl<'de, T> Deserialize<'de> for Canister<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        ManagedCanisterStatus::deserialize(deserializer).map(Self::new)
    }
}

#[derive(Debug)]
pub enum Ledger {}
pub type LedgerCanister = Canister<Ledger>;

#[derive(Debug)]
pub enum Index {}
pub type IndexCanister = Canister<Index>;

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub enum ManagedCanisterStatus {
    /// Canister created with the given principal
    /// but wasm module is not yet installed.
    Created { canister_id: Principal },

    /// Canister created and wasm module installed.
    /// The wasm_hash reflects the installed wasm module by the orchestrator
    /// but *may differ* from the one being currently deployed (if another controller did an upgrade)
    Installed {
        canister_id: Principal,
        installed_wasm_hash: WasmHash,
    },
}

impl ManagedCanisterStatus {
    pub fn canister_id(&self) -> &Principal {
        match self {
            ManagedCanisterStatus::Created { canister_id }
            | ManagedCanisterStatus::Installed { canister_id, .. } => canister_id,
        }
    }
}

/// Configuration state of the ledger orchestrator.
#[derive(Debug, PartialEq, Clone, Default)]
enum ConfigState {
    #[default]
    Uninitialized, // This state is only used between wasm module initialization and init().
    Initialized(State),
}

impl ConfigState {
    fn expect_initialized(&self) -> &State {
        match &self {
            ConfigState::Uninitialized => trap("BUG: state not initialized"),
            ConfigState::Initialized(s) => s,
        }
    }
}

impl Storable for ConfigState {
    fn to_bytes(&self) -> Cow<[u8]> {
        match &self {
            ConfigState::Uninitialized => Cow::Borrowed(&[]),
            ConfigState::Initialized(config) => {
                let mut buf = vec![];
                ciborium::ser::into_writer(config, &mut buf)
                    .expect("failed to encode a minter event");
                Cow::Owned(buf)
            }
        }
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        if bytes.is_empty() {
            return ConfigState::Uninitialized;
        }
        ConfigState::Initialized(
            ciborium::de::from_reader(bytes.as_ref()).unwrap_or_else(|e| {
                panic!("failed to decode state bytes {}: {e}", hex::encode(bytes))
            }),
        )
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct State {
    ledger_wasm: Wasm,
    index_wasm: Wasm,
    archive_wasm: Wasm,
    managed_canisters: ManagedCanisters,
    tasks: Tasks,
    processing_tasks_guard: bool,
}

impl State {
    pub fn tasks(&self) -> &Tasks {
        &self.tasks
    }

    pub fn ledger_wasm(&self) -> &Wasm {
        &self.ledger_wasm
    }

    pub fn index_wasm(&self) -> &Wasm {
        &self.index_wasm
    }

    pub fn add_task(&mut self, task: Task) {
        self.tasks.add_task(task);
    }

    pub fn set_tasks(&mut self, tasks: Tasks) {
        self.tasks = tasks;
    }

    pub fn maybe_set_timer_guard(&mut self) -> bool {
        if self.processing_tasks_guard {
            return false;
        }
        self.processing_tasks_guard = true;
        true
    }

    pub fn managed_canisters(&self, contract: &Erc20Contract) -> Option<&Canisters> {
        self.managed_canisters.canisters.get(contract)
    }

    fn managed_canisters_mut(&mut self, contract: &Erc20Contract) -> Option<&mut Canisters> {
        self.managed_canisters.canisters.get_mut(contract)
    }

    pub fn unset_timer_guard(&mut self) {
        self.processing_tasks_guard = false;
    }

    pub fn managed_status<'a, T: 'a>(
        &'a self,
        contract: &Erc20Contract,
    ) -> Option<&'a ManagedCanisterStatus>
    where
        Canisters: ManageSingleCanister<T>,
    {
        self.managed_canisters(contract)
            .and_then(|c| c.get().map(|c| &c.status))
    }

    pub fn record_created_canister<T: Debug>(
        &mut self,
        contract: &Erc20Contract,
        canister_id: Principal,
    ) where
        Canisters: ManageSingleCanister<T>,
    {
        if self.managed_canisters(contract).is_none() {
            self.managed_canisters
                .canisters
                .insert(contract.clone(), Canisters::default());
        }
        let canisters = self
            .managed_canisters_mut(contract)
            .expect("BUG: no managed canisters");
        canisters
            .try_insert(Canister::<T>::new(ManagedCanisterStatus::Created {
                canister_id,
            }))
            .unwrap_or_else(|e| {
                panic!(
                    "BUG: canister {} already created: {:?}",
                    Canisters::display_name(),
                    e
                )
            });
    }

    pub fn record_installed_canister<T>(&mut self, contract: &Erc20Contract, wasm_hash: WasmHash)
    where
        Canisters: ManageSingleCanister<T>,
    {
        let managed_canister = self
            .managed_canisters_mut(contract)
            .and_then(Canisters::get_mut)
            .unwrap_or_else(|| {
                panic!(
                    "BUG: no managed canisters or no {} canister for {:?}",
                    Canisters::display_name(),
                    contract
                )
            });
        let canister_id = *managed_canister.canister_id();
        managed_canister.status = ManagedCanisterStatus::Installed {
            canister_id,
            installed_wasm_hash: wasm_hash,
        };
    }
}

pub trait ManageSingleCanister<T> {
    fn display_name() -> &'static str;

    fn get(&self) -> Option<&Canister<T>>;

    fn get_mut(&mut self) -> Option<&mut Canister<T>>;

    fn try_insert(&mut self, canister: Canister<T>) -> Result<(), OccupiedError<Canister<T>>>;
}

#[derive(Debug, PartialEq, Clone)]
pub struct OccupiedError<T> {
    value: T,
}

impl ManageSingleCanister<Ledger> for Canisters {
    fn display_name() -> &'static str {
        "ledger"
    }

    fn get(&self) -> Option<&Canister<Ledger>> {
        self.ledger.as_ref()
    }

    fn get_mut(&mut self) -> Option<&mut Canister<Ledger>> {
        self.ledger.as_mut()
    }

    fn try_insert(
        &mut self,
        canister: Canister<Ledger>,
    ) -> Result<(), OccupiedError<Canister<Ledger>>> {
        match self.get() {
            Some(c) => Err(OccupiedError { value: c.clone() }),
            None => {
                self.ledger = Some(canister);
                Ok(())
            }
        }
    }
}

impl ManageSingleCanister<Index> for Canisters {
    fn display_name() -> &'static str {
        "index"
    }

    fn get(&self) -> Option<&Canister<Index>> {
        self.index.as_ref()
    }

    fn get_mut(&mut self) -> Option<&mut Canister<Index>> {
        self.index.as_mut()
    }

    fn try_insert(
        &mut self,
        canister: Canister<Index>,
    ) -> Result<(), OccupiedError<Canister<Index>>> {
        match self.get() {
            Some(c) => Err(OccupiedError { value: c.clone() }),
            None => {
                self.index = Some(canister);
                Ok(())
            }
        }
    }
}

pub trait RetrieveCanisterWasm<T> {
    fn retrieve_wasm(&self) -> &Wasm;
}

impl RetrieveCanisterWasm<Ledger> for State {
    fn retrieve_wasm(&self) -> &Wasm {
        self.ledger_wasm()
    }
}

impl RetrieveCanisterWasm<Index> for State {
    fn retrieve_wasm(&self) -> &Wasm {
        self.index_wasm()
    }
}

impl From<InitArg> for State {
    fn from(
        InitArg {
            ledger_wasm,
            index_wasm,
            archive_wasm,
        }: InitArg,
    ) -> Self {
        Self {
            ledger_wasm: Wasm::from(ledger_wasm),
            index_wasm: Wasm::from(index_wasm),
            archive_wasm: Wasm::from(archive_wasm),
            managed_canisters: Default::default(),
            tasks: Default::default(),
            processing_tasks_guard: false,
        }
    }
}

pub fn read_state<R>(f: impl FnOnce(&State) -> R) -> R {
    STATE.with(|cell| f(cell.borrow().get().expect_initialized()))
}

/// Mutates (part of) the current state using `f`.
///
/// Panics if there is no state.
pub fn mutate_state<F, R>(f: F) -> R
where
    F: FnOnce(&mut State) -> R,
{
    STATE.with(|cell| {
        let mut borrowed = cell.borrow_mut();
        let mut state = borrowed.get().expect_initialized().clone();
        let result = f(&mut state);
        borrowed
            .set(ConfigState::Initialized(state))
            .expect("failed to write state in stable cell");
        result
    })
}

pub fn init_state(state: State) {
    STATE.with(|cell| {
        let mut borrowed = cell.borrow_mut();
        assert_eq!(
            borrowed.get(),
            &ConfigState::Uninitialized,
            "BUG: State is already initialized and has value {:?}",
            borrowed.get()
        );
        borrowed
            .set(ConfigState::Initialized(state))
            .expect("failed to initialize state in stable cell")
    });
}
