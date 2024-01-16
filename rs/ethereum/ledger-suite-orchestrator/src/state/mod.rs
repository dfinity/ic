use crate::candid::InitArg;
use crate::scheduler::{Erc20Contract, Task, Tasks};
use candid::Principal;
use ic_cdk::trap;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{Cell, DefaultMemoryImpl, Storable};
use minicbor::{Decode, Encode};
use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::BTreeMap;

const STATE_MEMORY_ID: MemoryId = MemoryId::new(0);

thread_local! {
     static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> = RefCell::new(
        MemoryManager::init(DefaultMemoryImpl::default())
    );

    //TODO: more refined stable memory structure, right now we just dump everything into a single Cell
    pub static STATE: RefCell<Cell<ConfigState, VirtualMemory<DefaultMemoryImpl>>> = RefCell::new(Cell::init(
    MEMORY_MANAGER.with(|m| m.borrow().get(STATE_MEMORY_ID)), ConfigState::default())
    .expect("failed to initialize stable cell for state"));
}

#[derive(Debug, PartialEq, Encode, Decode, Clone)]
pub struct Wasm(#[cbor(n(0), with = "minicbor::bytes")] Vec<u8>);

impl Wasm {
    pub fn to_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl From<Vec<u8>> for Wasm {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

#[derive(Debug, PartialEq, Clone, Encode, Decode, Default)]
pub struct ManagedCanisters {
    #[n(0)]
    canisters: BTreeMap<Erc20Contract, Canisters>,
}

#[derive(Debug, PartialEq, Encode, Decode, Clone)]
pub struct Canisters {
    #[cbor(n(0), with = "crate::cbor::principal")]
    ledger: Principal,
    #[cbor(n(1), with = "crate::cbor::principal")]
    index: Principal,
    #[cbor(n(2), with = "crate::cbor::principal::vec")]
    archives: Vec<Principal>,
}

impl Canisters {
    pub fn new(ledger: Principal, index: Principal) -> Self {
        Self {
            ledger,
            index,
            archives: vec![],
        }
    }

    pub fn ledger_canister_id(&self) -> &Principal {
        &self.ledger
    }

    pub fn index_canister_id(&self) -> &Principal {
        &self.index
    }

    pub fn archive_canister_ids(&self) -> &[Principal] {
        &self.archives
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
                minicbor::encode(config, &mut buf).expect("state encoding should always succeed");
                Cow::Owned(buf)
            }
        }
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        if bytes.is_empty() {
            return ConfigState::Uninitialized;
        }
        ConfigState::Initialized(
            minicbor::decode(bytes.as_ref()).unwrap_or_else(|e| {
                panic!("failed to decode state bytes {}: {e}", hex::encode(bytes))
            }),
        )
    }
}

#[derive(Debug, PartialEq, Encode, Decode, Clone)]
pub struct State {
    #[n(0)]
    ledger_wasm: Wasm,
    #[n(1)]
    index_wasm: Wasm,
    #[n(2)]
    archive_wasm: Wasm,
    #[n(3)]
    managed_canisters: ManagedCanisters,
    #[n(4)]
    tasks: Tasks,
    #[n(5)]
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

    pub fn unset_timer_guard(&mut self) {
        self.processing_tasks_guard = false;
    }

    pub fn record_managed_canisters(&mut self, contract: Erc20Contract, canisters: Canisters) {
        assert_eq!(
            self.managed_canisters
                .canisters
                .insert(contract.clone(), canisters),
            None,
            "Canisters are already registered for {:?}",
            contract
        );
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
