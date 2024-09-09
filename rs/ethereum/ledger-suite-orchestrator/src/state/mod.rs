#[cfg(test)]
pub mod test_fixtures;
#[cfg(test)]
mod tests;

use crate::candid::{CyclesManagement, InitArg};
use crate::scheduler::{Erc20Token, InvalidManageInstalledCanistersError, Task};
use crate::storage::memory::{state_memory, StableMemory};
use crate::storage::WasmHashError;
use candid::Principal;
use ic_cdk::trap;
use ic_stable_structures::{storable::Bound, Cell, Storable};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_bytes::ByteArray;
use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Debug, Display, Formatter};
use std::iter::once;
use std::marker::PhantomData;
use std::str::FromStr;

pub(crate) const LEDGER_BYTECODE: &[u8] = include_bytes!(env!("LEDGER_CANISTER_WASM_PATH"));
pub(crate) const INDEX_BYTECODE: &[u8] = include_bytes!(env!("INDEX_CANISTER_WASM_PATH"));
pub(crate) const ARCHIVE_NODE_BYTECODE: &[u8] =
    include_bytes!(env!("LEDGER_ARCHIVE_NODE_CANISTER_WASM_PATH"));

const WASM_HASH_LENGTH: usize = 32;
const GIT_COMMIT_HASH_LENGTH: usize = 20;

thread_local! {
    pub static STATE: RefCell<Cell<ConfigState, StableMemory>> = RefCell::new(Cell::init(
   state_memory(), ConfigState::default())
    .expect("failed to initialize stable cell for state"));
}

/// `Wasm<Canister>` is a wrapper around a wasm binary and its memoized hash.
/// It provides a type-safe way to handle wasm binaries for different canisters.
#[derive(Debug)]
pub struct Wasm<T> {
    binary: Vec<u8>,
    hash: WasmHash,
    marker: PhantomData<T>,
}

pub type LedgerWasm = Wasm<Ledger>;
pub type IndexWasm = Wasm<Index>;
pub type ArchiveWasm = Wasm<Archive>;

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Deserialize, Serialize)]
#[serde(from = "serde_bytes::ByteArray<N>", into = "serde_bytes::ByteArray<N>")]
pub struct Hash<const N: usize>([u8; N]);

impl<const N: usize> Default for Hash<N> {
    fn default() -> Self {
        Self([0; N])
    }
}

impl<const N: usize> From<ByteArray<N>> for Hash<N> {
    fn from(value: ByteArray<N>) -> Self {
        Self(value.into_array())
    }
}

impl<const N: usize> From<Hash<N>> for ByteArray<N> {
    fn from(value: Hash<N>) -> Self {
        ByteArray::new(value.0)
    }
}

impl<const N: usize> AsRef<[u8]> for Hash<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> From<[u8; N]> for Hash<N> {
    fn from(value: [u8; N]) -> Self {
        Self(value)
    }
}

impl<const N: usize> From<Hash<N>> for [u8; N] {
    fn from(value: Hash<N>) -> Self {
        value.0
    }
}

impl<const N: usize> FromStr for Hash<N> {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let expected_num_hex_chars = N * 2;
        if s.len() != expected_num_hex_chars {
            return Err(format!(
                "Invalid hash: expected {} characters, got {}",
                expected_num_hex_chars,
                s.len()
            ));
        }
        let mut bytes = [0u8; N];
        hex::decode_to_slice(s, &mut bytes).map_err(|e| format!("Invalid hex string: {}", e))?;
        Ok(Self(bytes))
    }
}

impl<const N: usize> Display for Hash<N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl<const N: usize> Storable for Hash<N> {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::from(self.as_ref())
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        assert_eq!(bytes.len(), N, "Hash representation is {}-bytes long", N);
        let mut be_bytes = [0u8; N];
        be_bytes.copy_from_slice(bytes.as_ref());
        Self(be_bytes)
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: N as u32,
        is_fixed_size: true,
    };
}

pub type WasmHash = Hash<WASM_HASH_LENGTH>;

impl WasmHash {
    /// Creates an array of wasm hashes from an array of their respective string representations.
    /// This method preserves the order of the input strings:
    /// element with index i in the input, will have index i in the output.
    /// The input strings are expected to be distinct and valid wasm hashes.
    ///
    /// # Errors
    /// * If any of the strings is not a valid wasm hash.
    /// * If there are any duplicates.
    pub fn from_distinct_opt_str<const N: usize>(
        hashes: [Option<&str>; N],
    ) -> Result<[Option<WasmHash>; N], String> {
        let mut duplicates = BTreeSet::new();
        let mut result = Vec::with_capacity(N);
        for maybe_hash in hashes {
            match maybe_hash {
                None => {
                    result.push(None);
                }
                Some(hash) => {
                    let hash = WasmHash::from_str(hash)?;
                    if !duplicates.insert(hash.clone()) {
                        return Err(format!("Duplicate hash: {}", hash));
                    }
                    result.push(Some(hash));
                }
            }
        }
        Ok(result
            .try_into()
            .map_err(|_err| "failed to convert to fixed size array")
            .expect("BUG: failed to convert to fixed size array"))
    }
}

impl<T> Wasm<T> {
    pub fn new(binary: Vec<u8>) -> Self {
        let hash = WasmHash::from(ic_crypto_sha2::Sha256::hash(binary.as_slice()));
        Self {
            binary,
            hash,
            marker: PhantomData,
        }
    }

    pub fn to_bytes(self) -> Vec<u8> {
        self.binary
    }

    pub fn hash(&self) -> &WasmHash {
        &self.hash
    }
}

impl<T> Clone for Wasm<T> {
    fn clone(&self) -> Self {
        Self::new(self.binary.clone())
    }
}

impl<T> PartialEq for Wasm<T> {
    fn eq(&self, other: &Self) -> bool {
        self.binary.eq(&other.binary)
    }
}

impl<T> From<Vec<u8>> for Wasm<T> {
    fn from(v: Vec<u8>) -> Self {
        Self::new(v)
    }
}

impl<T> From<&[u8]> for Wasm<T> {
    fn from(value: &[u8]) -> Self {
        Self::new(value.to_vec())
    }
}

/// Uniquely identifies a Git commit revision by its full 40-character SHA-1 hash,
/// see [Git Revision Selection](https://git-scm.com/book/en/v2/Git-Tools-Revision-Selection).
pub type GitCommitHash = Hash<GIT_COMMIT_HASH_LENGTH>;

#[derive(Clone, PartialEq, Debug, Default, Deserialize, Serialize)]
pub struct ManagedCanisters {
    /// Canisters for an ERC-20 token
    canisters: BTreeMap<Erc20Token, Canisters>,
    /// Canisters for a non-ERC-20 token, identified by its token symbol
    #[serde(default)]
    other_canisters: BTreeMap<TokenSymbol, Canisters>,
}

impl ManagedCanisters {
    pub fn find_by_id(&self, token_id: &TokenId) -> Option<&Canisters> {
        match token_id {
            TokenId::Erc20(contract) => self.canisters.get(contract),
            TokenId::Other(symbol) => self.other_canisters.get(symbol),
        }
    }

    pub fn get_mut(&mut self, token_id: &TokenId) -> Option<&mut Canisters> {
        match token_id {
            TokenId::Erc20(contract) => self.canisters.get_mut(contract),
            TokenId::Other(symbol) => self.other_canisters.get_mut(symbol),
        }
    }

    pub fn insert_once(&mut self, token_id: TokenId, canisters: Canisters) {
        assert_eq!(
            self.find_by_id(&token_id),
            None,
            "BUG: token {:?} is already managed",
            token_id
        );
        let previous_element = match token_id {
            TokenId::Erc20(contract) => self.canisters.insert(contract, canisters),
            TokenId::Other(token_symbol) => self.other_canisters.insert(token_symbol, canisters),
        };
        assert_eq!(previous_element, None);
    }

    pub fn all_canisters_iter(&self) -> impl Iterator<Item = (TokenId, &Canisters)> {
        self.canisters
            .iter()
            .map(|(key, value)| (TokenId::from(key.clone()), value))
            .chain(
                self.other_canisters
                    .iter()
                    .map(|(key, value)| (TokenId::from(key.clone()), value)),
            )
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Deserialize, Serialize)]
pub struct TokenSymbol(String);

impl Display for TokenSymbol {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for TokenSymbol {
    fn from(value: String) -> Self {
        Self(value)
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Deserialize, Serialize)]
pub enum TokenId {
    Erc20(Erc20Token),
    Other(TokenSymbol),
}
impl TokenId {
    pub fn into_erc20_unchecked(self) -> Erc20Token {
        match self {
            TokenId::Erc20(token) => token,
            TokenId::Other(symbol) => panic!("BUG: token id {:?} is not an ERC-20 token", symbol),
        }
    }

    pub fn into_other_unchecked(self) -> TokenSymbol {
        match self {
            TokenId::Erc20(token) => panic!("BUG: token id {:?} is an ERC-20 token", token),
            TokenId::Other(symbol) => symbol,
        }
    }
}

impl From<Erc20Token> for TokenId {
    fn from(value: Erc20Token) -> Self {
        TokenId::Erc20(value)
    }
}

impl From<TokenSymbol> for TokenId {
    fn from(value: TokenSymbol) -> Self {
        TokenId::Other(value)
    }
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct Canisters {
    pub ledger: Option<LedgerCanister>,
    pub index: Option<IndexCanister>,
    pub archives: Vec<Principal>,
    pub metadata: CanistersMetadata,
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Deserialize, Serialize)]
pub struct CanistersMetadata {
    pub token_symbol: String,
}

impl Canisters {
    pub fn new(metadata: CanistersMetadata) -> Self {
        Self {
            ledger: None,
            index: None,
            archives: vec![],
            metadata,
        }
    }

    pub fn ledger_canister_id(&self) -> Option<&Principal> {
        self.ledger.as_ref().map(LedgerCanister::canister_id)
    }

    pub fn index_canister_id(&self) -> Option<&Principal> {
        self.index.as_ref().map(IndexCanister::canister_id)
    }

    pub fn archive_canister_ids(&self) -> &[Principal] {
        &self.archives
    }

    pub fn principals_iter(&self) -> impl Iterator<Item = &Principal> {
        self.ledger_canister_id()
            .into_iter()
            .chain(self.index_canister_id())
            .chain(self.archive_canister_ids().iter())
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

    pub fn installed_wasm_hash(&self) -> Option<&WasmHash> {
        self.status.installed_wasm_hash()
    }

    pub fn status(&self) -> &ManagedCanisterStatus {
        &self.status
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

#[derive(Debug)]
pub enum Archive {}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
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

    fn installed_wasm_hash(&self) -> Option<&WasmHash> {
        match self {
            ManagedCanisterStatus::Created { .. } => None,
            ManagedCanisterStatus::Installed {
                installed_wasm_hash,
                ..
            } => Some(installed_wasm_hash),
        }
    }
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct LedgerSuiteVersion {
    pub ledger_compressed_wasm_hash: WasmHash,
    pub index_compressed_wasm_hash: WasmHash,
    pub archive_compressed_wasm_hash: WasmHash,
}

/// Configuration state of the ledger orchestrator.
#[derive(Clone, PartialEq, Debug, Default)]
enum ConfigState {
    #[default]
    Uninitialized,
    // This state is only used between wasm module initialization and init().
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
            ConfigState::Initialized(config) => Cow::Owned(encode(config)),
        }
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        if bytes.is_empty() {
            return ConfigState::Uninitialized;
        }
        ConfigState::Initialized(decode(bytes.as_ref()))
    }

    const BOUND: Bound = Bound::Unbounded;
}

fn encode<S: ?Sized + serde::Serialize>(state: &S) -> Vec<u8> {
    let mut buf = vec![];
    ciborium::ser::into_writer(state, &mut buf).expect("failed to encode state");
    buf
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> T {
    ciborium::de::from_reader(bytes)
        .unwrap_or_else(|e| panic!("failed to decode state bytes {}: {e}", hex::encode(bytes)))
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct State {
    managed_canisters: ManagedCanisters,
    cycles_management: CyclesManagement,
    more_controller_ids: Vec<Principal>,
    minter_id: Option<Principal>,
    /// Locks preventing concurrent execution timer tasks
    pub active_tasks: BTreeSet<Task>,
    #[serde(default)]
    ledger_suite_version: Option<LedgerSuiteVersion>,
}

impl State {
    pub fn more_controller_ids(&self) -> &[Principal] {
        &self.more_controller_ids
    }

    pub fn minter_id(&self) -> Option<&Principal> {
        self.minter_id.as_ref()
    }

    pub fn cycles_management(&self) -> &CyclesManagement {
        &self.cycles_management
    }

    pub fn cycles_management_mut(&mut self) -> &mut CyclesManagement {
        &mut self.cycles_management
    }

    pub fn all_managed_canisters_iter(&self) -> impl Iterator<Item = (TokenId, &Canisters)> {
        self.managed_canisters.all_canisters_iter()
    }

    pub fn all_managed_principals(&self) -> impl Iterator<Item = &Principal> {
        self.all_managed_canisters_iter()
            .flat_map(|(_, canisters)| canisters.principals_iter())
    }

    pub fn all_managed_tokens_ids_iter(&self) -> impl Iterator<Item = TokenId> + '_ {
        self.all_managed_canisters_iter().map(|(id, _)| id)
    }

    pub fn managed_canisters(&self, token_id: &TokenId) -> Option<&Canisters> {
        self.managed_canisters.find_by_id(token_id)
    }

    pub fn ledger_suite_version(&self) -> Option<&LedgerSuiteVersion> {
        self.ledger_suite_version.as_ref()
    }

    /// Initializes the ledger suite version if it is not already set.
    /// No-op if the ledger suite version is already set.
    pub fn init_ledger_suite_version(&mut self, version: LedgerSuiteVersion) {
        if self.ledger_suite_version.is_none() {
            self.ledger_suite_version = Some(version);
        }
    }

    pub fn update_ledger_suite_version(&mut self, new_version: LedgerSuiteVersion) {
        self.ledger_suite_version = Some(new_version);
    }

    fn managed_canisters_mut(&mut self, token_id: &TokenId) -> Option<&mut Canisters> {
        self.managed_canisters.get_mut(token_id)
    }

    pub fn managed_status<'a, T: 'a>(
        &'a self,
        token_id: &TokenId,
    ) -> Option<&'a ManagedCanisterStatus>
    where
        Canisters: ManageSingleCanister<T>,
    {
        self.managed_canisters(token_id)
            .and_then(|c| c.get().map(|c| &c.status))
    }

    /// Record other canisters managed by the orchestrator.
    pub fn record_manage_other_canisters(&mut self, other_canisters: ManageOtherCanisters) {
        let token_id = TokenId::from(other_canisters.token_symbol.clone());
        self.managed_canisters
            .insert_once(token_id, Canisters::from(other_canisters));
    }

    pub fn record_new_erc20_token(&mut self, contract: Erc20Token, metadata: CanistersMetadata) {
        let token_id = TokenId::from(contract);
        self.managed_canisters
            .insert_once(token_id, Canisters::new(metadata));
    }

    pub fn record_archives(&mut self, token_id: &TokenId, archives: Vec<Principal>) {
        let canisters = self
            .managed_canisters_mut(token_id)
            .unwrap_or_else(|| panic!("BUG: token {:?} is not managed", token_id));
        canisters.archives = archives;
    }

    pub fn record_created_canister<T: Debug>(
        &mut self,
        contract: &Erc20Token,
        canister_id: Principal,
    ) where
        Canisters: ManageSingleCanister<T>,
    {
        let token_id = TokenId::from(contract.clone());
        let canisters = self
            .managed_canisters_mut(&token_id)
            .unwrap_or_else(|| panic!("BUG: token {:?} is not managed", token_id));
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

    pub fn record_installed_canister<T>(&mut self, contract: &Erc20Token, wasm_hash: WasmHash)
    where
        Canisters: ManageSingleCanister<T>,
    {
        let token_id = TokenId::from(contract.clone());
        let managed_canister = self
            .managed_canisters_mut(&token_id)
            .and_then(Canisters::get_mut)
            .unwrap_or_else(|| {
                panic!(
                    "BUG: no managed canisters or no {} canister for {:?}",
                    Canisters::display_name(),
                    token_id
                )
            });
        let canister_id = *managed_canister.canister_id();
        managed_canister.status = ManagedCanisterStatus::Installed {
            canister_id,
            installed_wasm_hash: wasm_hash,
        };
    }

    pub fn validate_config(&self) -> Result<(), InvalidStateError> {
        const MAX_ADDITIONAL_CONTROLLERS: usize = 9;
        if self.more_controller_ids.len() > MAX_ADDITIONAL_CONTROLLERS {
            return Err(InvalidStateError::TooManyAdditionalControllers {
                max: MAX_ADDITIONAL_CONTROLLERS,
                actual: self.more_controller_ids.len(),
            });
        }
        Ok(())
    }
}

pub trait ManageSingleCanister<T> {
    fn display_name() -> &'static str;

    fn get(&self) -> Option<&Canister<T>>;

    fn get_mut(&mut self) -> Option<&mut Canister<T>>;

    fn try_insert(&mut self, canister: Canister<T>) -> Result<(), OccupiedError<Canister<T>>>;
}

#[derive(Clone, PartialEq, Debug)]
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

#[derive(Eq, PartialEq, Debug)]
pub enum InvalidStateError {
    TooManyAdditionalControllers { max: usize, actual: usize },
}

impl TryFrom<InitArg> for State {
    type Error = InvalidStateError;
    fn try_from(
        InitArg {
            more_controller_ids,
            minter_id,
            cycles_management,
        }: InitArg,
    ) -> Result<Self, Self::Error> {
        let state = Self {
            managed_canisters: Default::default(),
            cycles_management: cycles_management.unwrap_or_default(),
            more_controller_ids,
            minter_id,
            ledger_suite_version: Default::default(),
            active_tasks: Default::default(),
        };
        state.validate_config()?;
        Ok(state)
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

#[derive(Clone, PartialEq, Debug)]
pub struct ManageOtherCanisters {
    token_symbol: TokenSymbol,
    ledger: Principal,
    ledger_wasm_hash: WasmHash,
    index: Principal,
    index_wasm_hash: WasmHash,
    archives: Vec<Principal>,
}

impl From<ManageOtherCanisters> for Canisters {
    fn from(value: ManageOtherCanisters) -> Self {
        Self {
            ledger: Some(LedgerCanister::new(ManagedCanisterStatus::Installed {
                canister_id: value.ledger,
                installed_wasm_hash: value.ledger_wasm_hash,
            })),
            index: Some(IndexCanister::new(ManagedCanisterStatus::Installed {
                canister_id: value.index,
                installed_wasm_hash: value.index_wasm_hash,
            })),
            archives: value.archives,
            metadata: CanistersMetadata {
                token_symbol: value.token_symbol.to_string(),
            },
        }
    }
}

impl ManageOtherCanisters {
    pub fn validate(
        state: &State,
        args: crate::candid::ManageOtherCanisters,
    ) -> Result<ManageOtherCanisters, InvalidManageInstalledCanistersError> {
        let token_symbol = TokenSymbol(args.token_symbol);
        let token_id = TokenId::Other(token_symbol.clone());
        if state.managed_canisters(&token_id).is_some() {
            return Err(InvalidManageInstalledCanistersError::TokenAlreadyManaged(
                token_symbol,
            ));
        }
        let ledger = args.ledger.canister_id;
        let ledger_wasm_hash = args.ledger.installed_wasm_hash.parse().map_err(|e| {
            InvalidManageInstalledCanistersError::WasmHashError(WasmHashError::Invalid(e))
        })?;
        let index = args.index.canister_id;
        let index_wasm_hash = args.index.installed_wasm_hash.parse().map_err(|e| {
            InvalidManageInstalledCanistersError::WasmHashError(WasmHashError::Invalid(e))
        })?;
        if ledger_wasm_hash == index_wasm_hash {
            return Err(InvalidManageInstalledCanistersError::WasmHashError(
                WasmHashError::Invalid("ledger and index wasm hashes are the same".to_string()),
            ));
        }
        let archives = args.archives.unwrap_or_default();

        let installed_principals: BTreeSet<_> = once(&ledger)
            .chain(once(&index))
            .chain(archives.iter())
            .collect();
        let managed_principals: BTreeSet<_> = state.all_managed_principals().collect();
        let overlapping_principals: BTreeSet<_> = managed_principals
            .intersection(&installed_principals)
            .collect();
        if !overlapping_principals.is_empty() {
            return Err(
                InvalidManageInstalledCanistersError::AlreadyManagedPrincipals(
                    overlapping_principals
                        .into_iter()
                        .cloned()
                        .cloned()
                        .collect(),
                ),
            );
        }
        Ok(ManageOtherCanisters {
            token_symbol,
            ledger,
            ledger_wasm_hash,
            index,
            index_wasm_hash,
            archives,
        })
    }
}
