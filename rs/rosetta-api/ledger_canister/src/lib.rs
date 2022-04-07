use candid::CandidType;
use dfn_protobuf::ProtoBuf;
use ic_base_types::{CanisterId, PrincipalId};
use ic_crypto_sha::Sha256;
use intmap::IntMap;
use lazy_static::lazy_static;
use on_wire::{FromWire, IntoWire};
use phantom_newtype::Id;
use serde::{
    de::{Deserializer, MapAccess, Visitor},
    ser::SerializeMap,
    Deserialize, Serialize, Serializer,
};
use std::borrow::Cow;
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::convert::TryFrom;
use std::convert::TryInto;
use std::fmt;
use std::hash::Hash;
use std::marker::PhantomData;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

pub mod account_identifier;
pub mod tokens;
#[path = "../gen/ic_ledger.pb.v1.rs"]
#[rustfmt::skip]
pub mod protobuf;
pub mod range_utils;
pub mod timestamp;
pub mod validate_endpoints;

pub mod archive;

use archive::Archive;
pub use archive::ArchiveOptions;
use dfn_core::api::now;

pub mod spawn;
pub use account_identifier::{AccountIdentifier, Subaccount};
pub use protobuf::TimeStamp;
pub use tokens::{Tokens, DECIMAL_PLACES, DEFAULT_TRANSFER_FEE, TOKEN_SUBDIVIDABLE_BY};

pub const HASH_LENGTH: usize = 32;
pub const MAX_BLOCKS_PER_REQUEST: usize = 2000;

#[derive(CandidType, Clone, Hash, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct HashOf<T> {
    inner: Id<T, [u8; HASH_LENGTH]>,
}

impl<T: std::clone::Clone> Copy for HashOf<T> {}

impl<T> HashOf<T> {
    pub fn into_bytes(self) -> [u8; HASH_LENGTH] {
        self.inner.get()
    }

    pub fn new(bs: [u8; HASH_LENGTH]) -> Self {
        HashOf { inner: Id::new(bs) }
    }
}

impl<T> fmt::Display for HashOf<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let res = hex::encode(self.inner.get());
        write!(f, "{}", res)
    }
}

impl<T> FromStr for HashOf<T> {
    type Err = String;
    fn from_str(s: &str) -> Result<HashOf<T>, String> {
        let v = hex::decode(s).map_err(|e| e.to_string())?;
        let slice = v.as_slice();
        match slice.try_into() {
            Ok(ba) => Ok(HashOf::new(ba)),
            Err(_) => Err(format!(
                "Expected a Vec of length {} but it was {}",
                HASH_LENGTH,
                v.len(),
            )),
        }
    }
}

impl<T> Serialize for HashOf<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            serializer.serialize_bytes(self.inner.get_ref())
        }
    }
}

impl<'de, T> Deserialize<'de> for HashOf<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct HashOfVisitor<T> {
            phantom: PhantomData<T>,
        }

        impl<'de, T> Visitor<'de> for HashOfVisitor<T> {
            type Value = HashOf<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    formatter,
                    "a hash of type {}: a blob with at most {} bytes",
                    std::any::type_name::<T>(),
                    HASH_LENGTH
                )
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(HashOf::new(
                    v.try_into().expect("hash does not have correct length"),
                ))
            }

            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                HashOf::from_str(s).map_err(E::custom)
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_str(HashOfVisitor {
                phantom: PhantomData,
            })
        } else {
            deserializer.deserialize_bytes(HashOfVisitor {
                phantom: PhantomData,
            })
        }
    }
}

#[derive(
    Serialize, Deserialize, CandidType, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
#[serde(transparent)]
pub struct EncodedBlock(pub serde_bytes::ByteBuf);

impl From<Vec<u8>> for EncodedBlock {
    fn from(bytes: Vec<u8>) -> Self {
        Self::from_vec(bytes)
    }
}

impl EncodedBlock {
    pub fn hash(&self) -> HashOf<Self> {
        let mut state = Sha256::new();
        state.write(&self.0);
        HashOf::new(state.finish())
    }

    pub fn decode(&self) -> Result<Block, String> {
        let bytes = self.0.to_vec();
        Ok(ProtoBuf::from_bytes(bytes)?.get())
    }

    pub fn from_vec(bytes: Vec<u8>) -> Self {
        Self(serde_bytes::ByteBuf::from(bytes))
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn size_bytes(&self) -> usize {
        self.0.len()
    }
}

#[derive(
    Serialize,
    Deserialize,
    CandidType,
    Clone,
    Copy,
    Default,
    Hash,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
pub struct Memo(pub u64);

/// Position of a block in the chain. The first block has position 0.
pub type BlockHeight = u64;

pub type Certification = Option<Vec<u8>>;

pub type LedgerBalances = Balances<HashMap<AccountIdentifier, Tokens>>;

pub trait BalancesStore {
    /// Returns the balance on the specified account.
    fn get_balance(&self, k: &AccountIdentifier) -> Option<&Tokens>;

    /// Update balance for an account using function f.
    /// Its arg is previous balance or None if not found and
    /// return value is the new balance.
    fn update<F, E>(&mut self, acc: AccountIdentifier, action_on_acc: F) -> Result<Tokens, E>
    where
        F: FnMut(Option<&Tokens>) -> Result<Tokens, E>;
}

impl BalancesStore for HashMap<AccountIdentifier, Tokens> {
    fn get_balance(&self, k: &AccountIdentifier) -> Option<&Tokens> {
        self.get(k)
    }

    fn update<F, E>(&mut self, k: AccountIdentifier, mut f: F) -> Result<Tokens, E>
    where
        F: FnMut(Option<&Tokens>) -> Result<Tokens, E>,
    {
        match self.entry(k) {
            Occupied(mut entry) => {
                let new_v = f(Some(entry.get()))?;
                if new_v != Tokens::ZERO {
                    *entry.get_mut() = new_v;
                } else {
                    entry.remove_entry();
                }
                Ok(new_v)
            }
            Vacant(entry) => {
                let new_v = f(None)?;
                if new_v != Tokens::ZERO {
                    entry.insert(new_v);
                }
                Ok(new_v)
            }
        }
    }
}

/// An error returned by `Balances` if the debit operation fails.
#[derive(Debug)]
pub enum BalanceError {
    /// An error indicating that the account doesn't hold enough funds for
    /// completing the transaction.
    InsufficientFunds { balance: Tokens },
}

/// Describes the state of users accounts at the tip of the chain
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Balances<S: BalancesStore> {
    // This uses a mutable map because we don't want to risk a space leak and we only require the
    // account balances at the tip of the chain
    pub store: S,
    #[serde(alias = "icpt_pool")]
    pub token_pool: Tokens,
}

impl<S: Default + BalancesStore> Default for Balances<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: Default + BalancesStore> Balances<S> {
    pub fn new() -> Self {
        Self {
            store: S::default(),
            token_pool: Tokens::MAX,
        }
    }

    pub fn add_payment(&mut self, payment: &Operation) -> Result<(), BalanceError> {
        match payment {
            Operation::Transfer {
                from,
                to,
                amount,
                fee,
            } => {
                let debit_amount = (*amount + *fee).map_err(|_| {
                    // No account can hold more than u64::MAX.
                    let balance = self.account_balance(from);
                    BalanceError::InsufficientFunds { balance }
                })?;
                self.debit(from, debit_amount)?;
                self.credit(to, *amount);
                // NB. integer overflow is not possible here unless there is a
                // severe bug in the system: total amount of tokens in the
                // circulation cannot exceed u64::MAX.
                self.token_pool += *fee;
            }
            Operation::Burn { from, amount, .. } => {
                self.debit(from, *amount)?;
                self.token_pool += *amount;
            }
            Operation::Mint { to, amount, .. } => {
                self.token_pool = (self.token_pool - *amount).expect("total token supply exceeded");
                self.credit(to, *amount);
            }
        }
        Ok(())
    }

    // Debiting an account will automatically remove it from the `inner`
    // HashMap if the balance reaches zero.
    pub fn debit(
        &mut self,
        from: &AccountIdentifier,
        amount: Tokens,
    ) -> Result<Tokens, BalanceError> {
        self.store.update(*from, |prev| {
            let mut balance = match prev {
                Some(x) => *x,
                None => {
                    return Err(BalanceError::InsufficientFunds {
                        balance: Tokens::ZERO,
                    });
                }
            };
            if balance < amount {
                return Err(BalanceError::InsufficientFunds { balance });
            }

            balance -= amount;
            Ok(balance)
        })
    }

    // Crediting an account will automatically add it to the `inner` HashMap if
    // not already present.
    pub fn credit(&mut self, to: &AccountIdentifier, amount: Tokens) {
        self.store
            .update(*to, |prev| -> Result<Tokens, std::convert::Infallible> {
                // NB. credit cannot overflow unless there is a bug in the
                // system: the total amount of tokens in the circulation cannot
                // exceed u64::MAX, so it's impossible to have more than
                // u64::MAX tokens on a single account.
                Ok((amount + *prev.unwrap_or(&Tokens::ZERO)).expect("bug: overflow in credit"))
            })
            .unwrap();
    }

    pub fn account_balance(&self, account: &AccountIdentifier) -> Tokens {
        self.store
            .get_balance(account)
            .cloned()
            .unwrap_or(Tokens::ZERO)
    }

    /// Returns the total quantity of Tokens that are "in existence" -- that
    /// is, excluding un-minted "potential" Tokens.
    pub fn total_supply(&self) -> Tokens {
        (Tokens::MAX - self.token_pool).unwrap_or_else(|e| {
            panic!(
                "It is expected that the token_pool is always smaller than \
            or equal to Tokens::MAX, yet subtracting it lead to the following error: {}",
                e
            )
        })
    }
}

impl LedgerBalances {
    // Find the specified number of accounts with lowest balances so that their
    // balances can be reclaimed.
    fn select_accounts_to_trim(&mut self, num_accounts: usize) -> Vec<(Tokens, AccountIdentifier)> {
        let mut to_trim: std::collections::BinaryHeap<(Tokens, AccountIdentifier)> =
            std::collections::BinaryHeap::new();

        let mut iter = self.store.iter();

        // Accumulate up to `trim_quantity` accounts
        for (account, balance) in iter.by_ref().take(num_accounts) {
            to_trim.push((*balance, *account));
        }

        for (account, balance) in iter {
            // If any account's balance is lower than the maximum in our set,
            // include that account, and remove the current maximum
            if let Some((greatest_balance, _)) = to_trim.peek() {
                if balance < greatest_balance {
                    to_trim.push((*balance, *account));
                    to_trim.pop();
                }
            }
        }

        to_trim.into_vec()
    }
}

/// An operation which modifies account balances
#[derive(
    Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq, PartialOrd, Ord,
)]
pub enum Operation {
    Burn {
        from: AccountIdentifier,
        amount: Tokens,
    },
    Mint {
        to: AccountIdentifier,
        amount: Tokens,
    },
    Transfer {
        from: AccountIdentifier,
        to: AccountIdentifier,
        amount: Tokens,
        fee: Tokens,
    },
}

/// An operation with the metadata the client generated attached to it
#[derive(
    Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq, PartialOrd, Ord,
)]
pub struct Transaction {
    pub operation: Operation,
    pub memo: Memo,

    /// The time this transaction was created.
    pub created_at_time: TimeStamp,
}

impl Transaction {
    pub fn new(
        from: AccountIdentifier,
        to: AccountIdentifier,
        amount: Tokens,
        fee: Tokens,
        memo: Memo,
        created_at_time: TimeStamp,
    ) -> Self {
        let operation = Operation::Transfer {
            from,
            to,
            amount,
            fee,
        };
        Transaction {
            operation,
            memo,
            created_at_time,
        }
    }

    pub fn hash(&self) -> HashOf<Self> {
        let mut state = Sha256::new();
        state.write(&serde_cbor::ser::to_vec_packed(&self).unwrap());
        HashOf::new(state.finish())
    }
}

/// A transaction with the metadata the canister generated attached to it
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub parent_hash: Option<HashOf<EncodedBlock>>,
    pub transaction: Transaction,
    /// Nanoseconds since the Unix epoch.
    pub timestamp: TimeStamp,
}

impl Block {
    pub fn new(
        parent_hash: Option<HashOf<EncodedBlock>>,
        operation: Operation,
        memo: Memo,
        created_at_time: TimeStamp, // transaction timestamp
        timestamp: TimeStamp,       // block timestamp
    ) -> Result<Self, String> {
        let transaction = Transaction {
            operation,
            memo,
            created_at_time,
        };
        Ok(Self::new_from_transaction(
            parent_hash,
            transaction,
            timestamp,
        ))
    }

    pub fn new_from_transaction(
        parent_hash: Option<HashOf<EncodedBlock>>,
        transaction: Transaction,
        timestamp: TimeStamp,
    ) -> Self {
        Self {
            parent_hash,
            transaction,
            timestamp,
        }
    }

    pub fn encode(self) -> Result<EncodedBlock, String> {
        let bytes = ProtoBuf::new(self).into_bytes()?;
        Ok(EncodedBlock::from(bytes))
    }

    pub fn parent_hash(&self) -> Option<HashOf<EncodedBlock>> {
        self.parent_hash
    }

    pub fn transaction(&self) -> Cow<Transaction> {
        Cow::Borrowed(&self.transaction)
    }

    pub fn timestamp(&self) -> TimeStamp {
        self.timestamp
    }
}

/// Stores a chain of transactions with their metadata
#[derive(Serialize, Deserialize, Debug)]
pub struct Blockchain {
    pub blocks: Vec<EncodedBlock>,
    pub last_hash: Option<HashOf<EncodedBlock>>,

    /// The timestamp of the most recent block. Must be monotonically
    /// non-decreasing.
    pub last_timestamp: TimeStamp,

    /// This `Arc` is safe to (de)serialize because uniqueness is guaranteed
    /// by the canister upgrade procedure.
    #[serde(serialize_with = "ic_utils::serde_arc::serialize_arc")]
    #[serde(deserialize_with = "ic_utils::serde_arc::deserialize_arc")]
    pub archive: Arc<RwLock<Option<Archive>>>,

    /// How many blocks have been sent to the archive
    pub num_archived_blocks: u64,
}

impl Default for Blockchain {
    fn default() -> Self {
        Self {
            blocks: vec![],
            last_hash: None,
            last_timestamp: SystemTime::UNIX_EPOCH.into(),
            archive: Arc::new(RwLock::new(None)),
            num_archived_blocks: 0,
        }
    }
}

impl Blockchain {
    pub fn add_block(&mut self, block: Block) -> Result<BlockHeight, String> {
        let raw_block = block.clone().encode()?;
        self.add_block_with_encoded(block, raw_block)
    }

    pub fn add_block_with_encoded(
        &mut self,
        block: Block,
        encoded_block: EncodedBlock,
    ) -> Result<BlockHeight, String> {
        if block.parent_hash != self.last_hash {
            return Err("Cannot apply block because its parent hash doesn't match.".to_string());
        }
        if block.timestamp < self.last_timestamp {
            return Err(
                "Cannot apply block because its timestamp is older than the previous tip."
                    .to_owned(),
            );
        }
        self.last_hash = Some(encoded_block.hash());
        self.last_timestamp = block.timestamp;
        self.blocks.push(encoded_block);
        Ok(self.chain_length().checked_sub(1).unwrap())
    }

    pub fn get(&self, height: BlockHeight) -> Option<&EncodedBlock> {
        if height < self.num_archived_blocks() {
            None
        } else {
            self.blocks
                .get(usize::try_from(height - self.num_archived_blocks()).unwrap())
        }
    }

    pub fn last(&self) -> Option<&EncodedBlock> {
        self.blocks.last()
    }

    pub fn num_archived_blocks(&self) -> u64 {
        self.num_archived_blocks
    }

    pub fn num_unarchived_blocks(&self) -> u64 {
        self.blocks.len() as u64
    }

    /// The range of block indices that are not archived yet.
    pub fn local_block_range(&self) -> std::ops::Range<u64> {
        self.num_archived_blocks..self.num_archived_blocks + self.blocks.len() as u64
    }

    pub fn chain_length(&self) -> BlockHeight {
        self.num_archived_blocks() + self.num_unarchived_blocks() as BlockHeight
    }

    pub fn remove_archived_blocks(&mut self, len: usize) {
        // redundant since split_off would panic, but here we can give a more
        // descriptive message
        if len > self.blocks.len() {
            panic!(
                "Asked to remove more blocks than present. Present: {}, to remove: {}",
                self.blocks.len(),
                len
            );
        }
        self.blocks = self.blocks.split_off(len);
        self.num_archived_blocks += len as u64;
    }

    pub fn get_blocks_for_archiving(
        &self,
        trigger_threshold: usize,
        num_blocks_to_archive: usize,
    ) -> VecDeque<EncodedBlock> {
        // Upon reaching the `trigger_threshold` we will archive
        // `num_blocks_to_archive`. For example, when set to (2000, 1000)
        // archiving will trigger when there are 2000 blocks in the ledger and
        // the 1000 oldest bocks will be archived, leaving the remaining 1000
        // blocks in place.
        let num_blocks_before = self.num_unarchived_blocks() as usize;

        if num_blocks_before < trigger_threshold {
            return VecDeque::new();
        }

        let blocks_to_archive: VecDeque<EncodedBlock> =
            VecDeque::from(self.blocks[0..num_blocks_to_archive.min(num_blocks_before)].to_vec());

        println!(
            "get_blocks_for_archiving(): trigger_threshold: {}, num_blocks: {}, blocks before archiving: {}, blocks to archive: {}",
            trigger_threshold,
            num_blocks_to_archive,
            num_blocks_before,
            blocks_to_archive.len(),
        );

        blocks_to_archive
    }
}

fn serialize_int_map<S>(im: &IntMap<()>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut map = serializer.serialize_map(Some(im.len()))?;
    for (k, v) in im.iter() {
        map.serialize_entry(k, v)?;
    }
    map.end()
}

struct IntMapVisitor<V> {
    marker: PhantomData<fn() -> IntMap<V>>,
}

impl<V> IntMapVisitor<V> {
    fn new() -> Self {
        IntMapVisitor {
            marker: PhantomData,
        }
    }
}

impl<'de, V> Visitor<'de> for IntMapVisitor<V>
where
    V: Deserialize<'de>,
{
    type Value = IntMap<V>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a very special map")
    }

    fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut map = IntMap::with_capacity(access.size_hint().unwrap_or(0));

        while let Some((key, value)) = access.next_entry()? {
            map.insert(key, value);
        }

        Ok(map)
    }
}

fn deserialize_int_map<'de, D>(deserializer: D) -> Result<IntMap<()>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_map(IntMapVisitor::new())
}

fn default_max_transactions_in_window() -> usize {
    Ledger::DEFAULT_MAX_TRANSACTIONS_IN_WINDOW
}

fn default_transfer_fee() -> Tokens {
    DEFAULT_TRANSFER_FEE
}

//this is only for deserialization from previous version of the ledger
fn unknown_token() -> String {
    "???".to_string()
}

#[derive(Serialize, Deserialize, CandidType, Clone, Debug, PartialEq, Eq)]
pub struct TransferFee {
    /// The fee to pay to perform a transfer
    pub transfer_fee: Tokens,
}

impl Default for TransferFee {
    fn default() -> Self {
        TransferFee {
            transfer_fee: DEFAULT_TRANSFER_FEE,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Ledger {
    pub balances: LedgerBalances,
    pub blockchain: Blockchain,
    // A cap on the maximum number of accounts
    pub maximum_number_of_accounts: usize,
    // When maximum number of accounts is exceeded, a specified number of
    // accounts with lowest balances are removed
    accounts_overflow_trim_quantity: usize,
    pub minting_account_id: Option<AccountIdentifier>,
    // This is a set of blockheights that have been notified
    #[serde(
        serialize_with = "serialize_int_map",
        deserialize_with = "deserialize_int_map",
        default = "IntMap::new"
    )]
    pub blocks_notified: IntMap<()>,
    /// How long transactions are remembered to detect duplicates.
    pub transaction_window: Duration,
    /// For each transaction, record the block in which the
    /// transaction was created. This only contains transactions from
    /// the last `transaction_window` period.
    transactions_by_hash: BTreeMap<HashOf<Transaction>, BlockHeight>,
    /// The transactions in the transaction window, sorted by block
    /// index / block timestamp. (Block timestamps are monotonically
    /// non-decreasing, so this is the same.)
    transactions_by_height: VecDeque<TransactionInfo>,
    /// Used to prevent non-whitelisted canisters from sending tokens
    send_whitelist: HashSet<CanisterId>,
    /// Maximum number of transactions which ledger will accept
    /// within the transaction_window.
    #[serde(default = "default_max_transactions_in_window")]
    max_transactions_in_window: usize,
    /// The fee to pay to perform a transfer
    #[serde(default = "default_transfer_fee")]
    pub transfer_fee: Tokens,

    /// Token symbol
    #[serde(default = "unknown_token")]
    pub token_symbol: String,
    /// Token name
    #[serde(default = "unknown_token")]
    pub token_name: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct TransactionInfo {
    block_timestamp: TimeStamp,
    transaction_hash: HashOf<Transaction>,
}

impl Default for Ledger {
    fn default() -> Self {
        Self {
            balances: LedgerBalances::default(),
            blockchain: Blockchain::default(),
            maximum_number_of_accounts: 28_000_000,
            accounts_overflow_trim_quantity: 100_000,
            minting_account_id: None,
            blocks_notified: IntMap::new(),
            transaction_window: Duration::from_secs(24 * 60 * 60),
            transactions_by_hash: BTreeMap::new(),
            transactions_by_height: VecDeque::new(),
            send_whitelist: HashSet::new(),
            max_transactions_in_window: Self::DEFAULT_MAX_TRANSACTIONS_IN_WINDOW,
            transfer_fee: DEFAULT_TRANSFER_FEE,
            token_symbol: unknown_token(),
            token_name: unknown_token(),
        }
    }
}

impl Ledger {
    /// The maximum number of transactions that we attempt to purge in one go.
    /// If there are many transactions in the buffer, purging them all in one go
    /// might require more instructions than one message execution allows.
    /// Hence, we purge old transactions incrementally, up to
    /// MAX_TRANSACTIONS_TO_PURGE at a time.
    const MAX_TRANSACTIONS_TO_PURGE: usize = 100_000;
    /// See Ledger::max_transactions_in_window
    const DEFAULT_MAX_TRANSACTIONS_IN_WINDOW: usize = 3_000_000;

    /// Returns true if the next transaction should be throttled due to high
    /// load on the ledger.
    fn throttle(&self, now: TimeStamp) -> bool {
        let num_in_window = self.transactions_by_height.len();
        // We admit the first half of max_transactions_in_window freely.
        // After that we start throttling on per-second basis.
        // This way we guarantee that at most max_transactions_in_window will
        // get through within the transaction window.
        if num_in_window >= self.max_transactions_in_window / 2 {
            // max num of transactions allowed per second
            let max_rate = (0.5 * self.max_transactions_in_window as f64
                / self.transaction_window.as_secs_f64())
            .ceil() as usize;

            if self
                .transactions_by_height
                .get(num_in_window.saturating_sub(max_rate))
                .map(|x| x.block_timestamp)
                .unwrap_or_else(|| TimeStamp::from_nanos_since_unix_epoch(0))
                + Duration::from_secs(1)
                > now
            {
                return true;
            }
        }
        false
    }

    /// This creates a block and adds it to the ledger
    pub fn add_payment(
        &mut self,
        memo: Memo,
        payment: Operation,
        created_at_time: Option<TimeStamp>,
    ) -> Result<(BlockHeight, HashOf<EncodedBlock>), PaymentError> {
        self.add_payment_with_timestamp(memo, payment, created_at_time, dfn_core::api::now().into())
    }

    /// Internal version of `add_payment` that takes a timestamp, for
    /// testing.
    fn add_payment_with_timestamp(
        &mut self,
        memo: Memo,
        payment: Operation,
        created_at_time: Option<TimeStamp>,
        now: TimeStamp,
    ) -> Result<(BlockHeight, HashOf<EncodedBlock>), PaymentError> {
        let num_pruned = self.purge_old_transactions(now);

        let created_at_time = created_at_time.unwrap_or(now);

        if created_at_time + self.transaction_window < now {
            return Err(PaymentError::TransferError(TransferError::TxTooOld {
                allowed_window_nanos: self.transaction_window.as_nanos() as u64,
            }));
        }

        if created_at_time > now + ic_constants::PERMITTED_DRIFT {
            return Err(PaymentError::TransferError(
                TransferError::TxCreatedInFuture,
            ));
        }

        // If we pruned some transactions, let this one through
        // otherwise throttle if there are too many
        if num_pruned == 0 && self.throttle(now) {
            return Err(PaymentError::Reject("Too many transactions in replay prevention window, ledger is throttling, please retry later".to_string()));
        }

        let transaction = Transaction {
            operation: payment.clone(),
            memo,
            created_at_time,
        };

        let transaction_hash = transaction.hash();

        if let Some(block_height) = self.transactions_by_hash.get(&transaction_hash) {
            return Err(PaymentError::TransferError(TransferError::TxDuplicate {
                duplicate_of: *block_height,
            }));
        }

        let block = Block::new_from_transaction(self.blockchain.last_hash, transaction, now);
        let block_timestamp = block.timestamp;

        self.balances.add_payment(&payment).map_err(|e| match e {
            BalanceError::InsufficientFunds { balance } => {
                PaymentError::TransferError(TransferError::InsufficientFunds { balance })
            }
        })?;

        let height = self
            .blockchain
            .add_block(block)
            .expect("failed to add block");

        self.transactions_by_hash.insert(transaction_hash, height);
        self.transactions_by_height.push_back(TransactionInfo {
            block_timestamp,
            transaction_hash,
        });

        let to_trim = if self.balances.store.len()
            >= self.maximum_number_of_accounts + self.accounts_overflow_trim_quantity
        {
            self.balances
                .select_accounts_to_trim(self.accounts_overflow_trim_quantity)
        } else {
            vec![]
        };

        for (balance, account) in to_trim {
            let operation = Operation::Burn {
                from: account,
                amount: balance,
            };
            self.balances
                .add_payment(&operation)
                .expect("failed to burn funds that must have existed");
            self.blockchain
                .add_block(Block::new_from_transaction(
                    self.blockchain.last_hash,
                    Transaction {
                        operation,
                        memo: Memo::default(),
                        created_at_time: now,
                    },
                    now,
                ))
                .unwrap();
        }

        Ok((height, self.blockchain.last_hash.unwrap()))
    }

    /// Removes at most [MAX_TRANSACTIONS_TO_PURGE] transactions older
    /// than `now - transaction_window` and returns the number of pruned
    /// transactions.
    fn purge_old_transactions(&mut self, now: TimeStamp) -> usize {
        let mut cnt = 0usize;
        while let Some(TransactionInfo {
            block_timestamp,
            transaction_hash,
        }) = self.transactions_by_height.front()
        {
            if *block_timestamp + self.transaction_window + ic_constants::PERMITTED_DRIFT >= now {
                // Stop at a sufficiently recent block.
                break;
            }
            let removed = self.transactions_by_hash.remove(transaction_hash);
            assert!(removed.is_some());

            // After 24 hours we don't need to store notification state because it isn't
            // accessible. We don't inspect the result because we don't care whether a
            // notification at this block height was made or not.
            match removed {
                Some(bh) => self.blocks_notified.remove(bh),
                None => None,
            };
            self.transactions_by_height.pop_front();
            cnt += 1;
            if cnt >= Self::MAX_TRANSACTIONS_TO_PURGE {
                break;
            }
        }
        cnt
    }

    /// This adds a pre created block to the ledger. This should only be used
    /// during canister migration or upgrade
    pub fn add_block(&mut self, block: Block) -> Result<BlockHeight, String> {
        self.balances
            .add_payment(&block.transaction.operation)
            .map_err(|e| format!("failed to execute transfer {:?}: {:?}", block, e))?;
        self.blockchain.add_block(block)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_init(
        &mut self,
        initial_values: HashMap<AccountIdentifier, Tokens>,
        minting_account: AccountIdentifier,
        timestamp: TimeStamp,
        transaction_window: Option<Duration>,
        send_whitelist: HashSet<CanisterId>,
        transfer_fee: Option<Tokens>,
        token_symbol: Option<String>,
        token_name: Option<String>,
    ) {
        self.token_symbol = token_symbol.unwrap_or_else(|| "ICP".to_string());
        self.token_name = token_name.unwrap_or_else(|| "Internet Computer".to_string());
        self.balances.token_pool = Tokens::MAX;
        self.minting_account_id = Some(minting_account);
        if let Some(t) = transaction_window {
            self.transaction_window = t;
        }

        for (to, amount) in initial_values.into_iter() {
            self.add_payment_with_timestamp(
                Memo::default(),
                Operation::Mint { to, amount },
                None,
                timestamp,
            )
            .expect(&format!("Creating account {:?} failed", to)[..]);
        }

        self.send_whitelist = send_whitelist;
        if let Some(transfer_fee) = transfer_fee {
            self.transfer_fee = transfer_fee;
        }
    }

    pub fn change_notification_state(
        &mut self,
        height: BlockHeight,
        block_timestamp: TimeStamp,
        new_state: bool,
        now: TimeStamp,
    ) -> Result<(), String> {
        if block_timestamp + self.transaction_window <= now {
            return Err(format!(
                "You cannot send a notification for a transaction that is more than {} seconds old",
                self.transaction_window.as_secs(),
            ));
        }

        let is_notified = self.blocks_notified.get(height).is_some();

        match (is_notified, new_state) {
            (true, true) | (false, false) => {
                Err(format!("The notification state is already {}", is_notified))
            }
            (true, false) => {
                self.blocks_notified.remove(height);
                Ok(())
            }
            (false, true) => {
                self.blocks_notified.insert(height, ());
                Ok(())
            }
        }
    }

    pub fn find_block_in_archive(&self, block_height: u64) -> Option<CanisterId> {
        let index = self
            .blockchain
            .archive
            .try_read()
            .expect("Failed to get lock on archive")
            .as_ref()
            .expect("archiving not enabled")
            .index();
        let result = index.binary_search_by(|((from, to), _)| {
            // If within the range we've found the right node
            if *from <= block_height && block_height <= *to {
                std::cmp::Ordering::Equal
            } else if *from < block_height {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Greater
            }
        });
        match result {
            Ok(i) => Some(index[i].1),
            Err(_) => None,
        }
    }

    pub fn remove_archived_blocks(&mut self, len: usize) {
        self.blockchain.remove_archived_blocks(len);
    }

    pub fn get_blocks_for_archiving(
        &self,
        trigger_threshold: usize,
        num_blocks: usize,
    ) -> VecDeque<EncodedBlock> {
        self.blockchain
            .get_blocks_for_archiving(trigger_threshold, num_blocks)
    }

    pub fn can_send(&self, principal_id: &PrincipalId) -> bool {
        !principal_id.is_anonymous()
    }

    /// Check if it's allowed to notify this canister
    /// Currently we reuse whitelist for that
    pub fn can_be_notified(&self, canister_id: &CanisterId) -> bool {
        LEDGER.read().unwrap().send_whitelist.contains(canister_id)
    }

    pub fn transactions_by_hash_len(&self) -> usize {
        self.transactions_by_hash.len()
    }

    pub fn transactions_by_height_len(&self) -> usize {
        self.transactions_by_height.len()
    }

    pub fn transfer_fee(&self) -> TransferFee {
        TransferFee {
            transfer_fee: self.transfer_fee,
        }
    }
}

lazy_static! {
    pub static ref LEDGER: RwLock<Ledger> = RwLock::new(Ledger::default());
    // Maximum inter-canister message size in bytes
    pub static ref MAX_MESSAGE_SIZE_BYTES: RwLock<usize> = RwLock::new(1024 * 1024);
}

pub fn add_payment(
    memo: Memo,
    payment: Operation,
    created_at_time: Option<TimeStamp>,
) -> (BlockHeight, HashOf<EncodedBlock>) {
    LEDGER
        .write()
        .unwrap()
        .add_payment(memo, payment, created_at_time)
        .expect("Transfer failed")
}

pub fn change_notification_state(
    height: BlockHeight,
    block_timestamp: TimeStamp,
    new_state: bool,
) -> Result<(), String> {
    LEDGER.write().unwrap().change_notification_state(
        height,
        block_timestamp,
        new_state,
        now().into(),
    )
}

// This is how we pass arguments to 'init' in main.rs
#[derive(Serialize, Deserialize, CandidType, Clone, Debug, PartialEq, Eq)]
pub struct LedgerCanisterInitPayload {
    pub minting_account: AccountIdentifier,
    pub initial_values: HashMap<AccountIdentifier, Tokens>,
    pub max_message_size_bytes: Option<usize>,
    pub transaction_window: Option<Duration>,
    pub archive_options: Option<ArchiveOptions>,
    pub send_whitelist: HashSet<CanisterId>,
    pub transfer_fee: Option<Tokens>,
    pub token_symbol: Option<String>,
    pub token_name: Option<String>,
}

impl LedgerCanisterInitPayload {
    pub fn builder() -> LedgerCanisterInitPayloadBuilder {
        LedgerCanisterInitPayloadBuilder::new()
    }
}

pub struct LedgerCanisterInitPayloadBuilder {
    minting_account: Option<AccountIdentifier>,
    initial_values: HashMap<AccountIdentifier, Tokens>,
    max_message_size_bytes: Option<usize>,
    transaction_window: Option<Duration>,
    archive_options: Option<ArchiveOptions>,
    send_whitelist: HashSet<CanisterId>,
    transfer_fee: Option<Tokens>,
    token_symbol: Option<String>,
    token_name: Option<String>,
}

impl LedgerCanisterInitPayloadBuilder {
    fn new() -> Self {
        Self {
            minting_account: None,
            initial_values: Default::default(),
            max_message_size_bytes: None,
            transaction_window: None,
            archive_options: None,
            send_whitelist: Default::default(),
            transfer_fee: None,
            token_symbol: None,
            token_name: None,
        }
    }

    pub fn minting_account(mut self, minting_account: AccountIdentifier) -> Self {
        self.minting_account = Some(minting_account);
        self
    }

    pub fn initial_values(mut self, initial_values: HashMap<AccountIdentifier, Tokens>) -> Self {
        self.initial_values = initial_values;
        self
    }

    pub fn max_message_size_bytes(mut self, max_message_size_bytes: usize) -> Self {
        self.max_message_size_bytes = Some(max_message_size_bytes);
        self
    }

    pub fn transaction_window(mut self, transaction_window: Duration) -> Self {
        self.transaction_window = Some(transaction_window);
        self
    }

    pub fn archive_options(mut self, archive_options: ArchiveOptions) -> Self {
        self.archive_options = Some(archive_options);
        self
    }

    pub fn send_whitelist(mut self, send_whitelist: HashSet<CanisterId>) -> Self {
        self.send_whitelist = send_whitelist;
        self
    }

    pub fn transfer_fee(mut self, transfer_fee: Tokens) -> Self {
        self.transfer_fee = Some(transfer_fee);
        self
    }

    pub fn token_symbol_and_name(mut self, token_symbol: &str, token_name: &str) -> Self {
        self.token_symbol = Some(token_symbol.to_string());
        self.token_name = Some(token_name.to_string());
        self
    }

    pub fn build(self) -> Result<LedgerCanisterInitPayload, String> {
        let minting_account = self
            .minting_account
            .ok_or("minting_account must be set in the payload")?;

        // verify ledger's invariant about the maximum amount
        let mut sum = Tokens::ZERO;
        for initial_value in self.initial_values.values() {
            sum = (sum + *initial_value).map_err(|_| "initial_values sum overflows".to_string())?
        }

        // Don't allow self-transfers of the minting canister
        if self.initial_values.get(&minting_account).is_some() {
            return Err(
                "initial_values cannot contain transfers to the minting_account".to_string(),
            );
        }

        Ok(LedgerCanisterInitPayload {
            minting_account,
            initial_values: self.initial_values,
            max_message_size_bytes: self.max_message_size_bytes,
            transaction_window: self.transaction_window,
            archive_options: self.archive_options,
            send_whitelist: self.send_whitelist,
            transfer_fee: self.transfer_fee,
            token_symbol: self.token_symbol,
            token_name: self.token_name,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    #[test]
    fn balances_overflow() {
        let balances = LedgerBalances::new();
        let mut state = Ledger {
            balances,
            maximum_number_of_accounts: 8,
            accounts_overflow_trim_quantity: 2,
            minting_account_id: Some(PrincipalId::new_user_test_id(137).into()),
            ..Default::default()
        };
        assert_eq!(state.balances.token_pool, Tokens::MAX);
        println!(
            "minting canister initial balance: {}",
            state.balances.token_pool
        );
        let mut credited = Tokens::ZERO;

        // 11 accounts. The one with 0 will not be added
        // The rest will be added and trigger a trim of 2 once
        // the total number reaches 8 + 2
        // the number of active accounts won't go below 8 after trimming
        for i in 0..11 {
            let amount = Tokens::new(i, 0).unwrap();
            state
                .add_payment(
                    Memo::default(),
                    Operation::Mint {
                        to: PrincipalId::new_user_test_id(i).into(),
                        amount,
                    },
                    None,
                )
                .unwrap();
            credited += amount
        }
        println!("amount credited to accounts: {}", credited);

        println!("balances: {:?}", state.balances);

        // The two accounts with lowest balances, 0 and 1 respectively, have been
        // removed
        assert_eq!(state.balances.store.len(), 8);
        assert_eq!(
            state
                .balances
                .account_balance(&PrincipalId::new_user_test_id(0).into()),
            Tokens::ZERO
        );
        assert_eq!(
            state
                .balances
                .account_balance(&PrincipalId::new_user_test_id(1).into()),
            Tokens::ZERO
        );
        // We have credited 55 Tokens to various accounts but the three accounts
        // with lowest balances, 0, 1 and 2, should have been removed and their
        // balance returned to the minting canister
        let expected_minting_canister_balance =
            ((Tokens::MAX - credited).unwrap() + Tokens::new(1 + 2, 0).unwrap()).unwrap();
        assert_eq!(state.balances.token_pool, expected_minting_canister_balance);
    }

    #[test]
    fn balances_remove_accounts_with_zero_balance() {
        let mut b = LedgerBalances::new();
        let canister = CanisterId::from_u64(7).get().into();
        let target_canister = CanisterId::from_u64(13).into();
        b.add_payment(&Operation::Mint {
            to: canister,
            amount: Tokens::from_e8s(1000),
        })
        .unwrap();
        // verify that an account entry exists for the `canister`
        assert_eq!(b.store.get(&canister), Some(&Tokens::from_e8s(1000)));
        // make 2 transfers that empty the account
        for _ in 0..2 {
            b.add_payment(&Operation::Transfer {
                from: canister,
                to: target_canister,
                amount: Tokens::from_e8s(400),
                fee: Tokens::from_e8s(100),
            })
            .unwrap();
        }
        // target canister's balance adds up
        assert_eq!(b.store.get(&target_canister), Some(&Tokens::from_e8s(800)));
        // source canister has been removed
        assert_eq!(b.store.get(&canister), None);
        assert_eq!(b.account_balance(&canister), Tokens::ZERO);

        // one account left in the store
        assert_eq!(b.store.len(), 1);

        b.add_payment(&Operation::Transfer {
            from: target_canister,
            to: canister,
            amount: Tokens::from_e8s(0),
            fee: Tokens::from_e8s(100),
        })
        .unwrap();
        // No new account should have been created
        assert_eq!(b.store.len(), 1);
        // and the fee should have been taken from sender
        assert_eq!(b.store.get(&target_canister), Some(&Tokens::from_e8s(700)));

        b.add_payment(&Operation::Mint {
            to: canister,
            amount: Tokens::from_e8s(0),
        })
        .unwrap();

        // No new account should have been created
        assert_eq!(b.store.len(), 1);

        b.add_payment(&Operation::Burn {
            from: target_canister,
            amount: Tokens::from_e8s(700),
        })
        .unwrap();

        // And burn should have exhausted the target_canister
        assert_eq!(b.store.len(), 0);
    }

    #[test]
    fn balances_fee() {
        let mut b = LedgerBalances::new();
        let pool_start_balance = b.token_pool.get_e8s();
        let uid0 = PrincipalId::new_user_test_id(1000).into();
        let uid1 = PrincipalId::new_user_test_id(1007).into();
        let mint_amount = 1000000;
        let send_amount = 10000;
        let send_fee = 100;

        b.add_payment(&Operation::Mint {
            to: uid0,
            amount: Tokens::from_e8s(mint_amount),
        })
        .unwrap();
        assert_eq!(b.token_pool.get_e8s(), pool_start_balance - mint_amount);
        assert_eq!(b.account_balance(&uid0).get_e8s(), mint_amount);

        b.add_payment(&Operation::Transfer {
            from: uid0,
            to: uid1,
            amount: Tokens::from_e8s(send_amount),
            fee: Tokens::from_e8s(send_fee),
        })
        .unwrap();

        assert_eq!(
            b.token_pool.get_e8s(),
            pool_start_balance - mint_amount + send_fee
        );
        assert_eq!(
            b.account_balance(&uid0).get_e8s(),
            mint_amount - send_amount - send_fee
        );
        assert_eq!(b.account_balance(&uid1).get_e8s(), send_amount);
    }

    #[test]
    fn serialize() {
        let mut state = Ledger::default();

        state.from_init(
            vec![(
                PrincipalId::new_user_test_id(0).into(),
                Tokens::new(2000000, 0).unwrap(),
            )]
            .into_iter()
            .collect(),
            PrincipalId::new_user_test_id(1000).into(),
            SystemTime::UNIX_EPOCH.into(),
            None,
            HashSet::new(),
            None,
            Some("ICP".into()),
            Some("icp".into()),
        );

        let txn = Transaction::new(
            PrincipalId::new_user_test_id(0).into(),
            PrincipalId::new_user_test_id(1).into(),
            Tokens::new(10000, 50).unwrap(),
            state.transfer_fee,
            Memo(456),
            TimeStamp::new(1, 0),
        );

        let block = Block {
            parent_hash: state.blockchain.last_hash,
            transaction: txn,
            timestamp: (SystemTime::UNIX_EPOCH + Duration::new(2000000000, 123456789)).into(),
        };

        let block_bytes = block.clone().encode().unwrap();
        println!("block bytes = {:02x?}", block_bytes.0);
        let block_hash = block_bytes.hash();
        println!("block hash = {}", block_hash);
        let block_decoded = block_bytes.decode().unwrap();
        println!("block decoded = {:#?}", block_decoded);

        let block_decoded = block_bytes.decode().unwrap();
        assert_eq!(block, block_decoded);

        state.add_block(block).unwrap();

        let txn2 = Transaction::new(
            PrincipalId::new_user_test_id(0).into(),
            PrincipalId::new_user_test_id(200).into(),
            Tokens::new(30000, 10000).unwrap(),
            state.transfer_fee,
            Memo(0),
            TimeStamp::new(1, 100),
        );

        let block2 = Block {
            parent_hash: Some(block_hash),
            transaction: txn2,
            timestamp: (SystemTime::UNIX_EPOCH + Duration::new(2000000000, 123456790)).into(),
        };

        state.add_block(block2).unwrap();

        let state_bytes = serde_cbor::to_vec(&state).unwrap();

        let state_decoded: Ledger = serde_cbor::from_slice(&state_bytes).unwrap();

        assert_eq!(
            state.blockchain.chain_length(),
            state_decoded.blockchain.chain_length()
        );
        assert_eq!(
            state.blockchain.last_hash,
            state_decoded.blockchain.last_hash
        );
        assert_eq!(
            state.blockchain.blocks.len(),
            state_decoded.blockchain.blocks.len()
        );
        assert_eq!(state.balances.store, state_decoded.balances.store);
    }

    /// Check that 'created_at_time' is not too far in the past or
    /// future.
    #[test]
    fn bad_created_at_time() {
        let mut state = Ledger::default();

        let user1 = PrincipalId::new_user_test_id(1).into();

        let transfer = Operation::Mint {
            to: user1,
            amount: Tokens::from_e8s(1000),
        };

        let now = dfn_core::api::now().into();

        assert_eq!(
            PaymentError::TransferError(TransferError::TxTooOld {
                allowed_window_nanos: Duration::from_secs(24 * 60 * 60).as_nanos() as u64,
            }),
            state
                .add_payment(
                    Memo(1),
                    transfer.clone(),
                    Some(now - state.transaction_window - Duration::from_secs(1))
                )
                .unwrap_err()
        );

        state
            .add_payment(
                Memo(2),
                transfer.clone(),
                Some(now - Duration::from_secs(1)),
            )
            .unwrap();

        assert_eq!(
            PaymentError::TransferError(TransferError::TxCreatedInFuture),
            state
                .add_payment(
                    Memo(3),
                    transfer.clone(),
                    Some(now + Duration::from_secs(120))
                )
                .unwrap_err()
        );

        state.add_payment(Memo(4), transfer, Some(now)).unwrap();
    }

    /// Check that block timestamps don't go backwards.
    #[test]
    #[should_panic(expected = "timestamp is older")]
    fn monotonic_timestamps() {
        let mut state = Ledger::default();

        let user1 = PrincipalId::new_user_test_id(1).into();

        let transfer = Operation::Mint {
            to: user1,
            amount: Tokens::from_e8s(1000),
        };

        state.add_payment(Memo(1), transfer.clone(), None).unwrap();

        state.add_payment(Memo(2), transfer.clone(), None).unwrap();

        state
            .add_payment_with_timestamp(
                Memo(2),
                transfer,
                None,
                state.blockchain.last_timestamp - Duration::from_secs(1),
            )
            .unwrap();
    }

    /// Check that duplicate transactions during transaction_window
    /// are rejected.
    #[test]
    fn duplicate_txns() {
        let mut state = Ledger::default();

        state.blockchain.archive =
            Arc::new(RwLock::new(Some(archive::Archive::new(ArchiveOptions {
                trigger_threshold: 2000,
                num_blocks_to_archive: 1000,
                node_max_memory_size_bytes: None,
                max_message_size_bytes: None,
                controller_id: CanisterId::from_u64(876),
                cycles_for_archive_creation: Some(0),
            }))));

        let user1 = PrincipalId::new_user_test_id(1).into();

        let transfer = Operation::Mint {
            to: user1,
            amount: Tokens::from_e8s(1000),
        };

        let now = dfn_core::api::now().into();

        assert_eq!(
            state
                .add_payment(Memo::default(), transfer.clone(), Some(now))
                .unwrap()
                .0,
            0
        );

        assert_eq!(
            state
                .add_payment(Memo(123), transfer.clone(), Some(now))
                .unwrap()
                .0,
            1
        );

        assert_eq!(
            state
                .add_payment(
                    Memo::default(),
                    transfer.clone(),
                    Some(now - Duration::from_secs(1))
                )
                .unwrap()
                .0,
            2
        );

        assert_eq!(
            state
                .add_payment_with_timestamp(
                    Memo::default(),
                    transfer.clone(),
                    Some(now - Duration::from_secs(2)),
                    state.blockchain.last_timestamp + Duration::from_secs(10000)
                )
                .unwrap()
                .0,
            3
        );

        assert_eq!(
            PaymentError::TransferError(TransferError::TxDuplicate { duplicate_of: 0 }),
            state
                .add_payment(Memo::default(), transfer.clone(), Some(now))
                .unwrap_err()
        );

        // A day later we should have forgotten about these transactions.
        let t = state.blockchain.last_timestamp + Duration::from_secs(1);
        assert_eq!(
            state
                .add_payment_with_timestamp(
                    Memo::default(),
                    transfer.clone(),
                    Some(t),
                    state.blockchain.last_timestamp + state.transaction_window
                )
                .unwrap()
                .0,
            4
        );

        assert_eq!(
            PaymentError::TransferError(TransferError::TxDuplicate { duplicate_of: 4 }),
            state
                .add_payment_with_timestamp(
                    Memo::default(),
                    transfer.clone(),
                    Some(t),
                    state.blockchain.last_timestamp + Duration::from_secs(1),
                )
                .unwrap_err()
        );

        // Corner case 1 -- attempts which are transaction_window apart from each other
        let t = state.blockchain.last_timestamp + Duration::from_secs(100);

        assert_eq!(
            state
                .add_payment_with_timestamp(Memo::default(), transfer.clone(), Some(t), t)
                .unwrap()
                .0,
            5
        );

        assert_eq!(
            PaymentError::TransferError(TransferError::TxDuplicate { duplicate_of: 5 }),
            state
                .add_payment_with_timestamp(
                    Memo::default(),
                    transfer.clone(),
                    Some(t),
                    t + state.transaction_window,
                )
                .unwrap_err()
        );

        // Corner case 2 -- attempts which are transaction_window + drift apart from
        // each other
        let t = state.blockchain.last_timestamp + Duration::from_secs(200);
        let drift = ic_constants::PERMITTED_DRIFT;

        assert_eq!(
            PaymentError::TransferError(TransferError::TxCreatedInFuture),
            state
                .add_payment_with_timestamp(
                    Memo::default(),
                    transfer.clone(),
                    Some(t),
                    t - (drift + Duration::from_nanos(1)),
                )
                .unwrap_err()
        );

        assert_eq!(
            state
                .add_payment_with_timestamp(Memo::default(), transfer.clone(), Some(t), t - drift)
                .unwrap()
                .0,
            6
        );

        assert_eq!(
            PaymentError::TransferError(TransferError::TxDuplicate { duplicate_of: 6 }),
            state
                .add_payment_with_timestamp(
                    Memo::default(),
                    transfer.clone(),
                    Some(t),
                    t + state.transaction_window,
                )
                .unwrap_err()
        );

        assert_eq!(
            PaymentError::TransferError(TransferError::TxTooOld {
                allowed_window_nanos: state.transaction_window.as_nanos() as u64,
            }),
            state
                .add_payment_with_timestamp(
                    Memo::default(),
                    transfer,
                    Some(t),
                    t + state.transaction_window + Duration::from_nanos(1),
                )
                .unwrap_err()
        );
    }

    #[test]
    fn get_blocks_returns_correct_blocks() {
        let mut state = Ledger::default();

        state.from_init(
            vec![(
                PrincipalId::new_user_test_id(0).into(),
                Tokens::new(1000000, 0).unwrap(),
            )]
            .into_iter()
            .collect(),
            PrincipalId::new_user_test_id(1000).into(),
            SystemTime::UNIX_EPOCH.into(),
            None,
            HashSet::new(),
            None,
            Some("ICP".into()),
            Some("icp".into()),
        );

        for i in 0..10 {
            let txn = Transaction::new(
                PrincipalId::new_user_test_id(0).into(),
                PrincipalId::new_user_test_id(1).into(),
                Tokens::new(1, 0).unwrap(),
                state.transfer_fee,
                Memo(i),
                TimeStamp::new(1, 0),
            );

            let block = Block {
                parent_hash: state.blockchain.last_hash,
                transaction: txn,
                timestamp: (SystemTime::UNIX_EPOCH + Duration::new(1, 0)).into(),
            };

            state.add_block(block).unwrap();
        }

        let blocks = &state.blockchain.blocks;

        let first_blocks = super::get_blocks(blocks, 0, 1, 5).0.unwrap();
        for i in 0..first_blocks.len() {
            let block = first_blocks.get(i).unwrap().decode().unwrap();
            assert_eq!(block.transaction.memo.0, i as u64);
        }

        let last_blocks = super::get_blocks(blocks, 0, 6, 5).0.unwrap();
        for i in 0..last_blocks.len() {
            let block = last_blocks.get(i).unwrap().decode().unwrap();
            assert_eq!(block.transaction.memo.0, 5 + i as u64);
        }
    }

    #[test]
    fn test_purge() {
        let mut ledger = Ledger::default();
        let genesis = SystemTime::now().into();
        ledger.from_init(
            vec![
                (
                    PrincipalId::new_user_test_id(0).into(),
                    Tokens::new(1, 0).unwrap(),
                ),
                (
                    PrincipalId::new_user_test_id(1).into(),
                    Tokens::new(1, 0).unwrap(),
                ),
            ]
            .into_iter()
            .collect(),
            PrincipalId::new_user_test_id(1000).into(),
            genesis,
            Some(Duration::from_millis(10)),
            HashSet::new(),
            None,
            Some("ICP".into()),
            Some("icp".into()),
        );
        let little_later = genesis + Duration::from_millis(1);

        let res1 = ledger.change_notification_state(1, genesis, true, little_later);
        assert_eq!(res1, Ok(()), "The first notification succeeds");

        let res2 = ledger.blocks_notified.get(1);
        assert_eq!(res2, Some(&()), "You can see the lock in the store");

        ledger.purge_old_transactions(genesis);

        let res2 = ledger.blocks_notified.get(1);
        assert_eq!(
            res2,
            Some(&()),
            "A purge before the end of the window doesn't remove the notification"
        );

        let later = genesis + Duration::from_secs(10) + ic_constants::PERMITTED_DRIFT;
        ledger.purge_old_transactions(later);

        let res3 = ledger.blocks_notified.get(1);
        assert_eq!(res3, None, "A purge afterwards does");

        let res4 = ledger.blocks_notified.get(2);
        assert_eq!(res4, None);

        let res5 = ledger.change_notification_state(1, genesis, true, later);
        assert!(res5.unwrap_err().contains("that is more than"));

        let res5 = ledger.change_notification_state(1, genesis, false, later);
        assert!(res5.unwrap_err().contains("that is more than"));

        let res5 = ledger.change_notification_state(2, genesis, true, later);
        assert!(res5.unwrap_err().contains("that is more than"));

        let res6 = ledger.blocks_notified.get(2);
        assert_eq!(res6, None);
    }

    fn apply_at(ledger: &mut Ledger, op: &Operation, ts: TimeStamp) -> BlockHeight {
        let memo = Memo::default();
        ledger
            .add_payment_with_timestamp(memo, op.clone(), None, ts)
            .unwrap_or_else(|e| {
                panic!(
                    "Failed to execute operation {:?} with memo {:?} at {:?}: {:?}",
                    op, memo, ts, e
                )
            })
            .0
    }

    #[test]
    #[should_panic(expected = "Too many transactions")]
    fn test_throttle_tx_per_second_nok() {
        let millis = Duration::from_millis;

        let mut ledger = Ledger {
            transaction_window: millis(2000),
            max_transactions_in_window: 2,
            ..Ledger::default()
        };

        let op = Operation::Mint {
            to: PrincipalId::new_user_test_id(1).into(),
            amount: Tokens::from_e8s(1000),
        };

        let now: TimeStamp = dfn_core::api::now().into();

        assert_eq!(apply_at(&mut ledger, &op, now + millis(1)), 0);
        assert_eq!(apply_at(&mut ledger, &op, now + millis(1002)), 1);

        // expecting panic here
        apply_at(&mut ledger, &op, now + millis(1003));
    }

    #[test]
    fn test_throttle_tx_per_second_ok() {
        let millis = Duration::from_millis;

        let mut ledger = Ledger {
            transaction_window: millis(2000),
            max_transactions_in_window: 2,
            ..Ledger::default()
        };

        let op = Operation::Mint {
            to: PrincipalId::new_user_test_id(1).into(),
            amount: Tokens::from_e8s(1000),
        };
        let now: TimeStamp = dfn_core::api::now().into();

        assert_eq!(apply_at(&mut ledger, &op, now + millis(1)), 0);
        assert_eq!(apply_at(&mut ledger, &op, now + millis(1002)), 1);
        assert_eq!(apply_at(&mut ledger, &op, now + millis(2003)), 2);
    }

    #[test]
    fn test_throttle_two_tx_per_second_after_soft_limit_ok() {
        let millis = Duration::from_millis;

        let mut ledger = Ledger {
            transaction_window: millis(2000),
            max_transactions_in_window: 8,
            ..Ledger::default()
        };

        let op = Operation::Mint {
            to: PrincipalId::new_user_test_id(1).into(),
            amount: Tokens::from_e8s(1000),
        };
        let now: TimeStamp = dfn_core::api::now().into();

        assert_eq!(apply_at(&mut ledger, &op, now + millis(1)), 0);
        assert_eq!(apply_at(&mut ledger, &op, now + millis(2)), 1);
        assert_eq!(apply_at(&mut ledger, &op, now + millis(3)), 2);
        assert_eq!(apply_at(&mut ledger, &op, now + millis(4)), 3);
        assert_eq!(apply_at(&mut ledger, &op, now + millis(1005)), 4);
        assert_eq!(apply_at(&mut ledger, &op, now + millis(1006)), 5);
        assert_eq!(apply_at(&mut ledger, &op, now + millis(2007)), 6);
        assert_eq!(apply_at(&mut ledger, &op, now + millis(3008)), 7);
    }

    #[test]
    #[should_panic(expected = "Too many transactions")]
    fn test_throttle_two_tx_per_second_after_soft_limit_nok() {
        let millis = Duration::from_millis;

        let mut ledger = Ledger {
            transaction_window: millis(2000),
            max_transactions_in_window: 8,
            ..Ledger::default()
        };

        let op = Operation::Mint {
            to: PrincipalId::new_user_test_id(1).into(),
            amount: Tokens::from_e8s(1000),
        };
        let now: TimeStamp = dfn_core::api::now().into();

        assert_eq!(apply_at(&mut ledger, &op, now + millis(1)), 0);
        assert_eq!(apply_at(&mut ledger, &op, now + millis(2)), 1);
        assert_eq!(apply_at(&mut ledger, &op, now + millis(3)), 2);
        assert_eq!(apply_at(&mut ledger, &op, now + millis(4)), 3);
        assert_eq!(apply_at(&mut ledger, &op, now + millis(1005)), 4);
        assert_eq!(apply_at(&mut ledger, &op, now + millis(1006)), 5);
        // expecting panic here
        apply_at(&mut ledger, &op, now + millis(1007));
    }

    /// Verify consistency of transaction hash after renaming transfer to
    /// operation (see NNS1-765).
    #[test]
    fn test_transaction_hash_consistency() {
        let transaction = Transaction::new(
            PrincipalId::new_user_test_id(0).into(),
            PrincipalId::new_user_test_id(1).into(),
            Tokens::new(1, 0).unwrap(),
            DEFAULT_TRANSFER_FEE,
            Memo(123456),
            TimeStamp::new(1, 0),
        );
        let transaction_hash = transaction.hash();
        // panic!("Transaction hash: {}",transaction_hash);
        let hash_string = hex::encode(transaction_hash.inner.get());
        assert_eq!(
            hash_string, "f39130181586ea3d166185104114d7697d1e18af4f65209a53627f39b2fa0996",
            "Transaction hash must be stable."
        );
    }
}

/// Argument taken by the send endpoint
#[derive(Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq)]
pub struct SendArgs {
    pub memo: Memo,
    pub amount: Tokens,
    pub fee: Tokens,
    pub from_subaccount: Option<Subaccount>,
    pub to: AccountIdentifier,
    pub created_at_time: Option<TimeStamp>,
}

impl From<SendArgs> for TransferArgs {
    fn from(
        SendArgs {
            memo,
            amount,
            fee,
            from_subaccount,
            to,
            created_at_time,
        }: SendArgs,
    ) -> Self {
        Self {
            memo,
            amount,
            fee,
            from_subaccount,
            to: to.to_address(),
            created_at_time,
        }
    }
}

pub type AccountIdBlob = [u8; 32];

/// Argument taken by the transfer endpoint
#[derive(Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq)]
pub struct TransferArgs {
    pub memo: Memo,
    pub amount: Tokens,
    pub fee: Tokens,
    pub from_subaccount: Option<Subaccount>,
    pub to: AccountIdBlob,
    pub created_at_time: Option<TimeStamp>,
}

#[derive(Serialize, Deserialize, CandidType, Clone, Debug, PartialEq, Eq)]
pub enum TransferError {
    BadFee { expected_fee: Tokens },
    InsufficientFunds { balance: Tokens },
    TxTooOld { allowed_window_nanos: u64 },
    TxCreatedInFuture,
    TxDuplicate { duplicate_of: BlockHeight },
}

impl fmt::Display for TransferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadFee { expected_fee } => {
                write!(f, "transfer fee should be {}", expected_fee)
            }
            Self::InsufficientFunds { balance } => {
                write!(
                    f,
                    "the debit account doesn't have enough funds to complete the transaction, current balance: {}",
                    balance
                )
            }
            Self::TxTooOld {
                allowed_window_nanos,
            } => write!(
                f,
                "transaction is older than {} seconds",
                allowed_window_nanos / 1_000_000_000
            ),
            Self::TxCreatedInFuture => write!(f, "transaction's created_at_time is in future"),
            Self::TxDuplicate { duplicate_of } => write!(
                f,
                "transaction is a duplicate of another transaction in block {}",
                duplicate_of
            ),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum PaymentError {
    Reject(String),
    TransferError(TransferError),
}

/// Struct sent by the ledger canister when it notifies a recipient of a payment
#[derive(Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq)]
pub struct TransactionNotification {
    pub from: PrincipalId,
    pub from_subaccount: Option<Subaccount>,
    pub to: CanisterId,
    pub to_subaccount: Option<Subaccount>,
    pub block_height: BlockHeight,
    pub amount: Tokens,
    pub memo: Memo,
}

/// Argument taken by the notification endpoint
#[derive(Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq)]
pub struct NotifyCanisterArgs {
    pub block_height: BlockHeight,
    pub max_fee: Tokens,
    pub from_subaccount: Option<Subaccount>,
    pub to_canister: CanisterId,
    pub to_subaccount: Option<Subaccount>,
}

impl NotifyCanisterArgs {
    /// Construct a `notify` call to notify a canister about the
    /// transaction created by a previous `send` call. `block_height`
    /// is the index of the block returned by `send`.
    pub fn new_from_send(
        send_args: &SendArgs,
        block_height: BlockHeight,
        to_canister: CanisterId,
        to_subaccount: Option<Subaccount>,
    ) -> Result<Self, String> {
        if AccountIdentifier::new(to_canister.get(), to_subaccount) != send_args.to {
            Err("Account identifier does not match canister args".to_string())
        } else {
            Ok(NotifyCanisterArgs {
                block_height,
                max_fee: send_args.fee,
                from_subaccount: send_args.from_subaccount,
                to_canister,
                to_subaccount,
            })
        }
    }
}

/// Arguments taken by the account_balance candid endpoint.
#[derive(Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq)]
pub struct BinaryAccountBalanceArgs {
    pub account: AccountIdBlob,
}

/// Argument taken by the account_balance_dfx endpoint
#[derive(Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq)]
pub struct AccountBalanceArgs {
    pub account: AccountIdentifier,
}

impl AccountBalanceArgs {
    pub fn new(account: AccountIdentifier) -> Self {
        AccountBalanceArgs { account }
    }
}

/// An operation which modifies account balances
#[derive(
    Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq, PartialOrd, Ord,
)]
pub enum CandidOperation {
    Burn {
        from: AccountIdBlob,
        amount: Tokens,
    },
    Mint {
        to: AccountIdBlob,
        amount: Tokens,
    },
    Transfer {
        from: AccountIdBlob,
        to: AccountIdBlob,
        amount: Tokens,
        fee: Tokens,
    },
}

impl From<Operation> for CandidOperation {
    fn from(op: Operation) -> Self {
        match op {
            Operation::Burn { from, amount } => Self::Burn {
                from: from.to_address(),
                amount,
            },
            Operation::Mint { to, amount } => Self::Mint {
                to: to.to_address(),
                amount,
            },
            Operation::Transfer {
                from,
                to,
                amount,
                fee,
            } => Self::Transfer {
                from: from.to_address(),
                to: to.to_address(),
                amount,
                fee,
            },
        }
    }
}

/// An operation with the metadata the client generated attached to it
#[derive(
    Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq, PartialOrd, Ord,
)]
pub struct CandidTransaction {
    pub operation: CandidOperation,
    pub memo: Memo,
    pub created_at_time: TimeStamp,
}

impl From<Transaction> for CandidTransaction {
    fn from(
        Transaction {
            operation,
            memo,
            created_at_time,
        }: Transaction,
    ) -> Self {
        Self {
            memo,
            operation: operation.into(),
            created_at_time,
        }
    }
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CandidBlock {
    pub parent_hash: Option<[u8; HASH_LENGTH]>,
    pub transaction: CandidTransaction,
    pub timestamp: TimeStamp,
}

impl From<Block> for CandidBlock {
    fn from(
        Block {
            parent_hash,
            transaction,
            timestamp,
        }: Block,
    ) -> Self {
        Self {
            parent_hash: parent_hash.map(|h| h.into_bytes()),
            transaction: transaction.into(),
            timestamp,
        }
    }
}

/// Argument taken by the transfer fee endpoint
///
/// The reason it is a struct is so that it can be extended -- e.g., to be able
/// to query past values. Requiring 1 candid value instead of zero is a
/// non-backward compatible change. But adding optional fields to a struct taken
/// as input is backward-compatible.
#[derive(Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq)]
pub struct TransferFeeArgs {}

/// Argument taken by the total_supply endpoint
///
/// The reason it is a struct is so that it can be extended -- e.g., to be able
/// to query past values. Requiring 1 candid value instead of zero is a
/// non-backward compatible change. But adding optional fields to a struct taken
/// as input is backward-compatible.
#[derive(Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq)]
pub struct TotalSupplyArgs {}

#[derive(Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq)]
pub struct Symbol {
    pub symbol: String,
}

#[derive(Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq)]
pub struct Name {
    pub name: String,
}

#[derive(Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq)]
pub struct Decimals {
    pub decimals: u32,
}

#[derive(Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq)]
pub struct ArchiveInfo {
    pub canister_id: CanisterId,
}

#[derive(Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq)]
pub struct Archives {
    pub archives: Vec<ArchiveInfo>,
}

/// Argument returned by the tip_of_chain endpoint
pub struct TipOfChainRes {
    pub certification: Option<Vec<u8>>,
    pub tip_index: BlockHeight,
}

#[derive(Serialize, Deserialize, CandidType)]
pub struct GetBlocksArgs {
    pub start: BlockHeight,
    pub length: usize,
}

#[derive(Serialize, Deserialize, CandidType, Debug)]
pub struct BlockRange {
    pub blocks: Vec<CandidBlock>,
}

pub type GetBlocksResult = Result<BlockRange, GetBlocksError>;

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, CandidType)]
pub enum GetBlocksError {
    BadFirstBlockIndex {
        requested_index: BlockHeight,
        first_valid_index: BlockHeight,
    },
    Other {
        error_code: u64,
        error_message: String,
    },
}

pub struct GetBlocksRes(pub Result<Vec<EncodedBlock>, String>);

pub struct IterBlocksArgs {
    pub start: usize,
    pub length: usize,
}

impl IterBlocksArgs {
    pub fn new(start: usize, length: usize) -> Self {
        IterBlocksArgs { start, length }
    }
}

pub struct IterBlocksRes(pub Vec<EncodedBlock>);

// These is going away soon
pub struct BlockArg(pub BlockHeight);
pub struct BlockRes(pub Option<Result<EncodedBlock, CanisterId>>);

// A helper function for ledger/get_blocks and archive_node/get_blocks endpoints
pub fn get_blocks(
    blocks: &[EncodedBlock],
    range_from_offset: BlockHeight,
    range_from: BlockHeight,
    length: usize,
) -> GetBlocksRes {
    // Inclusive end of the range of *requested* blocks
    let requested_range_to = range_from as usize + length - 1;
    // Inclusive end of the range of *available* blocks
    let range_to = range_from_offset as usize + blocks.len() - 1;
    // Example: If the Node stores 10 blocks beginning at BlockHeight 100, i.e.
    // [100 .. 109] then requesting blocks at BlockHeight < 100 or BlockHeight
    // > 109 is an error
    if range_from < range_from_offset || requested_range_to > range_to {
        return GetBlocksRes(Err(format!("Requested blocks outside the range stored in the archive node. Requested [{} .. {}]. Available [{} .. {}].",
            range_from, requested_range_to, range_from_offset, range_to)));
    }
    // Example: If the node stores blocks [100 .. 109] then BLOCK_HEIGHT_OFFSET
    // is 100 and the Block with BlockHeight 100 is at index 0
    let offset = (range_from - range_from_offset) as usize;
    GetBlocksRes(Ok(blocks[offset..offset + length].to_vec()))
}

// A helper function for ledger/iter_blocks and archive_node/iter_blocks
// endpoints
pub fn iter_blocks(blocks: &[EncodedBlock], offset: usize, length: usize) -> IterBlocksRes {
    let start = std::cmp::min(offset, blocks.len());
    let end = std::cmp::min(start + length, blocks.len());
    let blocks = blocks[start..end].to_vec();
    IterBlocksRes(blocks)
}

#[derive(CandidType, Deserialize)]
pub enum CyclesResponse {
    CanisterCreated(CanisterId),
    // Silly requirement by the candid derivation
    ToppedUp(()),
    Refunded(String, Option<BlockHeight>),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(try_from = "candid::types::reference::Func")]
pub struct QueryArchiveFn {
    pub canister_id: CanisterId,
    pub method: String,
}

impl From<QueryArchiveFn> for candid::types::reference::Func {
    fn from(archive_fn: QueryArchiveFn) -> Self {
        Self {
            principal: candid::Principal::from_slice(archive_fn.canister_id.as_ref()),
            method: archive_fn.method,
        }
    }
}

impl TryFrom<candid::types::reference::Func> for QueryArchiveFn {
    type Error = String;
    fn try_from(func: candid::types::reference::Func) -> Result<Self, Self::Error> {
        let canister_id = CanisterId::try_from(func.principal.as_slice())
            .map_err(|e| format!("principal is not a canister id: {}", e))?;
        Ok(QueryArchiveFn {
            canister_id,
            method: func.method,
        })
    }
}

impl CandidType for QueryArchiveFn {
    fn _ty() -> candid::types::Type {
        candid::types::Type::Func(candid::types::Function {
            modes: vec![candid::parser::types::FuncMode::Query],
            args: vec![GetBlocksArgs::_ty()],
            rets: vec![GetBlocksResult::_ty()],
        })
    }

    fn idl_serialize<S>(&self, serializer: S) -> Result<(), S::Error>
    where
        S: candid::types::Serializer,
    {
        candid::types::reference::Func::from(self.clone()).idl_serialize(serializer)
    }
}

#[derive(Debug, CandidType, Deserialize)]
pub struct ArchivedBlocksRange {
    pub start: BlockHeight,
    pub length: u64,
    pub callback: QueryArchiveFn,
}

#[derive(Debug, CandidType, Deserialize)]
pub struct QueryBlocksResponse {
    pub chain_length: u64,
    pub certificate: Option<serde_bytes::ByteBuf>,
    pub blocks: Vec<CandidBlock>,
    pub first_block_index: BlockHeight,
    pub archived_blocks: Vec<ArchivedBlocksRange>,
}
