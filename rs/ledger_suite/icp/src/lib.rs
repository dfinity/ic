use candid::{CandidType, Nat};
use dfn_protobuf::ProtoBuf;
use dfn_protobuf::ToProto;
use ic_base_types::{CanisterId, PrincipalId};
use ic_crypto_sha2::Sha256;
pub use ic_ledger_canister_core::archive::ArchiveOptions;
use ic_ledger_canister_core::ledger::{LedgerContext, LedgerTransaction, TxApplyError};
use ic_ledger_core::{
    approvals::{AllowanceTable, HeapAllowancesData},
    balances::Balances,
    block::{BlockType, EncodedBlock, FeeCollector},
    tokens::CheckedAdd,
};
use ic_ledger_hash_of::HASH_LENGTH;
use ic_ledger_hash_of::HashOf;
use icrc_ledger_types::icrc1::account::Account;
use on_wire::{FromWire, IntoWire};
use prost::Message;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::fmt;
use std::time::Duration;
use std::{borrow::Cow, collections::BTreeMap};
use strum_macros::IntoStaticStr;

pub use ic_ledger_core::{
    block::BlockIndex,
    timestamp::TimeStamp,
    tokens::{TOKEN_SUBDIVIDABLE_BY, Tokens},
};

pub mod account_identifier;
#[allow(clippy::all)]
#[path = "gen/ic_ledger.pb.v1.rs"]
pub mod protobuf;
mod validate_endpoints;
pub use account_identifier::{AccountIdentifier, Subaccount};
use icrc_ledger_types::icrc1::account::Subaccount as Icrc1Subaccount;
pub use validate_endpoints::{tokens_from_proto, tokens_into_proto};

/// Note that the Ledger can be deployed with a
/// different transaction fee. Clients that want to use the Ledger should query
/// for the fee before doing transactions.
pub const DEFAULT_TRANSFER_FEE: Tokens = Tokens::from_e8s(10_000);

pub const MAX_BLOCKS_PER_REQUEST: usize = 2000;
pub const MAX_BLOCKS_PER_INGRESS_REPLICATED_QUERY_REQUEST: usize = 50;

pub const MEMO_SIZE_BYTES: usize = 32;

pub const MAX_TAKE_ALLOWANCES: u64 = 500;

pub const GOVERNANCE_CANISTER_INDEX_IN_NNS_SUBNET: u64 = 1;
pub const LEDGER_CANISTER_INDEX_IN_NNS_SUBNET: u64 = 2;
pub const ROOT_CANISTER_INDEX_IN_NNS_SUBNET: u64 = 3;
pub const LEDGER_INDEX_CANISTER_INDEX_IN_NNS_SUBNET: u64 = 11;

/// 1: rrkah-fqaaa-aaaaa-aaaaq-cai
pub const GOVERNANCE_CANISTER_ID: CanisterId =
    CanisterId::from_u64(GOVERNANCE_CANISTER_INDEX_IN_NNS_SUBNET);
/// 2: ryjl3-tyaaa-aaaaa-aaaba-cai
pub const LEDGER_CANISTER_ID: CanisterId =
    CanisterId::from_u64(LEDGER_CANISTER_INDEX_IN_NNS_SUBNET);
/// 3: r7inp-6aaaa-aaaaa-aaabq-cai
pub const ROOT_CANISTER_ID: CanisterId = CanisterId::from_u64(ROOT_CANISTER_INDEX_IN_NNS_SUBNET);
/// 11: qhbym-qaaaa-aaaaa-aaafq-cai
pub const LEDGER_INDEX_CANISTER_ID: CanisterId =
    CanisterId::from_u64(LEDGER_INDEX_CANISTER_INDEX_IN_NNS_SUBNET);

pub type LedgerBalances = Balances<BTreeMap<AccountIdentifier, Tokens>>;
pub type LedgerAllowances = AllowanceTable<HeapAllowancesData<AccountIdentifier, Tokens>>;

#[derive(
    Copy,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Debug,
    Default,
    CandidType,
    Deserialize,
    Serialize,
)]
pub struct Memo(pub u64);

pub type Certification = Option<Vec<u8>>;

/// An operation which modifies account balances
#[derive(
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Debug,
    CandidType,
    Deserialize,
    IntoStaticStr,
    Serialize,
)]
pub enum Operation {
    Burn {
        from: AccountIdentifier,
        amount: Tokens,
        #[serde(skip_serializing_if = "Option::is_none")]
        spender: Option<AccountIdentifier>,
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
        #[serde(skip_serializing_if = "Option::is_none")]
        spender: Option<AccountIdentifier>,
    },
    Approve {
        from: AccountIdentifier,
        spender: AccountIdentifier,
        allowance: Tokens,
        expected_allowance: Option<Tokens>,
        expires_at: Option<TimeStamp>,
        fee: Tokens,
    },
}

pub fn apply_operation<C>(
    context: &mut C,
    operation: &Operation,
    now: TimeStamp,
) -> Result<(), TxApplyError<C::Tokens>>
where
    C: LedgerContext<AccountId = AccountIdentifier, Tokens = Tokens>,
{
    match operation {
        Operation::Burn {
            from,
            amount,
            spender,
        } => {
            if let Some(spender) = spender.as_ref() {
                let allowance = context.approvals().allowance(from, spender, now);
                if allowance.amount < *amount {
                    return Err(TxApplyError::InsufficientAllowance {
                        allowance: allowance.amount,
                    });
                }
            }
            context.balances_mut().burn(from, *amount)?;
            if spender.is_some() && from != &spender.unwrap() {
                context
                    .approvals_mut()
                    .use_allowance(from, &spender.unwrap(), *amount, now)
                    .expect("bug: cannot use allowance");
            }
        }
        Operation::Mint { to, amount, .. } => context.balances_mut().mint(to, *amount)?,
        Operation::Approve {
            from,
            spender,
            allowance,
            expected_allowance,
            expires_at,
            fee,
        } => {
            // NB. We cannot reliably detect self-approvals at this level
            // because the approver and the spender principals are hashed.
            // We rely on the approve endpoint to perform this check.

            context.balances_mut().burn(from, *fee)?;

            let result = context
                .approvals_mut()
                .approve(
                    from,
                    spender,
                    *allowance,
                    *expires_at,
                    now,
                    *expected_allowance,
                )
                .map_err(TxApplyError::from);
            if let Err(e) = result {
                context
                    .balances_mut()
                    .mint(from, *fee)
                    .expect("bug: failed to refund approval fee");
                return Err(e);
            }
        }

        Operation::Transfer {
            from,
            to,
            spender,
            amount,
            fee,
        } => {
            if spender.is_none() || *from == spender.unwrap() {
                // It is either a regular transfer or a self-transfer_from.

                // NB. We bypass the allowance check if the account owner calls
                // transfer_from.

                // NB. We cannot reliably detect self-transfer_from at this level.
                // We need help from the transfer_from endpoint to populate
                // [from] and [spender] with equal values if the spender is the
                // account owner.
                context
                    .balances_mut()
                    .transfer(from, to, *amount, *fee, None)?;
                return Ok(());
            }

            let allowance = context.approvals().allowance(from, &spender.unwrap(), now);
            let used_allowance =
                amount
                    .checked_add(fee)
                    .ok_or(TxApplyError::InsufficientAllowance {
                        allowance: allowance.amount,
                    })?;
            if allowance.amount < used_allowance {
                return Err(TxApplyError::InsufficientAllowance {
                    allowance: allowance.amount,
                });
            }
            context
                .balances_mut()
                .transfer(from, to, *amount, *fee, None)?;
            context
                .approvals_mut()
                .use_allowance(from, &spender.unwrap(), used_allowance, now)
                .expect("bug: cannot use allowance");
        }
    };
    Ok(())
}

/// An operation with the metadata the client generated attached to it
#[derive(
    Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, CandidType, Deserialize, Serialize,
)]
pub struct Transaction {
    pub operation: Operation,
    pub memo: Memo,
    /// The time this transaction was created.
    pub created_at_time: Option<TimeStamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icrc1_memo: Option<ByteBuf>,
}

impl LedgerTransaction for Transaction {
    type AccountId = AccountIdentifier;
    type Tokens = Tokens;

    fn burn(
        from: Self::AccountId,
        spender: Option<Self::AccountId>,
        amount: Tokens,
        created_at_time: Option<TimeStamp>,
        memo: Option<u64>,
    ) -> Self {
        Self {
            operation: Operation::Burn {
                from,
                amount,
                spender,
            },
            memo: memo.map(Memo).unwrap_or_default(),
            icrc1_memo: None,
            created_at_time,
        }
    }

    fn approve(
        from: Self::AccountId,
        spender: Self::AccountId,
        amount: Self::Tokens,
        created_at_time: Option<TimeStamp>,
        memo: Option<u64>,
    ) -> Self {
        Self {
            operation: Operation::Approve {
                from,
                spender,
                allowance: amount,
                expected_allowance: None,
                expires_at: None,
                fee: Tokens::ZERO,
            },
            memo: memo.map(Memo).unwrap_or_default(),
            icrc1_memo: None,
            created_at_time,
        }
    }

    fn created_at_time(&self) -> Option<TimeStamp> {
        self.created_at_time
    }

    fn hash(&self) -> HashOf<Self> {
        let mut state = Sha256::new();
        state.write(&serde_cbor::ser::to_vec_packed(&self).unwrap());
        HashOf::new(state.finish())
    }

    fn apply<C>(
        &self,
        context: &mut C,
        now: TimeStamp,
        _effective_fee: C::Tokens,
    ) -> Result<(), TxApplyError<C::Tokens>>
    where
        C: LedgerContext<AccountId = Self::AccountId, Tokens = Tokens>,
    {
        apply_operation(context, &self.operation, now)
    }
}

impl Transaction {
    pub fn new(
        from: AccountIdentifier,
        to: AccountIdentifier,
        spender: Option<AccountIdentifier>,
        amount: Tokens,
        fee: Tokens,
        memo: Memo,
        created_at_time: TimeStamp,
    ) -> Self {
        let operation = Operation::Transfer {
            from,
            to,
            spender,
            amount,
            fee,
        };
        Transaction {
            operation,
            memo,
            icrc1_memo: None,
            created_at_time: Some(created_at_time),
        }
    }
}

/// A transaction with the metadata the canister generated attached to it
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
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
        effective_fee: Tokens,
    ) -> Result<Self, String> {
        let transaction = Transaction {
            operation,
            memo,
            icrc1_memo: None,
            created_at_time: Some(created_at_time),
        };
        Ok(Self::from_transaction(
            parent_hash,
            transaction,
            timestamp,
            effective_fee,
            None,
        ))
    }

    #[inline]
    pub fn new_from_transaction(
        parent_hash: Option<HashOf<EncodedBlock>>,
        transaction: Transaction,
        timestamp: TimeStamp,
        effective_fee: Tokens,
    ) -> Self {
        Self::from_transaction(parent_hash, transaction, timestamp, effective_fee, None)
    }

    pub fn transaction(&self) -> Cow<'_, Transaction> {
        Cow::Borrowed(&self.transaction)
    }
}

impl BlockType for Block {
    type Transaction = Transaction;
    type AccountId = AccountIdentifier;
    type Tokens = Tokens;

    fn encode(self) -> EncodedBlock {
        EncodedBlock::from_vec(
            ProtoBuf::new(self)
                .into_bytes()
                .expect("unreachable: failed to encode a block"),
        )
    }

    fn decode(encoded_block: EncodedBlock) -> Result<Self, String> {
        Ok(ProtoBuf::from_bytes(encoded_block.into_vec())?.get())
    }

    fn block_hash(encoded_block: &EncodedBlock) -> HashOf<EncodedBlock> {
        let mut state = Sha256::new();
        state.write(encoded_block.as_slice());
        HashOf::new(state.finish())
    }

    fn parent_hash(&self) -> Option<HashOf<EncodedBlock>> {
        self.parent_hash
    }

    fn timestamp(&self) -> TimeStamp {
        self.timestamp
    }

    fn from_transaction(
        parent_hash: Option<HashOf<EncodedBlock>>,
        transaction: Self::Transaction,
        timestamp: TimeStamp,
        _effective_fee: Tokens,
        _fee_collector: Option<FeeCollector<AccountIdentifier>>,
    ) -> Self {
        Self {
            parent_hash,
            transaction,
            timestamp,
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
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

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub enum LedgerCanisterPayload {
    Init(InitArgs),
    Upgrade(Option<UpgradeArgs>),
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct LedgerCanisterInitPayload(pub LedgerCanisterPayload);

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct LedgerCanisterUpgradePayload(pub LedgerCanisterPayload);

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct UpgradeArgs {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icrc1_minting_account: Option<Account>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub feature_flags: Option<FeatureFlags>,
}

// This is how we pass arguments to 'init' in main.rs
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct InitArgs {
    pub minting_account: AccountIdentifier,
    pub icrc1_minting_account: Option<Account>,
    pub initial_values: HashMap<AccountIdentifier, Tokens>,
    pub max_message_size_bytes: Option<usize>,
    pub transaction_window: Option<Duration>,
    pub archive_options: Option<ArchiveOptions>,
    pub send_whitelist: HashSet<CanisterId>,
    pub transfer_fee: Option<Tokens>,
    pub token_symbol: Option<String>,
    pub token_name: Option<String>,
    pub feature_flags: Option<FeatureFlags>,
}

impl LedgerCanisterInitPayload {
    pub fn builder() -> LedgerCanisterInitPayloadBuilder {
        LedgerCanisterInitPayloadBuilder::new()
    }
    pub fn init_args(&mut self) -> Option<&mut InitArgs> {
        match &mut self.0 {
            LedgerCanisterPayload::Init(args) => Some(args),
            LedgerCanisterPayload::Upgrade(_) => None,
        }
    }
}

impl LedgerCanisterUpgradePayload {
    pub fn builder() -> LedgerCanisterUpgradePayloadBuilder {
        LedgerCanisterUpgradePayloadBuilder::new()
    }
}

pub struct LedgerCanisterInitPayloadBuilder {
    minting_account: Option<AccountIdentifier>,
    icrc1_minting_account: Option<Account>,
    initial_values: HashMap<AccountIdentifier, Tokens>,
    max_message_size_bytes: Option<usize>,
    transaction_window: Option<Duration>,
    archive_options: Option<ArchiveOptions>,
    send_whitelist: HashSet<CanisterId>,
    transfer_fee: Option<Tokens>,
    token_symbol: Option<String>,
    token_name: Option<String>,
    feature_flags: Option<FeatureFlags>,
}

impl LedgerCanisterInitPayloadBuilder {
    fn new() -> Self {
        Self {
            minting_account: None,
            icrc1_minting_account: None,
            initial_values: Default::default(),
            max_message_size_bytes: None,
            transaction_window: None,
            archive_options: None,
            send_whitelist: Default::default(),
            transfer_fee: None,
            token_symbol: None,
            token_name: None,
            feature_flags: None,
        }
    }

    pub fn new_with_mainnet_settings() -> Self {
        Self::new()
            .minting_account(GOVERNANCE_CANISTER_ID.get().into())
            .archive_options(ArchiveOptions {
                trigger_threshold: 2000,
                num_blocks_to_archive: 1000,
                // 1 GB, which gives us 3 GB space when upgrading
                node_max_memory_size_bytes: Some(1024 * 1024 * 1024),
                // 128kb
                max_message_size_bytes: Some(128 * 1024),
                controller_id: ROOT_CANISTER_ID.into(),
                more_controller_ids: None,
                cycles_for_archive_creation: Some(0),
                max_transactions_per_response: None,
            })
            .max_message_size_bytes(128 * 1024)
            // 24 hour transaction window
            .transaction_window(Duration::from_secs(24 * 60 * 60))
            .transfer_fee(DEFAULT_TRANSFER_FEE)
    }

    pub fn minting_account(mut self, minting_account: AccountIdentifier) -> Self {
        self.minting_account = Some(minting_account);
        self
    }

    pub fn icrc1_minting_account(mut self, minting_account: Account) -> Self {
        self.icrc1_minting_account = Some(minting_account);
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

    pub fn feature_flags(mut self, feature_flags: FeatureFlags) -> Self {
        self.feature_flags = Some(feature_flags);
        self
    }

    pub fn build(self) -> Result<LedgerCanisterInitPayload, String> {
        let minting_account = self
            .minting_account
            .ok_or("minting_account must be set in the payload")?;

        // verify ledger's invariant about the maximum amount
        let mut sum = Tokens::ZERO;
        for initial_value in self.initial_values.values() {
            sum = sum
                .checked_add(initial_value)
                .ok_or_else(|| "initial_values sum overflows".to_string())?
        }

        // Don't allow self-transfers of the minting canister
        if self.initial_values.contains_key(&minting_account) {
            return Err(
                "initial_values cannot contain transfers to the minting_account".to_string(),
            );
        }

        Ok(LedgerCanisterInitPayload(LedgerCanisterPayload::Init(
            InitArgs {
                minting_account,
                icrc1_minting_account: self.icrc1_minting_account,
                initial_values: self.initial_values,
                max_message_size_bytes: self.max_message_size_bytes,
                transaction_window: self.transaction_window,
                archive_options: self.archive_options,
                send_whitelist: self.send_whitelist,
                transfer_fee: self.transfer_fee,
                token_symbol: self.token_symbol,
                token_name: self.token_name,
                feature_flags: self.feature_flags,
            },
        )))
    }
}

pub struct LedgerCanisterUpgradePayloadBuilder {
    icrc1_minting_account: Option<Account>,
    feature_flags: Option<FeatureFlags>,
}

impl LedgerCanisterUpgradePayloadBuilder {
    fn new() -> Self {
        Self {
            icrc1_minting_account: None,
            feature_flags: None,
        }
    }

    pub fn icrc1_minting_account(mut self, minting_account: Account) -> Self {
        self.icrc1_minting_account = Some(minting_account);
        self
    }

    pub fn build(self) -> Result<LedgerCanisterUpgradePayload, String> {
        Ok(LedgerCanisterUpgradePayload(
            LedgerCanisterPayload::Upgrade(Some(UpgradeArgs {
                icrc1_minting_account: self.icrc1_minting_account,
                feature_flags: self.feature_flags,
            })),
        ))
    }
}

/// Argument taken by the send endpoint
#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize, Serialize)]
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
#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize, Serialize)]
pub struct TransferArgs {
    pub memo: Memo,
    pub amount: Tokens,
    pub fee: Tokens,
    pub from_subaccount: Option<Subaccount>,
    pub to: AccountIdBlob,
    pub created_at_time: Option<TimeStamp>,
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub enum TransferError {
    BadFee { expected_fee: Tokens },
    InsufficientFunds { balance: Tokens },
    TxTooOld { allowed_window_nanos: u64 },
    TxCreatedInFuture,
    TxDuplicate { duplicate_of: BlockIndex },
}

impl fmt::Display for TransferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadFee { expected_fee } => {
                write!(f, "transfer fee should be {expected_fee}")
            }
            Self::InsufficientFunds { balance } => {
                write!(
                    f,
                    "the debit account doesn't have enough funds to complete the transaction, current balance: {balance}"
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
                "transaction is a duplicate of another transaction in block {duplicate_of}"
            ),
        }
    }
}

#[derive(Eq, PartialEq, Debug)]
pub enum PaymentError {
    Reject(String),
    TransferError(TransferError),
}

/// Struct sent by the ledger canister when it notifies a recipient of a payment
#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize, Serialize)]
pub struct TransactionNotification {
    pub from: PrincipalId,
    pub from_subaccount: Option<Subaccount>,
    pub to: CanisterId,
    pub to_subaccount: Option<Subaccount>,
    pub block_height: BlockIndex,
    pub amount: Tokens,
    pub memo: Memo,
}

/// Argument taken by the notification endpoint
#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize, Serialize)]
pub struct NotifyCanisterArgs {
    pub block_height: BlockIndex,
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
        block_height: BlockIndex,
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
#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize, Serialize)]
pub struct AccountIdentifierByteBuf {
    pub account: ByteBuf,
}

impl TryFrom<AccountIdentifierByteBuf> for BinaryAccountBalanceArgs {
    type Error = String;

    fn try_from(value: AccountIdentifierByteBuf) -> Result<Self, Self::Error> {
        Ok(BinaryAccountBalanceArgs {
            account: AccountIdBlob::try_from(value.account.as_slice()).map_err(|_| {
                format!(
                    "Invalid account identifier length (expected 32, got {})",
                    value.account.len()
                )
            })?,
        })
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize, Serialize)]
pub struct BinaryAccountBalanceArgs {
    pub account: AccountIdBlob,
}

/// Argument taken by the account_balance_dfx endpoint
#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize, Serialize)]
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
    Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, CandidType, Deserialize, Serialize,
)]
pub enum CandidOperation {
    Burn {
        from: AccountIdBlob,
        amount: Tokens,
        spender: Option<AccountIdBlob>,
    },
    Mint {
        to: AccountIdBlob,
        amount: Tokens,
    },
    Transfer {
        from: AccountIdBlob,
        to: AccountIdBlob,
        spender: Option<AccountIdBlob>,
        amount: Tokens,
        fee: Tokens,
    },
    Approve {
        from: AccountIdBlob,
        spender: AccountIdBlob,
        // This field is deprecated and should not be used.
        allowance_e8s: i128,
        allowance: Tokens,
        expected_allowance: Option<Tokens>,
        fee: Tokens,
        expires_at: Option<TimeStamp>,
    },
}

impl From<Operation> for CandidOperation {
    fn from(op: Operation) -> Self {
        match op {
            Operation::Burn {
                from,
                amount,
                spender,
            } => Self::Burn {
                from: from.to_address(),
                amount,
                spender: spender.map(|s| s.to_address()),
            },
            Operation::Mint { to, amount } => Self::Mint {
                to: to.to_address(),
                amount,
            },
            Operation::Transfer {
                from,
                to,
                spender,
                amount,
                fee,
            } => Self::Transfer {
                from: from.to_address(),
                to: to.to_address(),
                spender: spender.map(|s| s.to_address()),
                amount,
                fee,
            },
            Operation::Approve {
                from,
                spender,
                allowance,
                expected_allowance,
                fee,
                expires_at,
            } => Self::Approve {
                from: from.to_address(),
                spender: spender.to_address(),
                allowance_e8s: allowance.get_e8s() as i128,
                expected_allowance,
                fee,
                expires_at,
                allowance,
            },
        }
    }
}

impl TryFrom<CandidOperation> for Operation {
    type Error = String;

    fn try_from(value: CandidOperation) -> Result<Self, Self::Error> {
        let address_to_accountidentifier = |acc| -> Result<AccountIdentifier, Self::Error> {
            AccountIdentifier::from_address(acc).map_err(|err| err.to_string())
        };
        Ok(match value {
            CandidOperation::Burn {
                from,
                amount,
                spender,
            } => {
                let spender = if spender.is_some() {
                    Some(address_to_accountidentifier(spender.unwrap())?)
                } else {
                    None
                };
                Operation::Burn {
                    from: address_to_accountidentifier(from)?,
                    amount,
                    spender,
                }
            }
            CandidOperation::Mint { to, amount } => Operation::Mint {
                to: address_to_accountidentifier(to)?,
                amount,
            },
            CandidOperation::Transfer {
                from,
                to,
                spender,
                amount,
                fee,
            } => {
                let spender = if spender.is_some() {
                    Some(address_to_accountidentifier(spender.unwrap())?)
                } else {
                    None
                };
                Operation::Transfer {
                    to: address_to_accountidentifier(to)?,
                    from: address_to_accountidentifier(from)?,
                    spender,
                    amount,
                    fee,
                }
            }
            CandidOperation::Approve {
                from,
                spender,
                fee,
                expires_at,
                allowance,
                expected_allowance,
                ..
            } => Operation::Approve {
                spender: address_to_accountidentifier(spender)?,
                from: address_to_accountidentifier(from)?,
                allowance,
                expected_allowance,
                fee,
                expires_at,
            },
        })
    }
}

/// An operation with the metadata the client generated attached to it
#[derive(
    Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, CandidType, Deserialize, Serialize,
)]
pub struct CandidTransaction {
    pub operation: Option<CandidOperation>,
    pub memo: Memo,
    pub icrc1_memo: Option<ByteBuf>,
    pub created_at_time: TimeStamp,
}

impl TryFrom<CandidTransaction> for Transaction {
    type Error = String;
    fn try_from(value: CandidTransaction) -> Result<Self, Self::Error> {
        Ok(Self {
            operation: value.operation.map_or(
                Err("Operation is None --> Cannot convert CandidOperation to icp_ledger Operation"),
                |candid_block| Ok(Operation::try_from(candid_block)),
            )??,
            memo: value.memo,
            created_at_time: Some(value.created_at_time),
            icrc1_memo: value.icrc1_memo,
        })
    }
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
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
            transaction: CandidTransaction {
                memo: transaction.memo,
                icrc1_memo: transaction.icrc1_memo,
                operation: Some(transaction.operation.into()),
                created_at_time: transaction.created_at_time.unwrap_or(timestamp),
            },
            timestamp,
        }
    }
}

impl TryFrom<CandidBlock> for Block {
    type Error = String;
    fn try_from(value: CandidBlock) -> Result<Self, Self::Error> {
        Ok(Self {
            parent_hash: value.parent_hash.map(HashOf::<EncodedBlock>::new),
            transaction: Transaction::try_from(value.transaction)?,
            timestamp: value.timestamp,
        })
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize, Serialize)]
pub struct IcpAllowanceArgs {
    pub account: AccountIdentifier,
    pub spender: AccountIdentifier,
}

/// Argument taken by the transfer fee endpoint
///
/// The reason it is a struct is so that it can be extended -- e.g., to be able
/// to query past values. Requiring 1 candid value instead of zero is a
/// non-backward compatible change. But adding optional fields to a struct taken
/// as input is backward-compatible.
#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize, Serialize)]
pub struct TransferFeeArgs {}

/// Argument taken by the total_supply endpoint
///
/// The reason it is a struct is so that it can be extended -- e.g., to be able
/// to query past values. Requiring 1 candid value instead of zero is a
/// non-backward compatible change. But adding optional fields to a struct taken
/// as input is backward-compatible.
#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize, Serialize)]
pub struct TotalSupplyArgs {}

#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize, Serialize)]
pub struct Symbol {
    pub symbol: String,
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize, Serialize)]
pub struct Name {
    pub name: String,
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize, Serialize)]
pub struct Decimals {
    pub decimals: u32,
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize, Serialize)]
pub struct ArchiveInfo {
    pub canister_id: CanisterId,
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize, Serialize)]
pub struct Archives {
    pub archives: Vec<ArchiveInfo>,
}

/// Argument returned by the tip_of_chain endpoint
#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize, Serialize)]
pub struct TipOfChainRes {
    pub certification: Option<Vec<u8>>,
    pub tip_index: BlockIndex,
}

#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub struct GetBlocksArgs {
    pub start: BlockIndex,
    pub length: u64,
}

#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub struct BlockRange {
    pub blocks: Vec<CandidBlock>,
}

pub type GetBlocksResult = Result<BlockRange, GetBlocksError>;

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub enum GetBlocksError {
    BadFirstBlockIndex {
        requested_index: BlockIndex,
        first_valid_index: BlockIndex,
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
pub struct BlockArg(pub BlockIndex);
pub struct BlockRes(pub Option<Result<EncodedBlock, CanisterId>>);

// A helper function for archive_node/get_blocks endpoints
pub fn get_blocks(
    blocks: &[EncodedBlock],
    range_from_offset: BlockIndex,
    range_from: BlockIndex,
    length: usize,
) -> GetBlocksRes {
    // Inclusive end of the range of *requested* blocks
    let requested_range_to = range_from as usize + length - 1;
    // Inclusive end of the range of *available* blocks
    let range_to = range_from_offset as usize + blocks.len() - 1;
    // Example: If the Node stores 10 blocks beginning at BlockIndex 100, i.e.
    // [100 .. 109] then requesting blocks at BlockIndex < 100 or BlockIndex
    // > 109 is an error
    if range_from < range_from_offset || requested_range_to > range_to {
        return GetBlocksRes(Err(format!(
            "Requested blocks outside the range stored in the archive node. Requested [{range_from} .. {requested_range_to}]. Available [{range_from_offset} .. {range_to}]."
        )));
    }
    // Example: If the node stores blocks [100 .. 109] then BLOCK_HEIGHT_OFFSET
    // is 100 and the Block with BlockIndex 100 is at index 0
    let offset = (range_from - range_from_offset) as usize;
    GetBlocksRes(Ok(blocks[offset..offset + length].to_vec()))
}

// A helper function for archive_node/iter_blocks endpoint
pub fn iter_blocks(blocks: &[EncodedBlock], offset: usize, length: usize) -> IterBlocksRes {
    let start = std::cmp::min(offset, blocks.len());
    let end = std::cmp::min(start + length, blocks.len());
    let blocks = blocks[start..end].to_vec();
    IterBlocksRes(blocks)
}

#[derive(Clone, CandidType, Deserialize)]
pub enum CyclesResponse {
    CanisterCreated(CanisterId),
    // Silly requirement by the candid derivation
    ToppedUp(()),
    Refunded(String, Option<BlockIndex>),
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct ArchivedBlocksRange {
    pub start: BlockIndex,
    pub length: u64,
    pub callback: QueryArchiveBlocksFn,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct QueryBlocksResponse {
    pub chain_length: u64,
    pub certificate: Option<serde_bytes::ByteBuf>,
    pub blocks: Vec<CandidBlock>,
    pub first_block_index: BlockIndex,
    pub archived_blocks: Vec<ArchivedBlocksRange>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct QueryEncodedBlocksResponse {
    pub chain_length: u64,
    pub certificate: Option<serde_bytes::ByteBuf>,
    pub blocks: Vec<EncodedBlock>,
    pub first_block_index: BlockIndex,
    pub archived_blocks: Vec<ArchivedEncodedBlocksRange>,
}

pub type GetEncodedBlocksResult = Result<Vec<EncodedBlock>, GetBlocksError>;

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct ArchivedEncodedBlocksRange {
    pub start: BlockIndex,
    pub length: u64,
    pub callback: QueryArchiveEncodedBlocksFn,
}

pub type QueryArchiveBlocksFn =
    icrc_ledger_types::icrc3::archive::QueryArchiveFn<GetBlocksArgs, GetBlocksResult>;
pub type QueryArchiveEncodedBlocksFn =
    icrc_ledger_types::icrc3::archive::QueryArchiveFn<GetBlocksArgs, GetEncodedBlocksResult>;

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct FeatureFlags {
    pub icrc2: bool,
}

impl FeatureFlags {
    const fn const_default() -> Self {
        Self { icrc2: true }
    }
}

impl Default for FeatureFlags {
    fn default() -> Self {
        Self::const_default()
    }
}

pub fn max_blocks_per_request(principal_id: &PrincipalId) -> usize {
    if ic_cdk::api::in_replicated_execution() && principal_id.is_self_authenticating() {
        return MAX_BLOCKS_PER_INGRESS_REPLICATED_QUERY_REQUEST;
    }
    MAX_BLOCKS_PER_REQUEST
}

pub fn to_proto_bytes<T: ToProto>(msg: T) -> Result<Vec<u8>, String> {
    let proto = msg.into_proto();
    let mut proto_bytes = Vec::with_capacity(proto.encoded_len());
    proto.encode(&mut proto_bytes).map_err(|e| e.to_string())?;
    Ok(proto_bytes)
}

pub fn from_proto_bytes<T: ToProto>(msg: Vec<u8>) -> Result<T, String> {
    T::from_proto(prost::Message::decode(&msg[..]).map_err(|e| e.to_string())?)
}

/// The arguments for the `get_allowances` endpoint.
/// The `prev_spender_id` argument can be used for pagination. If specified
/// the endpoint returns allowances that are lexicographically greater than
/// (`from_account_id`, `prev_spender_id`) - start with spender after `prev_spender_id`.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct GetAllowancesArgs {
    pub from_account_id: AccountIdentifier,
    pub prev_spender_id: Option<AccountIdentifier>,
    pub take: Option<u64>,
}

/// The allowance returned by the `get_allowances` endpoint.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Allowance {
    pub from_account_id: AccountIdentifier,
    pub to_spender_id: AccountIdentifier,
    pub allowance: Tokens,
    pub expires_at: Option<u64>,
}

/// The allowances vector returned by the `get_allowances` endpoint.
pub type Allowances = Vec<Allowance>;

/// The arguments for the `remove_approval` endpoint.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RemoveApprovalArgs {
    pub from_subaccount: Option<Icrc1Subaccount>,
    pub spender: AccountIdBlob,
    pub fee: Option<Nat>,
}
#[cfg(test)]
mod test {
    use ic_stable_structures::storable::Storable;
    use std::str::FromStr;

    use proptest::{arbitrary::any, prop_assert_eq, prop_oneof, proptest, strategy::Strategy};

    use super::*;

    #[test]
    fn transaction_hash() {
        let expected_hash = "be31664ef154456aec5df2e4acc7f23a715ad8ea33ad9dbcbb7e6e90bc5a8b8f";

        let transaction = Transaction {
            operation: Operation::Transfer {
                from: AccountIdentifier::from_str(
                    "e7a879ea563d273c46dd28c1584eaa132fad6f3e316615b3eb657d067f3519b5",
                )
                .unwrap(),
                to: AccountIdentifier::from_str(
                    "207ec07185bedd0f2176ec2760057b8b7bc619a94d60e70fbc91af322a9f7e93",
                )
                .unwrap(),
                amount: Tokens::from_e8s(11541900000),
                fee: Tokens::from_e8s(10_000),
                spender: None,
            },
            memo: Memo(5432845643782906771),
            created_at_time: Some(TimeStamp::from_nanos_since_unix_epoch(1621901572293430780)),
            icrc1_memo: None,
        };

        assert_eq!(expected_hash, transaction.hash().to_string());
    }

    fn arb_principal_id() -> impl Strategy<Value = PrincipalId> {
        // PrincipalId::try_from won't panic for any byte array with len <= 29
        proptest::collection::vec(any::<u8>(), 0..30)
            .prop_map(|v| PrincipalId::try_from(v).unwrap())
    }

    fn arb_opt_subaccount() -> impl Strategy<Value = Option<Subaccount>> {
        proptest::option::of(any::<[u8; 32]>().prop_map(Subaccount))
    }

    fn arb_account() -> impl Strategy<Value = AccountIdentifier> {
        (arb_principal_id(), arb_opt_subaccount())
            .prop_map(|(owner, subaccount)| AccountIdentifier::new(owner, subaccount))
    }

    fn arb_tokens() -> impl Strategy<Value = Tokens> {
        any::<u64>().prop_map(Tokens::from_e8s)
    }

    fn arb_burn() -> impl Strategy<Value = Operation> {
        (
            arb_account(),
            arb_tokens(),
            proptest::option::of(arb_account()),
        )
            .prop_map(|(from, amount, spender)| Operation::Burn {
                from,
                amount,
                spender,
            })
    }

    fn arb_mint() -> impl Strategy<Value = Operation> {
        (arb_account(), arb_tokens()).prop_map(|(to, amount)| Operation::Mint { to, amount })
    }

    fn arb_tranfer() -> impl Strategy<Value = Operation> {
        (
            arb_account(),
            arb_account(),
            arb_tokens(),
            arb_tokens(),
            proptest::option::of(arb_account()),
        )
            .prop_map(|(from, to, amount, fee, spender)| Operation::Transfer {
                from,
                to,
                amount,
                fee,
                spender,
            })
    }

    fn arb_approve() -> impl Strategy<Value = Operation> {
        (
            arb_account(),
            arb_account(),
            arb_tokens(),
            proptest::option::of(arb_tokens()),
            proptest::option::of(arb_timestamp()),
            arb_tokens(),
        )
            .prop_map(
                |(from, spender, allowance, expected_allowance, expires_at, fee)| {
                    Operation::Approve {
                        from,
                        spender,
                        allowance,
                        expected_allowance,
                        expires_at,
                        fee,
                    }
                },
            )
    }

    fn arb_operation() -> impl Strategy<Value = Operation> {
        prop_oneof![arb_burn(), arb_mint(), arb_tranfer(), arb_approve(),]
    }

    fn arb_memo() -> impl Strategy<Value = Memo> {
        any::<u64>().prop_map(Memo)
    }

    fn arb_icrc1_memo() -> impl Strategy<Value = Option<ByteBuf>> {
        proptest::option::of(any::<[u8; 32]>().prop_map(ByteBuf::from))
    }

    fn arb_transaction() -> impl Strategy<Value = Transaction> {
        (
            arb_operation(),
            arb_memo(),
            proptest::option::of(arb_timestamp()),
            arb_icrc1_memo(),
        )
            .prop_map(
                |(operation, memo, created_at_time, icrc1_memo)| Transaction {
                    operation,
                    memo,
                    created_at_time,
                    icrc1_memo,
                },
            )
    }

    fn arb_parent_hash() -> impl Strategy<Value = Option<HashOf<EncodedBlock>>> {
        proptest::option::of(any::<[u8; 32]>().prop_map(HashOf::new))
    }

    fn arb_timestamp() -> impl Strategy<Value = TimeStamp> {
        any::<u64>().prop_map(TimeStamp::from_nanos_since_unix_epoch)
    }

    fn arb_block() -> impl Strategy<Value = Block> {
        (arb_parent_hash(), arb_transaction(), arb_timestamp()).prop_map(
            |(parent_hash, transaction, timestamp)| Block {
                parent_hash,
                transaction,
                timestamp,
            },
        )
    }

    #[test]
    fn test_encode_decode() {
        proptest!(|(block in arb_block())| {
            let encoded = block.clone().encode();
            let decoded = Block::decode(encoded).expect("Unable to decode block!");
            prop_assert_eq!(block, decoded)
        })
    }

    #[test]
    fn test_storable_serialization() {
        proptest!(|(a in arb_account())| {
            prop_assert_eq!(AccountIdentifier::from_bytes(a.to_bytes()), a)
        })
    }
}
