//! A library of types to communicate with the ICP ledger canister.

#![warn(
    elided_lifetimes_in_paths,
    missing_debug_implementations,
    missing_docs,
    unsafe_op_in_unsafe_fn,
    clippy::undocumented_unsafe_blocks,
    clippy::missing_safety_doc
)]

use std::convert::TryFrom;
use std::fmt::{self, Display, Formatter};
use std::ops::{Add, AddAssign, Sub, SubAssign};

use candid::{CandidType, Principal, types::reference::Func};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use sha2::Digest;

use ic_cdk::call::{Call, CallResult};

/// The subaccount that is used by default.
pub const DEFAULT_SUBACCOUNT: Subaccount = Subaccount([0; 32]);

/// The default fee for ledger transactions.
pub const DEFAULT_FEE: Tokens = Tokens { e8s: 10_000 };

/// Id of the ledger canister on the IC.
pub const MAINNET_LEDGER_CANISTER_ID: Principal =
    Principal::from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x01]);

/// Id of the governance canister on the IC.
pub const MAINNET_GOVERNANCE_CANISTER_ID: Principal =
    Principal::from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01]);

/// Id of the cycles minting canister on the IC.
pub const MAINNET_CYCLES_MINTING_CANISTER_ID: Principal =
    Principal::from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x01, 0x01]);

/// Number of nanoseconds from the UNIX epoch in UTC timezone.
#[derive(
    CandidType, Serialize, Deserialize, Clone, Copy, Hash, Debug, PartialEq, Eq, PartialOrd, Ord,
)]
pub struct Timestamp {
    /// Number of nanoseconds from the UNIX epoch in UTC timezone.
    pub timestamp_nanos: u64,
}

/// A type for representing amounts of Tokens.
///
/// # Panics
///
/// * Arithmetics (addition, subtraction) on the Tokens type panics if the underlying type
///   overflows.
#[derive(
    CandidType, Serialize, Deserialize, Clone, Copy, Hash, Debug, PartialEq, Eq, PartialOrd, Ord,
)]
pub struct Tokens {
    e8s: u64,
}

impl Tokens {
    /// The maximum number of Tokens we can hold on a single account.
    pub const MAX: Self = Tokens { e8s: u64::MAX };
    /// Zero Tokens.
    pub const ZERO: Self = Tokens { e8s: 0 };
    /// How many times can Tokenss be divided
    pub const SUBDIVIDABLE_BY: u64 = 100_000_000;

    /// Constructs an amount of Tokens from the number of 10^-8 Tokens.
    pub const fn from_e8s(e8s: u64) -> Self {
        Self { e8s }
    }

    /// Returns the number of 10^-8 Tokens in this amount.
    pub const fn e8s(&self) -> u64 {
        self.e8s
    }
}

impl Add for Tokens {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let e8s = self.e8s.checked_add(other.e8s).unwrap_or_else(|| {
            panic!(
                "Add Tokens {} + {} failed because the underlying u64 overflowed",
                self.e8s, other.e8s
            )
        });
        Self { e8s }
    }
}

impl AddAssign for Tokens {
    fn add_assign(&mut self, other: Self) {
        *self = *self + other;
    }
}

impl Sub for Tokens {
    type Output = Self;
    fn sub(self, other: Self) -> Self {
        let e8s = self.e8s.checked_sub(other.e8s).unwrap_or_else(|| {
            panic!(
                "Subtracting Tokens {} - {} failed because the underlying u64 underflowed",
                self.e8s, other.e8s
            )
        });
        Self { e8s }
    }
}

impl SubAssign for Tokens {
    fn sub_assign(&mut self, other: Self) {
        *self = *self - other;
    }
}

impl Display for Tokens {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{:08}",
            self.e8s / Tokens::SUBDIVIDABLE_BY,
            self.e8s % Tokens::SUBDIVIDABLE_BY
        )
    }
}

/// Subaccount is an arbitrary 32-byte byte array.
/// Ledger uses subaccounts to compute account address, which enables one
/// principal to control multiple ledger accounts.
#[derive(
    CandidType, Serialize, Deserialize, Clone, Copy, Hash, Debug, PartialEq, Eq, PartialOrd, Ord,
)]
pub struct Subaccount(pub [u8; 32]);

#[allow(clippy::range_plus_one)]
impl From<Principal> for Subaccount {
    fn from(principal: Principal) -> Self {
        let mut subaccount = [0; 32];
        let principal = principal.as_slice();
        subaccount[0] = principal.len().try_into().unwrap();
        subaccount[1..1 + principal.len()].copy_from_slice(principal);
        Subaccount(subaccount)
    }
}

/// `AccountIdentifier` is a 32-byte array.
/// The first 4 bytes is a big-endian encoding of a CRC32 checksum of the last 28 bytes.
#[derive(
    CandidType, Serialize, Deserialize, Clone, Copy, Hash, Debug, PartialEq, Eq, PartialOrd, Ord,
)]
pub struct AccountIdentifier([u8; 32]);

impl AccountIdentifier {
    /// Creates a new account identifier from a principal and subaccount.
    pub fn new(owner: &Principal, subaccount: &Subaccount) -> Self {
        let mut hasher = sha2::Sha224::new();
        hasher.update(b"\x0Aaccount-id");
        hasher.update(owner.as_slice());
        hasher.update(&subaccount.0[..]);
        let hash: [u8; 28] = hasher.finalize().into();

        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&hash);
        let crc32_bytes = hasher.finalize().to_be_bytes();

        let mut result = [0u8; 32];
        result[0..4].copy_from_slice(&crc32_bytes[..]);
        result[4..32].copy_from_slice(hash.as_ref());
        Self(result)
    }

    /// Convert hex string into `AccountIdentifier`.
    pub fn from_hex(hex_str: &str) -> Result<AccountIdentifier, String> {
        let hex: Vec<u8> = hex::decode(hex_str).map_err(|e| e.to_string())?;
        Self::from_slice(&hex[..]).map_err(|err| match err {
            // Since the input was provided in hex, return an error that is hex-friendly.
            AccountIdParseError::InvalidLength(_) => format!(
                "{} has a length of {} but we expected a length of 64 or 56",
                hex_str,
                hex_str.len()
            ),
            AccountIdParseError::InvalidChecksum(err) => err.to_string(),
        })
    }

    /// Converts a blob into an `AccountIdentifier`.
    ///
    /// The blob can be either:
    ///
    /// 1. The 32-byte canonical format (4 byte checksum + 28 byte hash).
    /// 2. The 28-byte hash.
    ///
    /// If the 32-byte canonical format is provided, the checksum is verified.
    pub fn from_slice(v: &[u8]) -> Result<AccountIdentifier, AccountIdParseError> {
        // Try parsing it as a 32-byte blob.
        match v.try_into() {
            Ok(h) => {
                // It's a 32-byte blob. Validate the checksum.
                check_sum(h).map_err(AccountIdParseError::InvalidChecksum)
            }
            Err(_) => {
                // Try parsing it as a 28-byte hash.
                match <&[u8] as TryInto<[u8; 28]>>::try_into(v) {
                    Ok(hash) => AccountIdentifier::try_from(hash)
                        .map_err(|_| AccountIdParseError::InvalidLength(v.to_vec())),
                    Err(_) => Err(AccountIdParseError::InvalidLength(v.to_vec())),
                }
            }
        }
    }

    /// Convert `AccountIdentifier` into hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Provide the account identifier as bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the checksum of the account identifier.
    pub fn generate_checksum(&self) -> [u8; 4] {
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&self.0[4..]);
        hasher.finalize().to_be_bytes()
    }
}

fn check_sum(hex: [u8; 32]) -> Result<AccountIdentifier, ChecksumError> {
    // Get the checksum provided
    let found_checksum = &hex[0..4];

    let mut hasher = crc32fast::Hasher::new();
    hasher.update(&hex[4..]);
    let expected_checksum = hasher.finalize().to_be_bytes();

    // Check the generated checksum matches
    if expected_checksum == found_checksum {
        Ok(AccountIdentifier(hex))
    } else {
        Err(ChecksumError {
            input: hex,
            expected_checksum,
            found_checksum: found_checksum.try_into().unwrap(),
        })
    }
}

impl TryFrom<[u8; 32]> for AccountIdentifier {
    type Error = String;

    fn try_from(bytes: [u8; 32]) -> Result<Self, Self::Error> {
        let hash = &bytes[4..];
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(hash);
        let crc32_bytes = hasher.finalize().to_be_bytes();
        if bytes[0..4] == crc32_bytes[0..4] {
            Ok(Self(bytes))
        } else {
            Err("CRC-32 checksum failed to verify".to_string())
        }
    }
}

impl TryFrom<[u8; 28]> for AccountIdentifier {
    type Error = String;

    fn try_from(bytes: [u8; 28]) -> Result<Self, Self::Error> {
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(bytes.as_slice());
        let crc32_bytes = hasher.finalize().to_be_bytes();

        let mut aid_bytes = [0u8; 32];
        aid_bytes[..4].copy_from_slice(&crc32_bytes[..4]);
        aid_bytes[4..].copy_from_slice(&bytes[..]);

        Ok(Self(aid_bytes))
    }
}

impl AsRef<[u8]> for AccountIdentifier {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Display for AccountIdentifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.as_ref()))
    }
}

/// An error for reporting invalid checksums.
#[derive(Debug, PartialEq, Eq)]
pub struct ChecksumError {
    input: [u8; 32],
    expected_checksum: [u8; 4],
    found_checksum: [u8; 4],
}

impl Display for ChecksumError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Checksum failed for {}, expected check bytes {} but found {}",
            hex::encode(&self.input[..]),
            hex::encode(self.expected_checksum),
            hex::encode(self.found_checksum),
        )
    }
}

/// An error for reporting invalid Account Identifiers.
#[derive(Debug, PartialEq, Eq)]
pub enum AccountIdParseError {
    /// The checksum failed to verify.
    InvalidChecksum(ChecksumError),
    /// The length of the input was invalid.
    InvalidLength(Vec<u8>),
}

impl Display for AccountIdParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidChecksum(err) => write!(f, "{err}"),
            Self::InvalidLength(input) => write!(
                f,
                "Received an invalid AccountIdentifier with length {} bytes instead of the expected 28 or 32.",
                input.len()
            ),
        }
    }
}

/// Arguments for the `account_balance` call.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct AccountBalanceArgs {
    /// The account identifier to query the balance of.
    pub account: AccountIdentifier,
}

/// An arbitrary number associated with a transaction.
/// The caller can set it in a `transfer` call as a correlation identifier.
#[derive(
    CandidType, Serialize, Deserialize, Clone, Copy, Hash, Debug, PartialEq, Eq, PartialOrd, Ord,
)]
pub struct Memo(pub u64);

/// Arguments for the `transfer` call.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct TransferArgs {
    /// Transaction memo.
    /// See docs for the [`Memo`] type.
    pub memo: Memo,
    /// The amount that the caller wants to transfer to the destination address.
    pub amount: Tokens,
    /// The amount that the caller pays for the transaction.
    /// Must be 10000 e8s.
    pub fee: Tokens,
    /// The subaccount from which the caller wants to transfer funds.
    /// If `None`, the ledger uses the default (all zeros) subaccount to compute the source address.
    /// See docs for the [`Subaccount`] type.
    pub from_subaccount: Option<Subaccount>,
    /// The destination account.
    /// If the transfer is successful, the balance of this address increases by `amount`.
    pub to: AccountIdentifier,
    /// The point in time when the caller created this request.
    /// If `None`, the ledger uses the current IC time as the timestamp.
    /// Transactions more than one day old will be rejected.
    pub created_at_time: Option<Timestamp>,
}

/// The sequence number of a block in the Tokens ledger blockchain.
pub type BlockIndex = u64;

/// Result of the `transfer` call.
pub type TransferResult = Result<BlockIndex, TransferError>;

/// Error of the `transfer` call.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum TransferError {
    /// The fee that the caller specified in the transfer request was not the one that the ledger expects.
    /// The caller can change the transfer fee to the `expected_fee` and retry the request.
    BadFee {
        /// The account specified by the caller doesn't have enough funds.
        expected_fee: Tokens,
    },
    /// The caller did not have enough ICP in the specified subaccount.
    InsufficientFunds {
        /// The caller's balance.
        balance: Tokens,
    },
    /// The request is too old.
    /// The ledger only accepts requests created within a 24-hour window.
    /// This is a non-recoverable error.
    TxTooOld {
        /// The permitted duration between `created_at_time` and now.
        allowed_window_nanos: u64,
    },
    /// The caller specified a `created_at_time` that is too far in the future.
    /// The caller can retry the request later.
    /// This may also be caused by clock desynchronization.
    TxCreatedInFuture,
    /// The ledger has already executed the request.
    TxDuplicate {
        /// The index of the block containing the original transaction.
        duplicate_of: BlockIndex,
    },
}

impl Display for TransferError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadFee { expected_fee } => {
                write!(f, "transaction fee should be {expected_fee}")
            }
            Self::InsufficientFunds { balance } => {
                write!(
                    f,
                    "the debit account doesn't have enough funds to complete the transaction, current balance: {balance}",
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

/// The content of a ledger transaction.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum Operation {
    /// Tokens were minted, usually via spawning/disbursing neuron maturity or as node operator rewards.
    Mint {
        /// The account that the tokens were transferred to.
        to: AccountIdentifier,
        /// The amount that was transferred.
        amount: Tokens,
    },
    /// Tokens were burned, usually to create cycles for a canister.
    Burn {
        /// The account that sent the tokens to be burned.
        from: AccountIdentifier,
        /// The amount that was burned.
        amount: Tokens,
    },
    /// Tokens were transferred from one account to another.
    Transfer {
        /// The account the tokens were transferred from.
        from: AccountIdentifier,
        /// The account the tokens were transferred to.
        to: AccountIdentifier,
        /// The amount of tokens that were transferred.
        amount: Tokens,
        /// The fee that was charged for the transfer.
        fee: Tokens,
    },
    /// An account approved another account to transfer tokens on its behalf.
    Approve {
        /// The account that owns the tokens.
        from: AccountIdentifier,
        /// The account that was enabled to spend them.
        spender: AccountIdentifier,
        // TODO: add the allowance_e8s field after the official ICRC-2 release.
        /// The expiration date for this approval.
        expires_at: Option<Timestamp>,
        /// The fee that was charged for the approval.
        fee: Tokens,
    },
    /// An account transferred tokens from another account on its behalf, following an approval.
    TransferFrom {
        /// The account that the tokens were transferred from.
        from: AccountIdentifier,
        /// The account that the tokens were transferred to.
        to: AccountIdentifier,
        /// The account that performed the transfer.
        spender: AccountIdentifier,
        /// The amount that was transferred.
        amount: Tokens,
        /// The fee that was charged for the transfer.
        fee: Tokens,
    },
}

/// A recorded ledger transaction.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    /// The memo that was provided for the transaction.
    pub memo: Memo,
    /// The content of the transaction.
    pub operation: Option<Operation>,
    /// The time at which the client of the ledger constructed the transaction.
    pub created_at_time: Timestamp,
    /// The memo that was provided to the `icrc1_transfer` method.
    pub icrc1_memo: Option<ByteBuf>,
}

/// A single record in the ledger.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Block {
    /// The hash of the parent block.
    pub parent_hash: Option<[u8; 32]>,
    /// The transaction that occurred in this block.
    pub transaction: Transaction,
    /// The time at which the ledger constructed the block.
    pub timestamp: Timestamp,
}

/// Arguments for the `get_blocks` function.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct GetBlocksArgs {
    /// The index of the first block to fetch.
    pub start: BlockIndex,
    /// Max number of blocks to fetch.
    pub length: u64,
}

/// Return type for the `query_blocks` function.
#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct QueryBlocksResponse {
    /// The total number of blocks in the chain.
    /// If the chain length is positive, the index of the last block is `chain_length - 1`.
    pub chain_length: u64,
    /// The replica certificate for the last block hash (see [Encoding of Certificates](https://internetcomputer.org/docs/current/references/ic-interface-spec#certification-encoding)).
    /// Only available when *querying* blocks from a canister.
    pub certificate: Option<ByteBuf>,
    /// List of blocks that were available in the ledger when it processed the call.
    ///
    /// The blocks form a contiguous range, with the first block having index
    /// `first_block_index` (see below), and the last block having index
    /// `first_block_index + blocks.len() - 1`.
    ///
    /// The block range can be an arbitrary sub-range of the originally requested range.
    pub blocks: Vec<Block>,
    /// The index of the first block in [`QueryBlocksResponse::blocks`].
    /// If the `blocks` vector is empty, the exact value of this field is not specified.
    pub first_block_index: BlockIndex,
    /// Encoded functions for fetching archived blocks whose indices fall into the
    /// requested range.
    ///
    /// For each entry `e` in `archived_blocks`, `e.start..e.start + e.length` is a sub-range
    /// of the originally requested block range.
    pub archived_blocks: Vec<ArchivedBlockRange>,
}

/// A function that can be called to retrieve a range of archived blocks.
#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct ArchivedBlockRange {
    /// The index of the first archived block that can be fetched using `callback`.
    pub start: BlockIndex,
    /// The number of blocks that can be fetched using `callback`.
    pub length: u64,
    /// The function that should be called to fetch the archived blocks.
    /// The range of the blocks accessible using this function is given by the `start`
    /// and `length` fields above.
    pub callback: QueryArchiveFn,
}

/// A prefix of the block range specified in the `get_blocks` and [`query_archived_blocks`] function.
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct BlockRange {
    /// A prefix of the requested block range.
    /// The index of the first block is equal to [`GetBlocksArgs.start`](GetBlocksArgs).
    ///
    /// ## Note
    ///
    /// The number of blocks might be less than the requested
    /// [`GetBlocksArgs.length`](GetBlocksArgs) for various reasons, for example:
    ///
    /// 1. The query might have hit the replica with an outdated state
    ///    that doesn't have the full block range yet.
    /// 2. The requested range is too large to fit into a single reply.
    ///
    /// The list of blocks can be empty if:
    ///
    /// 1. [`GetBlocksArgs.length`](GetBlocksArgs) was zero.
    /// 2. [`GetBlocksArgs.start`](GetBlocksArgs) was larger than the last block known to the canister.
    pub blocks: Vec<Block>,
}

/// The return type of `get_blocks`.
pub type GetBlocksResult = Result<BlockRange, GetBlocksError>;

/// An error indicating that the arguments passed to `get_blocks` or [`query_archived_blocks`] were invalid.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, CandidType)]
pub enum GetBlocksError {
    /// The [`GetBlocksArgs.start`](GetBlocksArgs) argument was smaller than the first block
    /// served by the canister that received the request.
    BadFirstBlockIndex {
        /// The index that was requested.
        requested_index: BlockIndex,
        /// The minimum index that can be requested, for this particular call.
        first_valid_index: BlockIndex,
    },
    /// Reserved for future use.
    Other {
        /// A machine-readable error code.
        error_code: u64,
        /// A human-readable error message.
        error_message: String,
    },
}

impl Display for GetBlocksError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadFirstBlockIndex {
                requested_index,
                first_valid_index,
            } => write!(
                f,
                "invalid first block index: requested block = {requested_index}, first valid block = {first_valid_index}"
            ),
            Self::Other {
                error_code,
                error_message,
            } => write!(
                f,
                "failed to query blocks (error code {error_code}): {error_message}"
            ),
        }
    }
}

/// Function type used by `query_blocks` for fetching blocks from the archive.
/// Has the signature `(`[`GetBlocksArgs`]`) -> (`[`GetBlocksResult`]`)`.
#[derive(Debug, Clone, Deserialize)]
#[serde(transparent)]
pub struct QueryArchiveFn(Func);

impl From<Func> for QueryArchiveFn {
    fn from(func: Func) -> Self {
        Self(func)
    }
}

impl From<QueryArchiveFn> for Func {
    fn from(query_func: QueryArchiveFn) -> Self {
        query_func.0
    }
}

impl CandidType for QueryArchiveFn {
    fn _ty() -> candid::types::Type {
        candid::func!((GetBlocksArgs) -> (GetBlocksResult) query)
    }

    fn idl_serialize<S>(&self, serializer: S) -> Result<(), S::Error>
    where
        S: candid::types::Serializer,
    {
        Func::from(self.clone()).idl_serialize(serializer)
    }
}

/// Calls the `account_balance` method on the specified canister.
///
/// # Example
/// ```no_run
/// use ic_cdk::api::msg_caller;
/// use ic_ledger_types::{AccountIdentifier, AccountBalanceArgs, Tokens, DEFAULT_SUBACCOUNT, MAINNET_LEDGER_CANISTER_ID, account_balance};
///
/// async fn check_callers_balance() -> Tokens {
///   account_balance(
///     MAINNET_LEDGER_CANISTER_ID,
///     &AccountBalanceArgs {
///       account: AccountIdentifier::new(&msg_caller(), &DEFAULT_SUBACCOUNT)
///     }
///   ).await.expect("call to ledger failed")
/// }
/// ```
pub async fn account_balance(
    ledger_canister_id: Principal,
    args: &AccountBalanceArgs,
) -> CallResult<Tokens> {
    Ok(Call::bounded_wait(ledger_canister_id, "account_balance")
        .with_arg(args)
        .await?
        .candid()?)
}

/// Calls the "transfer" method on the specified canister.
/// # Example
/// ```no_run
/// use ic_cdk::api::msg_caller;
/// use ic_ledger_types::{AccountIdentifier, BlockIndex, Memo, TransferArgs, Tokens, DEFAULT_SUBACCOUNT, DEFAULT_FEE, MAINNET_LEDGER_CANISTER_ID, transfer};
///
/// async fn transfer_to_caller() -> BlockIndex {
///   transfer(
///     MAINNET_LEDGER_CANISTER_ID,
///     &TransferArgs {
///       memo: Memo(0),
///       amount: Tokens::from_e8s(1_000_000),
///       fee: DEFAULT_FEE,
///       from_subaccount: None,
///       to: AccountIdentifier::new(&msg_caller(), &DEFAULT_SUBACCOUNT),
///       created_at_time: None,
///     }
///   ).await.expect("call to ledger failed").expect("transfer failed")
/// }
/// ```
pub async fn transfer(
    ledger_canister_id: Principal,
    args: &TransferArgs,
) -> CallResult<TransferResult> {
    Ok(Call::bounded_wait(ledger_canister_id, "transfer")
        .with_arg(args)
        .await?
        .candid()?)
}

/// Return type of the `token_symbol` function.
#[derive(Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq)]
pub struct Symbol {
    /// A token's trade symbol, e.g. 'ICP'.
    pub symbol: String,
}

/// Calls the `token_symbol` method on the specified canister.
/// # Example
/// ```no_run
/// use candid::Principal;
/// use ic_ledger_types::{Symbol, token_symbol};
///
/// async fn symbol(ledger_canister_id: Principal) -> String {
///   token_symbol(ledger_canister_id).await.expect("call to ledger failed").symbol
/// }
/// ```
pub async fn token_symbol(ledger_canister_id: Principal) -> CallResult<Symbol> {
    Ok(Call::bounded_wait(ledger_canister_id, "token_symbol")
        .await?
        .candid()?)
}

/// Calls the `query_block` method on the specified canister.
/// # Example
/// ```no_run
/// use candid::Principal;
/// use ic_cdk::call::CallResult;
/// use ic_ledger_types::{BlockIndex, Block, GetBlocksArgs, query_blocks, query_archived_blocks};
///
/// async fn query_one_block(ledger: Principal, block_index: BlockIndex) -> CallResult<Option<Block>> {
///   let args = GetBlocksArgs { start: block_index, length: 1 };
///
///   let blocks_result = query_blocks(ledger, &args).await?;
///
///   if blocks_result.blocks.len() >= 1 {
///       debug_assert_eq!(blocks_result.first_block_index, block_index);
///       return Ok(blocks_result.blocks.into_iter().next());
///   }
///
///   if let Some(func) = blocks_result
///       .archived_blocks
///       .into_iter()
///       .find_map(|b| (b.start <= block_index && (block_index - b.start) < b.length).then(|| b.callback)) {
///       match query_archived_blocks(&func, &args).await? {
///           Ok(range) => return Ok(range.blocks.into_iter().next()),
///           _ => (),
///       }
///   }
///   Ok(None)
/// }
pub async fn query_blocks(
    ledger_canister_id: Principal,
    args: &GetBlocksArgs,
) -> CallResult<QueryBlocksResponse> {
    Ok(Call::bounded_wait(ledger_canister_id, "query_blocks")
        .with_arg(args)
        .await?
        .candid()?)
}

/// Continues a query started in [`query_blocks`] by calling its returned archive function.
///
/// # Example
///
/// ```no_run
/// use candid::Principal;
/// use ic_cdk::call::CallResult;
/// use ic_ledger_types::{BlockIndex, Block, GetBlocksArgs, query_blocks, query_archived_blocks};
///
/// async fn query_one_block(ledger: Principal, block_index: BlockIndex) -> CallResult<Option<Block>> {
///   let args = GetBlocksArgs { start: block_index, length: 1 };
///
///   let blocks_result = query_blocks(ledger, &args).await?;
///
///   if blocks_result.blocks.len() >= 1 {
///       debug_assert_eq!(blocks_result.first_block_index, block_index);
///       return Ok(blocks_result.blocks.into_iter().next());
///   }
///
///   if let Some(func) = blocks_result
///       .archived_blocks
///       .into_iter()
///       .find_map(|b| (b.start <= block_index && (block_index - b.start) < b.length).then(|| b.callback)) {
///       match query_archived_blocks(&func, &args).await? {
///           Ok(range) => return Ok(range.blocks.into_iter().next()),
///           _ => (),
///       }
///   }
///   Ok(None)
/// }
pub async fn query_archived_blocks(
    func: &QueryArchiveFn,
    args: &GetBlocksArgs,
) -> CallResult<GetBlocksResult> {
    Ok(Call::bounded_wait(func.0.principal, &func.0.method)
        .with_arg(args)
        .await?
        .candid()?)
}

#[cfg(test)]
mod tests {
    use std::string::ToString;

    use super::*;

    #[test]
    fn test_account_id() {
        assert_eq!(
            "bdc4ee05d42cd0669786899f256c8fd7217fa71177bd1fa7b9534f568680a938".to_string(),
            AccountIdentifier::new(
                &Principal::from_text(
                    "iooej-vlrze-c5tme-tn7qt-vqe7z-7bsj5-ebxlc-hlzgs-lueo3-3yast-pae"
                )
                .unwrap(),
                &DEFAULT_SUBACCOUNT,
            )
            .to_string()
        );
    }

    #[test]
    fn test_account_id_try_from() {
        let mut bytes: [u8; 32] = [0; 32];
        bytes.copy_from_slice(
            &hex::decode("bdc4ee05d42cd0669786899f256c8fd7217fa71177bd1fa7b9534f568680a938")
                .unwrap(),
        );
        assert!(AccountIdentifier::try_from(bytes).is_ok());
        bytes[0] = 0;
        assert!(AccountIdentifier::try_from(bytes).is_err());
    }

    #[test]
    fn test_ledger_canister_id() {
        assert_eq!(
            MAINNET_LEDGER_CANISTER_ID,
            Principal::from_text("ryjl3-tyaaa-aaaaa-aaaba-cai").unwrap()
        );
    }

    #[test]
    fn test_governance_canister_id() {
        assert_eq!(
            MAINNET_GOVERNANCE_CANISTER_ID,
            Principal::from_text("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap()
        );
    }

    #[test]
    fn test_cycles_minting_canister_id() {
        assert_eq!(
            MAINNET_CYCLES_MINTING_CANISTER_ID,
            Principal::from_text("rkp4c-7iaaa-aaaaa-aaaca-cai").unwrap()
        );
    }

    #[test]
    fn principal_to_subaccount() {
        // The account generated is the account used to top up canister 4bkt6-4aaaa-aaaaf-aaaiq-cai
        let principal = Principal::from_text("4bkt6-4aaaa-aaaaf-aaaiq-cai").unwrap();
        let subaccount = Subaccount::from(principal);
        assert_eq!(
            AccountIdentifier::new(&MAINNET_CYCLES_MINTING_CANISTER_ID, &subaccount).to_string(),
            "d8646d1cbe44002026fa3e0d86d51a560b1c31d669bc8b7f66421c1b2feaa59f"
        )
    }

    /// Verifies that these conversions yield the same result:
    /// * bytes -> AccountIdentifier -> hex -> AccountIdentifier
    /// * bytes -> AccountIdentifier
    #[test]
    fn check_hex_round_trip() {
        let bytes: [u8; 32] = [
            237, 196, 46, 168, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
            7, 7, 7, 7, 7,
        ];
        let ai = AccountIdentifier::from_slice(bytes.as_ref())
            .expect("Failed to create account identifier");
        let res = ai.to_hex();
        assert_eq!(
            AccountIdentifier::from_hex(&res),
            Ok(ai),
            "The account identifier doesn't change after going back and forth between a string"
        )
    }

    /// Verifies that this convertion yields the original data:
    /// * bytes -> AccountIdentifier -> bytes
    #[test]
    fn check_bytes_round_trip() {
        let bytes: [u8; 32] = [
            237, 196, 46, 168, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
            7, 7, 7, 7, 7,
        ];
        assert_eq!(
            AccountIdentifier::from_slice(&bytes)
                .expect("Failed to parse bytes as principal")
                .as_bytes(),
            &bytes,
            "The account identifier doesn't change after going back and forth between a string"
        )
    }

    #[test]
    fn test_account_id_from_slice() {
        let length_27 = b"123456789_123456789_1234567".to_vec();
        assert_eq!(
            AccountIdentifier::from_slice(&length_27),
            Err(AccountIdParseError::InvalidLength(length_27))
        );

        let length_28 = b"123456789_123456789_12345678".to_vec();
        assert_eq!(
            AccountIdentifier::from_slice(&length_28),
            Ok(AccountIdentifier::try_from(
                <&[u8] as TryInto<[u8; 28]>>::try_into(&length_28).unwrap()
            )
            .unwrap())
        );

        let length_29 = b"123456789_123456789_123456789".to_vec();
        assert_eq!(
            AccountIdentifier::from_slice(&length_29),
            Err(AccountIdParseError::InvalidLength(length_29))
        );

        let length_32 = [0; 32].to_vec();
        assert_eq!(
            AccountIdentifier::from_slice(&length_32),
            Err(AccountIdParseError::InvalidChecksum(ChecksumError {
                input: length_32.try_into().unwrap(),
                expected_checksum: [128, 112, 119, 233],
                found_checksum: [0, 0, 0, 0],
            }))
        );

        // A 32-byte address with a valid checksum
        let length_32 = [
            128, 112, 119, 233, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0,
        ]
        .to_vec();
        assert_eq!(
            AccountIdentifier::from_slice(&length_32),
            Ok(AccountIdentifier::try_from(
                <&[u8] as TryInto<[u8; 28]>>::try_into(&[0u8; 28]).unwrap()
            )
            .unwrap())
        );
    }

    #[test]
    fn test_account_id_from_hex() {
        let length_56 = "00000000000000000000000000000000000000000000000000000000";
        let aid_bytes = [
            128, 112, 119, 233, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(
            AccountIdentifier::from_hex(length_56),
            Ok(AccountIdentifier(aid_bytes))
        );

        let length_57 = "000000000000000000000000000000000000000000000000000000000";
        assert!(AccountIdentifier::from_hex(length_57).is_err());

        let length_58 = "0000000000000000000000000000000000000000000000000000000000";
        assert_eq!(
            AccountIdentifier::from_hex(length_58),
            Err("0000000000000000000000000000000000000000000000000000000000 has a length of 58 but we expected a length of 64 or 56".to_string())
        );

        let length_64 = "0000000000000000000000000000000000000000000000000000000000000000";
        assert!(
            AccountIdentifier::from_hex(length_64)
                .unwrap_err()
                .contains("Checksum failed")
        );

        // Try again with correct checksum
        let length_64 = "807077e900000000000000000000000000000000000000000000000000000000";
        assert_eq!(
            AccountIdentifier::from_hex(length_64),
            Ok(AccountIdentifier(aid_bytes))
        );
    }
}
