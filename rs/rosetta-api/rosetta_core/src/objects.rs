use crate::models::Ed25519KeyPair;
use crate::models::RosettaSupportedKeyPair;
use crate::models::Secp256k1KeyPair;
use crate::{
    identifiers::{
        AccountIdentifier, BlockIdentifier, CoinIdentifier, NetworkIdentifier, OperationIdentifier,
        TransactionIdentifier,
    },
    miscellaneous::*,
};
use anyhow::bail;
use anyhow::Context;
use candid::Nat;
use candid::Principal;
use ic_types::PrincipalId;
use num_bigint::BigInt;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

pub type Object = serde_json::Value;
pub type ObjectMap = serde_json::map::Map<String, Object>;

/// Currency is composed of a canonical Symbol and Decimals. This Decimals value is used to convert an Amount.
/// Value from atomic units (Satoshis) to standard units (Bitcoins).
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Currency {
    /// Canonical symbol associated with a currency.
    pub symbol: String,

    /// Number of decimal places in the standard unit representation of the amount. For example, BTC has 8 decimals.
    /// Note that it is not possible to represent the value of some currency in atomic units that is not base 10.
    pub decimals: u32,

    /// Any additional information related to the currency itself. For example, it would be useful to populate this
    /// object with the contract address of an ERC-20 token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Object>,
}

impl Currency {
    pub fn new(symbol: String, decimals: u32) -> Currency {
        Currency {
            symbol,
            decimals,
            metadata: None,
        }
    }
}

/// Blocks contain an array of Transactions that occurred at a particular
/// BlockIdentifier.  A hard requirement for blocks returned by Rosetta
/// implementations is that they MUST be _inalterable_: once a client has
/// requested and received a block identified by a specific BlockIdentifier,
/// all future calls for that same BlockIdentifier must return the same block
/// contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    /// The block_identifier uniquely identifies a block in a particular network.
    pub block_identifier: BlockIdentifier,

    /// The block_identifier uniquely identifies a block in a particular network.
    pub parent_block_identifier: BlockIdentifier,

    /// The timestamp of the block in milliseconds since the Unix Epoch. The timestamp is stored in milliseconds because some blockchains produce blocks more often than once a second.
    pub timestamp: u64,

    pub transactions: Vec<Transaction>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ObjectMap>,
}

impl Block {
    pub fn new(
        block_identifier: BlockIdentifier,
        parent_block_identifier: BlockIdentifier,
        timestamp: u64,
        transactions: Vec<Transaction>,
    ) -> Block {
        Block {
            block_identifier,
            parent_block_identifier,
            timestamp,
            transactions,
            metadata: None,
        }
    }
}

/// Operations contain all balance-changing information within a transaction.
/// They are always one-sided (only affect 1 AccountIdentifier) and can succeed
/// or fail independently from a Transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Operation {
    /// The operation_identifier uniquely identifies an operation within a transaction.
    pub operation_identifier: OperationIdentifier,

    /// Restrict referenced related_operations to identifier indexes < the
    /// current operation_identifier.index. This ensures there exists a clear
    /// DAG-structure of relations.  Since operations are one-sided, one could
    /// imagine relating operations in a single transfer or linking operations
    /// in a call tree.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub related_operations: Option<Vec<OperationIdentifier>>,

    /// The network-specific type of the operation. Ensure that any type that
    /// can be returned here is also specified in the NetworkOptionsResponse.
    /// This can be very useful to downstream consumers that parse all block
    /// data.
    #[serde(rename = "type")]
    pub type_: String,

    /// The network-specific status of the operation. Status is not defined on
    /// the transaction object because blockchains with smart contracts may have
    /// transactions that partially apply.  Blockchains with atomic transactions
    /// (all operations succeed or all operations fail) will have the same
    /// status for each operation.
    pub status: Option<String>,

    /// The account_identifier uniquely identifies an account within a network. All fields in the account_identifier are utilized to determine this uniqueness (including the metadata field, if populated).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<AccountIdentifier>,

    /// Amount is some Value of a Currency. It is considered invalid to specify a Value without a Currency.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<Amount>,

    /// CoinChange is used to represent a change in state of a some coin identified by a coin_identifier. This object is part of the Operation model and must be populated for UTXO-based blockchains. Coincidentally, this abstraction of UTXOs allows for supporting both account-based transfers and UTXO-based transfers on the same blockchain (when a transfer is account-based, don't populate this model).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coin_change: Option<CoinChange>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ObjectMap>,
}

impl Operation {
    pub fn new(
        op_id: u64,
        _type: String,
        account: Option<AccountIdentifier>,
        amount: Option<Amount>,
        related_operations: Option<Vec<OperationIdentifier>>,
        metadata: Option<ObjectMap>,
    ) -> Operation {
        Operation {
            operation_identifier: OperationIdentifier::new(op_id),
            related_operations,
            type_: _type,
            status: None,
            account,
            amount,
            coin_change: None,
            metadata,
        }
    }
}

/// CoinChange is used to represent a change in state of a some coin identified
/// by a coin_identifier. This object is part of the Operation model and must be
/// populated for UTXO-based blockchains.  Coincidentally, this abstraction of
/// UTXOs allows for supporting both account-based transfers and UTXO-based
/// transfers on the same blockchain (when a transfer is account-based, don't
/// populate this model).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoinChange {
    /// CoinIdentifier uniquely identifies a Coin.
    pub coin_identifier: CoinIdentifier,

    /// CoinActions are different state changes that a Coin can undergo. When a Coin is created, it is coin_created. When a Coin is spent, it is coin_spent. It is assumed that a single Coin cannot be created or spent more than once.
    pub coin_action: CoinAction,
}

impl CoinChange {
    pub fn new(coin_identifier: CoinIdentifier, coin_action: CoinAction) -> CoinChange {
        CoinChange {
            coin_identifier,
            coin_action,
        }
    }
}

/// CoinActions are different state changes that a Coin can undergo. When a Coin
/// is created, it is coin_created. When a Coin is spent, it is coin_spent. It
/// is assumed that a single Coin cannot be created or spent more than once.
/// Enumeration of values.
/// Since this enum's variants do not hold data, we can easily define them
/// as `#[repr(C)]` which helps with FFI.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CoinAction {
    /// CoinAction indicating a Coin was created.
    #[serde(rename = "coin_created")]
    Created,

    /// CoinAction indicating a Coin was spent.
    #[serde(rename = "coin_spent")]
    Spent,
}

impl ::std::fmt::Display for CoinAction {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            CoinAction::Created => write!(f, "coin_created"),
            CoinAction::Spent => write!(f, "coin_spent"),
        }
    }
}

impl ::std::str::FromStr for CoinAction {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "coin_created" => Ok(CoinAction::Created),
            "coin_spent" => Ok(CoinAction::Spent),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelatedTransaction {
    /// The network_identifier specifies which network a particular object is associated with..
    pub network_identifier: NetworkIdentifier,

    /// The transaction_identifier uniquely identifies a transaction in a particular network and block or in the mempool..
    pub transaction_identifier: TransactionIdentifier,
    /// Used by RelatedTransaction to indicate the direction of the relation (i.e. cross-shard/cross-network sends may reference backward to an earlier transaction and async execution may reference forward). Can be used to indicate if a transaction relation is from child to parent or the reverse..
    pub direction: Direction,
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Direction {
    /// CoinAction indicating a Coin was created.
    #[serde(rename = "forward")]
    Forward,

    /// CoinAction indicating a Coin was spent.
    #[serde(rename = "backward")]
    Backward,
}

impl ::std::fmt::Display for Direction {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Direction::Forward => write!(f, "forward"),
            Direction::Backward => write!(f, "backward"),
        }
    }
}

impl ::std::str::FromStr for Direction {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "forward" => Ok(Direction::Forward),
            "backward" => Ok(Direction::Backward),
            _ => Err(()),
        }
    }
}

/// Transactions contain an array of Operations that are attributable to the
/// same TransactionIdentifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    /// The transaction_identifier uniquely identifies a transaction in a particular network and block or in the mempool.
    pub transaction_identifier: TransactionIdentifier,

    pub operations: Vec<Operation>,

    /// Transactions that are related to other transactions (like a cross-shard transaction) should include the tranaction_identifier of these transactions in the metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ObjectMap>,
}

impl Transaction {
    pub fn new(
        transaction_identifier: TransactionIdentifier,
        operations: Vec<Operation>,
    ) -> Transaction {
        Transaction {
            transaction_identifier,
            operations,
            metadata: None,
        }
    }
}

// Amount is some Value of a Currency. It is considered invalid to specify a
/// Value without a Currency.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Amount {
    /// Value of the transaction in atomic units represented as an
    /// arbitrary-sized signed integer.  For example, 1 BTC would be represented
    /// by a value of 100000000.
    pub value: String,

    /// Currency is composed of a canonical Symbol and Decimals. This Decimals value is used to convert an Amount.Value from atomic units (Satoshis) to standard units (Bitcoins).
    pub currency: Currency,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ObjectMap>,
}

impl Amount {
    pub fn new(value: BigInt, currency: Currency) -> Self {
        Self {
            value: value.to_string(),
            currency,
            metadata: None,
        }
    }
}

impl TryFrom<Amount> for Nat {
    type Error = anyhow::Error;
    fn try_from(value: Amount) -> std::prelude::v1::Result<Self, Self::Error> {
        Nat::from_str(match value.value.strip_prefix('-') {
            Some(value) => value,
            None => &value.value,
        })
        .with_context(|| format!("Failed to convert Amount to Nat: {:?}", value))
    }
}

/// Allow specifies supported Operation status, Operation types, and all possible error statuses.
/// This Allow object is used by clients to validate the correctness of a Rosetta Server implementation.
/// It is expected that these clients will error if they receive some response that contains any of
/// the above information that is not specified here.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Allow {
    /// All Operation.Status this implementation supports. Any status that is returned during parsing
    /// that is not listed here will cause client validation to error.
    pub operation_statuses: Vec<OperationStatus>,

    /// All Operation.Type this implementation supports. Any type that is returned during parsing
    /// that is not listed here will cause client validation to error.
    pub operation_types: Vec<String>,

    /// All Errors that this implementation could return. Any error that is returned during parsing
    /// that is not listed here will cause client validation to error.
    pub errors: Vec<Error>,

    /// Any Rosetta implementation that supports querying the balance of an account at any height in
    /// the past should set this to true.
    pub historical_balance_lookup: bool,

    /// If populated, timestamp_start_index indicates the first block index where block timestamps
    /// are considered valid (i.e. all blocks less than timestamp_start_index could have invalid timestamps).
    /// This is useful when the genesis block (or blocks) of a network have timestamp 0. If not populated,
    /// block timestamps are assumed to be valid for all available blocks.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp_start_index: Option<i64>,

    /// All methods that are supported by the /call endpoint. Communicating which parameters should be provided
    /// to /call is the responsibility of the implementer (this is en lieu of defining an entire type system
    /// and requiring the implementer to define that in Allow).
    pub call_methods: Vec<String>,

    /// BalanceExemptions is an array of BalanceExemption indicating which account balances could change without
    /// a corresponding Operation. BalanceExemptions should be used sparingly as they may introduce significant
    /// complexity for integrators that attempt to reconcile all account balance changes. If your implementation
    /// relies on any BalanceExemptions, you MUST implement historical balance lookup (the ability to query an
    /// account balance at any BlockIdentifier).
    pub balance_exemptions: Vec<BalanceExemption>,

    /// Any Rosetta implementation that can update an AccountIdentifier's unspent coins based on the contents
    /// of the mempool should populate this field as true. If false, requests to /account/coins that set
    /// include_mempool as true will be automatically rejected.
    pub mempool_coins: bool,

    /// Case specifies the expected case for strings and hashes.
    #[serde(
        default,
        with = "::serde_with::rust::double_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub block_hash_case: Option<Option<Case>>,

    /// Case specifies the expected case for strings and hashes.
    #[serde(
        default,
        with = "::serde_with::rust::double_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub transaction_hash_case: Option<Option<Case>>,
}

impl Allow {
    pub fn new(
        operation_statuses: Vec<OperationStatus>,
        operation_types: Vec<String>,
        errors: Vec<Error>,
        historical_balance_lookup: bool,
    ) -> Allow {
        Allow {
            operation_statuses,
            operation_types,
            errors,
            historical_balance_lookup,
            timestamp_start_index: None,
            call_methods: vec![],
            balance_exemptions: vec![],
            mempool_coins: false,
            block_hash_case: None,
            transaction_hash_case: None,
        }
    }
}

/// BalanceExemption indicates that the balance for an exempt account could change without a corresponding Operation.
/// This typically occurs with staking rewards, vesting balances, and Currencies with a dynamic supply.
/// Currently, it is possible to exempt an account from strict reconciliation by SubAccountIdentifier.Address or by Currency.
/// This means that any account with SubAccountIdentifier.Address would be exempt or any balance of a particular Currency would
/// be exempt, respectively. BalanceExemptions should be used sparingly as they may introduce significant complexity for
/// integrators that attempt to reconcile all account balance changes. If your implementation relies on any BalanceExemptions,
/// you MUST implement historical balance lookup (the ability to query an account balance at any BlockIdentifier).
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct BalanceExemption {
    /// SubAccountAddress is the SubAccountIdentifier.Address that the BalanceExemption applies
    /// to (regardless of the value of SubAccountIdentifier.Metadata).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_account_address: Option<String>,

    /// Currency is composed of a canonical Symbol and Decimals. This Decimals value is used to
    /// convert an Amount.Value from atomic units (Satoshis) to standard units (Bitcoins).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency: Option<Box<Currency>>,

    /// ExemptionType is used to indicate if the live balance for an account subject to a BalanceExemption
    /// could increase above, decrease below, or equal the computed balance. * greater_or_equal:
    /// The live balance may increase above or equal the computed balance. This typically occurs with staking
    /// rewards that accrue on each block. * less_or_equal: The live balance may decrease below or equal the computed balance.
    /// This typically occurs as balance moves from locked to spendable on a vesting account. * dynamic:
    /// The live balance may increase above, decrease below, or equal the computed balance.
    /// This typically occurs with tokens that have a dynamic supply.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exemption_type: Option<ExemptionType>,
}

/// ExemptionType is used to indicate if the live balance for an account subject to a BalanceExemption could increase above,
/// decrease below, or equal the computed balance.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub enum ExemptionType {
    /// The live balance may increase above or equal the computed balance. This typically occurs with staking rewards that accrue on each block.
    GreaterOrEqual,
    /// The live balance may decrease below or equal the computed balance. This typically occurs as balance moves from locked to spendable on a vesting account.
    LessOrEqual,
    /// The live balance may increase above, decrease below, or equal the computed balance. This typically occurs with tokens that have a dynamic supply.
    Dynamic,
}

impl Default for ExemptionType {
    fn default() -> ExemptionType {
        Self::GreaterOrEqual
    }
}

/// Case specifies the expected case for strings and hashes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Case {
    /// Lower Case hash
    UpperCase,
    /// Upper Case hash
    LowerCase,
    /// Case sensitive hash
    CaseSensitive,
    /// Case insensitive hash
    Null,
}

/// PublicKey contains a public key byte array for a particular CurveType
/// encoded in hex.  Note that there is no PrivateKey struct as this is NEVER
/// the concern of an implementation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PublicKey {
    /// Hex-encoded public key bytes in the format specified by the CurveType.
    pub hex_bytes: String,

    /// CurveType is the type of cryptographic curve associated with a PublicKey.
    pub curve_type: CurveType,
}

impl PublicKey {
    pub fn new(hex_bytes: String, curve_type: CurveType) -> PublicKey {
        PublicKey {
            hex_bytes,
            curve_type,
        }
    }

    pub fn get_der_encoding(&self) -> anyhow::Result<Vec<u8>> {
        match self.curve_type {
            CurveType::Edwards25519 => {
                Ed25519KeyPair::der_encode_pk(Ed25519KeyPair::hex_decode_pk(&self.hex_bytes)?)
            }
            CurveType::Secp256K1 => {
                Secp256k1KeyPair::der_encode_pk(Secp256k1KeyPair::hex_decode_pk(&self.hex_bytes)?)
            }
            _ => bail!("Curve Type {:?} is not supported", self.curve_type),
        }
    }

    pub fn get_principal(&self) -> anyhow::Result<Principal> {
        Ok(PrincipalId::new_self_authenticating(&self.get_der_encoding()?).0)
    }

    pub fn get_public_key(&self) -> anyhow::Result<Vec<u8>> {
        Ok(hex::decode(&self.hex_bytes)?)
    }
}

impl<T> From<&T> for PublicKey
where
    T: RosettaSupportedKeyPair,
{
    fn from(keypair: &T) -> Self {
        PublicKey {
            hex_bytes: keypair.hex_encode_pk(),
            curve_type: keypair.get_curve_type(),
        }
    }
}

/// CurveType is the type of cryptographic curve associated with a PublicKey.  * secp256k1: SEC compressed - `33 bytes` (https://secg.org/sec1-v2.pdf#subsubsection.2.3.3) * secp256r1: SEC compressed - `33 bytes` (https://secg.org/sec1-v2.pdf#subsubsection.2.3.3) * edwards25519: `y (255-bits) || x-sign-bit (1-bit)` - `32 bytes` (https://ed25519.cr.yp.to/ed25519-20110926.pdf) * tweedle: 1st pk : Fq.t (32 bytes) || 2nd pk : Fq.t (32 bytes) (https://github.com/CodaProtocol/coda/blob/develop/rfcs/0038-rosetta-construction-api.md#marshal-keys)
/// Enumeration of values.
/// Since this enum's variants do not hold data, we can easily define them them
/// as `#[repr(C)]` which helps with FFI.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CurveType {
    /// https://secg.org/sec1-v2.pdf#subsubsection.2.3.3
    #[serde(rename = "secp256k1")]
    Secp256K1,

    /// https://secg.org/sec1-v2.pdf#subsubsection.2.3.3
    #[serde(rename = "secp256r1")]
    Secp256R1,

    /// https://ed25519.cr.yp.to/ed25519-20110926.pdf
    #[serde(rename = "edwards25519")]
    Edwards25519,

    /// https://github.com/MinaProtocol/mina/blob/develop/rfcs/0038-rosetta-construction-api.md#marshal-keys
    #[serde(rename = "tweedle")]
    Tweedle,

    /// https://github.com/zcash/pasta
    #[serde(rename = "pallas")]
    Pallas,
}

impl ::std::fmt::Display for CurveType {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            CurveType::Secp256K1 => write!(f, "secp256k1"),
            CurveType::Secp256R1 => write!(f, "secp256r1"),
            CurveType::Edwards25519 => write!(f, "edwards25519"),
            CurveType::Tweedle => write!(f, "tweedle"),
            CurveType::Pallas => write!(f, "pallas"),
        }
    }
}

impl ::std::str::FromStr for CurveType {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "secp256k1" => Ok(CurveType::Secp256K1),
            "secp256r1" => Ok(CurveType::Secp256R1),
            "edwards25519" => Ok(CurveType::Edwards25519),
            "tweedle" => Ok(CurveType::Tweedle),
            "pallas" => Ok(CurveType::Pallas),
            _ => bail!("Invalid curve type: {}", s),
        }
    }
}

/// SigningPayload is signed by the client with the keypair associated with an
/// AccountIdentifier using the specified SignatureType.  SignatureType can be
/// optionally populated if there is a restriction on the signature scheme that
/// can be used to sign the payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningPayload {
    /// [DEPRECATED by `account_identifier` in `v1.4.4`] The network-specific
    /// address of the account that should sign the payload.
    #[serde(rename = "address")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,

    #[serde(rename = "account_identifier")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_identifier: Option<AccountIdentifier>,

    #[serde(rename = "hex_bytes")]
    pub hex_bytes: String,

    #[serde(rename = "signature_type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_type: Option<SignatureType>,
}

impl SigningPayload {
    pub fn new(hex_bytes: String) -> SigningPayload {
        SigningPayload {
            address: None,
            account_identifier: None,
            hex_bytes,
            signature_type: None,
        }
    }
}

/// SignatureType is the type of a cryptographic signature.  * ecdsa: `r (32-bytes) || s (32-bytes)` - `64 bytes` * ecdsa_recovery: `r (32-bytes) || s (32-bytes) || v (1-byte)` - `65 bytes` * ed25519: `R (32-byte) || s (32-bytes)` - `64 bytes` * schnorr_1: `r (32-bytes) || s (32-bytes)` - `64 bytes`  (schnorr signature implemented by Zilliqa where both `r` and `s` are scalars encoded as `32-bytes` values, most significant byte first.) * schnorr_poseidon: `r (32-bytes) || s (32-bytes)` where s = Hash(1st pk || 2nd pk || r) - `64 bytes`  (schnorr signature w/ Poseidon hash function implemented by O(1) Labs where both `r` and `s` are scalars encoded as `32-bytes` values, least significant byte first. https://github.com/CodaProtocol/signer-reference/blob/master/schnorr.ml )
/// Enumeration of values.
/// Since this enum's variants do not hold data, we can easily define them them
/// as `#[repr(C)]` which helps with FFI.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SignatureType {
    #[serde(rename = "ecdsa")]
    Ecdsa,
    #[serde(rename = "ecdsa_recovery")]
    EcdsaRecovery,
    #[serde(rename = "ed25519")]
    Ed25519,
    #[serde(rename = "schnorr_1")]
    Schnorr1,
    #[serde(rename = "schnorr_poseidon")]
    SchnorrPoseidon,
}

impl From<CurveType> for SignatureType {
    fn from(curve_type: CurveType) -> Self {
        match curve_type {
            CurveType::Secp256K1 => SignatureType::Ecdsa,
            CurveType::Secp256R1 => SignatureType::Ecdsa,
            CurveType::Edwards25519 => SignatureType::Ed25519,
            CurveType::Tweedle => SignatureType::Schnorr1,
            CurveType::Pallas => SignatureType::SchnorrPoseidon,
        }
    }
}

impl ::std::fmt::Display for SignatureType {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            SignatureType::Ecdsa => write!(f, "ecdsa"),
            SignatureType::EcdsaRecovery => write!(f, "ecdsa_recovery"),
            SignatureType::Ed25519 => write!(f, "ed25519"),
            SignatureType::Schnorr1 => write!(f, "schnorr_1"),
            SignatureType::SchnorrPoseidon => write!(f, "schnorr_poseidon"),
        }
    }
}

impl ::std::str::FromStr for SignatureType {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ecdsa" => Ok(SignatureType::Ecdsa),
            "ecdsa_recovery" => Ok(SignatureType::EcdsaRecovery),
            "ed25519" => Ok(SignatureType::Ed25519),
            "schnorr_1" => Ok(SignatureType::Schnorr1),
            "schnorr_poseidon" => Ok(SignatureType::SchnorrPoseidon),
            _ => Err(()),
        }
    }
}

/// Signature contains the payload that was signed, the public keys of the
/// keypairs used to produce the signature, the signature (encoded in hex), and
/// the SignatureType.  PublicKey is often times not known during construction
/// of the signing payloads but may be needed to combine signatures properly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    /// SigningPayload is signed by the client with the keypair associated with an AccountIdentifier using the specified SignatureType. SignatureType can be optionally populated if there is a restriction on the signature scheme that can be used to sign the payload.
    pub signing_payload: SigningPayload,

    /// PublicKey contains a public key byte array for a particular CurveType encoded in hex. Note that there is no PrivateKey struct as this is NEVER the concern of an implementation.
    pub public_key: PublicKey,

    /// SignatureType is the type of a cryptographic signature.
    pub signature_type: SignatureType,

    pub hex_bytes: String,
}

/// BlockTransaction contains a populated Transaction and the BlockIdentifier that contains it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockTransaction {
    /// The block_identifier uniquely identifies a block in a particular network.
    pub block_identifier: BlockIdentifier,

    /// Transactions contain an array of Operations that are attributable to the same TransactionIdentifier.
    pub transaction: Transaction,
}

/// Operator is used by query-related endpoints to determine how to apply
/// conditions. If this field is not populated, the default and value will be
/// used.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Operator {
    /// If any condition is satisfied, it is considered a match.
    #[serde(rename = "or")]
    Or,
    /// If all conditions are satisfied, it is considered a match.
    #[serde(rename = "and")]
    And,
}

impl ::std::fmt::Display for Operator {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Operator::Or => write!(f, "or"),
            Operator::And => write!(f, "and"),
        }
    }
}
