use crate::objects::{Object, ObjectMap};
use anyhow::{anyhow, Context};
use candid::Principal;
use ic_types::{CanisterId, PrincipalId};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::str::FromStr;

/// The network_identifier specifies which network a particular object is
/// associated with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct NetworkIdentifier {
    pub blockchain: String,

    /// If a blockchain has a specific chain-id or network identifier, it should
    /// go in this field. It is up to the client to determine which
    /// network-specific identifier is mainnet or testnet.
    pub network: String,

    /// In blockchains with sharded state, the SubNetworkIdentifier is required to query some object on a specific shard.
    /// This identifier is optional for all non-sharded blockchains.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_network_identifier: Option<SubNetworkIdentifier>,
}

impl NetworkIdentifier {
    pub fn new(blockchain: String, network: String) -> NetworkIdentifier {
        NetworkIdentifier {
            blockchain,
            network,
            sub_network_identifier: None,
        }
    }
}

impl TryFrom<&NetworkIdentifier> for CanisterId {
    type Error = anyhow::Error;
    fn try_from(value: &NetworkIdentifier) -> Result<Self, Self::Error> {
        let principal_bytes: Vec<u8> =
            hex::decode(&value.network).context("Hex decoding of network string failed")?;
        let principal_id =
            PrincipalId::try_from(&principal_bytes).context("Invalid principal id")?;
        CanisterId::try_from(principal_id).context("Invalid canister id")
    }
}

/// In blockchains with sharded state, the SubNetworkIdentifier is required to
/// query some object on a specific shard. This identifier is optional for all
/// non-sharded blockchains.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubNetworkIdentifier {
    pub network: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Object>,
}

impl SubNetworkIdentifier {
    pub fn new(network: String) -> SubNetworkIdentifier {
        SubNetworkIdentifier {
            network,
            metadata: None,
        }
    }
}

/// The block_identifier uniquely identifies a block in a particular network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockIdentifier {
    /// This is also known as the block height.
    pub index: u64,

    /// This should be normalized according to the case specified in the block_hash_case network options.
    pub hash: String,
}

impl BlockIdentifier {
    pub fn new(index: u64, hash: String) -> BlockIdentifier {
        BlockIdentifier { index, hash }
    }
    pub fn from_bytes(index: u64, bytes: &ByteBuf) -> BlockIdentifier {
        BlockIdentifier {
            index,
            hash: hex::encode(bytes),
        }
    }
}

impl TryFrom<BlockIdentifier> for ByteBuf {
    type Error = anyhow::Error;
    fn try_from(value: BlockIdentifier) -> Result<Self, Self::Error> {
        Ok(ByteBuf::from(
            hex::decode(value.hash.clone()).with_context(|| {
                format!(
                    "Could not decode string format for BlockIdentifier: {}",
                    value.hash
                )
            })?,
        ))
    }
}

/// When fetching data by BlockIdentifier, it may be possible to only specify
/// the index or hash. If neither property is specified, it is assumed that the
/// client is making a request at the current block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PartialBlockIdentifier {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

impl PartialBlockIdentifier {
    pub fn new() -> PartialBlockIdentifier {
        PartialBlockIdentifier {
            index: None,
            hash: None,
        }
    }
}

impl From<BlockIdentifier> for PartialBlockIdentifier {
    fn from(value: BlockIdentifier) -> Self {
        Self {
            index: Some(value.index),
            hash: Some(value.hash),
        }
    }
}

/// Neuron management commands have no transaction identifier.
/// Since Rosetta requires a transaction identifier,
/// `None` is serialized to a transaction identifier with the hash
/// "Neuron management commands have no transaction identifier".
///
/// The transaction_identifier uniquely identifies a transaction in a particular
/// network and block or in the mempool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionIdentifier {
    /// Any transactions that are attributable only to a block (ex: a block event) should use the hash of the block as the identifier. This should be normalized according to the case specified in the transaction_hash_case in network options.
    pub hash: String,
}

impl TransactionIdentifier {
    pub fn from_bytes(bytes: &ByteBuf) -> TransactionIdentifier {
        TransactionIdentifier {
            hash: hex::encode(bytes),
        }
    }
}

impl TryFrom<TransactionIdentifier> for ByteBuf {
    type Error = anyhow::Error;

    fn try_from(value: TransactionIdentifier) -> Result<Self, Self::Error> {
        Ok(ByteBuf::from(
            hex::decode(value.hash.clone()).with_context(|| {
                format!(
                    "Could not decode string format for TransactionIdentifier: {}",
                    value.hash
                )
            })?,
        ))
    }
}

/// The operation_identifier uniquely identifies an operation within a
/// transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct OperationIdentifier {
    /// The operation index is used to ensure each operation has a unique
    /// identifier within a transaction. This index is only relative to the
    /// transaction and NOT GLOBAL. The operations in each transaction should
    /// start from index 0.  To clarify, there may not be any notion of an
    /// operation index in the blockchain being described.
    pub index: u64,

    /// Some blockchains specify an operation index that is essential for client
    /// use. For example, Bitcoin uses a network_index to identify which UTXO
    /// was used in a transaction.  network_index should not be populated if
    /// there is no notion of an operation index in a blockchain (typically most
    /// account-based blockchains).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_index: Option<u64>,
}

impl OperationIdentifier {
    pub fn new(index: u64) -> OperationIdentifier {
        OperationIdentifier {
            index,
            network_index: None,
        }
    }
}

/// The account_identifier uniquely identifies an account within a network. All
/// fields in the account_identifier are utilized to determine this uniqueness
/// (including the metadata field, if populated).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountIdentifier {
    /// The address may be a cryptographic public key (or some encoding of it)
    /// or a provided username.
    pub address: String,

    /// An account may have state specific to a contract address (ERC-20 token) and/or a stake (delegated balance). The sub_account_identifier should specify which state (if applicable) an account instantiation refers to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_account: Option<SubAccountIdentifier>,

    /// Blockchains that utilize a username model (where the address is not a
    /// derivative of a cryptographic public key) should specify the public
    /// key(s) owned by the address in metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ObjectMap>,
}

impl TryFrom<AccountIdentifier> for icrc_ledger_types::icrc1::account::Account {
    type Error = anyhow::Error;
    fn try_from(value: AccountIdentifier) -> Result<Self, Self::Error> {
        let subaccount: Option<[u8; 32]> = match value.sub_account.as_ref() {
            None => None,
            Some(sub_acc) => Some(hex::decode(&sub_acc.address)?.try_into().map_err(|_| {
                anyhow!(
                    "Could not convert subaccount to [u8;32] array: {:?}",
                    sub_acc
                )
            })?),
        };
        Ok(icrc_ledger_types::icrc1::account::Account {
            owner: Principal::from_str(&value.address).with_context(|| {
                format!(
                    "Unable to convert accountidentifier.address {:?} to Principal",
                    &value.address
                )
            })?,
            subaccount,
        })
    }
}

impl From<icrc_ledger_types::icrc1::account::Account> for AccountIdentifier {
    fn from(value: icrc_ledger_types::icrc1::account::Account) -> Self {
        Self {
            address: value.owner.to_string(),
            sub_account: Some(SubAccountIdentifier {
                address: hex::encode(value.effective_subaccount()),
                metadata: None,
            }),
            metadata: None,
        }
    }
}

impl From<icp_ledger::AccountIdentifier> for AccountIdentifier {
    fn from(value: icp_ledger::AccountIdentifier) -> Self {
        Self {
            address: value.to_hex(),
            sub_account: None,
            metadata: None,
        }
    }
}

impl TryFrom<AccountIdentifier> for icp_ledger::AccountIdentifier {
    type Error = anyhow::Error;
    fn try_from(value: AccountIdentifier) -> Result<Self, Self::Error> {
        icp_ledger::AccountIdentifier::from_hex(&value.address).map_err(|err| {
                anyhow!(
                    "Unable to convert accountidentifier.address {:?} to AccountIdentifier. Error: {:?}",
                    &value.address,
                    err
                )
            })
    }
}

/// An account may have state specific to a contract address (ERC-20 token)
/// and/or a stake (delegated balance). The sub_account_identifier should
/// specify which state (if applicable) an account instantiation refers to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubAccountIdentifier {
    /// The SubAccount address may be a cryptographic value or some other
    /// identifier (ex: bonded) that uniquely specifies a SubAccount.
    pub address: String,

    /// If the SubAccount address is not sufficient to uniquely specify a
    /// SubAccount, any other identifying information can be stored here.  It is
    /// important to note that two SubAccounts with identical addresses but
    /// differing metadata will not be considered equal by clients.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ObjectMap>,
}

/// CoinIdentifier uniquely identifies a Coin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoinIdentifier {
    /// Identifier should be populated with a globally unique identifier of a
    /// Coin. In Bitcoin, this identifier would be transaction_hash:index.
    pub identifier: String,
}

impl CoinIdentifier {
    pub fn new(identifier: String) -> CoinIdentifier {
        CoinIdentifier { identifier }
    }
}
