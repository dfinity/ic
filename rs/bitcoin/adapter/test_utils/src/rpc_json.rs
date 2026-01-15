//! JSON types for Bitcoin daemon RPC API.
//!
//! Code in this module is adapted from https://github.com/rust-bitcoin/rust-bitcoincore-rpc/.
//! The original license is CC0.

use bitcoin::{Address, Amount, BlockHash, Network, ScriptBuf, Txid, address::NetworkUnchecked};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

type AddressUnchecked = Address<NetworkUnchecked>;

// Used for createrawtransaction argument.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRawTransactionInput {
    pub txid: Txid,
    pub vout: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetBalancesResultEntry {
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    pub trusted: Amount,
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    pub untrusted_pending: Amount,
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    pub immature: Amount,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBalancesResult {
    pub mine: GetBalancesResultEntry,
    pub watchonly: Option<GetBalancesResultEntry>,
}

/// Models the result of "getblockchaininfo"
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetBlockchainInfoResult {
    /// Current network name as defined in BIP70 (main, test, signet, regtest)
    #[serde(deserialize_with = "deserialize_bip70_network")]
    pub chain: Network,
    /// The current number of blocks processed in the server
    pub blocks: u64,
    /// The current number of headers we have validated
    pub headers: u64,
    /// The hash of the currently best block
    #[serde(rename = "bestblockhash")]
    pub best_block_hash: BlockHash,
    /// The current difficulty
    pub difficulty: f64,
    /// Median time for the current best block
    #[serde(rename = "mediantime")]
    pub median_time: u64,
    /// Estimate of verification progress [0..1]
    #[serde(rename = "verificationprogress")]
    pub verification_progress: f64,
    /// Estimate of whether this node is in Initial Block Download mode
    #[serde(rename = "initialblockdownload")]
    pub initial_block_download: bool,
    /// Total amount of work in active chain, in hexadecimal
    #[serde(rename = "chainwork", with = "serde_hex")]
    pub chain_work: Vec<u8>,
    /// The estimated size of the block and undo files on disk
    pub size_on_disk: u64,
    /// If the blocks are subject to pruning
    pub pruned: bool,
    /// Lowest-height complete block stored (only present if pruning is enabled)
    #[serde(rename = "pruneheight")]
    pub prune_height: Option<u64>,
    /// Whether automatic pruning is enabled (only present if pruning is enabled)
    pub automatic_pruning: Option<bool>,
    /// The target size used by pruning (only present if automatic pruning is enabled)
    pub prune_target_size: Option<u64>,
    /// Any network and blockchain warnings. In later versions of bitcoind, it's an array of strings.
    pub warnings: StringOrStringArray,
}

/// Used to represent values that can either be a string or a string array.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StringOrStringArray {
    String(String),
    StringArray(Vec<String>),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BtcGetMempoolEntryResult {
    /// Virtual transaction size as defined in BIP 141. This is different from actual serialized
    /// size for witness transactions as witness data is discounted.
    #[serde(alias = "size")]
    pub vsize: u64,
    /// Transaction weight as defined in BIP 141. Added in Core v0.19.0.
    pub weight: Option<u64>,
    /// Local time transaction entered pool in seconds since 1 Jan 1970 GMT
    pub time: u64,
    /// Block height when transaction entered pool
    pub height: u64,
    /// Number of in-mempool descendant transactions (including this one)
    #[serde(rename = "descendantcount")]
    pub descendant_count: u64,
    /// Virtual transaction size of in-mempool descendants (including this one)
    #[serde(rename = "descendantsize")]
    pub descendant_size: u64,
    /// Number of in-mempool ancestor transactions (including this one)
    #[serde(rename = "ancestorcount")]
    pub ancestor_count: u64,
    /// Virtual transaction size of in-mempool ancestors (including this one)
    #[serde(rename = "ancestorsize")]
    pub ancestor_size: u64,
    /// Hash of serialized transaction, including witness data
    pub wtxid: bitcoin::Txid,
    /// Fee information
    pub fees: GetMempoolEntryResultFees,
    /// Unconfirmed transactions used as inputs for this transaction
    pub depends: Vec<Txid>,
    /// Unconfirmed transactions spending outputs from this transaction
    #[serde(rename = "spentby")]
    pub spent_by: Vec<Txid>,
    /// Whether this transaction could be replaced due to BIP125
    #[serde(rename = "bip125-replaceable")]
    pub bip125_replaceable: bool,
    /// Whether this transaction is currently unbroadcast (initial broadcast not yet acknowledged by any peers)
    /// Added in Bitcoin Core v0.21
    pub unbroadcast: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetMempoolEntryResultFees {
    /// Transaction fee in BTC
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    pub base: Amount,
    /// Transaction fee with fee deltas used for mining priority in BTC
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    pub modified: Amount,
    /// Modified fees (see above) of in-mempool ancestors (including this one) in BTC
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    pub ancestor: Amount,
    /// Modified fees (see above) of in-mempool descendants (including this one) in BTC
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    pub descendant: Amount,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DogeGetMempoolEntryResult {
    /// Virtual transaction size as defined in BIP 141. This is different from actual serialized
    /// size for witness transactions as witness data is discounted.
    #[serde(alias = "size")]
    pub vsize: u64,
    /// Transaction weight as defined in BIP 141. Added in Core v0.19.0.
    pub weight: Option<u64>,
    /// Local time transaction entered pool in seconds since 1 Jan 1970 GMT
    pub time: u64,
    /// Block height when transaction entered pool
    pub height: u64,
    /// Number of in-mempool descendant transactions (including this one)
    #[serde(rename = "descendantcount")]
    pub descendant_count: u64,
    /// Virtual transaction size of in-mempool descendants (including this one)
    #[serde(rename = "descendantsize")]
    pub descendant_size: u64,
    /// Number of in-mempool ancestor transactions (including this one)
    #[serde(rename = "ancestorcount")]
    pub ancestor_count: u64,
    /// Virtual transaction size of in-mempool ancestors (including this one)
    #[serde(rename = "ancestorsize")]
    pub ancestor_size: u64,
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    /// Transaction fee.
    pub fee: Amount,
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    /// Transaction fee with fee deltas used for mining priority.
    pub modifiedfee: Amount,
    /// Modified fees (see above) of in-mempool ancestors (including this one).
    /// Dogecoin)
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    pub ancestorfees: Amount,
    /// Modified fees (see above) of in-mempool descendants (including this one).
    /// Dogecoin)
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    pub descendantfees: Amount,
    /// Unconfirmed transactions used as inputs for this transaction
    pub depends: Vec<Txid>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListUnspentResultEntry {
    pub txid: Txid,
    pub vout: u32,
    pub address: Option<AddressUnchecked>,
    pub label: Option<String>,
    pub redeem_script: Option<ScriptBuf>,
    pub witness_script: Option<ScriptBuf>,
    pub script_pub_key: ScriptBuf,
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    pub amount: Amount,
    pub confirmations: u32,
    pub spendable: bool,
    pub solvable: bool,
    #[serde(rename = "desc")]
    pub descriptor: Option<String>,
    pub safe: Option<bool>,
}

// Used for signrawtransaction argument.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignRawTransactionInput {
    pub txid: Txid,
    pub vout: u32,
    pub script_pub_key: ScriptBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redeem_script: Option<ScriptBuf>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "bitcoin::amount::serde::as_btc::opt"
    )]
    pub amount: Option<Amount>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignRawTransactionResultError {
    pub txid: Txid,
    pub vout: u32,
    pub script_sig: ScriptBuf,
    pub sequence: u32,
    pub error: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignRawTransactionResult {
    #[serde(with = "serde_hex")]
    pub hex: Vec<u8>,
    pub complete: bool,
    pub errors: Option<Vec<SignRawTransactionResultError>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LoadWalletResult {
    pub name: String,
    pub warning: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnloadWalletResult {
    pub warning: Option<String>,
}

/// deserialize_bip70_network deserializes a Bitcoin Core network according to BIP70
/// The accepted input variants are: {"main", "test", "signet", "regtest"}
fn deserialize_bip70_network<'de, D>(deserializer: D) -> Result<Network, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct NetworkVisitor;
    impl<'de> serde::de::Visitor<'de> for NetworkVisitor {
        type Value = Network;

        fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
            Network::from_str(s).map_err(|_| {
                E::invalid_value(
                    serde::de::Unexpected::Str(s),
                    &"bitcoin network encoded as a string",
                )
            })
        }

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "bitcoin network encoded as a string")
        }
    }

    deserializer.deserialize_str(NetworkVisitor)
}

/// A module used for serde serialization of bytes in hexadecimal format.
///
/// The module is compatible with the serde attribute.
pub mod serde_hex {
    pub use bitcoin::hex;

    use hex::{DisplayHex, FromHex};
    use serde::de::Error;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&b.to_lower_hex_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let hex_str: String = ::serde::Deserialize::deserialize(d)?;
        FromHex::from_hex(&hex_str).map_err(D::Error::custom)
    }
}
