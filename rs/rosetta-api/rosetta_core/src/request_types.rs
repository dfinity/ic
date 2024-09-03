use crate::identifiers::*;
use crate::objects::*;
use serde::{Deserialize, Serialize};

/// A MetadataRequest is utilized in any request where the only argument is
/// optional metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct MetadataRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Object>,
}

impl MetadataRequest {
    pub fn new() -> MetadataRequest {
        MetadataRequest { metadata: None }
    }
}

/// A NetworkRequest is utilized to retrieve some data specific exclusively to a NetworkIdentifier.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NetworkRequest {
    /// The network_identifier specifies which network a particular object is associated with.
    pub network_identifier: NetworkIdentifier,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Object>,
}

impl NetworkRequest {
    pub fn new(network_identifier: NetworkIdentifier) -> Self {
        Self {
            network_identifier,
            metadata: None,
        }
    }
}

/// A BlockRequest is utilized to make a block request on the /block endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockRequest {
    /// The network_identifier specifies which network a particular object is associated with.
    pub network_identifier: NetworkIdentifier,

    /// When fetching data by BlockIdentifier, it may be possible to only specify the index or hash. If neither property is specified, it is assumed that the client is making a request at the current block.
    pub block_identifier: PartialBlockIdentifier,
}

impl BlockRequest {
    pub fn new(
        network_identifier: NetworkIdentifier,
        block_identifier: PartialBlockIdentifier,
    ) -> BlockRequest {
        BlockRequest {
            network_identifier,
            block_identifier,
        }
    }
}

/// A BlockTransactionRequest is used to fetch a Transaction included in a block
/// that is not returned in a BlockResponse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockTransactionRequest {
    /// The network_identifier specifies which network a particular object is associated with.
    pub network_identifier: NetworkIdentifier,

    /// The block_identifier uniquely identifies a block in a particular network.
    pub block_identifier: BlockIdentifier,

    /// The transaction_identifier uniquely identifies a transaction in a particular network and block or in the mempool.
    pub transaction_identifier: TransactionIdentifier,
}

impl BlockTransactionRequest {
    pub fn new(
        network_identifier: NetworkIdentifier,
        block_identifier: BlockIdentifier,
        transaction_identifier: TransactionIdentifier,
    ) -> BlockTransactionRequest {
        BlockTransactionRequest {
            network_identifier,
            block_identifier,
            transaction_identifier,
        }
    }
}

/// A MempoolTransactionRequest is utilized to retrieve a transaction from the
/// mempool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MempoolTransactionRequest {
    /// The network_identifier specifies which network a particular object is associated with.
    #[serde(rename = "network_identifier")]
    pub network_identifier: NetworkIdentifier,

    /// The transaction_identifier uniquely identifies a transaction in a particular network and block or in the mempool.
    #[serde(rename = "transaction_identifier")]
    pub transaction_identifier: TransactionIdentifier,
}

impl MempoolTransactionRequest {
    pub fn new(
        network_identifier: NetworkIdentifier,
        transaction_identifier: TransactionIdentifier,
    ) -> MempoolTransactionRequest {
        MempoolTransactionRequest {
            network_identifier,
            transaction_identifier,
        }
    }
}

/// ConstructionDeriveRequest is passed to the `/construction/derive` endpoint.
/// Network is provided in the request because some blockchains have different
/// address formats for different networks. Metadata is provided in the request
/// because some blockchains allow for multiple address types (i.e. different
/// address for validators vs normal accounts).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstructionDeriveRequest {
    /// The network_identifier specifies which network a particular object is associated with.
    pub network_identifier: NetworkIdentifier,

    /// PublicKey contains a public key byte array for a particular CurveType encoded in hex. Note that there is no PrivateKey struct as this is NEVER the concern of an implementation.
    pub public_key: PublicKey,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ObjectMap>,
}

impl ConstructionDeriveRequest {
    pub fn new(
        network_identifier: NetworkIdentifier,
        public_key: PublicKey,
    ) -> ConstructionDeriveRequest {
        ConstructionDeriveRequest {
            network_identifier,
            public_key,
            metadata: None,
        }
    }
}

/// ConstructionPreprocessRequest is passed to the /construction/preprocess endpoint so that a Rosetta implementation can determine which metadata it needs to request for construction. Metadata provided in this object should NEVER be a product of live data (i.e. the caller must follow some network-specific data fetching strategy outside of the Construction API to populate required Metadata). If live data is required for construction, it MUST be fetched in the call to /construction/metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConstructionPreprocessRequest {
    // The network_identifier specifies which network a particular object is associated with.
    pub network_identifier: NetworkIdentifier,

    pub operations: Vec<Operation>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ObjectMap>,
}

impl ConstructionPreprocessRequest {
    pub fn new(
        network_identifier: NetworkIdentifier,
        operations: Vec<Operation>,
    ) -> ConstructionPreprocessRequest {
        ConstructionPreprocessRequest {
            network_identifier,
            operations,
            metadata: None,
        }
    }
}

/// A ConstructionMetadataRequest is utilized to get information required to
/// construct a transaction. The Options object used to specify which metadata
/// to return is left purposely unstructured to allow flexibility for
/// implementers.  Optionally, the request can also include an array of
/// PublicKeys associated with the AccountIdentifiers returned in
/// ConstructionPreprocessResponse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstructionMetadataRequest {
    // The network_identifier specifies which network a particular object is associated with.
    pub network_identifier: NetworkIdentifier,

    /// Some blockchains require different metadata for different types of
    /// transaction construction (ex: delegation versus a transfer). Instead of
    /// requiring a blockchain node to return all possible types of metadata for
    /// construction (which may require multiple node fetches), the client can
    /// populate an options object to limit the metadata returned to only the
    /// subset required.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub options: Option<ObjectMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_keys: Option<Vec<PublicKey>>,
}

impl ConstructionMetadataRequest {
    pub fn builder(network_identifier: NetworkIdentifier) -> ConstructionMetadataRequestBuilder {
        ConstructionMetadataRequestBuilder::new(network_identifier)
    }
}

pub struct ConstructionMetadataRequestBuilder {
    network_identifier: NetworkIdentifier,
    options: Option<ObjectMap>,
    public_keys: Option<Vec<PublicKey>>,
}

impl ConstructionMetadataRequestBuilder {
    pub fn new(network_identifier: NetworkIdentifier) -> ConstructionMetadataRequestBuilder {
        ConstructionMetadataRequestBuilder {
            network_identifier,
            options: None,
            public_keys: None,
        }
    }

    pub fn with_options(mut self, options: ObjectMap) -> Self {
        self.options = Some(options);
        self
    }

    pub fn build(self) -> ConstructionMetadataRequest {
        ConstructionMetadataRequest {
            network_identifier: self.network_identifier,
            options: self.options,
            public_keys: self.public_keys,
        }
    }
}

/// ConstructionPayloadsRequest is the request to `/construction/payloads`. It
/// contains the network, a slice of operations, and arbitrary metadata that was
/// returned by the call to `/construction/metadata`.  Optionally, the request
/// can also include an array of PublicKeys associated with the
/// AccountIdentifiers returned in ConstructionPreprocessResponse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstructionPayloadsRequest {
    pub network_identifier: NetworkIdentifier,

    pub operations: Vec<Operation>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ObjectMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_keys: Option<Vec<PublicKey>>,
}

impl ConstructionPayloadsRequest {
    pub fn new(
        network_identifier: NetworkIdentifier,
        operations: Vec<Operation>,
    ) -> ConstructionPayloadsRequest {
        ConstructionPayloadsRequest {
            network_identifier,
            operations,
            metadata: None,
            public_keys: None,
        }
    }
}

/// ConstructionParseRequest is the input to the `/construction/parse` endpoint.
/// It allows the caller to parse either an unsigned or signed transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstructionParseRequest {
    /// The network_identifier specifies which network a particular object is associated with.
    pub network_identifier: NetworkIdentifier,

    /// Signed is a boolean indicating whether the transaction is signed.
    pub signed: bool,

    /// This must be either the unsigned transaction blob returned by
    /// `/construction/payloads` or the signed transaction blob returned by
    /// `/construction/combine`.
    pub transaction: String,
}

impl ConstructionParseRequest {
    pub fn new(
        network_identifier: NetworkIdentifier,
        signed: bool,
        transaction: String,
    ) -> ConstructionParseRequest {
        ConstructionParseRequest {
            network_identifier,
            signed,
            transaction,
        }
    }
}

/// ConstructionCombineRequest is the input to the `/construction/combine`
/// endpoint. It contains the unsigned transaction blob returned by
/// `/construction/payloads` and all required signatures to create a network
/// transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstructionCombineRequest {
    /// The network_identifier specifies which network a particular object is associated with.
    pub network_identifier: NetworkIdentifier,

    /// CBOR+hex-encoded 'UnsignedTransaction'
    pub unsigned_transaction: String,

    pub signatures: Vec<Signature>,
}

/// The transaction submission request includes a signed transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstructionSubmitRequest {
    pub network_identifier: NetworkIdentifier,

    // = CBOR+hex-encoded 'SignedTransaction'
    pub signed_transaction: String,
}

impl ConstructionSubmitRequest {
    pub fn new(
        network_identifier: NetworkIdentifier,
        signed_transaction: String,
    ) -> ConstructionSubmitRequest {
        ConstructionSubmitRequest {
            network_identifier,
            signed_transaction,
        }
    }
}

/// An AccountBalanceRequest is utilized to make a balance request on the
/// /account/balance endpoint. If the block_identifier is populated, a
/// historical balance query should be performed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountBalanceRequest {
    #[serde(rename = "network_identifier")]
    pub network_identifier: NetworkIdentifier,

    #[serde(rename = "account_identifier")]
    pub account_identifier: AccountIdentifier,

    #[serde(rename = "block_identifier")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_identifier: Option<PartialBlockIdentifier>,

    #[serde(rename = "metadata")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ObjectMap>,
}

impl AccountBalanceRequest {
    pub fn builder(
        network_identifier: NetworkIdentifier,
        account_identifier: AccountIdentifier,
    ) -> AccountBalanceRequestBuilder {
        AccountBalanceRequestBuilder::new(network_identifier, account_identifier)
    }
}

pub struct AccountBalanceRequestBuilder {
    network_identifier: NetworkIdentifier,
    account_identifier: AccountIdentifier,
    block_identifier: Option<PartialBlockIdentifier>,
}

impl AccountBalanceRequestBuilder {
    pub fn new(
        network_identifier: NetworkIdentifier,
        account_identifier: AccountIdentifier,
    ) -> AccountBalanceRequestBuilder {
        AccountBalanceRequestBuilder {
            network_identifier,
            account_identifier,
            block_identifier: None,
        }
    }

    pub fn with_block_index(mut self, block_index: u64) -> Self {
        match self.block_identifier {
            Some(ref mut block_identifier) => {
                block_identifier.index = Some(block_index);
            }
            None => {
                self.block_identifier = Some(PartialBlockIdentifier {
                    index: Some(block_index),
                    hash: None,
                });
            }
        }
        self
    }

    pub fn build(self) -> AccountBalanceRequest {
        AccountBalanceRequest {
            network_identifier: self.network_identifier,
            account_identifier: self.account_identifier,
            block_identifier: self.block_identifier,
            metadata: None,
        }
    }
}

/// ConstructionHashRequest is the input to the `/construction/hash` endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstructionHashRequest {
    pub network_identifier: NetworkIdentifier,

    pub signed_transaction: String,
}

/// SearchTransactionsRequest models a small subset of the /search/transactions
/// endpoint. Currently we only support looking up a transaction given its hash;
/// this functionality is desired by our crypto exchanges partners.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SearchTransactionsRequest {
    #[serde(rename = "network_identifier")]
    pub network_identifier: NetworkIdentifier,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub operator: Option<Operator>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_block: Option<i64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<i64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_identifier: Option<TransactionIdentifier>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_identifier: Option<AccountIdentifier>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub coin_identifier: Option<CoinIdentifier>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency: Option<Currency>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub success: Option<bool>,
}

impl SearchTransactionsRequest {
    pub fn builder(network_identifier: NetworkIdentifier) -> SearchTransactionsRequestBuilder {
        SearchTransactionsRequestBuilder::new(network_identifier)
    }
}

pub struct SearchTransactionsRequestBuilder {
    network_identifier: NetworkIdentifier,
    operator: Option<Operator>,
    max_block: Option<i64>,
    offset: Option<i64>,
    limit: Option<i64>,
    transaction_identifier: Option<TransactionIdentifier>,
    account_identifier: Option<AccountIdentifier>,
    coin_identifier: Option<CoinIdentifier>,
    currency: Option<Currency>,
    status: Option<String>,
    type_: Option<String>,
    address: Option<String>,
    success: Option<bool>,
}

impl SearchTransactionsRequestBuilder {
    pub fn new(network_identifier: NetworkIdentifier) -> SearchTransactionsRequestBuilder {
        SearchTransactionsRequestBuilder {
            network_identifier,
            operator: None,
            max_block: None,
            offset: None,
            limit: None,
            transaction_identifier: None,
            account_identifier: None,
            coin_identifier: None,
            currency: None,
            status: None,
            type_: None,
            address: None,
            success: None,
        }
    }

    pub fn with_transaction_identifier(
        mut self,
        transaction_identifier: TransactionIdentifier,
    ) -> Self {
        self.transaction_identifier = Some(transaction_identifier);
        self
    }

    pub fn with_account_identifier(mut self, account_identifier: AccountIdentifier) -> Self {
        self.account_identifier = Some(account_identifier);
        self
    }

    pub fn build(self) -> SearchTransactionsRequest {
        SearchTransactionsRequest {
            network_identifier: self.network_identifier,
            operator: self.operator,
            max_block: self.max_block,
            offset: self.offset,
            limit: self.limit,
            transaction_identifier: self.transaction_identifier,
            account_identifier: self.account_identifier,
            coin_identifier: self.coin_identifier,
            currency: self.currency,
            status: self.status,
            type_: self.type_,
            address: self.address,
            success: self.success,
        }
    }
}

/// CallRequest is the input to the `/call`
/// endpoint. It contains the method name the user wants to call and some parameters specific for the method call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallRequest {
    #[serde(rename = "network_identifier")]
    pub network_identifier: NetworkIdentifier,

    /// Method is some network-specific procedure call. This method could map to a network-specific RPC endpoint, a method in an SDK generated from a smart contract, or some hybrid of the two. The implementation must define all available methods in the Allow object. However, it is up to the caller to determine which parameters to provide when invoking /call.
    #[serde(rename = "method_name")]
    pub method_name: String,

    /// Parameters is some network-specific argument for a method. It is up to the caller to determine which parameters to provide when invoking /call.
    #[serde(rename = "parameters")]
    pub parameters: ObjectMap,
}

impl CallRequest {
    pub fn new(
        network_identifier: NetworkIdentifier,
        method_name: String,
        parameters: ObjectMap,
    ) -> CallRequest {
        CallRequest {
            network_identifier,
            method_name,
            parameters,
        }
    }
}
