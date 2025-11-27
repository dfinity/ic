use crate::objects::*;
use serde::{Deserialize, Serialize};
use std::fmt::Display;

/// SyncStatus is used to provide additional context about an implementation's
/// sync status. It is often used to indicate that an implementation is healthy
/// when it cannot be queried  until some sync phase occurs.  If an
/// implementation is immediately queryable, this model is often not populated.
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct SyncStatus {
    /// CurrentIndex is the index of the last synced block in the current stage. This is a separate field from current_block_identifier in NetworkStatusResponse because blocks with indices up to and including the current_index may not yet be queryable by the caller. To reiterate, all indices up to and including current_block_identifier in NetworkStatusResponse must be queryable via the /block endpoint (excluding indices less than oldest_block_identifier).
    pub current_index: i64,

    /// TargetIndex is the index of the block that the implementation is
    /// attempting to sync to in the current stage.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_index: Option<i64>,

    /// Stage is the phase of the sync process.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,

    /// synced is a boolean that indicates if an implementation has synced up to the most recent block. If this field is not populated, the caller should rely on a traditional tip timestamp comparison to determine if an implementation is synced. This field is particularly useful for quiescent blockchains (blocks only produced when there are pending transactions). In these blockchains, the most recent block could have a timestamp far behind the current time but the node could be healthy and at tip.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub synced: Option<bool>,
}

impl SyncStatus {
    pub fn new(current_index: i64, synced: Option<bool>) -> SyncStatus {
        SyncStatus {
            current_index,
            target_index: None,
            stage: None,
            synced,
        }
    }
}

/// A Peer is a representation of a node's peer.
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct Peer {
    pub peer_id: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ObjectMap>,
}

impl Peer {
    pub fn new(peer_id: String) -> Peer {
        Peer {
            peer_id,
            metadata: None,
        }
    }
}

/// OperationStatus is utilized to indicate which Operation status are considered successful.
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct OperationStatus {
    /// The status is the network-specific status of the operation.
    pub status: String,

    /// An Operation is considered successful if the Operation.Amount should affect the Operation.Account.
    /// Some blockchains (like Bitcoin) only include successful operations in blocks but other blockchains
    /// (like Ethereum) include unsuccessful operations that incur a fee. To reconcile the computed balance
    /// from the stream of Operations, it is critical to understand which Operation.
    /// Status indicate an Operation is successful and should affect an Account.
    pub successful: bool,
}

impl OperationStatus {
    pub fn new(status: String, successful: bool) -> OperationStatus {
        OperationStatus { status, successful }
    }
}

/// The Version object is utilized to inform the client of the versions of different components of the Rosetta implementation.
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct Version {
    /// The rosetta_version is the version of the Rosetta interface
    /// the implementation adheres to. This can be useful for clients looking to reliably parse responses.
    pub rosetta_version: String,

    /// The node_version is the canonical version of the node runtime. This can help clients manage deployments.
    pub node_version: String,

    /// When a middleware server is used to adhere to the Rosetta interface, it should return its version here.
    /// This can help clients manage deployments.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub middleware_version: Option<String>,

    /// Any other information that may be useful about versioning of dependent services should be returned here.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Object>,
}

impl Version {
    pub fn new(
        rosetta_version: String,
        node_version: String,
        middleware_version: Option<String>,
        metadata: Option<Object>,
    ) -> Version {
        Version {
            rosetta_version,
            node_version,
            middleware_version,
            metadata,
        }
    }
}

/// Instead of utilizing HTTP status codes to describe node errors (which often
/// do not have a good analog), rich errors are returned using this object.
/// Both the code and message fields can be individually used to correctly
/// identify an error. Implementations MUST use unique values for both fields.
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct Error {
    /// Code is a network-specific error code. If desired, this code can be
    /// equivalent to an HTTP status code.
    pub code: u32,

    /// Message is a network-specific error message.  The message MUST NOT
    /// change for a given code. In particular, this means that any contextual
    /// information should be included in the details field.
    pub message: String,

    /// Description allows the implementer to optionally provide additional
    /// information about an error. In many cases, the content of this field
    ///  will be a copy-and-paste from existing developer documentation.
    /// Description can ONLY be populated with generic information about a
    /// particular type of error. It MUST NOT be populated with information
    /// about a particular instantiation of an error (use details for this).
    /// Whereas the content of Error.Message should stay stable across releases,
    /// the content of Error.Description will likely change across releases
    /// (as implementers improve error documentation). For this reason,
    /// the content in this field is not part of any type assertion (unlike Error.Message).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// An error is retriable if the same request may succeed if submitted
    /// again.
    pub retriable: bool,

    /// Often times it is useful to return context specific to the request that
    /// caused the error (i.e. a sample of the stack trace or impacted account)
    /// in addition to the standard error message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<ObjectMap>,
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            serde_json::to_string(self)
                .expect("This should be impossible, all errors must be serializable")
        )
    }
}

impl From<hex::FromHexError> for Error {
    fn from(e: hex::FromHexError) -> Error {
        Error {
            code: 701,
            message: format!("Hex could not be decoded {e}"),
            description: None,
            retriable: false,
            details: None,
        }
    }
}

impl From<ic_secp256k1::KeyDecodingError> for Error {
    fn from(e: ic_secp256k1::KeyDecodingError) -> Error {
        Error {
            code: 701,
            message: "ecdsa_secp256k1 key could not be decoded!".to_string(),
            description: Some(format!("{e:?}")),
            retriable: false,
            details: None,
        }
    }
}
