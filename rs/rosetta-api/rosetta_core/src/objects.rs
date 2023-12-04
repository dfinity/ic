use serde::{Deserialize, Serialize};
use std::fmt::Display;

pub type Object = serde_json::Value;
pub type ObjectMap = serde_json::map::Map<String, Object>;

/// Instead of utilizing HTTP status codes to describe node errors (which often
/// do not have a good analog), rich errors are returned using this object.
/// Both the code and message fields can be individually used to correctly
/// identify an error. Implementations MUST use unique values for both fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
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
