use serde::{Deserialize, Serialize};
use std::fmt::Display;

pub type Object = serde_json::map::Map<String, serde_json::Value>;

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
    pub details: Option<Object>,
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
