use serde::{Deserialize, Serialize};
use std::{
    fmt::{Display, Formatter},
    num::ParseIntError,
    str::FromStr,
};

/// An identifier established by the Client that MUST contain a String, Number, or NULL value if included.
///
/// If it is not included it is assumed to be a notification.
/// The value SHOULD normally not be Null.
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Id {
    /// Numeric ID.
    Number(u64),

    /// String ID
    String(String),

    /// Null ID.
    ///
    /// The use of `Null` as a value for the id member in a Request object is discouraged,
    /// because this specification uses a value of Null for Responses with an unknown id.
    /// Also, because JSON-RPC 1.0 uses an id value of Null for Notifications this could cause confusion in handling.
    Null,
}

impl Id {
    /// Zero numeric ID.
    pub const ZERO: Id = Id::Number(0);

    /// Return `true` if and only if the [`Id`] is [`Id::Null`].
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }
}

impl<T: Into<u64>> From<T> for Id {
    fn from(value: T) -> Self {
        Id::Number(value.into())
    }
}

impl Display for Id {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Id::Number(id) => Display::fmt(id, f),
            Id::String(id) => Display::fmt(id, f),
            Id::Null => f.write_str("null"),
        }
    }
}

/// An identifier that uses the same number of bytes when serialized to JSON.
///
/// Having the same number of bytes for JSON-RPC request IDs ensures that
/// two JSON-RPC requests only differing by their IDs will have the same number of bytes once serialized.
/// Since the number of bytes of a serialized JSON-RPC request directly influences the
/// cycles cost of an HTTP outcall, two requests only differing by their IDs will therefore require the same amount of cycles,
/// which helps applications in estimating the cycle cost of their requests.
///
/// # Examples
///
/// ```rust
/// use canhttp::http::json::{ConstantSizeId, JsonRpcRequest};
///
/// let request_1 = JsonRpcRequest::new("getVersion", serde_json::Value::Null).with_id(ConstantSizeId::ZERO);
/// let request_2 = JsonRpcRequest::new("getVersion", serde_json::Value::Null).with_id(ConstantSizeId::MAX);
///
/// assert_eq!(
///     serde_json::to_vec(&request_1).unwrap().len(),
///     serde_json::to_vec(&request_2).unwrap().len()
/// );
/// ```
#[derive(Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct ConstantSizeId(u64);

impl<T: Into<u64>> From<T> for ConstantSizeId {
    fn from(value: T) -> Self {
        Self(value.into())
    }
}

impl Display for ConstantSizeId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.to_constant_size_string(), f)
    }
}

impl ConstantSizeId {
    /// Zero numeric ID.
    pub const ZERO: ConstantSizeId = ConstantSizeId(0);
    /// Largest ID.
    pub const MAX: ConstantSizeId = ConstantSizeId(u64::MAX);

    /// Increment the current value and return the previous value.
    ///
    /// If the maximum ID is reached, the next value will be wrapped to [`Self::ZERO`].
    /// This method never panics.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use canhttp::http::json::ConstantSizeId;
    ///
    /// let mut id = ConstantSizeId::ZERO;
    /// assert_eq!(id.get_and_increment(), 0_u64.into());
    /// assert_eq!(id.get_and_increment(), 1_u64.into());
    /// assert_eq!(id.get_and_increment(), 2_u64.into());
    ///
    /// let mut id = ConstantSizeId::MAX;
    /// assert_eq!(id.get_and_increment(), u64::MAX.into());
    /// assert_eq!(id.get_and_increment(), 0_u64.into());
    /// ```
    pub fn get_and_increment(&mut self) -> ConstantSizeId {
        let previous = self.0;
        self.0 = self.0.wrapping_add(1);
        ConstantSizeId::from(previous)
    }

    fn to_constant_size_string(&self) -> String {
        // Need at most 20 decimal characters to represent a u64:
        // 19 < log_10(u64::MAX) < 20
        format!("{:0>20}", self.0)
    }
}

impl From<ConstantSizeId> for Id {
    fn from(value: ConstantSizeId) -> Self {
        Id::String(value.to_string())
    }
}

impl FromStr for ConstantSizeId {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let num = match s.find(|c| c != '0') {
            Some(non_zero_index) => s[non_zero_index..].parse::<u64>(),
            None => s.parse::<u64>(),
        };
        num.map(ConstantSizeId::from)
    }
}
