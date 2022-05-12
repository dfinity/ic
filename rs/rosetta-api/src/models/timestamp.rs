use crate::errors::ApiError;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::time::{SystemTime, UNIX_EPOCH};

/// The timestamp of the block in milliseconds since the Unix Epoch. The
/// timestamp is stored in milliseconds because some blockchains produce blocks
/// more often than once a second.
#[derive(Debug, Clone, PartialEq, PartialOrd, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct Timestamp(i64);

pub fn from_system_time(timestamp: SystemTime) -> Result<Timestamp, ApiError> {
    timestamp
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_millis())
        .ok()
        .and_then(|x| i64::try_from(x).ok())
        .map(Timestamp::from)
        .ok_or_else(|| {
            ApiError::internal_error(format!(
                "Could not create Timestamp from SystemTime: {:?}",
                timestamp
            ))
        })
}

impl ::std::convert::From<i64> for Timestamp {
    fn from(x: i64) -> Self {
        Timestamp(x)
    }
}

impl ::std::convert::From<Timestamp> for i64 {
    fn from(x: Timestamp) -> Self {
        x.0
    }
}

impl ::std::ops::Deref for Timestamp {
    type Target = i64;
    fn deref(&self) -> &i64 {
        &self.0
    }
}

impl ::std::ops::DerefMut for Timestamp {
    fn deref_mut(&mut self) -> &mut i64 {
        &mut self.0
    }
}
