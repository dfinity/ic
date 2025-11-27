use std::fmt::Display;

use candid::CandidType;
use prost::Message;
use serde::{Deserialize, Serialize};

static SHA256_BYTES_LEN: usize = 32;

#[derive(Clone, Eq, PartialEq, CandidType, Deserialize, Message, Serialize)]
pub struct ApproveAddNodePayload {
    /// Represents the hash of the payload sent by the
    /// node operator that will be used to map an incoming
    /// request from the node to register itself.
    #[prost(message, optional, tag = "1")]
    pub new_payload_hash: Option<Vec<u8>>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ApprovePayloadError {
    InvalidPayload { received_length: usize },
}

impl Display for ApprovePayloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                ApprovePayloadError::InvalidPayload { received_length } => format!(
                    "Received invalid payload. `new_payload_hash` should contain {SHA256_BYTES_LEN} bytes, but got {received_length} bytes."
                ),
            }
        )
    }
}

impl ApproveAddNodePayload {
    fn validate(&self) -> Result<(), ApprovePayloadError> {
        let received_bytes_len = self
            .new_payload_hash
            .as_ref()
            .map(|bytes| bytes.len())
            .ok_or(ApprovePayloadError::InvalidPayload { received_length: 0 })?;

        if received_bytes_len != SHA256_BYTES_LEN {
            return Err(ApprovePayloadError::InvalidPayload {
                received_length: received_bytes_len,
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disallow_empty_payload() {
        let payload = ApproveAddNodePayload {
            new_payload_hash: None,
        };

        let result = payload.validate();

        let expected_err = ApprovePayloadError::InvalidPayload { received_length: 0 };
        assert_eq!(result, Err(expected_err))
    }

    #[test]
    fn disallow_wrong_size_of_payloads() {
        for payload_size in [10, 42] {
            let payload = ApproveAddNodePayload {
                new_payload_hash: Some(vec![0; payload_size]),
            };

            let result = payload.validate();

            let expected_err = ApprovePayloadError::InvalidPayload {
                received_length: payload_size,
            };

            assert_eq!(result, Err(expected_err))
        }
    }

    #[test]
    fn valid_payload_size() {
        let payload = ApproveAddNodePayload {
            new_payload_hash: Some(vec![0; SHA256_BYTES_LEN]),
        };

        let result = payload.validate();

        assert!(result.is_ok());
    }
}
