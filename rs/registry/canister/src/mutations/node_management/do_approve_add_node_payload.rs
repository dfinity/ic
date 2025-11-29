use std::fmt::Display;

use candid::CandidType;
use hex::FromHexError;
use prost::Message;
use serde::{Deserialize, Serialize};

static SHA256_BYTES_LEN: usize = 32;

#[derive(Clone, Eq, PartialEq, CandidType, Deserialize, Message, Serialize)]
pub struct ApproveAddNodePayload {
    /// Represents the hash of the payload sent by the
    /// node operator that will be used to map an incoming
    /// request from the node to register itself.
    #[prost(message, optional, tag = "1")]
    pub new_payload_hash_hex: Option<String>,
}

#[derive(Debug, PartialEq)]
pub enum ApprovePayloadError {
    InvalidPayloadHex(FromHexError),
    InvalidPayloadLength { received_length: usize },
}

impl Display for ApprovePayloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                ApprovePayloadError::InvalidPayloadLength { received_length } => format!(
                    "Received invalid payload. `new_payload_hash_hex` should contain {SHA256_BYTES_LEN} bytes, but got {received_length} bytes."
                ),
                ApprovePayloadError::InvalidPayloadHex(hex_error) =>
                    format!("Received invalid payload. Error from decoding hex bytes: {hex_error}"),
            }
        )
    }
}

impl ApproveAddNodePayload {
    pub fn validate(&self) -> Result<(), ApprovePayloadError> {
        let received_hex = self
            .new_payload_hash_hex
            .as_ref()
            .ok_or(ApprovePayloadError::InvalidPayloadLength { received_length: 0 })?;

        let received_bytes_len = hex::decode(received_hex)
            .map(|bytes| bytes.len())
            .map_err(ApprovePayloadError::InvalidPayloadHex)?;

        if received_bytes_len != SHA256_BYTES_LEN {
            return Err(ApprovePayloadError::InvalidPayloadLength {
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
            new_payload_hash_hex: None,
        };

        let result = payload.validate();

        let expected_err = ApprovePayloadError::InvalidPayloadLength { received_length: 0 };
        assert_eq!(result, Err(expected_err))
    }

    #[test]
    fn disallow_wrong_size_of_payloads() {
        for payload_size in [10, 42] {
            let payload = ApproveAddNodePayload {
                new_payload_hash_hex: Some("a".repeat(payload_size)),
            };

            let result = payload.validate();

            let expected_err = ApprovePayloadError::InvalidPayloadLength {
                // Two chars in a hex byte
                received_length: payload_size / 2,
            };

            assert_eq!(result, Err(expected_err))
        }
    }

    #[test]
    fn disallow_wrong_chars_in_hex() {
        for disallowed in 'g'..='z' {
            let payload = ApproveAddNodePayload {
                // No need to send over more than one byte as it is enough to fail
                new_payload_hash_hex: Some(disallowed.to_string().repeat(2)),
            };

            let result = payload.validate();

            let expected_err =
                ApprovePayloadError::InvalidPayloadHex(FromHexError::InvalidHexCharacter {
                    c: disallowed,
                    index: 0,
                });

            assert_eq!(result, Err(expected_err));
        }
    }

    #[test]
    fn valid_payload_size() {
        let payload = ApproveAddNodePayload {
            new_payload_hash_hex: Some("a".repeat(SHA256_BYTES_LEN * 2)),
        };

        let result = payload.validate();

        assert!(result.is_ok());
    }
}
