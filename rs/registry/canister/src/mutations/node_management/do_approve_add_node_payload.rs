use std::fmt::Display;

use candid::CandidType;
use ic_types::PrincipalId;
use prost::Message;
use serde::{Deserialize, Serialize};

#[derive(Clone, Eq, PartialEq, CandidType, Deserialize, Message, Serialize)]
pub struct ApproveAddNodePayload {
    /// Represents the expected node ID sent by the
    /// node operator that will be used to map an incoming
    /// request from the node to register itself.
    #[prost(message, optional, tag = "1")]
    pub node_id: Option<PrincipalId>,
}

#[derive(Debug, PartialEq)]
pub enum ApprovePayloadError {
    MissingNodeId,
}

impl Display for ApprovePayloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                ApprovePayloadError::MissingNodeId =>
                    "Received invalid payload. `node_id` must be specified.".to_string(),
            }
        )
    }
}

impl ApproveAddNodePayload {
    pub fn validate(&self) -> Result<(), ApprovePayloadError> {
        if self.node_id.is_none() {
            return Err(ApprovePayloadError::MissingNodeId);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disallow_empty_payload() {
        let payload = ApproveAddNodePayload { node_id: None };

        let result = payload.validate();

        let expected_err = ApprovePayloadError::MissingNodeId;
        assert_eq!(result, Err(expected_err))
    }

    #[test]
    fn valid_payload_size() {
        let payload = ApproveAddNodePayload {
            node_id: Some(PrincipalId::new_node_test_id(1)),
        };

        let result = payload.validate();

        assert!(result.is_ok());
    }
}
