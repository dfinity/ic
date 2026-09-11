use ic_base_types::NumBytes;
use ic_protobuf::proxy::{ProxyDecodeError, try_from_option_field};
use ic_protobuf::types::v1 as pb;
use pb::upgrade_action::Action;
use std::collections::BTreeMap;

use super::{iterator_to_bytes, slice_to_messages};
use crate::consensus::UpgradePermitAuthorizationRequest;
use crate::consensus::upgrade::UpgradePermitAction;
use crate::signature::{BasicSignature, BasicSignatureBatch};

/// Serializes a list of [`UpgradePermitAction`]s to a length-delimited protobuf
/// stream, respecting the `max_size` budget. Actions that don't fit are
/// silently dropped.
pub fn upgrade_payload_to_bytes(actions: Vec<UpgradePermitAction>, max_size: NumBytes) -> Vec<u8> {
    let message_iterator = actions.into_iter().map(pb::UpgradeAction::from);
    iterator_to_bytes(message_iterator, max_size)
}

/// Deserializes a length-delimited protobuf stream into a list of
/// [`UpgradePermitAction`]s. An empty byte slice yields an empty list.
pub fn bytes_to_upgrade_payload(data: &[u8]) -> Result<Vec<UpgradePermitAction>, ProxyDecodeError> {
    let messages: Vec<pb::UpgradeAction> =
        slice_to_messages(data).map_err(ProxyDecodeError::DecodeError)?;
    messages
        .into_iter()
        .map(UpgradePermitAction::try_from)
        .collect()
}

impl From<UpgradePermitAction> for pb::UpgradeAction {
    fn from(action: UpgradePermitAction) -> Self {
        let proto_action = match action {
            UpgradePermitAction::Request(request) => {
                Action::RequestPermit(pb::RequestUpgradePermit {
                    request: Some(pb::UpgradePermitRequest::from(request)),
                })
            }
            UpgradePermitAction::Authorize {
                request,
                signatures,
            } => Action::AuthorizePermit(pb::AuthorizeUpgradePermit {
                request: Some(pb::UpgradePermitRequest::from(request)),
                signatures: signatures
                    .signatures_map
                    .into_iter()
                    .map(|(signer, signature)| {
                        pb::BasicSignature::from(BasicSignature { signature, signer })
                    })
                    .collect(),
            }),
            UpgradePermitAction::Return { node } => Action::ReturnPermit(pb::ReturnUpgradePermit {
                node: Some(crate::node_id_into_protobuf(node)),
            }),
        };
        Self {
            action: Some(proto_action),
        }
    }
}

impl TryFrom<pb::UpgradeAction> for UpgradePermitAction {
    type Error = ProxyDecodeError;

    fn try_from(proto: pb::UpgradeAction) -> Result<Self, Self::Error> {
        let action = proto
            .action
            .ok_or(ProxyDecodeError::MissingField("UpgradeAction::action"))?;
        Ok(match action {
            Action::RequestPermit(request) => UpgradePermitAction::Request(try_from_option_field(
                request.request,
                "RequestUpgradePermit::request",
            )?),
            Action::AuthorizePermit(authorize) => UpgradePermitAction::Authorize {
                request: try_from_option_field(
                    authorize.request,
                    "AuthorizeUpgradePermit::request",
                )?,
                signatures: signature_batch(authorize.signatures)?,
            },
            Action::ReturnPermit(return_permit) => UpgradePermitAction::Return {
                node: crate::node_id_try_from_option(return_permit.node)?,
            },
        })
    }
}

/// Decodes a list of basic signatures over the same content into a
/// [`BasicSignatureBatch`], rejecting duplicate signers.
fn signature_batch(
    signatures: Vec<pb::BasicSignature>,
) -> Result<BasicSignatureBatch<UpgradePermitAuthorizationRequest>, ProxyDecodeError> {
    let mut signatures_map = BTreeMap::new();
    for signature in signatures {
        let signature: BasicSignature<UpgradePermitAuthorizationRequest> = signature.try_into()?;
        if signatures_map
            .insert(signature.signer, signature.signature)
            .is_some()
        {
            return Err(ProxyDecodeError::DuplicateEntry {
                key: format!("{:?}", signature.signer),
                v1: "signature".to_string(),
                v2: "signature".to_string(),
            });
        }
    }
    Ok(BasicSignatureBatch { signatures_map })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Height;
    use crate::NodeId;
    use ic_base_types::PrincipalId;

    fn node(node_index: u64) -> NodeId {
        NodeId::from(PrincipalId::new_node_test_id(node_index))
    }

    #[test]
    fn test_round_trip_request() {
        let actions = vec![UpgradePermitAction::Request(
            UpgradePermitAuthorizationRequest {
                requestor: node(3),
                request_height: Height::new(42),
            },
        )];
        let bytes = upgrade_payload_to_bytes(actions.clone(), NumBytes::new(u64::MAX));
        let decoded = bytes_to_upgrade_payload(&bytes).unwrap();
        assert_eq!(actions, decoded);
    }

    #[test]
    fn test_round_trip_authorize() {
        let actions = vec![UpgradePermitAction::Authorize {
            request: UpgradePermitAuthorizationRequest {
                requestor: node(5),
                request_height: Height::new(3),
            },
            signatures: BasicSignatureBatch {
                signatures_map: BTreeMap::new(),
            },
        }];
        let bytes = upgrade_payload_to_bytes(actions.clone(), NumBytes::new(u64::MAX));
        let decoded = bytes_to_upgrade_payload(&bytes).unwrap();
        assert_eq!(actions, decoded);
    }

    #[test]
    fn test_round_trip_return() {
        let actions = vec![UpgradePermitAction::Return { node: node(7) }];
        let bytes = upgrade_payload_to_bytes(actions.clone(), NumBytes::new(u64::MAX));
        let decoded = bytes_to_upgrade_payload(&bytes).unwrap();
        assert_eq!(actions, decoded);
    }

    #[test]
    fn test_round_trip_empty() {
        let bytes = upgrade_payload_to_bytes(vec![], NumBytes::new(u64::MAX));
        assert!(bytes.is_empty());
        let decoded = bytes_to_upgrade_payload(&bytes).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_round_trip_multiple_actions() {
        let actions = vec![
            UpgradePermitAction::Request(UpgradePermitAuthorizationRequest {
                requestor: node(1),
                request_height: Height::new(10),
            }),
            UpgradePermitAction::Authorize {
                request: UpgradePermitAuthorizationRequest {
                    requestor: node(2),
                    request_height: Height::new(4),
                },
                signatures: BasicSignatureBatch {
                    signatures_map: BTreeMap::new(),
                },
            },
            UpgradePermitAction::Return { node: node(3) },
        ];
        let bytes = upgrade_payload_to_bytes(actions.clone(), NumBytes::new(u64::MAX));
        let decoded = bytes_to_upgrade_payload(&bytes).unwrap();
        assert_eq!(actions, decoded);
    }

    #[test]
    fn test_max_size_drops_overflow() {
        // With max_size = 0, no actions should be encoded.
        let actions = vec![UpgradePermitAction::Return { node: node(1) }];
        let bytes = upgrade_payload_to_bytes(actions, NumBytes::new(0));
        assert!(bytes.is_empty());
    }
}
