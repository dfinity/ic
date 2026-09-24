use ic_base_types::NumBytes;
use ic_protobuf::proxy::{ProxyDecodeError, try_from_option_field};
use ic_protobuf::types::v1 as pb;
use pb::upgrade_permit_action::Action;
use std::collections::BTreeMap;

use super::{iterator_to_bytes, slice_to_messages};
use crate::consensus::UpgradePermitRequest;
use crate::consensus::upgrade::UpgradePermitAction;
use crate::crypto::Signed;
use crate::signature::{BasicSignature, BasicSignatureBatch};

/// The upgrade permit actions of a block's batch payload.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Default)]
pub struct UpgradePayload {
    pub actions: Vec<UpgradePermitAction>,
}

impl UpgradePayload {
    /// Serialize this payload into a vector.
    ///
    /// This function will drop actions that do not fit to guarantee that the
    /// payload fits into the `byte_limit`. Smaller actions after a dropped
    /// action can still be included.
    pub fn serialize_with_limit(&self, byte_limit: NumBytes) -> Vec<u8> {
        iterator_to_bytes(
            self.actions.iter().map(pb::UpgradePermitAction::from),
            byte_limit,
        )
    }

    /// Deserializes an [`UpgradePayload`]. An empty byte slice yields an empty
    /// payload.
    pub fn deserialize(data: &[u8]) -> Result<Self, ProxyDecodeError> {
        let messages: Vec<pb::UpgradePermitAction> =
            slice_to_messages(data).map_err(ProxyDecodeError::DecodeError)?;
        Ok(Self {
            actions: messages
                .into_iter()
                .map(UpgradePermitAction::try_from)
                .collect::<Result<_, _>>()?,
        })
    }
}

impl From<&UpgradePermitAction> for pb::UpgradePermitAction {
    fn from(action: &UpgradePermitAction) -> Self {
        let proto_action = match action {
            UpgradePermitAction::RequestPermit(request) => {
                Action::RequestPermit(pb::RequestUpgradePermit {
                    request: Some(pb::UpgradePermitRequest::from(request)),
                })
            }
            UpgradePermitAction::AuthorizePermit(authorization) => {
                Action::AuthorizePermit(pb::AuthorizeUpgradePermit {
                    request: Some(pb::UpgradePermitRequest::from(&authorization.content)),
                    signatures: authorization
                        .signature
                        .signatures_map
                        .iter()
                        .map(|(signer, signature)| {
                            pb::BasicSignature::from(BasicSignature {
                                signature: signature.clone(),
                                signer: *signer,
                            })
                        })
                        .collect(),
                })
            }
            UpgradePermitAction::ReturnPermit { node } => {
                Action::ReturnPermit(pb::ReturnUpgradePermit {
                    node: Some(crate::node_id_into_protobuf(*node)),
                })
            }
        };
        Self {
            action: Some(proto_action),
        }
    }
}

impl TryFrom<pb::UpgradePermitAction> for UpgradePermitAction {
    type Error = ProxyDecodeError;

    fn try_from(proto: pb::UpgradePermitAction) -> Result<Self, Self::Error> {
        let action = proto.action.ok_or(ProxyDecodeError::MissingField(
            "UpgradePermitAction::action",
        ))?;
        Ok(match action {
            Action::RequestPermit(request) => UpgradePermitAction::RequestPermit(
                try_from_option_field(request.request, "RequestUpgradePermit::request")?,
            ),
            Action::AuthorizePermit(authorize) => UpgradePermitAction::AuthorizePermit(Signed {
                content: try_from_option_field(
                    authorize.request,
                    "AuthorizeUpgradePermit::request",
                )?,
                signature: signature_batch(authorize.signatures)?,
            }),
            Action::ReturnPermit(return_permit) => UpgradePermitAction::ReturnPermit {
                node: crate::node_id_try_from_option(return_permit.node)?,
            },
        })
    }
}

/// Decodes a list of basic signatures over the same content into a
/// [`BasicSignatureBatch`], rejecting duplicate signers.
fn signature_batch(
    signatures: Vec<pb::BasicSignature>,
) -> Result<BasicSignatureBatch<UpgradePermitRequest>, ProxyDecodeError> {
    let mut signatures_map = BTreeMap::new();
    for signature in signatures {
        let signature: BasicSignature<UpgradePermitRequest> = signature.try_into()?;
        if let Some(previous) = signatures_map.insert(signature.signer, signature.signature) {
            // Unwrap is fine, entry has just been inserted
            let new = signatures_map.get(&signature.signer).unwrap();
            return Err(ProxyDecodeError::DuplicateEntry {
                key: format!("{:?}", signature.signer),
                v1: format!("{previous:?}"),
                v2: format!("{new:?}"),
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
    use crate::crypto::{BasicSig, BasicSigOf};
    use ic_base_types::PrincipalId;

    fn node(node_index: u64) -> NodeId {
        NodeId::from(PrincipalId::new_node_test_id(node_index))
    }

    fn round_trip(payload: UpgradePayload) {
        let bytes = payload.serialize_with_limit(NumBytes::new(u64::MAX));
        let decoded = UpgradePayload::deserialize(&bytes).unwrap();
        assert_eq!(payload, decoded);
    }

    #[test]
    fn test_round_trip_request() {
        round_trip(UpgradePayload {
            actions: vec![UpgradePermitAction::RequestPermit(UpgradePermitRequest {
                requestor: node(3),
                request_height: Height::new(42),
            })],
        });
    }

    #[test]
    fn test_round_trip_authorize() {
        round_trip(UpgradePayload {
            actions: vec![UpgradePermitAction::AuthorizePermit(Signed {
                content: UpgradePermitRequest {
                    requestor: node(5),
                    request_height: Height::new(3),
                },
                signature: BasicSignatureBatch {
                    signatures_map: BTreeMap::new(),
                },
            })],
        });
    }

    #[test]
    fn test_round_trip_return() {
        round_trip(UpgradePayload {
            actions: vec![UpgradePermitAction::ReturnPermit { node: node(7) }],
        });
    }

    #[test]
    fn test_round_trip_empty() {
        round_trip(UpgradePayload { actions: vec![] });
    }

    #[test]
    fn test_serialize_with_limit_drops_overflow() {
        // A limit of 0 cannot fit any action, so nothing is serialized.
        let payload = UpgradePayload {
            actions: vec![UpgradePermitAction::ReturnPermit { node: node(1) }],
        };
        assert!(payload.serialize_with_limit(NumBytes::new(0)).is_empty());
    }

    #[test]
    fn test_serialize_with_limit_skips_actions_that_do_not_fit() {
        // The authorize action does not fit the limit, but the smaller return
        // action after it still does.
        let payload = UpgradePayload {
            actions: vec![
                UpgradePermitAction::AuthorizePermit(Signed {
                    content: UpgradePermitRequest {
                        requestor: node(1),
                        request_height: Height::new(4),
                    },
                    signature: BasicSignatureBatch {
                        signatures_map: BTreeMap::from([(
                            node(2),
                            BasicSigOf::new(BasicSig(vec![0x42; 64])),
                        )]),
                    },
                }),
                UpgradePermitAction::ReturnPermit { node: node(3) },
            ],
        };
        let return_entry_len = UpgradePayload {
            actions: vec![UpgradePermitAction::ReturnPermit { node: node(3) }],
        }
        .serialize_with_limit(NumBytes::new(u64::MAX))
        .len();
        let bytes = payload.serialize_with_limit(NumBytes::new(return_entry_len as u64));
        let decoded = UpgradePayload::deserialize(&bytes).unwrap();
        assert_eq!(
            decoded.actions,
            vec![UpgradePermitAction::ReturnPermit { node: node(3) }]
        );
    }

    #[test]
    fn test_round_trip_multiple_actions() {
        round_trip(UpgradePayload {
            actions: vec![
                UpgradePermitAction::RequestPermit(UpgradePermitRequest {
                    requestor: node(1),
                    request_height: Height::new(10),
                }),
                UpgradePermitAction::AuthorizePermit(Signed {
                    content: UpgradePermitRequest {
                        requestor: node(2),
                        request_height: Height::new(4),
                    },
                    signature: BasicSignatureBatch {
                        signatures_map: BTreeMap::new(),
                    },
                }),
                UpgradePermitAction::ReturnPermit { node: node(3) },
            ],
        });
    }
}
