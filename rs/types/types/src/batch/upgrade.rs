//! Protobuf (de)serialization for the Phase-2 upgrade payload section carried
//! in a block's [`crate::batch::BatchPayload`].
//!
//! The upgrade section is a stream of length-delimited protobuf messages
//! (one per [`UpgradePermitAction`]), following the same pattern as the chain-key
//! and canister-http sections. This allows incremental size-limiting: actions
//! that don't fit within `max_size` are silently dropped by
//! [`iterator_to_bytes`].

use ic_base_types::NumBytes;
use ic_protobuf::{
    proxy::ProxyDecodeError,
    types::v1::{
        UpgradePayloadContentProto,
        upgrade_payload_content_proto::Content as UpgradePayloadContentProtoContent,
    },
};

use crate::{Height, RegistryVersion, consensus::upgrade::UpgradePermitAction};
use super::{iterator_to_bytes, slice_to_messages};

/// Serializes a list of [`UpgradePermitAction`]s to a length-delimited protobuf
/// stream, respecting the `max_size` budget. Actions that don't fit are
/// silently dropped.
pub fn upgrade_payload_to_bytes(actions: Vec<UpgradePermitAction>, max_size: NumBytes) -> Vec<u8> {
    let message_iterator = actions.into_iter().map(UpgradePayloadContentProto::from);
    iterator_to_bytes(message_iterator, max_size)
}

/// Deserializes a length-delimited protobuf stream into a list of
/// [`UpgradePermitAction`]s. An empty byte slice yields an empty list.
pub fn bytes_to_upgrade_payload(data: &[u8]) -> Result<Vec<UpgradePermitAction>, ProxyDecodeError> {
    let messages: Vec<UpgradePayloadContentProto> =
        slice_to_messages(data).map_err(ProxyDecodeError::DecodeError)?;
    messages.into_iter().map(UpgradePermitAction::try_from).collect()
}

impl From<UpgradePermitAction> for UpgradePayloadContentProto {
    fn from(action: UpgradePermitAction) -> Self {
        let proto_content = match action {
            UpgradePermitAction::Request {
                node,
                request_height,
                registry_version,
            } => UpgradePayloadContentProtoContent::Request(
                ic_protobuf::types::v1::UpgradePayloadRequestProto {
                    node: Some(crate::node_id_into_protobuf(node)),
                    request_height: request_height.get(),
                    registry_version: registry_version.get(),
                },
            ),
            UpgradePermitAction::Authorize(shares) => {
                UpgradePayloadContentProtoContent::Authorize(
                    ic_protobuf::types::v1::UpgradePayloadAuthorizeProto {
                        node: Some(crate::node_id_into_protobuf(shares.node)),
                        shares: shares
                            .shares
                            .into_iter()
                            .map(ic_protobuf::types::v1::UpgradePermitAuthShare::from)
                            .collect(),
                    },
                )
            }
            UpgradePermitAction::Return { node } => {
                UpgradePayloadContentProtoContent::ReturnVal(
                    ic_protobuf::types::v1::UpgradePayloadReturnProto {
                        node: Some(crate::node_id_into_protobuf(node)),
                    },
                )
            }
        };
        Self {
            content: Some(proto_content),
        }
    }
}

impl TryFrom<UpgradePayloadContentProto> for UpgradePermitAction {
    type Error = ProxyDecodeError;

    fn try_from(proto: UpgradePayloadContentProto) -> Result<Self, Self::Error> {
        let content = proto.content.ok_or(ProxyDecodeError::MissingField(
            "UpgradePayloadContentProto::content",
        ))?;
        Ok(match content {
            UpgradePayloadContentProtoContent::Request(request) => UpgradePermitAction::Request {
                node: crate::node_id_try_from_option(request.node)?,
                request_height: Height::new(request.request_height),
                registry_version: RegistryVersion::new(request.registry_version),
            },
            UpgradePayloadContentProtoContent::Authorize(authorize) => {
                UpgradePermitAction::Authorize(crate::consensus::upgrade::UpgradePermitShares {
                    node: crate::node_id_try_from_option(authorize.node)?,
                    shares: authorize
                        .shares
                        .into_iter()
                        .map(TryInto::try_into)
                        .collect::<Result<_, _>>()?,
                })
            }
            UpgradePayloadContentProtoContent::ReturnVal(return_val) => UpgradePermitAction::Return {
                node: crate::node_id_try_from_option(return_val.node)?,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use ic_base_types::PrincipalId;

    use super::*;
    use crate::NodeId;

    fn node(node_index: u64) -> NodeId {
        NodeId::from(PrincipalId::new_node_test_id(node_index))
    }

    #[test]
    fn test_round_trip_request() {
        let actions = vec![UpgradePermitAction::Request {
            node: node(3),
            request_height: Height::new(42),
            registry_version: RegistryVersion::new(11),
        }];
        let bytes = upgrade_payload_to_bytes(actions.clone(), NumBytes::new(u64::MAX));
        let decoded = bytes_to_upgrade_payload(&bytes).unwrap();
        assert_eq!(actions, decoded);
    }

    #[test]
    fn test_round_trip_authorize() {
        let actions = vec![UpgradePermitAction::Authorize(
            crate::consensus::upgrade::UpgradePermitShares {
                node: node(5),
                shares: vec![],
            },
        )];
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
            UpgradePermitAction::Request {
                node: node(1),
                request_height: Height::new(10),
                registry_version: RegistryVersion::new(7),
            },
            UpgradePermitAction::Authorize(crate::consensus::upgrade::UpgradePermitShares {
                node: node(2),
                shares: vec![],
            }),
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
