//! Protobuf (de)serialization for the Phase-2 [`UpgradePayload`] carried in a
//! block's [`crate::batch::BatchPayload`].
//!
//! Unlike the chain-key payload (a list of length-delimited messages), the
//! upgrade payload is a single protobuf message, so it is encoded with
//! [`prost::Message::encode`] and decoded with [`prost::Message::decode`].

use ic_base_types::NumBytes;
use ic_protobuf::{
    proxy::ProxyDecodeError,
    types::v1::{
        UpgradePayloadAuthorizeProto, UpgradePayloadContentProto, UpgradePayloadProto,
        UpgradePayloadRequestProto, UpgradePayloadReturnProto,
        upgrade_payload_content_proto::Content as UpgradePayloadContentProtoContent,
    },
};
use prost::Message;

use crate::{
    Height,
    consensus::upgrade::{UpgradePayload, UpgradePayloadContent, UpgradePermitShares},
};

/// Serializes an [`UpgradePayload`] to its protobuf encoding. Returns empty
/// bytes if the encoded payload would exceed `max_size`.
pub fn upgrade_payload_to_bytes(payload: UpgradePayload, max_size: NumBytes) -> Vec<u8> {
    let proto = UpgradePayloadProto::from(payload);
    let encoded_len = proto.encoded_len();
    if encoded_len > max_size.get() as usize {
        return Vec::new();
    }
    let mut bytes = Vec::with_capacity(encoded_len);
    proto
        .encode(&mut bytes)
        .expect("encoding into Vec<u8> is infallible");
    bytes
}

/// Deserializes an [`UpgradePayload`] from its protobuf encoding.
pub fn bytes_to_upgrade_payload(data: &[u8]) -> Result<UpgradePayload, ProxyDecodeError> {
    let proto = UpgradePayloadProto::decode(data).map_err(ProxyDecodeError::DecodeError)?;
    UpgradePayload::try_from(proto)
}

impl From<UpgradePayload> for UpgradePayloadProto {
    fn from(payload: UpgradePayload) -> Self {
        Self {
            content: payload.content.map(UpgradePayloadContentProto::from),
        }
    }
}

impl TryFrom<UpgradePayloadProto> for UpgradePayload {
    type Error = ProxyDecodeError;

    fn try_from(proto: UpgradePayloadProto) -> Result<Self, Self::Error> {
        Ok(Self {
            content: proto
                .content
                .map(UpgradePayloadContent::try_from)
                .transpose()?,
        })
    }
}

impl From<UpgradePayloadContent> for UpgradePayloadContentProto {
    fn from(content: UpgradePayloadContent) -> Self {
        let proto_content = match content {
            UpgradePayloadContent::Request { node, request_height } => {
                UpgradePayloadContentProtoContent::Request(UpgradePayloadRequestProto {
                    node: Some(crate::node_id_into_protobuf(node)),
                    request_height: request_height.get(),
                })
            }
            UpgradePayloadContent::Authorize(shares) => {
                UpgradePayloadContentProtoContent::Authorize(UpgradePayloadAuthorizeProto {
                    node: Some(crate::node_id_into_protobuf(shares.node)),
                    shares: shares
                        .shares
                        .into_iter()
                        .map(ic_protobuf::types::v1::UpgradePermitAuthShare::from)
                        .collect(),
                })
            }
            UpgradePayloadContent::Return { node } => {
                UpgradePayloadContentProtoContent::ReturnVal(UpgradePayloadReturnProto {
                    node: Some(crate::node_id_into_protobuf(node)),
                })
            }
        };
        Self {
            content: Some(proto_content),
        }
    }
}

impl TryFrom<UpgradePayloadContentProto> for UpgradePayloadContent {
    type Error = ProxyDecodeError;

    fn try_from(proto: UpgradePayloadContentProto) -> Result<Self, Self::Error> {
        let content = proto.content.ok_or(ProxyDecodeError::MissingField(
            "UpgradePayloadContentProto::content",
        ))?;
        Ok(match content {
            UpgradePayloadContentProtoContent::Request(request) => {
                UpgradePayloadContent::Request {
                    node: crate::node_id_try_from_option(request.node)?,
                    request_height: Height::new(request.request_height),
                }
            }
            UpgradePayloadContentProtoContent::Authorize(authorize) => {
                UpgradePayloadContent::Authorize(UpgradePermitShares {
                    node: crate::node_id_try_from_option(authorize.node)?,
                    shares: authorize
                        .shares
                        .into_iter()
                        .map(TryInto::try_into)
                        .collect::<Result<_, _>>()?,
                })
            }
            UpgradePayloadContentProtoContent::ReturnVal(return_val) => {
                UpgradePayloadContent::Return {
                    node: crate::node_id_try_from_option(return_val.node)?,
                }
            }
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
        let payload = UpgradePayload {
            content: Some(UpgradePayloadContent::Request {
                node: node(3),
                request_height: Height::new(42),
            }),
        };
        let bytes = upgrade_payload_to_bytes(payload.clone(), NumBytes::new(u64::MAX));
        let decoded = bytes_to_upgrade_payload(&bytes).unwrap();
        assert_eq!(payload, decoded);
    }

    #[test]
    fn test_round_trip_authorize() {
        let payload = UpgradePayload {
            content: Some(UpgradePayloadContent::Authorize(UpgradePermitShares {
                node: node(5),
                shares: vec![],
            })),
        };
        let bytes = upgrade_payload_to_bytes(payload.clone(), NumBytes::new(u64::MAX));
        let decoded = bytes_to_upgrade_payload(&bytes).unwrap();
        assert_eq!(payload, decoded);
    }

    #[test]
    fn test_round_trip_return() {
        let payload = UpgradePayload {
            content: Some(UpgradePayloadContent::Return { node: node(7) }),
        };
        let bytes = upgrade_payload_to_bytes(payload.clone(), NumBytes::new(u64::MAX));
        let decoded = bytes_to_upgrade_payload(&bytes).unwrap();
        assert_eq!(payload, decoded);
    }

    #[test]
    fn test_round_trip_empty() {
        let payload = UpgradePayload::default();
        let bytes = upgrade_payload_to_bytes(payload.clone(), NumBytes::new(u64::MAX));
        let decoded = bytes_to_upgrade_payload(&bytes).unwrap();
        assert_eq!(payload, decoded);
    }
}
