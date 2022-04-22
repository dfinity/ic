use ic_base_types::SubnetId;
use ic_protobuf::{messaging::xnet::v1 as messaging_pb, types::v1 as pb};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, convert::TryFrom};

use crate::{xnet::CertifiedStreamSlice, CountBytes};

/// Payload that contains XNet messages.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct XNetPayload {
    pub stream_slices: BTreeMap<SubnetId, CertifiedStreamSlice>,
}

impl From<&XNetPayload> for pb::XNetPayload {
    fn from(payload: &XNetPayload) -> Self {
        Self {
            stream_slices: payload
                .stream_slices
                .iter()
                .map(|(subnet_id, stream_slice)| pb::SubnetStreamSlice {
                    subnet_id: Some(crate::subnet_id_into_protobuf(*subnet_id)),
                    stream_slice: Some(messaging_pb::CertifiedStreamSlice::from(
                        stream_slice.clone(),
                    )),
                })
                .collect(),
        }
    }
}

impl TryFrom<pb::XNetPayload> for XNetPayload {
    type Error = String;
    fn try_from(payload: pb::XNetPayload) -> Result<Self, Self::Error> {
        Ok(Self {
            stream_slices: payload
                .stream_slices
                .into_iter()
                .map(|subnet_stream_slice| {
                    Ok((
                        crate::subnet_id_try_from_protobuf(
                            subnet_stream_slice.subnet_id.ok_or_else(|| {
                                String::from("Error: stream_slices missing subnet_id")
                            })?,
                        )
                        .map_err(|e| format!("{:?}", e))?,
                        CertifiedStreamSlice::try_from(
                            subnet_stream_slice.stream_slice.ok_or_else(|| {
                                String::from("Error: stream_slices missing from XNetPayload")
                            })?,
                        )
                        .map_err(|e| format!("{:?}", e))?,
                    ))
                })
                .collect::<Result<BTreeMap<SubnetId, CertifiedStreamSlice>, String>>()?,
        })
    }
}

impl CountBytes for XNetPayload {
    /// Returns the approximate amount of bytes in xnet payload.
    fn count_bytes(&self) -> usize {
        self.stream_slices
            .values()
            .map(|slice| {
                slice.payload.len() + slice.merkle_proof.len() + slice.certification.count_bytes()
            })
            .sum()
    }
}
