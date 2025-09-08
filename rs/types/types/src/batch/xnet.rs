use ic_base_types::{SubnetId, subnet_id_try_from_option};
#[cfg(test)]
use ic_exhaustive_derive::ExhaustiveSet;
use ic_protobuf::{
    messaging::xnet::v1 as messaging_pb,
    proxy::{ProxyDecodeError, try_from_option_field},
    types::v1 as pb,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, convert::TryFrom};

use crate::{CountBytes, xnet::CertifiedStreamSlice};

/// Payload that contains XNet messages.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Default, Deserialize, Serialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
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
    type Error = ProxyDecodeError;

    fn try_from(payload: pb::XNetPayload) -> Result<Self, Self::Error> {
        Ok(Self {
            stream_slices: payload
                .stream_slices
                .into_iter()
                .map(|subnet_stream_slice| {
                    Ok((
                        subnet_id_try_from_option(subnet_stream_slice.subnet_id)?,
                        try_from_option_field(
                            subnet_stream_slice.stream_slice,
                            "XNetPayload::subnet_stream_slices::stream_slice",
                        )?,
                    ))
                })
                .collect::<Result<BTreeMap<SubnetId, CertifiedStreamSlice>, Self::Error>>()?,
        })
    }
}

impl XNetPayload {
    /// Returns an approximation of the byte size of the `XNetPayload`, exclusively
    /// for use in stats.
    ///
    /// Not implemented as an `impl CountBytes for XNetPayload` because this is NOT
    /// THE SAME ESTIMATE that is used when building and validating a `XNetPayload`
    /// and accidentally using this to validate payload sizes WILL cause breakages.
    pub fn size_bytes(&self) -> usize {
        self.stream_slices
            .values()
            .map(|slice| {
                slice.payload.len() + slice.merkle_proof.len() + slice.certification.count_bytes()
            })
            .sum()
    }

    /// Returns true if the payload is empty
    pub fn is_empty(&self) -> bool {
        let XNetPayload { stream_slices } = &self;
        stream_slices.is_empty()
    }
}
