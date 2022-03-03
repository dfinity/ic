use candid::{CandidType, Deserialize};
use dfn_core::api::CanisterId;
use serde::Serialize;

use std::cmp::Eq;
use std::cmp::PartialEq;
use std::convert::TryFrom;
use std::fmt::{self, Debug, Display, Formatter};
use std::hash::Hash;
use std::num::ParseIntError;
use std::str::FromStr;

use crate::pb::v1::{
    CanisterId as CanisterIdProto, NeuronId as NeuronIdProto, ProposalId as ProposalIdProto,
};
use ic_protobuf::registry::conversion_rate::v1::IcpXdrConversionRateRecord;

impl From<CanisterId> for CanisterIdProto {
    fn from(id: CanisterId) -> Self {
        CanisterIdProto {
            serialized_id: id.get().as_slice().to_vec(),
        }
    }
}

impl From<CanisterIdProto> for CanisterId {
    fn from(id: CanisterIdProto) -> Self {
        CanisterId::try_from(id.serialized_id).unwrap()
    }
}

// A unique Id for a Neuron.
#[cfg_attr(test, derive(comparable::Comparable))]
#[derive(CandidType, Clone, Copy, Debug, Serialize, Deserialize, Eq, Hash, PartialEq)]
pub struct NeuronId(pub u64);

impl From<NeuronIdProto> for NeuronId {
    fn from(pb: NeuronIdProto) -> Self {
        NeuronId(pb.id)
    }
}

impl From<NeuronId> for NeuronIdProto {
    fn from(id: NeuronId) -> Self {
        NeuronIdProto { id: id.0 }
    }
}

pub type NeuronIdParseError = ic_base_types::PrincipalIdParseError;

impl FromStr for NeuronId {
    type Err = ParseIntError;
    fn from_str(src: &str) -> Result<Self, Self::Err> {
        let id = u64::from_str(src)?;
        Ok(NeuronId(id))
    }
}

/// Proposal IDs are simply u64. All proposals are public, therefore it is a
/// non-goal to make IDs hard to guess.
#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Hash, Default, CandidType, Deserialize)]
pub struct ProposalId(pub u64);

impl From<ProposalIdProto> for ProposalId {
    fn from(pb: ProposalIdProto) -> Self {
        ProposalId(pb.id)
    }
}

impl From<ProposalId> for ProposalIdProto {
    fn from(id: ProposalId) -> Self {
        ProposalIdProto { id: id.0 }
    }
}

impl Debug for ProposalId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl Display for ProposalId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "proposal {}", self.0)
    }
}

/// The payload of a proposal to update the ICP/XDR conversion rate.
///
/// See /rs/protobuf/def/registry/conversion_rate/v1/conversion_rate.proto for
/// the explanation of the fields for the IcpXdrConversionRateRecord.
/// The fields will be used by the subnet canister to create an
/// IcpXdrConversionRateRecord.
#[derive(CandidType, Default, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct UpdateIcpXdrConversionRatePayload {
    pub data_source: String,
    pub timestamp_seconds: u64,
    pub xdr_permyriad_per_icp: u64,
}

impl From<UpdateIcpXdrConversionRatePayload> for IcpXdrConversionRateRecord {
    fn from(val: UpdateIcpXdrConversionRatePayload) -> Self {
        IcpXdrConversionRateRecord {
            timestamp_seconds: val.timestamp_seconds,
            xdr_permyriad_per_icp: val.xdr_permyriad_per_icp,
        }
    }
}
