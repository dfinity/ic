use crate::pb::v1::{NeuronId as NeuronIdProto, ProposalId as ProposalIdProto};
use candid::{CandidType, Deserialize};
use ic_base_types::CanisterId;
use serde::Serialize;
use std::{
    cmp::{Eq, PartialEq},
    fmt::{self, Debug, Display, Formatter},
    hash::Hash,
    num::ParseIntError,
    str::FromStr,
};

// A unique Id for a Neuron.
#[derive(
    Copy,
    Clone,
    Eq,
    PartialEq,
    Hash,
    Debug,
    CandidType,
    Deserialize,
    Serialize,
    comparable::Comparable,
)]
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

impl NeuronIdProto {
    pub fn from_u64(id: u64) -> Self {
        Self { id }
    }
}

impl FromStr for NeuronId {
    type Err = ParseIntError;
    fn from_str(src: &str) -> Result<Self, Self::Err> {
        let id = u64::from_str(src)?;
        Ok(NeuronId(id))
    }
}

/// Proposal IDs are simply u64. All proposals are public, therefore it is a
/// non-goal to make IDs hard to guess.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Default, CandidType, Deserialize)]
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
        write!(f, "{self}")
    }
}

impl Display for ProposalId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "proposal {}", self.0)
    }
}

/// The reason for why an exchange rate proposal is created.
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub enum UpdateIcpXdrConversionRatePayloadReason {
    /// The timestamp of the rate stored in the CMC is older than the execution interval.
    OldRate,
    /// The relative difference between the rate in the CMC and the rate the conversion rate provider retrieved exceeds
    /// a threshold defined by the conversion rate provider.
    DivergedRate,
    /// Used to restart the cycles minting canister automatic exchange rate update mechanism
    /// that calls the exchange rate canister.
    EnableAutomaticExchangeRateUpdates,
}

/// The payload of a proposal to update the ICP/XDR conversion rate in the CMC.
#[derive(Clone, Eq, PartialEq, Debug, Default, CandidType, Deserialize, Serialize)]
pub struct UpdateIcpXdrConversionRatePayload {
    pub data_source: String,
    pub timestamp_seconds: u64,
    pub xdr_permyriad_per_icp: u64,
    pub reason: Option<UpdateIcpXdrConversionRatePayloadReason>,
}

// A proposal payload to call a canister.
#[derive(Clone, Debug, candid::CandidType, candid::Deserialize, serde::Serialize)]
pub struct CallCanisterRequest {
    pub canister_id: CanisterId,
    pub method_name: String,
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,
}
