//! Types for non-interactive distributed key generation (NI-DKG).
#[cfg(test)]
use crate::NodeId;
use crate::NumberOfNodes;
use crate::crypto::threshold_sig::ni_dkg::config::NiDkgThreshold;
pub use crate::crypto::threshold_sig::ni_dkg::config::receivers::NiDkgReceivers;
use crate::{Height, PrincipalId, PrincipalIdBlobParseError, RegistryVersion, SubnetId};
use core::fmt;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::{CspNiDkgDealing, CspNiDkgTranscript};
#[cfg(test)]
use ic_crypto_test_utils_ni_dkg::ni_dkg_csp_dealing;
#[cfg(test)]
use ic_exhaustive_derive::ExhaustiveSet;
use ic_management_canister_types_private::{MasterPublicKeyId, VetKdKeyId};
use ic_protobuf::proxy::ProxyDecodeError;
use ic_protobuf::types::v1 as pb;
use ic_protobuf::types::v1::NiDkgId as NiDkgIdProto;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::convert::TryFrom;
use strum_macros::EnumCount;
use thiserror::Error;

pub mod config;
pub mod errors;
pub mod id;
pub mod transcripts_to_retain;

use ic_crypto_internal_types::sign::threshold_sig::public_coefficients::CspPublicCoefficients;
use ic_protobuf::registry::subnet::v1::InitialNiDkgTranscriptRecord;
pub use id::NiDkgId;

#[cfg(test)]
mod tests;

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, EnumCount, Serialize, Deserialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub enum NiDkgMasterPublicKeyId {
    VetKd(VetKdKeyId),
}

impl From<NiDkgMasterPublicKeyId> for MasterPublicKeyId {
    fn from(val: NiDkgMasterPublicKeyId) -> Self {
        match val {
            NiDkgMasterPublicKeyId::VetKd(k) => MasterPublicKeyId::VetKd(k),
        }
    }
}

impl TryFrom<MasterPublicKeyId> for NiDkgMasterPublicKeyId {
    type Error = &'static str;

    fn try_from(value: MasterPublicKeyId) -> Result<Self, Self::Error> {
        match value {
            MasterPublicKeyId::VetKd(vet_kd_key_id) => {
                Ok(NiDkgMasterPublicKeyId::VetKd(vet_kd_key_id))
            }
            MasterPublicKeyId::Ecdsa(_) | MasterPublicKeyId::Schnorr(_) => {
                Err("This is not a NiDkg key")
            }
        }
    }
}

impl From<&NiDkgMasterPublicKeyId> for pb::MasterPublicKeyId {
    fn from(item: &NiDkgMasterPublicKeyId) -> Self {
        Self {
            key_id: Some(match item {
                NiDkgMasterPublicKeyId::VetKd(vetkd_key_id) => {
                    pb::master_public_key_id::KeyId::Vetkd(pb::VetKdKeyId::from(vetkd_key_id))
                }
            }),
        }
    }
}

impl TryFrom<pb::MasterPublicKeyId> for NiDkgMasterPublicKeyId {
    type Error = ProxyDecodeError;
    fn try_from(item: pb::MasterPublicKeyId) -> Result<Self, Self::Error> {
        use pb::master_public_key_id::KeyId;
        let Some(key_id_pb) = item.key_id else {
            return Err(ProxyDecodeError::MissingField("MasterPublicKeyId::key_id"));
        };
        Ok(match key_id_pb {
            KeyId::Vetkd(vetkd_key_id_pb) => {
                NiDkgMasterPublicKeyId::VetKd(VetKdKeyId::try_from(vetkd_key_id_pb)?)
            }
            KeyId::Ecdsa(_) | KeyId::Schnorr(_) => {
                return Err(ProxyDecodeError::ValueOutOfRange {
                    typ: "NiDkgMasterPublicKeyId",
                    err: format!("Unable to convert {key_id_pb:?} to a NiDkgMasterPublicKeyId"),
                });
            }
        })
    }
}

impl fmt::Display for NiDkgMasterPublicKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&MasterPublicKeyId::from(self.clone()), f)
    }
}

/// Allows to distinguish NI-DKG protocol executions for different purposes:
/// * LowThreshold: generate a transcript with a low threshold,
/// * HighThreshold: generate a transcript with a high threshold,
/// * HighThresholdForKey: generate a transcript with a high threshold for
///   a master public key with a particular ID
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, EnumCount, Serialize)]
#[repr(isize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub enum NiDkgTag {
    LowThreshold = 1,
    HighThreshold = 2,
    HighThresholdForKey(NiDkgMasterPublicKeyId) = 3,
}

impl From<&NiDkgTag> for pb::NiDkgTag {
    fn from(tag: &NiDkgTag) -> Self {
        match tag {
            NiDkgTag::LowThreshold => pb::NiDkgTag::LowThreshold,
            NiDkgTag::HighThreshold => pb::NiDkgTag::HighThreshold,
            NiDkgTag::HighThresholdForKey(_master_public_key_id) => {
                pb::NiDkgTag::HighThresholdForKey
            }
        }
    }
}

/// The subnet for which the DKG generates keys.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Deserialize, Serialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub enum NiDkgTargetSubnet {
    /// `Local` means the subnet creates keys for itself.
    Local,
    /// `Remote` means the subnet creates keys for another subnet. This is used,
    /// e.g., when the NNS generates initial key material for a new subnet.
    ///
    /// We cannot use `SubnetId` as type contained in the `Remote` variant
    /// because the exact subnet ID is derived from the subnet's public key,
    /// which is only known _after_ the DKG protocol was successfully run. Said
    /// differently, at the time the containing `NiDkgId` is created, the exact
    /// `SubnetId` of the target subnet is not (and cannot be) known yet.
    Remote(NiDkgTargetId),
}

/// An ID for a remote `NiDkgTargetSubnet`.
///
/// Please refer to the rustdoc of `NiDkgTargetSubnet::Remote` for an
/// explanation of why this is needed.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct NiDkgTargetId([u8; NiDkgTargetId::SIZE]);
ic_crypto_internal_types::derive_serde!(NiDkgTargetId, NiDkgTargetId::SIZE);

impl NiDkgTargetId {
    pub const SIZE: usize = 32;

    pub const fn new(id: [u8; NiDkgTargetId::SIZE]) -> Self {
        NiDkgTargetId(id)
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl fmt::Debug for NiDkgTargetSubnet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local => write!(f, "Local"),
            Self::Remote(target_id) => write!(f, "Remote(0x{})", hex::encode(target_id.0)),
        }
    }
}

impl fmt::Display for NiDkgTargetSubnet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// A dealer's contribution (called dealing) to distributed key generation.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
pub struct NiDkgDealing {
    pub internal_dealing: CspNiDkgDealing,
}

impl fmt::Display for NiDkgDealing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", &self)
    }
}

#[cfg(test)]
impl NiDkgDealing {
    pub fn dummy_dealing_for_tests(seed: u8) -> NiDkgDealing {
        NiDkgDealing {
            internal_dealing: ni_dkg_csp_dealing(seed),
        }
    }
}

impl From<CspNiDkgDealing> for NiDkgDealing {
    fn from(csp_dealing: CspNiDkgDealing) -> Self {
        NiDkgDealing {
            internal_dealing: csp_dealing,
        }
    }
}

impl From<NiDkgDealing> for CspNiDkgDealing {
    fn from(dealing: NiDkgDealing) -> Self {
        dealing.internal_dealing
    }
}

#[derive(Debug, Error)]
pub enum ThresholdSigPublicKeyError {
    #[error("threshold signature public key coefficients empty")]
    CoefficientsEmpty,
}

/// Summarizes a distributed key generation.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
pub struct NiDkgTranscript {
    pub dkg_id: NiDkgId,
    pub threshold: NiDkgThreshold,
    pub committee: NiDkgReceivers,
    pub registry_version: RegistryVersion,
    pub internal_csp_transcript: CspNiDkgTranscript,
}

impl From<&NiDkgTranscript> for CspPublicCoefficients {
    fn from(transcript: &NiDkgTranscript) -> Self {
        let csp_transcript = CspNiDkgTranscript::from(transcript);
        CspPublicCoefficients::from(&csp_transcript)
    }
}

impl From<&NiDkgTranscript> for pb::NiDkgTranscript {
    fn from(transcript: &NiDkgTranscript) -> Self {
        Self {
            dkg_id: Some(pb::NiDkgId::from(transcript.dkg_id.clone())),
            threshold: transcript.threshold.get().get(),
            committee: transcript
                .committee
                .get()
                .iter()
                .cloned()
                .map(crate::node_id_into_protobuf)
                .collect(),
            registry_version: transcript.registry_version.get(),
            internal_csp_transcript: bincode::serialize(&transcript.internal_csp_transcript)
                .unwrap(),
        }
    }
}

impl TryFrom<&pb::NiDkgTranscript> for NiDkgTranscript {
    type Error = String;
    fn try_from(summary: &pb::NiDkgTranscript) -> Result<Self, Self::Error> {
        Ok(Self {
            dkg_id: NiDkgId::from_option_protobuf(summary.dkg_id.clone(), "NiDkgTranscript")?,
            threshold: NiDkgThreshold::new(NumberOfNodes::from(summary.threshold))
                .map_err(|e| format!("threshold error {e:?}"))?,
            committee: NiDkgReceivers::new(
                summary
                    .committee
                    .iter()
                    .cloned()
                    .map(|committee_member| crate::node_id_try_from_option(Some(committee_member)))
                    .collect::<Result<BTreeSet<_>, _>>()
                    .map_err(|err| {
                        format!("Problem loading committee in NiDkgTranscript: {err:?}")
                    })?,
            )
            .map_err(|e| format!("{e:?}"))?,
            registry_version: RegistryVersion::from(summary.registry_version),
            internal_csp_transcript: bincode::deserialize(&summary.internal_csp_transcript)
                .map_err(|e| format!("{e:?}"))?,
        })
    }
}

impl fmt::Display for NiDkgTranscript {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", &self)
    }
}

impl From<&NiDkgTranscript> for CspNiDkgTranscript {
    fn from(transcript: &NiDkgTranscript) -> Self {
        transcript.internal_csp_transcript.clone()
    }
}

#[cfg(test)]
impl NiDkgTranscript {
    pub fn dummy_transcript_for_tests_with_params(
        committee: Vec<NodeId>,
        dkg_tag: NiDkgTag,
        threshold: u32,
        registry_version: u64,
    ) -> Self {
        Self {
            dkg_id: NiDkgId {
                start_block_height: Height::from(0),
                dealer_subnet: SubnetId::from(PrincipalId::new_subnet_test_id(0)),
                dkg_tag,
                target_subnet: NiDkgTargetSubnet::Local,
            },
            threshold: NiDkgThreshold::new(crate::NumberOfNodes::new(threshold))
                .expect("Couldn't create a non-interactive DKG threshold."),
            committee: NiDkgReceivers::new(committee.into_iter().collect())
                .expect("Couldn't create non-interactive DKG committee"),
            registry_version: RegistryVersion::from(registry_version),
            internal_csp_transcript: dummy_internal_transcript(),
        }
    }
    pub fn dummy_transcript_for_tests() -> Self {
        NiDkgTranscript::dummy_transcript_for_tests_with_params(
            vec![NodeId::from(PrincipalId::new_node_test_id(0))],
            NiDkgTag::LowThreshold,
            1,
            0,
        )
    }
}

/// Converts an NI-DKG transcript into the corresponding protobuf
/// representation.
impl From<NiDkgTranscript> for InitialNiDkgTranscriptRecord {
    fn from(transcript: NiDkgTranscript) -> Self {
        let dkg_id = NiDkgIdProto::from(transcript.dkg_id);
        InitialNiDkgTranscriptRecord {
            id: Some(dkg_id),
            threshold: transcript.threshold.get().get(),
            committee: transcript
                .committee
                .get()
                .iter()
                .map(|node| node.get().into_vec())
                .collect(),
            registry_version: transcript.registry_version.get(),
            internal_csp_transcript: serde_cbor::to_vec(&transcript.internal_csp_transcript)
                .expect("failed to serialize CSP NI-DKG transcript to CBOR"),
        }
    }
}

#[cfg(test)]
fn dummy_internal_transcript() -> CspNiDkgTranscript {
    use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381;
    use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes;
    CspNiDkgTranscript::Groth20_Bls12_381(ni_dkg_groth20_bls12_381::Transcript {
        public_coefficients: ni_dkg_groth20_bls12_381::PublicCoefficientsBytes {
            coefficients: vec![PublicKeyBytes([0; PublicKeyBytes::SIZE])],
        },
        receiver_data: std::collections::BTreeMap::new(),
    })
}
