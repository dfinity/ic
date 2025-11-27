//! Protocol buffer equivalents to the various structs that make up a
//! `CertifiedStreamSlice`, for backwards- and forwards-compatible XNet
//! wire format.

use crate::{
    CryptoHashOfPartialState, Height,
    consensus::certification::{Certification, CertificationContent, CertificationShare},
    crypto::{CryptoHash, Signed},
    replica_version::ReplicaVersionParseError,
    xnet::CertifiedStreamSlice,
};
use ic_protobuf::messaging::xnet::v1 as pb;
use ic_protobuf::proxy::{ProxyDecodeError, try_from_option_field};
use std::convert::TryFrom;

#[cfg(test)]
mod tests;

impl From<ReplicaVersionParseError> for ProxyDecodeError {
    fn from(err: ReplicaVersionParseError) -> Self {
        Self::ReplicaVersionParseError(Box::new(err))
    }
}

impl From<CertificationContent> for pb::CertificationContent {
    fn from(value: CertificationContent) -> Self {
        Self {
            hash: value.hash.get().0,
        }
    }
}
impl From<pb::CertificationContent> for CertificationContent {
    fn from(value: pb::CertificationContent) -> Self {
        CertificationContent {
            hash: CryptoHashOfPartialState::new(CryptoHash(value.hash)),
        }
    }
}

impl From<Certification> for pb::Certification {
    fn from(value: Certification) -> Self {
        Self {
            height: value.height.get(),
            content: Some(value.signed.content.into()),
            signature: Some(value.signed.signature.into()),
        }
    }
}
impl TryFrom<pb::Certification> for Certification {
    type Error = ProxyDecodeError;

    fn try_from(value: pb::Certification) -> Result<Self, Self::Error> {
        Ok(Self {
            height: Height::new(value.height),
            signed: Signed {
                content: try_from_option_field(value.content, "Certification::content")?,
                signature: try_from_option_field(value.signature, "Certification::signature")?,
            },
        })
    }
}

impl From<CertificationShare> for pb::CertificationShare {
    fn from(share: CertificationShare) -> Self {
        Self {
            height: share.height.get(),
            content: Some(share.signed.content.into()),
            signature: Some(share.signed.signature.into()),
        }
    }
}
impl TryFrom<pb::CertificationShare> for CertificationShare {
    type Error = ProxyDecodeError;

    fn try_from(value: pb::CertificationShare) -> Result<Self, Self::Error> {
        Ok(Self {
            height: Height::new(value.height),
            signed: Signed {
                content: try_from_option_field(value.content, "CertificationShare::content")?,
                signature: try_from_option_field(value.signature, "CertificationShare::signature")?,
            },
        })
    }
}

impl From<CertifiedStreamSlice> for pb::CertifiedStreamSlice {
    fn from(value: CertifiedStreamSlice) -> Self {
        Self {
            payload: value.payload,
            merkle_proof: value.merkle_proof,
            certification: Some(value.certification.into()),
        }
    }
}
impl TryFrom<pb::CertifiedStreamSlice> for CertifiedStreamSlice {
    type Error = ProxyDecodeError;

    fn try_from(value: pb::CertifiedStreamSlice) -> Result<Self, Self::Error> {
        Ok(Self {
            payload: value.payload,
            merkle_proof: value.merkle_proof,
            certification: try_from_option_field(
                value.certification,
                "CertifiedStreamSlice::certification",
            )?,
        })
    }
}
