//! Protocol buffer equivalents to the various structs that make up a
//! `CertifiedStreamSlice`, for backwards- and forwards-compatible XNet
//! wire format.

use crate::{
    CryptoHashOfPartialState, Height,
    consensus::certification::{
        Certification, CertificationContent, CertificationShare, SignedCertificationContent,
    },
    crypto::{CryptoHash, Signed, threshold_sig::ni_dkg::NiDkgTag},
    replica_version::ReplicaVersionParseError,
    signature::ThresholdSignature,
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
            height_witness: Some(value.height_witness.into()),
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
            height_witness: try_from_option_field(
                value.height_witness,
                "Certification::height_witness",
            )?,
            signed: Signed {
                content: try_from_option_field(value.content, "Certification::content")?,
                signature: try_from_option_field(value.signature, "Certification::signature")?,
            },
        })
    }
}

impl From<SignedCertificationContent> for pb::SignedCertificationContent {
    fn from(value: SignedCertificationContent) -> Self {
        Self {
            content: Some(value.content.into()),
            signature: Some(value.signature.into()),
        }
    }
}
/// Sets the signer's NI-DKG tag to `HighThreshold`, as the signature does not
/// cover it.
///
/// TODO: Reject other NI-DKG tags instead, once all subnets validate the signer
/// (see `CertifierImpl::validate_certification()`).
impl TryFrom<pb::SignedCertificationContent> for SignedCertificationContent {
    type Error = ProxyDecodeError;

    fn try_from(value: pb::SignedCertificationContent) -> Result<Self, Self::Error> {
        let mut signature: ThresholdSignature<CertificationContent> =
            try_from_option_field(value.signature, "SignedCertificationContent::signature")?;
        signature.signer.dkg_tag = NiDkgTag::HighThreshold;
        Ok(Signed {
            content: try_from_option_field(value.content, "SignedCertificationContent::content")?,
            signature,
        })
    }
}

impl From<CertificationShare> for pb::CertificationShare {
    fn from(share: CertificationShare) -> Self {
        Self {
            height: share.height.get(),
            height_witness: Some(share.height_witness.into()),
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
            height_witness: try_from_option_field(
                value.height_witness,
                "CertificationShare::height_witness",
            )?,
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
