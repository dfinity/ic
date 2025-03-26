use crate::{
    crypto::threshold_sig::ni_dkg::NiDkgId, crypto::*, node_id_into_protobuf,
    node_id_try_from_option, CountBytes, NodeId,
};
use ic_protobuf::{
    proxy::{try_from_option_field, ProxyDecodeError},
    types::v1 as pb,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// BasicSignature captures basic signature on a value and the identity of the
/// replica that signed it
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, Serialize)]
pub struct BasicSignature<T> {
    pub signature: BasicSigOf<T>,
    pub signer: NodeId,
}

impl<T> CountBytes for BasicSignature<T> {
    fn count_bytes(&self) -> usize {
        self.signature.get_ref().count_bytes() + std::mem::size_of::<NodeId>()
    }
}

/// `BasicSigned<T>` captures a value of type T and a BasicSignature on it
pub type BasicSigned<T> = Signed<T, BasicSignature<T>>;

/// BasicSignatureBatch captures a collection of basic signatures on the same value and
/// the identities of the replicas that signed it.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, Serialize)]
pub struct BasicSignatureBatch<T> {
    pub signatures_map: BTreeMap<NodeId, BasicSigOf<T>>,
}

/// ThresholdSignature captures a threshold signature on a value and the
/// DKG id of the threshold key material used to sign
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
pub struct ThresholdSignature<T> {
    pub signature: CombinedThresholdSigOf<T>,
    pub signer: NiDkgId,
}

/// ThresholdSignatureShare captures a share of a threshold signature on a value
/// and the identity of the replica that signed
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, Serialize)]
pub struct ThresholdSignatureShare<T> {
    pub signature: ThresholdSigShareOf<T>,
    pub signer: NodeId,
}

/// MultiSignature captures a cryptographic multi-signature, which is one
/// message signed by multiple signers
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, Serialize)]
pub struct MultiSignature<T> {
    pub signature: CombinedMultiSigOf<T>,
    pub signers: Vec<NodeId>,
}

/// MultiSignatureShare is a signature from one replica. Multiple shares can be
/// aggregated into a MultiSignature.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, Serialize)]
pub struct MultiSignatureShare<T> {
    pub signature: IndividualMultiSigOf<T>,
    pub signer: NodeId,
}

impl<T> From<BasicSignature<T>> for pb::BasicSignature {
    fn from(value: BasicSignature<T>) -> Self {
        Self {
            signature: value.signature.get().0,
            signer: Some(node_id_into_protobuf(value.signer)),
        }
    }
}

impl<T> TryFrom<pb::BasicSignature> for BasicSignature<T> {
    type Error = ProxyDecodeError;
    fn try_from(value: pb::BasicSignature) -> Result<Self, Self::Error> {
        Ok(Self {
            signature: BasicSigOf::new(BasicSig(value.signature)),
            signer: node_id_try_from_option(value.signer)?,
        })
    }
}

impl<T> From<ThresholdSignature<T>> for pb::ThresholdSignature {
    fn from(value: ThresholdSignature<T>) -> Self {
        Self {
            signature: value.signature.get().0,
            signer: Some(value.signer.into()),
        }
    }
}

impl<T> TryFrom<pb::ThresholdSignature> for ThresholdSignature<T> {
    type Error = ProxyDecodeError;

    fn try_from(value: pb::ThresholdSignature) -> Result<Self, Self::Error> {
        Ok(Self {
            signature: CombinedThresholdSigOf::new(CombinedThresholdSig(value.signature)),
            signer: try_from_option_field(value.signer, "ThresholdSignature::signer")?,
        })
    }
}

impl<T> From<ThresholdSignatureShare<T>> for pb::ThresholdSignatureShare {
    fn from(value: ThresholdSignatureShare<T>) -> Self {
        Self {
            signature: value.signature.get().0,
            signer: Some(node_id_into_protobuf(value.signer)),
        }
    }
}

impl<T> TryFrom<pb::ThresholdSignatureShare> for ThresholdSignatureShare<T> {
    type Error = ProxyDecodeError;

    fn try_from(value: pb::ThresholdSignatureShare) -> Result<Self, Self::Error> {
        Ok(Self {
            signature: ThresholdSigShareOf::new(ThresholdSigShare(value.signature)),
            signer: node_id_try_from_option(value.signer)?,
        })
    }
}
