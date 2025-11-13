use crate::crypto::canister_threshold_sig::idkg::{
    BatchSignedIDkgDealing, IDkgDealing, IDkgMaskedTranscriptOrigin, IDkgReceivers, IDkgTranscript,
    IDkgTranscriptId, IDkgTranscriptType, SignedIDkgDealing,
};
use crate::crypto::{AlgorithmId, BasicSig, BasicSigOf};
use crate::signature::{BasicSignature, BasicSignatureBatch};
use crate::{Height, NodeId, PrincipalId, RegistryVersion, SubnetId};
use maplit::{btreemap, btreeset};
use std::collections::BTreeMap;
use std::sync::Arc;

#[test]
fn should_return_correct_dealer_id_for_index() {
    let transcript = IDkgTranscript {
        verified_dealings: Arc::new(btreemap! {
            0 => batch_signed_dealing(node_id(42)),
            1 => batch_signed_dealing(node_id(43)),
            3 => batch_signed_dealing(node_id(45))
        }),
        transcript_id: dummy_transcript_id(),
        receivers: dummy_receivers(),
        registry_version: dummy_registry_version(),
        transcript_type: dummy_transcript_type(),
        algorithm_id: dummy_algorithm_id(),
        internal_transcript_raw: dummy_internal_transcript_raw(),
    };

    assert_eq!(transcript.dealer_id_for_index(0), Some(node_id(42)));
    assert_eq!(transcript.dealer_id_for_index(1), Some(node_id(43)));
    assert_eq!(transcript.dealer_id_for_index(2), None);
    assert_eq!(transcript.dealer_id_for_index(3), Some(node_id(45)));
    assert_eq!(transcript.dealer_id_for_index(4), None);
}

#[test]
fn should_return_correct_index_for_dealer_id() {
    let transcript = IDkgTranscript {
        verified_dealings: Arc::new(btreemap! {
            0 => batch_signed_dealing(node_id(42)),
            1 => batch_signed_dealing(node_id(43)),
            3 => batch_signed_dealing(node_id(45))
        }),
        transcript_id: dummy_transcript_id(),
        receivers: dummy_receivers(),
        registry_version: dummy_registry_version(),
        transcript_type: dummy_transcript_type(),
        algorithm_id: dummy_algorithm_id(),
        internal_transcript_raw: dummy_internal_transcript_raw(),
    };

    assert_eq!(transcript.index_for_dealer_id(node_id(42)), Some(0));
    assert_eq!(transcript.index_for_dealer_id(node_id(43)), Some(1));
    assert_eq!(transcript.index_for_dealer_id(node_id(44)), None);
    assert_eq!(transcript.index_for_dealer_id(node_id(45)), Some(3));
    assert_eq!(transcript.index_for_dealer_id(node_id(46)), None);
}

#[test]
fn should_return_correct_index_for_signer_id() {
    let transcript = IDkgTranscript {
        verified_dealings: Arc::new(dummy_dealings()),
        transcript_id: dummy_transcript_id(),
        receivers: IDkgReceivers::new(btreeset! {
            node_id(42),
            node_id(43),
            node_id(45),
            node_id(128),
        })
        .unwrap(),
        registry_version: dummy_registry_version(),
        transcript_type: dummy_transcript_type(),
        algorithm_id: dummy_algorithm_id(),
        internal_transcript_raw: dummy_internal_transcript_raw(),
    };

    assert_eq!(transcript.index_for_signer_id(node_id(42)), Some(0));
    assert_eq!(transcript.index_for_signer_id(node_id(43)), Some(1));
    assert_eq!(transcript.index_for_signer_id(node_id(44)), None);
    assert_eq!(transcript.index_for_signer_id(node_id(45)), Some(2));
    assert_eq!(transcript.index_for_signer_id(node_id(46)), None);
    assert_eq!(transcript.index_for_signer_id(node_id(128)), Some(3));
}

fn batch_signed_dealing(dealer_id: NodeId) -> BatchSignedIDkgDealing {
    let dealing = IDkgDealing {
        transcript_id: dummy_transcript_id(),
        internal_dealing_raw: dummy_internal_dealing_raw(),
    };
    let signed_dealing = SignedIDkgDealing {
        content: dealing,
        signature: BasicSignature {
            signature: BasicSigOf::new(BasicSig(vec![1, 2, 3])),
            signer: dealer_id,
        },
    };
    BatchSignedIDkgDealing {
        content: signed_dealing,
        signature: BasicSignatureBatch {
            signatures_map: BTreeMap::new(),
        },
    }
}

fn dummy_transcript_id() -> IDkgTranscriptId {
    IDkgTranscriptId::new(subnet_id(0), 0, Height::new(0))
}

fn dummy_dealings() -> std::collections::BTreeMap<crate::NodeIndex, BatchSignedIDkgDealing> {
    std::collections::BTreeMap::new()
}

fn dummy_receivers() -> IDkgReceivers {
    IDkgReceivers::new(btreeset! {node_id(0)}).expect("failed to create receivers")
}

fn subnet_id(id: u64) -> SubnetId {
    SubnetId::from(PrincipalId::new_subnet_test_id(id))
}

fn dummy_registry_version() -> RegistryVersion {
    RegistryVersion::from(0)
}

fn dummy_transcript_type() -> IDkgTranscriptType {
    IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random)
}

fn dummy_algorithm_id() -> AlgorithmId {
    AlgorithmId::ThresholdEcdsaSecp256k1
}

fn dummy_internal_transcript_raw() -> Vec<u8> {
    vec![]
}

fn dummy_internal_dealing_raw() -> Vec<u8> {
    vec![]
}

fn node_id(id: u64) -> NodeId {
    NodeId::from(PrincipalId::new_node_test_id(id))
}
