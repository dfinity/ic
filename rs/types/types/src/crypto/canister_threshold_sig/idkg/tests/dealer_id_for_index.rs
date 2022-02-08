use crate::consensus::ecdsa::EcdsaDealing;
use crate::crypto::canister_threshold_sig::idkg::{
    IDkgDealing, IDkgMaskedTranscriptOrigin, IDkgMultiSignedDealing, IDkgReceivers, IDkgTranscript,
    IDkgTranscriptId, IDkgTranscriptType,
};
use crate::crypto::{AlgorithmId, CombinedMultiSig, CombinedMultiSigOf};
use crate::{Height, NodeId, PrincipalId, RegistryVersion, SubnetId};
use maplit::{btreemap, btreeset};
use std::collections::BTreeSet;

#[test]
fn should_return_correct_dealer_id_for_index() {
    let transcript = IDkgTranscript {
        verified_dealings: btreemap! {
            0 => multi_signed_dealing(node_id(42)),
            1 => multi_signed_dealing(node_id(43)),
            3 => multi_signed_dealing(node_id(45))
        },
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

fn multi_signed_dealing(dealer_id: NodeId) -> IDkgMultiSignedDealing {
    let ecdsa_dealing = EcdsaDealing {
        requested_height: dummy_height(),
        idkg_dealing: IDkgDealing {
            transcript_id: dummy_transcript_id(),
            dealer_id,
            internal_dealing_raw: dummy_internal_dealing_raw(),
        },
    };

    IDkgMultiSignedDealing {
        signature: CombinedMultiSigOf::new(CombinedMultiSig(vec![])),
        signers: BTreeSet::new(),
        dealing: ecdsa_dealing,
    }
}

fn dummy_transcript_id() -> IDkgTranscriptId {
    IDkgTranscriptId::new(subnet_id(0), 0)
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

fn dummy_height() -> Height {
    Height::new(0)
}

fn node_id(id: u64) -> NodeId {
    NodeId::from(PrincipalId::new_node_test_id(id))
}
