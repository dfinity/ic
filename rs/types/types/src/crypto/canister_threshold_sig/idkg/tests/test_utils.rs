use crate::crypto::canister_threshold_sig::idkg::{
    IDkgMaskedTranscriptOrigin, IDkgReceivers, IDkgTranscript, IDkgTranscriptId,
    IDkgTranscriptOperation, IDkgTranscriptParams, IDkgTranscriptType,
    IDkgUnmaskedTranscriptOrigin,
};
use crate::crypto::AlgorithmId;
use crate::{NodeId, PrincipalId, RegistryVersion, SubnetId};
use ic_crypto_test_utils_canister_threshold_sigs::node_id;
use rand::Rng;
use std::collections::{BTreeMap, BTreeSet};

pub fn create_params_for_dealers(
    dealer_set: &BTreeSet<NodeId>,
    operation: IDkgTranscriptOperation,
) -> IDkgTranscriptParams {
    IDkgTranscriptParams::new(
        transcript_id_generator(),
        dealer_set.clone(),
        dealer_set.clone(),
        RegistryVersion::from(0),
        AlgorithmId::ThresholdEcdsaSecp256k1,
        operation,
    )
    .expect("Should be able to create IDKG params")
}

// A randomized way to get non-repeating IDs.
pub fn transcript_id_generator() -> IDkgTranscriptId {
    const SUBNET_ID: u64 = 314159;

    let rng = &mut rand::thread_rng();
    let id = rng.gen();
    let subnet = SubnetId::from(PrincipalId::new_subnet_test_id(SUBNET_ID));

    IDkgTranscriptId::new(subnet, id)
}

pub fn mock_unmasked_transcript_type() -> IDkgTranscriptType {
    IDkgTranscriptType::Unmasked(IDkgUnmaskedTranscriptOrigin::ReshareMasked(
        transcript_id_generator(),
    ))
}

pub fn mock_masked_transcript_type() -> IDkgTranscriptType {
    IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random)
}

pub fn mock_transcript(
    receivers: Option<BTreeSet<NodeId>>,
    transcript_type: IDkgTranscriptType,
) -> IDkgTranscript {
    let receivers = match receivers {
        Some(receivers) => receivers,
        None => {
            let mut receivers = BTreeSet::new();
            for i in 1..10 {
                receivers.insert(node_id(i));
            }
            receivers
        }
    };

    IDkgTranscript {
        transcript_id: transcript_id_generator(),
        receivers: IDkgReceivers::new(receivers).unwrap(),
        registry_version: RegistryVersion::from(314),
        verified_dealings: BTreeMap::new(),
        transcript_type,
        algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
        internal_transcript_raw: vec![],
    }
}
