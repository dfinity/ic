use crate::crypto::canister_threshold_sig::idkg::{
    IDkgMaskedTranscriptOrigin, IDkgReceivers, IDkgTranscript, IDkgTranscriptId,
    IDkgTranscriptOperation, IDkgTranscriptParams, IDkgTranscriptType,
    IDkgUnmaskedTranscriptOrigin,
};
use crate::crypto::AlgorithmId;
use crate::{Height, NodeId, PrincipalId, RegistryVersion, SubnetId};
use ic_crypto_test_utils_canister_threshold_sigs::node_id;
use rand::Rng;
use std::collections::{BTreeMap, BTreeSet};

pub fn create_params_for_dealers(
    dealer_set: &BTreeSet<NodeId>,
    operation: IDkgTranscriptOperation,
) -> IDkgTranscriptParams {
    IDkgTranscriptParams::new(
        random_transcript_id(),
        dealer_set.clone(),
        dealer_set.clone(),
        RegistryVersion::from(0),
        AlgorithmId::ThresholdEcdsaSecp256k1,
        operation,
    )
    .expect("Should be able to create IDKG params")
}

// A randomized way to get non-repeating IDs.
pub fn random_transcript_id() -> IDkgTranscriptId {
    let rng = &mut rand::thread_rng();

    let id = rng.gen();
    let subnet = SubnetId::from(PrincipalId::new_subnet_test_id(rng.gen::<u64>()));
    let height = Height::from(rng.gen::<u64>());

    IDkgTranscriptId::new(subnet, id, height)
}

pub fn mock_unmasked_transcript_type() -> IDkgTranscriptType {
    IDkgTranscriptType::Unmasked(IDkgUnmaskedTranscriptOrigin::ReshareMasked(
        random_transcript_id(),
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
        transcript_id: random_transcript_id(),
        receivers: IDkgReceivers::new(receivers).unwrap(),
        registry_version: RegistryVersion::from(314),
        verified_dealings: BTreeMap::new(),
        transcript_type,
        algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
        internal_transcript_raw: vec![],
    }
}
