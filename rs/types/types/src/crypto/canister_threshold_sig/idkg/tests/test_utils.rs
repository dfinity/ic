use crate::crypto::AlgorithmId;
use crate::crypto::canister_threshold_sig::idkg::{
    IDkgMaskedTranscriptOrigin, IDkgReceivers, IDkgTranscript, IDkgTranscriptId,
    IDkgTranscriptOperation, IDkgTranscriptParams, IDkgTranscriptType,
    IDkgUnmaskedTranscriptOrigin,
};
use crate::{Height, NodeId, PrincipalId, RegistryVersion, SubnetId};
use ic_crypto_test_utils_canister_threshold_sigs::node_id;
use rand::{CryptoRng, Rng};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

// Due to a quasi-circular dependency with ic-types
// the test utilities here cannot be replaced by the ones in
// ic-crypto-test-utils-canister-threshold-sigs
pub fn create_idkg_params<R: Rng + CryptoRng>(
    dealer_set: &BTreeSet<NodeId>,
    receiver_set: &BTreeSet<NodeId>,
    operation: IDkgTranscriptOperation,
    rng: &mut R,
) -> IDkgTranscriptParams {
    IDkgTranscriptParams::new(
        random_transcript_id(rng),
        dealer_set.clone(),
        receiver_set.clone(),
        RegistryVersion::from(0),
        AlgorithmId::ThresholdEcdsaSecp256k1,
        operation,
    )
    .expect("Should be able to create IDKG params")
}

// A randomized way to get non-repeating IDs.
pub fn random_transcript_id<R: Rng + CryptoRng>(rng: &mut R) -> IDkgTranscriptId {
    let id = rng.r#gen();
    let subnet = SubnetId::from(PrincipalId::new_subnet_test_id(rng.r#gen::<u64>()));
    let height = Height::from(rng.r#gen::<u64>());

    IDkgTranscriptId::new(subnet, id, height)
}

pub fn mock_unmasked_transcript_type<R: Rng + CryptoRng>(rng: &mut R) -> IDkgTranscriptType {
    IDkgTranscriptType::Unmasked(IDkgUnmaskedTranscriptOrigin::ReshareMasked(
        random_transcript_id(rng),
    ))
}

pub fn mock_masked_transcript_type() -> IDkgTranscriptType {
    IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random)
}

pub fn mock_transcript<R: Rng + CryptoRng>(
    receivers: Option<BTreeSet<NodeId>>,
    transcript_type: IDkgTranscriptType,
    rng: &mut R,
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
        transcript_id: random_transcript_id(rng),
        receivers: IDkgReceivers::new(receivers).unwrap(),
        registry_version: RegistryVersion::from(314),
        verified_dealings: Arc::new(BTreeMap::new()),
        transcript_type,
        algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
        internal_transcript_raw: vec![],
    }
}
