//! Utilities for testing Distributed Key Generation (DKG) code.
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::{
    ni_dkg_groth20_bls12_381, CspNiDkgDealing,
};
use ic_types::crypto::canister_threshold_sig::idkg::IDkgTranscriptId;
use ic_types::crypto::threshold_sig::ni_dkg::{NiDkgTag, NiDkgTranscript};
use ic_types::{Height, IDkgId, NodeId, PrincipalId, SubnetId};
use ic_types_test_utils::ids::node_test_id;
use rand::Rng;

/// Generate a random `IDkgId`.
///
/// Note: There is a proptest strategy for `IDkgId` which is useful in many
/// circumstances but cumbersome in others.  Please use the appropriate method
/// for each circumstance.
pub fn random_dkg_id<R: Rng>(rng: &mut R) -> IDkgId {
    let instance_id = Height::from(rng.gen::<u64>());
    let subnet_id = SubnetId::from(PrincipalId::new_subnet_test_id(rng.gen::<u64>()));
    IDkgId {
        instance_id,
        subnet_id,
    }
}

pub fn ni_dkg_csp_dealing(seed: u8) -> CspNiDkgDealing {
    use ni_dkg_groth20_bls12_381 as scheme;
    fn fr(seed: u8) -> scheme::Fr {
        scheme::Fr([seed; scheme::Fr::SIZE])
    }
    fn g1(seed: u8) -> scheme::G1 {
        scheme::G1([seed; scheme::G1::SIZE])
    }
    fn g2(seed: u8) -> scheme::G2 {
        scheme::G2([seed; scheme::G2::SIZE])
    }
    const NUM_RECEIVERS: usize = 1;
    CspNiDkgDealing::Groth20_Bls12_381(scheme::Dealing {
        public_coefficients: scheme::PublicCoefficientsBytes {
            coefficients: Vec::new(),
        },
        ciphertexts: scheme::EncryptedShares {
            rand_r: [g1(seed); scheme::NUM_CHUNKS],
            rand_s: [g1(seed); scheme::NUM_CHUNKS],
            rand_z: [g2(seed); scheme::NUM_CHUNKS],
            ciphertext_chunks: (0..NUM_RECEIVERS)
                .map(|i| [g1(seed ^ (i as u8)); scheme::NUM_CHUNKS])
                .collect(),
        },
        zk_proof_decryptability: ni_dkg_groth20_bls12_381::ZKProofDec {
            // TODO(CRP-530): Populate this when it has been defined in the spec.
            first_move_y0: g1(seed),
            first_move_b: [g1(seed); scheme::NUM_ZK_REPETITIONS],
            first_move_c: [g1(seed); scheme::NUM_ZK_REPETITIONS],
            second_move_d: (0..NUM_RECEIVERS + 1)
                .map(|i| g1(seed ^ (i as u8)))
                .collect(),
            second_move_y: g1(seed),
            response_z_r: (0..NUM_RECEIVERS).map(|i| fr(seed | (i as u8))).collect(),
            response_z_s: [fr(seed); scheme::NUM_ZK_REPETITIONS],
            response_z_b: fr(seed),
        },
        zk_proof_correct_sharing: ni_dkg_groth20_bls12_381::ZKProofShare {
            first_move_f: g1(seed),
            first_move_a: g2(seed),
            first_move_y: g1(seed),
            response_z_r: fr(seed),
            response_z_a: fr(seed),
        },
    })
}

pub fn empty_ni_dkg_transcripts_with_committee(
    committee: Vec<NodeId>,
    registry_version: u64,
) -> std::collections::BTreeMap<NiDkgTag, NiDkgTranscript> {
    vec![
        (
            NiDkgTag::LowThreshold,
            NiDkgTranscript::dummy_transcript_for_tests_with_params(
                committee.clone(),
                NiDkgTag::LowThreshold,
                NiDkgTag::LowThreshold.threshold_for_subnet_of_size(committee.len()) as u32,
                registry_version,
            ),
        ),
        (
            NiDkgTag::HighThreshold,
            NiDkgTranscript::dummy_transcript_for_tests_with_params(
                committee.clone(),
                NiDkgTag::HighThreshold,
                NiDkgTag::HighThreshold.threshold_for_subnet_of_size(committee.len()) as u32,
                registry_version,
            ),
        ),
    ]
    .into_iter()
    .collect()
}

pub fn empty_ni_dkg_transcripts() -> std::collections::BTreeMap<NiDkgTag, NiDkgTranscript> {
    empty_ni_dkg_transcripts_with_committee(vec![node_test_id(0)], 0)
}

pub fn dummy_idkg_transcript_id_for_tests(id: u64) -> IDkgTranscriptId {
    let subnet = SubnetId::from(PrincipalId::new_subnet_test_id(314159));
    let height = Height::new(42);
    IDkgTranscriptId::new(subnet, id, height)
}
