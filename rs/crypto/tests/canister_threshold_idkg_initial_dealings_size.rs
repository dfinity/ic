use ic_crypto_test_utils_canister_threshold_sigs::{
    CanisterThresholdSigTestEnvironment, generate_initial_dealings,
};
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_types::crypto::AlgorithmId;

#[test]
fn should_have_expected_size_for_initial_idkg_dealings() {
    use ic_protobuf::registry::subnet::v1::InitialIDkgDealings as InitialIDkgDealingsProto;
    use prost::Message;

    let rng = &mut reproducible_rng();

    const ALLOWED_OVERHEAD: f64 = 1.25;

    // Sizes based on the optimium possible size computed using
    // the following, plugged into the cost_estimator.py script:

    /*
    subnet_size = 13

    # by default assume sending and receiving subnet are same size
    dealers = subnet_size
    receivers = subnet_size

    # size of NodeID in bytes
    node_id_bytes = 29

    # size of a TranscriptID in bytes
    transcript_id_bytes = 45

    point_bytes = 32

    faults_tolerated = (receivers - 1) // 3

    # Size of a polynomial commitment in bytes
    commitment_bytes = point_bytes*(1 + faults_tolerated)

    # Size of a MeGA ciphertext in bytes
    ciphertext_bytes = point_bytes*(4 + receivers)

    # Size of an EdDSA signature in bytes
    signature_bytes = 64

    # Size in bytes of a dealing issued by a dealer
    dealing_bytes = node_id_bytes + transcript_id_bytes + signature_bytes + ciphertext_bytes + commitment_bytes

    # Size in bytes of a dealing with maximum support shares
    verified_dealing = dealing_bytes + receivers*(node_id_bytes + signature_bytes)

    # Size of an IDKG transcript in bytes
    transcript_bytes = transcript_id_bytes + commitment_bytes + node_id_bytes*receivers + verified_dealing*(1 + faults_tolerated)

    # Size of the IDKG params in bytes
    params_bytes = transcript_id_bytes + node_id_bytes*(dealers + receivers) + transcript_bytes

    # Size of initial IDKG dealings for XNet resharing in bytes
    initial_dealings_bytes = params_bytes + dealing_bytes*(1 + 2*faults_tolerated)
     */
    let testcases = [
        (AlgorithmId::ThresholdEcdsaSecp256k1, 13, 19214),
        (AlgorithmId::ThresholdEcdsaSecp256k1, 28, 71864),
        (AlgorithmId::ThresholdEcdsaSecp256k1, 40, 137852),
    ];

    for (alg, subnet_size, expected_size) in &testcases {
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size * 2, rng);

        let (source_subnet_nodes, destination_subnet_nodes) =
            env.nodes.partition(|(index, _node)| *index < *subnet_size);

        let (initial_dealings, _params) = generate_initial_dealings(
            *alg,
            env.newest_registry_version,
            source_subnet_nodes,
            destination_subnet_nodes,
            false,
            rng,
        );

        let proto = InitialIDkgDealingsProto::from(&initial_dealings);

        let mut record_pb = vec![];
        proto
            .encode(&mut record_pb)
            .expect("Protobuf encoding failed");
        let len = record_pb.len();

        let lower_bound = *expected_size;
        let upper_bound = (*expected_size as f64 * ALLOWED_OVERHEAD) as usize;

        assert!(len >= lower_bound);
        assert!(len <= upper_bound);
    }
}
