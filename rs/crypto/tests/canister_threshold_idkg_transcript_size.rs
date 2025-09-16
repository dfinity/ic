use ic_crypto_test_utils_canister_threshold_sigs::{
    CanisterThresholdSigTestEnvironment, IDkgParticipants, build_params_from_previous,
    generate_ecdsa_presig_quadruple, setup_masked_random_params,
};
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_types::crypto::AlgorithmId;
use ic_types::crypto::canister_threshold_sig::idkg::{IDkgTranscript, IDkgTranscriptOperation};

#[test]
fn should_have_expected_size_for_idkg_transcripts() {
    let rng = &mut reproducible_rng();

    fn transcript_bytes(transcript: &IDkgTranscript) -> usize {
        use ic_protobuf::registry::subnet::v1::IDkgTranscript as IDkgTranscriptProto;
        use prost::Message;

        let proto = IDkgTranscriptProto::from(transcript);

        let mut record_pb = vec![];
        proto
            .encode(&mut record_pb)
            .expect("Protobuf encoding failed");
        record_pb.len()
    }

    fn check_size(what: &str, transcript: &IDkgTranscript, expected_size: usize) {
        let allowed_overhead = 1.05;

        let tb = transcript_bytes(transcript);
        println!("{what} transcript is {tb} bytes expected {expected_size}");
        assert!(tb >= expected_size);
        assert!(tb as f64 <= expected_size as f64 * allowed_overhead);
    }

    struct IDkgTranscriptSizes {
        alg: AlgorithmId,
        subnet_size: usize,
        unmasked_key: usize,
        kappa_unmasked: usize,
        lambda_masked: usize,
        kappa_times_lambda: usize,
        key_times_lambda: usize,
    }

    impl IDkgTranscriptSizes {
        fn new(
            alg: AlgorithmId,
            subnet_size: usize,
            unmasked_key: usize,
            kappa_unmasked: usize,
            lambda_masked: usize,
            kappa_times_lambda: usize,
            key_times_lambda: usize,
        ) -> Self {
            Self {
                alg,
                subnet_size,
                unmasked_key,
                kappa_unmasked,
                lambda_masked,
                kappa_times_lambda,
                key_times_lambda,
            }
        }
    }

    let test_config = [
        IDkgTranscriptSizes::new(
            AlgorithmId::ThresholdEcdsaSecp256k1,
            28,
            49000,
            47800,
            57900,
            111800,
            111800,
        ),
        IDkgTranscriptSizes::new(
            AlgorithmId::ThresholdEcdsaSecp256k1,
            40,
            93500,
            92200,
            112300,
            219000,
            219000,
        ),
    ];

    for config in &test_config {
        println!("{:?} {}", config.alg, config.subnet_size);
        let env = CanisterThresholdSigTestEnvironment::new(config.subnet_size, rng);
        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::AllNodesAsDealersAndReceivers, rng);

        let masked_key_params =
            setup_masked_random_params(&env, config.alg, &dealers, &receivers, rng);

        let masked_key_transcript = env
            .nodes
            .run_idkg_and_create_and_verify_transcript(&masked_key_params, rng);

        let unmasked_key_params = build_params_from_previous(
            masked_key_params,
            IDkgTranscriptOperation::ReshareOfMasked(masked_key_transcript.clone()),
            rng,
        );

        let unmasked_key_transcript = env
            .nodes
            .run_idkg_and_create_and_verify_transcript(&unmasked_key_params, rng);

        check_size(
            "unmasked_key",
            &unmasked_key_transcript,
            config.unmasked_key,
        );

        let quadruple = generate_ecdsa_presig_quadruple(
            &env,
            &dealers,
            &receivers,
            config.alg,
            &unmasked_key_transcript,
            rng,
        );

        check_size(
            "kappa_unmasked",
            quadruple.kappa_unmasked(),
            config.kappa_unmasked,
        );
        check_size(
            "lambda_masked",
            quadruple.lambda_masked(),
            config.lambda_masked,
        );
        check_size(
            "kappa_times_lambda",
            quadruple.kappa_times_lambda(),
            config.kappa_times_lambda,
        );
        check_size(
            "key_times_lambda",
            quadruple.key_times_lambda(),
            config.key_times_lambda,
        );
    }
}
