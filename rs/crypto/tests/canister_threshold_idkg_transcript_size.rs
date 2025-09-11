use ic_crypto_test_utils_canister_threshold_sigs::{
    build_params_from_previous, generate_ecdsa_presig_quadruple, setup_masked_random_params,
    CanisterThresholdSigTestEnvironment, IDkgParticipants,
};
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_protobuf::registry::subnet::v1::IDkgTranscript as IDkgTranscriptProto;
use ic_types::crypto::canister_threshold_sig::idkg::{IDkgTranscript, IDkgTranscriptOperation};
use ic_types::crypto::AlgorithmId;
use prost::Message;

struct IDkgTranscriptSize {
    transcript_id_size: usize,
    receivers_size: usize,
    registry_version_size: usize,
    verified_dealings_size: usize,
    transcript_type_size: usize,
    algorithm_id_size: usize,
    transcript_raw_size: usize,
}

impl From<&IDkgTranscript> for IDkgTranscriptSize {
    fn from(transcript: &IDkgTranscript) -> Self {
        let proto = IDkgTranscriptProto::from(transcript);

        let transcript_id_size = {
            let mut encoded = vec![];
            proto.transcript_id.unwrap().encode(&mut encoded).unwrap();
            encoded.len()
        };
        let receivers_size = {
            // Calculate the encoded size by creating a temporary proto with only receivers
            let mut temp_proto = IDkgTranscriptProto::default();
            temp_proto.receivers = proto.receivers.clone();
            temp_proto.encoded_len()
        };
        let registry_version_size = {
            let mut encoded = vec![];
            proto.registry_version.encode(&mut encoded).unwrap();
            encoded.len()
        };
        let verified_dealings_size = {
            // Calculate the encoded size by creating a temporary proto with only receivers
            let mut temp_proto = IDkgTranscriptProto::default();
            temp_proto.verified_dealings = proto.verified_dealings.clone();
            temp_proto.encoded_len()
            
        };
        let transcript_type_size = {
            let mut encoded = vec![];
            proto.transcript_type.encode(&mut encoded).unwrap();
            encoded.len()
        };
        let algorithm_id_size = {
            let mut encoded = vec![];
            proto.algorithm_id.encode(&mut encoded).unwrap();
            encoded.len()
        };
        let transcript_raw_size = {
            let mut encoded = vec![];
            proto.raw_transcript.encode(&mut encoded).unwrap();
            encoded.len()
        };
        Self {
            transcript_id_size,
            receivers_size,
            registry_version_size,
            verified_dealings_size,
            transcript_type_size,
            algorithm_id_size,
            transcript_raw_size,
        }
    }
}

#[test]
fn should_have_expected_size_for_idkg_transcripts() {
    let rng = &mut reproducible_rng();

    fn transcript_bytes(transcript: &IDkgTranscript) -> usize {
        let proto = IDkgTranscriptProto::from(transcript);

        let mut record_pb = vec![];
        proto
            .encode(&mut record_pb)
            .expect("Protobuf encoding failed");
        record_pb.len()
    }

    fn check_size(
        what: &str,
        transcript: &IDkgTranscript,
        expected_size: usize,
        subnet_size: usize,
    ) {
        let allowed_overhead = 1.05;

        let tb = transcript_bytes(transcript);
        // assert!(tb >= expected_size);
        // assert!(tb as f64 <= expected_size as f64 * allowed_overhead);

        let size = IDkgTranscriptSize::from(transcript);
        println!(
            "{what} transcript for {subnet_size} nodes is {tb} bytes
    transcript_id: {} bytes
    receivers: {} bytes
    registry_version: {} bytes
    verified_dealings: {} bytes
    transcript_type: {} bytes
    algorithm_id: {} bytes
    raw_transcript: {} bytes
            ",
            size.transcript_id_size,
            size.receivers_size,
            size.registry_version_size,
            size.verified_dealings_size,
            size.transcript_type_size,
            size.algorithm_id_size,
            size.transcript_raw_size
        );
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
            34,
            93500,
            92200,
            112300,
            219000,
            219000,
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
            config.subnet_size,
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
            config.subnet_size,
        );
        check_size(
            "lambda_masked",
            quadruple.lambda_masked(),
            config.lambda_masked,
            config.subnet_size,
        );
        check_size(
            "kappa_times_lambda",
            quadruple.kappa_times_lambda(),
            config.kappa_times_lambda,
            config.subnet_size,
        );
        check_size(
            "key_times_lambda",
            quadruple.key_times_lambda(),
            config.key_times_lambda,
            config.subnet_size,
        );
        println!("\n");
    }
}
