use ic_crypto_test_utils_ni_dkg::{
    NiDkgTestEnvironment, RandomNiDkgConfig, run_ni_dkg_and_create_single_transcript,
};
use ic_crypto_test_utils_reproducible_rng::{ReproducibleRng, reproducible_rng};
use ic_types::RegistryVersion;
use ic_types::crypto::threshold_sig::ni_dkg::NiDkgTag;

const REG_V1: RegistryVersion = RegistryVersion::new(1);

#[test]
fn should_have_expected_size_for_nidkg_transcript_serializations() {
    fn protobuf_encoding_of_initial_dkg_transcript_record(
        rng: &mut ReproducibleRng,
        subnet_size: usize,
        dealer_count: usize,
        threshold: NiDkgTag,
    ) -> usize {
        use ic_protobuf::registry::subnet::v1::InitialNiDkgTranscriptRecord;
        use prost::Message;

        let config = RandomNiDkgConfig::builder()
            .dealer_count(dealer_count)
            .subnet_size(subnet_size)
            .max_corrupt_dealers((dealer_count - 1) / 3)
            .dkg_tag(threshold)
            .registry_version(REG_V1)
            .build(rng);

        let env = NiDkgTestEnvironment::new_for_config(config.get(), rng);
        let transcript =
            run_ni_dkg_and_create_single_transcript(config.get(), &env.crypto_components);

        let record = InitialNiDkgTranscriptRecord::from(transcript);

        let mut record_pb = vec![];
        record
            .encode(&mut record_pb)
            .expect("Protobuf encoding failed");
        record_pb.len()
    }

    // (dealer_count, subnet_size, expected_transcript_size)
    //
    // Expected sizes are computed using cost_estimator.py
    let config_and_expected_size: [(usize, usize, usize); 2] = [
        (13, 13, 66144),
        (34, 34, 352416),
        // (40, 13, 183648), // disabled so the test has reasonable runtime
        // (40, 28, 345888), // disabled so the test has reasonable runtime
    ];

    let allowed_overhead = 1.05;

    let rng = &mut reproducible_rng();

    for (dealer_count, subnet_size, expected_size) in config_and_expected_size {
        for threshold in [NiDkgTag::LowThreshold, NiDkgTag::HighThreshold] {
            let record_len = protobuf_encoding_of_initial_dkg_transcript_record(
                rng,
                subnet_size,
                dealer_count,
                threshold.clone(),
            );
            let overhead = (record_len as f64) / (expected_size as f64);

            println!(
                "Subnet size {subnet_size} with {dealer_count} dealers, threshold {threshold:?} protobuf transcript size {record_len} (overhead {overhead:.3})",
            );

            assert!(
                record_len >= expected_size,
                "Record is smaller than theoretical minimum"
            );

            assert!(
                overhead < allowed_overhead,
                "Record exceeds allowed overhead"
            );
        }
    }
}
