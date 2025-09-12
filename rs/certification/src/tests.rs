use std::str::FromStr;

use assert_matches::assert_matches;
use rand::{Rng, thread_rng};

use ic_base_types::{CanisterId, PrincipalId, SubnetId};
use ic_certification_test_utils::{
    CanisterRangesFormat, CertificateBuilder,
    CertificateData::{CanisterData, CustomTree, SubnetData},
    encoded_time, serialize_to_cbor,
};
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_crypto_tree_hash::{Digest, Label, LabeledTree, flatmap};
use ic_crypto_utils_threshold_sig_der::{parse_threshold_sig_key_from_der, public_key_to_der};
use ic_types::Time;
use ic_types::crypto::threshold_sig::ThresholdSigPublicKey;
use rstest::rstest;

use crate::{
    CertificateValidationError, validate_subnet_delegation_certificate,
    validate_subnet_delegation_certificate_with_cache, verify_certified_data,
    verify_certified_data_with_cache, verify_delegation_certificate,
};

fn verify_certified_data_with_and_without_cache(
    certificate: &[u8],
    canister_id: &CanisterId,
    root_pk: &ThresholdSigPublicKey,
    certified_data: &[u8],
) -> Result<Time, CertificateValidationError> {
    let verification_result_without_cache =
        verify_certified_data(certificate, canister_id, root_pk, certified_data);

    let verification_result_with_cache =
        verify_certified_data_with_cache(certificate, canister_id, root_pk, certified_data);

    assert_eq!(
        verification_result_without_cache,
        verification_result_with_cache
    );

    verification_result_without_cache
}

fn validate_subnet_delegation_certificate_with_and_without_cache(
    certificate: &[u8],
    subnet_id: &SubnetId,
    root_pk: &ThresholdSigPublicKey,
) -> Result<(), CertificateValidationError> {
    let verification_result_without_cache =
        validate_subnet_delegation_certificate(certificate, subnet_id, root_pk);
    let verification_result_with_cache =
        validate_subnet_delegation_certificate_with_cache(certificate, subnet_id, root_pk);

    assert_eq!(
        verification_result_without_cache,
        verification_result_with_cache
    );

    verification_result_without_cache
}

fn verify_subnet_delegation_certificate_with_and_without_cache(
    certificate: &[u8],
    subnet_id: &SubnetId,
    canister_id: &CanisterId,
    root_pk: &ThresholdSigPublicKey,
) -> Result<ThresholdSigPublicKey, CertificateValidationError> {
    let verification_result_without_cache =
        verify_delegation_certificate(certificate, subnet_id, root_pk, Some(canister_id), false);
    let verification_result_with_cache =
        verify_delegation_certificate(certificate, subnet_id, root_pk, Some(canister_id), true);

    assert_eq!(
        verification_result_without_cache,
        verification_result_with_cache
    );

    verification_result_without_cache
}

#[test]
fn should_validate_subnet_delegation_test_vector() {
    // test vector was generated on a testnet using Internet Identity deployed to an application subnet
    let certificate = hex::decode("D9D9F7A3647472656583018301830183024863616E6973746572830183018301830183024A000000000010000001018301830183024E6365727469666965645F6461746182035820619D02453B55BA8EA01DA1D26DF7083644EBE84A97AFC8D4ECE7F82453548EAA82045820D598630C2C94E80F8EDD451F3B7E942ACE5680B60FB5897A96A466D2F8FCF6F882045820FD96014A4A0368DBD8BD4BD05806C0F8C6BDFBDFBE6F6182B9E4963F18ADD55B8204582072379FD63D4B0A8E7D0C9F87316613DC1ADED56B7311F83213FF213F8B802F1C820458208079C8D69F2C1813E63B2488CD1C7D0BAA73ECE24AEAAD48348D7A1F9B8E868F82045820F7251F6708258AA9E995EE4A923E615908D40E9D4C57DFA84640B77B76D016D0820458205D38A89DDE470A2252C2F4060C42AD6EBCBE5C689CA68241C2858D1149B13386820458200BDF772535F123B48C553D3AE0B6B464277B8E2DDF887CDFE5F54B595352BD658204582055A1F078E350F151DDDE43AEDFBAC8647AC4B392F7141917824EFB1A956B79DB8301820458205C9ABFBA1DFE4D188D30474AF0A1BB796D8EFA15353973A0EEC3427675789C1783024474696D6582034980EFCBB1A5FEF5E616697369676E61747572655830A754B5AE47F254B23420F17E71265CDAF64D34BA002BA88578FDF3CD9B2436FE5A3B7A2245E6DCF4A574169EB72DD4DF6A64656C65676174696F6EA2697375626E65745F6964581DCF9D54E35F653FD0FD4FF05E9C020923B719429C9A3139BEAAF4871B026B6365727469666963617465590199D9D9F7A26474726565830182045820E82F4E336F033E15D337975AF1617E1030F4C6F9F53FCF89A48E861F75C5C98483018302467375626E6574830182045820FB286DDA6CB7FE72AF261F5C896D51CBF82F233679907A1CB7E7299B44F5E23D8302581DCF9D54E35F653FD0FD4FF05E9C020923B719429C9A3139BEAAF4871B02830183024F63616E69737465725F72616E6765738203581BD9D9F781824A000000000010000001014A00000000001FFFFF010183024A7075626C69635F6B657982035885308182301D060D2B0601040182DC7C0503010201060C2B0601040182DC7C0503020103610088EB824FC43459023B08806C56AC224EDEA54AF7A656D96F6E909906B7442AC65A60D2C0B831425B0376674430E48F1D09658CD3F86BDD8607199401422C8B641C43F58740F52B497136E70B62522AEF12A6DB95ECBA58123D44D9B2E852B40883024474696D6582034987A5E7EB83F2E3E416697369676E6174757265583091EC641476446FFA0AB613BE624664BFEC32F7AC20B7E943EA7DACE1B7247101CA5B3CD6DFF38E6276BD6A7AF6C0587F").unwrap();
    let root_pubkey = hex::decode("308182301D060D2B0601040182DC7C0503010201060C2B0601040182DC7C05030201036100923A67B791270CD8F5320212AE224377CF407D3A8A2F44F11FED5915A97EE67AD0E90BC382A44A3F14C363AD2006640417B4BBB3A304B97088EC6B4FC87A25558494FC239B47E129260232F79973945253F5036FD520DDABD1E2DE57ABFB40CB").unwrap();
    let certified_data = [
        97, 157, 2, 69, 59, 85, 186, 142, 160, 29, 161, 210, 109, 247, 8, 54, 68, 235, 232, 74,
        151, 175, 200, 212, 236, 231, 248, 36, 83, 84, 142, 170,
    ];

    let verification_result = verify_certified_data_with_and_without_cache(
        &certificate,
        &CanisterId::from_str("5v3p4-iyaaa-aaaaa-qaaaa-cai").unwrap(),
        &parse_threshold_sig_key_from_der(&root_pubkey).unwrap(),
        &certified_data,
    );

    verification_result.expect("expect valid signature");
}

#[test]
fn should_validate_certificate_without_delegation() {
    let rng = &mut reproducible_rng();
    let certified_data = random_certified_data();
    let (_cert, pk, cbor) = CertificateBuilder::new_with_rng(
        CanisterData {
            canister_id: canister_id(1),
            certified_data: certified_data.clone(),
        },
        rng,
    )
    .build();

    let verification_result = verify_certified_data_with_and_without_cache(
        &cbor,
        &canister_id(1),
        &pk,
        certified_data.as_bytes(),
    );

    verification_result.expect("expect valid signature");
}

#[test]
fn should_return_correct_time() {
    let rng = &mut reproducible_rng();
    let certified_data = random_certified_data();
    let time = Time::from_nanos_since_unix_epoch(1);

    let (_cert, pk, cbor) = CertificateBuilder::new_with_rng(
        CanisterData {
            canister_id: canister_id(1),
            certified_data: certified_data.clone(),
        },
        rng,
    )
    .with_time(time.as_nanos_since_unix_epoch())
    .build();

    let verification_result = verify_certified_data_with_and_without_cache(
        &cbor,
        &canister_id(1),
        &pk,
        certified_data.as_bytes(),
    );

    verification_result.expect("expect valid signature");
}

#[test]
fn should_validate_certificate_with_delegation() {
    let rng = &mut reproducible_rng();
    let certified_data = random_certified_data();
    let (_cert, pk, cbor) = CertificateBuilder::new_with_rng(
        CanisterData {
            canister_id: canister_id(1),
            certified_data: certified_data.clone(),
        },
        rng,
    )
    .with_delegation(CertificateBuilder::new_with_rng(
        SubnetData {
            subnet_id: subnet_id(1),
            canister_id_ranges: vec![(canister_id(0), canister_id(10))],
        },
        rng,
    ))
    .build();

    let verification_result = verify_certified_data_with_and_without_cache(
        &cbor,
        &canister_id(1),
        &pk,
        certified_data.as_bytes(),
    );

    verification_result.expect("expect valid signature");
}

#[rstest]
#[case::old_format(CanisterRangesFormat::Flat)]
#[case::new_format(CanisterRangesFormat::Tree)]
fn should_validate_certificate_with_delegation_lowest_canister_id(
    #[case] format: CanisterRangesFormat,
) {
    let rng = &mut reproducible_rng();
    let low_canister_id = canister_id(0);
    let certified_data = random_certified_data();
    let (_cert, pk, cbor) = CertificateBuilder::new_with_rng(
        CanisterData {
            canister_id: low_canister_id,
            certified_data: certified_data.clone(),
        },
        rng,
    )
    .with_delegation(
        CertificateBuilder::new_with_rng(
            SubnetData {
                subnet_id: subnet_id(1),
                canister_id_ranges: vec![(low_canister_id, canister_id(10))],
            },
            rng,
        )
        .with_canister_ranges_format(format),
    )
    .build();

    let verification_result = verify_certified_data_with_and_without_cache(
        &cbor,
        &low_canister_id,
        &pk,
        certified_data.as_bytes(),
    );

    verification_result.expect("expect valid signature");
}

#[rstest]
#[case::old_format(CanisterRangesFormat::Flat)]
#[case::new_format(CanisterRangesFormat::Tree)]
fn should_validate_certificate_with_delegation_highest_canister_id(
    #[case] format: CanisterRangesFormat,
) {
    let rng = &mut reproducible_rng();
    let high_canister_id = canister_id(10);
    let certified_data = random_certified_data();
    let (_cert, pk, cbor) = CertificateBuilder::new_with_rng(
        CanisterData {
            canister_id: high_canister_id,
            certified_data: certified_data.clone(),
        },
        rng,
    )
    .with_delegation(
        CertificateBuilder::new_with_rng(
            SubnetData {
                subnet_id: subnet_id(1),
                canister_id_ranges: vec![(canister_id(0), high_canister_id)],
            },
            rng,
        )
        .with_canister_ranges_format(format),
    )
    .build();
    let verification_result = verify_certified_data_with_and_without_cache(
        &cbor,
        &high_canister_id,
        &pk,
        certified_data.as_bytes(),
    );

    verification_result.expect("expect valid signature");
}

#[rstest]
#[case::old_format(CanisterRangesFormat::Flat)]
#[case::new_format(CanisterRangesFormat::Tree)]
fn should_validate_certificate_with_single_id_canister_id_range(
    #[case] format: CanisterRangesFormat,
) {
    let rng = &mut reproducible_rng();
    let canister_id = canister_id(1);
    let certified_data = random_certified_data();
    let (_cert, pk, cbor) = CertificateBuilder::new_with_rng(
        CanisterData {
            canister_id,
            certified_data: certified_data.clone(),
        },
        rng,
    )
    .with_delegation(
        CertificateBuilder::new_with_rng(
            SubnetData {
                subnet_id: subnet_id(1),
                canister_id_ranges: vec![(canister_id, canister_id)],
            },
            rng,
        )
        .with_canister_ranges_format(format),
    )
    .build();
    let verification_result = verify_certified_data_with_and_without_cache(
        &cbor,
        &canister_id,
        &pk,
        certified_data.as_bytes(),
    );

    verification_result.expect("expect valid signature");
}

#[rstest]
#[case::old_format(CanisterRangesFormat::Flat)]
#[case::new_format(CanisterRangesFormat::Tree)]
fn should_validate_certificate_with_delegation_with_multiple_canister_id_ranges(
    #[case] format: CanisterRangesFormat,
) {
    let rng = &mut reproducible_rng();
    let cid = canister_id(21);
    let certified_data = random_certified_data();
    let (_cert, pk, cbor) = CertificateBuilder::new_with_rng(
        CanisterData {
            canister_id: cid,
            certified_data: certified_data.clone(),
        },
        rng,
    )
    .with_delegation(
        CertificateBuilder::new_with_rng(
            SubnetData {
                subnet_id: subnet_id(1),
                canister_id_ranges: vec![
                    (canister_id(0), canister_id(2)),
                    (canister_id(4), canister_id(6)),
                    (canister_id(8), canister_id(10)),
                    (canister_id(12), canister_id(14)),
                    (canister_id(14), canister_id(16)),
                    (canister_id(16), canister_id(18)),
                    (canister_id(20), canister_id(22)),
                ],
            },
            rng,
        )
        .with_canister_ranges_format(format),
    )
    .build();
    let verification_result =
        verify_certified_data_with_and_without_cache(&cbor, &cid, &pk, certified_data.as_bytes());

    verification_result.expect("expect valid signature");
}

#[test]
fn should_fail_certificate_verification_with_empty_canister_id_range() {
    let rng = &mut reproducible_rng();
    let (_cert, pk, cbor) = CertificateBuilder::new_with_rng(
        CanisterData {
            canister_id: canister_id(1),
            certified_data: random_certified_data(),
        },
        rng,
    )
    .with_delegation(CertificateBuilder::new_with_rng(
        SubnetData {
            subnet_id: subnet_id(1),
            canister_id_ranges: vec![(canister_id(10), canister_id(0))],
        },
        rng,
    ))
    .build();

    let verification_result = verify_certified_data_with_and_without_cache(
        &cbor,
        &canister_id(1),
        &pk,
        random_certified_data().as_bytes(),
    );

    assert_matches!(
        verification_result,
        Err(CertificateValidationError::CanisterIdOutOfRange)
    );
}

#[test]
fn should_fail_certificate_with_invalid_signature() {
    let rng = &mut reproducible_rng();
    let (_cert, pk, cbor) = CertificateBuilder::new_with_rng(
        CanisterData {
            canister_id: canister_id(1),
            certified_data: random_certified_data(),
        },
        rng,
    )
    .with_invalid_sig()
    .build();

    let verification_result = verify_certified_data_with_and_without_cache(
        &cbor,
        &canister_id(1),
        &pk,
        random_certified_data().as_bytes(),
    );
    assert_matches!(
        verification_result,
        Err(CertificateValidationError::InvalidSignature(_))
    );
}

#[test]
fn should_fail_certificate_validation_with_wrong_public_key() {
    let rng = &mut reproducible_rng();
    // public key taken from the identity testnet subnet info https://internetcomputer.org/docs/interface-spec/index.html#state-tree-subnet
    let wrong_pk = parse_threshold_sig_key_from_der(&hex::decode("308182301D060D2B0601040182DC7C0503010201060C2B0601040182DC7C05030201036100923A67B791270CD8F5320212AE224377CF407D3A8A2F44F11FED5915A97EE67AD0E90BC382A44A3F14C363AD2006640417B4BBB3A304B97088EC6B4FC87A25558494FC239B47E129260232F79973945253F5036FD520DDABD1E2DE57ABFB40CB").unwrap()).unwrap();
    let (_cert, pk, cbor) = CertificateBuilder::new_with_rng(
        CanisterData {
            canister_id: canister_id(1),
            certified_data: random_certified_data(),
        },
        rng,
    )
    .with_invalid_sig()
    .build();

    assert_ne!(pk, wrong_pk);

    let verification_result = verify_certified_data_with_and_without_cache(
        &cbor,
        &canister_id(1),
        &wrong_pk,
        random_certified_data().as_bytes(),
    );
    assert_matches!(
        verification_result,
        Err(CertificateValidationError::InvalidSignature(_))
    );
}

#[test]
fn should_fail_certificate_verification_with_invalid_delegation_signature() {
    let rng = &mut reproducible_rng();
    let (_cert, pk, cbor) = CertificateBuilder::new_with_rng(
        CanisterData {
            canister_id: canister_id(1),
            certified_data: random_certified_data(),
        },
        rng,
    )
    .with_delegation(
        CertificateBuilder::new_with_rng(
            SubnetData {
                subnet_id: subnet_id(1),
                canister_id_ranges: vec![(canister_id(0), canister_id(10))],
            },
            rng,
        )
        .with_invalid_sig(),
    )
    .build();

    let verification_result = verify_certified_data_with_and_without_cache(
        &cbor,
        &canister_id(1),
        &pk,
        random_certified_data().as_bytes(),
    );

    assert_matches!(
        verification_result,
        Err(CertificateValidationError::InvalidSignature(_))
    );
}

#[test]
fn should_fail_certificate_verification_with_mismatched_delegation_subnet_id() {
    let rng = &mut reproducible_rng();
    let cert_subnet_id = subnet_id(1);
    let delegation_subnet_id = subnet_id(2);

    let (_cert, pk, cbor) = CertificateBuilder::new_with_rng(
        CanisterData {
            canister_id: canister_id(1),
            certified_data: random_certified_data(),
        },
        rng,
    )
    .with_delegation_subnet_id(cert_subnet_id)
    .with_delegation(CertificateBuilder::new_with_rng(
        SubnetData {
            subnet_id: delegation_subnet_id,
            canister_id_ranges: vec![(canister_id(0), canister_id(10))],
        },
        rng,
    ))
    .build();

    let verification_result = verify_certified_data_with_and_without_cache(
        &cbor,
        &canister_id(1),
        &pk,
        random_certified_data().as_bytes(),
    );

    assert_matches!(
        verification_result,
        Err(CertificateValidationError::MalformedHashTree(_))
    );
}

#[test]
fn should_fail_certificate_verification_with_too_many_delegations() {
    let rng = &mut reproducible_rng();
    let (_cert, pk, cbor) = CertificateBuilder::new_with_rng(
        CanisterData {
            canister_id: canister_id(1),
            certified_data: random_certified_data(),
        },
        rng,
    )
    .with_delegation(
        CertificateBuilder::new_with_rng(
            SubnetData {
                subnet_id: subnet_id(1),
                canister_id_ranges: vec![(canister_id(0), canister_id(10))],
            },
            rng,
        )
        .with_delegation(CertificateBuilder::new_with_rng(
            SubnetData {
                subnet_id: subnet_id(1),
                canister_id_ranges: vec![(canister_id(0), canister_id(100))],
            },
            rng,
        )),
    )
    .build();

    let verification_result = verify_certified_data_with_and_without_cache(
        &cbor,
        &canister_id(1),
        &pk,
        random_certified_data().as_bytes(),
    );

    assert_matches!(
        verification_result,
        Err(CertificateValidationError::MultipleSubnetDelegationsNotAllowed)
    );
}

#[rstest]
#[case::old_format(CanisterRangesFormat::Flat)]
#[case::new_format(CanisterRangesFormat::Tree)]
fn should_fail_certificate_verification_with_canister_id_out_of_range(
    #[case] format: CanisterRangesFormat,
) {
    let rng = &mut reproducible_rng();
    let (_cert, pk, cbor) = CertificateBuilder::new_with_rng(
        CanisterData {
            canister_id: canister_id(1),
            certified_data: random_certified_data(),
        },
        rng,
    )
    .with_delegation(
        CertificateBuilder::new_with_rng(
            SubnetData {
                subnet_id: subnet_id(1),
                canister_id_ranges: vec![(canister_id(20), canister_id(30))],
            },
            rng,
        )
        .with_canister_ranges_format(format),
    )
    .build();

    let verification_result = verify_certified_data_with_and_without_cache(
        &cbor,
        &canister_id(1),
        &pk,
        random_certified_data().as_bytes(),
    );

    assert_matches!(
        verification_result,
        Err(CertificateValidationError::CanisterIdOutOfRange)
    );
}

#[rstest]
#[case::old_format(CanisterRangesFormat::Flat)]
#[case::new_format(CanisterRangesFormat::Tree)]
fn should_fail_certificate_verification_with_canister_id_out_of_range_multiple_ranges(
    #[case] format: CanisterRangesFormat,
) {
    let rng = &mut reproducible_rng();
    let (_cert, pk, cbor) = CertificateBuilder::new_with_rng(
        CanisterData {
            canister_id: canister_id(10),
            certified_data: random_certified_data(),
        },
        rng,
    )
    .with_delegation(
        CertificateBuilder::new_with_rng(
            SubnetData {
                subnet_id: subnet_id(1),
                canister_id_ranges: vec![
                    (canister_id(2), canister_id(3)),
                    (canister_id(20), canister_id(30)),
                ],
            },
            rng,
        )
        .with_canister_ranges_format(format),
    )
    .build();

    let verification_result = verify_certified_data_with_and_without_cache(
        &cbor,
        &canister_id(10),
        &pk,
        random_certified_data().as_bytes(),
    );

    assert_matches!(
        verification_result,
        Err(CertificateValidationError::CanisterIdOutOfRange)
    );
}

#[test]
fn should_fail_on_certified_data_mismatch() {
    let rng = &mut reproducible_rng();
    let certificate_certified_data = random_certified_data();
    let expected_certified_data = Digest([1; 32]);
    assert_ne!(certificate_certified_data, expected_certified_data);

    let (_cert, pk, cbor) = CertificateBuilder::new_with_rng(
        CanisterData {
            canister_id: canister_id(1),
            certified_data: certificate_certified_data,
        },
        rng,
    )
    .build();

    let verification_result = verify_certified_data_with_and_without_cache(
        &cbor,
        &canister_id(1),
        &pk,
        expected_certified_data.as_bytes(),
    );

    assert_matches!(
        verification_result,
        Err(CertificateValidationError::CertifiedDataMismatch { .. })
    );
}

#[test]
fn should_fail_on_invalid_cbor() {
    let rng = &mut reproducible_rng();
    let pk = CertificateBuilder::new_with_rng(CustomTree(LabeledTree::Leaf(b"".to_vec())), rng)
        .get_root_public_key();
    let mut garbled_data: [u8; 128] = [0; 128];
    thread_rng().fill(&mut garbled_data);

    let verification_result = verify_certified_data_with_and_without_cache(
        &garbled_data,
        &canister_id(1),
        &pk,
        Digest([1; 32]).as_bytes(),
    );

    assert_matches!(
        verification_result,
        Err(CertificateValidationError::DeserError { .. })
    );
}

#[test]
fn should_fail_on_unexpected_tree() {
    let rng = &mut reproducible_rng();
    let (_cert, pk, cbor) = CertificateBuilder::new_with_rng(
        CustomTree(LabeledTree::SubTree(flatmap![
            Label::from("schubidu") => LabeledTree::Leaf(b"schubidu_data".to_vec()),
            Label::from("time") => LabeledTree::Leaf(b"some_data".to_vec())
        ])),
        rng,
    )
    .build();

    let verification_result = verify_certified_data_with_and_without_cache(
        &cbor,
        &canister_id(1),
        &pk,
        Digest([1; 32]).as_bytes(),
    );

    assert_matches!(
        verification_result,
        Err(CertificateValidationError::DeserError { .. })
    );
}

#[test]
fn should_validate_delegation_cert() {
    let rng = &mut reproducible_rng();
    let subnet_id = subnet_id(42);

    let (cert, root_pk, _cbor) = CertificateBuilder::new_with_rng(
        CanisterData {
            canister_id: canister_id(1),
            certified_data: random_certified_data(),
        },
        rng,
    )
    .with_delegation(CertificateBuilder::new_with_rng(
        SubnetData {
            subnet_id,
            canister_id_ranges: vec![(canister_id(0), canister_id(10))],
        },
        rng,
    ))
    .build();
    let delegation = cert.delegation.expect("missing delegation");

    assert!(
        validate_subnet_delegation_certificate_with_and_without_cache(
            &delegation.certificate,
            &subnet_id,
            &root_pk
        )
        .is_ok()
    );
}

#[test]
fn should_fail_to_validate_delegation_cert_if_it_contains_further_delegations() {
    let rng = &mut reproducible_rng();
    let subnet_id = subnet_id(42);

    let (cert, root_pk, _cbor) = CertificateBuilder::new_with_rng(
        CanisterData {
            canister_id: canister_id(1),
            certified_data: random_certified_data(),
        },
        rng,
    )
    .with_delegation(
        CertificateBuilder::new_with_rng(
            SubnetData {
                subnet_id,
                canister_id_ranges: vec![(canister_id(0), canister_id(10))],
            },
            rng,
        )
        .with_delegation(CertificateBuilder::new_with_rng(
            SubnetData {
                subnet_id,
                canister_id_ranges: vec![(canister_id(0), canister_id(100))],
            },
            rng,
        )),
    )
    .build();
    let delegation = cert.delegation.expect("missing delegation");

    assert_matches!(
        validate_subnet_delegation_certificate_with_and_without_cache(
            &delegation.certificate,
            &subnet_id,
            &root_pk
        ),
        Err(CertificateValidationError::MultipleSubnetDelegationsNotAllowed)
    );
}

#[test]
fn should_fail_to_validate_delegation_cert_with_invalid_signature() {
    let rng = &mut reproducible_rng();
    let subnet_id = subnet_id(42);

    let (cert, root_pk, _cbor) = CertificateBuilder::new_with_rng(
        CanisterData {
            canister_id: canister_id(1),
            certified_data: random_certified_data(),
        },
        rng,
    )
    .with_delegation(
        CertificateBuilder::new_with_rng(
            SubnetData {
                subnet_id,
                canister_id_ranges: vec![(canister_id(0), canister_id(10))],
            },
            rng,
        )
        .with_invalid_sig(),
    )
    .build();
    let delegation = cert.delegation.expect("missing delegation");

    assert_matches!(
        validate_subnet_delegation_certificate_with_and_without_cache(
            &delegation.certificate,
            &subnet_id,
            &root_pk
        ),
        Err(CertificateValidationError::InvalidSignature(_))
    );
}

#[test]
fn should_fail_to_validate_delegation_cert_if_cert_tree_is_malformed() {
    let rng = &mut reproducible_rng();
    let dummy_root_pk =
        CertificateBuilder::new_with_rng(CustomTree(LabeledTree::Leaf(b"".to_vec())), rng)
            .get_root_public_key();

    assert_matches!(
        validate_subnet_delegation_certificate_with_and_without_cache(&[42, 128], &subnet_id(42), &dummy_root_pk),
        Err(CertificateValidationError::DeserError(e)) if e.contains("failed to decode certificate")
    );
}

#[test]
fn should_fail_to_validate_delegation_cert_if_time_missing() {
    let rng = &mut reproducible_rng();
    let subnet_id = subnet_id(42);

    let (cert, root_pk, _cbor) = CertificateBuilder::new_with_rng(CanisterData {
                    canister_id: canister_id(1),
                    certified_data: random_certified_data(),
                },rng)
                .with_delegation(CertificateBuilder::new_with_rng(CustomTree(LabeledTree::SubTree(
                    flatmap![
                        Label::from("subnet") => LabeledTree::SubTree(flatmap![
                            Label::from(subnet_id.get_ref().to_vec()) => LabeledTree::SubTree(flatmap![
                                Label::from("canister_ranges") => LabeledTree::Leaf(b"dummy_canister_ranges".to_vec()),
                                Label::from("public_key") => LabeledTree::Leaf(b"dummy_public_key".to_vec()),
                            ])
                        ]),
                        // time is missing here
                    ],
                )),rng))
                .with_delegation_subnet_id(subnet_id)
                .build();
    let delegation = cert.delegation.expect("missing delegation");

    assert_matches!(
        validate_subnet_delegation_certificate_with_and_without_cache(&delegation.certificate, &subnet_id, &root_pk),
        Err(CertificateValidationError::DeserError(e))
        if e.contains("failed to unpack replica state from a labeled tree")
    );
}

#[test]
fn should_fail_to_validate_delegation_cert_if_time_malformed() {
    let rng = &mut reproducible_rng();
    let subnet_id = subnet_id(42);

    let (cert, root_pk, _cbor) = CertificateBuilder::new_with_rng(CanisterData {
                    canister_id: canister_id(1),
                    certified_data: random_certified_data(),
                },rng)
                .with_delegation(CertificateBuilder::new_with_rng(CustomTree(LabeledTree::SubTree(
                    flatmap![
                    Label::from("subnet") => LabeledTree::SubTree(flatmap![
                        Label::from(subnet_id.get_ref().to_vec()) => LabeledTree::SubTree(flatmap![
                            Label::from("canister_ranges") => LabeledTree::Leaf(b"dummy_canister_ranges".to_vec()),
                            Label::from("public_key") => LabeledTree::Leaf(b"dummy_public_key".to_vec()),
                        ])
                    ]),
                    Label::from("time") => LabeledTree::Leaf(b"malformed_time".to_vec())
                ],
                )),rng))
                .with_delegation_subnet_id(subnet_id)
                .build();
    let delegation = cert.delegation.expect("missing delegation");

    assert_matches!(
        validate_subnet_delegation_certificate_with_and_without_cache(&delegation.certificate, &subnet_id, &root_pk),
        Err(CertificateValidationError::DeserError(e))
        if e.contains("failed to unpack replica state from a labeled tree")
    );
}

#[test]
fn should_fail_to_validate_delegation_cert_if_subnet_public_key_missing() {
    let rng = &mut reproducible_rng();
    let subnet_id = subnet_id(42);

    let (cert, root_pk, _cbor) = CertificateBuilder::new_with_rng(CanisterData {
                    canister_id: canister_id(1),
                    certified_data: random_certified_data(),
                },rng)
                .with_delegation(CertificateBuilder::new_with_rng(CustomTree(LabeledTree::SubTree(
                    flatmap![
                        Label::from("subnet") => LabeledTree::SubTree(flatmap![
                            Label::from(subnet_id.get_ref().to_vec()) => LabeledTree::SubTree(flatmap![
                                Label::from("canister_ranges") => LabeledTree::Leaf(b"dummy_canister_ranges".to_vec()),
                                // public key is missing here
                            ])
                        ]),
                        Label::from("time") => LabeledTree::Leaf(encoded_time(1234567))
                    ],
                )),rng))
                .with_delegation_subnet_id(subnet_id)
                .build();
    let delegation = cert.delegation.expect("missing delegation");

    assert_matches!(
        validate_subnet_delegation_certificate_with_and_without_cache(&delegation.certificate, &subnet_id, &root_pk),
        Err(CertificateValidationError::DeserError(e))
        if e.contains("failed to unpack replica state from a labeled tree")
    );
}

#[test]
fn should_fail_to_validate_delegation_cert_if_subnet_canister_ranges_missing() {
    let rng = &mut reproducible_rng();
    let subnet_id = subnet_id(42);
    let canister_id = canister_id(1);

    let (cert, root_pk, _cbor) = CertificateBuilder::new_with_rng(
        CanisterData {
            canister_id,
            certified_data: random_certified_data(),
        },
        rng,
    )
    .with_delegation(CertificateBuilder::new_with_rng(
        CustomTree(LabeledTree::SubTree(flatmap![
            Label::from("subnet") => LabeledTree::SubTree(flatmap![
                Label::from(subnet_id.get_ref().to_vec()) => LabeledTree::SubTree(flatmap![
                    // canister_ranges are missing here
                    Label::from("public_key") => LabeledTree::Leaf(b"dummy_public_key".to_vec()),
                ])
            ]),
            Label::from("time") => LabeledTree::Leaf(encoded_time(1234567))
        ])),
        rng,
    ))
    .with_delegation_subnet_id(subnet_id)
    .build();
    let delegation = cert.delegation.expect("missing delegation");

    assert_matches!(
        verify_subnet_delegation_certificate_with_and_without_cache(&delegation.certificate, &subnet_id, &canister_id, &root_pk),
        Err(CertificateValidationError::MalformedHashTree(e))
        if e.contains("state tree doesn't have canister ranges")
    );
}

#[test]
fn should_fail_to_validate_delegation_cert_if_subnet_public_key_malformed() {
    let rng = &mut reproducible_rng();
    let subnet_id = subnet_id(42);
    let canister_ranges: Vec<(CanisterId, CanisterId)> = vec![(canister_id(0), canister_id(10))];

    let (cert, root_pk, _cbor) = CertificateBuilder::new_with_rng(CanisterData {
                    canister_id: canister_id(1),
                    certified_data: random_certified_data(),
                },rng)
                .with_delegation(CertificateBuilder::new_with_rng(CustomTree(LabeledTree::SubTree(
                    flatmap![
                        Label::from("subnet") => LabeledTree::SubTree(flatmap![
                            Label::from(subnet_id.get_ref().to_vec()) => LabeledTree::SubTree(flatmap![
                                Label::from("canister_ranges") => LabeledTree::Leaf(serialize_to_cbor(&canister_ranges)),
                                Label::from("public_key") => LabeledTree::Leaf(b"dummy_public_key".to_vec()),
                            ])
                        ]),
                        Label::from("time") => LabeledTree::Leaf(encoded_time(1234567))
                    ],
                )),rng))
                .with_delegation_subnet_id(subnet_id)
                .build();
    let delegation = cert.delegation.expect("missing delegation");

    assert_matches!(
        validate_subnet_delegation_certificate_with_and_without_cache(&delegation.certificate, &subnet_id, &root_pk),
        Err(CertificateValidationError::DeserError(e))
        if e.contains("failed to deserialize public key")
    );
}

#[test]
fn should_fail_to_validate_delegation_cert_if_subnet_canister_ranges_malformed() {
    let rng = &mut reproducible_rng();
    let subnet_id = subnet_id(42);
    let canister_id = canister_id(1);

    let (cert, root_pk, _cbor) = CertificateBuilder::new_with_rng(CanisterData {
                    canister_id,
                    certified_data: random_certified_data(),
                },rng)
                .with_delegation(CertificateBuilder::new_with_rng(CustomTree(LabeledTree::SubTree(
                    flatmap![
                        Label::from("subnet") => LabeledTree::SubTree(flatmap![
                            Label::from(subnet_id.get_ref().to_vec()) => LabeledTree::SubTree(flatmap![
                                Label::from("canister_ranges") => LabeledTree::Leaf(b"dummy_canister_ranges".to_vec()),
                                Label::from("public_key") => LabeledTree::Leaf(public_key_to_der(&threshold_sig_pubkey().into_bytes()).unwrap()),
                            ])
                        ]),
                        Label::from("time") => LabeledTree::Leaf(encoded_time(1234567))
                    ],
                )),rng))
                .with_delegation_subnet_id(subnet_id)
                .build();
    let delegation = cert.delegation.expect("missing delegation");
    assert_matches!(
        verify_subnet_delegation_certificate_with_and_without_cache(&delegation.certificate, &subnet_id, &canister_id, &root_pk),
        Err(CertificateValidationError::DeserError(e))
        if e.contains("failed to unpack canister range")
    );
}

#[test]
fn should_fail_to_validate_delegation_cert_if_subnet_new_canister_ranges_malformed() {
    let rng = &mut reproducible_rng();
    let subnet_id = subnet_id(42);
    let canister_id = canister_id(1);

    let (cert, root_pk, _cbor) = CertificateBuilder::new_with_rng(CanisterData {
                    canister_id,
                    certified_data: random_certified_data(),
                },rng)
                .with_delegation(CertificateBuilder::new_with_rng(CustomTree(LabeledTree::SubTree(
                    flatmap![
                        Label::from("subnet") => LabeledTree::SubTree(flatmap![
                            Label::from(subnet_id.get_ref().to_vec()) => LabeledTree::SubTree(flatmap![
                                Label::from("public_key") => LabeledTree::Leaf(public_key_to_der(&threshold_sig_pubkey().into_bytes()).unwrap()),
                            ])
                        ]),
                        Label::from("time") => LabeledTree::Leaf(encoded_time(1234567)),
                        Label::from("canister_ranges") => LabeledTree::SubTree(flatmap![
                            Label::from(subnet_id.get_ref().to_vec()) => LabeledTree::SubTree(flatmap![
                                Label::from(canister_id.get().to_vec()) => LabeledTree::Leaf(b"dummy_canister_ranges".to_vec()),
                            ])
                        ])
                    ],
                )),rng))
                .with_delegation_subnet_id(subnet_id)
                .build();
    let delegation = cert.delegation.expect("missing delegation");
    assert_matches!(
        verify_subnet_delegation_certificate_with_and_without_cache(&delegation.certificate, &subnet_id, &canister_id, &root_pk),
        Err(CertificateValidationError::DeserError(e))
        if e.contains("failed to unpack canister range")
    );
}

fn random_certified_data() -> Digest {
    let mut random_certified_data: [u8; 32] = [0; 32];
    thread_rng().fill(&mut random_certified_data);
    Digest(random_certified_data)
}

fn subnet_id(id: u64) -> SubnetId {
    SubnetId::from(PrincipalId::new_subnet_test_id(id))
}

fn canister_id(id: u64) -> CanisterId {
    CanisterId::from_u64(id)
}

fn threshold_sig_pubkey() -> ThresholdSigPublicKey {
    ThresholdSigPublicKey::from(PublicKeyBytes([123; 96]))
}
