use super::super::*;
use crate::PrincipalId;

#[test]
fn should_create_context_data_as_expected() {
    let transcript_id = IDkgTranscriptId::new(
        SubnetId::from(PrincipalId::new_subnet_test_id(2)),
        1,
        Height::new(1),
    );
    let registry_version = RegistryVersion::from(1);
    let algorithm_id = AlgorithmId::ThresholdEcdsaSecp256k1;

    let mut expected = Vec::new();
    expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 10]);
    expected.extend_from_slice(&[2, 0, 0, 0, 0, 0, 0, 0, 252, 1]);
    expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]);
    expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]);
    expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]);
    expected.push(15);

    assert_eq!(
        context_data(&transcript_id, registry_version, algorithm_id),
        expected
    );
}
