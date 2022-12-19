use crate::metrics::{BooleanOperation, KeyType, MetricsDomain};

#[test]
fn shall_convert_enum_variants_to_snake_case_correctly() {
    assert_eq!(
        "key_in_registry_missing_locally",
        format!("{}", BooleanOperation::KeyInRegistryMissingLocally)
    );
    assert_eq!(
        "latest_local_idkg_key_exists_in_registry",
        format!("{}", BooleanOperation::LatestLocalIdkgKeyExistsInRegistry)
    );
    assert_eq!("secret_sks", format!("{}", KeyType::SecretSKS));
    assert_eq!("idkg_protocol", format!("{}", MetricsDomain::IdkgProtocol));
}
