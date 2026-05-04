use crate::metrics::{
    BooleanOperation, BooleanResult, KeyRotationResult, KeyType, MessageType, MetricsDomain,
    MetricsResult, MetricsScope, ServiceType,
};
use convert_case::{Case, Casing};
use strum::IntoEnumIterator;

#[test]
fn shall_convert_enum_variants_to_snake_case_correctly() {
    assert_eq!(
        "latest_local_idkg_key_exists_in_registry",
        format!("{}", BooleanOperation::LatestLocalIdkgKeyExistsInRegistry)
    );
    assert_eq!("secret_sks", format!("{}", KeyType::SecretSKS));
    assert_eq!("idkg_protocol", format!("{}", MetricsDomain::IdkgProtocol));
}

fn verify_enum_variants<E>(enum_variants: E)
where
    E: IntoIterator,
    E::Item: std::fmt::Display,
    &'static str: From<<E as IntoIterator>::Item>,
{
    enum_variants.into_iter().for_each(|variant| {
        let display = format!("{}", &variant);
        let value: &'static str = variant.into();
        let expected = value.to_case(Case::Snake).to_string();
        assert_eq!(display, expected);
    });
}

#[test]
fn should_display_all_enum_variants_in_snake_case() {
    verify_enum_variants(BooleanOperation::iter());
    verify_enum_variants(BooleanResult::iter());
    verify_enum_variants(KeyRotationResult::iter());
    verify_enum_variants(KeyType::iter());
    verify_enum_variants(MessageType::iter());
    verify_enum_variants(MetricsDomain::iter());
    verify_enum_variants(MetricsResult::iter());
    verify_enum_variants(MetricsScope::iter());
    verify_enum_variants(ServiceType::iter());
}
