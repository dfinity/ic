use crate::metrics::{
    BooleanOperation, BooleanResult, KeyRotationResult, KeyType, MessageType, MetricsDomain,
    MetricsResult, MetricsScope, ServiceType,
};
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

/// Converts a `PascalCase` (or `camelCase`) identifier such as an enum variant
/// name to `snake_case`, treating runs of upper-case letters as acronyms
/// (e.g. `SecretSKS` -> `secret_sks`, `IdkgProtocol` -> `idkg_protocol`).
fn to_snake_case(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let mut result = String::with_capacity(value.len() + 4);
    for (i, &c) in chars.iter().enumerate() {
        if c.is_uppercase() && i > 0 {
            let prev = chars[i - 1];
            let next_is_lower = chars.get(i + 1).is_some_and(|n| n.is_lowercase());
            // Start a new word at a lower->upper boundary, or at the last
            // upper-case letter of an acronym followed by a lower-case letter
            // (e.g. the `K` in `SKSKey`).
            if prev.is_lowercase()
                || prev.is_ascii_digit()
                || (prev.is_uppercase() && next_is_lower)
            {
                result.push('_');
            }
        }
        result.extend(c.to_lowercase());
    }
    result
}

#[test]
fn to_snake_case_helper_handles_words_and_acronyms() {
    assert_eq!(to_snake_case("Snake"), "snake");
    assert_eq!(to_snake_case("SecretSKS"), "secret_sks");
    assert_eq!(to_snake_case("IdkgProtocol"), "idkg_protocol");
    assert_eq!(
        to_snake_case("LatestLocalIdkgKeyExistsInRegistry"),
        "latest_local_idkg_key_exists_in_registry"
    );
    assert_eq!(to_snake_case("SKSKey"), "sks_key");
    assert_eq!(to_snake_case("TlsKey2"), "tls_key2");
    assert_eq!(to_snake_case("already_snake"), "already_snake");
}

fn verify_enum_variants<E>(enum_variants: E)
where
    E: IntoIterator,
    E::Item: std::fmt::Display,
    &'static str: From<<E as IntoIterator>::Item>,
{
    enum_variants.into_iter().for_each(|variant| {
        let display = format!("{}", variant);
        let value: &'static str = variant.into();
        let expected = to_snake_case(value);
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
