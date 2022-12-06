use crate::metrics::BooleanOperation;

#[test]
fn shall_convert_enum_variants_to_snake_case() {
    let formatted = format!("{}", BooleanOperation::KeyInRegistryMissingLocally);
    assert_eq!("key_in_registry_missing_locally", formatted);
}
