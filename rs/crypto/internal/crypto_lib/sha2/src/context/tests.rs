use super::*;

#[test]
fn should_return_correct_byte_representation() {
    let context = DomainSeparationContext::new("test-🦀");
    assert_eq!(
        context.as_bytes(),
        [9, b't', b'e', b's', b't', b'-', 240, 159, 166, 128]
    );
}

#[test]
fn should_return_correct_byte_representation_for_empty_domain() {
    let context = DomainSeparationContext::new("");
    assert_eq!(context.as_bytes(), [0]);
}

#[test]
fn should_return_correct_domain() {
    let context = DomainSeparationContext::new("test-🦀");
    assert_eq!(context.domain(), "test-🦀");
}

#[test]
fn should_return_correct_empty_domain() {
    let context = DomainSeparationContext::new("");
    assert_eq!(context.domain(), "");
}

#[test]
#[should_panic(expected = "domain too long")]
fn should_panic_if_domain_too_long_for_1_byte_length_prefix() {
    let _panic = DomainSeparationContext::new("a".repeat(256));
}

#[test]
fn should_be_instantiable_for_domains_with_maximum_possible_length() {
    let _ = DomainSeparationContext::new("a".repeat(255));
}

#[test]
fn should_be_instantiable_from_string() {
    let context = DomainSeparationContext::new(String::from("test"));
    assert_eq!(context.domain, "test");
}

#[test]
fn should_be_instantiable_from_str() {
    let context = DomainSeparationContext::new("test");
    assert_eq!(context.domain, "test");
}
