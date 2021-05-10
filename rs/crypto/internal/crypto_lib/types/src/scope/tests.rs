//! Test key scopes
use super::*;
use std::str::FromStr;

fn test_string_representation(value: &Scope, string: &str) {
    assert_eq!(
        String::from(value),
        string,
        "Stringifying {} does not yield expected '{}'.",
        value,
        string
    );
    assert_eq!(
        Ok(*value),
        Scope::from_str(string),
        "Parsing '{}' does not yield expected {}.",
        string,
        value
    );
}

#[test]
fn serialisation_is_stable() {
    // Const scopes:
    test_string_representation(&Scope::Const(ConstScope::Test0), "Const:Test0");
    test_string_representation(&Scope::Const(ConstScope::Test1), "Const:Test1");
    // There are more variants but they share the exact same code paths, so if
    // the above are correct, it is highly likely that the remainder will be
    // correct as well.
}
