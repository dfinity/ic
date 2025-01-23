use super::*;
use pretty_assertions::{assert_eq, assert_str_eq};

#[derive(CandidType)]
struct DummyCandidStruct {
    pub status: Option<i32>,
    pub module_hash: Vec<u8>,
    pub controllers: String,
    pub memory_size: Option<u64>,
    pub cycles: Option<u64>,
}

#[derive(CandidType)]
enum DummyCandidVariant {
    Foo(String),
    Bar { abc: String, xyz: String },
}

#[derive(CandidType)]
struct DummyCandidContainer {
    foo: DummyCandidVariant,
    bar: Result<DummyCandidVariant, String>,
}

#[track_caller]
fn assert_expectation<T: CandidType>(value: &T, expected_result: Result<String, String>) {
    let observed_result = pretty(value);

    match (observed_result, expected_result) {
        (Ok(observed), Ok(expected)) => {
            assert_str_eq!(observed, expected);
        }
        (observed, expected) => {
            assert_eq!(observed, expected);
        }
    }
}

#[test]
fn test_pretty_printing_simple_struct() {
    assert_expectation(
        &DummyCandidStruct {
            status: Some(42),
            module_hash: vec![1, 2, 3, 4],
            controllers: "foo".to_string(),
            memory_size: Some(100),
            cycles: Some(123),
        },
        Ok(r#"record {
  status = opt (42 : int32);
  controllers = "foo";
  memory_size = opt (100 : nat64);
  cycles = opt (123 : nat64);
  module_hash = blob "\01\02\03\04";
}"#
        .to_string()),
    );
}

#[test]
fn test_pretty_printing_complex_struct() {
    assert_expectation(
        &DummyCandidContainer {
            foo: DummyCandidVariant::Foo("hello".to_string()),
            bar: Ok(DummyCandidVariant::Bar {
                abc: "abc".to_string(),
                xyz: "xyz".to_string(),
            }),
        },
        Ok(r#"record {
  bar = variant { Ok = variant { Bar = record { abc = "abc"; xyz = "xyz" } } };
  foo = variant { Foo = "hello" };
}"#
        .to_string()),
    );
}
