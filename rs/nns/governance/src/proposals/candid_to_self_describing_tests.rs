use super::*;

use candid::{Encode, Nat, Principal};
use ic_nns_governance_api::SelfDescribingValue as ApiValue;
use maplit::hashmap;

#[track_caller]
fn assert_candid_converts_to(
    candid_source: &str,
    method_name: &str,
    encoded_args: &[u8],
    expected: ApiValue,
) {
    let result = candid_to_self_describing(candid_source, method_name, encoded_args).unwrap();
    let api_value = ApiValue::from(result);
    assert_eq!(api_value, expected);
}

// Tests for candid_to_self_describing

#[test]
fn test_candid_to_self_describing_simple_record() {
    let candid_source = r#"
        type MyRecord = record {
            name: text;
            age: nat;
        };
        service : {
            my_method : (MyRecord) -> ();
        }
    "#;

    #[derive(candid::CandidType)]
    struct MyRecord {
        name: String,
        age: Nat,
    }

    let arg = MyRecord {
        name: "Alice".to_string(),
        age: Nat::from(30u64),
    };
    let encoded = Encode!(&arg).unwrap();

    assert_candid_converts_to(
        candid_source,
        "my_method",
        &encoded,
        ApiValue::Map(hashmap! {
            "name".to_string() => ApiValue::Text("Alice".to_string()),
            "age".to_string() => ApiValue::Nat(Nat::from(30u64)),
        }),
    );
}

#[test]
fn test_candid_to_self_describing_text() {
    let candid_source = r#"
        service : {
            greet : (text) -> ();
        }
    "#;

    let arg = "Hello, World!";
    let encoded = Encode!(&arg).unwrap();

    assert_candid_converts_to(
        candid_source,
        "greet",
        &encoded,
        ApiValue::Text("Hello, World!".to_string()),
    );
}

#[test]
fn test_candid_to_self_describing_nat() {
    let candid_source = r#"
        service : {
            set_count : (nat) -> ();
        }
    "#;

    let arg = Nat::from(42u64);
    let encoded = Encode!(&arg).unwrap();

    assert_candid_converts_to(
        candid_source,
        "set_count",
        &encoded,
        ApiValue::Nat(Nat::from(42u64)),
    );
}

#[test]
fn test_candid_to_self_describing_principal() {
    let candid_source = r#"
        service : {
            set_owner : (principal) -> ();
        }
    "#;

    let principal = Principal::from_text("aaaaa-aa").unwrap();
    let encoded = Encode!(&principal).unwrap();

    assert_candid_converts_to(
        candid_source,
        "set_owner",
        &encoded,
        ApiValue::Text(principal.to_string()),
    );
}

#[test]
fn test_candid_to_self_describing_opt_some() {
    let candid_source = r#"
        service : {
            set_value : (opt nat) -> ();
        }
    "#;

    let arg = Some(Nat::from(42u64));
    let encoded = Encode!(&arg).unwrap();

    assert_candid_converts_to(
        candid_source,
        "set_value",
        &encoded,
        ApiValue::Array(vec![ApiValue::Nat(Nat::from(42u64))]),
    );
}

#[test]
fn test_candid_to_self_describing_opt_none() {
    let candid_source = r#"
        service : {
            set_value : (opt nat) -> ();
        }
    "#;

    let arg: Option<Nat> = None;
    let encoded = Encode!(&arg).unwrap();

    assert_candid_converts_to(
        candid_source,
        "set_value",
        &encoded,
        ApiValue::Array(vec![]),
    );
}

#[test]
fn test_candid_to_self_describing_vec() {
    let candid_source = r#"
        service : {
            set_values : (vec nat) -> ();
        }
    "#;

    let arg = vec![Nat::from(1u64), Nat::from(2u64), Nat::from(3u64)];
    let encoded = Encode!(&arg).unwrap();

    assert_candid_converts_to(
        candid_source,
        "set_values",
        &encoded,
        ApiValue::Array(vec![
            ApiValue::Nat(Nat::from(1u64)),
            ApiValue::Nat(Nat::from(2u64)),
            ApiValue::Nat(Nat::from(3u64)),
        ]),
    );
}

#[test]
fn test_candid_to_self_describing_variant() {
    let candid_source = r#"
        type Status = variant {
            Active;
            Pending: nat;
        };
        service : {
            set_status : (Status) -> ();
        }
    "#;

    #[derive(candid::CandidType)]
    enum Status {
        Active,
        Pending(Nat),
    }

    // Test unit variant
    let arg = Status::Active;
    let encoded = Encode!(&arg).unwrap();
    assert_candid_converts_to(
        candid_source,
        "set_status",
        &encoded,
        ApiValue::Text("Active".to_string()),
    );

    // Test variant with value
    let arg = Status::Pending(Nat::from(42u64));
    let encoded = Encode!(&arg).unwrap();
    assert_candid_converts_to(
        candid_source,
        "set_status",
        &encoded,
        ApiValue::Map(hashmap! {
            "Pending".to_string() => ApiValue::Nat(Nat::from(42u64)),
        }),
    );
}

#[test]
fn test_candid_to_self_describing_blob() {
    let candid_source = r#"
        service : {
            set_data : (blob) -> ();
        }
    "#;

    let arg = vec![1u8, 2u8, 3u8, 4u8];
    let encoded = Encode!(&arg).unwrap();

    assert_candid_converts_to(
        candid_source,
        "set_data",
        &encoded,
        ApiValue::Blob(vec![1u8, 2u8, 3u8, 4u8]),
    );
}

#[test]
fn test_candid_to_self_describing_empty_args() {
    let candid_source = r#"
        service : {
            no_args : () -> ();
        }
    "#;

    let encoded = Encode!().unwrap();

    assert_candid_converts_to(candid_source, "no_args", &encoded, ApiValue::Array(vec![]));
}

#[test]
fn test_candid_to_self_describing_multiple_args_error() {
    let candid_source = r#"
        service : {
            multi_args : (text, nat) -> ();
        }
    "#;

    let arg1 = "hello";
    let arg2 = Nat::from(42u64);
    let encoded = Encode!(&arg1, &arg2).unwrap();

    let result = candid_to_self_describing(candid_source, "multi_args", &encoded);

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .contains("Expected at most one argument"));
}

#[test]
fn test_candid_to_self_describing_invalid_candid_source() {
    let candid_source = "this is not valid candid";

    let arg = "hello";
    let encoded = Encode!(&arg).unwrap();

    let result = candid_to_self_describing(candid_source, "my_method", &encoded);

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Failed to parse candid source"));
}

#[test]
fn test_candid_to_self_describing_method_not_found() {
    let candid_source = r#"
        service : {
            existing_method : (text) -> ();
        }
    "#;

    let arg = "hello";
    let encoded = Encode!(&arg).unwrap();

    let result = candid_to_self_describing(candid_source, "nonexistent_method", &encoded);

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Failed to get method"));
}

#[test]
fn test_candid_to_self_describing_no_service() {
    let candid_source = r#"
        type MyRecord = record {
            name: text;
        };
    "#;

    let arg = "hello";
    let encoded = Encode!(&arg).unwrap();

    let result = candid_to_self_describing(candid_source, "my_method", &encoded);

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("no service found"));
}

#[test]
fn test_candid_to_self_describing_nested_record() {
    let candid_source = r#"
        type Address = record {
            street: text;
            city: text;
        };
        type Person = record {
            name: text;
            address: Address;
        };
        service : {
            set_person : (Person) -> ();
        }
    "#;

    #[derive(candid::CandidType)]
    struct Address {
        street: String,
        city: String,
    }

    #[derive(candid::CandidType)]
    struct Person {
        name: String,
        address: Address,
    }

    let arg = Person {
        name: "Alice".to_string(),
        address: Address {
            street: "123 Main St".to_string(),
            city: "Wonderland".to_string(),
        },
    };
    let encoded = Encode!(&arg).unwrap();

    assert_candid_converts_to(
        candid_source,
        "set_person",
        &encoded,
        ApiValue::Map(hashmap! {
            "name".to_string() => ApiValue::Text("Alice".to_string()),
            "address".to_string() => ApiValue::Map(hashmap! {
                "street".to_string() => ApiValue::Text("123 Main St".to_string()),
                "city".to_string() => ApiValue::Text("Wonderland".to_string()),
            }),
        }),
    );
}

