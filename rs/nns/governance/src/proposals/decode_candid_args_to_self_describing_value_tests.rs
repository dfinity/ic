use super::*;

use candid::{Encode, Nat, Principal};
use ic_nns_governance_api::SelfDescribingValue;
use maplit::hashmap;

#[track_caller]
fn assert_candid_converts_to(
    schema: &str,
    method_name: &str,
    encoded_args: &[u8],
    expected: SelfDescribingValue,
) {
    let result =
        decode_candid_args_to_self_describing_value(schema, method_name, encoded_args).unwrap();
    let api_value = SelfDescribingValue::from(result);
    assert_eq!(api_value, expected);
}

// Tests for decode_candid_args_to_self_describing_value

#[test]
fn test_decode_candid_args_to_self_describing_value_simple_record() {
    let schema = r#"
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
        schema,
        "my_method",
        &encoded,
        SelfDescribingValue::Map(hashmap! {
            "name".to_string() => SelfDescribingValue::Text("Alice".to_string()),
            "age".to_string() => SelfDescribingValue::Nat(Nat::from(30u64)),
        }),
    );
}

#[test]
fn test_decode_candid_args_to_self_describing_value_text() {
    let schema = r#"
        service : {
            greet : (text) -> ();
        }
    "#;

    let arg = "Hello, World!";
    let encoded = Encode!(&arg).unwrap();

    assert_candid_converts_to(
        schema,
        "greet",
        &encoded,
        SelfDescribingValue::Text("Hello, World!".to_string()),
    );
}

#[test]
fn test_decode_candid_args_to_self_describing_value_nat() {
    let schema = r#"
        service : {
            set_count : (nat) -> ();
        }
    "#;

    let arg = Nat::from(42u64);
    let encoded = Encode!(&arg).unwrap();

    assert_candid_converts_to(
        schema,
        "set_count",
        &encoded,
        SelfDescribingValue::Nat(Nat::from(42u64)),
    );
}

#[test]
fn test_decode_candid_args_to_self_describing_value_principal() {
    let schema = r#"
        service : {
            set_owner : (principal) -> ();
        }
    "#;

    let principal = Principal::from_text("aaaaa-aa").unwrap();
    let encoded = Encode!(&principal).unwrap();

    assert_candid_converts_to(
        schema,
        "set_owner",
        &encoded,
        SelfDescribingValue::Text(principal.to_string()),
    );
}

#[test]
fn test_decode_candid_args_to_self_describing_value_opt_some() {
    let schema = r#"
        service : {
            set_value : (opt nat) -> ();
        }
    "#;

    let arg = Some(Nat::from(42u64));
    let encoded = Encode!(&arg).unwrap();

    assert_candid_converts_to(
        schema,
        "set_value",
        &encoded,
        SelfDescribingValue::Array(vec![SelfDescribingValue::Nat(Nat::from(42u64))]),
    );
}

#[test]
fn test_decode_candid_args_to_self_describing_value_opt_none() {
    let schema = r#"
        service : {
            set_value : (opt nat) -> ();
        }
    "#;

    let arg: Option<Nat> = None;
    let encoded = Encode!(&arg).unwrap();

    assert_candid_converts_to(
        schema,
        "set_value",
        &encoded,
        SelfDescribingValue::Array(vec![]),
    );
}

#[test]
fn test_decode_candid_args_to_self_describing_value_vec() {
    let schema = r#"
        service : {
            set_values : (vec nat) -> ();
        }
    "#;

    let arg = vec![Nat::from(1u64), Nat::from(2u64), Nat::from(3u64)];
    let encoded = Encode!(&arg).unwrap();

    assert_candid_converts_to(
        schema,
        "set_values",
        &encoded,
        SelfDescribingValue::Array(vec![
            SelfDescribingValue::Nat(Nat::from(1u64)),
            SelfDescribingValue::Nat(Nat::from(2u64)),
            SelfDescribingValue::Nat(Nat::from(3u64)),
        ]),
    );
}

#[test]
fn test_decode_candid_args_to_self_describing_value_variant() {
    let schema = r#"
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
        schema,
        "set_status",
        &encoded,
        SelfDescribingValue::Text("Active".to_string()),
    );

    // Test variant with value
    let arg = Status::Pending(Nat::from(42u64));
    let encoded = Encode!(&arg).unwrap();
    assert_candid_converts_to(
        schema,
        "set_status",
        &encoded,
        SelfDescribingValue::Map(hashmap! {
            "Pending".to_string() => SelfDescribingValue::Nat(Nat::from(42u64)),
        }),
    );
}

#[test]
fn test_decode_candid_args_to_self_describing_value_blob() {
    let schema = r#"
        service : {
            set_data_vec_nat8 : (vec nat8) -> ();
            set_data_blob : (blob) -> ();
        }
    "#;

    let arg = vec![1u8, 2u8, 3u8, 4u8];
    let encoded = Encode!(&arg).unwrap();

    // Both `vec nat8` and `blob` (an alias for `vec nat8`) should be converted to `Blob`.
    assert_candid_converts_to(
        schema,
        "set_data_vec_nat8",
        &encoded,
        SelfDescribingValue::Blob(vec![1u8, 2u8, 3u8, 4u8]),
    );
    assert_candid_converts_to(
        schema,
        "set_data_blob",
        &encoded,
        SelfDescribingValue::Blob(vec![1u8, 2u8, 3u8, 4u8]),
    );
}

#[test]
fn test_decode_candid_args_to_self_describing_value_empty_args() {
    let schema = r#"
        service : {
            no_args : () -> ();
        }
    "#;

    let encoded = Encode!().unwrap();

    assert_candid_converts_to(
        schema,
        "no_args",
        &encoded,
        SelfDescribingValue::Array(vec![]),
    );
}

#[test]
fn test_decode_candid_args_to_self_describing_value_reserved() {
    let schema = r#"
        type Name = record {
            first: text;
            last: reserved;
        };
        service : {
            set_name : (Name) -> ();
        }
    "#;

    #[derive(candid::CandidType)]
    struct Name {
        first: String,
        last: String,
    }

    let name = Name {
        first: "John".to_string(),
        last: "Doe".to_string(),
    };
    let encoded = Encode!(&name).unwrap();

    assert_candid_converts_to(
        schema,
        "set_name",
        &encoded,
        SelfDescribingValue::Map(hashmap! {
            "first".to_string() => SelfDescribingValue::Text("John".to_string()),
            "last".to_string() => SelfDescribingValue::Array(vec![]),
        }),
    );
}

#[test]
fn test_decode_candid_args_to_self_describing_value_multiple_args_error() {
    let schema = r#"
        service : {
            multi_args : (text, nat) -> ();
        }
    "#;

    let arg1 = "hello";
    let arg2 = Nat::from(42u64);
    let encoded = Encode!(&arg1, &arg2).unwrap();

    let result = decode_candid_args_to_self_describing_value(schema, "multi_args", &encoded);

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .contains("Expected at most one argument")
    );
}

#[test]
fn test_decode_candid_args_to_self_describing_value_invalid_schema() {
    let schema = "this is not valid candid";

    let arg = "hello";
    let encoded = Encode!(&arg).unwrap();

    let result = decode_candid_args_to_self_describing_value(schema, "my_method", &encoded);

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .contains("Failed to parse candid source")
    );
}

#[test]
fn test_decode_candid_args_to_self_describing_value_method_not_found() {
    let schema = r#"
        service : {
            existing_method : (text) -> ();
        }
    "#;

    let arg = "hello";
    let encoded = Encode!(&arg).unwrap();

    let result =
        decode_candid_args_to_self_describing_value(schema, "nonexistent_method", &encoded);

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Failed to get method"));
}

#[test]
fn test_decode_candid_args_to_self_describing_value_no_service() {
    let schema = r#"
        type MyRecord = record {
            name: text;
        };
    "#;

    let arg = "hello";
    let encoded = Encode!(&arg).unwrap();

    let result = decode_candid_args_to_self_describing_value(schema, "my_method", &encoded);

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("no service found"));
}

#[test]
fn test_decode_candid_args_to_self_describing_value_nested_record() {
    let schema = r#"
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
        schema,
        "set_person",
        &encoded,
        SelfDescribingValue::Map(hashmap! {
            "name".to_string() => SelfDescribingValue::Text("Alice".to_string()),
            "address".to_string() => SelfDescribingValue::Map(hashmap! {
                "street".to_string() => SelfDescribingValue::Text("123 Main St".to_string()),
                "city".to_string() => SelfDescribingValue::Text("Wonderland".to_string()),
            }),
        }),
    );
}
