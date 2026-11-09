use super::*;
use crate::{
    pb::v1::SelfDescribingValue as SelfDescribingValuePb, proposals::self_describing::ValueBuilder,
};
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
        age: Nat::from(30_u64),
    };
    let encoded = Encode!(&arg).unwrap();

    assert_candid_converts_to(
        schema,
        "my_method",
        &encoded,
        SelfDescribingValue::Map(hashmap! {
            "name".to_string() => SelfDescribingValue::from("Alice"),
            "age".to_string() => SelfDescribingValue::from(30_u64),
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
        SelfDescribingValue::from("Hello, World!"),
    );
}

#[test]
fn test_decode_candid_args_to_self_describing_value_nat() {
    let schema = r#"
        service : {
            set_count : (nat) -> ();
        }
    "#;

    let arg = Nat::from(42_u64);
    let encoded = Encode!(&arg).unwrap();

    assert_candid_converts_to(
        schema,
        "set_count",
        &encoded,
        SelfDescribingValue::from(42_u64),
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
        SelfDescribingValue::from(principal.to_string()),
    );
}

#[test]
fn test_decode_candid_args_to_self_describing_value_opt_some() {
    let schema = r#"
        service : {
            set_value : (opt nat) -> ();
        }
    "#;

    let arg = Some(Nat::from(42_u64));
    let encoded = Encode!(&arg).unwrap();

    assert_candid_converts_to(
        schema,
        "set_value",
        &encoded,
        SelfDescribingValue::from(42_u64),
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

    assert_candid_converts_to(schema, "set_value", &encoded, SelfDescribingValue::Null);
}

#[test]
fn test_decode_candid_args_to_self_describing_value_vec() {
    let schema = r#"
        service : {
            set_values : (vec nat) -> ();
        }
    "#;

    let arg = vec![Nat::from(1_u64), Nat::from(2_u64), Nat::from(3_u64)];
    let encoded = Encode!(&arg).unwrap();

    assert_candid_converts_to(
        schema,
        "set_values",
        &encoded,
        SelfDescribingValue::Array(vec![
            SelfDescribingValue::from(1_u64),
            SelfDescribingValue::from(2_u64),
            SelfDescribingValue::from(3_u64),
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
        SelfDescribingValue::from("Active"),
    );

    // Test variant with value
    let arg = Status::Pending(Nat::from(42_u64));
    let encoded = Encode!(&arg).unwrap();
    assert_candid_converts_to(
        schema,
        "set_status",
        &encoded,
        SelfDescribingValue::Map(hashmap! {
            "Pending".to_string() => SelfDescribingValue::from(42_u64),
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

    let arg = vec![1_u8, 2_u8, 3_u8, 4_u8];
    let encoded = Encode!(&arg).unwrap();

    // Both `vec nat8` and `blob` (an alias for `vec nat8`) should be converted to `Blob`.
    assert_candid_converts_to(
        schema,
        "set_data_vec_nat8",
        &encoded,
        SelfDescribingValue::from(vec![1_u8, 2, 3, 4]),
    );
    assert_candid_converts_to(
        schema,
        "set_data_blob",
        &encoded,
        SelfDescribingValue::from(vec![1_u8, 2, 3, 4]),
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

    assert_candid_converts_to(schema, "no_args", &encoded, SelfDescribingValue::Null);
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
            "first".to_string() => SelfDescribingValue::from("John"),
            "last".to_string() => SelfDescribingValue::Null,
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
    let arg2 = Nat::from(42_u64);
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
            "name".to_string() => SelfDescribingValue::from("Alice"),
            "address".to_string() => SelfDescribingValue::Map(hashmap! {
                "street".to_string() => SelfDescribingValue::from("123 Main St"),
                "city".to_string() => SelfDescribingValue::from("Wonderland"),
            }),
        }),
    );
}

// Tests for the decoding cost limit.

const CANDID_INTERFACE: &str = r#"
    type Record = record {
        key_id : opt nat32;
        pre_signatures_to_create_in_advance : opt nat32;
        max_queue_size : opt nat32;
    };

    service : {
        pass_many_records : (vec Record) -> ();
    }
"#;

#[derive(candid::CandidType, Clone)]
struct Record {
    key_id: Option<u32>,
    pre_signatures_to_create_in_advance: Option<u32>,
    max_queue_size: Option<u32>,
}

const REPRESENTATIVE_RECORD: Record = Record {
    key_id: Some(42),
    pre_signatures_to_create_in_advance: Some(43),
    max_queue_size: Some(44),
};

#[test]
fn test_decode_candid_args_to_self_describing_value_rejects_high_candid_decoding_cost() {
    // Step 1: Prepare the world.
    // Our goal here is to break the Candid decoding budget(s) with a large, but
    // not "insane" number of elements.
    let large_request = Encode!(&vec![REPRESENTATIVE_RECORD; 8_000]).unwrap();
    let not_large_request = Encode!(&vec![REPRESENTATIVE_RECORD; 6_000]).unwrap();

    // Step 2: Run the code under test.
    let large_result = decode_candid_args_to_self_describing_value(
        CANDID_INTERFACE,
        "pass_many_records",
        &large_request,
    );

    let not_large_result = decode_candid_args_to_self_describing_value(
        CANDID_INTERFACE,
        "pass_many_records",
        &not_large_request,
    );

    // Step 3: Verify result(s).

    // Step 3.1: Inspect large_result.
    let err = large_result.unwrap_err();
    for key_word in [
        "cost", // This is the telltale sign that Candid budget was exceeded, not some other limit.
        "exceed", "limit",
    ] {
        assert!(
            err.to_lowercase().contains(key_word),
            "{} not in {}",
            key_word,
            err,
        );
    }

    // Step 3.2: Inspect not_large_result.
    let key_config = ValueBuilder::new()
        .add_field("key_id", 42_u32)
        .add_field("pre_signatures_to_create_in_advance", 43_u32)
        .add_field("max_queue_size", 44_u32)
        .build();
    assert_eq!(
        not_large_result.unwrap(),
        SelfDescribingValuePb::from(vec![key_config; 6_000]),
    );
}

#[test]
fn test_decode_candid_args_to_self_describing_value_accepts_large_blob() {
    // Step 1: Prepare the world. Blobs (e.g. WASM modules) can be large, but they are cheap to
    // decode relative to their size.
    let schema = r#"
        service : {
            install : (record { wasm_module : blob }) -> ();
        }
    "#;

    #[derive(candid::CandidType)]
    struct Payload {
        wasm_module: serde_bytes::ByteBuf,
    }

    let wasm_module = vec![42_u8; 10 * 1024 * 1024];
    let encoded = Encode!(&Payload {
        wasm_module: serde_bytes::ByteBuf::from(wasm_module.clone()),
    })
    .unwrap();

    // Step 2: Run the code under test.
    let result = decode_candid_args_to_self_describing_value(schema, "install", &encoded);

    // Step 3: Verify result(s).
    assert_eq!(
        SelfDescribingValue::from(result.unwrap()),
        SelfDescribingValue::Map(hashmap! {
            "wasm_module".to_string() => SelfDescribingValue::Blob(wasm_module),
        }),
    );
}

#[test]
fn test_decode_candid_args_to_self_describing_value_does_not_block_prematurely_during_candid_decoding()
 {
    // Step 1: Prepare the world.

    let schema = r#"
        service : {
            // From experiments, this shape has the highest Candid decoding cost
            // "inflation" of 4x: 20 decoding cost units per element vs. 5 bytes
            // of resulting SelfDescribingValue (when encoded using Protocol
            // Buffers). If data with the highest possible "inflation" does not
            // get "prematurely blocked" by Candid decoding (the thing we are
            // trying to avoid), then, no data suffers that fate.
            set_letters : (vec variant { A }) -> ();
        }
    "#;

    #[derive(candid::CandidType, Clone)]
    enum Letter {
        A,
    }

    // Verify the per-element numbers in the comment above. Comparing 1_000 vs. 2_000 elements
    // cancels out fixed overhead (e.g. the Candid header).
    let measure_cost_and_encoded_len = |element_count: usize| -> (usize, usize) {
        let encoded = Encode!(&vec![Letter::A; element_count]).unwrap();
        let (_decoding_cost, skipping_cost) = measure_candid_costs(schema, "set_letters", &encoded);

        let value =
            decode_candid_args_to_self_describing_value(schema, "set_letters", &encoded).unwrap();
        assert_eq!(value, SelfDescribingValuePb::from(vec!["A"; element_count]));

        // Skipping cost is used, because Candid imposes a 50x "penalty" on
        // decoding_cost when decoding "dynamically"/to a generic type.
        (skipping_cost, prost::Message::encoded_len(&value))
    };
    let (cost_1_000, encoded_len_1_000) = measure_cost_and_encoded_len(1_000);
    let (cost_2_000, encoded_len_2_000) = measure_cost_and_encoded_len(2_000);
    let cost_per_element = (cost_2_000 - cost_1_000) as f64 / 1_000.0;
    let output_bytes_per_element = (encoded_len_2_000 - encoded_len_1_000) as f64 / 1_000.0;
    assert_eq!(cost_per_element, 20.0);
    assert_eq!(output_bytes_per_element, 5.0);

    // Per the previous assert, this many elements will result in a Request that
    // barely fits. At the same time, this maximizes Candid decoding costs, per
    // earlier comments.
    let element_count = (MAX_SELF_DESCRIBING_VALUE_ENCODED_LEN_BYTES - 100) / 5;
    let encoded = Encode!(&vec![Letter::A; element_count]).unwrap();

    // Step 2: Run the code under test.
    let result = decode_candid_args_to_self_describing_value(schema, "set_letters", &encoded);

    // Step 3: Verify result(s).

    // Step 3.1: Despite the high Candid decode cost, the input survived.
    let value = result.unwrap();

    // Step 3.2: The value is close to, but within, the self-describing size
    // limit. Otherwise, this test would not be testing what it is meant to
    // test. This is more telling us that the test is using a good input, one
    // tha results in a large (but not too large) output.
    let encoded_len_bytes = prost::Message::encoded_len(&value);
    let relative_size =
        encoded_len_bytes as f64 / MAX_SELF_DESCRIBING_VALUE_ENCODED_LEN_BYTES as f64;
    assert!(
        relative_size < 1.0 && relative_size > 0.9,
        "{}",
        encoded_len_bytes
    );

    // Step 3.3: Inspect the value itself.
    assert_eq!(value, SelfDescribingValuePb::from(vec!["A"; element_count]));
}

/// Returns the Candid decoding and skipping costs of decoding `encoded_args` to `IDLValue`.
fn measure_candid_costs(schema: &str, method_name: &str, encoded_args: &[u8]) -> (usize, usize) {
    let prog = IDLProg::from_str(schema).unwrap();
    let mut type_env = TypeEnv::new();
    let service = check_prog(&mut type_env, &prog).unwrap().unwrap();
    let method = type_env.get_method(&service, method_name).unwrap();

    // Decode with quotas that will not run out, and see how much of them gets used.
    let mut original_config = DecoderConfig::new();
    original_config.set_decoding_quota(usize::MAX / 2);
    original_config.set_skipping_quota(usize::MAX / 2);
    let mut deserializer =
        candid::de::IDLDeserialize::new_with_config(encoded_args, &original_config).unwrap();
    let _idl_value = deserializer
        .get_value_with_type(&type_env, &method.args[0])
        .unwrap();
    deserializer.done().unwrap();

    let cost = deserializer.get_config().compute_cost(&original_config);
    (cost.decoding_quota.unwrap(), cost.skipping_quota.unwrap())
}

/// If this test starts breaking, that most likely means that Candid changed the
/// way it performs decoding cost accounting. In that case, do NOT ONLY update
/// the numbers in this test with the new observed values!
///
/// Rather, adjust `new_decoder_config` in the parent module so that it still
/// achieves the same goals. In particular, it tries to balance the following:
///
/// 1. Allow anything that fits within the size limit on the resulting
///    SelfDescribingValue,
///
/// 2. Do not waste effort on payloads that are going to get thrown away by the
///    aforementioned size limit.
///
/// (While it is unlikely that Candid would make such changes, not all aspects
/// of how it works are documented, and therefore, they seem prone to change.)
#[test]
fn test_candid_cost_model_is_as_assumed() {
    // Step 1: Prepare the world.

    #[derive(candid::CandidType, Clone)]
    enum Letter {
        A,
    }

    const SCHEMA: &str = r#"
        type Variant = variant {
            A;
        };

        type Record = record {
            key_id : opt nat32;
            pre_signatures_to_create_in_advance : opt nat32;
            max_queue_size : opt nat32;
        };

        service : {
            pass_many_variants : (vec Variant) -> ();
            pass_many_records : (vec Record) -> ();
            pass_one_blob : (blob) -> ();
        }
    "#;

    // Each case:
    // 1. method_name
    // 2. encoded args
    // 3. expected skipping cost
    let cases = vec![
        (
            "pass_many_variants",
            Encode!(&vec![Letter::A; 10_000]).unwrap(),
            210_002,
        ),
        (
            "pass_many_records",
            Encode!(&vec![REPRESENTATIVE_RECORD; 10_000]).unwrap(),
            970_002,
        ),
        (
            "pass_one_blob",
            Encode!(&serde_bytes::ByteBuf::from(vec![7_u8; 1_000_000])).unwrap(),
            1_000_002,
        ),
    ];

    for (method_name, encoded, expected_skipping_cost) in cases {
        // Step 2: Run the code under test.
        let (decoding_cost, skipping_cost) = measure_candid_costs(SCHEMA, method_name, &encoded);

        // Step 3: Verify result(s).
        assert_eq!(skipping_cost, expected_skipping_cost, "{}", method_name);

        let penalty = decoding_cost as f64 / skipping_cost as f64;
        assert!(
            (50.0..=51.0).contains(&penalty),
            "{}: {} vs. {} ({}x)",
            method_name,
            decoding_cost,
            skipping_cost,
            penalty,
        );
    }
}
