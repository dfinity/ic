#![allow(clippy::unwrap_used)]
use crate::arbitrary::arbitrary_mixed_hash_tree;
use crate::MixedHashTree as T;
use proptest::prelude::*;
use serde_cbor::Value as Cbor;

fn arbitrary_invalid_cbor_encoding() -> impl Strategy<Value = Cbor> {
    let leaf = prop_oneof![
        Just(Cbor::Null),
        any::<bool>().prop_map(Cbor::Bool),
        any::<f64>().prop_map(Cbor::Float),
        (5..100i128).prop_map(Cbor::Integer),
        prop::collection::vec(any::<u8>(), 0..40).prop_map(Cbor::Bytes),
        ".*".prop_map(Cbor::Text),
    ];
    leaf.prop_recursive(
        /* depth= */ 3,
        /* max_size= */ 64,
        /* items_per_collection= */ 5,
        |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 0..5).prop_map(Cbor::Array),
                prop::collection::btree_map(inner.clone(), inner.clone(), 0..5).prop_map(Cbor::Map),
                (any::<u64>(), inner).prop_map(|(tag, value)| Cbor::Tag(tag, Box::new(value))),
            ]
        },
    )
}

fn arbitrary_valid_cbor_encoding() -> impl Strategy<Value = Cbor> {
    let leaf = prop_oneof![
        Just(Cbor::Array(vec![Cbor::Integer(0)])),
        prop::collection::vec(any::<u8>(), 1..100)
            .prop_map(|leaf_data| Cbor::Array(vec![Cbor::Integer(3), Cbor::Bytes(leaf_data)])),
        any::<[u8; 32]>()
            .prop_map(|digest| Cbor::Array(vec![Cbor::Integer(4), Cbor::Bytes(digest.to_vec())])),
    ];

    leaf.prop_recursive(
        /* depth= */ 5,
        /* max_size= */ 128,
        /* items_per_collection= */ 8,
        |inner| {
            prop_oneof![
                (inner.clone(), inner.clone()).prop_map(|(l, r)| Cbor::Array(vec![
                    Cbor::Integer(1),
                    l,
                    r
                ])),
                (".*", inner).prop_map(|(l, t)| Cbor::Array(vec![
                    Cbor::Integer(2),
                    Cbor::Bytes(l.as_bytes().to_vec()),
                    t
                ])),
            ]
        },
    )
}

proptest! {
    #[test]
    fn prop_tree_to_cbor_roundtrip(t in arbitrary_mixed_hash_tree()) {
        let cbor = serde_cbor::to_vec(&t).expect("failed to encode into CBOR");
        let decoded: T = serde_cbor::from_slice(&cbor[..]).expect("failed to decode CBOR");
        assert_eq!(t, decoded);
    }

    #[test]
    fn prop_cbor_to_tree_roundtrip(v in arbitrary_valid_cbor_encoding()) {
        let t: T = serde_cbor::value::from_value(v.clone()).expect("failed to decode CBOR");
        let v_encoded = serde_cbor::value::to_value(&t).expect("failed to encode into CBOR");
        assert_eq!(v, v_encoded);
    }


    #[test]
    fn prop_encoding_fails_on_invalid_cbor(v in arbitrary_invalid_cbor_encoding()) {
        let r: Result<T, _> = serde_cbor::value::from_value(v.clone());

        assert!(r.is_err(), "Successfully parsed a MixedHashTree {:?} from invalid CBOR {:?}", r.unwrap(), v);
    }

    #[test]
    fn prop_fails_on_extra_array_items(v in arbitrary_valid_cbor_encoding()) {
        use std::string::ToString;

        if let Cbor::Array(mut vec) = v {
            vec.push(Cbor::Array(vec![]));

            let v = Cbor::Array(vec);
            let r: Result<T, _> = serde_cbor::value::from_value(v.clone());
            match r {
                Ok(_) => panic!("Successfully parsed a MixedHashTree from invalid CBOR {:?}", v),
                Err(err) => assert!(err.to_string().contains("length"), "Expected invalid length error, got {:?}", err),
            }
        }
    }

    #[test]
    fn prop_fails_on_missing_array_items(v in arbitrary_valid_cbor_encoding()) {
        use std::string::ToString;

        if let Cbor::Array(mut vec) = v {
            vec.pop();

            let v = Cbor::Array(vec);
            let r: Result<T, _> = serde_cbor::value::from_value(v.clone());
            match r {
                Ok(_) => panic!("Successfully parsed a MixedHashTree from invalid CBOR {:?}", v),
                Err(err) => assert!(err.to_string().contains("length"), "Expected invalid length error, got {:?}", err),
            }
        }
    }

}

#[test]
fn fail_to_decode_unknown_tag() {
    use serde_cbor::{
        error::Error,
        value::Value::{Array, Integer, Null},
    };

    match serde_cbor::value::from_value(Array(vec![Integer(5), Null])) as Result<T, Error> {
        Err(err) if err.to_string().contains("unknown tag: 5") => (),
        other => panic!(
            "Expected an error with message containing 'unknown tag', got {:?}",
            other
        ),
    }
}
