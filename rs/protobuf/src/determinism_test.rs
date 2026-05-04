//! `prost` deterministic encoding tests.
//!
//! For each of a number of message types covering all `proto3` supported types,
//! the various tests encode a specific instance (default and non-default
//! values, single and multiple repeated fields, etc.) and ensure that the
//! output is an exact byte sequence.
//!
//! The decoded representations of the byte sequences were obtained from a mix
//! of `protoscope` and `protoc --decode_raw` on the output of
//! ```text
//! echo "$BYTE_SEQUENCE" | xxd -r -ps
//! ```
//!
//! # Warning
//! The failure of any of these tests (likely following a `prost` crate upgrade)
//! could result in stalled replicas or non-deterministic behavior. Please do
//! not "fix" any such test failures and notify the Message Routing team.

use maplit::btreemap;
use prost::Message;
use v1::*;

use crate::determinism_test::v1::composite::NestedInner;

#[allow(clippy::all)]
#[path = "gen/determinism_test/determinism_test.v1.rs"]
pub mod v1;

#[test]
fn scalars() {
    let scalars = Scalars {
        v_float: 1.0,
        v_double: 2.0,
        v_i32: -3,
        v_i64: -4,
        v_u32: 5,
        v_u64: 6,
        v_s32: -7,
        v_s64: -8,
        v_fu32: 9,
        v_fu64: 10,
        v_fi32: -11,
        v_fi64: -12,
        v_bool: true,
        v_string: "string".into(),
        v_bytes: b"bytes".to_vec(),
        r_float: vec![1.6, 11.66, 111.666],
        r_double: vec![1.7, 11.77, 111.777],
        r_i32: vec![18, -1188, 111888],
        r_i64: vec![19, -1199, 111999],
        r_u32: vec![20, 2200, 222000],
        r_u64: vec![21, 2211, 222111],
        r_s32: vec![22, -2222, 222222],
        r_s64: vec![23, -2233, 222333],
        r_fu32: vec![24, 2244, 222444],
        r_fu64: vec![25, 2255, 222555],
        r_fi32: vec![26, -2266, 222666],
        r_fi64: vec![27, -2277, 222777],
        r_bool: vec![false, true, false],
        r_string: vec!["one".into(), "two".into(), "three".into()],
        r_bytes: vec![b"1".to_vec(), b"2".to_vec(), b"3".to_vec()],
    };

    let mut buf = Vec::new();
    scalars.encode(&mut buf).unwrap();

    // Encoding roundtrip.
    assert_eq!(scalars, Scalars::decode(buf.as_slice()).unwrap());

    // Expected encoding:
    //
    // 1: 1.0i32   # 0x3f800000i32
    // 2: 2.0      # 0x4000000000000000i64
    // 3: -3
    // 4: -4
    // 5: 5
    // 6: 6
    // 7: 13
    // 8: 15
    // 9: 9i32
    // 10: 10i64
    // 11: 0xfffffff5i32
    // 12: 0xfffffffffffffff4i64
    // 13: 1
    // 14: {"string"}
    // 15: {"bytes"}
    // 16: {`cdcccc3f5c8f3a41fe54df42`}
    // 17: {`333333333333fb3f0ad7a3703d8a27407d3f355ebaf15b40`}
    // 18: {`12dcf6ffffffffffffff0190ea06`}
    // 19: {`13d1f6ffffffffffffff01ffea06`}
    // 20: {`149811b0c60d`}
    // 21: {`15a3119fc70d`}
    // 22: {`2cdb229c901b`}
    // 23: {`2ef122fa911b`}
    // 24: {`18000000c4080000ec640300`}
    // 25: {`1900000000000000cf080000000000005b65030000000000`}
    // 26: {`1a00000026f7ffffca650300`}
    // 27: {`1b000000000000001bf7ffffffffffff3966030000000000`}
    // 28: {`000100`}
    // 29: {"one"}
    // 29: {"two"}
    // 29: {"three"}
    // 30: {"1"}
    // 30: {"2"}
    // 30: {"3"}
    assert_eq!(
        "\
        0d0000803f11000000000000004018fdffffffffffffffff0120fcffffffffffffffff01280530\
        06380d400f4d09000000510a000000000000005df5ffffff61f4ffffffffffffff680172067374\
        72696e677a05627974657382010ccdcccc3f5c8f3a41fe54df428a0118333333333333fb3f0ad7\
        a3703d8a27407d3f355ebaf15b4092010e12dcf6ffffffffffffff0190ea069a010e13d1f6ffff\
        ffffffffff01ffea06a20106149811b0c60daa010615a3119fc70db201062cdb229c901bba0106\
        2ef122fa911bc2010c18000000c4080000ec640300ca01181900000000000000cf080000000000\
        005b65030000000000d2010c1a00000026f7ffffca650300da01181b000000000000001bf7ffff\
        ffffffff3966030000000000e20103000100ea01036f6e65ea010374776fea01057468726565f2\
        010131f2010132f2010133",
        hex::encode(buf),
        "Please do not \"fix\" this test and notify the Message Routing team"
    );
}

#[test]
fn scalars_single_repeated_value() {
    let scalars = Scalars {
        v_float: 1.0,
        v_double: 2.0,
        v_i32: -3,
        v_i64: -4,
        v_u32: 5,
        v_u64: 6,
        v_s32: -7,
        v_s64: -8,
        v_fu32: 9,
        v_fu64: 10,
        v_fi32: -11,
        v_fi64: -12,
        v_bool: true,
        v_string: "string".into(),
        v_bytes: b"bytes".to_vec(),
        r_float: vec![1.6],
        r_double: vec![1.7],
        r_i32: vec![18],
        r_i64: vec![19],
        r_u32: vec![20],
        r_u64: vec![21],
        r_s32: vec![22],
        r_s64: vec![23],
        r_fu32: vec![24],
        r_fu64: vec![25],
        r_fi32: vec![26],
        r_fi64: vec![27],
        r_bool: vec![true],
        r_string: vec!["one".into()],
        r_bytes: vec![b"1".to_vec()],
    };

    let mut buf = Vec::new();
    scalars.encode(&mut buf).unwrap();

    // Encoding roundtrip.
    assert_eq!(scalars, Scalars::decode(buf.as_slice()).unwrap());

    // Expected encoding:
    //
    // 1: 1.0i32   # 0x3f800000i32
    // 2: 2.0      # 0x4000000000000000i64
    // 3: -3
    // 4: -4
    // 5: 5
    // 6: 6
    // 7: 13
    // 8: 15
    // 9: 9i32
    // 10: 10i64
    // 11: 0xfffffff5i32
    // 12: 0xfffffffffffffff4i64
    // 13: 1
    // 14: {"string"}
    // 15: {"bytes"}
    // 16: {`cdcccc3f`}
    // 17: {`333333333333fb3f`}
    // 18: {`12`}
    // 19: {`13`}
    // 20: {`14`}
    // 21: {`15`}
    // 22: {`2c`}
    // 23: {`2e`}
    // 24: {`18000000`}
    // 25: {`1900000000000000`}
    // 26: {`1a000000`}
    // 27: {`1b00000000000000`}
    // 28: {`01`}
    // 29: {"one"}
    // 30: {"1"}
    assert_eq!(
        "\
        0d0000803f11000000000000004018fdffffffffffffffff0120fcffffffffffffffff01280530\
        06380d400f4d09000000510a000000000000005df5ffffff61f4ffffffffffffff680172067374\
        72696e677a056279746573820104cdcccc3f8a0108333333333333fb3f920101129a010113a201\
        0114aa010115b201012cba01012ec2010418000000ca01081900000000000000d201041a000000\
        da01081b00000000000000e2010101ea01036f6e65f2010131",
        hex::encode(buf),
        "Please do not \"fix\" this test and notify the Message Routing team"
    );
}

#[test]
fn scalars_default() {
    let scalars = Scalars::default();

    let mut buf = Vec::new();
    scalars.encode(&mut buf).unwrap();

    // Encoding roundtrip.
    assert_eq!(scalars, Scalars::decode(buf.as_slice()).unwrap());

    // Expected encoding
    assert_eq!(
        "",
        hex::encode(buf),
        "Please do not \"fix\" this test and notify the Message Routing team"
    );
}

#[test]
fn composite() {
    let simple = Simple {
        v_i64: 1,
        v_string: "one".into(),
    };
    let composite = Composite {
        v_simple: Some(simple.clone()),
        r_simple: vec![simple; 2],
        v_enum: Enum::One as i32,
        r_enum: vec![
            Enum::Unspecified as i32,
            Enum::One as i32,
            Enum::Many as i32,
        ],
        v_map: btreemap! {"one".into() => 1, "two".into() => 2, "three".into() => 3},
        v_oneof: Some(composite::VOneof::OneofInner(NestedInner { inner_u64: 4 })),
    };

    let mut buf = Vec::new();
    composite.encode(&mut buf).unwrap();

    // Encoding roundtrip.
    assert_eq!(composite, Composite::decode(buf.as_slice()).unwrap());

    // Expected encoding:
    //
    // 1: {
    //   1: 1
    //   2: {"one"}
    // }
    // 2: {
    //   1: 1
    //   2: {"one"}
    // }
    // 2: {
    //   1: 1
    //   2: {"one"}
    // }
    // 3: 1
    // 4: {`00010a`}
    // 5: {
    //   1: {"one"}
    //   2: 1
    // }
    // 5: {
    //   1: {"three"}
    //   2: 3
    // }
    // 5: {
    //   1: {"two"}
    //   2: 2
    // }
    // 7: {1: 4}
    assert_eq!(
        "\
        0a07080112036f6e651207080112036f6e651207080112036f6e651801220300010a2a070a036f\
        6e6510012a090a05746872656510032a070a0374776f10023a020804",
        hex::encode(buf),
        "Please do not \"fix\" this test and notify the Message Routing team"
    );
}

#[test]
fn composite_single_repeated_value() {
    let simple = Simple {
        v_i64: 2,
        v_string: "two".into(),
    };
    let composite = Composite {
        v_simple: Some(simple.clone()),
        r_simple: vec![simple],
        v_enum: Enum::One as i32,
        r_enum: vec![Enum::Unspecified as i32],
        v_map: btreemap! {"one".into() => 1},
        v_oneof: Some(composite::VOneof::OneofString("string".into())),
    };

    let mut buf = Vec::new();
    composite.encode(&mut buf).unwrap();

    // Encoding roundtrip.
    assert_eq!(composite, Composite::decode(buf.as_slice()).unwrap());

    // Expected encoding:
    //
    // 1: {
    //   1: 2
    //   2: {"two"}
    // }
    // 2: {
    //   1: 2
    //   2: {"two"}
    // }
    // 3: 1
    // 4: {`00`}
    // 5: {
    //   1: {"one"}
    //   2: 1
    // }
    // 6: {"string"}
    assert_eq!(
        "\
        0a070802120374776f12070802120374776f18012201002a070a036f6e6510013206737472696e\
        67",
        hex::encode(buf),
        "Please do not \"fix\" this test and notify the Message Routing team"
    );
}

#[test]
fn composite_default() {
    let composite = Composite::default();

    let mut buf = Vec::new();
    composite.encode(&mut buf).unwrap();

    // Encoding roundtrip.
    assert_eq!(composite, Composite::decode(buf.as_slice()).unwrap());

    // Expected encoding
    assert_eq!(
        "",
        hex::encode(buf),
        "Please do not \"fix\" this test and notify the Message Routing team"
    );
}

#[test]
fn composite_default_inner() {
    let simple = Simple::default();

    let composite = Composite {
        v_simple: Some(simple.clone()),
        r_simple: vec![simple; 2],
        v_enum: Enum::Unspecified as i32,
        r_enum: vec![
            Enum::Unspecified as i32,
            Enum::Unspecified as i32,
            Enum::Unspecified as i32,
        ],
        v_map: btreemap! {"".into() => 0, "zero.0".into() => 0, "zero.1".into() => 0},
        v_oneof: Some(composite::VOneof::OneofInner(NestedInner::default())),
    };

    let mut buf = Vec::new();
    composite.encode(&mut buf).unwrap();

    // Encoding roundtrip.
    assert_eq!(composite, Composite::decode(buf.as_slice()).unwrap());

    // Expected encoding:
    //
    // 1: {}
    // 2: {}
    // 2: {}
    // 4: {`000000`}
    // 5: {}
    // 5: {
    //   1: {"zero.0"}
    // }
    // 5: {
    //   1: {"zero.1"}
    // }
    // 7: {}
    assert_eq!(
        "0a001200120022030000002a002a080a067a65726f2e302a080a067a65726f2e313a00",
        hex::encode(buf),
        "Please do not \"fix\" this test and notify the Message Routing team"
    );
}

#[test]
fn ordering() {
    let ordering = Ordering {
        v_inner: Some(NestedInner { inner_u64: 1 }),
        r_bool: vec![true, false],
        v_bytes: b"bytes".to_vec(),
        v_string: "string".into(),
        v_i64: 2,
    };

    let mut buf = Vec::new();
    ordering.encode(&mut buf).unwrap();

    // Encoding roundtrip.
    assert_eq!(ordering, Ordering::decode(buf.as_slice()).unwrap());

    // Expected encoding:
    //
    // 2: {1: 1}
    // 3: {`0100`}
    // 5: {"string"}
    // 14: {"bytes"}
    // 16: 2
    assert_eq!(
        "120208011a0201002a06737472696e6772056279746573800102",
        hex::encode(buf),
        "Please do not \"fix\" this test and notify the Message Routing team"
    );
}
