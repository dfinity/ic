use std::collections::BTreeMap;

use super::ByteCount;
use ic_byte_count_derive::ByteCount;

#[test]
fn empty_byte_count() {
    #[derive(ByteCount, Default)]
    struct S {}
    assert_eq!(S::default().byte_count(), 0);
    #[derive(ByteCount, Default)]
    enum E {
        #[default]
        One,
    }
    assert_eq!(E::default().byte_count(), 0);
    assert_eq!(String::new().byte_count(), size_of::<String>());
    assert_eq!([()].byte_count(), 0);
    assert_eq!(vec![()].byte_count(), size_of::<Vec<()>>());
    assert_eq!(
        BTreeMap::<(), ()>::new().byte_count(),
        size_of::<BTreeMap<(), ()>>()
    );
    assert_eq!(().byte_count(), 0);
    assert_eq!(None::<()>.byte_count(), 1);
    assert_eq!(Ok::<(), ()>(()).byte_count(), 1);
    assert_eq!(Err::<(), ()>(()).byte_count(), 1);
}

macro_rules! assert_struct_basic_field_byte_count_eq {
    ($field_type:ty, $expected_size:expr) => {{
        #[derive(ByteCount, Default)]
        struct S {
            v: $field_type,
        }
        assert_eq!(S::default().byte_count(), $expected_size);
    }};
}

#[test]
fn struct_basic_field_byte_count() {
    assert_struct_basic_field_byte_count_eq!(u8, size_of::<u8>());
    assert_struct_basic_field_byte_count_eq!(u16, size_of::<u16>());
    assert_struct_basic_field_byte_count_eq!(u32, size_of::<u32>());
    assert_struct_basic_field_byte_count_eq!(u64, size_of::<u64>());
    assert_struct_basic_field_byte_count_eq!(u128, size_of::<u128>());
    assert_struct_basic_field_byte_count_eq!(usize, size_of::<usize>());
    assert_struct_basic_field_byte_count_eq!(i8, size_of::<i8>());
    assert_struct_basic_field_byte_count_eq!(i16, size_of::<i16>());
    assert_struct_basic_field_byte_count_eq!(i32, size_of::<i32>());
    assert_struct_basic_field_byte_count_eq!(i64, size_of::<i64>());
    assert_struct_basic_field_byte_count_eq!(i128, size_of::<i128>());
    assert_struct_basic_field_byte_count_eq!(isize, size_of::<isize>());
    assert_struct_basic_field_byte_count_eq!(f32, size_of::<f32>());
    assert_struct_basic_field_byte_count_eq!(f64, size_of::<f64>());
    assert_struct_basic_field_byte_count_eq!(bool, size_of::<bool>());
    assert_struct_basic_field_byte_count_eq!(char, size_of::<char>());
}

#[test]
fn struct_basic_fields_byte_count() {
    #[derive(ByteCount, Default)]
    struct S {
        v1: u8,
        v2: u128,
    }
    assert_eq!(S::default().byte_count(), size_of::<S>());
}

macro_rules! assert_enum_basic_field_byte_count_eq {
    ($field_type:ty, $expected_size:expr) => {{
        #[derive(ByteCount)]
        enum E {
            One($field_type),
        }
        assert_eq!(
            E::One(<$field_type>::default()).byte_count(),
            $expected_size
        );
    }};
}

#[test]
fn enum_basic_field_byte_count() {
    assert_enum_basic_field_byte_count_eq!(u8, size_of::<u8>());
    assert_enum_basic_field_byte_count_eq!(u16, size_of::<u16>());
    assert_enum_basic_field_byte_count_eq!(u32, size_of::<u32>());
    assert_enum_basic_field_byte_count_eq!(u64, size_of::<u64>());
    assert_enum_basic_field_byte_count_eq!(u128, size_of::<u128>());
    assert_enum_basic_field_byte_count_eq!(usize, size_of::<usize>());
    assert_enum_basic_field_byte_count_eq!(i8, size_of::<i8>());
    assert_enum_basic_field_byte_count_eq!(i16, size_of::<i16>());
    assert_enum_basic_field_byte_count_eq!(i32, size_of::<i32>());
    assert_enum_basic_field_byte_count_eq!(i64, size_of::<i64>());
    assert_enum_basic_field_byte_count_eq!(i128, size_of::<i128>());
    assert_enum_basic_field_byte_count_eq!(isize, size_of::<isize>());
    assert_enum_basic_field_byte_count_eq!(f32, size_of::<f32>());
    assert_enum_basic_field_byte_count_eq!(f64, size_of::<f64>());
    assert_enum_basic_field_byte_count_eq!(bool, size_of::<bool>());
    assert_enum_basic_field_byte_count_eq!(char, size_of::<char>());
}

#[test]
fn enum_basic_fields_byte_count() {
    #[derive(ByteCount)]
    enum E {
        One(u8, u128),
    }
    assert_eq!(
        E::One(<u8>::default(), <u128>::default()).byte_count(),
        size_of::<E>()
    );
}

#[test]
fn enum_repr_byte_count() {
    #[derive(ByteCount, Default)]
    #[repr(u8)]
    enum U8 {
        #[default]
        One,
    }
    assert_eq!(U8::default().byte_count(), size_of::<u8>());

    #[derive(ByteCount, Default)]
    #[repr(u64)]
    enum U64 {
        #[default]
        One,
    }
    assert_eq!(U64::default().byte_count(), size_of::<u64>());
}

#[test]
fn string_byte_count() {
    let b = size_of::<String>();
    assert_eq!("".to_string().byte_count(), b);
    assert_eq!("123".to_string().byte_count(), b + 3);
}

#[test]
fn array_basic_byte_count() {
    assert_eq!([42_u8; 42].byte_count(), size_of::<u8>() * 42);
    assert_eq!([42_u16; 42].byte_count(), size_of::<u16>() * 42);
    assert_eq!([42_u32; 42].byte_count(), size_of::<u32>() * 42);
    assert_eq!([42_u64; 42].byte_count(), size_of::<u64>() * 42);
    assert_eq!([42_u128; 42].byte_count(), size_of::<u128>() * 42);
    assert_eq!([42_usize; 42].byte_count(), size_of::<usize>() * 42);
    assert_eq!([42_i8; 42].byte_count(), size_of::<i8>() * 42);
    assert_eq!([42_i16; 42].byte_count(), size_of::<i16>() * 42);
    assert_eq!([42_i32; 42].byte_count(), size_of::<i32>() * 42);
    assert_eq!([42_i64; 42].byte_count(), size_of::<i64>() * 42);
    assert_eq!([42_i128; 42].byte_count(), size_of::<i128>() * 42);
    assert_eq!([42_isize; 42].byte_count(), size_of::<isize>() * 42);
    assert_eq!([42_f32; 42].byte_count(), size_of::<f32>() * 42);
    assert_eq!([42_f64; 42].byte_count(), size_of::<f64>() * 42);
    assert_eq!([true; 42].byte_count(), size_of::<bool>() * 42);
    assert_eq!(['c'; 42].byte_count(), size_of::<char>() * 42);
}

#[test]
fn vec_basic_byte_count() {
    let b = size_of::<Vec<()>>();
    assert_eq!(vec![42_u8; 42].byte_count(), b + size_of::<u8>() * 42);
    assert_eq!(vec![42_u16; 42].byte_count(), b + size_of::<u16>() * 42);
    assert_eq!(vec![42_u32; 42].byte_count(), b + size_of::<u32>() * 42);
    assert_eq!(vec![42_u64; 42].byte_count(), b + size_of::<u64>() * 42);
    assert_eq!(vec![42_u128; 42].byte_count(), b + size_of::<u128>() * 42);
    assert_eq!(vec![42_usize; 42].byte_count(), b + size_of::<usize>() * 42);
    assert_eq!(vec![42_i8; 42].byte_count(), b + size_of::<i8>() * 42);
    assert_eq!(vec![42_i16; 42].byte_count(), b + size_of::<i16>() * 42);
    assert_eq!(vec![42_i32; 42].byte_count(), b + size_of::<i32>() * 42);
    assert_eq!(vec![42_i64; 42].byte_count(), b + size_of::<i64>() * 42);
    assert_eq!(vec![42_i128; 42].byte_count(), b + size_of::<i128>() * 42);
    assert_eq!(vec![42_isize; 42].byte_count(), b + size_of::<isize>() * 42);
    assert_eq!(vec![42_f32; 42].byte_count(), b + size_of::<f32>() * 42);
    assert_eq!(vec![42_f64; 42].byte_count(), b + size_of::<f64>() * 42);
    assert_eq!(vec![true; 42].byte_count(), b + size_of::<bool>() * 42);
    assert_eq!(vec!['c'; 42].byte_count(), b + size_of::<char>() * 42);
}

macro_rules! assert_btree_map_basic_byte_count_eq {
    ($field_type:ty, $expected_size:expr) => {{
        let t = <$field_type>::default();
        assert_eq!(BTreeMap::from([(t, t)]).byte_count(), $expected_size);
    }};
}

#[test]
fn btree_map_basic_byte_count() {
    let b = size_of::<BTreeMap<(), ()>>();
    assert_btree_map_basic_byte_count_eq!(u8, b + size_of::<u8>() * 2);
    assert_btree_map_basic_byte_count_eq!(u16, b + size_of::<u16>() * 2);
    assert_btree_map_basic_byte_count_eq!(u32, b + size_of::<u32>() * 2);
    assert_btree_map_basic_byte_count_eq!(u64, b + size_of::<u64>() * 2);
    assert_btree_map_basic_byte_count_eq!(u128, b + size_of::<u128>() * 2);
    assert_btree_map_basic_byte_count_eq!(usize, b + size_of::<usize>() * 2);
    assert_btree_map_basic_byte_count_eq!(i8, b + size_of::<i8>() * 2);
    assert_btree_map_basic_byte_count_eq!(i16, b + size_of::<i16>() * 2);
    assert_btree_map_basic_byte_count_eq!(i32, b + size_of::<i32>() * 2);
    assert_btree_map_basic_byte_count_eq!(i64, b + size_of::<i64>() * 2);
    assert_btree_map_basic_byte_count_eq!(i128, b + size_of::<i128>() * 2);
    assert_btree_map_basic_byte_count_eq!(isize, b + size_of::<isize>() * 2);
    assert_btree_map_basic_byte_count_eq!(bool, b + size_of::<bool>() * 2);
    assert_btree_map_basic_byte_count_eq!(char, b + size_of::<char>() * 2);
}

#[test]
fn tuple_basic_byte_count() {
    assert_eq!((42_u8,).byte_count(), size_of::<u8>());
    assert_eq!((42_u8, 42_u8,).byte_count(), size_of::<u8>() * 2);
    assert_eq!((42_u8, 42_u8, 42_u8,).byte_count(), size_of::<u8>() * 3);
    assert_eq!(
        (42_u8, 42_u8, 42_u8, 42_u8,).byte_count(),
        size_of::<u8>() * 4
    );
    assert_eq!(
        (42_u8, 42_u8, 42_u8, 42_u8, 42_u8,).byte_count(),
        size_of::<u8>() * 5
    );
    assert_eq!(
        (42_u8, 42_u8, 42_u8, 42_u8, 42_u8, 42_u8,).byte_count(),
        size_of::<u8>() * 6
    );
    assert_eq!(
        (42_u8, 42_u8, 42_u8, 42_u8, 42_u8, 42_u8, 42_u8,).byte_count(),
        size_of::<u8>() * 7
    );
    assert_eq!(
        (42_u8, 42_u8, 42_u8, 42_u8, 42_u8, 42_u8, 42_u8, 42_u8,).byte_count(),
        size_of::<(u8, u8, u8, u8, u8, u8, u8, u8,)>()
    );
}

#[test]
fn option_basic_byte_count() {
    assert_eq!(Some(42_u8).byte_count(), size_of::<u8>() * 2);
    assert_eq!(None::<u8>.byte_count(), size_of::<u8>() * 2);
    assert_eq!(Some(42_u16).byte_count(), size_of::<u16>() * 2);
    assert_eq!(None::<u16>.byte_count(), size_of::<u16>() * 2);
    assert_eq!(Some(42_u32).byte_count(), size_of::<u32>() * 2);
    assert_eq!(None::<u32>.byte_count(), size_of::<u32>() * 2);
    assert_eq!(Some(42_u64).byte_count(), size_of::<u64>() * 2);
    assert_eq!(None::<u64>.byte_count(), size_of::<u64>() * 2);
    assert_eq!(Some(42_u128).byte_count(), size_of::<u128>() * 2);
    assert_eq!(None::<u128>.byte_count(), size_of::<u128>() * 2);
    assert_eq!(Some(42_usize).byte_count(), size_of::<usize>() * 2);
    assert_eq!(None::<usize>.byte_count(), size_of::<usize>() * 2);
    assert_eq!(Some(true).byte_count(), size_of::<bool>());
    assert_eq!(None::<bool>.byte_count(), size_of::<bool>());
    assert_eq!(Some('c').byte_count(), size_of::<char>());
    assert_eq!(None::<char>.byte_count(), size_of::<char>());
}

#[test]
fn result_basic_byte_count() {
    assert_eq!(Ok::<u8, u8>(42).byte_count(), size_of::<u8>() * 2);
    assert_eq!(Err::<u8, u8>(42).byte_count(), size_of::<u8>() * 2);
    assert_eq!(Ok::<u16, u16>(42).byte_count(), size_of::<u16>() * 2);
    assert_eq!(Err::<u16, u16>(42).byte_count(), size_of::<u16>() * 2);
    assert_eq!(Ok::<u32, u32>(42).byte_count(), size_of::<u32>() * 2);
    assert_eq!(Err::<u32, u32>(42).byte_count(), size_of::<u32>() * 2);
    assert_eq!(Ok::<u64, u64>(42).byte_count(), size_of::<u64>() * 2);
    assert_eq!(Err::<u64, u64>(42).byte_count(), size_of::<u64>() * 2);
    assert_eq!(Ok::<u128, u128>(42).byte_count(), size_of::<u128>() * 2);
    assert_eq!(Err::<u128, u128>(42).byte_count(), size_of::<u128>() * 2);
    assert_eq!(Ok::<usize, usize>(42).byte_count(), size_of::<usize>() * 2);
    assert_eq!(Err::<usize, usize>(42).byte_count(), size_of::<usize>() * 2);
    assert_eq!(Ok::<bool, bool>(true).byte_count(), size_of::<bool>() * 2);
    assert_eq!(Err::<bool, bool>(true).byte_count(), size_of::<bool>() * 2);
    assert_eq!(Ok::<char, char>('c').byte_count(), size_of::<char>() * 2);
    assert_eq!(Err::<char, char>('c').byte_count(), size_of::<char>() * 2);
}

#[test]
fn mixed_struct() {
    #[derive(ByteCount, Default)]
    struct S {
        b: usize,
        s: String,
        o: Option<String>,
        t: (String, String),
        a: [String; 3],
        v: Vec<String>,
        m: BTreeMap<String, String>,
    }
    assert_eq!(
        S::default().byte_count(),
        size_of::<usize>()
            + size_of::<String>()
            + size_of::<Option<String>>()
            + size_of::<(String, String)>()
            + size_of::<[String; 3]>()
            + size_of::<Vec<String>>()
            + size_of::<BTreeMap<String, String>>()
    );
}

#[test]
fn mixed_enum() {
    #[allow(dead_code)]
    #[derive(ByteCount, Default)]
    #[repr(usize)]
    enum E {
        #[default]
        Empty,
        Basic(usize),
        String(String),
        Option(Option<usize>),
        Tuple((usize, usize)),
        Array([usize; 3]),
        Vec(Vec<usize>),
        BTreeMap(BTreeMap<usize, usize>),
    }
    assert_eq!(
        E::default().byte_count(),
        size_of::<usize>()
            + size_of::<String>()
                .max(size_of::<Option<usize>>())
                .max(size_of::<(usize, usize)>())
                .max(size_of::<[usize; 3]>())
                .max(size_of::<Vec<usize>>())
                .max(size_of::<BTreeMap<usize, usize>>())
    );
}

#[test]
fn mixed_tuple() {
    let tuple = (
        42_usize,
        String::new(),
        Some(String::new()),
        Ok::<String, String>(String::new()),
        (String::new(), String::new()),
        [42_usize; 3],
        vec![String::new(); 3],
        BTreeMap::from([(String::new(), String::new())]),
    );
    assert_eq!(
        tuple.byte_count(),
        size_of::<usize>()
            + size_of::<String>()
            + size_of::<Option<String>>()
            + size_of::<Result::<String, String>>()
            + size_of::<(String, String)>()
            + size_of::<[usize; 3]>()
            + size_of::<Vec<String>>()
            + size_of::<String>() * 3
            + size_of::<BTreeMap<String, String>>()
            + size_of::<String>() * 2
    );

    let tuple = ("1".to_string(), "123".to_string(), "12345".to_string());
    assert_eq!(tuple.byte_count(), size_of::<String>() * 3 + 1 + 3 + 5);
}

#[test]
fn mixed_array() {
    let arr = [
        ("1".to_string(), "123".to_string()),
        ("12345".to_string(), "1234567".to_string()),
    ];
    assert_eq!(
        arr.byte_count(),
        size_of::<[(String, String); 2]>() + 1 + 3 + 5 + 7
    );
}

#[test]
fn mixed_vec() {
    let vec = vec![
        ("1".to_string(), "123".to_string()),
        ("12345".to_string(), "1234567".to_string()),
    ];
    assert_eq!(
        vec.byte_count(),
        size_of::<Vec<(String, String)>>() + size_of::<String>() * 4 + 1 + 3 + 5 + 7
    );
}

#[test]
fn mixed_btree_map() {
    let btree_map = BTreeMap::from([
        ("1".to_string(), "123".to_string()),
        ("12345".to_string(), "1234567".to_string()),
    ]);
    assert_eq!(
        btree_map.byte_count(),
        size_of::<BTreeMap<String, String>>() + size_of::<String>() * 4 + 1 + 3 + 5 + 7
    );
}

#[test]
fn nested_vec_enum_struct_string() {
    #[derive(ByteCount)]
    struct S {
        v: Vec<String>,
        m: BTreeMap<String, String>,
    }
    #[derive(ByteCount)]
    enum E {
        One,
        Two(Option<(S, S)>),
        Three(Vec<Result<S, S>>),
    }
    let v = vec![
        E::One,
        E::Two(Some((
            S {
                v: vec!["!".to_string(), "!".repeat(3).to_string()],
                m: BTreeMap::from([("!".repeat(5).to_string(), "!".repeat(7).to_string())]),
            },
            S {
                v: vec!["!".repeat(11).to_string(), "!".repeat(13).to_string()],
                m: BTreeMap::from([("!".repeat(17).to_string(), "!".repeat(19).to_string())]),
            },
        ))),
        E::Three(vec![
            Ok(S {
                v: vec!["!".repeat(23).to_string(), "!".repeat(29).to_string()],
                m: BTreeMap::from([("!".repeat(31).to_string(), "!".repeat(37).to_string())]),
            }),
            Err(S {
                v: vec!["!".repeat(41).to_string(), "!".repeat(43).to_string()],
                m: BTreeMap::from([("!".repeat(47).to_string(), "!".repeat(53).to_string())]),
            }),
        ]),
    ];
    assert_eq!(
        v.byte_count(),
        size_of::<Vec<E>>()
            + size_of::<E>() * 3
            + size_of::<Result<S, S>>() * 2
            + size_of::<String>() * 16
            + 1
            + 3
            + 5
            + 7
            + 11
            + 13
            + 17
            + 19
            + 23
            + 29
            + 31
            + 37
            + 41
            + 43
            + 47
            + 53
    );
}

#[test]
fn approx_vec_enum_struct_string() {
    #[derive(ByteCount)]
    struct S {
        v: Vec<String>,
        #[byte_count(approx)]
        m: BTreeMap<String, String>,
    }
    #[derive(ByteCount)]
    enum E {
        One,
        Two(Option<(S, S)>),
        #[byte_count(approx)]
        Three(Vec<Result<S, S>>),
    }
    let v = vec![
        E::One,
        E::Two(Some((
            S {
                v: vec!["!".to_string(), "!".repeat(3).to_string()],
                m: BTreeMap::from([("!".repeat(5).to_string(), "!".repeat(7).to_string())]),
            },
            S {
                v: vec!["!".repeat(11).to_string(), "!".repeat(13).to_string()],
                m: BTreeMap::from([("!".repeat(17).to_string(), "!".repeat(19).to_string())]),
            },
        ))),
        E::Three(vec![
            Ok(S {
                v: vec!["!".repeat(23).to_string(), "!".repeat(29).to_string()],
                m: BTreeMap::from([("!".repeat(31).to_string(), "!".repeat(37).to_string())]),
            }),
            Err(S {
                v: vec!["!".repeat(41).to_string(), "!".repeat(43).to_string()],
                m: BTreeMap::from([("!".repeat(47).to_string(), "!".repeat(53).to_string())]),
            }),
        ]),
    ];
    // All BTreeMap strings and vector of results (third enum variant) are approximated.
    assert_eq!(
        v.byte_count(),
        size_of::<Vec<E>>()
            + size_of::<E>() * 3
            + size_of::<Result<S, S>>() * 2
            + size_of::<String>() * 8
            + 1
            + 3
            + 11
            + 13
    );
}

#[test]
fn example_struct() {
    #[derive(ByteCount)]
    struct PreciseCount {
        s: String,
        v: Vec<String>,
    }

    assert_eq!(
        PreciseCount {
            s: "1".to_string(),
            v: vec!["123".to_string(), "12345".to_string()]
        }
        .byte_count(),
        size_of::<PreciseCount>() + size_of::<String>() * 2 + 1 + 3 + 5
    );

    #[derive(ByteCount)]
    struct ApproxCount {
        s: String,
        #[byte_count(approx)]
        v: Vec<String>,
    }

    assert_eq!(
        ApproxCount {
            s: "1".to_string(),
            v: vec!["123".to_string(), "12345".to_string()]
        }
        .byte_count(),
        size_of::<ApproxCount>() + size_of::<String>() * 2 + 1
    );
}
