use std::collections::BTreeMap;

use super::HeapBytes;

#[test]
fn empty_total_bytes() {
    #[derive(HeapBytes, Default)]
    struct S {}
    assert_eq!(S::default().total_bytes(), 0);
    #[derive(HeapBytes, Default)]
    enum E {
        #[default]
        One,
    }
    assert_eq!(E::default().total_bytes(), 0);
    assert_eq!(String::new().total_bytes(), size_of::<String>());
    assert_eq!([()].total_bytes(), 0);
    assert_eq!(vec![()].total_bytes(), size_of::<Vec<()>>());
    assert_eq!(
        BTreeMap::<(), ()>::new().total_bytes(),
        size_of::<BTreeMap<(), ()>>()
    );
    assert_eq!(().total_bytes(), 0);
    assert_eq!(None::<()>.total_bytes(), 1);
    assert_eq!(Ok::<(), ()>(()).total_bytes(), 1);
    assert_eq!(Err::<(), ()>(()).total_bytes(), 1);
}

macro_rules! assert_struct_basic_field_total_bytes_eq {
    ($field_type:ty, $expected_size:expr) => {{
        #[derive(HeapBytes, Default)]
        struct S {
            v: $field_type,
        }
        assert_eq!(S::default().total_bytes(), $expected_size);
    }};
}

#[test]
fn struct_basic_field_total_bytes() {
    assert_struct_basic_field_total_bytes_eq!(u8, size_of::<u8>());
    assert_struct_basic_field_total_bytes_eq!(u16, size_of::<u16>());
    assert_struct_basic_field_total_bytes_eq!(u32, size_of::<u32>());
    assert_struct_basic_field_total_bytes_eq!(u64, size_of::<u64>());
    assert_struct_basic_field_total_bytes_eq!(u128, size_of::<u128>());
    assert_struct_basic_field_total_bytes_eq!(usize, size_of::<usize>());
    assert_struct_basic_field_total_bytes_eq!(i8, size_of::<i8>());
    assert_struct_basic_field_total_bytes_eq!(i16, size_of::<i16>());
    assert_struct_basic_field_total_bytes_eq!(i32, size_of::<i32>());
    assert_struct_basic_field_total_bytes_eq!(i64, size_of::<i64>());
    assert_struct_basic_field_total_bytes_eq!(i128, size_of::<i128>());
    assert_struct_basic_field_total_bytes_eq!(isize, size_of::<isize>());
    assert_struct_basic_field_total_bytes_eq!(f32, size_of::<f32>());
    assert_struct_basic_field_total_bytes_eq!(f64, size_of::<f64>());
    assert_struct_basic_field_total_bytes_eq!(bool, size_of::<bool>());
    assert_struct_basic_field_total_bytes_eq!(char, size_of::<char>());
}

#[test]
fn struct_basic_fields_total_bytes() {
    #[derive(HeapBytes, Default)]
    struct S {
        v1: u8,
        v2: u128,
    }
    assert_eq!(S::default().total_bytes(), size_of::<S>());
}

macro_rules! assert_enum_basic_field_total_bytes_eq {
    ($field_type:ty, $expected_size:expr) => {{
        #[derive(HeapBytes)]
        enum E {
            One($field_type),
        }
        assert_eq!(
            E::One(<$field_type>::default()).total_bytes(),
            $expected_size
        );
    }};
}

#[test]
fn enum_basic_field_total_bytes() {
    assert_enum_basic_field_total_bytes_eq!(u8, size_of::<u8>());
    assert_enum_basic_field_total_bytes_eq!(u16, size_of::<u16>());
    assert_enum_basic_field_total_bytes_eq!(u32, size_of::<u32>());
    assert_enum_basic_field_total_bytes_eq!(u64, size_of::<u64>());
    assert_enum_basic_field_total_bytes_eq!(u128, size_of::<u128>());
    assert_enum_basic_field_total_bytes_eq!(usize, size_of::<usize>());
    assert_enum_basic_field_total_bytes_eq!(i8, size_of::<i8>());
    assert_enum_basic_field_total_bytes_eq!(i16, size_of::<i16>());
    assert_enum_basic_field_total_bytes_eq!(i32, size_of::<i32>());
    assert_enum_basic_field_total_bytes_eq!(i64, size_of::<i64>());
    assert_enum_basic_field_total_bytes_eq!(i128, size_of::<i128>());
    assert_enum_basic_field_total_bytes_eq!(isize, size_of::<isize>());
    assert_enum_basic_field_total_bytes_eq!(f32, size_of::<f32>());
    assert_enum_basic_field_total_bytes_eq!(f64, size_of::<f64>());
    assert_enum_basic_field_total_bytes_eq!(bool, size_of::<bool>());
    assert_enum_basic_field_total_bytes_eq!(char, size_of::<char>());
}

#[test]
fn enum_basic_fields_total_bytes() {
    #[derive(HeapBytes)]
    enum E {
        One(u8, u128),
    }
    assert_eq!(
        E::One(<u8>::default(), <u128>::default()).total_bytes(),
        size_of::<E>()
    );
}

#[test]
fn enum_repr_total_bytes() {
    #[derive(HeapBytes, Default)]
    #[repr(u8)]
    enum U8 {
        #[default]
        One,
    }
    assert_eq!(U8::default().total_bytes(), size_of::<u8>());

    #[derive(HeapBytes, Default)]
    #[repr(u64)]
    enum U64 {
        #[default]
        One,
    }
    assert_eq!(U64::default().total_bytes(), size_of::<u64>());
}

#[test]
fn string_total_bytes() {
    let b = size_of::<String>();
    assert_eq!("".to_string().total_bytes(), b);
    assert_eq!("123".to_string().total_bytes(), b + 3);
}

#[test]
fn array_basic_total_bytes() {
    assert_eq!([42_u8; 42].total_bytes(), size_of::<u8>() * 42);
    assert_eq!([42_u16; 42].total_bytes(), size_of::<u16>() * 42);
    assert_eq!([42_u32; 42].total_bytes(), size_of::<u32>() * 42);
    assert_eq!([42_u64; 42].total_bytes(), size_of::<u64>() * 42);
    assert_eq!([42_u128; 42].total_bytes(), size_of::<u128>() * 42);
    assert_eq!([42_usize; 42].total_bytes(), size_of::<usize>() * 42);
    assert_eq!([42_i8; 42].total_bytes(), size_of::<i8>() * 42);
    assert_eq!([42_i16; 42].total_bytes(), size_of::<i16>() * 42);
    assert_eq!([42_i32; 42].total_bytes(), size_of::<i32>() * 42);
    assert_eq!([42_i64; 42].total_bytes(), size_of::<i64>() * 42);
    assert_eq!([42_i128; 42].total_bytes(), size_of::<i128>() * 42);
    assert_eq!([42_isize; 42].total_bytes(), size_of::<isize>() * 42);
    assert_eq!([42_f32; 42].total_bytes(), size_of::<f32>() * 42);
    assert_eq!([42_f64; 42].total_bytes(), size_of::<f64>() * 42);
    assert_eq!([true; 42].total_bytes(), size_of::<bool>() * 42);
    assert_eq!(['c'; 42].total_bytes(), size_of::<char>() * 42);
}

#[test]
fn vec_basic_total_bytes() {
    let b = size_of::<Vec<()>>();
    assert_eq!(vec![42_u8; 42].total_bytes(), b + size_of::<u8>() * 42);
    assert_eq!(vec![42_u16; 42].total_bytes(), b + size_of::<u16>() * 42);
    assert_eq!(vec![42_u32; 42].total_bytes(), b + size_of::<u32>() * 42);
    assert_eq!(vec![42_u64; 42].total_bytes(), b + size_of::<u64>() * 42);
    assert_eq!(vec![42_u128; 42].total_bytes(), b + size_of::<u128>() * 42);
    assert_eq!(
        vec![42_usize; 42].total_bytes(),
        b + size_of::<usize>() * 42
    );
    assert_eq!(vec![42_i8; 42].total_bytes(), b + size_of::<i8>() * 42);
    assert_eq!(vec![42_i16; 42].total_bytes(), b + size_of::<i16>() * 42);
    assert_eq!(vec![42_i32; 42].total_bytes(), b + size_of::<i32>() * 42);
    assert_eq!(vec![42_i64; 42].total_bytes(), b + size_of::<i64>() * 42);
    assert_eq!(vec![42_i128; 42].total_bytes(), b + size_of::<i128>() * 42);
    assert_eq!(
        vec![42_isize; 42].total_bytes(),
        b + size_of::<isize>() * 42
    );
    assert_eq!(vec![42_f32; 42].total_bytes(), b + size_of::<f32>() * 42);
    assert_eq!(vec![42_f64; 42].total_bytes(), b + size_of::<f64>() * 42);
    assert_eq!(vec![true; 42].total_bytes(), b + size_of::<bool>() * 42);
    assert_eq!(vec!['c'; 42].total_bytes(), b + size_of::<char>() * 42);
}

macro_rules! assert_btree_map_basic_total_bytes_eq {
    ($field_type:ty, $expected_size:expr) => {{
        let t = <$field_type>::default();
        assert_eq!(BTreeMap::from([(t, t)]).total_bytes(), $expected_size);
    }};
}

#[test]
fn btree_map_basic_total_bytes() {
    let b = size_of::<BTreeMap<(), ()>>();
    assert_btree_map_basic_total_bytes_eq!(u8, b + size_of::<u8>() * 2);
    assert_btree_map_basic_total_bytes_eq!(u16, b + size_of::<u16>() * 2);
    assert_btree_map_basic_total_bytes_eq!(u32, b + size_of::<u32>() * 2);
    assert_btree_map_basic_total_bytes_eq!(u64, b + size_of::<u64>() * 2);
    assert_btree_map_basic_total_bytes_eq!(u128, b + size_of::<u128>() * 2);
    assert_btree_map_basic_total_bytes_eq!(usize, b + size_of::<usize>() * 2);
    assert_btree_map_basic_total_bytes_eq!(i8, b + size_of::<i8>() * 2);
    assert_btree_map_basic_total_bytes_eq!(i16, b + size_of::<i16>() * 2);
    assert_btree_map_basic_total_bytes_eq!(i32, b + size_of::<i32>() * 2);
    assert_btree_map_basic_total_bytes_eq!(i64, b + size_of::<i64>() * 2);
    assert_btree_map_basic_total_bytes_eq!(i128, b + size_of::<i128>() * 2);
    assert_btree_map_basic_total_bytes_eq!(isize, b + size_of::<isize>() * 2);
    assert_btree_map_basic_total_bytes_eq!(bool, b + size_of::<bool>() * 2);
    assert_btree_map_basic_total_bytes_eq!(char, b + size_of::<char>() * 2);
}

#[test]
fn tuple_basic_total_bytes() {
    assert_eq!((42_u8,).total_bytes(), size_of::<u8>());
    assert_eq!((42_u8, 42_u8,).total_bytes(), size_of::<u8>() * 2);
    assert_eq!((42_u8, 42_u8, 42_u8,).total_bytes(), size_of::<u8>() * 3);
    assert_eq!(
        (42_u8, 42_u8, 42_u8, 42_u8,).total_bytes(),
        size_of::<u8>() * 4
    );
    assert_eq!(
        (42_u8, 42_u8, 42_u8, 42_u8, 42_u8,).total_bytes(),
        size_of::<u8>() * 5
    );
    assert_eq!(
        (42_u8, 42_u8, 42_u8, 42_u8, 42_u8, 42_u8,).total_bytes(),
        size_of::<u8>() * 6
    );
    assert_eq!(
        (42_u8, 42_u8, 42_u8, 42_u8, 42_u8, 42_u8, 42_u8,).total_bytes(),
        size_of::<u8>() * 7
    );
    assert_eq!(
        (42_u8, 42_u8, 42_u8, 42_u8, 42_u8, 42_u8, 42_u8, 42_u8,).total_bytes(),
        size_of::<(u8, u8, u8, u8, u8, u8, u8, u8,)>()
    );
}

#[test]
fn option_basic_total_bytes() {
    assert_eq!(Some(42_u8).total_bytes(), size_of::<u8>() * 2);
    assert_eq!(None::<u8>.total_bytes(), size_of::<u8>() * 2);
    assert_eq!(Some(42_u16).total_bytes(), size_of::<u16>() * 2);
    assert_eq!(None::<u16>.total_bytes(), size_of::<u16>() * 2);
    assert_eq!(Some(42_u32).total_bytes(), size_of::<u32>() * 2);
    assert_eq!(None::<u32>.total_bytes(), size_of::<u32>() * 2);
    assert_eq!(Some(42_u64).total_bytes(), size_of::<u64>() * 2);
    assert_eq!(None::<u64>.total_bytes(), size_of::<u64>() * 2);
    assert_eq!(Some(42_u128).total_bytes(), size_of::<u128>() * 2);
    assert_eq!(None::<u128>.total_bytes(), size_of::<u128>() * 2);
    assert_eq!(Some(42_usize).total_bytes(), size_of::<usize>() * 2);
    assert_eq!(None::<usize>.total_bytes(), size_of::<usize>() * 2);
    assert_eq!(Some(true).total_bytes(), size_of::<bool>());
    assert_eq!(None::<bool>.total_bytes(), size_of::<bool>());
    assert_eq!(Some('c').total_bytes(), size_of::<char>());
    assert_eq!(None::<char>.total_bytes(), size_of::<char>());
}

#[test]
fn result_basic_total_bytes() {
    assert_eq!(Ok::<u8, u8>(42).total_bytes(), size_of::<u8>() * 2);
    assert_eq!(Err::<u8, u8>(42).total_bytes(), size_of::<u8>() * 2);
    assert_eq!(Ok::<u16, u16>(42).total_bytes(), size_of::<u16>() * 2);
    assert_eq!(Err::<u16, u16>(42).total_bytes(), size_of::<u16>() * 2);
    assert_eq!(Ok::<u32, u32>(42).total_bytes(), size_of::<u32>() * 2);
    assert_eq!(Err::<u32, u32>(42).total_bytes(), size_of::<u32>() * 2);
    assert_eq!(Ok::<u64, u64>(42).total_bytes(), size_of::<u64>() * 2);
    assert_eq!(Err::<u64, u64>(42).total_bytes(), size_of::<u64>() * 2);
    assert_eq!(Ok::<u128, u128>(42).total_bytes(), size_of::<u128>() * 2);
    assert_eq!(Err::<u128, u128>(42).total_bytes(), size_of::<u128>() * 2);
    assert_eq!(Ok::<usize, usize>(42).total_bytes(), size_of::<usize>() * 2);
    assert_eq!(
        Err::<usize, usize>(42).total_bytes(),
        size_of::<usize>() * 2
    );
    assert_eq!(Ok::<bool, bool>(true).total_bytes(), size_of::<bool>() * 2);
    assert_eq!(Err::<bool, bool>(true).total_bytes(), size_of::<bool>() * 2);
    assert_eq!(Ok::<char, char>('c').total_bytes(), size_of::<char>() * 2);
    assert_eq!(Err::<char, char>('c').total_bytes(), size_of::<char>() * 2);
}

#[test]
fn mixed_struct() {
    #[derive(HeapBytes, Default)]
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
        S::default().total_bytes(),
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
    #[derive(HeapBytes, Default)]
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
        E::default().total_bytes(),
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
        tuple.total_bytes(),
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
    assert_eq!(tuple.total_bytes(), size_of::<String>() * 3 + 1 + 3 + 5);
}

#[test]
fn mixed_array() {
    let arr = [
        ("1".to_string(), "123".to_string()),
        ("12345".to_string(), "1234567".to_string()),
    ];
    assert_eq!(
        arr.total_bytes(),
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
        vec.total_bytes(),
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
        btree_map.total_bytes(),
        size_of::<BTreeMap<String, String>>() + size_of::<String>() * 4 + 1 + 3 + 5 + 7
    );
}

#[test]
fn nested_vec_enum_struct_string() {
    #[derive(HeapBytes)]
    struct S {
        v: Vec<String>,
        m: BTreeMap<String, String>,
    }
    #[derive(HeapBytes)]
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
        v.total_bytes(),
        size_of::<Vec<E>>()
            + size_of::<E>()
            + size_of::<E>()
            + size_of::<String>() * 8
            + 1
            + 3
            + 5
            + 7
            + 11
            + 13
            + 17
            + 19
            + size_of::<E>()
            + size_of::<Result<S, S>>() * 2
            + size_of::<String>() * 8
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
fn with_vec_enum_struct_string() {
    #[derive(HeapBytes)]
    struct S {
        v: Vec<String>,
        m: BTreeMap<String, String>,
    }
    #[derive(HeapBytes)]
    enum E {
        One,
        Two(Option<(S, S)>),
        #[heap_bytes(with = |v: &Vec<_>| v.len() + 17)]
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
    // Same as above, but the third option has a custom size calculation.
    assert_eq!(
        v.total_bytes(),
        size_of::<Vec<E>>()
            + size_of::<E>()
            + size_of::<E>()
            + size_of::<String>() * 8
            + 1
            + 3
            + 5
            + 7
            + 11
            + 13
            + 17
            + 19
            + size_of::<E>()
            + 2
            + 17
    );
}

#[test]
fn with_external_types() {
    #[derive(Default)]
    #[allow(dead_code)]
    struct ExternalStruct {
        u: u16,
    }

    #[derive(Default)]
    #[allow(dead_code)]
    enum ExternalEnum {
        #[default]
        One,
        Two(u32),
    }

    #[derive(HeapBytes, Default)]
    struct S {
        #[heap_bytes(with = |v: &Vec<_>| v.len() + 7)]
        v: Vec<ExternalStruct>,
        #[heap_bytes(with = |_| 11)]
        e: ExternalEnum,
    }
    assert_eq!(S::default().total_bytes(), size_of::<S>() + 7 + 11);
    assert_eq!(
        S {
            v: vec![
                ExternalStruct::default(),
                ExternalStruct::default(),
                ExternalStruct::default()
            ],
            e: ExternalEnum::Two(u32::MAX),
        }
        .total_bytes(),
        size_of::<S>() + 3 + 7 + 11
    );
}

#[test]
fn custom_heap_bytes() {
    #[derive(HeapBytes)]
    struct PreciseCount {
        s: String,
        v: Vec<String>,
    }

    assert_eq!(
        PreciseCount {
            s: "1".to_string(),
            v: vec!["123".to_string(), "12345".to_string()]
        }
        .total_bytes(),
        size_of::<PreciseCount>() + size_of::<String>() * 2 + 1 + 3 + 5
    );
}

#[test]
fn struct_heap_bytes_with() {
    #[derive(HeapBytes)]
    struct FieldWith {
        #[heap_bytes(with = |s: &String| s.len() + 5)]
        string: String,
        #[heap_bytes(with = |_v| self.vec.len() + 7)]
        vec: Vec<String>,
    }

    assert_eq!(
        FieldWith {
            string: "1".to_string(),
            vec: vec!["123".to_string(), "12345".to_string()]
        }
        .total_bytes(),
        size_of::<FieldWith>() + 1 + 5 + 2 + 7
    );

    #[derive(HeapBytes)]
    struct SuperWith {
        #[heap_bytes(with = |s: &String| s.len() + 11)]
        string: String,
        vec: Vec<FieldWith>,
    }

    assert_eq!(
        SuperWith {
            string: "1".to_string(),
            vec: vec![FieldWith {
                string: "1".to_string(),
                vec: vec!["123".to_string(), "12345".to_string()]
            }]
        }
        .total_bytes(),
        size_of::<SuperWith>() + 1 + 11 + size_of::<FieldWith>() + 1 + 5 + 2 + 7
    );
}

#[test]
fn enum_heap_bytes_with() {
    #[derive(HeapBytes)]
    enum VariantWith {
        #[heap_bytes(with = |s: &String| s.len() + 13)]
        One(String),
        #[heap_bytes(with = |v: &Vec<_>| v.len() + 17)]
        Two(Vec<String>),
    }

    assert_eq!(
        VariantWith::One("1".to_string()).total_bytes(),
        size_of::<VariantWith>() + 1 + 13
    );
    assert_eq!(
        VariantWith::Two(vec!["123".to_string(), "12345".to_string()]).total_bytes(),
        size_of::<VariantWith>() + 2 + 17
    );

    #[derive(HeapBytes)]
    enum FieldWith {
        One(
            #[heap_bytes(with = |s: &String| s.len() + 19)] String,
            String,
        ),
        Two(
            String,
            #[heap_bytes(with = |v: &Vec<_>| v.len() + 23)] Vec<String>,
        ),
    }

    assert_eq!(
        FieldWith::One("1".to_string(), "123".to_string()).total_bytes(),
        size_of::<FieldWith>() + 1 + 3 + 19
    );
    assert_eq!(
        FieldWith::Two(
            "1".to_string(),
            vec!["123".to_string(), "12345".to_string()]
        )
        .total_bytes(),
        size_of::<FieldWith>() + 1 + 2 + 23
    );

    #[derive(HeapBytes)]
    enum SuperdWith {
        #[heap_bytes(with = |s1: &String, s2: &String| s1.len() + s2.len() + 27)]
        One(String, String),
        Two(
            #[heap_bytes(with = |s: &String| s.len() + 29)] String,
            Vec<FieldWith>,
        ),
    }

    assert_eq!(
        SuperdWith::One("1".to_string(), "123".to_string()).total_bytes(),
        size_of::<SuperdWith>() + 1 + 3 + 27
    );
    assert_eq!(
        SuperdWith::Two(
            "12345".to_string(),
            vec![FieldWith::Two(
                "1".to_string(),
                vec!["123".to_string(), "12345".to_string()]
            )]
        )
        .total_bytes(),
        size_of::<SuperdWith>() + 5 + 29 + size_of::<FieldWith>() + 1 + 2 + 23
    );
}

#[test]
fn example_struct() {
    #[derive(HeapBytes)]
    struct MyStruct {
        s: String,
        v: Vec<String>,
    }

    let s = MyStruct {
        s: "1".to_string(),
        v: vec!["123".to_string(), "12345".to_string()],
    };
    assert_eq!(s.heap_bytes(), size_of::<String>() * 2 + 1 + 3 + 5);
    assert_eq!(
        s.total_bytes(),
        size_of::<MyStruct>() + size_of::<String>() * 2 + 1 + 3 + 5
    );

    #[derive(HeapBytes)]
    struct CustomHeapBytes {
        s: String,
        /// The vector's heap size is approximated using a constant-time closure.
        #[heap_bytes(with = |v: &Vec<String>| v.len() * size_of::<String>() + 17)]
        v: Vec<String>,
    }

    let s = CustomHeapBytes {
        s: "1".to_string(),
        v: vec!["123".to_string(), "12345".to_string()],
    };
    assert_eq!(s.heap_bytes(), 1 + 2 * size_of::<Vec<String>>() + 17);
    assert_eq!(
        s.total_bytes(),
        size_of::<CustomHeapBytes>() + 1 + 2 * size_of::<Vec<String>>() + 17
    );
}

#[test]
fn example_struct_with_function() {
    fn vec_approx(v: &[String]) -> usize {
        size_of_val(v) + 17
    }

    #[derive(HeapBytes)]
    struct CustomHeapBytes {
        s: String,
        /// The vector's heap size is approximated using a constant-time function.
        #[heap_bytes(with = vec_approx)]
        v: Vec<String>,
    }

    let s = CustomHeapBytes {
        s: "1".to_string(),
        v: vec!["123".to_string(), "12345".to_string()],
    };
    assert_eq!(s.heap_bytes(), 1 + 2 * size_of::<Vec<String>>() + 17);
    assert_eq!(
        s.total_bytes(),
        size_of::<CustomHeapBytes>() + 1 + 2 * size_of::<Vec<String>>() + 17
    );
}
