`DeterministicHeapBytes` Trait and Derive
=========================================

This crate provides the `DeterministicHeapBytes` trait and its derive macro.
The trait can be easily derived for structs and enums,
enabling deterministic memory usage estimation:

```rust
use ic_heap_bytes::{deterministic_total_bytes, DeterministicHeapBytes};

#[derive(DeterministicHeapBytes)]
struct MyStruct {
    s: String,
    v: Vec<String>,
}

let s = MyStruct {
    s: "1".to_string(),
    v: vec!["123".to_string(), "12345".to_string()],
};
assert_eq!(s.deterministic_heap_bytes(), size_of::<String>() * 2 + 1 + 3 + 5);
assert_eq!(
    deterministic_total_bytes(&s),
    size_of::<MyStruct>() + size_of::<String>() * 2 + 1 + 3 + 5
);
```

Performance Impact
------------------

The default trait implementation iterates over all elements in collections
and sums their heap usage. This is `O(n)` and may be slow for large collections.

To mitigate performance impact, field size calculations can be
approximated using the `#[deterministic_heap_bytes(with = <CLOSURE>)]` attribute:

```rust
use ic_heap_bytes::{deterministic_total_bytes, DeterministicHeapBytes};

#[derive(DeterministicHeapBytes)]
struct CustomHeapBytes {
    s: String,
    /// The vector's heap size is approximated using a constant-time closure.
    #[deterministic_heap_bytes(with = |v: &Vec<String>| v.len() * size_of::<String>() + 17)]
    v: Vec<String>,
}

let s = CustomHeapBytes {
    s: "1".to_string(),
    v: vec!["123".to_string(), "12345".to_string()],
};
assert_eq!(s.deterministic_heap_bytes(), 1 + 2 * size_of::<Vec<String>>() + 17);
assert_eq!(
    deterministic_total_bytes(&s),
    size_of::<CustomHeapBytes>() + 1 + 2 * size_of::<Vec<String>>() + 17
);
```

Closure errors are clearly reported:

```rust
error[E0282]: type annotations needed
   --> packages/ic-heap-bytes/src/tests.rs:711:30
    |
711 |         #[deterministic_heap_bytes(with = |v| v.len() * size_of::<String>() + 17)]
    |                                            ^  - type must be known at this point
    |
help: consider giving this closure parameter an explicit type
    |
711 |         #[deterministic_heap_bytes(with = |v: /* Type */| v.len() * size_of::<String>() + 17)]
    |                                             ++++++++++++

error: aborting due to 1 previous error
```

Closures and functions used with the `#[deterministic_heap_bytes(with = ...)]` attribute
must accept a reference to the corresponding field:

```rust
#[derive(DeterministicHeapBytes)]
struct S {
    #[deterministic_heap_bytes(with = |v: &Vec<String>| v.len() * size_of::<String>())]
    v: Vec<String>,
}
```

For enum variants, they must accept references to the variant's fields:

```rust
#[derive(DeterministicHeapBytes)]
enum SuperdWith {
    #[deterministic_heap_bytes(with = |s1: &String, s2: &String| s1.len() + s2.len())]
    One(String, String),
}
```

A function name may also be used instead of a closure:

```rust
use ic_heap_bytes::{deterministic_total_bytes, DeterministicHeapBytes};

fn vec_approx(v: &[String]) -> usize {
    size_of_val(v) + 17
}

#[derive(DeterministicHeapBytes)]
struct CustomHeapBytes {
    s: String,
    /// The vector's heap size is approximated using a constant-time function.
    #[deterministic_heap_bytes(with = vec_approx)]
    v: Vec<String>,
}

let s = CustomHeapBytes {
    s: "1".to_string(),
    v: vec!["123".to_string(), "12345".to_string()],
};
assert_eq!(s.deterministic_heap_bytes(), 1 + 2 * size_of::<Vec<String>>() + 17);
assert_eq!(
    deterministic_total_bytes(&s),
    size_of::<CustomHeapBytes>() + 1 + 2 * size_of::<Vec<String>>() + 17
);
```
