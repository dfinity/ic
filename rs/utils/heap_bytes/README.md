`HeapBytes` Trait and Derive
============================

This crate provides the `HeapBytes` trait and its derive macro. The trait
can be easily derived for structs and enums:

```rust
use ic_heap_bytes::HeapBytes;

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
```

To avoid performance issues, some field size calculations can be
approximated using the `#[heap_bytes(with = <CLOSURE>)]` attribute:

```rust
use ic_heap_bytes::HeapBytes;

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
```
