use lazy_static::lazy_static;
use wabt::wat2wasm;

/// This is the code of a canister that can do exactly one thing:
/// read the first 10 bytes stable memory.
pub const STABLE_MEMORY_READER_WAT: &str = r#"
        (module
          (import "ic0" "msg_reply" (func $msg_reply))
          (import "ic0" "msg_reply_data_append"
            (func $msg_reply_data_append (param i32 i32)))
          (import "ic0" "stable_read"
            (func $stable_read (param $dst i32) (param $offset i32) (param $size i32)))

          (memory $memory 1)
          (export "memory" (memory $memory))

          (func $read_10_bytes_from_stable
            (call $stable_read
              (i32.const 0) ;; destination heap offset
              (i32.const 0) ;; stable memory offset
              (i32.const 10) ;; size
            )
            (call $msg_reply_data_append
              (i32.const 0) ;; heap offset
              (i32.const 10) ;; length
            )
            (call $msg_reply)
          )

          (export "canister_query read_10_bytes_from_stable" (func $read_10_bytes_from_stable))
        )"#;

lazy_static! {
    pub static ref STABLE_MEMORY_READER_WASM: Vec<u8> = wat2wasm(STABLE_MEMORY_READER_WAT).unwrap();
    pub static ref STABLE_MEMORY_READER_SHA256: [u8; 32] =
        ic_crypto_sha256::Sha256::hash(&STABLE_MEMORY_READER_WASM);
}
