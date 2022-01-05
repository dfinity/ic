#![allow(clippy::unwrap_used)]
use ic_crypto_internal_sha2::{Context, Sha512};
use std::hash::Hash;

const EXPECTED_DIGEST: [u8; 64] = [
    0x77, 0xC7, 0xCE, 0x9A, 0x5D, 0x86, 0xBB, 0x38, 0x6D, 0x44, 0x3B, 0xB9, 0x63, 0x90, 0xFA, 0xA1,
    0x20, 0x63, 0x31, 0x58, 0x69, 0x9C, 0x88, 0x44, 0xC3, 0x0B, 0x13, 0xAB, 0x0B, 0xF9, 0x27, 0x60,
    0xB7, 0xE4, 0x41, 0x6A, 0xEA, 0x39, 0x7D, 0xB9, 0x1B, 0x4A, 0xC0, 0xE5, 0xDD, 0x56, 0xB8, 0xEF,
    0x7E, 0x4B, 0x06, 0x61, 0x62, 0xAB, 0x1F, 0xDC, 0x08, 0x83, 0x19, 0xCE, 0x6D, 0xEF, 0xC8, 0x76,
];

#[test]
fn should_return_correct_output_with_single_call_to_write() {
    let mut state = Sha512::new();
    state.write(b"data");
    let digest = state.finish();

    assert_eq!(digest, EXPECTED_DIGEST);
}

#[test]
fn should_return_correct_output_with_multiple_calls_to_write() {
    let mut state = Sha512::new();
    state.write(b"da");
    state.write(b"ta");
    let digest = state.finish();

    assert_eq!(digest, EXPECTED_DIGEST);
}

#[test]
fn should_return_correct_output_with_convenience_function() {
    let digest = Sha512::hash(b"data");

    assert_eq!(digest, EXPECTED_DIGEST);
}

#[test]
fn should_produce_hash_with_512_bit() {
    assert_eq!(Sha512::hash(b"data").len(), 512 / 8);
}

#[test]
fn should_produce_hash_with_512_bit_for_data_longer_than_512_bit() {
    let text_with_445_bytes: &[u8; 445] = b"Lorem ipsum dolor sit amet, consectetur \
        adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut \
        enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea \
        commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum \
        dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in \
        culpa qui officia deserunt mollit anim id est laborum.";

    assert_eq!(Sha512::hash(text_with_445_bytes).len(), 512 / 8);
}

#[test]
fn should_act_as_writer() {
    let mut reader: &[u8] = b"data";
    let mut hasher = Sha512::new();

    std::io::copy(&mut reader, &mut hasher).unwrap();

    assert_eq!(hasher.finish(), EXPECTED_DIGEST);
}

#[test]
fn should_act_as_std_hash_hasher() {
    let object_that_implements_the_std_hash_trait: u8 = 42;

    let mut hasher_fed_via_hash_trait = Sha512::new();
    object_that_implements_the_std_hash_trait.hash(&mut hasher_fed_via_hash_trait);

    let mut hasher_fed_directly = Sha512::new();
    hasher_fed_directly.write(&[object_that_implements_the_std_hash_trait]);

    assert_eq!(
        hasher_fed_via_hash_trait.finish(),
        hasher_fed_directly.finish()
    );
    // In general, the output when feeding the hasher via the hash trait is
    // _not_ the same as the output when feeding the hasher
    // directly. It is only the same for some primitive types (like
    // 'u8') but not, e.g., for arrays or vectors because the hash
    // for these takes into account the length of the array/vector.
    // For this test here, however, this is irrelevant because we
    // only test that the hasher acts as `std::hash::Hasher`.
}

#[test]
#[should_panic]
fn should_panic_on_calling_finish_of_std_hash_hasher() {
    use std::hash::Hasher;
    let _hash: u64 = Hasher::finish(&Sha512::new());
}

#[test]
fn test_sha512_with_nonempty_context_and_nonempty_input() {
    let context = TestContext::new(&[0x11, 0x22, 0x33, 0x44]);
    let data = b"data";

    let mut state = Sha512::new_with_context(&context);
    state.write(data);
    let digest = state.finish();

    // macOS: $ echo -n '\x11\x22\x33\x44data' | shasum -a 512
    assert_eq!(
        digest,
        [
            0xCD, 0x8B, 0x5A, 0x40, 0xAF, 0x62, 0xBA, 0xA0, 0x44, 0xB5, 0xAB, 0xA7, 0x61, 0x75,
            0xF2, 0x2C, 0xF1, 0xAB, 0x6A, 0x58, 0x19, 0x74, 0xA3, 0xA5, 0xFF, 0x9E, 0xEE, 0xE7,
            0x76, 0xBC, 0x36, 0xBB, 0x42, 0x0A, 0xBD, 0x44, 0xC6, 0x9A, 0xD0, 0xA9, 0x68, 0x51,
            0x97, 0x5C, 0xC8, 0xF6, 0x95, 0x94, 0x64, 0x75, 0xD2, 0x69, 0x93, 0xA3, 0xE6, 0xA9,
            0x7A, 0xD2, 0x39, 0x0C, 0x3A, 0x39, 0xC2, 0x56,
        ]
    );
}

#[test]
fn test_sha512_with_empty_context_and_emtpy_data() {
    let context = TestContext::new(&[]);
    let data = b"";

    let mut state = Sha512::new_with_context(&context);
    state.write(data);
    let digest = state.finish();

    // macOS: $ echo -n '' | shasum -a 512
    assert_eq!(
        digest,
        [
            0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d,
            0x80, 0x07, 0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21,
            0xd3, 0x6c, 0xe9, 0xce, 0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83,
            0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f, 0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
            0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e,
        ]
    );
}

#[test]
fn test_sha512_with_nonempty_context_and_emtpy_input() {
    let context = TestContext::new(&[0x11, 0x22, 0x33, 0x44]);
    let data = b"";

    let mut state = Sha512::new_with_context(&context);
    state.write(data);
    let digest = state.finish();

    // macOS: $ echo -n '\x11\x22\x33\x44' | shasum -a 512
    assert_eq!(
        digest,
        [
            0xDF, 0xF8, 0x4D, 0x65, 0x53, 0x00, 0x03, 0xB1, 0xB4, 0x61, 0x59, 0x4A, 0xDE, 0x1B,
            0x59, 0xBE, 0x19, 0x16, 0x0A, 0x72, 0x02, 0x64, 0x56, 0x45, 0xF1, 0x4C, 0x95, 0x93,
            0x3C, 0x6B, 0x86, 0x9F, 0x1B, 0x80, 0xF9, 0x71, 0x65, 0x51, 0x6D, 0xA4, 0x13, 0xB3,
            0xD4, 0xAA, 0x19, 0x19, 0x31, 0xA8, 0x9C, 0x0A, 0x0B, 0xBF, 0xF3, 0x67, 0x7C, 0x26,
            0xD9, 0x2D, 0xA1, 0x1C, 0xB8, 0x9A, 0x62, 0xCD,
        ]
    );
}

#[test]
fn test_sha512_with_empty_context_and_nonempty_input() {
    let context = TestContext::new(&[]);
    let data = b"data";

    let mut state = Sha512::new_with_context(&context);
    state.write(data);
    let digest = state.finish();

    assert_eq!(digest, EXPECTED_DIGEST);
}

#[test]
fn should_produce_same_sha512_digest_as_if_openssl_sha512_was_used_directly() {
    let context = TestContext::new(b"context");

    let mut lib_state = Sha512::new_with_context(&context);
    lib_state.write(b"some data!");
    let lib_digest = lib_state.finish();

    let mut openssl_state = openssl::sha::Sha512::new();
    openssl_state.update(context.as_bytes());
    openssl_state.update(b"some data!");
    let openssl_digest = openssl_state.finish();

    assert_eq!(lib_digest, openssl_digest);
}

#[derive(Debug)]
struct TestContext {
    bytes: Vec<u8>,
}

impl TestContext {
    pub fn new(bytes: &[u8]) -> Self {
        TestContext {
            bytes: bytes.to_vec(),
        }
    }
}

impl Context for TestContext {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}
