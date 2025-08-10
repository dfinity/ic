use ic_crypto_internal_sha2::Sha224;
use std::hash::Hash;

const EXPECTED_DIGEST: [u8; 28] = [
    0xf4, 0x73, 0x96, 0x73, 0xac, 0xc0, 0x3c, 0x42, 0x43, 0x43, 0xb4, 0x52, 0x78, 0x7e, 0xe2, 0x3d,
    0xd6, 0x29, 0x99, 0xa8, 0xa9, 0xf1, 0x4f, 0x42, 0x50, 0x99, 0x57, 0x69,
];

#[test]
fn should_return_correct_output_with_single_call_to_write() {
    let mut state = Sha224::new();
    state.write(b"data");
    let digest = state.finish();

    assert_eq!(digest, EXPECTED_DIGEST);
}

#[test]
fn should_return_correct_output_with_multiple_calls_to_write() {
    let mut state = Sha224::new();
    state.write(b"da");
    state.write(b"ta");
    let digest = state.finish();

    assert_eq!(digest, EXPECTED_DIGEST);
}

#[test]
fn should_return_correct_output_with_convenience_function() {
    let digest = Sha224::hash(b"data");

    assert_eq!(digest, EXPECTED_DIGEST);
}

#[test]
fn should_produce_hash_with_224_bit() {
    assert_eq!(Sha224::hash(b"data").len(), 224 / 8);
}

#[test]
fn should_produce_hash_with_224_bit_for_data_longer_than_224_bit() {
    let text_with_445_bytes: &[u8; 445] = b"Lorem ipsum dolor sit amet, consectetur \
        adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut \
        enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea \
        commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum \
        dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in \
        culpa qui officia deserunt mollit anim id est laborum.";

    assert_eq!(Sha224::hash(text_with_445_bytes).len(), 224 / 8);
}

#[test]
fn should_act_as_writer() {
    let mut reader: &[u8] = b"data";
    let mut hasher = Sha224::new();

    std::io::copy(&mut reader, &mut hasher).unwrap();

    assert_eq!(hasher.finish(), EXPECTED_DIGEST);
}

#[test]
fn should_act_as_std_hash_hasher() {
    let object_that_implements_the_std_hash_trait: u8 = 42;

    let mut hasher_fed_via_hash_trait = Sha224::new();
    object_that_implements_the_std_hash_trait.hash(&mut hasher_fed_via_hash_trait);

    let mut hasher_fed_directly = Sha224::new();
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
    let _hash: u64 = Hasher::finish(&Sha224::new());
}
