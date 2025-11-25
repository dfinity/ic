use ic_crypto_internal_sha2::{DomainSeparationContext, Sha512};
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
    let context = DomainSeparationContext::new("ctx");
    let data = b"data";

    let mut state = Sha512::new_with_context(&context);
    state.write(data);
    let digest = state.finish();

    // macOS/Linux: $ echo -n '\x03ctxdata' | shasum -a 512
    assert_eq!(
        hex::encode(digest),
        "65d6df8afdd6265c938d20c300420510af65378712f4286eecd3de772a2ce6abdadb3d8f6af69687394c4aa85a6228a0175d658efbaa2f6c0d328f48238b47e5"
    );
}

#[test]
fn test_sha512_with_empty_context_and_empty_data() {
    let context = DomainSeparationContext::new("");
    let data = b"";

    let mut state = Sha512::new_with_context(&context);
    state.write(data);
    let digest = state.finish();

    // macOS/Linux: $ echo -n '\x00' | shasum -a 512
    assert_eq!(
        hex::encode(digest),
        "b8244d028981d693af7b456af8efa4cad63d282e19ff14942c246e50d9351d22704a802a71c3580b6370de4ceb293c324a8423342557d4e5c38438f0e36910ee"
    );
}

#[test]
fn test_sha512_with_nonempty_context_and_empty_input() {
    let context = DomainSeparationContext::new("ctx");
    let data = b"";

    let mut state = Sha512::new_with_context(&context);
    state.write(data);
    let digest = state.finish();

    // macOS/Linux: $ echo -n '\x03ctx' | shasum -a 512
    assert_eq!(
        hex::encode(digest),
        "b853b52881da68aa94d4d938cb5ea61e75241cdab5a44db397f40111be0b77d6059c1b79a76f462d5a6f1cc75a92bd15fab2cf757306ce3cb10ab3ae095a52bd"
    );
}

#[test]
fn test_sha512_with_empty_context_and_nonempty_input() {
    let context = DomainSeparationContext::new("");
    let data = b"data";

    let mut state = Sha512::new_with_context(&context);
    state.write(data);
    let digest = state.finish();

    // macOS/Linux: $ echo -n '\x00data' | shasum -a 512
    assert_eq!(
        hex::encode(digest),
        "b563f34508ea65312780440f125b7e1c11be5babffb56b5dc72fffe3b958461573ca50122b97c20b19be1bc8904f9f5d0810823b023d79e1c685de4aac6e906e"
    );
}
