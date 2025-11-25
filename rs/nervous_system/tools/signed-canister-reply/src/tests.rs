use super::*;

const SAMPLE_SIGNED_REPLY: &[u8] = include_bytes!("../signed_reply.cbor");

#[test]
fn test_load_from_file() {
    // Step 1: Prepare the world.

    // Create an input file, by essentially copying ../signed_reply.cbor.
    let mut signed_reply = tempfile::NamedTempFile::new().unwrap();
    signed_reply.write(SAMPLE_SIGNED_REPLY).unwrap();

    // Step 2: Call the code under test.
    let mut stdout = vec![];
    LoadFromFile {
        signed_reply_path: signed_reply.path().to_str().unwrap().to_string(),
    }
    .execute(&mut stdout);

    // Step 3: Verify results.
    let reply = hex::decode(&stdout).unwrap();
    let reply = candid::decode_args::<(String,)>(&reply)
        // This is the main assertion right here. I.e. that the output can
        // actually be Candid decoded as (String,).
        .unwrap()
        .0;
    assert!(reply.starts_with("profile: "), "{reply:?}");
}
