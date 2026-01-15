use super::{
    test_data::{MEGA_BLOB, MEGA_BLOB_CHUNK_KEYS},
    *,
};
use std::{cell::RefCell, rc::Rc};

#[test]
fn test_chunks() {
    // Step 1: Prepare the world.
    let memory = Rc::new(RefCell::new(Vec::<u8>::new()));
    let mut chunks = Chunks::init(memory);

    // Step 2: Call code under test.
    let keys = chunks.upsert_monolithic_blob(MEGA_BLOB.clone());

    // Step 3: Verify result(s).

    // Step 3.1: Inspect the keys.
    // The expected value is based on the chunk size being a little bit less
    // that 2e6.
    assert_eq!(keys.len(), 3, "{keys:#?}");
    assert_eq!(keys, *MEGA_BLOB_CHUNK_KEYS);

    // Step 3.2: Inspect reconstituted blob.

    // Step 3.2.1: Reconstitute.
    let reconstituted_monolithic_blob = keys
        .iter()
        .flat_map(|key| chunks.get_chunk(key).unwrap())
        .collect::<Vec<u8>>();

    // Step 3.2.2: Partially inspect the reconstituted blob. In particular, look
    // at its length, head, and tail.
    let len = reconstituted_monolithic_blob.len();
    assert_eq!(len, MEGA_BLOB.len());
    const SLICE_SIZE: usize = 25;
    assert_eq!(
        &reconstituted_monolithic_blob[..SLICE_SIZE],
        &MEGA_BLOB[..SLICE_SIZE],
    );
    assert_eq!(
        reconstituted_monolithic_blob[len - SLICE_SIZE..len],
        MEGA_BLOB[len - SLICE_SIZE..len],
    );

    // Step 3.2.3: Finally, make sure the whole thing survived the round trip.
    // assert_eq is not used directly, because that would cause a large amount
    // of spam.
    assert!(reconstituted_monolithic_blob == *MEGA_BLOB);
}
