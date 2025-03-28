use super::*;

use crate::mock::MockCallCanisters;
use candid::Principal;
use ic_base_types::PrincipalId;
use ic_crypto_sha2::Sha256;

#[tokio::test]
async fn test_get_monolithic_blob_happy() {
    // Step 1: Prepare the world.

    let chunks = vec![
        b"It was the best of times.\n".to_vec(),
        b"It was the worst of times.\n".to_vec(),
        b"It was the age of foolishness.\n".to_vec(),
        b"It was the epoch of belief.\n".to_vec(),
    ];

    let content_sha256s = chunks
        .iter()
        .map(|chunk_content| Sha256::hash(chunk_content).to_vec())
        .collect::<Vec<Vec<u8>>>();

    // This is used by the code under test to talk to Registry. Whereas, in this
    // unit test, this is used in lieu of a real Registry canister.
    let call_canisters = MockCallCanisters::new();

    // Specify what registry calls the code under test is supposed to make.
    for (content, content_sha256) in chunks.iter().zip(content_sha256s.iter()) {
        let content_sha256 = Some(content_sha256.clone());
        let content = Some(content.clone());

        let request = GetChunkRequest { content_sha256 };
        let response = Ok(Chunk { content });
        call_canisters.expect_call(
            Principal::from(PrincipalId::from(REGISTRY_CANISTER_ID)),
            request,
            Ok(response),
        );
    }

    // Step 2: Call the code under test.
    let result = get_monolithic_blob(&call_canisters, REGISTRY_CANISTER_ID, &content_sha256s).await;

    // Step 3: Verify result(s).

    // The main thing that we care about is that the monolithic blob was
    // reconstructed.
    let monolithic_blob = chunks.clone().into_iter().flatten().collect::<Vec<u8>>();
    assert_eq!(result, Ok(monolithic_blob));

    // A secondary implicit assert here is that call_canisters has no left over
    // expected calls.
}
