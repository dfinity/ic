use canister_test::{local_test_e, Wasm};
use ic_canister_client::Sender;
use ic_test_identity::TEST_IDENTITY_KEYPAIR;
use ic_test_utilities::universal_canister::wasm as universal_canister_argument_builder;
use ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM;
use on_wire::bytes;

#[test]
fn test_update_from_sender() {
    local_test_e(|runtime| async move {
        let universal_canister = Wasm::from_bytes(UNIVERSAL_CANISTER_WASM)
            .install(&runtime)
            .bytes(Vec::new())
            .await
            .unwrap();
        let sender = Sender::from_keypair(&TEST_IDENTITY_KEYPAIR);

        let result: Result<Vec<u8>, String> = universal_canister
            .update_from_sender(
                "update",
                bytes,
                universal_canister_argument_builder()
                    .caller()
                    .reply_data_append()
                    .reply()
                    .build(),
                &sender,
            )
            .await;

        assert_eq!(sender.get_principal_id().to_vec(), result.unwrap());
        Ok(())
    });
}
