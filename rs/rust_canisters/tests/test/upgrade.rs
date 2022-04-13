//! Test that we can upgrade a canister and keep the stable memory,
//! and that we can re-install a canister, which wipes out the stable memory.

use assert_matches::assert_matches;
use canister_test::{local_test_e, Canister, Runtime, Wasm};
use ic_ic00_types::CanisterInstallMode;
use ic_test_utilities::stable_memory_reader::STABLE_MEMORY_READER_WAT;
use ic_test_utilities::universal_canister::wasm as universal_canister_argument_builder;
use ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM;
use on_wire::bytes;

async fn set_up_universal_canister(runtime: &'_ Runtime) -> Canister<'_> {
    Wasm::from_bytes(UNIVERSAL_CANISTER_WASM)
        .install(runtime)
        .bytes(Vec::new())
        .await
        .unwrap()
}

const MSG: &[u8] = b"this beautiful prose should be persisted for future generations";

/// Records the MSG in stable memory.
async fn push_message_to_stable(universal_canister: &Canister<'_>) {
    universal_canister
        .update_(
            "update",
            bytes,
            universal_canister_argument_builder()
                .stable_grow(1)
                .stable_write(0, MSG)
                .reply()
                .build(),
        )
        .await
        .unwrap();
}

/// Tries to read the first `MSG.len()` bytes of the stable memory.
async fn try_to_read_message_from_stable(
    universal_canister: &Canister<'_>,
) -> Result<Vec<u8>, String> {
    universal_canister
        .query_(
            "query",
            bytes,
            universal_canister_argument_builder()
                .stable_read(0, MSG.len() as u32)
                .reply_data_append()
                .reply()
                .build(),
        )
        .await
}

#[test]
fn test_upgrade_to_self_binary() {
    local_test_e(|runtime| async move {
        let mut universal_canister = set_up_universal_canister(&runtime).await;
        push_message_to_stable(&universal_canister).await;
        // We can read it back
        assert_eq!(
            try_to_read_message_from_stable(&universal_canister).await,
            Ok(MSG.to_vec())
        );
        // Upgrade to same binary
        universal_canister
            .upgrade_to_self_binary(Vec::new())
            .await
            .unwrap();
        // The message should still be there
        assert_eq!(
            try_to_read_message_from_stable(&universal_canister).await,
            Ok(MSG.to_vec())
        );
        // However, if we re-install, the stable memory should be wiped out
        universal_canister
            .reinstall_with_self_binary(Vec::new())
            .await
            .unwrap();
        assert_matches!(
            try_to_read_message_from_stable(&universal_canister).await,
            Err(err_msg) if err_msg.contains("stable memory out of bounds"));

        Ok(())
    })
}

#[test]
fn test_upgrade_to_different_binary() {
    local_test_e(|runtime| async move {
        let mut canister = set_up_universal_canister(&runtime).await;
        push_message_to_stable(&canister).await;
        // We can read it back
        assert_eq!(
            try_to_read_message_from_stable(&canister).await,
            Ok(MSG.to_vec())
        );
        // Upgrade to different binary
        Wasm::from_wat(STABLE_MEMORY_READER_WAT)
            .install(&runtime)
            .with_mode(CanisterInstallMode::Upgrade)
            .install(&mut canister, Vec::new())
            .await
            .unwrap();
        // Read
        assert_eq!(
            canister
                .query_("read_10_bytes_from_stable", bytes, Vec::new())
                .await
                .unwrap(),
            &MSG[..10],
        );

        Ok(())
    })
}
