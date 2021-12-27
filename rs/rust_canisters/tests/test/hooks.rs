use assert_matches::assert_matches;
use canister_test::*;
use dfn_core::bytes;

#[test]
fn test_panic_hook_single_method() {
    local_test_e(|runtime| async move {
        let canister = Project::new(env!("CARGO_MANIFEST_DIR"))
            .cargo_bin("panics", &[])
            .install_(&runtime, Vec::new())
            .await
            .unwrap();
        let res: Result<Vec<u8>, String> =
            canister.update_("test_panic_hook", bytes, Vec::new()).await;
        assert_matches!(res, Err(msg) if msg.contains("This message should be passed as trap message thanks to the hook"));
        Ok(())
    })
}

#[test]
fn test_panic_hook_across_methods() {
    local_test_e(|runtime| async move {
        let canister = Project::new(env!("CARGO_MANIFEST_DIR"))
            .cargo_bin("panics", &[])
            .install_(&runtime, Vec::new())
            .await
            .unwrap();
        // Set the hook in a first update call
        let _: Vec<u8> = canister
            .update_("set_hooks", bytes, Vec::new())
            .await
            .unwrap();
        // And verify that it still works in a second update call
        let res: Result<Vec<u8>, String> = canister.update_("panic", bytes, Vec::new()).await;
        assert_matches!(res, Err(msg) if msg.contains("A panic message in a function that does not set the hook"));
        Ok(())
    })
}
