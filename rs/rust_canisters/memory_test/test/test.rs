use canister_test::*;

#[test]
fn test_memory_test_canisters() {
    local_test_e(|r| async move {
        let proj = Project::new(env!("CARGO_MANIFEST_DIR"));

        println!("Start installing memory test canister");
        let canister = proj
            .cargo_bin("memory-test-canister")
            .install(&r)
            .with_memory_allocation(8 * 1024 * 1024 * 1024) // 8GiB
            .bytes(Vec::new())
            .await?;
        println!("Installed memory test canister");
        canister
            .update_(
                "update_write",
                dfn_core::bytes,
                r#"{"size": 4096, "address": 1024, "value": 32}"#.as_bytes().to_vec(),
            )
            .await
            .unwrap();
        canister
            .query_(
                "query_read",
                dfn_core::bytes,
                r#"{"size": 4096, "address": 1024, "value": 32}"#.as_bytes().to_vec(),
            )
            .await
            .unwrap();
        Ok(())
    })
}
