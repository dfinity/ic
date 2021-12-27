use canister_test::*;

#[test]
fn test_statesync_test_canisters() {
    local_test_e(|r| async move {
        let proj = Project::new(env!("CARGO_MANIFEST_DIR"));

        println!("Start installing statesync test canister");
        let canister = proj
            .cargo_bin("statesync-test-canister", &[])
            .install(&r)
            .with_memory_allocation(8 * 1024 * 1024 * 1024) // 8GiB
            .bytes(Vec::new())
            .await?;
        println!("Installed statesync test canister");

        let mut res: Result<u8, String> = canister
            .query_("read_state", dfn_json::json, 0_usize)
            .await
            .unwrap();
        assert_eq!(
            res,
            Ok(0),
            "Queried first element of state vector, should have been 0, was {:?}",
            res
        );

        res = canister
            .update_("change_state", dfn_json::json, 33_u32)
            .await
            .unwrap();
        assert_eq!(
            res,
            Ok(1),
            "Changed state for the first time, result should have been 1, was {:?}",
            res
        );

        res = canister
            .query_("read_state", dfn_json::json, 0_usize)
            .await
            .unwrap();
        assert_eq!(
            res,
            Ok(20),
            "Queried 0th element of state vector, should be 20 for seed 33, was {:?}",
            res
        );
        Ok(())
    })
}
