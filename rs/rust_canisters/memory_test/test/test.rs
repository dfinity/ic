use canister_test::*;

#[test]
fn test_memory_test_canisters() {
    local_test_e(|r| async move {
        let proj = Project::new(env!("CARGO_MANIFEST_DIR"));

        println!("Start installing memory test canister");
        let canister = proj
            .cargo_bin("memory-test-canister", &[])
            .install(&r)
            .with_memory_allocation(8 * 1024 * 1024 * 1024) // 8GiB
            .bytes(Vec::new())
            .await?;
        println!("Installed memory test canister");

        // Test reads after writes
        {
            let payload = r#"{"address": 0, "size": 4096, "value": 1}"#.as_bytes().to_vec();
            canister
                .update_("update_write", dfn_core::bytes, payload.clone())
                .await
                .unwrap();
            let res = canister
                .query_("query_read", dfn_core::bytes, payload)
                .await
                .unwrap();
            // By default we write and read every 8 bytes
            assert_eq!(String::from_utf8(res).unwrap(), (4096 / 8).to_string());
        }

        // Test reads after writes with step
        {
            let payload = r#"{"address": 0, "size": 1000000000, "value": 2, "step": 1000}"#
                .as_bytes()
                .to_vec();
            canister
                .update_("update_write", dfn_core::bytes, payload.clone())
                .await
                .unwrap();
            let res = canister
                .query_("query_read", dfn_core::bytes, payload)
                .await
                .unwrap();
            assert_eq!(
                String::from_utf8(res).unwrap(),
                (1_000_000_000 / 1_000 * 2).to_string()
            );
        }

        // Test read_write()
        {
            let payload = r#"{"address": 0, "size": 1000000000, "value": 3, "step": 1000}"#
                .as_bytes()
                .to_vec();
            canister
                .update_("update_read_write", dfn_core::bytes, payload.clone())
                .await
                .unwrap();
            let res = canister
                .update_("update_read_write", dfn_core::bytes, payload)
                .await
                .unwrap();
            assert_eq!(
                String::from_utf8(res).unwrap(),
                (1_000_000_000 / 1_000 * 3).to_string()
            );
            let payload = r#"{"address": 0, "size": 2000, "value": 3, "step": 1000}"#
                .as_bytes()
                .to_vec();
            let res = canister
                .query_("query_read", dfn_core::bytes, payload)
                .await
                .unwrap();
            assert_eq!(String::from_utf8(res).unwrap(), (2 * 3).to_string());
        }

        // Test stable read after stable write
        {
            let payload = r#"{"address": 0, "size": 5000000000, "value": 10, "step": 5000}"#
                .as_bytes()
                .to_vec();
            canister
                .update_("update_stable_write", dfn_core::bytes, payload.clone())
                .await
                .unwrap();
            let res = canister
                .query_("query_stable_read", dfn_core::bytes, payload)
                .await
                .unwrap();
            assert_eq!(
                String::from_utf8(res).unwrap(),
                (5_000_000_000_u64 / 5_000 * 10).to_string()
            );
        }

        // Test stable_read_write()
        {
            let payload = r#"{"address": 0, "size": 5000000000, "value": 11, "step": 5000}"#
                .as_bytes()
                .to_vec();
            canister
                .update_("update_stable_read_write", dfn_core::bytes, payload.clone())
                .await
                .unwrap();
            let res = canister
                .update_("update_stable_read_write", dfn_core::bytes, payload)
                .await
                .unwrap();
            assert_eq!(
                String::from_utf8(res).unwrap(),
                (5_000_000_000_u64 / 5_000 * 11).to_string()
            );
            let payload = r#"{"address": 0, "size": 10000, "value": 11, "step": 5000}"#
                .as_bytes()
                .to_vec();
            let res = canister
                .query_("query_stable_read", dfn_core::bytes, payload)
                .await
                .unwrap();
            assert_eq!(String::from_utf8(res).unwrap(), (2 * 11).to_string());
        }

        Ok(())
    })
}
