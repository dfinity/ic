use canister_test::*;
use dfn_core::bytes;
use std::convert::TryInto;

#[test]
fn reverse_test() {
    local_test_e(|r| async move {
        let proj = Project::new(std::env::var("CARGO_MANIFEST_DIR").unwrap());

        let canister = proj.cargo_bin("wasm", &[]).install_(&r, Vec::new()).await?;

        let res = canister.query_("reverse", bytes, vec![0, 1, 2, 3]).await?;

        assert_eq!(res, vec![3, 2, 1, 0]);
        Ok(())
    })
}

#[test]
fn balance128_test() {
    local_test_e(|r| async move {
        let proj = Project::new(std::env::var("CARGO_MANIFEST_DIR").unwrap());

        let canister = proj.cargo_bin("wasm", &[]).install_(&r, Vec::new()).await?;

        let res = canister.query_("balance128", bytes, vec![]).await?;

        let balance = u64::MAX;
        assert_eq!(
            u128::from_le_bytes(res.try_into().unwrap()),
            balance as u128
        );
        Ok(())
    })
}

#[test]
fn certification_api_test() {
    local_test_e(|r| async move {
        let proj = Project::new(std::env::var("CARGO_MANIFEST_DIR").unwrap());

        let canister = proj.cargo_bin("wasm", &[]).install_(&r, Vec::new()).await?;

        let _ = canister
            .update_("set_certified_data", bytes, vec![0u8; 32])
            .await?;

        let _ = canister.query_("get_certificate", bytes, vec![]).await?;

        Ok(())
    })
}

#[test]
fn stable_memory_read_write() {
    local_test_e(|r| async move {
        let proj = Project::new(std::env::var("CARGO_MANIFEST_DIR").unwrap());

        let canister = proj.cargo_bin("wasm", &[]).install_(&r, Vec::new()).await?;

        let contents_1 = vec![0xdeu8; 100];

        let _ = canister
            .update_("write_stable_memory_fn", bytes, contents_1.clone())
            .await?;

        let buf = canister
            .update_("read_stable_memory_reader", bytes, vec![])
            .await?;

        assert_eq!(buf, contents_1);

        let contents_2 = vec![0xadu8; 98];

        let _ = canister
            .update_("write_stable_memory_writer", bytes, contents_2.clone())
            .await?;

        let buf = canister
            .update_("read_stable_memory_fn", bytes, vec![])
            .await?;

        assert_eq!(buf, contents_2);

        Ok(())
    })
}
