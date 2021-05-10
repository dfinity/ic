use canister_test::*;
use dfn_core::bytes;

#[test]
fn reverse_test() {
    local_test_e(|r| async move {
        let proj = Project::new(env!("CARGO_MANIFEST_DIR"));

        let canister = proj.cargo_bin("wasm").install_(&r, Vec::new()).await?;

        let res = canister.query_("reverse", bytes, vec![0, 1, 2, 3]).await?;

        assert_eq!(res, vec![3, 2, 1, 0]);
        Ok(())
    })
}

#[test]
fn certification_api_test() {
    local_test_e(|r| async move {
        let proj = Project::new(env!("CARGO_MANIFEST_DIR"));

        let canister = proj.cargo_bin("wasm").install_(&r, Vec::new()).await?;

        let _ = canister
            .update_("set_certified_data", bytes, vec![0u8; 32])
            .await?;

        let _ = canister.query_("get_certificate", bytes, vec![]).await?;

        Ok(())
    })
}
