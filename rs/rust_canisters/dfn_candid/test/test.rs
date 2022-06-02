use canister_test::*;
use dfn_candid::candid;

#[test]
fn candid_test() {
    local_test_e(|runtime| async move {
        let mut canister = runtime
            .create_canister_max_cycles_with_retries()
            .await
            .unwrap();

        let wasm = Project::cargo_bin_maybe_use_path_relative_to_rs(
            "rust_canisters/dfn_candid",
            "candid-test-canister",
            &[],
        );

        let install = wasm
            .install(&runtime)
            .with_mode(CanisterInstallMode::Install);
        install.install(&mut canister, Vec::new()).await.unwrap();

        let inp: (&str, u16) = ("David", 28);
        let res: String = canister.query_("greeting", candid, inp).await?;

        assert_eq!("Hello David, you are 28 years old", &res);

        let inp: (u16, u16, u16, u16) = (1, 2, 3, 4);
        let res: (u16, u16) = canister.query_("sum", candid, inp).await?;

        assert_eq!((3, 7), res);
        Ok(())
    });
}
