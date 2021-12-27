use canister_test::*;
use dfn_candid::candid;
use on_wire::BytesS;

#[ignore]
#[test]
fn candid_test() {
    local_test_e(|r| async move {
        let proj = Project::new(env!("CARGO_MANIFEST_DIR"));

        let canister = proj
            .cargo_bin("wasm", &[])
            .install_(&r, BytesS(Vec::new()))
            .await?;

        let inp: (&str, u16) = ("David", 28);
        let res: String = canister.query_("greeting", candid, inp).await?;

        assert_eq!("Hello David, you are 28 years old", &res);

        let inp: (u16, u16, u16, u16) = (1, 2, 3, 4);
        let res: (u16, u16) = canister.query_("sum", candid, inp).await?;

        assert_eq!((3, 7), res);
        Ok(())
    });
}
