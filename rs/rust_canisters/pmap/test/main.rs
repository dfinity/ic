use canister_test::*;
use dfn_json::json;

#[test]
fn test() {
    local_test_e(|runtime| async move {
        ///////////////////////////////////////////////////////
        // Create a new instance of pmap
        ///////////////////////////////////////////////////////
        let proj = Project::new();

        let create_canister = |c| proj.cargo_bin(c, &[]).install(&runtime).bytes(Vec::new());

        let canister = create_canister("pmap_canister").await?;

        let res: Result<String, String> = canister.query_("test", json, ()).await?;
        assert!(res.is_ok());

        let res: Result<String, String> = canister.update_("create_array", json, ()).await?;
        assert!(res.is_ok());

        let res: Result<String, String> = canister.update_("increment_array", json, ()).await?;
        assert!(res.is_ok());

        let res: Result<String, String> = canister.update_("increment_array", json, ()).await?;
        assert!(res.is_ok());

        let res: Result<u32, String> = canister.update_("compute_sum", json, ()).await?;
        assert_eq!(res, Ok(20));

        let res: Result<String, String> = canister.query_("test", json, ()).await?;
        assert!(res.is_ok());
        Ok(())
    });
}

fn main() {}
