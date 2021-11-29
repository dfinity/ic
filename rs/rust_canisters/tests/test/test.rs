use canister_test::*;
use dfn_core::bytes;
use dfn_json::json;
use std::time::{Duration, SystemTime};

#[test]
fn nan_canonicalized() {
    local_test_e(|r| async move {
        let proj = Project::new(env!("CARGO_MANIFEST_DIR"));

        let canister = proj
            .cargo_bin("nan_canonicalized")
            .install_(&r, Vec::new())
            .await?;

        let res: Result<(), String> = canister
            .query_("nans_are_canonicalized", dfn_json::json, ())
            .await?;
        assert_eq!(res, Ok(()));
        Ok(())
    })
}

#[test]
fn stable() {
    local_test_e(|r| async move {
        let proj = Project::new(env!("CARGO_MANIFEST_DIR"));

        let stable = proj.cargo_bin("stable").install_(&r, Vec::new()).await?;

        stable.query_("stable", bytes, Vec::new()).await?;
        Ok(())
    })
}

#[test]
fn what_time_is_it() {
    fn roughly_the_same(t1: SystemTime, t2: SystemTime) -> bool {
        let one_minute = Duration::from_secs(60);
        t1 + one_minute > t2 && t1 - one_minute < t2
    }
    local_test_e(|r| async move {
        let proj = Project::new(env!("CARGO_MANIFEST_DIR"));

        let stable = proj.cargo_bin("time").install_(&r, Vec::new()).await?;

        let native_time: SystemTime = SystemTime::now();
        let canister_time: SystemTime = stable.query_("what_time_is_it", json, ()).await?;
        assert!(roughly_the_same(native_time, canister_time));

        Ok(())
    })
}

#[test]
fn call_nonesistent_method_should_not_panic() {
    local_test_e(|r| async move {
        let proj = Project::new(env!("CARGO_MANIFEST_DIR"));

        let canister = proj
            .cargo_bin("inter_canister_error_handling")
            .install_(&r, Vec::new())
            .await?;

        assert_eq!(
            canister
                .update_("call_nonexistent_method", bytes, Vec::<u8>::new())
                .await
                .unwrap(),
            b"inter-canister call did not work"
        );

        Ok(())
    })
}
