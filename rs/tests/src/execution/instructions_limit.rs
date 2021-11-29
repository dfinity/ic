/* tag::catalog[]
end::catalog[] */

use crate::{types::RejectCode, util::*};
use ic_fondue::ic_manager::IcHandle;
use ic_universal_canister::{wasm, UNIVERSAL_CANISTER_WASM};
use ic_utils::interfaces::{management_canister::builders::InstallMode, ManagementCanister};

const FIVE_HUNDRED_MB: u32 = 500 * 1024 * 1024;

pub fn can_use_more_instructions_during_install_code(handle: IcHandle, ctx: &fondue::pot::Context) {
    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on({
        async move {
            let endpoint = get_random_verified_app_node_endpoint(&handle, &mut rng);
            endpoint.assert_ready(ctx).await;
            let agent = assert_create_agent(endpoint.url.as_str()).await;

            let canister = UniversalCanister::new(&agent).await;

            canister
                // Grow stable memory to 1GB.
                .update(wasm().stable_grow(16_384).reply())
                .await
                .unwrap();

            // The update call should hit the instruction limit and fail.
            let res = canister
                .update(wasm().stable_fill(0, 42, FIVE_HUNDRED_MB).reply())
                .await;
            assert_reject(res, RejectCode::CanisterError);

            canister
                .update(
                    wasm()
                        .set_pre_upgrade(wasm().stable_fill(0, 1, FIVE_HUNDRED_MB))
                        .reply(),
                )
                .await
                .unwrap();

            // An upgrade of the canister succeeds because `install_code` has a
            // higher instruction limit.
            let mgr = ManagementCanister::create(&agent);
            mgr.install_code(&canister.canister_id(), UNIVERSAL_CANISTER_WASM)
                .with_mode(InstallMode::Upgrade)
                .with_raw_arg(vec![])
                .call_and_wait(delay())
                .await
                .unwrap();
        }
    })
}
