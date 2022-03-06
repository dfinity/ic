/* tag::catalog[]
Title:: Upgrade the NNS canisters through proposals

Goal:: Demonstrate that root canister controls the upgrade process and ensures that voting etc is still possible in the new version (includes unhappy paths)?

Notes:: The integration test for this feature offers high confidence that it
will work in production. It’s harder to test this in production.

Runbook::
. start NNS
. obtain `root` canister's status via `lifeline` for later comparison
. tell `root` to upgrade `lifeline` with a functionally equivalent Wasm
. verify that `lifeline` works by getting status again
. check that relevant fields in status didn't change


end::catalog[] */

use slog::info;

use crate::util::{get_random_nns_node_endpoint, runtime_from_url};

use ic_fondue::{ic_manager::IcHandle, prod_tests::ic::InternetComputer};

use crate::nns::NnsExt;
use candid::Encode;
use canister_test::Canister;
use dfn_candid::candid_one;

use ic_nns_common::pb::v1::MethodAuthzInfo;
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, LIFELINE_CANISTER_ID, ROOT_CANISTER_ID};
use ic_nns_test_utils::governance::{
    append_inert, upgrade_nns_canister_by_proposal, upgrade_nns_canister_with_arg_by_proposal,
};
use ic_registry_subnet_type::SubnetType;
use ic_types::ic00::{CanisterIdRecord, CanisterStatusResult};

pub fn config() -> InternetComputer {
    InternetComputer::new().add_fast_single_node_subnet(SubnetType::System)
}

pub fn test(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    // Install NNS canisters
    ctx.install_nns_canisters(&handle, true);

    let mut rng = ctx.rng.clone();
    let endpoint = get_random_nns_node_endpoint(&handle, &mut rng);
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");

    rt.block_on(async move {
        endpoint.assert_ready(ctx).await;
        let nns = runtime_from_url(endpoint.url.clone());

        let lifeline = Canister::new(&nns, LIFELINE_CANISTER_ID);

        let root_status: CanisterStatusResult = lifeline
            .update_(
                "canister_status",
                candid_one,
                CanisterIdRecord::from(ROOT_CANISTER_ID),
            )
            .await
            .unwrap();
        info!(ctx.logger, "root_status {:?}", root_status);

        // due to NNS1-402 an empty list will do, it is ignored anyway
        let methods_authz: Vec<MethodAuthzInfo> = vec![];
        upgrade_nns_canister_with_arg_by_proposal(
            &lifeline,
            &Canister::new(&nns, GOVERNANCE_CANISTER_ID),
            &Canister::new(&nns, ROOT_CANISTER_ID),
            append_inert(Some(&canister_test::Wasm::from_bytes(
                lifeline::LIFELINE_CANISTER_WASM,
            ))),
            Encode!(&methods_authz).unwrap(),
        )
        .await;

        // due to NNS1-479 no init arg is needed any more
        upgrade_nns_canister_by_proposal(
            &lifeline,
            &Canister::new(&nns, GOVERNANCE_CANISTER_ID),
            &Canister::new(&nns, ROOT_CANISTER_ID),
            false,
            canister_test::Wasm::from_bytes(lifeline::LIFELINE_CANISTER_WASM),
        )
        .await;

        let root_status_after: CanisterStatusResult = lifeline
            .update_(
                "canister_status",
                candid_one,
                CanisterIdRecord::from(ROOT_CANISTER_ID),
            )
            .await
            .unwrap();

        // obviously there was a memory increase in `root` due to storing the Wasm
        assert!(root_status_after.memory_size() >= root_status.memory_size());

        // the other fields didn't change
        assert_eq!(root_status.module_hash(), root_status_after.module_hash());
        assert_eq!(root_status.controller(), root_status_after.controller());
        assert_eq!(root_status.cycles(), root_status_after.cycles());
    });
}
