/* tag::catalog[]
Title:: Specification compliance test

Goal:: Ensure that the replica implementation is compliant with the formal specification.

Runbook::
. Set up two subnets, each containing one node

Success:: The ic-ref-test binary does not return an error.

end::catalog[] */

use ic_fondue::{
    ic_instance::InternetComputer,
    ic_manager::{IcEndpoint, IcHandle},
};
use ic_registry_subnet_type::SubnetType;
use slog::info;
use std::process::{Command, Stdio};

use crate::util;

const EXCLUDED: &[&str] = &[
    // to start with something that is always false
    "(1 == 0)",
    "$0 ~ /non-existence proofs for non-existing request id/",
    "$0 ~ /module_hash of empty canister/",
    // the replica does not yet check that the effective canister id is valid
    "$0 ~ /wrong effective canister id/",
    "$0 ~ /access denied two status to different canisters/",
    // In the replica, contexts marked as “deleted” (due to `canister_uninstall` or
    // running out of cycles) currently still block the transition from stopping to
    // stopped.
    "$0 ~ /deleted call contexts do not prevent stopping/",
    "$0 ~ /metadata.absent/",
    "$0 ~ /zero-length metadata name/",
    // TODO(VER-1507): investigate why this test always fails
    "$0 ~ /legacy API traps when a result is too big/",
];

pub fn ic_with_system_subnet() -> InternetComputer {
    InternetComputer::new().add_fast_single_node_subnet(SubnetType::System)
}

pub fn test_system_subnet(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    let endpoint = util::get_random_root_node_endpoint(&handle, &mut ctx.rng.clone());
    util::block_on(endpoint.assert_ready(ctx));
    with_endpoint(endpoint, ctx, EXCLUDED.to_vec());
}

pub fn ic_with_app_subnet() -> InternetComputer {
    InternetComputer::new().add_fast_single_node_subnet(SubnetType::Application)
}

pub fn test_app_subnet(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    let endpoint = util::get_random_application_node_endpoint(&handle, &mut ctx.rng.clone());
    util::block_on(endpoint.assert_ready(ctx));
    with_endpoint(
        endpoint,
        ctx,
        [EXCLUDED.to_vec(), vec!["$0 ~ /Canister signatures/"]].concat(),
    );
}

pub fn with_endpoint(
    endpoint: &IcEndpoint,
    ctx: &ic_fondue::pot::Context,
    excluded_tests: Vec<&str>,
) {
    let status = Command::new("ic-ref-test")
        .arg("-j16")
        .arg("--pattern")
        .arg(tests_to_pattern(excluded_tests))
        .arg("--endpoint")
        .arg(endpoint.url.clone().into_string())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .expect("ic-ref-test binary crashed");
    info!(
        &ctx.logger,
        "{}",
        format!("Status of ic-ref-test: {:?}", &status)
    );
    assert!(status.success());
}

fn tests_to_pattern(tests: Vec<&str>) -> String {
    format!("!({})", tests.join(" || "))
}
