/* tag::catalog[]
Title:: Replica Determinism Test

Goal:: Ensure that a node restarts and catches up after realizing a divergence of state. It can contribute to consensus after restarting.

Runbook::
. Set up one subnet
. Make a node diverge
. Wait until we see the newly started node's PID finalizing a block.

Success:: The restarted node reports block finalizations.


end::catalog[] */

use crate::util::*;
use ic_fondue::{
    ic_instance::{LegacyInternetComputer as InternetComputer, Subnet},
    ic_manager::IcHandle,
};
use ic_registry_subnet_type::SubnetType;
use ic_types::{malicious_behaviour::MaliciousBehaviour, Height};
use ic_universal_canister::wasm;

const DKG_INTERVAL: u64 = 9;
const FAULT_HEIGHT: u64 = DKG_INTERVAL + 1;

pub fn config() -> InternetComputer {
    let malicious_behaviour =
        MaliciousBehaviour::new(true).set_maliciously_corrupt_own_state_at_heights(FAULT_HEIGHT);

    InternetComputer::new().add_subnet(
        Subnet::new(SubnetType::System)
            .with_dkg_interval_length(Height::from(DKG_INTERVAL))
            .add_nodes(3)
            .add_malicious_nodes(1, malicious_behaviour),
    )
}

/// As the malicious behavior `CorruptOwnStateAtHeights` is enabled, this test
/// waits for the state to diverge and makes sure that the faulty replica is
/// restarted and that it can contribute to consensus afterwards.
pub fn test(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    let mut rng = ctx.rng.clone();
    let malicious_endpoint = handle
        .as_permutation_malicious(&mut rng)
        .next()
        .expect("could not get a malicious node");

    let rt = tokio::runtime::Runtime::new().expect("could not create tokio runtime");
    rt.block_on({
        async move {
            malicious_endpoint.assert_ready(ctx).await;
            let agent = assert_create_agent(malicious_endpoint.url.as_str()).await;
            let canister = UniversalCanister::new(&agent).await;

            // After N update&query requests the height of a subnet is >= N.
            // Thus, if N = FAULT_HEIGHT, it's guaranteed that divergence happens along the
            // way.
            for n in 0..FAULT_HEIGHT {
                let mut result = agent
                    .update(&canister.canister_id(), "update")
                    .with_arg(wasm().set_global_data(&[n as u8]).reply())
                    .call_and_wait(delay())
                    .await;
                // Error is expected after the malicious node panics due to divergence.
                if result.is_err() {
                    break;
                }
                result = canister
                    .query(wasm().get_global_data().append_and_reply())
                    .await;
                if result.is_err() {
                    break;
                }
                assert_eq!(result, Ok(vec![n as u8]));
            }

            // Wait until the malicious node restarts.
            malicious_endpoint.assert_ready(ctx).await;

            // For the same reason as before, if N = DKG_INTERVAL + 1, it's guaranteed
            // that a catch up package is proposed by the faulty node.
            for n in 0..(DKG_INTERVAL + 1) {
                agent
                    .update(&canister.canister_id(), "update")
                    .with_arg(wasm().set_global_data(&[n as u8]).reply())
                    .call_and_wait(delay())
                    .await
                    .expect("failed to update");
                let response = canister
                    .query(wasm().get_global_data().append_and_reply())
                    .await
                    .expect("failed to query");
                assert_eq!(response, vec![n as u8]);
            }
        }
    });
}
