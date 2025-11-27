use anyhow::Result;
use candid::Decode;
use futures::future::join_all;
use ic_agent::{AgentError, agent::RejectCode, export::Principal};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{GetFirstHealthyNodeSnapshot, HasPublicApiUrl};
use ic_system_test_driver::systest;
use ic_system_test_driver::types::CreateCanisterResult;
use ic_system_test_driver::util::{UniversalCanister, assert_reject, block_on};
use ic_types::Cycles;
use ic_universal_canister::{CallInterface, UNIVERSAL_CANISTER_WASM, call_args, management, wasm};
use ic_utils::call::AsyncCall;
use ic_utils::interfaces::ManagementCanister;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(total_compute_allocation_cannot_be_exceeded))
        .execute_from_args()?;

    Ok(())
}

pub fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::fast_single_node(SubnetType::System))
        .add_subnet(Subnet::fast_single_node(SubnetType::Application))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

/// This tests expects to be run on a clean slate, i.e. requires it's own Pot
/// with one subnet of type Application.
/// Tests whether the compute allocation limits are enforced on an app subnet
/// both when creating canisters via the provisional API and via another
/// canister (which acts as the wallet canister).
pub fn total_compute_allocation_cannot_be_exceeded(env: TestEnv) {
    let logger = env.logger();
    let app_node = env.get_first_healthy_application_node_snapshot();
    let agent = app_node.build_default_agent();
    // See the corresponding field in the execution environment config.
    let allocatable_compute_capacity_in_percent = 50;
    // Note: the DTS scheduler requires at least 2 scheduler cores
    assert!(ic_config::subnet_config::SchedulerConfig::application_subnet().scheduler_cores >= 2);
    let app_sched_cores =
        (ic_config::subnet_config::SchedulerConfig::application_subnet().scheduler_cores - 1)
            * allocatable_compute_capacity_in_percent
            / 100;
    const MAX_COMP_ALLOC: Option<u64> = Some(99);
    block_on(async move {
        let mut canister_principals = Vec::new();
        let cans = join_all((0..app_sched_cores).map(|_| {
            UniversalCanister::new_with_params_with_retries(
                &agent,
                app_node.effective_canister_id(),
                MAX_COMP_ALLOC,
                Some(u64::MAX as u128),
                None,
                &logger,
            )
        }))
        .await;
        for can in cans {
            canister_principals.push(can.canister_id());
        }

        // Installing the app_sched_cores + 1st canister should fail.
        let can = UniversalCanister::new_with_params(
            &agent,
            app_node.effective_canister_id(),
            MAX_COMP_ALLOC,
            Some(u64::MAX as u128),
            None,
        )
        .await;
        assert!(can.is_err());

        let mgr = ManagementCanister::create(&agent);
        // Stop and delete all canisters.

        let res = join_all(
            canister_principals
                .iter()
                .map(|c_id| mgr.stop_canister(c_id).call_and_wait()),
        )
        .await;
        res.into_iter()
            .for_each(|x| x.expect("Could not stop canister."));

        let res = join_all(
            canister_principals
                .iter()
                .map(|c_id| mgr.delete_canister(c_id).call_and_wait()),
        )
        .await;
        res.into_iter()
            .for_each(|x| x.expect("Could not delete canister."));

        // Create universal canister with 'best effort' compute allocation of `0`.
        let uni_can = UniversalCanister::new_with_params_with_retries(
            &agent,
            app_node.effective_canister_id(),
            Some(0),
            Some(u64::MAX as u128),
            None,
            &logger,
        )
        .await;
        let arbitrary_bytes = b";ioapusdvzn,x";

        async fn install_canister(
            universal_canister: &UniversalCanister<'_>,
            reply_data: &[u8],
        ) -> Result<(Principal, Vec<u8>), AgentError> {
            let created_canister = universal_canister
                .update(wasm().call(management::create_canister(Cycles::from(
                    10_000_000_000_000_000u128,
                ))))
                .await
                .map(|res| {
                    Decode!(res.as_slice(), CreateCanisterResult)
                        .unwrap()
                        .canister_id
                })
                .expect("Could not create canister.");

            universal_canister
                .update(
                    wasm().call(
                        management::update_settings(created_canister)
                            .with_compute_allocation(MAX_COMP_ALLOC.unwrap()),
                    ),
                )
                .await?;

            let res = universal_canister
                .update(wasm().call(
                    management::install_code(created_canister, &*UNIVERSAL_CANISTER_WASM).on_reply(
                        wasm().inter_update(
                            created_canister,
                            call_args().other_side(wasm().reply_data(reply_data)),
                        ),
                    ),
                ))
                .await;
            res.map(|r| (created_canister, r))
        }

        let results =
            join_all((0..app_sched_cores).map(|_| install_canister(&uni_can, arbitrary_bytes)))
                .await;
        for r in results {
            assert_eq!(r.unwrap().1, arbitrary_bytes);
        }

        let res = install_canister(&uni_can, arbitrary_bytes).await;
        assert_reject(res, RejectCode::CanisterReject);
    })
}
