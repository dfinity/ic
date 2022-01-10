/* tag::catalog[]
end::catalog[] */

use crate::{types::*, util::CYCLES_LIMIT_PER_CANISTER, util::*};
use candid::{Decode, Encode, Principal};
use ic_agent::AgentError;
use ic_base_types::RegistryVersion;
use ic_fondue::{
    ic_instance::{InternetComputer, Subnet},
    ic_manager::IcHandle,
};
use ic_ic00_types::SetupInitialDKGArgs;
use ic_nns_constants::CYCLES_MINTING_CANISTER_ID;
use ic_registry_subnet_type::SubnetType;
use ic_types::Cycles;
use ic_types_test_utils::ids::node_test_id;
use lazy_static::lazy_static;

const BALANCE_EPSILON: Cycles = Cycles::new(10_000_000);
const CANISTER_FREEZE_BALANCE_RESERVE: Cycles = Cycles::new(5_000_000_000_000);
lazy_static! {
    static ref INITIAL_CYCLES: Cycles =
        CANISTER_FREEZE_BALANCE_RESERVE + Cycles::new(5_000_000_000_000);
}

// Wasm for a canister that calls mint_cycles
// Replies `CanisterError` if canister is not on NNS subnet
const MINT_CYCLES: &str = r#"(module
                  (import "ic0" "msg_reply_data_append"
                            (func $msg_reply_data_append (param i32) (param i32)))
                  (import "ic0" "mint_cycles" (func $ic0_mint_cycles (param i64) (result i64)))
                  (import "ic0" "msg_reply" (func $ic0_msg_reply))


                  (func $test
                        (i64.store
                            (i32.const 0) ;; store at the beginning of the heap
                            (call $ic0_mint_cycles (i64.const 10000000000))
                        )
                        (call $msg_reply_data_append (i32.const 0) (i32.const 8))
                        (call $ic0_msg_reply)
                  )


                  (export "canister_update test" (func $test))
                  (memory $memory 1)
                  (export "memory" (memory $memory))
              )"#;

pub fn mint_cycles_not_supported_on_system_subnet(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");

    rt.block_on(async move {
        let wasm = wabt::wat2wasm(MINT_CYCLES).unwrap();
        let nns_endpoint = get_random_nns_node_endpoint(&handle, &mut rng);
        nns_endpoint.assert_ready(ctx).await;

        let nns_agent = assert_create_agent(nns_endpoint.url.as_str()).await;
        let nns_canister_id: Principal =
            create_and_install_with_cycles(&nns_agent, wasm.as_slice(), *INITIAL_CYCLES).await;

        let before_balance = get_balance(&nns_canister_id, &nns_agent).await;
        assert_balance_equals(
            *INITIAL_CYCLES,
            Cycles::from(before_balance),
            BALANCE_EPSILON,
        );

        let res = nns_agent
            .update(&nns_canister_id, "test")
            .call_and_wait(delay())
            .await
            .expect_err("should not succeed");

        assert_eq!(
            res,
            AgentError::ReplicaError { reject_code: 5, reject_message: format!("Canister {} violated contract: ic0.mint_cycles cannot be executed on non Cycles Minting Canister: {} != {}", nns_canister_id, nns_canister_id, CYCLES_MINTING_CANISTER_ID) }
        );

        let after_balance = get_balance(&nns_canister_id, &nns_agent).await;
        assert!(
            after_balance == before_balance,
            "expected {} == {}",
            after_balance,
            before_balance
        );
    });
}

pub fn mint_cycles_not_supported_on_application_subnet(
    handle: IcHandle,
    ctx: &ic_fondue::pot::Context,
) {
    let initial_cycles = CANISTER_FREEZE_BALANCE_RESERVE + Cycles::new(5_000_000_000_000);
    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");

    rt.block_on(async move {
        let wasm = wabt::wat2wasm(MINT_CYCLES).unwrap();
        let endpoint = get_random_application_node_endpoint(&handle, &mut rng);
        endpoint.assert_ready(ctx).await;

        let agent = assert_create_agent(endpoint.url.as_str()).await;
        let canister_id: Principal =
            create_and_install_with_cycles(&agent, wasm.as_slice(), initial_cycles * 3).await;

        let before_balance = get_balance(&canister_id, &agent).await;
        assert!(
            Cycles::from(before_balance) > initial_cycles * 2,
            "expected {} > {}",
            before_balance,
            initial_cycles * 2
        );
        assert!(
            Cycles::from(before_balance) <= initial_cycles * 3,
            "expected {} <= {}",
            before_balance,
            initial_cycles * 3
        );

        // The test function on the wasm module will call the mint_cycles system
        // call.
        let res = agent
            .update(&canister_id, "test")
            .call_and_wait(delay())
            .await;

        assert_reject(res, RejectCode::CanisterError);
        let after_balance = get_balance(&canister_id, &agent).await;
        assert!(
            after_balance < before_balance,
            "expected {} < expected {}",
            after_balance,
            before_balance
        );
    });
}

pub fn no_cycle_balance_limit_on_nns_subnet(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");

    rt.block_on(async move {
        let endpoint = get_random_nns_node_endpoint(&handle, &mut rng);
        endpoint.assert_ready(ctx).await;
        let agent = assert_create_agent(endpoint.url.as_str()).await;

        let canister_a =
            UniversalCanister::new_with_cycles(&agent, CYCLES_LIMIT_PER_CANISTER * 3).await;

        let balance = get_balance(&canister_a.canister_id(), &agent).await;
        assert!(
            Cycles::from(balance) == CYCLES_LIMIT_PER_CANISTER * 3,
            "expected {} == {}",
            balance,
            CYCLES_LIMIT_PER_CANISTER * 3
        );

        // Canister A creates canister B with `CYCLES_LIMIT_PER_CANISTER` cycles.
        let canister_b_id =
            create_canister_via_canister_with_cycles(&canister_a, CYCLES_LIMIT_PER_CANISTER)
                .await
                .unwrap();

        // Check canister_a's balance has decreased.
        let balance = get_balance(&canister_a.canister_id(), &agent).await;
        assert!(
            Cycles::from(balance) == CYCLES_LIMIT_PER_CANISTER * 2,
            "expected {} == {}",
            balance,
            CYCLES_LIMIT_PER_CANISTER * 2
        );

        // Deposit cycles from canister_a to canister_b to increase b's balance
        let cycles_to_deposit = CYCLES_LIMIT_PER_CANISTER;
        deposit_cycles(&canister_a, &canister_b_id, cycles_to_deposit).await;

        // Check canister_a's balance has not decreased as it's an NNS node.
        let balance = get_balance(&canister_a.canister_id(), &agent).await;
        assert!(
            Cycles::from(balance) == CYCLES_LIMIT_PER_CANISTER,
            "expected {} == {}",
            balance,
            CYCLES_LIMIT_PER_CANISTER
        );

        let balance = get_balance_via_canister(&canister_b_id, &canister_a).await;
        assert!(
            balance == CYCLES_LIMIT_PER_CANISTER * 2,
            "expected {} == {}",
            balance,
            CYCLES_LIMIT_PER_CANISTER * 2
        );
    });
}

pub fn config() -> InternetComputer {
    InternetComputer::new()
        .add_subnet(Subnet::fast_single_node(SubnetType::System).with_max_cycles_per_canister(None))
        .add_subnet(
            Subnet::fast_single_node(SubnetType::Application).with_max_cycles_per_canister(None),
        )
}

pub fn max_cycles_per_canister_system_subnet(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");

    rt.block_on(async move {
        let nns_endpoint = get_random_nns_node_endpoint(&handle, &mut rng);
        nns_endpoint.assert_ready(ctx).await;
        let nns_agent = assert_create_agent(nns_endpoint.url.as_str()).await;

        let canister_a =
            UniversalCanister::new_with_cycles(&nns_agent, CYCLES_LIMIT_PER_CANISTER * 3).await;

        let balance = get_balance(&canister_a.canister_id(), &nns_agent).await;
        assert_eq!(Cycles::from(balance), CYCLES_LIMIT_PER_CANISTER * 3);
    });
}

pub fn max_cycles_per_canister_application_subnet(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");

    rt.block_on(async move {
        let endpoint = get_random_application_node_endpoint(&handle, &mut rng);
        endpoint.assert_ready(ctx).await;
        let agent = assert_create_agent(endpoint.url.as_str()).await;

        let canister_a =
            UniversalCanister::new_with_cycles(&agent, CYCLES_LIMIT_PER_CANISTER).await;

        let canister_b =
            UniversalCanister::new_with_cycles(&agent, CYCLES_LIMIT_PER_CANISTER * 3).await;

        // Canister cannot have more cycles than max_cycles_per_canister.
        let balance = get_balance(&canister_b.canister_id(), &agent).await;
        assert!(
            Cycles::from(balance) <= CYCLES_LIMIT_PER_CANISTER,
            "expected {} <= {}",
            balance,
            CYCLES_LIMIT_PER_CANISTER
        );

        set_controller(&canister_b.canister_id(), &canister_a.canister_id(), &agent).await;

        let before_balance_a = get_balance(&canister_a.canister_id(), &agent).await;

        // Deposit cycles from canister_a to canister_b to increase b's balance
        let cycles_to_deposit = Cycles::new(1 << 40);
        deposit_cycles(&canister_a, &canister_b.canister_id(), cycles_to_deposit).await;

        // Check canister_a's balance has decreased after `deposit_cycles`
        // but not all cycles could fit into canister_b, thus canister_a's balance
        // has not decreased more than `cycles_to_deposit`.
        let after_balance_a = get_balance(&canister_a.canister_id(), &agent).await;
        let limit_balance = CYCLES_LIMIT_PER_CANISTER - cycles_to_deposit;
        assert!(
            after_balance_a < before_balance_a,
            "expected {} < {}",
            after_balance_a,
            before_balance_a,
        );
        assert!(
            Cycles::from(after_balance_a) > limit_balance,
            "expected {} > {}",
            after_balance_a,
            limit_balance.get()
        );

        // Canister cannot have more cycles than max_cycles_per_canister.
        let balance = get_balance_via_canister(&canister_b.canister_id(), &canister_a).await;
        assert!(
            balance <= CYCLES_LIMIT_PER_CANISTER,
            "expected {} <= {}",
            balance,
            CYCLES_LIMIT_PER_CANISTER
        );
    });
}

pub fn max_cycles_per_canister_is_none_application_subnet(
    handle: IcHandle,
    ctx: &ic_fondue::pot::Context,
) {
    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");

    rt.block_on(async move {
        let endpoint = get_random_application_node_endpoint(&handle, &mut rng);
        endpoint.assert_ready(ctx).await;
        let agent = assert_create_agent(endpoint.url.as_str()).await;

        let canister_a =
            UniversalCanister::new_with_cycles(&agent, CYCLES_LIMIT_PER_CANISTER * 3).await;

        let balance = get_balance(&canister_a.canister_id(), &agent).await;
        assert!(
            Cycles::from(balance) > CYCLES_LIMIT_PER_CANISTER * 2,
            "expected {} > {}",
            balance,
            CYCLES_LIMIT_PER_CANISTER * 2
        );
        assert!(
            Cycles::from(balance) <= CYCLES_LIMIT_PER_CANISTER * 3,
            "expected {} <= {}",
            balance,
            CYCLES_LIMIT_PER_CANISTER * 3
        );

        // Canister A creates canister B with `CYCLES_LIMIT_PER_CANISTER` cycles.
        let canister_b_id =
            create_canister_via_canister_with_cycles(&canister_a, CYCLES_LIMIT_PER_CANISTER)
                .await
                .unwrap();

        // Check canister_a's balance has decreased.
        let balance = get_balance(&canister_a.canister_id(), &agent).await;
        assert!(
            Cycles::from(balance) > CYCLES_LIMIT_PER_CANISTER,
            "expected {} > {}",
            balance,
            CYCLES_LIMIT_PER_CANISTER
        );
        assert!(
            Cycles::from(balance) <= CYCLES_LIMIT_PER_CANISTER * 2,
            "expected {} <= {}",
            balance,
            CYCLES_LIMIT_PER_CANISTER * 2
        );

        // Deposit cycles from canister_a to canister_b to increase b's balance
        let cycles_to_deposit = CYCLES_LIMIT_PER_CANISTER;
        deposit_cycles(&canister_a, &canister_b_id, cycles_to_deposit).await;

        // Check canister_a's balance has decreased after `deposit_cycles`.
        let balance = get_balance(&canister_a.canister_id(), &agent).await;
        assert!(
            Cycles::from(balance) < CYCLES_LIMIT_PER_CANISTER,
            "expected {} < {}",
            balance,
            CYCLES_LIMIT_PER_CANISTER
        );

        let balance = get_balance_via_canister(&canister_b_id, &canister_a).await;
        assert!(
            balance > CYCLES_LIMIT_PER_CANISTER,
            "expected {} > {}",
            balance,
            CYCLES_LIMIT_PER_CANISTER
        );
        assert!(
            balance < CYCLES_LIMIT_PER_CANISTER * 2,
            "expected {} < {}",
            balance,
            CYCLES_LIMIT_PER_CANISTER * 2
        );
    });
}

/// Tests whether creating a canister on a subnet other than self fails when not
/// on the NNS subnet.
pub fn non_nns_canister_attempt_to_create_canister_on_another_subnet_fails(
    handle: IcHandle,
    ctx: &ic_fondue::pot::Context,
) {
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    let mut rng = ctx.rng.clone();
    rt.block_on(async move {
        // Check that canisters on verified app subnets cannot create canisters on other
        // subnets.
        let verified_app_endpoint = get_random_verified_app_node_endpoint(&handle, &mut rng);
        verified_app_endpoint.assert_ready(ctx).await;
        let agent = assert_create_agent(verified_app_endpoint.url.as_str()).await;

        let uni_can = UniversalCanister::new_with_cycles(&agent, 900_000_000_000_000_u64).await;
        let other_subnet = get_random_application_node_endpoint(&handle, &mut rng)
            .subnet_id()
            .unwrap();
        let res = uni_can
            .forward_with_cycles_to(
                &other_subnet.get().into(),
                "create_canister",
                Encode!().unwrap(),
                100_000_000_000_000,
            )
            .await
            .map(|res| {
                Decode!(res.as_slice(), CreateCanisterResult)
                    .unwrap()
                    .canister_id
            });
        assert_reject(res, RejectCode::CanisterReject);

        let other_subnet = get_random_system_node_endpoint(&handle, &mut rng)
            .subnet_id()
            .unwrap();
        let res = uni_can
            .forward_with_cycles_to(
                &other_subnet.get().into(),
                "create_canister",
                Encode!().unwrap(),
                100_000_000_000_000,
            )
            .await
            .map(|res| {
                Decode!(res.as_slice(), CreateCanisterResult)
                    .unwrap()
                    .canister_id
            });
        assert_reject(res, RejectCode::CanisterReject);

        // Check that canisters on app subnets cannot create canisters on other subnets.
        let app_endpoint = get_random_application_node_endpoint(&handle, &mut rng);
        app_endpoint.assert_ready(ctx).await;
        let agent = assert_create_agent(app_endpoint.url.as_str()).await;

        let uni_can = UniversalCanister::new_with_cycles(&agent, 900_000_000_000_000_u64).await;
        let other_subnet = get_random_verified_app_node_endpoint(&handle, &mut rng)
            .subnet_id()
            .unwrap();
        let res = uni_can
            .forward_with_cycles_to(
                &other_subnet.get().into(),
                "create_canister",
                Encode!().unwrap(),
                0,
            )
            .await
            .map(|res| {
                Decode!(res.as_slice(), CreateCanisterResult)
                    .unwrap()
                    .canister_id
            });
        assert_reject(res, RejectCode::CanisterReject);

        let other_subnet = get_random_system_node_endpoint(&handle, &mut rng)
            .subnet_id()
            .unwrap();
        let res = uni_can
            .forward_with_cycles_to(
                &other_subnet.get().into(),
                "create_canister",
                Encode!().unwrap(),
                0,
            )
            .await
            .map(|res| {
                Decode!(res.as_slice(), CreateCanisterResult)
                    .unwrap()
                    .canister_id
            });
        assert_reject(res, RejectCode::CanisterReject);

        // Check that canisters on system subnets excluding NNS cannot create canisters
        // on other subnets.
        let app_endpoint = get_random_system_but_not_nns_node_endpoint(&handle, &mut rng);
        app_endpoint.assert_ready(ctx).await;
        let agent = assert_create_agent(app_endpoint.url.as_str()).await;

        let uni_can = UniversalCanister::new_with_cycles(&agent, 900_000_000_000_000_u64).await;
        let other_subnet = get_random_verified_app_node_endpoint(&handle, &mut rng)
            .subnet_id()
            .unwrap();
        let res = uni_can
            .forward_with_cycles_to(
                &other_subnet.get().into(),
                "create_canister",
                Encode!().unwrap(),
                50_000_000_000_000,
            )
            .await
            .map(|res| {
                Decode!(res.as_slice(), CreateCanisterResult)
                    .unwrap()
                    .canister_id
            });
        assert_reject(res, RejectCode::CanisterReject);

        let other_subnet = get_random_application_node_endpoint(&handle, &mut rng)
            .subnet_id()
            .unwrap();
        let res = uni_can
            .forward_with_cycles_to(
                &other_subnet.get().into(),
                "create_canister",
                Encode!().unwrap(),
                50_000_000_000_000,
            )
            .await
            .map(|res| {
                Decode!(res.as_slice(), CreateCanisterResult)
                    .unwrap()
                    .canister_id
            });
        assert_reject(res, RejectCode::CanisterReject);
    });
}

/// Tests whether creating a canister on another subnet is possible from an NNS
/// canister.
pub fn nns_canister_attempt_to_create_canister_on_another_subnet_succeeds(
    handle: IcHandle,
    ctx: &ic_fondue::pot::Context,
) {
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    let mut rng = ctx.rng.clone();
    rt.block_on(async move {
        let nns_endpoint = get_random_nns_node_endpoint(&handle, &mut rng);
        nns_endpoint.assert_ready(ctx).await;
        let agent = assert_create_agent(nns_endpoint.url.as_str()).await;

        let uni_can = UniversalCanister::new_with_cycles(&agent, 900_000_000_000_000_u64).await;
        let other_subnet = get_random_non_nns_node_endpoint(&handle, &mut rng)
            .subnet_id()
            .unwrap();
        uni_can
            .forward_with_cycles_to(
                &other_subnet.get().into(),
                "create_canister",
                Encode!().unwrap(),
                100_000_000_000_000,
            )
            .await
            .map(|res| {
                Decode!(res.as_slice(), CreateCanisterResult)
                    .unwrap()
                    .canister_id
            })
            .unwrap();
    });
}

/// Tests whether a call to `setup_initial_dkg` is rejected when called from a
/// canister installed on an application subnet.
pub fn app_canister_attempt_initiating_dkg_fails(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    let mut rng = ctx.rng.clone();

    rt.block_on(async move {
        let endpoint = get_random_application_node_endpoint(&handle, &mut rng);
        endpoint.assert_ready(ctx).await;
        let agent = assert_create_agent(endpoint.url.as_str()).await;

        let node_ids: Vec<_> = (0..4).map(node_test_id).collect();
        let request = SetupInitialDKGArgs::new(node_ids, RegistryVersion::from(2));

        let uni_can = UniversalCanister::new(&agent).await;
        let res = uni_can
            .forward_to(
                &Principal::management_canister(),
                "setup_initial_dkg",
                Encode!(&request).unwrap(),
            )
            .await;

        assert_reject(res, RejectCode::CanisterReject);
    });
}
