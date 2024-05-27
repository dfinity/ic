/* tag::catalog[]
end::catalog[] */

use crate::driver::ic::{InternetComputer, Subnet};
use crate::driver::test_env::TestEnv;
use crate::driver::test_env_api::{GetFirstHealthyNodeSnapshot, HasPublicApiUrl};
use crate::{types::*, util::CYCLES_LIMIT_PER_CANISTER, util::*};
use candid::{Decode, Encode, Principal};
use ic_agent::{
    agent::{RejectCode, RejectResponse},
    AgentError,
};
use ic_base_types::RegistryVersion;
use ic_management_canister_types::SetupInitialDKGArgs;
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

pub fn mint_cycles_supported_only_on_cycles_minting_canister(env: TestEnv) {
    let nns_node = env.get_first_healthy_nns_node_snapshot();
    let specified_id = nns_node.get_last_canister_id_in_allocation_ranges();
    // Check that 'specified_id' is not 'CYCLES_MINTING_CANISTER_ID'.
    assert_ne!(specified_id, CYCLES_MINTING_CANISTER_ID.into());
    let nns_agent = nns_node.build_default_agent();
    block_on(async move {
        let wasm = wat::parse_str(MINT_CYCLES).unwrap();
        let nns_canister_id: Principal = create_and_install_with_cycles_and_specified_id(
            &nns_agent,
            specified_id,
            wasm.as_slice(),
            *INITIAL_CYCLES,
        )
        .await;

        let before_balance = get_balance(&nns_canister_id, &nns_agent).await;
        assert_balance_equals(
            *INITIAL_CYCLES,
            Cycles::from(before_balance),
            BALANCE_EPSILON,
        );

        let res = nns_agent
            .update(&nns_canister_id, "test")
            .call_and_wait()
            .await
            .expect_err("should not succeed");

        assert_eq!(
            res,
            AgentError::CertifiedReject(
                RejectResponse {
                    reject_code: RejectCode::CanisterError,
                    reject_message: format!(
                        "Error from Canister {}: Canister violated contract: ic0.mint_cycles cannot be executed on non Cycles Minting Canister: {} != {}.\nThis is likely an error with the compiler/CDK toolchain being used to build the canister. Please report the error to IC devs on the forum: https://forum.dfinity.org and include which language/CDK was used to create the canister.",
                        nns_canister_id, nns_canister_id,
                        CYCLES_MINTING_CANISTER_ID),
                    error_code: None})
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

pub fn mint_cycles_not_supported_on_application_subnet(env: TestEnv) {
    let initial_cycles = CANISTER_FREEZE_BALANCE_RESERVE + Cycles::new(5_000_000_000_000);
    let app_node = env.get_first_healthy_application_node_snapshot();
    let agent = app_node.build_default_agent();
    block_on(async move {
        let wasm = wat::parse_str(MINT_CYCLES).unwrap();
        let canister_id: Principal = create_and_install_with_cycles(
            &agent,
            app_node.effective_canister_id(),
            wasm.as_slice(),
            initial_cycles * 3u64,
        )
        .await;

        let before_balance = get_balance(&canister_id, &agent).await;
        assert!(
            Cycles::from(before_balance) > initial_cycles * 2u64,
            "expected {} > {}",
            before_balance,
            initial_cycles * 2u64
        );
        assert!(
            Cycles::from(before_balance) <= initial_cycles * 3u64,
            "expected {} <= {}",
            before_balance,
            initial_cycles * 3u64
        );

        // The test function on the wasm module will call the mint_cycles system
        // call.
        let res = agent.update(&canister_id, "test").call_and_wait().await;

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

pub fn no_cycle_balance_limit_on_nns_subnet(env: TestEnv) {
    let logger = env.logger();
    let nns_node = env.get_first_healthy_nns_node_snapshot();
    let agent = nns_node.build_default_agent();
    block_on(async move {
        let canister_a = UniversalCanister::new_with_cycles_with_retries(
            &agent,
            nns_node.effective_canister_id(),
            CYCLES_LIMIT_PER_CANISTER * 3u64,
            &logger,
        )
        .await;

        let balance = get_balance(&canister_a.canister_id(), &agent).await;
        assert_eq!(
            Cycles::from(balance),
            CYCLES_LIMIT_PER_CANISTER * 3u64,
            "expected {} == {}",
            balance,
            CYCLES_LIMIT_PER_CANISTER * 3u64
        );

        // Canister A creates canister B with `CYCLES_LIMIT_PER_CANISTER` cycles.
        let canister_b_id =
            create_canister_via_canister_with_cycles(&canister_a, CYCLES_LIMIT_PER_CANISTER)
                .await
                .unwrap();

        // Check canister_a's balance has decreased.
        let balance = get_balance(&canister_a.canister_id(), &agent).await;
        assert_eq!(
            Cycles::from(balance),
            CYCLES_LIMIT_PER_CANISTER * 2u64,
            "expected {} == {}",
            balance,
            CYCLES_LIMIT_PER_CANISTER * 2u64
        );

        // Deposit cycles from canister_a to canister_b to increase b's balance
        let cycles_to_deposit = CYCLES_LIMIT_PER_CANISTER;
        deposit_cycles(&canister_a, &canister_b_id, cycles_to_deposit).await;

        // Check canister_a's balance has not decreased as it's an NNS node.
        let balance = get_balance(&canister_a.canister_id(), &agent).await;
        assert_eq!(
            Cycles::from(balance),
            CYCLES_LIMIT_PER_CANISTER,
            "expected {} == {}",
            balance,
            CYCLES_LIMIT_PER_CANISTER
        );

        let balance = get_balance_via_canister(&canister_b_id, &canister_a).await;
        assert_eq!(
            balance,
            CYCLES_LIMIT_PER_CANISTER * 2u64,
            "expected {} == {}",
            balance,
            CYCLES_LIMIT_PER_CANISTER * 2u64
        );
    });
}

pub fn config() -> InternetComputer {
    InternetComputer::new()
        .add_subnet(Subnet::fast_single_node(SubnetType::System))
        .add_subnet(Subnet::fast_single_node(SubnetType::Application))
}

/// Tests whether creating a canister on a subnet other than self fails when not
/// on the NNS subnet.
pub fn non_nns_canister_attempt_to_create_canister_on_another_subnet_fails(env: TestEnv) {
    let logger = env.logger();
    let ver_app_node = env.get_first_healthy_verified_application_node_snapshot();
    let app_node = env.get_first_healthy_application_node_snapshot();
    let sys_node = env.get_first_healthy_system_node_snapshot();
    let sys_no_nns_node = env.get_first_healthy_system_but_not_nns_node_snapshot();
    let ver_app_agent = ver_app_node.build_default_agent();
    let app_agent = app_node.build_default_agent();
    let sys_no_nns_agent = sys_no_nns_node.build_default_agent();
    block_on(async move {
        // Check that canisters on verified app subnets cannot create canisters on other
        // subnets.
        let uni_can = UniversalCanister::new_with_cycles_with_retries(
            &ver_app_agent,
            ver_app_node.effective_canister_id(),
            900_000_000_000_000_u64,
            &logger,
        )
        .await;
        let other_subnet = app_node.subnet_id().unwrap();
        let res = uni_can
            .forward_with_cycles_to(
                &other_subnet.get().into(),
                "create_canister",
                Encode!().unwrap(),
                Cycles::from(100_000_000_000_000u64),
            )
            .await
            .map(|res| {
                Decode!(res.as_slice(), CreateCanisterResult)
                    .unwrap()
                    .canister_id
            });
        assert_reject(res, RejectCode::CanisterReject);

        let other_subnet = sys_node.subnet_id().unwrap();
        let res = uni_can
            .forward_with_cycles_to(
                &other_subnet.get().into(),
                "create_canister",
                Encode!().unwrap(),
                Cycles::from(100_000_000_000_000u64),
            )
            .await
            .map(|res| {
                Decode!(res.as_slice(), CreateCanisterResult)
                    .unwrap()
                    .canister_id
            });
        assert_reject(res, RejectCode::CanisterReject);

        // Check that canisters on app subnets cannot create canisters on other subnets.
        let uni_can = UniversalCanister::new_with_cycles_with_retries(
            &app_agent,
            app_node.effective_canister_id(),
            900_000_000_000_000_u64,
            &logger,
        )
        .await;
        let other_subnet = ver_app_node.subnet_id().unwrap();
        let res = uni_can
            .forward_with_cycles_to(
                &other_subnet.get().into(),
                "create_canister",
                Encode!().unwrap(),
                Cycles::zero(),
            )
            .await
            .map(|res| {
                Decode!(res.as_slice(), CreateCanisterResult)
                    .unwrap()
                    .canister_id
            });
        assert_reject(res, RejectCode::CanisterReject);

        let other_subnet = sys_node.subnet_id().unwrap();
        let res = uni_can
            .forward_with_cycles_to(
                &other_subnet.get().into(),
                "create_canister",
                Encode!().unwrap(),
                Cycles::zero(),
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
        let uni_can = UniversalCanister::new_with_cycles_with_retries(
            &sys_no_nns_agent,
            sys_no_nns_node.effective_canister_id(),
            900_000_000_000_000_u64,
            &logger,
        )
        .await;
        let other_subnet = ver_app_node.subnet_id().unwrap();
        let res = uni_can
            .forward_with_cycles_to(
                &other_subnet.get().into(),
                "create_canister",
                Encode!().unwrap(),
                Cycles::from(50_000_000_000_000u64),
            )
            .await
            .map(|res| {
                Decode!(res.as_slice(), CreateCanisterResult)
                    .unwrap()
                    .canister_id
            });
        assert_reject(res, RejectCode::CanisterReject);

        let other_subnet = app_node.subnet_id().unwrap();
        let res = uni_can
            .forward_with_cycles_to(
                &other_subnet.get().into(),
                "create_canister",
                Encode!().unwrap(),
                Cycles::from(50_000_000_000_000u64),
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
pub fn nns_canister_attempt_to_create_canister_on_another_subnet_succeeds(env: TestEnv) {
    let logger = env.logger();
    let nns_node = env.get_first_healthy_nns_node_snapshot();
    let non_nns_node = env.get_first_healthy_non_nns_node_snapshot();
    let agent = nns_node.build_default_agent();
    block_on(async move {
        let uni_can = UniversalCanister::new_with_cycles_with_retries(
            &agent,
            nns_node.effective_canister_id(),
            900_000_000_000_000_u64,
            &logger,
        )
        .await;
        let other_subnet = non_nns_node.subnet_id().unwrap();
        uni_can
            .forward_with_cycles_to(
                &other_subnet.get().into(),
                "create_canister",
                Encode!().unwrap(),
                Cycles::from(100_000_000_000_000u64),
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
pub fn app_canister_attempt_initiating_dkg_fails(env: TestEnv) {
    let logger = env.logger();
    let app_node = env.get_first_healthy_application_node_snapshot();
    let agent = app_node.build_default_agent();
    block_on(async move {
        let node_ids: Vec<_> = (0..4).map(node_test_id).collect();
        let request = SetupInitialDKGArgs::new(node_ids, RegistryVersion::from(2));

        let uni_can =
            UniversalCanister::new_with_retries(&agent, app_node.effective_canister_id(), &logger)
                .await;
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
