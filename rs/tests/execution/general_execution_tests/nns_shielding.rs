/* tag::catalog[]
end::catalog[] */

use candid::{Encode, Principal};
use ic_agent::{
    AgentError,
    agent::{RejectCode, RejectResponse},
};
use ic_base_types::RegistryVersion;
use ic_management_canister_types_private::SetupInitialDKGArgs;
use ic_nns_constants::CYCLES_MINTING_CANISTER_ID;
use ic_system_test_driver::driver::test_env_api::{GetFirstHealthyNodeSnapshot, HasPublicApiUrl};
use ic_system_test_driver::driver::{test_env::TestEnv, test_env_api::IcNodeSnapshot};
use ic_system_test_driver::{util::CYCLES_LIMIT_PER_CANISTER, util::*};
use ic_types::Cycles;
use ic_types_test_utils::ids::node_test_id;
use ic_universal_canister::wasm;
use lazy_static::lazy_static;

const CANISTER_FREEZE_BALANCE_RESERVE: Cycles = Cycles::new(5_000_000_000_000);
lazy_static! {
    static ref INITIAL_CYCLES: Cycles =
        CANISTER_FREEZE_BALANCE_RESERVE + Cycles::new(5_000_000_000_000);
}

fn setup_ucan_and_try_mint128(node: IcNodeSnapshot) -> (AgentError, u128, u128, String) {
    let agent = node.build_default_agent();
    let effective_canister_id = node.get_last_canister_id_in_allocation_ranges();
    block_on(async move {
        let mut canister_id =
            UniversalCanister::new_with_cycles(&agent, effective_canister_id, *INITIAL_CYCLES)
                .await
                .unwrap()
                .canister_id();
        // Make sure that 'canister_id' is not 'CYCLES_MINTING_CANISTER_ID'.
        if canister_id == CYCLES_MINTING_CANISTER_ID.into() {
            let effective_canister_id = node.get_last_canister_id_in_allocation_ranges();
            canister_id =
                UniversalCanister::new_with_cycles(&agent, effective_canister_id, *INITIAL_CYCLES)
                    .await
                    .unwrap()
                    .canister_id();
        }
        let before_balance = get_balance(&canister_id, &agent).await;
        let res = agent
            .update(&canister_id, "update")
            .with_arg(
                wasm()
                    .mint_cycles128(Cycles::from(10_000_000_000u128))
                    .reply_data_append()
                    .reply()
                    .build(),
            )
            .call_and_wait()
            .await
            .expect_err("should not succeed");
        let after_balance = get_balance(&canister_id, &agent).await;
        (res, before_balance, after_balance, canister_id.to_string())
    })
}

pub fn mint_cycles128_not_supported_on_application_subnet(env: TestEnv) {
    let app_node = env.get_first_healthy_application_node_snapshot();
    let (res, before_balance, after_balance, canister_id) = setup_ucan_and_try_mint128(app_node);
    let expected_reject = RejectResponse {
        reject_code: RejectCode::CanisterError,
        reject_message: format!(
            "Error from Canister {canister_id}: Canister violated contract: ic0.mint_cycles128 cannot be executed on non Cycles Minting Canister: {canister_id} != {CYCLES_MINTING_CANISTER_ID}.\nIf you are running this canister in a test environment (e.g., dfx), make sure the test environment is up to date. Otherwise, this is likely an error with the compiler/CDK toolchain being used to build the canister. Please report the error to IC devs on the forum: https://forum.dfinity.org and include which language/CDK was used to create the canister."
        ),
        error_code: Some("IC0504".to_string()),
    };
    match res {
        AgentError::CertifiedReject { reject, .. } => assert_eq!(reject, expected_reject),
        _ => panic!("Unexpected error: {res:?}"),
    };
    assert!(
        after_balance <= before_balance,
        "expected {after_balance} <= {before_balance}"
    );
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
            "expected {balance} == {CYCLES_LIMIT_PER_CANISTER}"
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
