use candid::{Decode, Encode, Nat};
use ic_nns_test_utils::common::NnsInitPayloadsBuilder;
use ic_nns_test_utils::state_test_helpers::setup_nns_canisters;
use ic_state_machine_tests::{CanisterId, StateMachine};
use ic_tvl_canister::types::{TvlArgs as TVLInitArgs, TvlResult, TvlResultError};
use xrc_mock::{ExchangeRate, Response, XrcMockInitPayload};

pub fn get_tvl(
    env: &StateMachine,
    tvl_canister_id: CanisterId,
) -> Result<TvlResult, TvlResultError> {
    Decode!(
        &env.query(tvl_canister_id, "get_tvl", Encode!().unwrap())
            .expect("failed to query balance")
            .bytes(),
            Result<TvlResult, TvlResultError>
    )
    .expect("failed to decode get_tvl response")
}

pub fn setup(xrc_wasm: Vec<u8>) -> (StateMachine, CanisterId, CanisterId) {
    let env = StateMachine::new();
    env.set_time(std::time::SystemTime::now()); // to adapt to the node's fresh TLS keys

    let nns_init_payload = NnsInitPayloadsBuilder::new()
        .with_initial_invariant_compliant_mutations()
        .with_test_neurons()
        .build();

    setup_nns_canisters(&env, nns_init_payload);

    pub const GOVERNANCE_CANISTER_ID: CanisterId = CanisterId::from_u64(1);

    let xrc_args = XrcMockInitPayload {
        response: Response::ExchangeRate(ExchangeRate {
            base_asset: None,
            quote_asset: None,
            metadata: None,
            rate: 1_000_000_000, // This corresponds to an ICP price of 10$
        }),
    };

    let xrc_args = Encode!(&xrc_args).unwrap();
    let xrc_id = env.install_canister(xrc_wasm, xrc_args, None).unwrap();

    (env, GOVERNANCE_CANISTER_ID, xrc_id)
}

fn install_tvl(
    env: &StateMachine,
    tvl_wasm: Vec<u8>,
    governance_id: CanisterId,
    xrc_id: CanisterId,
) -> CanisterId {
    let args = tvl_init_args(governance_id, xrc_id);
    let args = Encode!(&args).unwrap();
    env.install_canister(tvl_wasm, args, None).unwrap()
}

fn tvl_init_args(governance_id: CanisterId, xrc_id: CanisterId) -> TVLInitArgs {
    TVLInitArgs {
        update_period: Some(30),
        governance_id: Some(governance_id.get()),
        xrc_id: Some(xrc_id.get()),
    }
}

pub fn test_tvl(tvl_wasm: Vec<u8>, xrc_wasm: Vec<u8>) {
    let (env, governance_id, xrc_id) = setup(xrc_wasm);

    let tvl_id = install_tvl(&env, tvl_wasm.clone(), governance_id, xrc_id);

    env.run_until_completion(10_000);

    env.advance_time(std::time::Duration::from_secs(60));
    env.tick();

    let get_tvl_result: TvlResult = get_tvl(&env, tvl_id).unwrap();
    // 3 neurons with respectively 10 ICP, 1 ICP and 0.1 ICP locked.
    // ICP price is 10$, hence tvl should be 111$.
    assert_eq!(get_tvl_result.tvl, Nat::from(111));

    let upgrade_args = tvl_init_args(governance_id, xrc_id);
    env.upgrade_canister(tvl_id, tvl_wasm, Encode!(&upgrade_args).unwrap())
        .expect("failed to upgrade the tvl canister");

    let get_tvl_result_after_upgrade: TvlResult = get_tvl(&env, tvl_id).unwrap();
    assert_eq!(get_tvl_result, get_tvl_result_after_upgrade);
}
