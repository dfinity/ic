use ic_ic00_types::{CanisterIdRecord, EmptyBlob, Method, Payload, IC_00};
use ic_replica_tests as utils;
use ic_test_utilities::assert_utils::assert_balance_equals;
use ic_test_utilities::universal_canister::{call_args, wasm};
use ic_types::Cycles;

const BALANCE_EPSILON: Cycles = Cycles::new(2_000_000u128);
const CANISTER_CREATION_FEE: Cycles = Cycles::new(1_000_000_000_000);
const CANISTER_FREEZE_BALANCE_RESERVE: Cycles = Cycles::new(5_000_000_000_000);

#[test]
fn can_refund_when_having_nested_calls() {
    utils::canister_test(|test| {
        let num_cycles = CANISTER_FREEZE_BALANCE_RESERVE + Cycles::new(5_000_000_000_000);
        let num_cycles: u128 = num_cycles.get();

        // Create universal canisters A, B and C.
        let canister_a_id = test.create_universal_canister_with_args(vec![], num_cycles);
        let canister_b_id = test.create_universal_canister_with_args(vec![], num_cycles);
        let canister_c_id = test.create_universal_canister_with_args(vec![], num_cycles);

        let a_cycles_balance_before = test.canister_state(&canister_a_id).system_state.balance();
        let b_cycles_balance_before = test.canister_state(&canister_b_id).system_state.balance();
        let c_cycles_balance_before = test.canister_state(&canister_c_id).system_state.balance();

        // A sends a message to B including 10^9 cycles and 10 ICP tokens.
        // B sends a message to C including 5*10^8 cycles and 5 ICP tokens.
        // C replies to B (without accepting any funds).
        // B should get a refund of 5*10^8 cycles and 5 ICP tokens.
        // B replies to A (without accepting any funds).
        // A should get a refund of 10^9 cycles and 10 ICP tokens.
        //
        // At the end, since no funds were accepted, the canisters should have a balance
        // equal to their initial one (almost equal for cycles).
        test.ingress(
            canister_a_id,
            "update",
            wasm().call_with_cycles(
                canister_b_id,
                "update",
                call_args().other_side(wasm().call_with_cycles(
                    canister_c_id,
                    "update",
                    call_args(),
                    Cycles::new(500_000_000).into_parts(),
                )),
                Cycles::new(1_000_000_000).into_parts(),
            ),
        )
        .unwrap();

        let a_cycles_balance_after = test.canister_state(&canister_a_id).system_state.balance();
        let b_cycles_balance_after = test.canister_state(&canister_b_id).system_state.balance();
        let c_cycles_balance_after = test.canister_state(&canister_c_id).system_state.balance();

        assert_balance_equals(
            a_cycles_balance_before,
            a_cycles_balance_after,
            BALANCE_EPSILON,
        );
        assert_balance_equals(
            b_cycles_balance_before,
            b_cycles_balance_after,
            BALANCE_EPSILON,
        );
        assert_balance_equals(
            c_cycles_balance_before,
            c_cycles_balance_after,
            BALANCE_EPSILON,
        );
    });
}

#[test]
fn can_deposit_cycles_via_the_management_canister() {
    utils::canister_test(|test| {
        let num_cycles = 1 << 50;

        // Create a universal canister.
        let canister_id = test.create_universal_canister_with_args(vec![], num_cycles);

        // Create another canister with some cycles and ICP tokens.
        let cycles_for_new_canister = CANISTER_CREATION_FEE + Cycles::from(100_000_000);
        let new_canister_id_payload = test
            .ingress(
                canister_id,
                "update",
                wasm().call_with_cycles(
                    IC_00,
                    Method::CreateCanister,
                    call_args().other_side(EmptyBlob::encode()),
                    cycles_for_new_canister.into_parts(),
                ),
            )
            .unwrap()
            .bytes();

        let new_canister_id = CanisterIdRecord::decode(new_canister_id_payload.as_slice())
            .unwrap()
            .get_canister_id();

        let old_canister_cycles_balance_before =
            test.canister_state(&canister_id).system_state.balance();
        let new_canister_cycles_balance_before =
            test.canister_state(&new_canister_id).system_state.balance();

        // Deposit cycles to the new canister.
        let cycles_to_deposit = Cycles::from(200_000_000);
        test.ingress(
            canister_id,
            "update",
            wasm().call_with_cycles(
                IC_00,
                Method::DepositCycles,
                call_args().other_side(CanisterIdRecord::from(new_canister_id).encode()),
                cycles_to_deposit.into_parts(),
            ),
        )
        .unwrap();

        let old_canister_cycles_balance_after =
            test.canister_state(&canister_id).system_state.balance();
        let new_canister_cycles_balance_after =
            test.canister_state(&new_canister_id).system_state.balance();

        // Check cycles balances.
        assert_balance_equals(
            old_canister_cycles_balance_before - cycles_to_deposit,
            old_canister_cycles_balance_after,
            BALANCE_EPSILON,
        );
        assert_balance_equals(
            new_canister_cycles_balance_before + cycles_to_deposit,
            new_canister_cycles_balance_after,
            BALANCE_EPSILON,
        );
    });
}
