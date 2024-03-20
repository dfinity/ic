use ic_base_types::NumBytes;
use ic_canonical_state::lazy_tree_conversion::replicated_state_as_lazy_tree;
use ic_canonical_state_tree_hash::hash_tree::hash_lazy_tree;
use ic_canonical_state_tree_hash_test_utils::crypto_hash_lazy_tree;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::ReplicatedState;
use ic_test_utilities_state::insert_dummy_canister;
use ic_test_utilities_types::ids::{
    canister_test_id, message_test_id, subnet_test_id, user_test_id,
};
use ic_types::ingress::{IngressState, IngressStatus, WasmResult};
use ic_types::time::UNIX_EPOCH;

#[test]
fn simple_state_old_vs_new_hashing() {
    let state = ReplicatedState::new(subnet_test_id(1), SubnetType::Application);

    let hash_tree = hash_lazy_tree(&replicated_state_as_lazy_tree(&state)).unwrap();
    let crypto_hash_tree = crypto_hash_lazy_tree(&replicated_state_as_lazy_tree(&state));

    assert_eq!(hash_tree, crypto_hash_tree);
}

#[test]
fn many_canister_state_old_vs_new_hashing() {
    let mut state = ReplicatedState::new(subnet_test_id(1), SubnetType::Application);
    for i in 1..1000 {
        insert_dummy_canister(&mut state, canister_test_id(i), user_test_id(24).get());
    }

    let hash_tree = hash_lazy_tree(&replicated_state_as_lazy_tree(&state)).unwrap();
    let crypto_hash_tree = crypto_hash_lazy_tree(&replicated_state_as_lazy_tree(&state));

    assert_eq!(hash_tree, crypto_hash_tree);
}

#[test]
fn large_history_state_old_vs_new_hashing() {
    let mut state = ReplicatedState::new(subnet_test_id(1), SubnetType::Application);
    for i in 1..1000 {
        state.set_ingress_status(
            message_test_id(i),
            IngressStatus::Known {
                receiver: canister_test_id(i).get(),
                user_id: user_test_id(i),
                time: UNIX_EPOCH,
                state: IngressState::Completed(WasmResult::Reply(b"done".to_vec())),
            },
            NumBytes::from(u64::MAX),
        );
    }

    let hash_tree = hash_lazy_tree(&replicated_state_as_lazy_tree(&state)).unwrap();
    let crypto_hash_tree = crypto_hash_lazy_tree(&replicated_state_as_lazy_tree(&state));

    assert_eq!(hash_tree, crypto_hash_tree);
}

#[test]
fn large_history_and_canisters_state_old_vs_new_hashing() {
    let mut state = ReplicatedState::new(subnet_test_id(1), SubnetType::Application);
    for i in 1..1000 {
        insert_dummy_canister(&mut state, canister_test_id(i), user_test_id(24).get());

        state.set_ingress_status(
            message_test_id(i),
            IngressStatus::Known {
                receiver: canister_test_id(i).get(),
                user_id: user_test_id(i),
                time: UNIX_EPOCH,
                state: IngressState::Completed(WasmResult::Reply(b"done".to_vec())),
            },
            NumBytes::from(u64::MAX),
        );
    }

    let hash_tree = hash_lazy_tree(&replicated_state_as_lazy_tree(&state)).unwrap();
    let crypto_hash_tree = crypto_hash_lazy_tree(&replicated_state_as_lazy_tree(&state));

    assert_eq!(hash_tree, crypto_hash_tree);
}
