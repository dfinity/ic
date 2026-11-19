use super::*;
use ic_test_utilities_state::get_running_canister;
use ic_types_test_utils::ids::subnet_test_id;

#[test]
fn only_management_and_existing_canisters_are_accepted() {
    let mut state = ReplicatedState::new(subnet_test_id(1), SubnetType::Application);
    state.put_canister_state(get_running_canister(CanisterId::from_u64(15)));

    assert_eq!(receiver_exists(&state, CanisterId::ic_00()), Ok(()));
    assert_eq!(receiver_exists(&state, CanisterId::from_u64(15)), Ok(()));
    let missing = CanisterId::from_u64(16);
    assert_eq!(
        receiver_exists(&state, missing),
        Err(UserError::new(
            ErrorCode::CanisterNotFound,
            format!("Canister {missing} not found"),
        ))
    );
    let anonymous = CanisterId::unchecked_from_principal(PrincipalId::new_anonymous());
    assert_eq!(
        receiver_exists(&state, anonymous),
        Err(UserError::new(
            ErrorCode::CanisterNotFound,
            format!("Canister {anonymous} not found"),
        ))
    );
}
