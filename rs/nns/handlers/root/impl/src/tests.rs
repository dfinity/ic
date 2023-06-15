use super::*;

#[test]
fn test_principal_name() {
    assert_eq!(
        principal_name(CanisterId::ic_00().get()),
        "management_canister",
    );
    assert_eq!(
        principal_name(GOVERNANCE_CANISTER_ID.get()),
        "governance_canister",
    );

    let test = PrincipalId::new_user_test_id(513_514);
    assert_eq!(principal_name(test), test.to_string());
}
