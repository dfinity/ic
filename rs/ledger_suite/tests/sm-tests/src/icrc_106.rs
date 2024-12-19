use super::*;

pub fn test_icrc106_unsupported_if_index_not_set<T, U>(
    ledger_wasm: Vec<u8>,
    encode_ledger_init_args: fn(InitArgs) -> T,
    encode_upgrade_args: fn(Option<Principal>) -> U,
) where
    T: CandidType,
    U: CandidType,
{
    fn assert_index_not_set(env: &StateMachine, ledger_canister_id: CanisterId) {
        assert_icrc106_supported(env, ledger_canister_id);
        assert_eq!(
            Err(Icrc106Error::IndexPrincipalNotSet),
            icrc106_get_index_principal(env, ledger_canister_id)
        );
        assert_eq!(
            None,
            metadata(env, ledger_canister_id).get("icrc106:index_principal")
        );
    }

    let env = StateMachine::new();
    let ledger_canister_id = env.create_canister(None);
    let ledger_init_args = encode_ledger_init_args(init_args(vec![]));
    env.install_existing_canister(
        ledger_canister_id,
        ledger_wasm.clone(),
        Encode!(&ledger_init_args).unwrap(),
    )
    .expect("should successfully install ledger canister");

    assert_index_not_set(&env, ledger_canister_id);

    let args = encode_upgrade_args(None);
    let encoded_upgrade_args = Encode!(&args).unwrap();
    env.upgrade_canister(
        ledger_canister_id,
        ledger_wasm,
        encoded_upgrade_args.clone(),
    )
    .expect("should successfully upgrade ledger canister");

    assert_index_not_set(&env, ledger_canister_id);
}

pub fn test_icrc106_set_index_in_install<T>(
    ledger_wasm: Vec<u8>,
    encode_ledger_init_args: fn(InitArgs) -> T,
) where
    T: CandidType,
{
    let env = StateMachine::new();
    let ledger_canister_id = env.create_canister(None);
    let index_canister_id = env.create_canister(None);
    let index_principal = Principal::from(index_canister_id.get());
    let ledger_init_args = encode_ledger_init_args(InitArgs {
        index_principal: Some(index_principal),
        ..init_args(vec![])
    });
    env.install_existing_canister(
        ledger_canister_id,
        ledger_wasm.clone(),
        Encode!(&ledger_init_args).unwrap(),
    )
    .expect("should successfully install ledger canister");

    assert_icrc106_supported(&env, ledger_canister_id);
    assert_eq!(
        Ok(index_principal),
        icrc106_get_index_principal(&env, ledger_canister_id)
    );
    assert_eq!(
        &Value::Text(index_principal.to_text()),
        metadata(&env, ledger_canister_id)
            .get("icrc106:index_principal")
            .expect("should have index principal metadata")
    );
}

pub fn test_icrc106_set_index_in_upgrade<T, U>(
    ledger_wasm: Vec<u8>,
    encode_init_args: fn(InitArgs) -> T,
    encode_upgrade_args: fn(Option<Principal>) -> U,
) where
    T: CandidType,
    U: CandidType,
{
    fn assert_index_set(
        env: &StateMachine,
        ledger_canister_id: CanisterId,
        index_principal: Principal,
    ) {
        assert_icrc106_supported(&env, ledger_canister_id);
        assert_eq!(
            Ok(index_principal),
            icrc106_get_index_principal(&env, ledger_canister_id)
        );
        assert_eq!(
            &Value::Text(index_principal.to_text()),
            metadata(&env, ledger_canister_id)
                .get("icrc106:index_principal")
                .expect("should have index principal metadata")
        );
    }

    let (env, canister_id) = setup(ledger_wasm.clone(), encode_init_args, vec![]);
    assert_icrc106_supported(&env, canister_id);
    assert_eq!(
        Err(Icrc106Error::IndexPrincipalNotSet),
        icrc106_get_index_principal(&env, canister_id)
    );
    assert!(!metadata(&env, canister_id).contains_key("icrc106:index_principal"));

    let index_principal = PrincipalId::new_user_test_id(1).0;
    let args = encode_upgrade_args(Some(index_principal));
    let encoded_upgrade_args = Encode!(&args).unwrap();
    env.upgrade_canister(canister_id, ledger_wasm.clone(), encoded_upgrade_args)
        .expect("should successfully upgrade ledger canister");
    // The index should now be set
    assert_index_set(&env, canister_id, index_principal);

    let args = encode_upgrade_args(None);
    let encoded_upgrade_args = Encode!(&args).unwrap();
    env.upgrade_canister(canister_id, ledger_wasm, encoded_upgrade_args)
        .expect("should successfully upgrade ledger canister");
    // Passing `None` should not change the previously set index
    assert_index_set(&env, canister_id, index_principal);
}

fn assert_icrc106_supported(env: &StateMachine, canister_id: CanisterId) {
    let mut found = false;
    for standard in supported_standards(env, canister_id) {
        if standard.name == "ICRC-106" {
            found = true;
            break;
        }
    }
    assert!(found, "ICRC-106 should be supported");
}
