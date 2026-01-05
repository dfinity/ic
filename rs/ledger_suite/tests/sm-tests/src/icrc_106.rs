use super::*;

pub fn test_icrc106_supported_even_if_index_not_set<T, U>(
    ledger_wasm: Vec<u8>,
    encode_ledger_init_args: fn(InitArgs) -> T,
    encode_upgrade_args: fn(Option<Principal>) -> U,
) where
    T: CandidType,
    U: CandidType,
{
    let env = StateMachine::new();
    let ledger_canister_id = env.create_canister(None);
    let ledger_init_args = encode_ledger_init_args(init_args(vec![]));
    env.install_existing_canister(
        ledger_canister_id,
        ledger_wasm.clone(),
        Encode!(&ledger_init_args).unwrap(),
    )
    .expect("should successfully install ledger canister");

    assert_index_not_set(&env, ledger_canister_id, true);

    let args = encode_upgrade_args(None);
    let encoded_upgrade_args = Encode!(&args).unwrap();
    env.upgrade_canister(
        ledger_canister_id,
        ledger_wasm,
        encoded_upgrade_args.clone(),
    )
    .expect("should successfully upgrade ledger canister");

    assert_index_not_set(&env, ledger_canister_id, true);
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

    assert_index_set(&env, ledger_canister_id, index_principal);
}

pub fn test_icrc106_set_index_in_install_with_mainnet_ledger_wasm<T>(
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

    assert_index_not_set(&env, ledger_canister_id, false);
}

pub fn test_icrc106_set_index_in_upgrade<T, U>(
    ledger_wasm: Vec<u8>,
    encode_init_args: fn(InitArgs) -> T,
    encode_upgrade_args: fn(Option<Principal>) -> U,
) where
    T: CandidType,
    U: CandidType,
{
    let (env, canister_id) = setup(ledger_wasm.clone(), encode_init_args, vec![]);
    assert_index_not_set(&env, canister_id, true);

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

pub fn test_upgrade_downgrade_with_mainnet_ledger<T, U>(
    mainnet_ledger_wasm: Vec<u8>,
    ledger_wasm: Vec<u8>,
    encode_init_args: fn(InitArgs) -> T,
    encode_empty_upgrade_args: fn() -> U,
    encode_upgrade_args: fn(Option<Principal>) -> U,
) where
    T: CandidType,
    U: CandidType,
{
    // Install the mainnet ledger canister that does not support ICRC-106
    let (env, canister_id) = setup(mainnet_ledger_wasm.clone(), encode_init_args, vec![]);
    assert_index_not_set(&env, canister_id, false);

    // Upgrade to a ledger version that supports ICRC-106, but does not set the index principal
    let encoded_empty_upgrade_args = Encode!(&encode_empty_upgrade_args()).unwrap();
    env.upgrade_canister(
        canister_id,
        ledger_wasm.clone(),
        encoded_empty_upgrade_args.clone(),
    )
    .expect("should successfully upgrade ledger canister");
    assert_index_not_set(&env, canister_id, true);

    // Self-upgrade to a ledger version and set the index principal
    let index_principal = PrincipalId::new_user_test_id(1).0;
    let args = encode_upgrade_args(Some(index_principal));
    let encoded_upgrade_args = Encode!(&args).unwrap();
    env.upgrade_canister(canister_id, ledger_wasm.clone(), encoded_upgrade_args)
        .expect("should successfully upgrade ledger canister");
    assert_index_set(&env, canister_id, index_principal);

    // Self-upgrade the ledger with empty upgrade args. The index principal should stay set.
    let encoded_empty_upgrade_args = Encode!(&encode_empty_upgrade_args()).unwrap();
    env.upgrade_canister(
        canister_id,
        ledger_wasm.clone(),
        encoded_empty_upgrade_args.clone(),
    )
    .expect("should successfully self-upgrade ledger canister");
    assert_index_set(&env, canister_id, index_principal);

    // Downgrade the ledger to the mainnet version that does not support ICRC-106
    env.upgrade_canister(canister_id, mainnet_ledger_wasm, encoded_empty_upgrade_args)
        .expect("should successfully downgrade ledger canister");
    assert_index_not_set(&env, canister_id, false);

    // Upgrade to a ledger version that supports ICRC-106, but do not set the index principal
    let encoded_empty_upgrade_args = Encode!(&encode_empty_upgrade_args()).unwrap();
    env.upgrade_canister(canister_id, ledger_wasm, encoded_empty_upgrade_args)
        .expect("should successfully upgrade ledger canister");
    assert_index_not_set(&env, canister_id, true);
}

fn assert_index_not_set(
    env: &StateMachine,
    ledger_canister_id: CanisterId,
    expect_icrc106_supported: bool,
) {
    check_icrc106_support(env, ledger_canister_id, expect_icrc106_supported);
    if expect_icrc106_supported {
        assert_eq!(
            Err(Icrc106Error::IndexPrincipalNotSet),
            icrc106_get_index_principal(env, ledger_canister_id)
        );
    }
    assert_eq!(
        None,
        metadata(env, ledger_canister_id).get(MetadataKey::ICRC106_INDEX_PRINCIPAL)
    );
}

fn assert_index_set(
    env: &StateMachine,
    ledger_canister_id: CanisterId,
    index_principal: Principal,
) {
    check_icrc106_support(env, ledger_canister_id, true);
    assert_eq!(
        Ok(index_principal),
        icrc106_get_index_principal(env, ledger_canister_id)
    );
    assert_eq!(
        &Value::Text(index_principal.to_text()),
        metadata(env, ledger_canister_id)
            .get(MetadataKey::ICRC106_INDEX_PRINCIPAL)
            .expect("should have index principal metadata")
    );
}

fn check_icrc106_support(
    env: &StateMachine,
    canister_id: CanisterId,
    expect_icrc106_supported: bool,
) {
    let mut found = false;
    for standard in supported_standards(env, canister_id) {
        if standard.name == "ICRC-106" {
            found = true;
            break;
        }
    }
    assert_eq!(
        found, expect_icrc106_supported,
        "ICRC-106 should be supported"
    );
}

fn icrc106_get_index_principal(
    env: &StateMachine,
    ledger: CanisterId,
) -> Result<Principal, Icrc106Error> {
    Decode!(
        &env.query(ledger, "icrc106_get_index_principal", Encode!().unwrap())
            .expect("failed to query icrc106_get_index_principal")
            .bytes(),
        Result<Principal, Icrc106Error>
    )
    .expect("failed to decode icrc106_get_index_principal response")
}
