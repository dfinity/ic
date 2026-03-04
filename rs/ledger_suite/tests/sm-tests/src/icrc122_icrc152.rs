use super::*;
use ic_management_canister_types_private as ic00;
use icrc_ledger_types::icrc122::schema::{BTYPE_122_BURN, BTYPE_122_MINT};

#[derive(Clone, Debug, CandidType, serde::Deserialize)]
pub struct Icrc152MintArgs {
    pub to: Account,
    pub amount: Nat,
    pub created_at_time: Option<u64>,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, CandidType, serde::Deserialize)]
pub enum Icrc152MintError {
    Unauthorized(String),
    InvalidAccount(String),
    Duplicate { duplicate_of: Nat },
    GenericError { error_code: Nat, message: String },
}

#[derive(Clone, Debug, CandidType, serde::Deserialize)]
pub struct Icrc152BurnArgs {
    pub from: Account,
    pub amount: Nat,
    pub created_at_time: Option<u64>,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, CandidType, serde::Deserialize)]
pub enum Icrc152BurnError {
    Unauthorized(String),
    InvalidAccount(String),
    InsufficientBalance { balance: Nat },
    Duplicate { duplicate_of: Nat },
    GenericError { error_code: Nat, message: String },
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn install_ledger_with_icrc152<T>(
    env: &StateMachine,
    ledger_wasm: Vec<u8>,
    encode_init_args: fn(InitArgs) -> T,
    initial_balances: Vec<(Account, u64)>,
    controller: PrincipalId,
) -> CanisterId
where
    T: CandidType,
{
    let args = encode_init_args(InitArgs {
        feature_flags: Some(FeatureFlags {
            icrc2: true,
            icrc152: true,
        }),
        ..init_args(initial_balances)
    });
    let canister_id = env.create_canister(Some(
        ic00::CanisterSettingsArgsBuilder::new()
            .with_controllers(vec![controller])
            .build(),
    ));
    env.install_existing_canister(canister_id, ledger_wasm, Encode!(&args).unwrap())
        .expect("failed to install ledger");
    canister_id
}

fn icrc152_mint(
    env: &StateMachine,
    ledger: CanisterId,
    caller: PrincipalId,
    arg: &Icrc152MintArgs,
) -> Result<Nat, Icrc152MintError> {
    Decode!(
        &env.execute_ingress_as(caller, ledger, "icrc152_mint", Encode!(arg).unwrap())
            .expect("failed to call icrc152_mint")
            .bytes(),
        Result<Nat, Icrc152MintError>
    )
    .expect("failed to decode icrc152_mint response")
}

fn try_icrc152_mint(
    env: &StateMachine,
    ledger: CanisterId,
    caller: PrincipalId,
    arg: &Icrc152MintArgs,
) -> Result<Nat, Icrc152MintError> {
    let result = env.execute_ingress_as(caller, ledger, "icrc152_mint", Encode!(arg).unwrap());
    match result {
        Ok(wasm_result) => Decode!(&wasm_result.bytes(), Result<Nat, Icrc152MintError>)
            .expect("failed to decode icrc152_mint response"),
        Err(e) => panic!("icrc152_mint call failed: {e:?}"),
    }
}

fn icrc152_burn(
    env: &StateMachine,
    ledger: CanisterId,
    caller: PrincipalId,
    arg: &Icrc152BurnArgs,
) -> Result<Nat, Icrc152BurnError> {
    Decode!(
        &env.execute_ingress_as(caller, ledger, "icrc152_burn", Encode!(arg).unwrap())
            .expect("failed to call icrc152_burn")
            .bytes(),
        Result<Nat, Icrc152BurnError>
    )
    .expect("failed to decode icrc152_burn response")
}

fn try_icrc152_burn(
    env: &StateMachine,
    ledger: CanisterId,
    caller: PrincipalId,
    arg: &Icrc152BurnArgs,
) -> Result<Nat, Icrc152BurnError> {
    let result = env.execute_ingress_as(caller, ledger, "icrc152_burn", Encode!(arg).unwrap());
    match result {
        Ok(wasm_result) => Decode!(&wasm_result.bytes(), Result<Nat, Icrc152BurnError>)
            .expect("failed to decode icrc152_burn response"),
        Err(e) => panic!("icrc152_burn call failed: {e:?}"),
    }
}

fn get_block_btype(env: &StateMachine, ledger: CanisterId, block_idx: u64) -> String {
    let result = icrc3_get_blocks(env, ledger, block_idx, 1);
    let block = result
        .blocks
        .into_iter()
        .next()
        .expect("expected at least one block");
    match &block.block {
        ICRC3Value::Map(map) => map
            .iter()
            .find(|(k, _)| k == "btype")
            .and_then(|(_, v)| {
                if let ICRC3Value::Text(s) = v {
                    Some(s.clone())
                } else {
                    None
                }
            })
            .expect("block has no btype field"),
        _ => panic!("block is not a Map"),
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

pub fn test_icrc152_mint_by_controller<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
    let controller = PrincipalId::new_user_test_id(1);
    let recipient = Account {
        owner: PrincipalId::new_user_test_id(2).0,
        subaccount: None,
    };

    let env = StateMachine::new();
    let ledger =
        install_ledger_with_icrc152(&env, ledger_wasm, encode_init_args, vec![], controller);

    let supply_before = total_supply(&env, ledger);
    let balance_before = balance_of(&env, ledger, recipient);

    let mint_amount = 1_000_000u64;
    let result = icrc152_mint(
        &env,
        ledger,
        controller,
        &Icrc152MintArgs {
            to: recipient,
            amount: Nat::from(mint_amount),
            created_at_time: None,
            reason: Some("controller mint".to_string()),
        },
    );

    let block_idx = result
        .expect("icrc152_mint should succeed")
        .0
        .to_u64()
        .unwrap();

    assert_eq!(
        balance_of(&env, ledger, recipient),
        balance_before + mint_amount,
        "recipient balance should have increased by the minted amount"
    );
    assert_eq!(
        total_supply(&env, ledger),
        supply_before + mint_amount,
        "total supply should have increased by the minted amount"
    );

    let btype = get_block_btype(&env, ledger, block_idx);
    assert_eq!(
        btype, BTYPE_122_MINT,
        "emitted block must be a 122mint block"
    );
}

pub fn test_icrc152_burn_by_controller<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
    let controller = PrincipalId::new_user_test_id(1);
    let account = Account {
        owner: PrincipalId::new_user_test_id(2).0,
        subaccount: None,
    };

    let initial_balance = 5_000_000u64;
    let env = StateMachine::new();
    let ledger = install_ledger_with_icrc152(
        &env,
        ledger_wasm,
        encode_init_args,
        vec![(account, initial_balance)],
        controller,
    );

    let supply_before = total_supply(&env, ledger);

    let burn_amount = 1_000_000u64;
    let result = icrc152_burn(
        &env,
        ledger,
        controller,
        &Icrc152BurnArgs {
            from: account,
            amount: Nat::from(burn_amount),
            created_at_time: None,
            reason: Some("controller burn".to_string()),
        },
    );

    let block_idx = result
        .expect("icrc152_burn should succeed")
        .0
        .to_u64()
        .unwrap();

    assert_eq!(
        balance_of(&env, ledger, account),
        initial_balance - burn_amount,
        "account balance should have decreased by the burned amount"
    );
    assert_eq!(
        total_supply(&env, ledger),
        supply_before - burn_amount,
        "total supply should have decreased by the burned amount"
    );

    let btype = get_block_btype(&env, ledger, block_idx);
    assert_eq!(
        btype, BTYPE_122_BURN,
        "emitted block must be a 122burn block"
    );
}

pub fn test_icrc152_unauthorized<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
    let controller = PrincipalId::new_user_test_id(1);
    let non_controller = PrincipalId::new_user_test_id(99);
    let recipient = Account {
        owner: PrincipalId::new_user_test_id(2).0,
        subaccount: None,
    };

    let env = StateMachine::new();
    let ledger =
        install_ledger_with_icrc152(&env, ledger_wasm, encode_init_args, vec![], controller);

    let mint_result = try_icrc152_mint(
        &env,
        ledger,
        non_controller,
        &Icrc152MintArgs {
            to: recipient,
            amount: Nat::from(1_000_000u64),
            created_at_time: None,
            reason: None,
        },
    );
    assert!(
        matches!(mint_result, Err(Icrc152MintError::Unauthorized(_))),
        "non-controller should get Unauthorized for icrc152_mint, got {mint_result:?}"
    );

    let account = Account {
        owner: PrincipalId::new_user_test_id(3).0,
        subaccount: None,
    };
    let burn_result = try_icrc152_burn(
        &env,
        ledger,
        non_controller,
        &Icrc152BurnArgs {
            from: account,
            amount: Nat::from(1_000_000u64),
            created_at_time: None,
            reason: None,
        },
    );
    assert!(
        matches!(burn_result, Err(Icrc152BurnError::Unauthorized(_))),
        "non-controller should get Unauthorized for icrc152_burn, got {burn_result:?}"
    );
}

pub fn test_icrc152_feature_flag_disabled<T>(
    ledger_wasm: Vec<u8>,
    encode_init_args: fn(InitArgs) -> T,
) where
    T: CandidType,
{
    let controller = PrincipalId::new_user_test_id(1);
    let recipient = Account {
        owner: PrincipalId::new_user_test_id(2).0,
        subaccount: None,
    };

    let env = StateMachine::new();
    // Install with icrc152 disabled (the default)
    let args = encode_init_args(InitArgs {
        feature_flags: Some(FeatureFlags {
            icrc2: true,
            icrc152: false,
        }),
        ..init_args(vec![])
    });
    let canister_id = env.create_canister(Some(
        ic00::CanisterSettingsArgsBuilder::new()
            .with_controllers(vec![controller])
            .build(),
    ));
    env.install_existing_canister(canister_id, ledger_wasm, Encode!(&args).unwrap())
        .expect("failed to install ledger");

    let mint_result = try_icrc152_mint(
        &env,
        canister_id,
        controller,
        &Icrc152MintArgs {
            to: recipient,
            amount: Nat::from(1_000_000u64),
            created_at_time: None,
            reason: None,
        },
    );
    assert!(
        matches!(
            mint_result,
            Err(Icrc152MintError::GenericError { error_code, .. }) if error_code == Nat::from(4u64)
        ),
        "disabled icrc152 should return GenericError(4), got {mint_result:?}"
    );
}

pub fn test_icrc152_insufficient_balance<T>(
    ledger_wasm: Vec<u8>,
    encode_init_args: fn(InitArgs) -> T,
) where
    T: CandidType,
{
    let controller = PrincipalId::new_user_test_id(1);
    let account = Account {
        owner: PrincipalId::new_user_test_id(2).0,
        subaccount: None,
    };

    let initial_balance = 500_000u64;
    let env = StateMachine::new();
    let ledger = install_ledger_with_icrc152(
        &env,
        ledger_wasm,
        encode_init_args,
        vec![(account, initial_balance)],
        controller,
    );

    let result = try_icrc152_burn(
        &env,
        ledger,
        controller,
        &Icrc152BurnArgs {
            from: account,
            amount: Nat::from(initial_balance + 1),
            created_at_time: None,
            reason: None,
        },
    );
    assert!(
        matches!(result, Err(Icrc152BurnError::InsufficientBalance { .. })),
        "burning more than balance should return InsufficientBalance, got {result:?}"
    );
}

pub fn test_icrc152_deduplication<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
    let controller = PrincipalId::new_user_test_id(1);
    let recipient = Account {
        owner: PrincipalId::new_user_test_id(2).0,
        subaccount: None,
    };

    let env = StateMachine::new();
    let ledger =
        install_ledger_with_icrc152(&env, ledger_wasm, encode_init_args, vec![], controller);

    let now = system_time_to_nanos(env.time());
    let arg = Icrc152MintArgs {
        to: recipient,
        amount: Nat::from(1_000_000u64),
        created_at_time: Some(now),
        reason: None,
    };

    let first = icrc152_mint(&env, ledger, controller, &arg);
    let block_idx = first
        .expect("first icrc152_mint should succeed")
        .0
        .to_u64()
        .unwrap();

    let second = try_icrc152_mint(&env, ledger, controller, &arg);
    assert!(
        matches!(
            second,
            Err(Icrc152MintError::Duplicate { duplicate_of }) if duplicate_of == Nat::from(block_idx)
        ),
        "duplicate transaction should return Duplicate, got {second:?}"
    );
}

pub fn test_icrc152_supported_block_types<T>(
    ledger_wasm: Vec<u8>,
    encode_init_args: fn(InitArgs) -> T,
) where
    T: CandidType,
{
    let env = StateMachine::new();
    let ledger = install_ledger_with_icrc152(
        &env,
        ledger_wasm,
        encode_init_args,
        vec![],
        PrincipalId::new_user_test_id(1),
    );

    let block_types = supported_block_types(&env, ledger);
    let btypes: Vec<String> = block_types.iter().map(|b| b.block_type.clone()).collect();

    assert!(
        btypes.contains(&BTYPE_122_MINT.to_string()),
        "supported block types should include 122mint, got {btypes:?}"
    );
    assert!(
        btypes.contains(&BTYPE_122_BURN.to_string()),
        "supported block types should include 122burn, got {btypes:?}"
    );
}

pub fn test_icrc152_supported_standards<T>(
    ledger_wasm: Vec<u8>,
    encode_init_args: fn(InitArgs) -> T,
) where
    T: CandidType,
{
    let env = StateMachine::new();
    let ledger = install_ledger_with_icrc152(
        &env,
        ledger_wasm,
        encode_init_args,
        vec![],
        PrincipalId::new_user_test_id(1),
    );

    let standards = supported_standards(&env, ledger);
    let names: Vec<String> = standards.iter().map(|s| s.name.clone()).collect();

    assert!(
        names.contains(&"ICRC-152".to_string()),
        "supported standards should include ICRC-152, got {names:?}"
    );
}
