use candid::{Decode, Encode};
use canister_test::Project;
use ic_base_types::PrincipalId;
use ic_ledger_core::Tokens;
use ic_ledger_icrc1::{Account, InitArgs};
use ic_state_machine_tests::StateMachine;

fn ledger_wasm() -> Vec<u8> {
    let proj = Project::new(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    proj.cargo_bin("ic-ledger-icrc1", &[]).bytes()
}

#[test]
fn test_symbol_and_name() {
    let env = StateMachine::new();
    let canister_id = env
        .install_canister(
            ledger_wasm(),
            Encode!(&InitArgs {
                minting_account: Account {
                    owner: PrincipalId::new_anonymous(),
                    subaccount: None,
                },
                transfer_fee: Tokens::from_e8s(10_000),
                token_name: "Test".to_string(),
                token_symbol: "TST".to_string(),
            })
            .unwrap(),
            None,
        )
        .unwrap();

    assert_eq!(
        "TST",
        Decode!(
            &env.query(canister_id, "icrc1_symbol", Encode!().unwrap())
                .unwrap()
                .bytes(),
            String
        )
        .unwrap()
    );

    assert_eq!(
        "Test",
        Decode!(
            &env.query(canister_id, "icrc1_name", Encode!().unwrap())
                .unwrap()
                .bytes(),
            String
        )
        .unwrap()
    );
}
