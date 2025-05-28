use crate::{icrc3_get_blocks, init_args, InitArgs};
use candid::{CandidType, Decode, Encode, Nat};
use ic_base_types::PrincipalId;
use ic_ledger_core::tokens::TokensType;
use ic_state_machine_tests::StateMachine;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc124::errors::Icrc124Error;
use icrc_ledger_types::icrc3::blocks::GenericBlock;
use num_traits::ToPrimitive;

pub fn test_icrc124_pause<T, B>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
    B: TokensType,
{
    const NUM_INITIAL_BALANCES: usize = 20;
    let p1 = PrincipalId::new_user_test_id(1);
    let mut initial_balances = vec![];
    for i in 0..NUM_INITIAL_BALANCES {
        initial_balances.push((
            Account::from(PrincipalId::new_user_test_id(i as u64).0),
            10_000_000,
        ));
    }

    let env = StateMachine::new();
    let args = encode_init_args(init_args(initial_balances));
    let args = Encode!(&args).unwrap();
    let ledger_id = env
        .install_canister(ledger_wasm.clone(), args, None)
        .unwrap();

    // let get_blocks_response = icrc3_get_blocks(&env, ledger_id, 0, NUM_INITIAL_BALANCES);
    let pause_args = icrc_ledger_types::icrc124::pause::PauseArgs {
        reason: "pineapple on pizza".to_string(),
        created_at_time: None,
    };
    let pause_wasm_result = env
        .execute_ingress_as(
            p1,
            ledger_id,
            "icrc124_pause",
            Encode!(&pause_args).unwrap(),
        )
        .expect("failed to pause ledger");
    let pause_result = Decode!(
        &pause_wasm_result.bytes(),
        Result<Nat, Icrc124Error>
    )
    .expect("failed to decode pause result")
    .expect("pause failed");

    let pause_get_blocks_response =
        icrc3_get_blocks(&env, ledger_id, pause_result.0.to_u64().unwrap(), 1);
    println!("pause get blocks response: {:?}", pause_get_blocks_response);
    assert_eq!(pause_get_blocks_response.blocks.len(), 1);
    let pause_block = &pause_get_blocks_response
        .blocks
        .first()
        .expect("no blocks returned")
        .block;
    println!("pause block: {:?}", pause_block);

    let pause_block = GenericBlock::from(pause_block.clone());
    let icrc1_pause_block: ic_icrc1::Block<B> = ic_icrc1::Block::try_from(pause_block)
        .expect("failed to convert pause block to icrc1 block");
    let block_timestamp = icrc1_pause_block.timestamp;
    let pause_transaction =
        icrc_ledger_types::icrc3::transactions::Transaction::from(icrc1_pause_block);
    let mut expected_transaction = icrc_ledger_types::icrc3::transactions::Transaction::pause(
        p1.0,
        "pineapple on pizza".to_string(),
        pause_result.0.to_u64().unwrap(),
    );
    expected_transaction.timestamp = block_timestamp;
    assert_eq!(pause_transaction, expected_transaction);
}
