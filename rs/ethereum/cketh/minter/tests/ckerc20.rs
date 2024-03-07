use assert_matches::assert_matches;
use candid::{Nat, Principal};
use ic_cketh_minter::endpoints::events::EventPayload;
use ic_cketh_minter::endpoints::AddCkErc20Token;
use ic_cketh_test_utils::ckerc20::CkErc20Setup;
use ic_cketh_test_utils::flow::DepositParams;
use ic_cketh_test_utils::CkEthSetup;
use ic_ethereum_types::Address;
use ic_ledger_suite_orchestrator_test_utils::supported_erc20_tokens;
use ic_state_machine_tests::ErrorCode;

#[test]
fn should_refuse_to_add_ckerc20_token_from_unauthorized_principal() {
    let cketh = CkEthSetup::default();
    let result = cketh.add_ckerc20_token(Principal::anonymous(), &ckusdc());
    assert_matches!(result, Err(e) if e.code() == ErrorCode::CanisterCalledTrap && e.description().contains("ERROR: ERC-20"));

    let orchestrator_id: Principal = "nbsys-saaaa-aaaar-qaaga-cai".parse().unwrap();
    let result = cketh
        .upgrade_minter_to_add_orchestrator_id(orchestrator_id)
        .add_ckerc20_token(Principal::anonymous(), &ckusdc());
    assert_matches!(result, Err(e) if e.code() == ErrorCode::CanisterCalledTrap && e.description().contains("ERROR: only the orchestrator"));

    fn ckusdc() -> AddCkErc20Token {
        AddCkErc20Token {
            chain_id: Nat::from(1_u8),
            address: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
            ckerc20_token_symbol: "ckUSDC".to_string(),
            ckerc20_ledger_id: "mxzaz-hqaaa-aaaar-qaada-cai".parse().unwrap(),
        }
    }
}

#[test]
fn should_add_ckusdc_and_ckusdt_to_minter_via_orchestrator() {
    let mut ckerc20 = CkErc20Setup::default();
    let embedded_ledger_wasm_hash = ckerc20.orchestrator.embedded_ledger_wasm_hash.clone();
    let embedded_index_wasm_hash = ckerc20.orchestrator.embedded_index_wasm_hash.clone();

    for token in supported_erc20_tokens(embedded_ledger_wasm_hash, embedded_index_wasm_hash) {
        ckerc20.orchestrator = ckerc20
            .orchestrator
            .add_erc20_token(token.clone())
            .expect_new_ledger_and_index_canisters()
            .setup;
        let new_ledger_id = ckerc20
            .orchestrator
            .call_orchestrator_canister_ids(&token.contract)
            .unwrap()
            .ledger
            .unwrap();

        ckerc20.cketh = ckerc20.cketh.assert_has_unique_events_in_order(&vec![
            EventPayload::AddedCkErc20Token {
                chain_id: token.contract.chain_id,
                address: format_ethereum_address_to_eip_55(&token.contract.address),
                ckerc20_token_symbol: token.ledger_init_arg.token_symbol,
                ckerc20_ledger_id: new_ledger_id,
            },
        ]);
    }
}

#[test]
fn should_mint_with_ckerc20_setup() {
    CkErc20Setup::default()
        .cketh
        .deposit(DepositParams::default())
        .expect_mint();
}

fn format_ethereum_address_to_eip_55(address: &str) -> String {
    use std::str::FromStr;
    Address::from_str(address).unwrap().to_string()
}
