use assert_matches::assert_matches;
use candid::{Nat, Principal};
use ic_cketh_minter::endpoints::events::EventPayload;
use ic_cketh_minter::endpoints::AddCkErc20Token;
use ic_cketh_test_utils::CkEthSetup;
use ic_state_machine_tests::ErrorCode;

#[test]
fn should_refuse_to_add_ckerc20_token() {
    let cketh = CkEthSetup::new();
    let result = cketh.add_ckerc20_token(Principal::anonymous(), &ckusdc());
    assert_matches!(result, Err(e) if e.code() == ErrorCode::CanisterCalledTrap && e.description().contains("ERROR: ERC-20"));

    let orchestrator_id: Principal = "nbsys-saaaa-aaaar-qaaga-cai".parse().unwrap();
    let result = cketh
        .upgrade_minter_to_add_orchestrator_id(orchestrator_id)
        .add_ckerc20_token(Principal::anonymous(), &ckusdc());
    assert_matches!(result, Err(e) if e.code() == ErrorCode::CanisterCalledTrap && e.description().contains("ERROR: only the orchestrator"));
}

#[test]
fn should_add_ckusdc_and_ckusdt() {
    let orchestrator_id: Principal = "nbsys-saaaa-aaaar-qaaga-cai".parse().unwrap();
    let ckusdc = ckusdc();
    let ckusdt = ckusdt();

    CkEthSetup::new()
        .upgrade_minter_to_add_orchestrator_id(orchestrator_id)
        .add_ckerc20_token_expecting_ok(orchestrator_id, &ckusdc)
        .assert_has_unique_events_in_order(&vec![EventPayload::AddedCkErc20Token {
            chain_id: ckusdc.chain_id,
            address: ckusdc.address,
            ckerc20_token_symbol: ckusdc.ckerc20_token_symbol,
            ckerc20_ledger_id: ckusdc.ckerc20_ledger_id,
        }])
        .add_ckerc20_token_expecting_ok(orchestrator_id, &ckusdt)
        .assert_has_unique_events_in_order(&vec![EventPayload::AddedCkErc20Token {
            chain_id: ckusdt.chain_id,
            address: ckusdt.address,
            ckerc20_token_symbol: ckusdt.ckerc20_token_symbol,
            ckerc20_ledger_id: ckusdt.ckerc20_ledger_id,
        }]);
}

fn ckusdc() -> AddCkErc20Token {
    AddCkErc20Token {
        chain_id: Nat::from(1_u8),
        address: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
        ckerc20_token_symbol: "ckUSDC".to_string(),
        ckerc20_ledger_id: "mxzaz-hqaaa-aaaar-qaada-cai".parse().unwrap(),
    }
}

fn ckusdt() -> AddCkErc20Token {
    AddCkErc20Token {
        chain_id: Nat::from(1_u8),
        address: "0xdAC17F958D2ee523a2206206994597C13D831ec7".to_string(),
        ckerc20_token_symbol: "ckUSDT".to_string(),
        ckerc20_ledger_id: "nbsys-saaaa-aaaar-qaaga-cai".parse().unwrap(),
    }
}
