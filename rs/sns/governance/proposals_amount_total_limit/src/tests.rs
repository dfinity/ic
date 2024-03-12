use super::*;
use candid::types::principal::Principal;
use ic_base_types::PrincipalId;
use ic_sns_governance_token_valuation::Token;
use icrc_ledger_types::icrc1::account::Account;
use lazy_static::lazy_static;
use std::time::SystemTime;

lazy_static! {
    // Each token is worth approximately 10 XDR.
    static ref VALUATION: Valuation = Valuation {
        token: Token::SnsToken,
        account: Account {
            owner: Principal::from(PrincipalId::new_user_test_id(0xF00D)),
            subaccount: None,
        },
        timestamp: SystemTime::now(),
        valuation_factors: ValuationFactors {
            tokens: Decimal::from(0),
            // Each token is worth approximately 10 XDR.
            icps_per_token: Decimal::from_f64_retain(5.05).unwrap(),
            xdrs_per_icp: Decimal::from_f64_retain(1.95).unwrap(),
        }
    };
}

#[test]
fn test_small_valuation_upper_bound() {
    // In XDR, this is is well under 100_000; thus, a treasury like this would be considered
    // "small" for the purposes of treasury transfer limits.
    let valuation = {
        let mut valuation = *VALUATION;
        valuation.valuation_factors.tokens = Decimal::from(42);
        valuation
    };

    let observed_treasury_upper_bound_tokens =
        transfer_sns_treasury_funds_7_day_total_upper_bound_tokens(&valuation).unwrap();
    let observed_minting_upper_bound_tokens =
        mint_sns_tokens_7_day_total_upper_bound_tokens(&valuation).unwrap();

    assert_eq!(observed_treasury_upper_bound_tokens, Decimal::from(42),);
    assert_eq!(observed_minting_upper_bound_tokens, Decimal::from(42),);
}

#[test]
fn test_medium_valuation_upper_bound() {
    // In XDR, this is is approximately 500_000; thus, a treasury like this would be considered
    // "medium" for the purposes of treasury transfer limits.
    let valuation = {
        let mut valuation = *VALUATION;
        valuation.valuation_factors.tokens = Decimal::from(50_000);
        valuation
    };

    let observed_treasury_upper_bound_tokens =
        transfer_sns_treasury_funds_7_day_total_upper_bound_tokens(&valuation).unwrap();
    let observed_minting_upper_bound_tokens =
        mint_sns_tokens_7_day_total_upper_bound_tokens(&valuation).unwrap();

    assert_eq!(
        observed_treasury_upper_bound_tokens,
        Decimal::from(50_000 / 4),
    );
    assert_eq!(
        observed_minting_upper_bound_tokens,
        Decimal::from(50_000 / 4),
    );
}

#[test]
fn test_large_valuation_upper_bound() {
    // In XDR, this is is approximately 3_000_000, a treasury like this would be considered
    // "large" for the purposes of treasury transfer limits.
    let valuation = {
        let mut valuation = *VALUATION;
        valuation.valuation_factors.tokens = Decimal::from(300_000);
        valuation
    };

    let observed_treasury_upper_bound_tokens =
        transfer_sns_treasury_funds_7_day_total_upper_bound_tokens(&valuation).unwrap();
    let observed_minting_upper_bound_tokens =
        mint_sns_tokens_7_day_total_upper_bound_tokens(&valuation).unwrap();

    let xdrs_per_token = Decimal::from_f64_retain(1.95 * 5.05).unwrap();
    let tokens_per_xdr = xdrs_per_token.inv();
    let expected_tokens = Decimal::from(300_000) * tokens_per_xdr;

    let relative_error = (observed_treasury_upper_bound_tokens - expected_tokens) / expected_tokens;
    assert!(
        relative_error < Decimal::from_f64_retain(1e-9).unwrap(),
        "observed: {}\n\
         vs.\n\
         expected: {}\n\
         (relative error = {}%)",
        observed_treasury_upper_bound_tokens,
        expected_tokens,
        relative_error * Decimal::from(100),
    );

    let relative_error = (observed_minting_upper_bound_tokens - expected_tokens) / expected_tokens;
    assert!(
        relative_error < Decimal::from_f64_retain(1e-9).unwrap(),
        "observed: {}\n\
         vs.\n\
         expected: {}\n\
         (relative error = {}%)",
        observed_minting_upper_bound_tokens,
        expected_tokens,
        relative_error * Decimal::from(100),
    );
}
