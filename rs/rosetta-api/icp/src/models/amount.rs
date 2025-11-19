use crate::errors::ApiError;
use crate::models::{Amount, Currency};
use ic_ledger_core::tokens::DECIMAL_PLACES;
use icp_ledger::Tokens;
use num_bigint::BigInt;
use std::convert::TryFrom;

pub fn tokens_to_amount(tokens: Tokens, token_name: &str) -> Result<Amount, ApiError> {
    let amount = tokens.get_e8s();
    Ok(Amount::new(
        BigInt::from(amount),
        Currency::new(token_name.into(), DECIMAL_PLACES),
    ))
}

pub fn signed_amount(amount: i128, token_name: &str) -> Amount {
    Amount::new(
        BigInt::from(amount),
        Currency::new(token_name.into(), DECIMAL_PLACES),
    )
}

pub fn from_amount(amount: &Amount, token_name: &str) -> Result<i128, String> {
    let cur = Currency::new(token_name.into(), DECIMAL_PLACES);
    match amount {
        Amount {
            value,
            currency,
            metadata: None,
        } if currency == &cur => {
            let val: i128 = value
                .parse()
                .map_err(|e| format!("Parsing amount failed: {e}"))?;
            let _ =
                u64::try_from(val.abs()).map_err(|_| "Amount does not fit in u64".to_string())?;
            Ok(val)
        }
        wrong => Err(format!("This value is not {token_name} {wrong:?}")),
    }
}

pub fn ledgeramount_from_amount(amount: &Amount, token_name: &str) -> Result<Tokens, String> {
    let inner = from_amount(amount, token_name)?;
    Ok(Tokens::from_e8s(inner as u64))
}
