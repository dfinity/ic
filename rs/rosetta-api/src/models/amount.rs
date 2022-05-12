use crate::errors::ApiError;
use crate::models::{Currency, Object};
use ledger_canister::{Tokens, DECIMAL_PLACES};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

/// Amount is some Value of a Currency. It is considered invalid to specify a
/// Value without a Currency.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct Amount {
    /// Value of the transaction in atomic units represented as an
    /// arbitrary-sized signed integer.  For example, 1 BTC would be represented
    /// by a value of 100000000.
    #[serde(rename = "value")]
    pub value: String,

    #[serde(rename = "currency")]
    pub currency: Currency,

    #[serde(rename = "metadata")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Object>,
}

impl Amount {
    pub fn new(value: String, currency: Currency) -> Self {
        Self {
            value,
            currency,
            metadata: None,
        }
    }
}

pub fn tokens_to_amount(tokens: Tokens, token_name: &str) -> Result<Amount, ApiError> {
    let amount = tokens.get_e8s();
    Ok(Amount {
        value: format!("{}", amount),
        currency: Currency::new(token_name.into(), DECIMAL_PLACES),
        metadata: None,
    })
}

pub fn signed_amount(amount: i128, token_name: &str) -> Amount {
    Amount {
        value: format!("{}", amount),
        currency: Currency::new(token_name.into(), DECIMAL_PLACES),
        metadata: None,
    }
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
                .map_err(|e| format!("Parsing amount failed: {}", e))?;
            let _ =
                u64::try_from(val.abs()).map_err(|_| "Amount does not fit in u64".to_string())?;
            Ok(val)
        }
        wrong => Err(format!("This value is not {} {:?}", token_name, wrong)),
    }
}

pub fn ledgeramount_from_amount(amount: &Amount, token_name: &str) -> Result<Tokens, String> {
    let inner = from_amount(amount, token_name)?;
    Ok(Tokens::from_e8s(inner as u64))
}
