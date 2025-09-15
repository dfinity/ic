use crate::pb::v1::{
    Account as AccountPb, Valuation as ValuationPb,
    valuation::{Token as TokenPb, ValuationFactors as ValuationFactorsPb},
};
use crate::proposal::TreasuryAccount;
use candid::Principal;
use ic_base_types::CanisterId;
use ic_base_types::PrincipalId;
use ic_nervous_system_common::E8;
use ic_nervous_system_proto::pb::v1::{Decimal as DecimalPb, Tokens};
use ic_sns_governance_token_valuation::{Token, Valuation, ValuationFactors};
use icrc_ledger_types::icrc1::account::Account;
use lazy_static::lazy_static;
use rust_decimal::Decimal;
use std::time::{Duration, SystemTime};

fn field_err(field_name: &str, child_message: String) -> String {
    format!("invalid {field_name}: {child_message}",)
}

impl TryFrom<Valuation> for ValuationPb {
    type Error = String;

    fn try_from(src: Valuation) -> Result<ValuationPb, String> {
        let Valuation {
            token,
            account,
            timestamp,
            valuation_factors,
        } = src;

        let token = Some(TokenPb::try_from(token).map_err(|err| field_err("token", err))? as i32);
        let account = Some(AccountPb::from(account));
        let timestamp_seconds = Some(
            timestamp
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_err(|err| field_err("timestamp", format!("{timestamp:?}: {err:?}")))?
                .as_secs(),
        );
        let valuation_factors = Some(
            ValuationFactorsPb::try_from(valuation_factors)
                .map_err(|err| field_err("valuation_factors", err))?,
        );

        Ok(ValuationPb {
            token,
            account,
            timestamp_seconds,
            valuation_factors,
        })
    }
}

pub(crate) fn tokens_to_e8s(tokens: Decimal) -> Result<u64, String> {
    let e8s = tokens.checked_mul(Decimal::from(E8)).ok_or_else(|| {
        format!(
            "Unable to convert {tokens} tokens (Decimal) to e8s (u64) due to multiplication overflow.",
        )
    })?;

    let e8s = u64::try_from(e8s).map_err(|err| {
        format!("Unable to convert {tokens} tokens (Decimal) to e8s (u64): {err:?}",)
    })?;

    Ok(e8s)
}

impl TryFrom<ValuationFactors> for ValuationFactorsPb {
    type Error = String;

    fn try_from(src: ValuationFactors) -> Result<ValuationFactorsPb, String> {
        let ValuationFactors {
            tokens,
            icps_per_token,
            xdrs_per_icp,
        } = src;

        let e8s = tokens_to_e8s(tokens)?;

        let tokens = Some(Tokens { e8s: Some(e8s) });

        let icps_per_token = Some(DecimalPb::from(icps_per_token));
        let xdrs_per_icp = Some(DecimalPb::from(xdrs_per_icp));

        Ok(ValuationFactorsPb {
            tokens,
            icps_per_token,
            xdrs_per_icp,
        })
    }
}

impl TryFrom<Token> for TokenPb {
    type Error = String;

    /// Never returns Err.
    fn try_from(src: Token) -> Result<TokenPb, String> {
        let result = match src {
            Token::Icp => TokenPb::Icp,
            Token::SnsToken => TokenPb::SnsToken,
        };

        Ok(result)
    }
}

impl TryFrom<&ValuationPb> for Valuation {
    type Error = String;

    fn try_from(src: &ValuationPb) -> Result<Valuation, String> {
        let ValuationPb {
            token,
            account,
            timestamp_seconds,
            valuation_factors,
        } = src;

        let mut defects = Vec::<String>::new();

        let token = interpret_token_code(token.unwrap_or_default())?;

        let account =
            Account::try_from(account.clone().unwrap_or_default()).unwrap_or_else(|err| {
                defects.push(format!("Unable to convert `account` {account:?}: {err:?}",));
                // Ditto earlier comment.
                Account {
                    owner: Principal::from(PrincipalId::new_user_test_id(0)),
                    subaccount: None,
                }
            });

        let timestamp = SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_secs(timestamp_seconds.unwrap_or_default()))
            .unwrap_or_else(|| {
                defects.push(format!(
                    "Unable to convert `timestamp` {timestamp_seconds:?}.",
                ));
                // Ditto earlier comment.
                SystemTime::UNIX_EPOCH
            });

        // Ditto earlier comment.
        let garbage_valuation_factors = ValuationFactors {
            tokens: Decimal::from(0),
            icps_per_token: Decimal::from(0),
            xdrs_per_icp: Decimal::from(0),
        };
        let valuation_factors: ValuationFactors = match valuation_factors {
            None => {
                defects.push("No valuation_factors.".to_string());
                garbage_valuation_factors
            }

            Some(valuation_factors) => ValuationFactors::try_from(valuation_factors)
                .unwrap_or_else(|err| {
                    defects.push(format!("Invalid valuation_factors: {err}"));
                    garbage_valuation_factors
                }),
        };

        if !defects.is_empty() {
            let err = format!(
                "Invalid ValuationPb. Defect(s):\n  - {}",
                defects.join("\n  - "),
            );
            return Err(err);
        }

        Ok(Valuation {
            token,
            account,
            timestamp,
            valuation_factors,
        })
    }
}

impl TryFrom<&ValuationFactorsPb> for ValuationFactors {
    type Error = String;

    fn try_from(src: &ValuationFactorsPb) -> Result<ValuationFactors, String> {
        let ValuationFactorsPb {
            tokens,
            icps_per_token,
            xdrs_per_icp,
        } = src;

        let mut defects = vec![];

        let e8s = Decimal::from(tokens.unwrap_or_default().e8s.unwrap_or_else(|| {
            defects.push("`tokens` is not specified".to_string());
            // This is a little dangerous, because it is misleading. However, since defects is
            // now non-empty, this won't get used.
            0
        }));
        let tokens = e8s / Decimal::from(E8);

        // Converts, and if unable, appends to defeects.
        let mut to_decimal = |name, value: &Option<DecimalPb>| {
            let decimal: DecimalPb = value.clone().unwrap_or_else(|| {
                defects.push("`icps_per_token` is not specified".to_string());
                // Ditto earlier comment.
                DecimalPb {
                    human_readable: Some("0".to_string()),
                }
            });

            Decimal::try_from(decimal).unwrap_or_else(|err| {
                defects.push(format!("Unable to convert `{name}' {value:?}: {err:?}",));
                // Ditto earlier comment.
                Decimal::from(0)
            })
        };

        let icps_per_token = to_decimal("icps_per_token", icps_per_token);
        let xdrs_per_icp = to_decimal("xdrs_per_icp", xdrs_per_icp);

        Ok(ValuationFactors {
            tokens,
            icps_per_token,
            xdrs_per_icp,
        })
    }
}

impl TryFrom<TokenPb> for Token {
    type Error = String;

    fn try_from(src: TokenPb) -> Result<Token, String> {
        match src {
            TokenPb::Unspecified => Err("Token not specified.".to_string()),
            TokenPb::Icp => Ok(Token::Icp),
            TokenPb::SnsToken => Ok(Token::SnsToken),
        }
    }
}

impl<'a> Default for &'a ValuationPb {
    fn default() -> &'a ValuationPb {
        lazy_static! {
            static ref DEFAULT: ValuationPb = ValuationPb::default();
        }
        &DEFAULT
    }
}

impl<'a> Default for &'a ValuationFactorsPb {
    fn default() -> &'a ValuationFactorsPb {
        lazy_static! {
            static ref DEFAULT: ValuationFactorsPb = ValuationFactorsPb::default();
        }
        &DEFAULT
    }
}

pub(crate) async fn assess_treasury_balance(
    token: Token,
    sns_governance_canister_id: CanisterId,
    sns_ledger_canister_id: CanisterId,
    swap_canister_id: CanisterId,
) -> Result<Valuation, String> {
    let treasury_account = token.treasury_account(sns_governance_canister_id)?;
    let valuation = token
        .assess_balance(sns_ledger_canister_id, swap_canister_id, treasury_account)
        .await
        .map_err(|valuation_error| {
            format!("Unable to assess current treasury balance: {valuation_error:?}")
        })?;
    Ok(valuation)
}

pub(crate) fn interpret_token_code(token: i32) -> Result<Token, String> {
    // First, convert from i32 to TokePb.
    let token_pb = TokenPb::try_from(token)
        .map_err(|err| format!("Unknown or unspecified token code {token:?}: {err:?}"))?;

    // Then, convert from TokenPb to Token.
    Token::try_from(token_pb)
        .map_err(|err| format!("Unknown or unspecified token code {token:?}: {err:?}",))
}
