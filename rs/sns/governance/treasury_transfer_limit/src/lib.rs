use ic_sns_governance_token_valuation::{Valuation, ValuationFactors};
use num_traits::ops::inv::Inv;
use rust_decimal::Decimal;
use rust_decimal_macros::dec;

const ONE_QUARTER: Decimal = dec!(0.25);

/// Within a 7 day window, at most, this much of the treasury can be transferred (out via proposal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreasuryTransferTotalUpperBound {
    /// Any amount can be transferred (out via proposal).
    NoLimit,

    /// How much of the treasury can be transferred (out via proposal). A real number in the real
    /// number interval [0.0, 1.0], where 0 = 0% and 1.0 = 100%.
    Fraction(Decimal),

    /// How much of the treasury can be transferred (out via proposal) stated in XDR.
    Xdr(Decimal),
}

impl TreasuryTransferTotalUpperBound {
    // A treasury can be small, medium, or large. These are the boundaries between those regimes.
    const MAX_SMALL_TREASURY_SIZE_XDR: Decimal = dec!(100_000);
    const MAX_MEDIUM_TREASURY_SIZE_XDR: Decimal = dec!(1_200_000);

    // No matter how large the treasury is, not more than this amount can be removed (within a 7 day
    // window).
    const MAX_XDR: Decimal = dec!(300_000);

    pub fn in_tokens(valuation: &Valuation) -> Result<Decimal, TreasuryLimitError> {
        let ValuationFactors {
            tokens: balance_tokens,
            icps_per_token,
            xdrs_per_icp,
        } = &valuation.valuation_factors;

        let self_ = Self::from_valuation_xdr(valuation.to_xdr());
        let result_tokens = match self_ {
            Self::NoLimit => *balance_tokens,

            Self::Fraction(fraction) => balance_tokens
                .checked_mul(fraction)
                // Overflow should not be possible, since fraction is supposed to be at most 1.0.
                .ok_or_else(|| {
                    TreasuryLimitError::new_arithmetic(format!(
                        "Unable to perform {} * {}.",
                        balance_tokens, fraction,
                    ))
                })?,

            Self::Xdr(max_xdr) => {
                let xdrs_per_token =
                    xdrs_per_icp.checked_mul(*icps_per_token).ok_or_else(|| {
                        TreasuryLimitError::new_arithmetic(format!(
                            "XDRs per token could not be calculated from valuation: {:?}",
                            valuation
                        ))
                    })?;

                if xdrs_per_token == Decimal::from(0) {
                    // This is not reachable, because in this case, valuation.to_xdr() would return
                    // 0, and in that case, we would have taken the NoLimit branch.
                    return Err(TreasuryLimitError::new_arithmetic(format!(
                        "It appears that the tokens have zero value in XDR. valuation = {:?}",
                        valuation
                    )));
                }
                let tokens_per_xdr = xdrs_per_token.inv();

                max_xdr.checked_mul(tokens_per_xdr).ok_or_else(|| {
                    TreasuryLimitError::new_arithmetic(format!(
                        "Max tokens could not be calculated with valuation: {:?}",
                        valuation,
                    ))
                })?
            }
        };

        Ok(result_tokens)
    }

    fn from_valuation_xdr(valuation_xdr: Decimal) -> Self {
        // Ideally, this would be checked at compile time. In principal should be possible, since
        // all the inputs are const, but I'm not sure if Rust can do that. Therefore,
        // debug_assert_eq is used instead.
        debug_assert_eq!(
            Self::MAX_MEDIUM_TREASURY_SIZE_XDR.checked_mul(ONE_QUARTER),
            Some(Self::MAX_XDR),
        );

        if valuation_xdr <= Self::MAX_SMALL_TREASURY_SIZE_XDR {
            return Self::NoLimit;
        }

        if valuation_xdr <= Self::MAX_MEDIUM_TREASURY_SIZE_XDR {
            return Self::Fraction(ONE_QUARTER);
        }

        Self::Xdr(Self::MAX_XDR)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreasuryLimitError {
    pub r#type: TreasuryLimitErrorType,
    pub message: String,
}

impl TreasuryLimitError {
    pub fn new_arithmetic(message: String) -> Self {
        Self {
            r#type: TreasuryLimitErrorType::Arithmetic,
            message,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreasuryLimitErrorType {
    Arithmetic,
}

#[cfg(test)]
mod tests;
