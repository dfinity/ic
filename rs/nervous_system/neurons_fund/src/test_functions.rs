use super::*;
use rust_decimal::Decimal;

#[derive(Debug)]
pub struct SimpleLinearFunction {}

impl DeserializableFunction for SimpleLinearFunction {
    /// Attempts to create an instance of `Self` from a serialized representation, `repr`.
    fn from_repr(repr: &str) -> Result<Box<Self>, String> {
        if repr == "<SimpleLinearFunction>" {
            Ok(Box::from(Self {}))
        } else {
            Err(format!(
                "Cannot deserialize `{repr}` as SimpleLinearFunction"
            ))
        }
    }
}

impl MatchingFunction for SimpleLinearFunction {
    fn apply(&self, x_icp_e8s: u64) -> Result<Decimal, String> {
        rescale_to_icp(x_icp_e8s)
    }
}

impl SerializableFunction for SimpleLinearFunction {
    fn serialize(&self) -> String {
        "<SimpleLinearFunction>".to_string()
    }
}

/// Returns the number of whole e8s that corresponds to the function value `target_y_icp`.
/// Used for testing; should be implemented as a closed form formula.
pub trait AnalyticallyInvertibleFunction {
    fn invert_analytically(&self, target_y_icp: Decimal) -> Result<u64, String>;
}

impl AnalyticallyInvertibleFunction for SimpleLinearFunction {
    fn invert_analytically(&self, target_y_icp: Decimal) -> Result<u64, String> {
        rescale_to_icp_e8s(target_y_icp)
    }
}

pub struct LinearFunction {
    pub slope: Decimal,
    pub intercept: Decimal,
}

impl AnalyticallyInvertibleFunction for LinearFunction {
    fn invert_analytically(&self, target_y: Decimal) -> Result<u64, String> {
        if self.slope.is_zero() {
            return Err("Cannot invert constant function.".to_string());
        }
        dec_to_u64((target_y - self.intercept) / self.slope)
    }
}

impl MatchingFunction for LinearFunction {
    fn apply(&self, x_icp_e8s: u64) -> Result<Decimal, String> {
        let x = u64_to_dec(x_icp_e8s)?;
        let Some(x_times_slope) = x.checked_mul(self.slope) else {
            return Err(format!(
                "Cannot apply linear function over {x} due to multiplication overflow."
            ));
        };
        let Some(y) = x_times_slope.checked_add(self.intercept) else {
            return Err(format!(
                "Cannot apply linear function over {x} due to addition overflow."
            ));
        };
        Ok(y)
    }
}
