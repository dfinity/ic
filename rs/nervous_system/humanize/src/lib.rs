use core::fmt::Display;
use ic_nervous_system_proto::pb::v1 as nervous_system_pb;
use lazy_static::lazy_static;
use regex::Regex;
use std::str::FromStr;

#[cfg(test)]
mod tests;

/// Parses decimal strings ending in "tokens" (plural), decimal strings end in
/// "token" (singular) , or integer strings (again, base 10) ending in "e8s". In
/// the case of "tokens" strings, the maximum number of digits after the
/// (optional) decimal point is 8.
///
/// As with parse_fixed_point_decimal, "_" may be sprinkled throughout.
///
/// Whitespace around number is insignificant. E.g. " 42 tokens" is equivalent
/// to "42tokens".
pub fn parse_tokens(s: &str) -> Result<nervous_system_pb::Tokens, String> {
    let e8s = if let Some(s) = s.strip_suffix("tokens").map(|s| s.trim()) {
        parse_fixed_point_decimal(s, /* decimal_places = */ 8)?
    } else if let Some(s) = s.strip_suffix("token").map(|s| s.trim()) {
        parse_fixed_point_decimal(s, /* decimal_places = */ 8)?
    } else if let Some(s) = s.strip_suffix("e8s").map(|s| s.trim()) {
        u64::from_str(&s.replace('_', "")).map_err(|err| err.to_string())?
    } else {
        return Err(format!("Invalid tokens input string: {}", s));
    };
    let e8s = Some(e8s);

    Ok(nervous_system_pb::Tokens { e8s })
}

/// A wrapper around humantime::parse_duration that does some additional
/// mechanical conversions.
///
/// To recapitulate the docs for humantime, "1w 2d 3h" gets parsed as
///
///   1 week + 2 days + 3 hours
///       =
///   (1 * (7 * 24 * 60 * 60) + 2 * 24 * 60 * 60 + 3 * (60 * 60)) seconds
pub fn parse_duration(s: &str) -> Result<nervous_system_pb::Duration, String> {
    humantime::parse_duration(s)
        .map(|d| nervous_system_pb::Duration {
            seconds: Some(d.as_secs()),
        })
        .map_err(|err| err.to_string())
}

/// Similar to parse_fixed_point_decimal(s, 2), except a trailing percent sign
/// is REQUIRED (and not fed into parse_fixed_point_decimal).
pub fn parse_percentage(s: &str) -> Result<nervous_system_pb::Percentage, String> {
    let number = s
        .strip_suffix('%')
        .ok_or_else(|| format!("Input string must end with a percent sign: {}", s))?;

    let basis_points = Some(parse_fixed_point_decimal(
        number, /* decimal_places = */ 2,
    )?);
    Ok(nervous_system_pb::Percentage { basis_points })
}

/// Parses strings like "123_456.789" into 123456789. Notice that in this
/// example, the decimal point in the result has been shifted to the right by 3
/// places. The amount of such shifting is specified using the decimal_places
/// parameter.
///
/// Also, notice that "_" (underscore) can be sprinkled as you wish in the input
/// for readability. No need to use groups of size 3, although it is
/// recommended, since that's what people are used to.
///
/// s is considered invalid if the number of digits after the decimal point >
/// decimal_places.
///
/// The decimal point is optional, but if it is included, it must have at least
/// one digit on each side (of course, the digit can be "0").
///
/// Prefixes (such as "0") do not change the base; base 10 is always
/// used. Therefore, s = "0xDEAD_BEEF" is invalid, for example.
fn parse_fixed_point_decimal(s: &str, decimal_places: usize) -> Result<u64, String> {
    lazy_static! {
        static ref REGEX: Regex = Regex::new(
            r"(?x) # Verbose (ignore white space, and comments, like this).
            ^  # begin
            (?P<whole>[\d_]+)  # Digit or underscores (for grouping digits).
            (  # The dot + fractional part...
                [.]  # dot
                (?P<fractional>[\d_]+)
            )?  # ... is optional.
            $  # end
        "
        )
        .unwrap();
    }

    let found = REGEX
        .captures(s)
        .ok_or_else(|| format!("Not a number: {}", s))?;

    let whole = u64::from_str(
        &found
            .name("whole")
            .expect("Missing capture group?!")
            .as_str()
            .replace('_', ""),
    )
    .map_err(|err| err.to_string())?;

    let fractional = format!(
        // Pad so that fractional ends up being of length (at least) decimal_places.
        "{:0<decimal_places$}",
        found
            .name("fractional")
            .map(|m| m.as_str())
            .unwrap_or("0")
            .replace('_', ""),
    );
    if fractional.len() > decimal_places {
        return Err(format!("Too many digits after the decimal place: {}", s));
    }
    let fractional = u64::from_str(&fractional).map_err(|err| err.to_string())?;

    Ok(shift_decimal_right(whole, decimal_places)? + fractional)
}

/// Multiplies n by 10^count.
fn shift_decimal_right<I>(n: u64, count: I) -> Result<u64, String>
where
    u32: TryFrom<I>,
    <u32 as TryFrom<I>>::Error: Display,
    I: Display + Copy,
{
    let count = u32::try_from(count)
        .map_err(|err| format!("Unable to convert {} to u32. Reason: {}", count, err))?;

    let boost = 10_u64
        .checked_pow(count)
        .ok_or_else(|| format!("Too large of an exponent: {}", count))?;

    n.checked_mul(boost)
        .ok_or_else(|| format!("Too large of a decimal shift: {} >> {}", n, count))
}
