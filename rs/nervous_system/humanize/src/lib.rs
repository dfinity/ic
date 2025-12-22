use core::fmt::Display;
use ic_nervous_system_proto::pb::v1 as nervous_system_pb;
use lazy_static::lazy_static;
use regex_lite::Regex;
use std::{collections::VecDeque, str::FromStr};

pub mod serde;

#[cfg(test)]
mod tests;

// Normally, we would import this from ic_nervous_system_common, but we'd be
// dragging in lots of stuff along with it. The main problem with that is that
// any random change that requires ic_nervous_system_common to be rebuilt will
// also trigger a rebuild here. This gives us a "fire wall" to prevent fires
// from spreading.
//
// TODO(NNS1-2284): Move E8, and other such things to their own tiny library to
// avoid triggering mass rebuilds.
const E8: u64 = 100_000_000;

/// Parses decimal strings ending in "tokens" (plural), decimal strings end in
/// "token" (singular) , or integer strings (again, base 10) ending in "e8s". In
/// the case of "tokens" strings, the maximum number of digits after the
/// (optional) decimal point is 8.
///
/// As with parse_fixed_point_decimal, "_" may be sprinkled throughout.
///
/// Whitespace around number is insignificant. E.g. " 42 tokens" is equivalent
/// to "42tokens".
///
/// Inverse of [`format_tokens`].
pub fn parse_tokens(s: &str) -> Result<nervous_system_pb::Tokens, String> {
    let e8s = if let Some(s) = s.strip_suffix("tokens").map(|s| s.trim()) {
        parse_fixed_point_decimal(s, /* decimal_places = */ 8)?
    } else if let Some(s) = s.strip_suffix("token").map(|s| s.trim()) {
        parse_fixed_point_decimal(s, /* decimal_places = */ 8)?
    } else if let Some(s) = s.strip_suffix("e8s").map(|s| s.trim()) {
        u64::from_str(&s.replace('_', "")).map_err(|err| err.to_string())?
    } else {
        return Err(format!("Invalid tokens input string: {s}"));
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
///
/// Inverse of [`format_duration`].
pub fn parse_duration(s: &str) -> Result<nervous_system_pb::Duration, String> {
    humantime::parse_duration(s)
        .map(|d| nervous_system_pb::Duration {
            seconds: Some(d.as_secs()),
        })
        .map_err(|err| err.to_string())
}

/// Similar to parse_fixed_point_decimal(s, 2), except a trailing percent sign
/// is REQUIRED (and not fed into parse_fixed_point_decimal).
///
/// Inverse of [`format_percentage`].
pub fn parse_percentage(s: &str) -> Result<nervous_system_pb::Percentage, String> {
    let number = s
        .strip_suffix('%')
        .ok_or_else(|| format!("Input string must end with a percent sign: {s}"))?;

    let basis_points = Some(parse_fixed_point_decimal(
        number, /* decimal_places = */ 2,
    )?);
    Ok(nervous_system_pb::Percentage { basis_points })
}

/// Inverse of [`format_time_of_day`].
///
/// Parses a string in the form "hh:mm UTC".
///
/// TODO(NNS1-2295): Support an optional "ss" suffix. E.g. "hh:mm:ss UTC".
pub fn parse_time_of_day(s: &str) -> Result<nervous_system_pb::GlobalTimeOfDay, String> {
    const FORMAT: &str = "hh:mm UTC";
    let error = format!("Unable to parse time of day \"{s}\". Format should be \"{FORMAT}\"",);

    // decompose "hh:mm UTC" into ["hh:mm", "UTC"]
    let parts = s.split_whitespace().collect::<Vec<_>>();
    let [hh_mm, "UTC"] = &parts[..] else {
        return Err(error);
    };

    // decompose "hh:mm" into ["hh", "mm"]
    let parts = hh_mm.split(':').collect::<Vec<_>>();
    let [hh, mm] = &parts[..] else {
        return Err(error);
    };
    if hh.len() != 2 || mm.len() != 2 {
        return Err(error);
    }

    // convert ["hh", "mm"] into hh, mm
    let Ok(hh) = u64::from_str(hh) else {
        return Err(error);
    };
    let Ok(mm) = u64::from_str(mm) else {
        return Err(error);
    };

    nervous_system_pb::GlobalTimeOfDay::from_hh_mm(hh, mm)
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
        .ok_or_else(|| format!("Not a number: {s}"))?;

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
        return Err(format!("Too many digits after the decimal place: {s}"));
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
        .map_err(|err| format!("Unable to convert {count} to u32. Reason: {err}"))?;

    let boost = 10_u64
        .checked_pow(count)
        .ok_or_else(|| format!("Too large of an exponent: {count}"))?;

    n.checked_mul(boost)
        .ok_or_else(|| format!("Too large of a decimal shift: {n} >> {count}"))
}

/// The inverse of [`parse_tokens`].
///
/// One wrinkle: if e8s is None, then this is equivalent to e8s = Some(0). This
/// follows the same logic as Protocol Buffers. If the caller wants None to be
/// treated differently, they must do it themselves.
pub fn format_tokens(tokens: &nervous_system_pb::Tokens) -> String {
    let nervous_system_pb::Tokens { e8s } = tokens;
    let e8s = e8s.unwrap_or(0);

    if 0 < e8s && e8s < 1_000_000 {
        return format!("{} e8s", group_digits(e8s));
    }

    // TODO: format_fixed_point_decimal. parse_fixed_point_decimal seems
    // lonesome. But seriously, it can also be used in format_percentage.

    let whole = e8s / E8;
    let fractional = e8s % E8;

    let fractional = if fractional == 0 {
        "".to_string()
    } else {
        // TODO: Group.
        format!(".{fractional:08}").trim_matches('0').to_string()
    };

    let units = if e8s == E8 { "token" } else { "tokens" };

    format!("{}{} {}", group_digits(whole), fractional, units)
}

/// The inverse of [`parse_duration`].
///
/// One wrinkle: if seconds is None, then this is equivalent to seconds =
/// Some(0). This follows the same logic as Protocol Buffers. If the caller
/// wants None to be treated differently, they must do it themselves.
pub fn format_duration(duration: &nervous_system_pb::Duration) -> String {
    let nervous_system_pb::Duration { seconds } = duration;
    let seconds = seconds.unwrap_or(0);

    humantime::format_duration(std::time::Duration::from_secs(seconds)).to_string()
}

/// The inverse of [`parse_percentage`].
///
/// One wrinkle: if basis_points is None, then this is equivalent to
/// basis_points = Some(0). This follows the same logic as Protocol Buffers. If
/// the caller wants None to be treated differently, they must do it themselves.
pub fn format_percentage(percentage: &nervous_system_pb::Percentage) -> String {
    let nervous_system_pb::Percentage { basis_points } = percentage;
    let basis_points = basis_points.unwrap_or(0);

    let whole = basis_points / 100;
    let fractional = basis_points % 100;

    let fractional = if fractional == 0 {
        "".to_string()
    } else {
        format!(".{fractional:02}").trim_matches('0').to_string()
    };

    format!("{}{}%", group_digits(whole), fractional)
}

/// The inverse of [`parse_time_of_day`].
///
/// Returns a string in the form "hh:mm UTC".
///
/// Will assume midnight if time_of_day.seconds_since_utc_midnight is None.
///
/// TODO(NNS1-2295): Additionally output ":ss" if the value doesn't slice evenly
/// into hours and minutes. E.g. "hh:mm:ss UTC".
pub fn format_time_of_day(time_of_day: &nervous_system_pb::GlobalTimeOfDay) -> String {
    let (hours, minutes) = time_of_day.to_hh_mm().unwrap_or((0, 0));

    format!("{hours:02}:{minutes:02} UTC")
}

pub(crate) fn group_digits(n: u64) -> String {
    let mut left_todo = n;
    let mut groups = VecDeque::new();

    while left_todo > 0 {
        let group = left_todo % 1000;
        left_todo /= 1000;

        let group = if left_todo == 0 {
            format!("{group}")
        } else {
            format!("{group:03}")
        };

        groups.push_front(group);
    }

    if groups.is_empty() {
        return "0".to_string();
    }

    Vec::from(groups).join("_")
}
