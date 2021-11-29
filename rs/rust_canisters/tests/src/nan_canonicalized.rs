#![allow(clippy::ptr_arg)]
// Canonical 32-bit and 64-bit NaN values from cranelift-codegen can be found at
// https://github.com/bytecodealliance/cranelift/blob/60ab06981ff9ab234d1a5fa4ffe30baeb9879319/cranelift-codegen/src/nan_canonicalization.rs#L14
static CANON_32BIT_NAN: u32 = 0b0111_1111_1100_0000_0000_0000_0000_0000;
static CANON_64BIT_NAN: u64 =
    0b0111_1111_1111_1000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000;

use dfn_macro::query;
use std::f32;
use std::f64;

type Floats = Vec<(f32, f64)>;

// combine +x and -x to make ±x
fn or(plus: &Floats, minus: &Floats) -> Floats {
    let mut p = plus.clone();
    p.extend(minus);
    p
}

fn product<F1, F2>(float: F1, double: F2, floats1: &Floats, floats2: &Floats) -> Floats
where
    F1: Fn(f32, f32) -> f32,
    F2: Fn(f64, f64) -> f64,
{
    let out_len = floats1.len() * floats2.len();
    let mut output = Vec::with_capacity(out_len);
    for &(f1, d1) in floats1 {
        for &(f2, d2) in floats2 {
            output.push((float(f1, f2), double(d1, d2)))
        }
    }
    output
}

fn divide(f1: &Floats, f2: &Floats) -> Floats {
    product(|x, y| x / y, |x, y| x / y, f1, f2)
}

fn multiply(f1: &Floats, f2: &Floats) -> Floats {
    product(|x, y| x * y, |x, y| x * y, f1, f2)
}

fn add(f1: &Floats, f2: &Floats) -> Floats {
    product(|x, y| x + y, |x, y| x + y, f1, f2)
}

fn subtract(f1: &Floats, f2: &Floats) -> Floats {
    product(|x, y| x - y, |x, y| x - y, f1, f2)
}

fn remainder(f1: &Floats, f2: &Floats) -> Floats {
    product(|x, y| x % y, |x, y| x % y, f1, f2)
}

/// The canonicalized NaN thing looks to be a bit off the beaten path for
/// WASM codegen, so I decided it makes sense to put some tests here as we
/// jump from one implementation to another.
/// Additionally this checks that the NaNs the rust compiler is spitting out
/// play nicely with the canonicalization
#[query]
fn nans_are_canonicalized(_: ()) -> Result<(), String> {
    let nan: Floats = vec![(f32::NAN, f64::NAN)];

    let inf = vec![(f32::INFINITY, f64::INFINITY)];
    let neg_inf = vec![(f32::NEG_INFINITY, f64::NEG_INFINITY)];
    let pm_inf = or(&inf, &neg_inf);

    let zero = vec![(0.0, 0.0)];
    let neg_zero = vec![(-0.0, -0.0)];
    let pm_zero = or(&zero, &neg_zero);

    // numbers which are not (±∞), (±0) or NaN
    let other = vec![(42.0, 42.0), (-42.0, -42.0)];

    is_canon("Regular NaN", &nan)?;

    is_canon("(±0) / (±0)", &divide(&pm_zero, &pm_zero))?;
    is_canon("(±∞) / (±∞)", &divide(&pm_inf, &pm_inf))?;

    is_canon("(±0) × (±∞)", &multiply(&pm_zero, &pm_inf))?;
    is_canon("(±∞) × (±0)", &multiply(&pm_inf, &pm_zero))?;

    is_canon("x % (±0)", &remainder(&other, &pm_zero))?;
    is_canon("(±∞) % y", &remainder(&pm_inf, &other))?;

    is_canon("(+∞) + (−∞)", &add(&inf, &neg_inf))?;
    is_canon("(-∞) + (+∞)", &add(&neg_inf, &inf))?;

    is_canon("(+∞) - (+∞)", &subtract(&inf, &inf))?;
    is_canon("(-∞) - (-∞)", &subtract(&neg_inf, &neg_inf))?;

    // This should be the same NaN, but the rust compiler actually checks
    // if the f32 is below zero and returns a different (deterministic) NaN
    // is_canon("sqrt(-1)", &vec![(f32::sqrt(-1.0), f64::sqrt(-1.0))])?;

    is_canon("asin(2)", &vec![(f32::asin(2.0), f64::asin(2.0))])?;

    is_canon("ln(-1)", &vec![(f32::ln(-1.0), f64::ln(-1.0))])?;

    if !f32::NAN.is_nan() || !f64::NAN.is_nan() {
        return Err("is_nan is false for a canonicalized NaN".into());
    }

    Ok(())
}

/// Is this a canonicalized NaN?
fn is_canon(msg: &str, inputs: &Floats) -> Result<(), String> {
    for (i, (float, double)) in inputs.iter().enumerate() {
        {
            let bits = float.to_bits();
            let target = CANON_32BIT_NAN;
            if bits != target {
                return Err(format!(
                    "In {} f32 element {} \nExpected: \t0x{:x}\nFound: \t0x{:x}",
                    msg, i, target, bits
                ));
            }
        }
        {
            let bits = double.to_bits();
            let target = CANON_64BIT_NAN;
            if bits != target {
                return Err(format!(
                    "In {} f64 element {} \nExpected: \t0x{:x}\nFound: \t0x{:x}",
                    msg, i, target, bits
                ));
            }
        }
    }

    Ok(())
}

fn main() {}
