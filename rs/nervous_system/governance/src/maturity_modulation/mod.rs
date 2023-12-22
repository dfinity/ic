use std::cmp::Ordering;

/// The maturity modulation range in basis points.
pub const MIN_MATURITY_MODULATION_PERMYRIAD: i32 = -500;
pub const MAX_MATURITY_MODULATION_PERMYRIAD: i32 = 500;

pub const BASIS_POINTS_PER_UNITY: u128 = 10_000;

/// Modulate amount_e8s. That is, multiply by 1 + X where
/// X = maturity_modulation_basis_points / 10_000.
pub fn apply_maturity_modulation(
    amount_maturity_e8s: u64,
    maturity_modulation_basis_points: i32,
) -> Result<u64, String> {
    let amount_e8s = u128::from(amount_maturity_e8s);

    let adjusted_maturity_modulation_basis_points = saturating_add_or_subtract_u128_i32(
        BASIS_POINTS_PER_UNITY,
        maturity_modulation_basis_points,
    );

    let modulated_amount_e8s: u128 = amount_e8s
        .checked_mul(adjusted_maturity_modulation_basis_points)
        .ok_or_else(|| "Underflow or overflow when calculating maturity modulation".to_string())?
        .checked_div(BASIS_POINTS_PER_UNITY)
        .ok_or_else(|| "Underflow or overflow when calculating maturity modulation".to_string())?;

    u64::try_from(modulated_amount_e8s).map_err(|err| err.to_string())
}

/// Adds or subtracts a i32 from a u128, resulting in a u128. Safety check allows for `as`
/// conversions inline.
fn saturating_add_or_subtract_u128_i32(initial_value: u128, delta: i32) -> u128 {
    match delta.cmp(&0) {
        Ordering::Less => initial_value.saturating_sub(delta.saturating_abs() as u128),
        Ordering::Equal => initial_value,
        Ordering::Greater => initial_value.saturating_add(delta as u128),
    }
}
