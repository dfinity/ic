/// Helper functions for converting from percentages to basis points.
///
/// Example:
/// ```
/// use ic_sns_cli::unit_helpers::percentage_to_basis_points;
/// let basis_points = percentage_to_basis_points(0.5);
/// assert_eq!(basis_points, 50);
/// ```
pub fn percentage_to_basis_points(percentage: f64) -> u64 {
    (percentage * 100.0).round() as u64
}

/// Helper functions for converting from basis points to percentages.
///
/// Example:
/// ```
/// use ic_sns_cli::unit_helpers::basis_points_to_percentage;
/// let percentage = basis_points_to_percentage(50);
/// assert_eq!(percentage, 0.5);
/// ```
pub fn basis_points_to_percentage(basis_points: u64) -> f64 {
    (basis_points as f64) / 100.0
}

/// Helper functions for converting from multipliers to percentage increases.
///
/// Example:
/// ```
/// use ic_sns_cli::unit_helpers::multiplier_to_percentage_increase;
/// let percentage_increase = multiplier_to_percentage_increase(1.15);
/// assert_eq!(percentage_increase, Some(15));
/// ```
pub fn multiplier_to_percentage_increase(multiplier: f64) -> Option<u64> {
    if multiplier >= 1.0 {
        Some(((multiplier - 1.0) * 100.0).round() as u64)
    } else {
        None
    }
}

/// Helper functions for converting from percentage increases to multipliers.
///
/// Example:
/// ```
/// use ic_sns_cli::unit_helpers::percentage_increase_to_multiplier;
/// let multiplier = percentage_increase_to_multiplier(15);
/// assert_eq!(multiplier, 1.15);
/// ```
pub fn percentage_increase_to_multiplier(percentage: u64) -> f64 {
    1.0 + ((percentage as f64) / 100.0)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn inverse_percentage_basis_points() {
        for value in 0..1000 {
            assert_eq!(
                value,
                percentage_to_basis_points(basis_points_to_percentage(value))
            );

            assert_eq!(
                value,
                basis_points_to_percentage(percentage_to_basis_points(value as f64)).round() as u64
            );
        }
    }

    #[test]
    fn inverse_multiplier_percentage_increase() {
        for value in 0..1000 {
            assert_eq!(
                value,
                multiplier_to_percentage_increase(percentage_increase_to_multiplier(value))
                    .unwrap()
            );

            if let Some(percentage_increase) = multiplier_to_percentage_increase(value as f64) {
                assert_eq!(
                    value,
                    percentage_increase_to_multiplier(percentage_increase).round() as u64
                );
            }
        }
    }
}
