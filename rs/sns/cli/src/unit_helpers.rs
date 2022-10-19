pub(crate) fn percentage_to_basis_points(percentage: f64) -> u64 {
    (percentage * 100.0) as u64
}

pub(crate) fn basis_points_to_percentage(basis_points: u64) -> f64 {
    (basis_points as f64) / 100.0
}

pub(crate) fn multiplier_to_percentage_increase(multiplier: f64) -> Option<u64> {
    if multiplier >= 1.0 {
        Some(((multiplier - 1.0) * 100.0) as u64)
    } else {
        None
    }
}

pub(crate) fn percentage_increase_to_multiplier(percentage: u64) -> f64 {
    1.0 + ((percentage as f64) / 100.0)
}
