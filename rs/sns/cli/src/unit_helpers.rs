pub(crate) fn percentage_to_basis_points(percentage: f64) -> u64 {
    (percentage * 100.0) as u64
}

pub(crate) fn basis_points_to_percentage(basis_points: u64) -> f64 {
    (basis_points as f64) / 100.0
}
