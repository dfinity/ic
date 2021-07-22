use ic_types::Cycles;
// Assert that a cycles balance is equal to some value. Given that some cycles
// can be deducted for storage and other minor costs, there's some tolerance to
// how close the two balances are defined by `epsilon`.
pub fn assert_balance_equals(expected: Cycles, actual: Cycles, epsilon: Cycles) {
    // Tolerate both positive and negative difference. Assumes no overflows.
    assert!(
        expected < actual + epsilon && actual < expected + epsilon,
        "assert_balance_equals: expected {} actual {} epsilon {}",
        expected,
        actual,
        epsilon
    );
}
