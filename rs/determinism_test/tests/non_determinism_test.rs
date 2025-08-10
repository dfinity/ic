use ic_determinism_test::determinism_test;

#[test]
fn test_process_batches_deterministically() {
    determinism_test(vec![
        "dirty1", "dirty2", "dirty1", "dirty2", "dirty1", "dirty2",
    ]);
}
