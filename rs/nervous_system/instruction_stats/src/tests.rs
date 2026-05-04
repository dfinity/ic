use super::*;

thread_local! {
    static CALL_CONTEXT_INSTRUCTION_COUNTER_RESULTS: RefCell<Vec<u64>> =
        RefCell::new(vec![40_000_000_001, 0, 2_760_000_000, 0, 1_500_000, 0, 123_456, 0]);
}

pub(crate) fn call_context_instruction_counter() -> u64 {
    CALL_CONTEXT_INSTRUCTION_COUNTER_RESULTS.with(|results| results.borrow_mut().pop().unwrap())
}

#[test]
fn test_on_drop() {
    // Simulate 4 calls.
    for _ in 0..4 {
        let additional_labels = BTreeMap::from([("page_size".to_string(), "<= 10".to_string())]);
        let _on_drop = UpdateInstructionStatsOnDrop::new("make_sandwich", additional_labels);
    }

    // Step 3: Inspect results.

    let stats = STATS.with(|stats| stats.borrow().clone());

    let expected_label_set = BTreeMap::from([
        ("operation_name".to_string(), "make_sandwich".to_string()),
        ("page_size".to_string(), "<= 10".to_string()),
    ]);
    let mut expected_histogram = Histogram::new(INSTRUCTIONS_BIN_INCLUSIVE_UPPER_BOUNDS.clone());
    for event in [40_000_000_001, 2_760_000_000, 1_500_000, 123_456] {
        expected_histogram.add_event(event);
    }
    assert_eq!(
        stats,
        BTreeMap::from([(expected_label_set, expected_histogram),]),
    );
}
