use super::*;

thread_local! {
    static CALL_CONTEXT_INSTRUCTION_COUNTER_RESULTS: RefCell<Vec<u64>> =
        RefCell::new(vec![40_000_000_001, 2_760_000_000, 1_500_000, 123_456]);
}

pub(crate) fn call_context_instruction_counter() -> u64 {
    CALL_CONTEXT_INSTRUCTION_COUNTER_RESULTS.with(|results| results.borrow_mut().pop().unwrap())
}

struct SomeRequest {
    x: String,
    y: String,
}

impl Request for SomeRequest {
    const METHOD_NAME: &'static str = "make_sandwhich";

    fn metric_labels(&self) -> HashMap<String, String> {
        HashMap::from([
            ("x".to_string(), self.x.clone()),
            ("y".to_string(), self.y.clone()),
        ])
    }
}

#[test]
fn test_on_drop() {
    let request = SomeRequest {
        x: "hello".to_string(),
        y: "world".to_string(),
    };

    {
        let _on_drop = UpdateInstructionStatsOnDrop::new(&request);
    }

    let stats = || {
        STATS.with(|stats| stats.borrow().clone())
    };

    let expected_key = vec![
        ("method_name".to_string(), "make_sandwhich".to_string()),
        ("x".to_string(), "hello".to_string()),
        ("y".to_string(), "world".to_string()),
    ];
    assert_eq!(
        stats().keys().cloned().collect::<Vec<Vec<(String, String)>>>(),
        vec![expected_key.clone()],
    );

    let observed_histogram = stats().get(&expected_key).unwrap().clone();
    let mut expected_histogram = Histogram::new(INSTRUCTIONS_BIN_INCLUSIVE_UPPER_BOUNDS.clone());
    expected_histogram.add_event(123_456);
    assert_eq!(observed_histogram, expected_histogram);

    for _ in 0..3 {
        let _on_drop = UpdateInstructionStatsOnDrop::new(&request);
    }

    assert_eq!(
        CALL_CONTEXT_INSTRUCTION_COUNTER_RESULTS.with(|results| results.borrow().clone()),
        vec![],
    );

    let observed_histogram = stats().get(&expected_key).unwrap().clone();
    for event in [1_500_000, 2_760_000_000, 40_000_000_001] {
        expected_histogram.add_event(event);
    }
    assert_eq!(observed_histogram, expected_histogram);
}
