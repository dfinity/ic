use ic_nervous_system_instruction_stats_update_attribute::update;
use std::{cell::RefCell, collections::BTreeMap};

thread_local! {
    static WAS_CALLED: RefCell<Vec<&'static str>> = Default::default();
}

mod ic_nervous_system_instruction_stats {
    use super::*;

    pub struct UpdateInstructionStatsOnDrop {}

    impl UpdateInstructionStatsOnDrop {
        pub fn new(operation_name: &str, additional_labels: BTreeMap<String, String>) -> Self {
            WAS_CALLED.with(|was_called| {
                was_called.borrow_mut().push("new");
            });

            assert_eq!(operation_name, "canister_method:hello_world");
            assert_eq!(additional_labels, BTreeMap::new());

            Self {}
        }
    }
}

#[update]
fn hello_world() {
    WAS_CALLED.with(|was_called| {
        was_called.borrow_mut().push("hello_world");
    });
}

#[test]
fn test_update() {
    hello_world();

    let observed_calls = WAS_CALLED.with(|was_called| was_called.borrow().clone());
    assert_eq!(observed_calls, vec!["new", "hello_world"],);
}
