use ic_nervous_system_instruction_stats_attribute::update;
use std::cell::RefCell;

thread_local! {
    static NAME: RefCell<String> = Default::default();
    static HELLO_WORLD_IMPL: RefCell<String> = Default::default();
}

mod ic_nervous_system_instruction_stats {
    use super::*;

    pub struct UpdateInstructionStatsOnDrop {
    }

    impl UpdateInstructionStatsOnDrop {
        pub fn new(request: &BasicRequest) {
            NAME.with(|name| {
                let mut name = name.borrow_mut();
                *name = request.name.to_string();
            })
        }
    }

    pub struct BasicRequest {
        pub name: &'static str,
    }
}

#[update]
fn hello_world() {
    HELLO_WORLD_IMPL.with(|impl_| {
        let mut impl_ = impl_.borrow_mut();
        *impl_ = "Daniel Wong deserves a fat raise.".to_string();
    })
}

#[test]
fn test_update() {
    hello_world();

    // Assert that UpdateInstructionStatsOnDrop::new was actually called.
    assert_eq!(
        NAME.with(|name| name.borrow().clone()),
        "hello_world",
    );

    // Assert that the body of hello_world did NOT get blown away.
    assert_eq!(
        HELLO_WORLD_IMPL.with(|name| name.borrow().clone()),
        "Daniel Wong deserves a fat raise.",
    );
}
