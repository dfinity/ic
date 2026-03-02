use ic_nervous_system_query_instruction_logger::query;
use std::cell::RefCell;

pub const LOG_PREFIX: &str = "[TEST] ";

thread_local! {
    static WAS_CALLED: RefCell<Vec<&'static str>> = Default::default();
}

// Mocking the behavior so we don't actually invoke the real ic_cdk::println!
// which can't easily be intercepted here. We just want to ensure it compiles
// and basically structures the code correctly.
mod ic_cdk {
    pub use ::ic_cdk::query;
    
    pub mod api {
        pub fn call_context_instruction_counter() -> u64 {
            super::super::WAS_CALLED.with(|c| c.borrow_mut().push("call_context_instruction_counter"));
            42
        }
    }
    
    // We mock the println macro by just logging to our tracking list
    #[macro_export]
    macro_rules! mock_println {
        ($fmt:expr $(, $arg:expr)* $(,)?) => {
            $( let _ = $arg; )* // Evaluate all arguments
            crate::WAS_CALLED.with(|c| c.borrow_mut().push("println"));
        }
    }
    
    pub use mock_println as println;
}

#[query]
fn my_query_method() -> i32 {
    WAS_CALLED.with(|c| c.borrow_mut().push("my_query_method"));
    100
}

#[test]
fn test_query_macro() {
    let result = my_query_method();
    
    assert_eq!(result, 100);
    
    let observed_calls = WAS_CALLED.with(|c| c.borrow().clone());
    
    // The macro should have injected call_context_instruction_counter and println
    assert_eq!(
        observed_calls,
        vec!["my_query_method", "call_context_instruction_counter", "println"]
    );
}
