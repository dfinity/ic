//! This should probably not be used outside of test.
//!
//! This is for "feature flags". That is,
//!
//!     use ic_nervous_system_temporary::Temporary;
//!     use std::cell::Cell;
//!     use rand::Rng;
//!
//!     thread_local! {
//!         static IS_FOO_ENABLED: Cell<bool> = Cell::new(rand::thread_rng().gen());
//!     }
//!
//!     pub fn is_foo_enabled() -> bool {
//!         IS_FOO_ENABLED.with(|ok| {
//!             ok.get()
//!         })
//!     }
//!
//!     fn code_under_test() -> i64 {
//!         if is_foo_enabled() {
//!             42
//!         } else {
//!             99
//!         }
//!     }
//!
//!     #[cfg(test)]
//!     fn temporarily_enable_foo() -> Temporary {
//!         Temporary::new(&FOO, true)
//!     }
//!
//!     #[cfg(test)]
//!     fn temporarily_disable_foo() -> Temporary {
//!         Temporary::new(&FOO, false)
//!     }
//!
//!     // Then, in tests, you can see what happens depending on whether the
//!     // feature is or disabled without having to have separate
//!     // feature = "test" builds, like so:
//!
//!     #[test]
//!     fn test_foo_enabled() {
//!         let _restore_foo_on_drop = temporarily_enable_foo();
//!
//!         let result = code_under_test();
//!
//!         assert_eq!(result, 42);
//!     }
//!
//!     #[test]
//!     fn test_foo_disabled() {
//!         let _restore_foo_on_drop = temporarily_disable_foo();
//!
//!         let result = code_under_test();
//!
//!         assert_eq!(result, 99);
//!     }
//!
//! If you want to call temporarily_*_foo from integration tests, you will have
//! to get rid of the #[cfg(test)] attributes, and also add pub.

use std::{cell::Cell, thread::LocalKey};

// This could be generic. That is, add a T parameter. Currently, only bool is supported, because YAGNI.
#[must_use]
pub struct Temporary {
    flag: &'static LocalKey<Cell<bool>>,
    original_value: bool,
}

impl Temporary {
    pub fn new(flag: &'static LocalKey<Cell<bool>>, temporary_value: bool) -> Self {
        // Set to true. Will be set back to false during drop.
        let original_value = flag.with(|flag| {
            let original_value: bool = flag.get();
            flag.set(temporary_value);
            original_value
        });

        Self {
            flag,
            original_value,
        }
    }
}

impl Drop for Temporary {
    fn drop(&mut self) {
        self.flag.with(|flag| {
            flag.set(self.original_value);
        });
    }
}
