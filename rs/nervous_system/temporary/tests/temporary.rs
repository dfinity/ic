use ic_nervous_system_temporary::Temporary;
use std::cell::Cell;

thread_local! {
    static IS_FOO_ENABLED: Cell<bool> = const { Cell::new(false) };
    static IS_BAR_ENABLED: Cell<bool> = const { Cell::new(true) };
}

pub fn is_foo_enabled() -> bool {
    IS_FOO_ENABLED.with(|ok| ok.get())
}

pub fn temporarily_enable_foo() -> Temporary {
    Temporary::new(&IS_FOO_ENABLED, true)
}

pub fn temporarily_disable_foo() -> Temporary {
    Temporary::new(&IS_FOO_ENABLED, false)
}

pub fn is_bar_enabled() -> bool {
    IS_BAR_ENABLED.with(|ok| ok.get())
}

pub fn temporarily_enable_bar() -> Temporary {
    Temporary::new(&IS_BAR_ENABLED, true)
}

pub fn temporarily_disable_bar() -> Temporary {
    Temporary::new(&IS_BAR_ENABLED, false)
}

#[test]
fn test_temporarily_enable() {
    assert!(!is_foo_enabled());
    assert!(is_bar_enabled());

    {
        let _restore_foo_on_drop = temporarily_enable_foo();
        let _restore_bar_on_drop = temporarily_enable_bar();

        assert!(is_foo_enabled());
        assert!(is_bar_enabled());
    }

    assert!(!is_foo_enabled());
    assert!(is_bar_enabled());
}

#[test]
fn test_temporarily_disable() {
    assert!(!is_foo_enabled());
    assert!(is_bar_enabled());

    {
        let _restore_foo_on_drop = temporarily_disable_foo();
        let _restore_bar_on_drop = temporarily_disable_bar();

        assert!(!is_foo_enabled());
        assert!(!is_bar_enabled());
    }

    assert!(!is_foo_enabled());
    assert!(is_bar_enabled());
}
