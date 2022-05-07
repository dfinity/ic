use candid::candid_method;
use dfn_candid::candid_one;
use dfn_core::over;
use std::cell::RefCell;

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
}

#[derive(Default, Debug, Clone, PartialEq, Eq)]
struct State {
    i: i32,
}

ic_nervous_system_common_build_metadata::define_get_build_metadata_candid_method! {}

/// Sets an internal integer variable.
#[export_name = "canister_update set_integer"]
fn set_integer() {
    over(candid_one, set_integer_);
}

/// Implementation of set_integer.
#[candid_method(update, rename = "set_integer")]
fn set_integer_(new_integer: i32) {
    STATE.with(move |state| {
        let mut state = state.borrow_mut();
        state.i = new_integer;
    });
}

/// Retrieves the value of the integer variable set by set_integer.
#[export_name = "canister_query get_integer"]
fn get_integer() {
    over(candid_one, get_integer_);
}

/// Implementation of get_integer.
#[candid_method(query, rename = "get_integer")]
fn get_integer_(_: ()) -> i32 {
    STATE.with(|state| state.borrow().i)
}

/// Panics with the given message.
#[export_name = "canister_query explode"]
fn explode() {
    over(candid_one, explode_);
}

/// Implementation of explode.
#[candid_method(query, rename = "explode")]
fn explode_(message: String) {
    panic!("Oh noez! {}", message);
}

// Prints Candid interface definition, which should only contain get_build_metadata method.
#[cfg(not(test))]
fn main() {
    candid::export_service!();
    std::print!("{}", __export_service());
}

#[cfg(test)]
mod test {

    #[test]
    fn matches_candid_file() {
        let expected = String::from_utf8(std::fs::read("interface.did").unwrap()).unwrap();

        candid::export_service!();
        let actual = __export_service();

        assert_eq!(
            actual, expected,
            "Generated candid definition does not match interface.did. \
             Run `cargo run --bin ic-nervous-system-common-test-canister > interface.did` in \
             rs/nns/common/test_canister to update interface.did."
        );
    }

    #[test]
    fn test_get_description() {
        let result = ic_nervous_system_common_build_metadata::get_description!();

        for required_chunk in [
            "profile: ",
            "optimization_level: ",
            "crate_name: ic-nervous-system-common-test-canister",
            "enabled_features: \n",
            "compiler_version: ",
        ] {
            assert!(
                result.contains(required_chunk),
                "result: {} vs. required_chunk: {}",
                result,
                required_chunk
            );
        }
    }
}
