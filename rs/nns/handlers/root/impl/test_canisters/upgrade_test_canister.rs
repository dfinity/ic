// This canister is used for testing upgrades with arguments and stable memory.

use ic_cdk::{
    api::{
        call::arg_data_raw,
        stable::{stable_grow, stable_read, stable_write},
    },
    post_upgrade, println, query,
};
use std::cell::RefCell;

thread_local! {
    static ARG_LEN: RefCell<usize>  = const {RefCell::new(0) };
}

fn main() {}

#[post_upgrade]
fn post_upgrade() {
    let arg = arg_data_raw();
    println!("Initializing test canister with arg={:?}", arg);
    stable_grow(1).expect("Could not grow stable memory");
    ARG_LEN.with(|len| {
        *len.borrow_mut() = arg.len();
    });
    stable_write(0, &arg);
}

#[query]
fn read_stable() -> Vec<u8> {
    let len = ARG_LEN.with(|len| *len.borrow());
    let mut buf = vec![0; len];
    stable_read(0, &mut buf);

    buf
}
