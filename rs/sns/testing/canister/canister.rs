use candid::CandidType;
use serde::Deserialize;
use std::cell::RefCell;

thread_local! {
    static STR: RefCell<String> = RefCell::new("Hoi".to_string());
}

#[derive(CandidType, Deserialize)]
pub struct InitArgs {
    pub greeting: Option<String>,
}

fn init_impl(x: Option<InitArgs>) {
    match x {
        None => (),
        Some(x) => {
            match x.greeting {
                None => (),
                Some(g) => {
                    STR.with(|s| *s.borrow_mut() = g);
                }
            };
        }
    }
}

#[ic_cdk::init]
fn init(x: Option<InitArgs>) {
    init_impl(x);
}

#[ic_cdk::post_upgrade]
fn post_upgrade(x: Option<InitArgs>) {
    init_impl(x);
}

#[ic_cdk::query]
fn greet(name: String) -> String {
    format!("{}, {}!", STR.with(|s| (*s.borrow_mut()).clone()), name)
}

fn main() {}
