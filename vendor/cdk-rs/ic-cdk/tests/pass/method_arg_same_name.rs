use ic_cdk::{query, update};

#[update]
fn foo(foo: i32) -> i32 {
    foo
}

#[query]
fn bar(bar: i32) -> i32 {
    bar
}

fn main() {}
