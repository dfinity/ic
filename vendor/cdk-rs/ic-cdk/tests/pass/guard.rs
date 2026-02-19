use ic_cdk::{query, update};

fn guard1() -> Result<(), String> {
    Ok(())
}

fn guard2() -> Result<(), String> {
    Ok(())
}

#[update(guard = "guard1")]
fn update_1_guard() {}

#[update(guard = "guard1", guard = "guard2")]
fn update_2_guards() {}

#[query(guard = "guard1")]
fn query_1_guard() {}

#[query(guard = "guard1", guard = "guard2")]
fn query_2_guards() {}

fn main() {}
