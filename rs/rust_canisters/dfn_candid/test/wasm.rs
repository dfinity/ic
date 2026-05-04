use dfn_candid::candid;
use dfn_core::over;

#[unsafe(export_name = "canister_query greeting")]
fn greeting() {
    over(candid, |(name, age): (String, u16)| {
        format!("Hello {name}, you are {age} years old")
    })
}

#[unsafe(export_name = "canister_query sum")]
fn combine() {
    over(candid, |(a, b, c, d): (u16, u16, u16, u16)| {
        let x = a + b;
        let y = c + d;
        (x, y)
    })
}

fn main() {}
